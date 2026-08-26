
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using ACT.Contracts;
using ACT.Scope;
using Microsoft.Extensions.Logging;

namespace ACT.Network;

/// <summary>Outcome of one bounded TCP service probe.</summary>
public sealed record TcpProbeResult(
    string Host,
    int Port,
    bool Reachable,
    bool TlsNegotiated,
    string? Banner,
    TimeSpan Elapsed,
    string? ErrorSafe,
    string DiagnosticDetail);

/// <summary>Detailed, evidence-grade outcome of a TLS handshake probe.</summary>
public sealed record TlsProbeResult(
    string Host,
    int Port,
    bool HandshakeSucceeded,
    SslProtocols? NegotiatedProtocol,
    string? CipherSuite,
    int? CipherStrengthBits,
    X509Certificate2? Certificate,
    IReadOnlyList<string> ChainSubjects,
    IReadOnlyList<string> ChainErrors,
    TimeSpan HandshakeElapsed,
    string? FailureSafe);

/// <summary>
/// Bounded TCP service discovery against explicitly permitted ports only.
/// Every connect is preceded by a full scope + DNS authorization check and pinned addresses.
/// </summary>
public sealed class TcpServiceProbe(IScopeValidator scopeValidator, IDnsGate dnsGate, ILogger logger)
{
    private static readonly TimeSpan ConnectTimeout = TimeSpan.FromSeconds(4);
    private const int MaxBannerBytes = 4096;

    public async Task<TcpProbeResult> ProbeAsync(string host, int port, CancellationToken cancellationToken)
    {
        var started = DateTimeOffset.UtcNow;
        var stopwatch = System.Diagnostics.Stopwatch.StartNew();

        // Authorization first; nothing leaves this machine otherwise.
        var resolved = await dnsGate.ResolveVerifiedAsync(host, cancellationToken);
        var verdict = scopeValidator.Evaluate(new TargetCandidate(host, port, ProtocolFor(port), null));
        if (!verdict.Allowed)
        {
            throw ActException.FailClosed(ErrorCategory.Scope, verdict.SafeMessage, verdict.DiagnosticDetail);
        }

        Exception? lastError = null;
        foreach (var address in resolved)
        {
            try
            {
                using var client = new TcpClient(address.AddressFamily);
                using var connectCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                connectCts.CancelAfter(ConnectTimeout);
                await client.ConnectAsync(address, port, connectCts.Token);

                NetworkStream stream = client.GetStream();
                var banner = await TryReadBannerAsync(stream, cancellationToken);

                bool tlsNegotiated = false;
                if (LooksLikeTlsPort(port) && banner is { Length: > 0 } && banner[0] == 0x16)
                {
                    tlsNegotiated = true; // Server spoke first with a TLS record; binary banner captured.
                }

                stopwatch.Stop();
                logger.LogDebug("Probed {Host}:{Port} reachable={Reachable} in {Elapsed}ms",
                    host, port, true, stopwatch.ElapsedMilliseconds);
                return new TcpProbeResult(host, port, true, tlsNegotiated, banner,
                    stopwatch.Elapsed, null, $"Connected to {address} within {ConnectTimeout.TotalSeconds}s.");
            }
            catch (SocketException ex)
            {
                lastError = ex;
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                lastError = new SocketException((int)SocketError.TimedOut);
            }
        }

        stopwatch.Stop();
        return new TcpProbeResult(host, port, false, false, null, stopwatch.Elapsed,
            "No connection could be established on this port.",
            $"All {resolved.Count} pinned address(es) failed for {host}:{port}: {lastError?.GetType().Name}");
    }

    private static ProtocolKind ProtocolFor(int port) => port switch
    {
        443 => ProtocolKind.Https,
        80 => ProtocolKind.Http,
        _ => ProtocolKind.Tcp
    };

    private static bool LooksLikeTlsPort(int port) => port is 443 or 8443 or 9443;

    private static async Task<string?> TryReadBannerAsync(NetworkStream stream, CancellationToken cancellationToken)
    {
        if (!stream.DataAvailable && !stream.CanRead) return null;

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        cts.CancelAfter(TimeSpan.FromMilliseconds(1200));
        var buffer = new byte[MaxBannerBytes];
        try
        {
            var read = await stream.ReadAsync(buffer.AsMemory(0, buffer.Length), cts.Token);
            if (read <= 0) return null;
            return Encoding.UTF8.GetString(buffer, 0, read);
        }
        catch (OperationCanceledException)
        {
            return null; // Silence is common for HTTP servers; not an error.
        }
    }
}

/// <summary>
/// Evidence-grade TLS handshake inspection. Performs multiple handshakes with forced protocol
/// versions to determine which protocol versions the endpoint actually accepts, and captures
/// certificate chain problems without ever trusting the target.
/// </summary>
public sealed class TlsHandshakeProbe(IScopeValidator scopeValidator, IDnsGate dnsGate)
{
    public async Task<IReadOnlyList<SslProtocols>> ProbeAcceptedVersionsAsync(string host, int port,
        CancellationToken cancellationToken)
    {
        var accepted = new List<SslProtocols>();
        // Deliberately probing deprecated protocol versions is the point of this check:
        // we must learn whether the TARGET still accepts them. The obsoletion applies to
        // clients using these versions in production traffic, not to capability detection.
#pragma warning disable SYSLIB0039
        foreach (var version in new[]
                 {
                     SslProtocols.Tls13, SslProtocols.Tls12, SslProtocols.Tls11, SslProtocols.Tls
                 })
        {
#pragma warning restore SYSLIB0039
            if (await TryHandshakeAsync(host, port, version, cancellationToken).ConfigureAwait(false))
            {
                accepted.Add(version);
            }
        }
        return accepted;
    }

    /// <summary>Natural negotiation (no forced version): yields what modern clients get.</summary>
    public async Task<TlsProbeResult> ProbeNaturalAsync(string host, int port, CancellationToken cancellationToken)
    {
        var verdict = scopeValidator.Evaluate(new TargetCandidate(host, port,
            port == 443 ? ProtocolKind.Https : ProtocolKind.Tls, null));
        if (!verdict.Allowed)
        {
            throw ActException.FailClosed(ErrorCategory.Scope, verdict.SafeMessage, verdict.DiagnosticDetail);
        }
        var verified = await dnsGate.ResolveVerifiedAsync(host, cancellationToken);
        var address = verified[0];

        var errors = new List<string>();
        var chainSubjects = new List<string>();
        var stopwatch = System.Diagnostics.Stopwatch.StartNew();

        using var tcp = new TcpClient(address.AddressFamily);
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        cts.CancelAfter(TimeSpan.FromSeconds(6));
        await tcp.ConnectAsync(address, port, cts.Token);

        await using var networkStream = tcp.GetStream();
        using var ssl = new SslStream(networkStream, leaveInnerStreamOpen: false,
            userCertificateValidationCallback: (_, cert, chain, policyErrors) =>
            {
                if (cert is X509Certificate2 x509) Capture(x509, chain, policyErrors, errors, chainSubjects);

                // Observe-only acceptance: the scope validator and DNS gate have already
                // authorized this exact endpoint, and aborting on trust failures would hide
                // precisely the certificate state this probe exists to inspect. Nothing is
                // trusted by this decision - the captured chain errors travel with the result
                // and drive the trust findings.
                return true;
            });

        try
        {
            await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
            {
                TargetHost = host,
                EnabledSslProtocols = SslProtocols.None
            }, cts.Token);
            stopwatch.Stop();

            var suite = ssl.NegotiatedCipherSuite.ToString();
            return new TlsProbeResult(host, port, true, ssl.SslProtocol,
                suite,
                InferStrengthBits(suite),
                CertificateOrNull(ssl),
                chainSubjects,
                errors,
                stopwatch.Elapsed,
                null);
        }
        catch (AuthenticationException)
        {
            stopwatch.Stop();
            return new TlsProbeResult(host, port, false, null, null, null, null,
                chainSubjects, errors, stopwatch.Elapsed,
                "TLS handshake failed during natural negotiation.");
        }
        catch (System.IO.IOException)
        {
            stopwatch.Stop();
            return new TlsProbeResult(host, port, false, null, null, null, null,
                chainSubjects, errors, stopwatch.Elapsed,
                "The connection failed during the TLS exchange.");
        }
    }

    private async Task<bool> TryHandshakeAsync(string host, int port, SslProtocols forceVersion,
        CancellationToken cancellationToken)
    {
        try
        {
            var verified = await dnsGate.ResolveVerifiedAsync(host, cancellationToken);
            var address = verified[0];
            using var tcp = new TcpClient(address.AddressFamily);
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            cts.CancelAfter(TimeSpan.FromSeconds(5));
            await tcp.ConnectAsync(address, port, cts.Token);
            await using var networkStream = tcp.GetStream();
            using var ssl = new SslStream(networkStream, leaveInnerStreamOpen: false,
                (_, _, _, _) => true); // Observe-only acceptance for capability probing.
            await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
            {
                TargetHost = host,
                EnabledSslProtocols = forceVersion
            }, cts.Token);
            return ssl.SslProtocol != SslProtocols.None;
        }
        catch (Exception ex) when (ex is AuthenticationException or IOException or SocketException
            or OperationCanceledException or PlatformNotSupportedException)
        {
            return false;
        }
    }

    private void Capture(X509Certificate2 certificate, X509Chain? chain, SslPolicyErrors policyErrors,
        List<string> errors, List<string> subjects)
    {
        subjects.Add(certificate.Subject);
        subjects.Add($"issuer={certificate.Issuer}");
        subjects.Add($"notAfter={certificate.NotAfter.ToString("O")}");

        if (policyErrors.HasFlag(SslPolicyErrors.RemoteCertificateNotAvailable))
        {
            errors.Add("RemoteCertificateNotAvailable");
        }
        if (policyErrors.HasFlag(SslPolicyErrors.RemoteCertificateNameMismatch))
        {
            errors.Add("RemoteCertificateNameMismatch");
        }
        if (policyErrors.HasFlag(SslPolicyErrors.RemoteCertificateChainErrors) && chain is not null)
        {
            foreach (var status in chain.ChainStatus)
            {
                if (status.Status != X509ChainStatusFlags.NoError)
                {
                    errors.Add(status.StatusInformation.Trim());
                }
            }
        }
    }

    /// <summary>Best-effort strength inference from the negotiated suite name; null when unknown.</summary>
    private static int? InferStrengthBits(string? cipherSuite)
    {
        if (string.IsNullOrEmpty(cipherSuite)) return null;
        if (cipherSuite.Contains("AES_256", StringComparison.OrdinalIgnoreCase) ||
            cipherSuite.Contains("CHACHA20_POLY1305", StringComparison.OrdinalIgnoreCase)) return 256;
        if (cipherSuite.Contains("AES_128", StringComparison.OrdinalIgnoreCase)) return 128;
        return null;
    }

    private static X509Certificate2? CertificateOrNull(SslStream stream) =>
        stream.RemoteCertificate is X509Certificate2 cert ? cert : null;
}
