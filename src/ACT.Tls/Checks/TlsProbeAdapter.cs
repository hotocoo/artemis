using System.Security.Authentication;
using ACT.Contracts;
using ACT.Network;
using ACT.Scope;

namespace ACT.Tls.Checks;

/// <summary>
/// TLS inspection surface consumed by TLS checks; isolates check logic from concrete
/// handshake plumbing so probing remains centralized in <see cref="TlsHandshakeProbe"/>.
/// </summary>
public interface ITlsProbe
{
    /// <summary>Performs one natural negotiation and returns evidence-grade results.</summary>
    Task<TlsProbeResult> ProbeNaturalAsync(string host, int port, CancellationToken cancellationToken);

    /// <summary>Returns every protocol version the endpoint accepts via forced-version handshakes.</summary>
    Task<IReadOnlyList<SslProtocols>> ProbeAcceptedVersionsAsync(string host, int port, CancellationToken cancellationToken);
}

/// <summary>Adapts the shared <see cref="TlsHandshakeProbe"/> to <see cref="ITlsProbe"/>.</summary>
public sealed class TlsHandshakeProbeAdapter : ITlsProbe
{
    private readonly TlsHandshakeProbe _probe;

    /// <summary>Initializes the adapter and fails closed when the underlying probe is missing.</summary>
    public TlsHandshakeProbeAdapter(TlsHandshakeProbe probe)
    {
        _probe = probe ?? throw ActException.FailClosed(
            ErrorCategory.Internal,
            "The TLS handshake probe dependency was not configured.",
            "TlsHandshakeProbeAdapter received a null TlsHandshakeProbe.");
    }

    /// <inheritdoc />
    public async Task<TlsProbeResult> ProbeNaturalAsync(string host, int port, CancellationToken cancellationToken) =>
        await _probe.ProbeNaturalAsync(host, port, cancellationToken).ConfigureAwait(false);

    /// <inheritdoc />
    public async Task<IReadOnlyList<SslProtocols>> ProbeAcceptedVersionsAsync(string host, int port, CancellationToken cancellationToken) =>
        await _probe.ProbeAcceptedVersionsAsync(host, port, cancellationToken).ConfigureAwait(false);
}

/// <summary>
/// Authorized collaborators required by TLS checks. Wired once at the composition root;
/// every dependency is mandatory and validated eagerly.
/// </summary>
public sealed record TlsServices
{
    /// <summary>Scope authority consulted before any contact attempt.</summary>
    public IScopeValidator Validator { get; }

    /// <summary>DNS authorization gate supplying pinned, scope-verified addresses.</summary>
    public IDnsGate Gate { get; }

    /// <summary>TLS inspection implementation used for every handshake.</summary>
    public ITlsProbe Probe { get; }

    /// <summary>Initializes the bundle and fails closed on any missing dependency.</summary>
    public TlsServices(IScopeValidator validator, IDnsGate gate, ITlsProbe probe)
    {
        Validator = Required(validator, nameof(validator));
        Gate = Required(gate, nameof(gate));
        Probe = Required(probe, nameof(probe));
    }

    private static T Required<T>(T value, string name) where T : class =>
        value ?? throw ActException.FailClosed(
            ErrorCategory.Internal,
            "A required TLS check dependency was not configured.",
            "TlsServices dependency '" + name + "' is null.");
}
