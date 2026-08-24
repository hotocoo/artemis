using ACT.Contracts;
using ACT.Scope;

namespace ACT.Network.Checks;

/// <summary>
/// Minimal TCP reachability surface consumed by network checks. Isolates check logic from
/// concrete socket plumbing so probing remains centralized in <see cref="TcpServiceProbe"/>.
/// </summary>
public interface ITcpProbe
{
    /// <summary>Probes one host:port and returns a bounded, evidence-grade result.</summary>
    Task<TcpProbeResult> ProbeAsync(string host, int port, CancellationToken cancellationToken);
}

/// <summary>Adapts the shared <see cref="TcpServiceProbe"/> to <see cref="ITcpProbe"/>.</summary>
public sealed class TcpServiceProbeAdapter : ITcpProbe
{
    private readonly TcpServiceProbe _probe;

    /// <summary>Initializes the adapter and fails closed when the underlying probe is missing.</summary>
    public TcpServiceProbeAdapter(TcpServiceProbe probe)
    {
        _probe = probe ?? throw ActException.FailClosed(
            ErrorCategory.Internal,
            "The TCP service probe dependency was not configured.",
            "TcpServiceProbeAdapter received a null TcpServiceProbe.");
    }

    /// <inheritdoc />
    public async Task<TcpProbeResult> ProbeAsync(string host, int port, CancellationToken cancellationToken) =>
        await _probe.ProbeAsync(host, port, cancellationToken).ConfigureAwait(false);
}

/// <summary>
/// Authorized collaborators required by network discovery checks. Wired once at the
/// composition root; every dependency is mandatory and validated eagerly.
/// </summary>
public sealed record DiscoveryServices
{
    /// <summary>Scope authority consulted before any contact attempt.</summary>
    public IScopeValidator Validator { get; }

    /// <summary>DNS authorization gate supplying pinned, scope-verified addresses.</summary>
    public IDnsGate Gate { get; }

    /// <summary>TCP probing implementation used for every port contact.</summary>
    public ITcpProbe Probe { get; }

    /// <summary>Initializes the bundle and fails closed on any missing dependency.</summary>
    public DiscoveryServices(IScopeValidator validator, IDnsGate gate, ITcpProbe probe)
    {
        Validator = Required(validator, nameof(validator));
        Gate = Required(gate, nameof(gate));
        Probe = Required(probe, nameof(probe));
    }

    private static T Required<T>(T value, string name) where T : class =>
        value ?? throw ActException.FailClosed(
            ErrorCategory.Internal,
            "A required network discovery dependency was not configured.",
            "DiscoveryServices dependency '" + name + "' is null.");
}
