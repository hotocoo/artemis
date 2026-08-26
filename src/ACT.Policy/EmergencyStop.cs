namespace ACT.Policy;

/// <summary>
/// Thread-safe emergency-stop latch. Once armed the latch stays armed (the first reason wins)
/// until an operator disarms. The exposed token source is cancelled on arm and replaced with a
/// fresh, non-cancelled source on disarm, so followers observe exactly the latch state.
/// Superseded sources are RETIRED, not disposed: any handle this latch ever handed out stays
/// valid until the latch itself is disposed, so a follower racing a disarm can query its token,
/// register callbacks, or cancel without ever observing ObjectDisposedException.
/// </summary>
public sealed class EmergencyStop : IDisposable
{
    private readonly object _gate = new();
    private readonly List<CancellationTokenSource> _retired = [];
    private CancellationTokenSource _tokenSource = new();
    private string? _armedReason;
    private bool _disposed;

    /// <summary>Gets a value indicating whether the latch is currently armed.</summary>
    public bool IsArmed
    {
        get { lock (_gate) { return _armedReason is not null; } }
    }

    /// <summary>Gets the reason recorded when the latch was armed, or the empty string when not armed.</summary>
    public string Reason
    {
        get { lock (_gate) { return _armedReason ?? string.Empty; } }
    }

    /// <summary>Gets the active token source; its token is cancelled while armed and fresh after disarm.</summary>
    public CancellationTokenSource TokenSource
    {
        get { lock (_gate) { return _tokenSource; } }
    }

    /// <summary>Arms the latch. The first reason is retained; repeated arms keep it and keep the token cancelled.</summary>
    public void Arm(string reason)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(reason);
        CancellationTokenSource source;
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            _armedReason ??= reason.Trim();
            source = _tokenSource;
        }

        try
        {
            source.Cancel();
        }
        catch (ObjectDisposedException)
        {
            // Lost a race with Disarm: the latch was reset, so there is nothing left to cancel.
        }
    }

    /// <summary>
    /// Disarms the latch and issues a fresh cancellation token source.
    /// <paramref name="actor"/> records who disarmed, for audit trails. The superseded source
    /// is retired, not disposed, so handles already handed out stay usable.
    /// </summary>
    public void Disarm(string actor)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(actor);
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            _retired.Add(_tokenSource);
            _tokenSource = new CancellationTokenSource();
            _armedReason = null;
        }
    }

    /// <summary>Disposes every source this latch ever created; the latch cannot be used afterwards.</summary>
    public void Dispose()
    {
        CancellationTokenSource active;
        CancellationTokenSource[] retired;
        lock (_gate)
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            active = _tokenSource;
            retired = [.. _retired];
            _retired.Clear();
        }

        foreach (var source in retired)
        {
            source.Dispose();
        }

        // The active source dies last and stays installed, preserving the pre-existing
        // post-dispose contract: touching TokenSource afterwards fails with ObjectDisposedException.
        active.Dispose();
    }
}
