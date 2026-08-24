
using System.Diagnostics;
using ACT.Contracts;

namespace ACT.Network;

/// <summary>
/// Token-bucket rate limiter. Capacity is one second worth of tokens at the configured rate,
/// so bursts can never exceed one second of requests. Thread-safe and cancellation-aware.
/// </summary>
public sealed class TokenBucketRateLimiter : IRateLimiter
{
    private readonly double _tokensPerSecond;
    private readonly double _capacity;
    private readonly object _sync = new();
    private double _tokens;
    private long _lastTicks;

    public TokenBucketRateLimiter(double tokensPerSecond)
    {
        if (!double.IsFinite(tokensPerSecond) || tokensPerSecond <= 0)
        {
            throw ActException.FailClosed(ErrorCategory.Configuration,
                "The request rate limit must be a positive number.",
                $"RateLimiter constructed with rate {tokensPerSecond}.");
        }
        _tokensPerSecond = tokensPerSecond;
        _capacity = Math.Max(1.0, Math.Ceiling(tokensPerSecond));
        _tokens = 1.0;
        _lastTicks = Stopwatch.GetTimestamp();
    }

    public async ValueTask WaitForTokenAsync(CancellationToken cancellationToken)
    {
        while (true)
        {
            var waitMilliseconds = 0;
            lock (_sync)
            {
                Refill();
                if (_tokens >= 1.0)
                {
                    _tokens -= 1.0;
                    return;
                }
                var secondsForNextToken = (1.0 - _tokens) / _tokensPerSecond;
                waitMilliseconds = (int)Math.Clamp(Math.Ceiling(secondsForNextToken * 1000), 1, 200);
            }

            await Task.Delay(waitMilliseconds, cancellationToken);
        }
    }

    private void Refill()
    {
        var now = Stopwatch.GetTimestamp();
        var elapsedSeconds = (now - _lastTicks) / (double)Stopwatch.Frequency;
        if (elapsedSeconds <= 0) return;
        _tokens = Math.Min(_capacity, _tokens + elapsedSeconds * _tokensPerSecond);
        _lastTicks = now;
    }
}

/// <summary>Composite limiter: waits on every registered limiter in deterministic order.</summary>
public sealed class CompositeRateLimiter(IReadOnlyList<IRateLimiter> limiters) : IRateLimiter
{
    public async ValueTask WaitForTokenAsync(CancellationToken cancellationToken)
    {
        foreach (var limiter in limiters)
        {
            await limiter.WaitForTokenAsync(cancellationToken);
        }
    }
}
