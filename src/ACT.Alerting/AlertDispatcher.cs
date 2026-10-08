namespace ACT.Alerting;

public class AlertDispatcher
{
    private readonly IReadOnlyList<IAlertChannel> _channels;

    public AlertDispatcher(IReadOnlyList<IAlertChannel> channels)
    {
        _channels = channels ?? throw new ArgumentNullException(nameof(channels));
    }

    public async Task DispatchAsync(AlertPayload payload, CancellationToken cancellationToken)
    {
        var tasks = _channels
            .Select(ch => SendWithRetryAsync(ch, payload, cancellationToken))
            .ToArray();

        await Task.WhenAll(tasks);
    }

    private static async Task SendWithRetryAsync(IAlertChannel channel, AlertPayload payload, CancellationToken cancellationToken)
    {
        int attempt = 0;
        Exception? lastException = null;

        while (attempt < 3)
        {
            try
            {
                await channel.SendAlertAsync(payload, cancellationToken);
                return;
            }
            catch (Exception ex) when (attempt < 2)
            {
                lastException = ex;
                attempt++;
                await Task.Delay(TimeSpan.FromSeconds(Math.Pow(2, attempt)), cancellationToken);
            }
        }

        // Re-throw on final failure so callers can log
        throw lastException ?? new InvalidOperationException($"Failed to send alert via {channel.ChannelType}");
    }
}
