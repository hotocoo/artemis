using System.Globalization;
using ACT.Contracts;

namespace ACT.Lab;

/// <summary>Parsed command-line options controlling the lab's loopback listeners and administrative token.</summary>
public sealed record LabRunOptions(int HttpPort, int? HttpsPort, int? HttpsExpiredPort, string LabToken)
{
    /// <summary>True when at least one HTTPS listener was requested.</summary>
    public bool HasHttpsListeners => HttpsPort.HasValue || HttpsExpiredPort.HasValue;

    /// <summary>Every loopback origin this lab instance can legitimately claim as its own.</summary>
    public IReadOnlyList<string> OwnOrigins()
    {
        var origins = new List<string> { $"http://127.0.0.1:{HttpPort}" };
        if (HttpsPort is { } httpsPort)
        {
            origins.Add($"https://127.0.0.1:{httpsPort}");
        }

        if (HttpsExpiredPort is { } expiredPort)
        {
            origins.Add($"https://127.0.0.1:{expiredPort}");
        }

        return origins;
    }

    /// <summary>Parses --port, --https-port, --https-expired-port, and --lab-token; fails closed on anything malformed.</summary>
    public static LabRunOptions Parse(IReadOnlyList<string> arguments)
    {
        var httpPort = 47390;
        int? httpsPort = null;
        int? httpsExpiredPort = null;
        string? labToken = null;

        for (var index = 0; index < arguments.Count; index++)
        {
            var name = arguments[index];
            string value;
            var inlineSeparator = name.IndexOf('=');
            if (inlineSeparator >= 0)
            {
                value = name[(inlineSeparator + 1)..];
                name = name[..inlineSeparator];
            }
            else
            {
                if (index + 1 >= arguments.Count)
                {
                    throw MissingValue(name);
                }

                value = arguments[++index];
            }

            switch (name.ToLowerInvariant())
            {
                case "--port":
                    httpPort = ParsePort(value, name);
                    break;
                case "--https-port":
                    httpsPort = ParsePort(value, name);
                    break;
                case "--https-expired-port":
                    httpsExpiredPort = ParsePort(value, name);
                    break;
                case "--lab-token":
                    labToken = RequireToken(value);
                    break;
                default:
                    throw FailClosed($"unknown option '{name}'.");
            }
        }

        return new LabRunOptions(httpPort, httpsPort, httpsExpiredPort, labToken ?? LabTokens.NewToken());
    }

    private static int ParsePort(string value, string optionName)
    {
        if (!int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var port) || port is < 1 or > 65535)
        {
            throw FailClosed($"option '{optionName}' needs a TCP port in 1..65535.");
        }

        return port;
    }

    private static string RequireToken(string value) =>
        string.IsNullOrWhiteSpace(value) ? throw FailClosed("option '--lab-token' needs a non-empty token.") : value;

    private static ActException MissingValue(string name) => FailClosed($"option '{name}' is missing its value.");

    private static ActException FailClosed(string diagnosticDetail) =>
        ActException.FailClosed(ErrorCategory.Configuration, "A lab command-line option is invalid.", diagnosticDetail);
}
