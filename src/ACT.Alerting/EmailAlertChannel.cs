using System.Net.Mail;

namespace ACT.Alerting;

public class EmailAlertChannel : IAlertChannel
{
    private readonly SmtpClient _smtp;
    private readonly string _from;
    private readonly string _to;

    public string ChannelType => "email";

    public EmailAlertChannel(SmtpClient smtp, string from, string to)
    {
        _smtp = smtp ?? throw new ArgumentNullException(nameof(smtp));
        _from = from ?? throw new ArgumentNullException(nameof(from));
        _to = to ?? throw new ArgumentNullException(nameof(to));
    }

    public async Task SendAlertAsync(AlertPayload payload, CancellationToken cancellationToken)
    {
        var body = $"Subject: {payload.Title}\n\n{payload.Message}\n\n";
        if (payload.Findings.Count > 0)
        {
            body += $"Findings ({payload.Findings.Count}):\n";
            foreach (var f in payload.Findings.Take(20))
            {
                body += $"\n[{f.Severity}] {f.Title} ({f.Id})\n{f.Description}\n";
                if (!string.IsNullOrEmpty(f.Recommendation))
                {
                    body += $"Recommendation: {f.Recommendation}\n";
                }
            }
        }
        if (payload.AssessmentUrl != null)
        {
            body += $"\nView full report: {payload.AssessmentUrl}\n";
        }

        var message = new MailMessage(_from, _to)
        {
            Subject = payload.Title,
            Body = body,
            IsBodyHtml = false
        };

        await _smtp.SendMailAsync(message, cancellationToken);
    }
}
