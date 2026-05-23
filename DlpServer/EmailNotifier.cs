using System;
using System.Net;
using System.Net.Mail;
using System.Threading;

namespace ZavetSec.DlpServer;

/// <summary>
/// Sends email alerts via SMTP when alert events are received.
/// Configure in appsettings.json under "Email" section.
/// Supports TLS (port 587) and SSL (port 465).
/// Rate-limited: max one email per host+module per 5 minutes.
/// </summary>
public class EmailNotifier
{
    private readonly EmailConfig _cfg;
    private readonly System.Collections.Concurrent.ConcurrentDictionary<string, DateTime> _lastSent = new();
    private const int RateLimitMinutes = 5;

    public EmailNotifier(EmailConfig cfg) => _cfg = cfg;

    public bool IsConfigured =>
        !string.IsNullOrWhiteSpace(_cfg.SmtpHost) &&
        !string.IsNullOrWhiteSpace(_cfg.From) &&
        !string.IsNullOrWhiteSpace(_cfg.To);

    public void SendAlert(string host, string module, string msg, string data)
    {
        if (!IsConfigured) return;

        // Rate limiting per host+module
        string key = $"{host}:{module}";
        if (_lastSent.TryGetValue(key, out var last) &&
            (DateTime.UtcNow - last).TotalMinutes < RateLimitMinutes) return;
        _lastSent[key] = DateTime.UtcNow;

        // Send in background — never block the ingest pipeline
        ThreadPool.QueueUserWorkItem(_ =>
        {
            try
            {
                using var client = new SmtpClient(_cfg.SmtpHost, _cfg.SmtpPort);
                client.EnableSsl             = _cfg.EnableSsl;
                client.DeliveryMethod        = SmtpDeliveryMethod.Network;
                client.UseDefaultCredentials = false;
                if (!string.IsNullOrWhiteSpace(_cfg.Username))
                    client.Credentials = new NetworkCredential(_cfg.Username, _cfg.Password);

                string subject = $"[ZavetSec DLP] {module} — {host}";
                string body    = $"Host:    {host}\n" +
                                 $"Module:  {module}\n" +
                                 $"Message: {msg}\n" +
                                 $"Data:    {data}\n" +
                                 $"Time:    {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss} UTC\n\n" +
                                 $"Open dashboard: https://YOUR-SERVER:5001";

                using var mail = new MailMessage(_cfg.From, _cfg.To, subject, body);
                client.Send(mail);
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[EMAIL] Send failed: {ex.Message}");
            }
        });
    }
}
