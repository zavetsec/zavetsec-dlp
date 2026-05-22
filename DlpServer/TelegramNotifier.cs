using System.Text;
using System.Text.Json;

namespace ZavetSec.DlpServer;

/// <summary>
/// Отправляет алерты в Telegram-чат через Bot API.
/// Настройка в appsettings.json:
///   "Telegram": { "BotToken": "123:ABC...", "ChatId": "-100123456" }
///
/// Как получить BotToken: создать бота через @BotFather.
/// Как получить ChatId: написать боту, открыть
///   https://api.telegram.org/bot{TOKEN}/getUpdates
/// </summary>
public class TelegramNotifier
{
    private readonly string? _botToken;
    private readonly string? _chatId;
    private readonly HttpClient _http;
    private readonly ILogger<TelegramNotifier> _logger;
    private readonly IConfiguration _config;

    // Rate-limit: не чаще 1 раза в 30 сек на host+module
    private readonly Dictionary<string, DateTime> _lastSent = new();
    private readonly TimeSpan _rateLimit = TimeSpan.FromSeconds(30);

    public bool IsConfigured => !string.IsNullOrEmpty(_botToken) && !string.IsNullOrEmpty(_chatId);

    public TelegramNotifier(IConfiguration config, ILogger<TelegramNotifier> logger)
    {
        _botToken = config["Telegram:BotToken"];
        _chatId   = config["Telegram:ChatId"];
        _logger   = logger;
        _config   = config;
        _http     = new HttpClient { Timeout = TimeSpan.FromSeconds(10) };
    }

    // Модули по умолчанию (если AlertModules не задан в конфиге)
    private static readonly string[] DefaultAlertModules = {
        "USB_ALERT", "CLIPBOARD_ALERT", "PROCESS_ALERT",
        "DNS_ALERT", "NETWORK_ALERT", "FILE_ALERT"
    };

    /// Fire-and-forget уведомление об алерте
    public void NotifyAlert(StoredEvent ev)
    {
        if (!IsConfigured) return;

        // Проверяем фильтр модулей из конфига
        var configured = _config.GetSection("Telegram:AlertModules").Get<string[]>();
        var allowedModules = (configured != null && configured.Length > 0)
            ? configured : DefaultAlertModules;

        bool matches = allowedModules.Any(m =>
            ev.Module.Equals(m, StringComparison.OrdinalIgnoreCase) ||
            ev.Module.StartsWith(m, StringComparison.OrdinalIgnoreCase));

        // Также пропускаем если настроен SendAllAlerts=true
        bool sendAll = _config.GetValue<bool>("Telegram:SendAllAlerts", false);
        if (!sendAll && !matches) return;

        string key = $"{ev.Host}|{ev.Module}";
        lock (_lastSent)
        {
            if (_lastSent.TryGetValue(key, out var last) &&
                (DateTime.UtcNow - last) < _rateLimit) return;
            _lastSent[key] = DateTime.UtcNow;
        }

        string emoji = ev.Module switch
        {
            _ when ev.Module.Contains("USB")       => "🔌",
            _ when ev.Module.Contains("CLIPBOARD") => "📋",
            _ when ev.Module.Contains("PROCESS")   => "⚙️",
            _ when ev.Module.Contains("DNS")       => "🌐",
            _ when ev.Module.Contains("NETWORK")   => "🌐",
            _ when ev.Module.Contains("FILE")      => "📁",
            _                                       => "🚨"
        };

        string data  = string.IsNullOrEmpty(ev.Data) ? "" :
            ev.Data.Length > 200 ? ev.Data[..200] + "…" : ev.Data;

        // FIX: escape-последовательности Markdown — используем \\ в обычных строках
        string text =
            emoji + " *ZavetSec DLP Alert*\n\n" +
            "Host: `" + Esc(ev.Host) + "`\n" +
            "User: `" + Esc(ev.User) + "`\n" +
            "Module: `" + Esc(ev.Module) + "`\n" +
            "Event: " + Esc(ev.Msg) + "\n" +
            (string.IsNullOrEmpty(data) ? "" : "`" + Esc(data) + "`\n") +
            "\n" + ev.Ts;

        _ = Task.Run(async () =>
        {
            try
            {
                string url  = $"https://api.telegram.org/bot{_botToken}/sendMessage";
                string body = JsonSerializer.Serialize(new
                {
                    chat_id    = _chatId,
                    text,
                    parse_mode = "Markdown"
                });
                await _http.PostAsync(url,
                    new StringContent(body, Encoding.UTF8, "application/json"));
            }
            catch (Exception ex)
            {
                _logger.LogWarning("Telegram send failed: {Msg}", ex.Message);
            }
        });
    }

    public async Task<bool> SendTest()
    {
        if (!IsConfigured) return false;
        try
        {
            string url  = $"https://api.telegram.org/bot{_botToken}/sendMessage";
            string body = JsonSerializer.Serialize(new
            {
                chat_id    = _chatId,
                text       = "✅ ZavetSec DLP: Telegram-уведомления работают корректно.",
                parse_mode = "Markdown"
            });
            var r = await _http.PostAsync(url,
                new StringContent(body, Encoding.UTF8, "application/json"));
            return r.IsSuccessStatusCode;
        }
        catch { return false; }
    }

    // FIX: используем Replace с двумя аргументами, без escape-проблем
    private static string Esc(string? s)
    {
        if (s == null) return "";
        return s
            .Replace("_",  "\\_")
            .Replace("*",  "\\*")
            .Replace("[",  "\\[")
            .Replace("`",  "\\`");
    }
}
