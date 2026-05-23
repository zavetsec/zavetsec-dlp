using System.Linq;
using System.Text.Json;
using ZavetSec.DlpServer;

var builder = WebApplication.CreateBuilder(args);

string apiKey = builder.Configuration["DlpServer:ApiKey"] ?? "change-me";
string dbPath = builder.Configuration["DlpServer:DbPath"]
                ?? Path.Combine(Environment.GetFolderPath(
                    Environment.SpecialFolder.CommonApplicationData),
                    "ZavetSec", "DLP", "events.db");
string ssDir  = builder.Configuration["DlpServer:ScreenshotDir"]
                ?? Path.Combine(Path.GetDirectoryName(dbPath)!, "screenshots");
int maxRet    = int.TryParse(
    builder.Configuration["DlpServer:MaxEventsReturn"], out int m) ? m : 500;

// ── HTTPS: авто-генерация самоподписанного сертификата ───────────────────
// Создаёт server.pfx при первом запуске. Сертификат на 10 лет.
// Агент использует HttpClientHandler с отключённой проверкой (корпоративная сеть).
static void EnsureCertificate(string certPath, string certPassword)
{
    if (File.Exists(certPath)) return;

    try
    {
        Directory.CreateDirectory(Path.GetDirectoryName(certPath)!);

        using var rsa = System.Security.Cryptography.RSA.Create(2048);
        var req = new System.Security.Cryptography.X509Certificates.CertificateRequest(
            "CN=ZavetSecDLP,O=ZavetSec,C=RU",
            rsa,
            System.Security.Cryptography.HashAlgorithmName.SHA256,
            System.Security.Cryptography.RSASignaturePadding.Pkcs1);

        req.CertificateExtensions.Add(
            new System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension(false, false, 0, false));
        req.CertificateExtensions.Add(
            new System.Security.Cryptography.X509Certificates.X509KeyUsageExtension(
                System.Security.Cryptography.X509Certificates.X509KeyUsageFlags.DigitalSignature |
                System.Security.Cryptography.X509Certificates.X509KeyUsageFlags.KeyEncipherment, false));
        req.CertificateExtensions.Add(
            new System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension(
                new System.Security.Cryptography.OidCollection {
                    new System.Security.Cryptography.Oid("1.3.6.1.5.5.7.3.1") // TLS Server Auth
                }, false));

        // SAN: localhost + IP 0.0.0.0 + имя машины
        var sanBuilder = new System.Security.Cryptography.X509Certificates.SubjectAlternativeNameBuilder();
        sanBuilder.AddDnsName("localhost");
        sanBuilder.AddDnsName(Environment.MachineName);
        sanBuilder.AddIpAddress(System.Net.IPAddress.Loopback);
        sanBuilder.AddIpAddress(System.Net.IPAddress.IPv6Loopback);
        req.CertificateExtensions.Add(sanBuilder.Build());

        var cert = req.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddYears(10));

        byte[] pfx = cert.Export(
            System.Security.Cryptography.X509Certificates.X509ContentType.Pfx,
            certPassword);
        File.WriteAllBytes(certPath, pfx);

        Console.WriteLine($"[HTTPS] Self-signed certificate created: {certPath}");
        Console.WriteLine($"[HTTPS] Valid until: {cert.NotAfter:yyyy-MM-dd}");
    }
    catch (Exception ex)
    {
        Console.WriteLine($"[HTTPS] Certificate creation failed: {ex.Message}");
        Console.WriteLine("[HTTPS] Server will run HTTP only.");
    }
}

string certPath = builder.Configuration["Kestrel:Endpoints:Https:Certificate:Path"]
    ?? Path.Combine(Path.GetDirectoryName(dbPath)!, "server.pfx");
string certPass = builder.Configuration["Kestrel:Endpoints:Https:Certificate:Password"]
    ?? "ZavetSecDLP2026";

// Если используется дефолтный пароль — предупреждение (не блокер)
if (certPass == "ZavetSecDLP2026")
    Console.WriteLine("[SECURITY] WARNING: Using default certificate password. " +
        "Set Kestrel:Endpoints:Https:Certificate:Password in appsettings.json");

EnsureCertificate(certPath, certPass);

var store = new EventStore(dbPath, ssDir);
store.InitCommandsTable();
store.InitAuthTables();
store.RunMigrations(); // применяет все pending миграции схемы БД

builder.Services.AddSingleton(store);
builder.Services.AddSingleton<TelegramNotifier>();
builder.Services.AddSingleton<EmailNotifier>(sp =>
    new EmailNotifier(builder.Configuration.GetSection("Email").Get<EmailConfig>()
        ?? new EmailConfig()));
builder.Services.AddCors(o => o.AddDefaultPolicy(p =>
    p.AllowAnyOrigin().AllowAnyHeader().AllowAnyMethod()));

var app = builder.Build();
app.UseCors();
app.UseStaticFiles();

var telegram = app.Services.GetRequiredService<TelegramNotifier>();
var email    = app.Services.GetRequiredService<EmailNotifier>();

// ── In-memory rate limiter для агентских эндпоинтов ─────────────────────
// Ограничение: 1000 запросов в минуту на IP (защита от flooding)
var rateLimitStore = new System.Collections.Concurrent.ConcurrentDictionary<string,
    (int Count, DateTime WindowStart)>();

// Cleanup task - каждые 5 минут чистим старые записи и login_attempts
_ = Task.Run(async () => {
    while (true) {
        await Task.Delay(TimeSpan.FromMinutes(5));
        var cutoff = DateTime.UtcNow.AddMinutes(-1);
        foreach (var kv in rateLimitStore)
            if (kv.Value.WindowStart < cutoff) rateLimitStore.TryRemove(kv.Key, out _);
        try { store.CleanupOldAttempts(); } catch { }
    }
});

// ── Middleware ────────────────────────────────────────────────────────────
app.Use(async (ctx, next) =>
{
    string path   = ctx.Request.Path.Value ?? "";
    string method = ctx.Request.Method;

    bool isPublic =
        path == "/api/auth/login" ||
        path == "/api/auth/me"    ||   // token validation — works without session
        path == "/" || path.StartsWith("/assets/") ||
        (path.StartsWith("/api/screenshots/") && path.EndsWith("/image")) ||
        !path.StartsWith("/api/");
    // Note: /api/auth/change-password and /api/auth/logout require a valid session

    bool isAgentEndpoint =
        path.StartsWith("/api/ingest") ||
        path.StartsWith("/api/screenshots/upload") ||
        path.StartsWith("/api/commands/result") ||
        (method == "GET" && path.StartsWith("/api/commands/") &&
         !path.StartsWith("/api/commands/history"));

    if (isPublic) { await next(); return; }

    if (isAgentEndpoint)
    {
        string? key = ctx.Request.Headers["X-Api-Key"].FirstOrDefault()
                   ?? ctx.Request.Query["key"].FirstOrDefault();
        if (key != apiKey)
        {
            ctx.Response.StatusCode = 401;
            await ctx.Response.WriteAsync("Unauthorized");
            return;
        }

        // Rate limiting для агентских эндпоинтов: 1000 req/min per IP
        string agentIp = ctx.Request.Headers["X-Forwarded-For"].FirstOrDefault()
                      ?? ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        var now = DateTime.UtcNow;
        var entry = rateLimitStore.GetOrAdd(agentIp, _ => (0, now));
        if ((now - entry.WindowStart).TotalSeconds > 60)
            entry = (0, now); // новое окно
        entry = (entry.Count + 1, entry.WindowStart);
        rateLimitStore[agentIp] = entry;

        if (entry.Count > 1000)
        {
            ctx.Response.StatusCode = 429;
            ctx.Response.Headers["Retry-After"] = "60";
            await ctx.Response.WriteAsync("Rate limit exceeded");
            return;
        }

        await next(); return;
    }

    string? token = ctx.Request.Headers["Authorization"]
                        .FirstOrDefault()?.Replace("Bearer ", "")
                 ?? ctx.Request.Cookies["dlp_session"];
    var session = store.GetSession(token ?? "");
    if (session == null)
    {
        ctx.Response.StatusCode = 401;
        await ctx.Response.WriteAsJsonAsync(new { error = "Not authenticated" });
        return;
    }
    ctx.Items["session"] = session;
    await next();
});

// ═══════════════════════════════════════════════════════════════════════════
//  Auth
// ═══════════════════════════════════════════════════════════════════════════

app.MapPost("/api/auth/login", async (HttpContext ctx, EventStore db) =>
{
    try
    {
        // Получаем реальный IP (с учётом reverse proxy)
        string ip = ctx.Request.Headers["X-Forwarded-For"].FirstOrDefault()
                 ?? ctx.Connection.RemoteIpAddress?.ToString()
                 ?? "unknown";

        // Проверка брутфорса
        var (locked, secsRemaining) = db.CheckBruteForce(ip);
        if (locked)
        {
            app.Logger.LogWarning("Login blocked (brute force) from {IP}, {Secs}s remaining", ip, secsRemaining);
            ctx.Response.Headers["Retry-After"] = secsRemaining.ToString();
            return Results.Json(new {
                error = $"Слишком много попыток. Попробуйте через {secsRemaining / 60 + 1} мин.",
                retryAfter = secsRemaining
            }, statusCode: 429);
        }

        var req = await JsonSerializer.DeserializeAsync<LoginRequest>(
            ctx.Request.Body,
            new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
        if (req == null) return Results.BadRequest();

        var result = db.Login(req.Username.Trim(), req.Password);
        if (result == null)
        {
            db.RecordFailedAttempt(ip);
            app.Logger.LogWarning("Failed login for '{User}' from {IP}", req.Username, ip);
            return Results.Json(new { error = "Неверный логин или пароль" }, statusCode: 401);
        }

        db.ResetFailedAttempts(ip);
        db.WriteAudit(result.Username, ip, "LOGIN", "", $"role={result.Role}");
        app.Logger.LogInformation("Login OK: {User} ({Role}) from {IP}", result.Username, result.Role, ip);
        return Results.Ok(result);
    }
    catch (Exception ex)
    {
        app.Logger.LogError(ex, "Login error");
        return Results.StatusCode(500);
    }
});

app.MapPost("/api/auth/logout", (HttpContext ctx, EventStore db) =>
{
    string? token = ctx.Request.Headers["Authorization"]
                        .FirstOrDefault()?.Replace("Bearer ", "");
    if (token != null)
    {
        var sLogout = store.GetSession(token ?? "");
        string logoutIp = ctx.Request.Headers["X-Forwarded-For"].FirstOrDefault()
                       ?? ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        if (sLogout != null)
            db.WriteAudit(sLogout.Username, logoutIp, "LOGOUT");
        db.Logout(token);
    }
    return Results.Ok();
});

// FIX: /api/auth/me публичный эндпоинт (начинается с /api/auth/),
// поэтому middleware не устанавливает session в ctx.Items.
// Читаем токен и проверяем сессию вручную здесь.
app.MapGet("/api/auth/me", (HttpContext ctx, EventStore db) =>
{
    string? token = ctx.Request.Headers["Authorization"]
                        .FirstOrDefault()?.Replace("Bearer ", "")
                 ?? ctx.Request.Cookies["dlp_session"];
    var session = db.GetSession(token ?? "");
    if (session == null)
        return Results.Json(new { error = "Not authenticated" }, statusCode: 401);
    return Results.Ok(new { username = session.Username, role = session.Role });
});

app.MapPost("/api/auth/change-password", async (HttpContext ctx, EventStore db) =>
{
    try
    {
        var s   = ctx.Items["session"] as SessionInfo;
        var req = await JsonSerializer.DeserializeAsync<ChangePasswordRequest>(
            ctx.Request.Body,
            new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
        if (req == null) return Results.BadRequest();

        var (ok, error) = db.ChangePassword(s!.Username, req.OldPassword, req.NewPassword);
        if (!ok) return Results.BadRequest(new { error });
        string pwIp = ctx.Request.Headers["X-Forwarded-For"].FirstOrDefault()
                   ?? ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        db.WriteAudit(s!.Username, pwIp, "PASSWORD_CHANGE", s!.Username);
        return Results.Ok(new { ok = true });
    }
    catch (Exception ex)
    {
        app.Logger.LogError(ex, "Change password error");
        return Results.StatusCode(500);
    }
});

// ═══════════════════════════════════════════════════════════════════════════
//  Пользователи (только admin)
// ═══════════════════════════════════════════════════════════════════════════

app.MapGet("/api/users", (HttpContext ctx, EventStore db) =>
{
    var s = ctx.Items["session"] as SessionInfo;
    if (s?.Role != "admin")
        return Results.Json(new { error = "Forbidden" }, statusCode: 403);
    return Results.Json(db.GetUsers());
});

app.MapPost("/api/users", async (HttpContext ctx, EventStore db) =>
{
    try
    {
        var s = ctx.Items["session"] as SessionInfo;
        if (s?.Role != "admin")
            return Results.Json(new { error = "Forbidden" }, statusCode: 403);

        var req = await JsonSerializer.DeserializeAsync<CreateUserRequest>(
            ctx.Request.Body,
            new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
        if (req == null) return Results.BadRequest();

        var (ok, error) = db.CreateUser(req, s.Username);
        if (!ok) return Results.BadRequest(new { error });
        {   string cuIp = ctx.Request.Headers["X-Forwarded-For"].FirstOrDefault()
                       ?? ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown";
            db.WriteAudit(s.Username, cuIp, "USER_CREATE", req.Username, $"role={req.Role}"); }
        app.Logger.LogInformation("User created: {U} by {By}", req.Username, s.Username);
        return Results.Ok(new { created = req.Username });
    }
    catch (Exception ex)
    {
        app.Logger.LogError(ex, "Create user error");
        return Results.StatusCode(500);
    }
});

app.MapDelete("/api/users/{username}", (string username, HttpContext ctx, EventStore db) =>
{
    var s = ctx.Items["session"] as SessionInfo;
    if (s?.Role != "admin")
        return Results.Json(new { error = "Forbidden" }, statusCode: 403);
    var (ok, error) = db.DeleteUser(username, s.Username);
    if (!ok) return Results.BadRequest(new { error });
    {   string duIp = ctx.Request.Headers["X-Forwarded-For"].FirstOrDefault()
                   ?? ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        db.WriteAudit(s.Username, duIp, "USER_DELETE", username); }
    app.Logger.LogInformation("User deleted: {U} by {By}", username, s.Username);
    return Results.Ok(new { deleted = username });
});

// ═══════════════════════════════════════════════════════════════════════════
//  Telegram
// ═══════════════════════════════════════════════════════════════════════════

app.MapGet("/api/telegram/test", async (HttpContext ctx) =>
{
    var s = ctx.Items["session"] as SessionInfo;
    if (s?.Role != "admin")
        return Results.Json(new { error = "Forbidden" }, statusCode: 403);
    if (!telegram.IsConfigured)
        return Results.BadRequest(new { error =
            "Telegram не настроен. Добавьте BotToken и ChatId в appsettings.json" });
    bool ok = await telegram.SendTest();
    return ok ? Results.Ok(new { sent = true })
              : Results.BadRequest(new { error = "Ошибка отправки. Проверьте BotToken и ChatId." });
});

// Возвращает текущую конфигурацию Telegram-фильтров
// ── Email config API ──────────────────────────────────────────────────────────
app.MapGet("/api/email/config", (HttpContext ctx, IConfiguration config) =>
{
    var s = ctx.Items["session"] as SessionInfo;
    if (s?.Role != "admin") return Results.Json(new { error = "Forbidden" }, statusCode: 403);
    var ec = config.GetSection("Email");
    return Results.Ok(new {
        smtpHost   = ec["SmtpHost"] ?? "",
        smtpPort   = ec.GetValue<int>("SmtpPort", 587),
        enableSsl  = ec.GetValue<bool>("EnableSsl", true),
        username   = ec["Username"] ?? "",
        from       = ec["From"] ?? "",
        to         = ec["To"] ?? "",
        alertModules = ec.GetSection("AlertModules").Get<string[]>() ?? Array.Empty<string>(),
        configured = !string.IsNullOrWhiteSpace(ec["SmtpHost"])
    });
});

app.MapPost("/api/email/save", async (HttpContext ctx) =>
{
    var s = ctx.Items["session"] as SessionInfo;
    if (s?.Role != "admin") return Results.Json(new { error = "Forbidden" }, statusCode: 403);
    try
    {
        var req = await System.Text.Json.JsonSerializer.DeserializeAsync<System.Text.Json.JsonElement>(
            ctx.Request.Body);
        // Read and update appsettings.json
        string path = Path.Combine(AppContext.BaseDirectory, "appsettings.json");
        if (!File.Exists(path)) return Results.BadRequest(new { error = "appsettings.json not found" });
        string json = File.ReadAllText(path);
        var doc = System.Text.Json.JsonDocument.Parse(json);
        var dict = System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, System.Text.Json.JsonElement>>(json)
            ?? new();
        // Update Email section
        var emailSection = new {
            SmtpHost     = req.TryGetProperty("smtpHost", out var h) ? h.GetString() : "",
            SmtpPort     = req.TryGetProperty("smtpPort", out var p) ? p.GetInt32() : 587,
            EnableSsl    = req.TryGetProperty("enableSsl", out var ssl) && ssl.GetBoolean(),
            Username     = req.TryGetProperty("username", out var u) ? u.GetString() : "",
            Password     = req.TryGetProperty("password", out var pw) ? pw.GetString() : "",
            From         = req.TryGetProperty("from", out var f) ? f.GetString() : "",
            To           = req.TryGetProperty("to", out var t) ? t.GetString() : "",
            AlertModules = req.TryGetProperty("alertModules", out var m)
                ? m.GetString()?.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                : Array.Empty<string>(),
            SendAllAlerts = false
        };
        dict["Email"] = System.Text.Json.JsonSerializer.SerializeToElement(emailSection);
        string newJson = System.Text.Json.JsonSerializer.Serialize(dict,
            new System.Text.Json.JsonSerializerOptions { WriteIndented = true });
        File.WriteAllText(path, newJson);
        string ip = ctx.Request.Headers["X-Forwarded-For"].FirstOrDefault()
                 ?? ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        store.WriteAudit(s.Username, ip, "EMAIL_CONFIG_SAVE", "appsettings.json");
        return Results.Ok(new { saved = true });
    }
    catch (Exception ex) { return Results.BadRequest(new { error = ex.Message }); }
});

app.MapPost("/api/email/test", async (HttpContext ctx) =>
{
    var s = ctx.Items["session"] as SessionInfo;
    if (s?.Role != "admin") return Results.Json(new { error = "Forbidden" }, statusCode: 403);
    if (!email.IsConfigured) return Results.BadRequest(new { error = "Email not configured" });
    try {
        email.SendAlert("TEST", "EMAIL_TEST", "ZavetSec DLP test email", "Sent from dashboard");
        return Results.Ok(new { sent = true });
    } catch (Exception ex) { return Results.BadRequest(new { error = ex.Message }); }
});

app.MapGet("/api/telegram/config", (HttpContext ctx, IConfiguration config) =>
{
    var s = ctx.Items["session"] as SessionInfo;
    if (s?.Role != "admin")
        return Results.Json(new { error = "Forbidden" }, statusCode: 403);

    var modules    = config.GetSection("Telegram:AlertModules").Get<string[]>() ?? Array.Empty<string>();
    bool sendAll   = config.GetValue<bool>("Telegram:SendAllAlerts", false);
    bool configured = !string.IsNullOrEmpty(config["Telegram:BotToken"])
                   && !string.IsNullOrEmpty(config["Telegram:ChatId"]);

    return Results.Ok(new {
        configured,
        sendAllAlerts = sendAll,
        alertModules  = modules
    });
});

// ═══════════════════════════════════════════════════════════════════════════
//  Агентские эндпоинты (X-Api-Key)
// ═══════════════════════════════════════════════════════════════════════════

app.MapPost("/api/ingest", async (HttpContext ctx, EventStore db) =>
{
    try
    {
        var events = await JsonSerializer.DeserializeAsync<List<LogEvent>>(
            ctx.Request.Body,
            new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
        if (events is null || events.Count == 0) return Results.BadRequest("Empty batch");
        if (events.Count > 1000)                 return Results.BadRequest("Too large");
        string ingestAgentId = ctx.Request.Headers["X-Agent-Id"].FirstOrDefault() ?? "";
        db.InsertBatch(events, ingestAgentId);

        // Telegram + Email алерты
        var alertEvs = events.Where(ev =>
            ev.Module.Contains("ALERT") || ev.Module.Contains("ERROR")).ToList();

        if (telegram.IsConfigured)
            foreach (var ev in alertEvs)
                telegram.NotifyAlert(new StoredEvent {
                    Ts=ev.Ts, Host=ev.Host, User=ev.User,
                    Module=ev.Module, Msg=ev.Msg, Data=ev.Data ?? "" });

        if (email.IsConfigured)
            foreach (var ev in alertEvs)
                email.SendAlert(ev.Host, ev.Module, ev.Msg, ev.Data ?? "");
        return Results.Ok(new { accepted = events.Count });
    }
    catch (Exception ex)
    {
        app.Logger.LogError(ex, "Ingest error");
        return Results.StatusCode(500);
    }
});

app.MapPost("/api/screenshots/upload", async (HttpContext ctx, EventStore db) =>
{
    try
    {
        var upload = await JsonSerializer.DeserializeAsync<ScreenshotUpload>(
            ctx.Request.Body,
            new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
        if (upload is null || string.IsNullOrEmpty(upload.Jpeg))
            return Results.BadRequest("Empty");
        upload.AgentId = ctx.Request.Headers["X-Agent-Id"].FirstOrDefault() ?? "";
        long id = db.SaveScreenshot(upload);
        return Results.Ok(new { id });
    }
    catch (Exception ex)
    {
        app.Logger.LogError(ex, "Screenshot upload error");
        return Results.StatusCode(500);
    }
});

app.MapGet("/api/commands/{host}", (string host, HttpContext ctx, EventStore db) =>
{
    string agentId     = ctx.Request.Headers["X-Agent-Id"].FirstOrDefault() ?? "";
    string agentStatus = ctx.Request.Query["status"].FirstOrDefault() ?? "active";
    return Results.Json(db.GetPendingCommands(host, agentId, agentStatus));
});

app.MapPost("/api/commands/result", async (HttpContext ctx, EventStore db) =>
{
    try
    {
        var result = await JsonSerializer.DeserializeAsync<CommandResult>(
            ctx.Request.Body,
            new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
        if (result is null) return Results.BadRequest();
        db.ReportCommandResult(result.Id, result.Status, result.Error);

        if (result.Status == "executed")
        {
            var command = db.GetCommandById(result.Id);
            if (command != null &&
                command.Command.Equals("uninstall", StringComparison.OrdinalIgnoreCase))
            {
                string host = command.Host == "*"
                    ? ctx.Connection.RemoteIpAddress?.ToString() ?? ""
                    : command.Host;
                if (!string.IsNullOrEmpty(host))
                {
                    // Log uninstall completion BEFORE removing from hosts table
                    // Get agentId from command host header (stored in command payload or derived)
                    string uninstAgentId = ctx.Request.Headers["X-Agent-Id"].FirstOrDefault() ?? "";
                    db.InsertSystemEvent(host, "AGENT_UNINSTALLED",
                        "Agent successfully uninstalled",
                        $"cmd_id={result.Id}|agent_id={uninstAgentId}");
                    db.RemoveAgent(host, uninstAgentId);
                }
            }
        }
        return Results.Ok();
    }
    catch (Exception ex)
    {
        app.Logger.LogError(ex, "Commands result error");
        return Results.StatusCode(500);
    }
});

// ═══════════════════════════════════════════════════════════════════════════
//  Дашборд эндпоинты
// ═══════════════════════════════════════════════════════════════════════════

app.MapGet("/api/events", async (HttpContext ctx, EventStore db) =>
{
    try
    {
        var q = ctx.Request.Query;
        var f = new EventFilter {
            Module  = q["module"].FirstOrDefault(),
            Host    = q["host"].FirstOrDefault(),
            AgentId = q["agentId"].FirstOrDefault(),
            From    = q["from"].FirstOrDefault(),
            To      = q["to"].FirstOrDefault(),
            Search  = q["search"].FirstOrDefault(),
            Limit  = int.TryParse(q["limit"],  out int l) ? Math.Min(l, maxRet) : 100,
            Offset = int.TryParse(q["offset"], out int o) ? o : 0
        };
        return Results.Json(db.Query(f));
    }
    catch (Exception ex)
    {
        app.Logger.LogError(ex, "Events error");
        return Results.StatusCode(500);
    }
});

// CSV-экспорт событий
app.MapGet("/api/export/events.csv", async (HttpContext ctx, EventStore db) =>
{
    try
    {
        var q = ctx.Request.Query;
        var f = new EventFilter {
            Module  = q["module"].FirstOrDefault(),
            Host    = q["host"].FirstOrDefault(),
            AgentId = q["agentId"].FirstOrDefault(),
            From    = q["from"].FirstOrDefault(),
            To      = q["to"].FirstOrDefault(),
            Search  = q["search"].FirstOrDefault()
        };
        string csv = db.QueryCsv(f);
        ctx.Response.Headers["Content-Disposition"] =
            "attachment; filename=\"dlp-events-" +
            DateTime.UtcNow.ToString("yyyyMMdd-HHmmss") + ".csv\"";
        return Results.Text(csv, "text/csv; charset=utf-8");
    }
    catch (Exception ex)
    {
        app.Logger.LogError(ex, "CSV export error");
        return Results.StatusCode(500);
    }
});

app.MapGet("/api/screenshots", async (HttpContext ctx, EventStore db) =>
{
    try
    {
        var q = ctx.Request.Query;
        var f = new ScreenshotFilter {
            Host   = q["host"].FirstOrDefault(),
            From   = q["from"].FirstOrDefault(),
            To     = q["to"].FirstOrDefault(),
            Search = q["search"].FirstOrDefault(),
            Limit  = int.TryParse(q["limit"],  out int l) ? Math.Min(l, 100) : 20,
            Offset = int.TryParse(q["offset"], out int o) ? o : 0
        };
        return Results.Json(db.QueryScreenshots(f));
    }
    catch (Exception ex)
    {
        app.Logger.LogError(ex, "Screenshots error");
        return Results.StatusCode(500);
    }
});

app.MapGet("/api/screenshots/{id}/image", (long id, EventStore db) =>
{
    string? path = db.GetScreenshotPath(id);
    if (path == null) { app.Logger.LogWarning("Screenshot {Id}: not in DB", id); return Results.NotFound(); }
    if (!File.Exists(path)) { app.Logger.LogWarning("Screenshot {Id}: missing at {Path}", id, path); return Results.NotFound(); }
    return Results.File(File.ReadAllBytes(path), "image/jpeg");
});

app.MapDelete("/api/screenshots/{id}", (long id, HttpContext ctx, EventStore db) =>
{
    var s = ctx.Items["session"] as SessionInfo;
    if (s?.Role != "admin")
        return Results.Json(new { error = "Forbidden" }, statusCode: 403);
    bool ok = db.DeleteScreenshot(id);
    if (ok)
    {
        string ssDelIp = ctx.Request.Headers["X-Forwarded-For"].FirstOrDefault()
                      ?? ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        db.WriteAudit(s.Username, ssDelIp, "SCREENSHOT_DELETE", id.ToString());
    }
    return ok ? Results.Ok(new { deleted = id }) : Results.NotFound();
});

app.MapGet("/api/stats", (EventStore db) =>
{
    try   { return Results.Json(db.GetStats()); }
    catch (Exception ex) { app.Logger.LogError(ex, "Stats error"); return Results.StatusCode(500); }
});

app.MapGet("/api/hosts", (EventStore db) =>
{
    try   { return Results.Json(db.GetHosts()); }
    catch (Exception ex) { app.Logger.LogError(ex, "Hosts error"); return Results.StatusCode(500); }
});

app.MapGet("/api/agents", (EventStore db) =>
{
    try   { return Results.Json(db.GetAgentStatuses()); }
    catch (Exception ex) { app.Logger.LogError(ex, "Agents error"); return Results.StatusCode(500); }
});

app.MapPost("/api/commands", async (HttpContext ctx, EventStore db) =>
{
    try
    {
        var s = ctx.Items["session"] as SessionInfo;
        if (s?.Role != "admin")
            return Results.Json(new { error = "Forbidden" }, statusCode: 403);

        var req = await JsonSerializer.DeserializeAsync<CreateCommandRequest>(
            ctx.Request.Body,
            new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
        if (req is null || string.IsNullOrEmpty(req.Command))
            return Results.BadRequest("Command required");

        var allowed = new[] { "stop", "start", "restart", "uninstall", "update_config" };
        if (!Array.Exists(allowed, c => c == req.Command))
            return Results.BadRequest("Unknown command");

        long id = db.CreateCommand(
            string.IsNullOrEmpty(req.Host) ? "*" : req.Host,
            req.Command, req.Payload ?? "", req.AgentId ?? "");

        {   string cmdIp = ctx.Request.Headers["X-Forwarded-For"].FirstOrDefault()
                        ?? ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown";
            db.WriteAudit(s.Username, cmdIp, "COMMAND",
                string.IsNullOrEmpty(req.Host) ? "*" : req.Host,
                $"cmd={req.Command}|id={id}"); }

        app.Logger.LogInformation("Command {Cmd}→{Host} by {U}",
            req.Command, req.Host, s.Username);
        return Results.Ok(new { id });
    }
    catch (Exception ex)
    {
        app.Logger.LogError(ex, "Create command error");
        return Results.StatusCode(500);
    }
});

app.MapGet("/api/commands/history", (HttpContext ctx, EventStore db) =>
{
    try
    {
        var q = ctx.Request.Query;
        string? host  = q["host"].FirstOrDefault();
        int     limit = int.TryParse(q["limit"], out int l) ? Math.Min(l, 200) : 50;
        return Results.Json(db.GetCommands(host, limit));
    }
    catch (Exception ex)
    {
        app.Logger.LogError(ex, "Commands history error");
        return Results.StatusCode(500);
    }
});

app.MapDelete("/api/agents/{host}", (string host, HttpContext ctx, EventStore db) =>
{
    string removeAgentId = ctx.Request.Query["agentId"].FirstOrDefault() ?? "";
    try { db.RemoveAgent(host, removeAgentId); return Results.Ok(new { removed = host }); }
    catch (Exception ex) { app.Logger.LogError(ex, "Remove agent error"); return Results.StatusCode(500); }
});

// Управление данными (только admin)
app.MapDelete("/api/data/{host}/screenshots", (string host, HttpContext ctx, EventStore db) =>
{
    var s = ctx.Items["session"] as SessionInfo;
    if (s?.Role != "admin") return Results.Json(new { error = "Forbidden" }, statusCode: 403);
    int count = db.DeleteScreenshotsByHost(host);
    {   string hssIp = ctx.Request.Headers["X-Forwarded-For"].FirstOrDefault()
                    ?? ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        db.WriteAudit(s.Username, hssIp, "DATA_DELETE", $"{host}:screenshots", $"count={count}"); }
    app.Logger.LogInformation("Deleted {N} screenshots for {Host} by {U}", count, host, s.Username);
    return Results.Ok(new { deleted = count, host });
});

app.MapDelete("/api/data/{host}/events", (string host, HttpContext ctx, EventStore db) =>
{
    var s = ctx.Items["session"] as SessionInfo;
    if (s?.Role != "admin") return Results.Json(new { error = "Forbidden" }, statusCode: 403);
    int count = db.DeleteEventsByHost(host);
    {   string hevIp = ctx.Request.Headers["X-Forwarded-For"].FirstOrDefault()
                    ?? ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        db.WriteAudit(s.Username, hevIp, "DATA_DELETE", $"{host}:events", $"count={count}"); }
    app.Logger.LogInformation("Deleted {N} events for {Host} by {U}", count, host, s.Username);
    return Results.Ok(new { deleted = count, host });
});

app.MapDelete("/api/data/{host}", (string host, HttpContext ctx, EventStore db) =>
{
    var s = ctx.Items["session"] as SessionInfo;
    if (s?.Role != "admin") return Results.Json(new { error = "Forbidden" }, statusCode: 403);
    var (ev, ss) = db.PurgeHost(host);
    return Results.Ok(new { host, deletedEvents = ev, deletedScreenshots = ss });
});

app.MapDelete("/api/data/all/screenshots", (HttpContext ctx, EventStore db) =>
{
    var s = ctx.Items["session"] as SessionInfo;
    if (s?.Role != "admin") return Results.Json(new { error = "Forbidden" }, statusCode: 403);
    int count = db.DeleteAllScreenshots();
    string daIp = ctx.Request.Headers["X-Forwarded-For"].FirstOrDefault()
               ?? ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown";
    db.WriteAudit(s.Username, daIp, "DATA_DELETE", "all-screenshots", $"count={count}");
    app.Logger.LogInformation("Deleted ALL {N} screenshots by {U}", count, s.Username);
    return Results.Ok(new { deleted = count });
});

app.MapDelete("/api/data/all/events", (HttpContext ctx, EventStore db) =>
{
    var s = ctx.Items["session"] as SessionInfo;
    if (s?.Role != "admin") return Results.Json(new { error = "Forbidden" }, statusCode: 403);
    int count = db.DeleteAllEvents();
    {   string devIp2 = ctx.Request.Headers["X-Forwarded-For"].FirstOrDefault()
                     ?? ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        db.WriteAudit(s.Username, devIp2, "DATA_DELETE", "all-events", $"count={count}"); }
    app.Logger.LogInformation("Deleted ALL {N} events by {U}", count, s.Username);
    return Results.Ok(new { deleted = count });
});

// Audit log endpoint — admin only
app.MapGet("/api/audit", (HttpContext ctx) =>
{
    var s = ctx.Items["session"] as SessionInfo;
    if (s?.Role != "admin")
        return Results.Json(new { error = "Forbidden" }, statusCode: 403);
    int limit  = int.TryParse(ctx.Request.Query["limit"],  out var l) ? Math.Min(l, 1000) : 200;
    int offset = int.TryParse(ctx.Request.Query["offset"], out var o) ? o : 0;
    var entries = store.GetAuditLog(limit, offset);
    var total   = store.GetAuditLogCount();
    return Results.Ok(new { total, entries });
});

// Health check endpoint — для мониторинга, балансировщиков, Kubernetes
app.MapGet("/health", (EventStore db) =>
{
    try
    {
        // Простая проверка доступности БД
        var stats = db.GetStats();
        return Results.Ok(new {
            status   = "healthy",
            version  = "1.0",
            database = "ok",
            events   = stats.TotalEvents,
            uptime   = Environment.TickCount64 / 1000
        });
    }
    catch (Exception ex)
    {
        return Results.Json(new {
            status   = "unhealthy",
            database = "error",
            error    = ex.Message
        }, statusCode: 503);
    }
});

// 404 для неизвестных /api/ маршрутов
app.Map("/api/{**slug}", (HttpContext ctx) =>
{
    ctx.Response.StatusCode = 404;
    return Results.Json(new { error = "API endpoint not found", path = ctx.Request.Path.Value });
});

app.MapFallbackToFile("index.html");

app.Logger.LogInformation("DLP Server started. DB={Db}", dbPath);
app.Logger.LogInformation("HTTP  → http://0.0.0.0:5000");
app.Logger.LogInformation("HTTPS → https://0.0.0.0:5001 (self-signed cert)");
if (!telegram.IsConfigured)
    app.Logger.LogInformation(
        "Telegram not configured. Add BotToken+ChatId to appsettings.json to enable alerts.");
app.Run();
