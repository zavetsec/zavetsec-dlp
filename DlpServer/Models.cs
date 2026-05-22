namespace ZavetSec.DlpServer;

public record LogEvent(string Ts, string Host, string User,
    string Module, string Msg, string Data);

public class EventFilter
{
    public string? Module  { get; set; }
    public string? Host    { get; set; }
    public string? AgentId { get; set; }
    public string? Search  { get; set; }
    public string? From    { get; set; }
    public string? To      { get; set; }
    public int     Limit   { get; set; } = 100;
    public int     Offset  { get; set; } = 0;
}

public class DashboardStats
{
    public long   TotalEvents      { get; set; }
    public long   AlertsToday      { get; set; }
    public int    ActiveHosts      { get; set; }
    public string LastEventTs      { get; set; } = "";
    public long   DbSizeBytes      { get; set; }
    public long   ScreenshotBytes  { get; set; }
    public List<ModuleStat> TopModules { get; set; } = new();
}

public class ModuleStat
{
    public string Module { get; set; } = "";
    public long   Count  { get; set; }
}

public class EventsResponse
{
    public List<StoredEvent> Events { get; set; } = new();
    public long Total  { get; set; }
    public int  Limit  { get; set; }
    public int  Offset { get; set; }
}

public class StoredEvent
{
    public long   Id         { get; set; }
    public string Ts         { get; set; } = "";
    public string Host       { get; set; } = "";
    public string User       { get; set; } = "";
    public string Module     { get; set; } = "";
    public string Msg        { get; set; } = "";
    public string Data       { get; set; } = "";
    public string ReceivedAt { get; set; } = "";
}

public class ScreenshotUpload
{
    public string Ts         { get; set; } = "";
    public string Host       { get; set; } = "";
    public string User       { get; set; } = "";
    public string Trigger    { get; set; } = "";
    public string Window     { get; set; } = "";
    public string Resolution { get; set; } = "";
    public string Jpeg       { get; set; } = "";
    public string AgentId    { get; set; } = "";
}

public class ScreenshotRecord
{
    public long   Id         { get; set; }
    public string Ts         { get; set; } = "";
    public string Host       { get; set; } = "";
    public string User       { get; set; } = "";
    public string Trigger    { get; set; } = "";
    public string Window     { get; set; } = "";
    public string Resolution { get; set; } = "";
    public long   SizeBytes  { get; set; }
    public string ReceivedAt { get; set; } = "";
}

public class ScreenshotsResponse
{
    public List<ScreenshotRecord> Screenshots { get; set; } = new();
    public long Total  { get; set; }
    public int  Limit  { get; set; }
    public int  Offset { get; set; }
}

public class ScreenshotFilter
{
    public string? Host    { get; set; }
    public string? AgentId { get; set; }
    public string? From   { get; set; }
    public string? To     { get; set; }
    public string? Search { get; set; }
    public int     Limit  { get; set; } = 20;
    public int     Offset { get; set; } = 0;
}

public class AgentCommand
{
    public long   Id          { get; set; }
    public string Host        { get; set; } = "";
    public string Command     { get; set; } = "";
    public string Payload     { get; set; } = "";
    public string Status      { get; set; } = "";
    public string CreatedAt   { get; set; } = "";
    public string DeliveredAt { get; set; } = "";
    public string ExecutedAt  { get; set; } = "";
    public string Error       { get; set; } = "";
}

public class CommandResult
{
    public long   Id     { get; set; }
    public string Status { get; set; } = "";
    public string Error  { get; set; } = "";
}

public class AgentStatus
{
    public string Host        { get; set; } = "";
    public string LastSeen    { get; set; } = "";
    public string FirstSeen   { get; set; } = "";
    public string AgentId     { get; set; } = "";
    public bool   Online      { get; set; }
    public long   Events      { get; set; }
    // "active" = monitoring running, "stopped" = process alive but monitors paused
    public string MonitorStatus { get; set; } = "active";
}

public class CreateCommandRequest
{
    public string  Host    { get; set; } = "";
    public string  Command { get; set; } = "";
    public string  Payload { get; set; } = "";
    public string? AgentId { get; set; }
}

// ── Auth ──────────────────────────────────────────────────────────────────
public class LoginRequest
{
    public string Username { get; set; } = "";
    public string Password { get; set; } = "";
}

public class LoginResponse
{
    public string Token               { get; set; } = "";
    public string Username            { get; set; } = "";
    public string Role                { get; set; } = "";
    public bool   MustChangePassword  { get; set; }  // true → форсированная смена пароля
}

public class SessionInfo
{
    public string Username  { get; set; } = "";
    public string Role      { get; set; } = "";
    public string CreatedAt { get; set; } = "";
    public string ExpiresAt { get; set; } = "";
}

// ── Пользователи ─────────────────────────────────────────────────────────
public class DlpUser
{
    public int    Id                 { get; set; }
    public string Username           { get; set; } = "";
    public string Role               { get; set; } = "viewer";
    public string CreatedAt          { get; set; } = "";
    public string CreatedBy          { get; set; } = "";
    public string LastLoginAt        { get; set; } = "";
    public bool   MustChangePassword { get; set; }
}

public class CreateUserRequest
{
    public string Username { get; set; } = "";
    public string Password { get; set; } = "";
    public string Role     { get; set; } = "viewer";
}

public class ChangePasswordRequest
{
    public string OldPassword { get; set; } = "";
    public string NewPassword { get; set; } = "";
}

// ── Telegram ──────────────────────────────────────────────────────────────
public class TelegramConfig
{
    public string BotToken { get; set; } = "";
    public string ChatId   { get; set; } = "";
    public bool   Enabled  => !string.IsNullOrEmpty(BotToken) && !string.IsNullOrEmpty(ChatId);
}

public class TelegramTestRequest
{
    public string BotToken { get; set; } = "";
    public string ChatId   { get; set; } = "";
}

// ── Статистика диска ──────────────────────────────────────────────────────
public class DiskStats
{
    public long ScreenshotsSizeBytes { get; set; }
    public long ScreenshotsCount     { get; set; }
    public long DbSizeBytes          { get; set; }
    public string ScreenshotsSizeHuman => FormatBytes(ScreenshotsSizeBytes);
    public string DbSizeHuman         => FormatBytes(DbSizeBytes);
    private static string FormatBytes(long b)
    {
        if (b < 1024) return $"{b} B";
        if (b < 1024*1024) return $"{b/1024.0:F1} KB";
        if (b < 1024L*1024*1024) return $"{b/1024.0/1024:F1} MB";
        return $"{b/1024.0/1024/1024:F2} GB";
    }
}

public class AuditEntry
{
    public int    Id     { get; set; }
    public string Ts     { get; set; } = "";
    public string Admin  { get; set; } = "";
    public string Ip     { get; set; } = "";
    public string Action { get; set; } = "";
    public string Target { get; set; } = "";
    public string Detail { get; set; } = "";
}

