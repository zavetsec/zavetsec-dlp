using Microsoft.Data.Sqlite;
using System.Security.Cryptography;
using System.Text;

namespace ZavetSec.DlpServer;

public class EventStore
{
    private readonly string _connStr;
    private readonly string _screenshotDir;
    private readonly string _dbPath;

    public EventStore(string dbPath, string screenshotDir)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(dbPath)!);
        Directory.CreateDirectory(screenshotDir);
        _dbPath        = dbPath;
        _connStr       = $"Data Source={dbPath}";
        _screenshotDir = screenshotDir;
        InitDb();
    }

    private void InitDb()
    {
        using var conn = Open();
        Exec(conn, "PRAGMA journal_mode=WAL");
        Exec(conn, "PRAGMA synchronous=NORMAL");
        Exec(conn, "CREATE TABLE IF NOT EXISTS events (" +
            "id INTEGER PRIMARY KEY AUTOINCREMENT," +
            "ts TEXT NOT NULL, host TEXT NOT NULL, user_name TEXT NOT NULL," +
            "module TEXT NOT NULL, msg TEXT NOT NULL," +
            "data TEXT NOT NULL DEFAULT '', received_at TEXT NOT NULL)");
        Exec(conn, "CREATE INDEX IF NOT EXISTS idx_ts     ON events(ts DESC)");
        Exec(conn, "CREATE INDEX IF NOT EXISTS idx_module ON events(module)");
        Exec(conn, "CREATE INDEX IF NOT EXISTS idx_host   ON events(host)");
        Exec(conn, "CREATE TABLE IF NOT EXISTS hosts (host TEXT NOT NULL, agent_id TEXT NOT NULL DEFAULT '', last_seen TEXT NOT NULL, first_seen TEXT NOT NULL DEFAULT '', agent_status TEXT NOT NULL DEFAULT 'active', PRIMARY KEY (agent_id, host))");
        Exec(conn, "CREATE TABLE IF NOT EXISTS screenshots (" +
            "id INTEGER PRIMARY KEY AUTOINCREMENT," +
            "ts TEXT NOT NULL, host TEXT NOT NULL, user_name TEXT NOT NULL," +
            "trigger TEXT NOT NULL, window TEXT NOT NULL, resolution TEXT NOT NULL," +
            "filename TEXT NOT NULL, size_bytes INTEGER NOT NULL, received_at TEXT NOT NULL)");
        Exec(conn, "CREATE INDEX IF NOT EXISTS idx_ss_ts   ON screenshots(ts DESC)");
        Exec(conn, "CREATE INDEX IF NOT EXISTS idx_ss_host ON screenshots(host)");
    }

    public void InitCommandsTable()
    {
        using var conn = Open();
        Exec(conn, "CREATE TABLE IF NOT EXISTS commands (" +
            "id INTEGER PRIMARY KEY AUTOINCREMENT," +
            "host TEXT NOT NULL, command TEXT NOT NULL," +
            "payload TEXT NOT NULL DEFAULT '', status TEXT NOT NULL DEFAULT 'pending'," +
            "created_at TEXT NOT NULL, delivered_at TEXT NOT NULL DEFAULT ''," +
            "executed_at TEXT NOT NULL DEFAULT '', error TEXT NOT NULL DEFAULT '')");
        Exec(conn, "CREATE INDEX IF NOT EXISTS idx_cmd_host   ON commands(host, status)");
        Exec(conn, "CREATE INDEX IF NOT EXISTS idx_cmd_status ON commands(status)");
    }

    // ── Audit Log ────────────────────────────────────────────────────────────
    /// Записывает действие администратора в immutable audit log.
    /// Вызывается из Program.cs при любом изменяющем действии.
    public void WriteAudit(string admin, string ip, string action,
                           string target = "", string detail = "")
    {
        using var conn = Open();
        var cmd = conn.CreateCommand();
        cmd.CommandText = "INSERT INTO audit_log (ts,admin,ip,action,target,detail) " +
                          "VALUES ($ts,$admin,$ip,$action,$target,$detail)";
        cmd.Parameters.AddWithValue("$ts",     DateTime.UtcNow.ToString("o"));
        cmd.Parameters.AddWithValue("$admin",  admin);
        cmd.Parameters.AddWithValue("$ip",     ip);
        cmd.Parameters.AddWithValue("$action", action);
        cmd.Parameters.AddWithValue("$target", target);
        cmd.Parameters.AddWithValue("$detail", detail);
        cmd.ExecuteNonQuery();
    }

    /// Возвращает последние N записей audit log.
    public List<AuditEntry> GetAuditLog(int limit = 200, int offset = 0)
    {
        using var conn = Open();
        var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT id,ts,admin,ip,action,target,detail " +
                          "FROM audit_log ORDER BY id DESC LIMIT $limit OFFSET $offset";
        cmd.Parameters.AddWithValue("$limit",  limit);
        cmd.Parameters.AddWithValue("$offset", offset);
        var list = new List<AuditEntry>();
        using var r = cmd.ExecuteReader();
        while (r.Read())
            list.Add(new AuditEntry {
                Id     = (int)r.GetInt64(0),
                Ts     = r.GetString(1),
                Admin  = r.GetString(2),
                Ip     = r.GetString(3),
                Action = r.GetString(4),
                Target = r.GetString(5),
                Detail = r.GetString(6)
            });
        return list;
    }

    public long GetAuditLogCount()
    {
        using var conn = Open();
        return Scalar<long>(conn, "SELECT COUNT(*) FROM audit_log");
    }

    // Версия схемы БД — увеличивать при каждом изменении схемы
    private const int DbSchemaVersion = 9;

    /// Выполняет все необходимые миграции для существующих баз данных.
    /// Безопасно вызывать на любой версии БД — применяются только нужные.
    public void RunMigrations()
    {
        using var conn = Open();

        // Получить текущую версию схемы (0 если таблицы нет)
        Exec(conn, "CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL DEFAULT 0)");
        long currentVersion = Scalar<long>(conn, "SELECT COALESCE(MAX(version),0) FROM schema_version");

        if (currentVersion < 1)
        {
            // v1: базовая схема (уже в InitDb/InitCommandsTable/InitAuthTables)
            // Ничего дополнительного не требуется — таблицы создаются IF NOT EXISTS
        }

        if (currentVersion < 2)
        {
            // v2: добавить must_change_password в users (если колонки нет)
            try { Exec(conn, "ALTER TABLE users ADD COLUMN must_change_password INTEGER NOT NULL DEFAULT 0"); }
            catch { /* уже существует */ }
        }

        if (currentVersion < 3)
        {
            // v3: таблица защиты от брутфорса
            Exec(conn, "CREATE TABLE IF NOT EXISTS login_attempts (" +
                "ip TEXT NOT NULL UNIQUE, failed_count INTEGER NOT NULL DEFAULT 0, " +
                "locked_until TEXT NOT NULL DEFAULT '', " +
                "last_attempt TEXT NOT NULL)");
            Exec(conn, "CREATE UNIQUE INDEX IF NOT EXISTS idx_attempts_ip ON login_attempts(ip)");
        }

        if (currentVersion < 4)
        {
            // v4: fix UNIQUE constraint on login_attempts.ip (was missing in v3 for existing DBs)
            try
            {
                Exec(conn, "CREATE TABLE IF NOT EXISTS login_attempts_new (" +
                    "ip TEXT NOT NULL UNIQUE, failed_count INTEGER NOT NULL DEFAULT 0, " +
                    "locked_until TEXT NOT NULL DEFAULT '', " +
                    "last_attempt TEXT NOT NULL)");
                Exec(conn, "INSERT OR IGNORE INTO login_attempts_new " +
                    "SELECT ip, MAX(failed_count), locked_until, MAX(last_attempt) " +
                    "FROM login_attempts GROUP BY ip");
                Exec(conn, "DROP TABLE login_attempts");
                Exec(conn, "ALTER TABLE login_attempts_new RENAME TO login_attempts");
                Exec(conn, "CREATE UNIQUE INDEX IF NOT EXISTS idx_attempts_ip ON login_attempts(ip)");
            }
            catch { }
        }

        if (currentVersion < 5)
        {
            // v5: admin audit log — immutable record of all admin actions
            Exec(conn, "CREATE TABLE IF NOT EXISTS audit_log (" +
                "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
                "ts TEXT NOT NULL, " +
                "admin TEXT NOT NULL, " +
                "ip TEXT NOT NULL DEFAULT '', " +
                "action TEXT NOT NULL, " +
                "target TEXT NOT NULL DEFAULT '', " +
                "detail TEXT NOT NULL DEFAULT '')");
            Exec(conn, "CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts)");
        }



        if (currentVersion < 6)
        {
            // v6: add agent_id + first_seen to hosts; recreate with new PK
            try
            {
                Exec(conn, "CREATE TABLE IF NOT EXISTS hosts_new (" +
                    "host TEXT NOT NULL, agent_id TEXT NOT NULL DEFAULT '', " +
                    "last_seen TEXT NOT NULL, " +
                    "first_seen TEXT NOT NULL DEFAULT '', " +
                    "PRIMARY KEY (agent_id, host))");
                // Migrate existing rows — generate pseudo agent_id from hostname
                Exec(conn, "INSERT OR IGNORE INTO hosts_new (host, agent_id, last_seen, first_seen) " +
                    "SELECT host, lower(hex(randomblob(8))), last_seen, last_seen FROM hosts");
                Exec(conn, "DROP TABLE IF EXISTS hosts");
                Exec(conn, "ALTER TABLE hosts_new RENAME TO hosts");
            }
            catch { /* fresh install - table already has new schema */ }
        }

        if (currentVersion < 7)
        {
            // v7: add agent_id to events, screenshots, commands; add agent_status to hosts
            // events
            try { Exec(conn, "ALTER TABLE events ADD COLUMN agent_id TEXT NOT NULL DEFAULT ''"); } catch { }
            try { Exec(conn, "CREATE INDEX IF NOT EXISTS idx_events_agent ON events(agent_id)"); } catch { }
            // screenshots
            try { Exec(conn, "ALTER TABLE screenshots ADD COLUMN agent_id TEXT NOT NULL DEFAULT ''"); } catch { }
            try { Exec(conn, "CREATE INDEX IF NOT EXISTS idx_ss_agent ON screenshots(agent_id)"); } catch { }
            // commands
            try { Exec(conn, "ALTER TABLE commands ADD COLUMN agent_id TEXT NOT NULL DEFAULT ''"); } catch { }
            try { Exec(conn, "CREATE INDEX IF NOT EXISTS idx_cmd_agent ON commands(agent_id)"); } catch { }
            // hosts: agent monitoring status
            try { Exec(conn, "ALTER TABLE hosts ADD COLUMN agent_status TEXT NOT NULL DEFAULT 'active'"); } catch { }
        }

        if (currentVersion < 8)
        {
            // v8: add agent_status column to hosts table
            try { Exec(conn, "ALTER TABLE hosts ADD COLUMN agent_status TEXT NOT NULL DEFAULT 'active'"); } catch { }
        }

        if (currentVersion < 9)
        {
            // v9: per-agent API keys
            Exec(conn, "CREATE TABLE IF NOT EXISTS agent_keys (" +
                "agent_id TEXT NOT NULL PRIMARY KEY, " +
                "api_key  TEXT NOT NULL, " +
                "host     TEXT NOT NULL DEFAULT '', " +
                "created_at TEXT NOT NULL, " +
                "revoked  INTEGER NOT NULL DEFAULT 0)");
        }

        // Обновить версию схемы
        if (currentVersion < DbSchemaVersion)
        {
            Exec(conn, "DELETE FROM schema_version");
            var upd = conn.CreateCommand();
            upd.CommandText = "INSERT INTO schema_version (version) VALUES ($v)";
            upd.Parameters.AddWithValue("$v", DbSchemaVersion);
            upd.ExecuteNonQuery();
        }
    }

    public void InitAuthTables()
    {
        using var conn = Open();
        Exec(conn, "CREATE TABLE IF NOT EXISTS users (" +
            "id INTEGER PRIMARY KEY AUTOINCREMENT," +
            "username TEXT NOT NULL UNIQUE COLLATE NOCASE," +
            "password_hash TEXT NOT NULL, salt TEXT NOT NULL," +
            "role TEXT NOT NULL DEFAULT 'viewer'," +
            "must_change_password INTEGER NOT NULL DEFAULT 0," +
            "created_at TEXT NOT NULL, created_by TEXT NOT NULL DEFAULT 'system'," +
            "last_login_at TEXT NOT NULL DEFAULT '')");
        try { Exec(conn, "ALTER TABLE users ADD COLUMN must_change_password INTEGER NOT NULL DEFAULT 0"); }
        catch { /* already exists */ }
        Exec(conn, "CREATE TABLE IF NOT EXISTS sessions (" +
            "token TEXT PRIMARY KEY, username TEXT NOT NULL, role TEXT NOT NULL," +
            "created_at TEXT NOT NULL, expires_at TEXT NOT NULL)");
        Exec(conn, "CREATE INDEX IF NOT EXISTS idx_sessions_exp ON sessions(expires_at)");

        // Таблица login_attempts создаётся в RunMigrations()

        long count = Scalar<long>(conn, "SELECT COUNT(*) FROM users");
        if (count == 0)
        {
            string hash = HashPassword("admin", out string salt);
            var cmd = conn.CreateCommand();
            cmd.CommandText = "INSERT INTO users " +
                "(username,password_hash,salt,role,must_change_password,created_at,created_by)" +
                " VALUES ('admin',$h,$s,'admin',1,$ts,'system')";
            cmd.Parameters.AddWithValue("$h",  hash);
            cmd.Parameters.AddWithValue("$s",  salt);
            cmd.Parameters.AddWithValue("$ts", DateTime.UtcNow.ToString("o"));
            cmd.ExecuteNonQuery();
        }
    }

    // ── Auth ──────────────────────────────────────────────────────────────
    // ── Brute Force Protection ───────────────────────────────────────────
    private const int MaxFailedAttempts = 5;
    private static readonly TimeSpan LockoutDuration = TimeSpan.FromMinutes(15);

    /// Проверить не заблокирован ли IP. Возвращает (isLocked, secondsRemaining)
    public (bool Locked, int SecondsRemaining) CheckBruteForce(string ip)
    {
        using var conn = Open();
        var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT failed_count, locked_until FROM login_attempts WHERE ip=$ip";
        cmd.Parameters.AddWithValue("$ip", ip);
        using var r = cmd.ExecuteReader();
        if (!r.Read()) return (false, 0);

        int failed = (int)r.GetInt64(0);
        string lockedUntilStr = r.GetString(1);
        r.Close();

        if (!string.IsNullOrEmpty(lockedUntilStr) &&
            DateTime.TryParse(lockedUntilStr, out var lockedUntil) &&
            lockedUntil > DateTime.UtcNow)
        {
            int secs = (int)(lockedUntil - DateTime.UtcNow).TotalSeconds;
            return (true, secs);
        }
        return (false, 0);
    }

    public void RecordFailedAttempt(string ip)
    {
        using var conn = Open();
        var cmd = conn.CreateCommand();
        cmd.CommandText = @"INSERT INTO login_attempts (ip, failed_count, locked_until, last_attempt)
            VALUES ($ip, 1, '', $now)
            ON CONFLICT(ip) DO UPDATE SET
                failed_count = failed_count + 1,
                last_attempt = $now,
                locked_until = CASE
                    WHEN failed_count + 1 >= $max
                    THEN $lockUntil
                    ELSE ''
                END";
        cmd.Parameters.AddWithValue("$ip",       ip);
        cmd.Parameters.AddWithValue("$now",      DateTime.UtcNow.ToString("o"));
        cmd.Parameters.AddWithValue("$max",      MaxFailedAttempts);
        cmd.Parameters.AddWithValue("$lockUntil",
            DateTime.UtcNow.Add(LockoutDuration).ToString("o"));
        cmd.ExecuteNonQuery();
    }

    public void ResetFailedAttempts(string ip)
    {
        using var conn = Open();
        var cmd = conn.CreateCommand();
        cmd.CommandText = "DELETE FROM login_attempts WHERE ip=$ip";
        cmd.Parameters.AddWithValue("$ip", ip);
        cmd.ExecuteNonQuery();
    }

    public void CleanupOldAttempts()
    {
        using var conn = Open();
        var cmd = conn.CreateCommand();
        // Удалить записи старше 1 часа где блокировка уже снята
        cmd.CommandText = "DELETE FROM login_attempts WHERE last_attempt < $cutoff AND " +
            "(locked_until = '' OR locked_until < $now)";
        cmd.Parameters.AddWithValue("$cutoff", DateTime.UtcNow.AddHours(-1).ToString("o"));
        cmd.Parameters.AddWithValue("$now",    DateTime.UtcNow.ToString("o"));
        cmd.ExecuteNonQuery();
    }

    public LoginResponse? Login(string username, string password)
    {
        using var conn = Open();
        var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT password_hash,salt,role,must_change_password FROM users " +
            "WHERE username=$u COLLATE NOCASE";
        cmd.Parameters.AddWithValue("$u", username);
        using var r = cmd.ExecuteReader();
        if (!r.Read()) return null;
        string ph = r.GetString(0), salt = r.GetString(1), role = r.GetString(2);
        bool mustChange = r.GetInt64(3) != 0;
        if (!VerifyPassword(password, ph, salt)) return null;
        r.Close();

        var upd = conn.CreateCommand();
        upd.CommandText = "UPDATE users SET last_login_at=$ts WHERE username=$u COLLATE NOCASE";
        upd.Parameters.AddWithValue("$ts", DateTime.UtcNow.ToString("o"));
        upd.Parameters.AddWithValue("$u",  username);
        upd.ExecuteNonQuery();

        string token = GenerateToken(), expiresAt = DateTime.UtcNow.AddDays(7).ToString("o");
        var ins = conn.CreateCommand();
        ins.CommandText = "INSERT INTO sessions (token,username,role,created_at,expires_at) " +
            "VALUES ($t,$u,$r,$now,$exp)";
        ins.Parameters.AddWithValue("$t",   token);
        ins.Parameters.AddWithValue("$u",   username);
        ins.Parameters.AddWithValue("$r",   role);
        ins.Parameters.AddWithValue("$now", DateTime.UtcNow.ToString("o"));
        ins.Parameters.AddWithValue("$exp", expiresAt);
        ins.ExecuteNonQuery();

        var clean = conn.CreateCommand();
        clean.CommandText = "DELETE FROM sessions WHERE expires_at<$now";
        clean.Parameters.AddWithValue("$now", DateTime.UtcNow.ToString("o"));
        clean.ExecuteNonQuery();

        return new LoginResponse { Token=token, Username=username, Role=role, MustChangePassword=mustChange };
    }

    public SessionInfo? GetSession(string token)
    {
        if (string.IsNullOrEmpty(token)) return null;
        using var conn = Open();
        var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT username,role,created_at,expires_at FROM sessions " +
            "WHERE token=$t AND expires_at>$now";
        cmd.Parameters.AddWithValue("$t",   token);
        cmd.Parameters.AddWithValue("$now", DateTime.UtcNow.ToString("o"));
        using var r = cmd.ExecuteReader();
        if (!r.Read()) return null;
        string u=r.GetString(0), ro=r.GetString(1), cr=r.GetString(2), ex=r.GetString(3);
        r.Close();
        var upd = conn.CreateCommand();
        upd.CommandText = "UPDATE sessions SET expires_at=$exp WHERE token=$t";
        upd.Parameters.AddWithValue("$exp", DateTime.UtcNow.AddDays(7).ToString("o"));
        upd.Parameters.AddWithValue("$t",   token);
        upd.ExecuteNonQuery();
        return new SessionInfo { Username=u, Role=ro, CreatedAt=cr, ExpiresAt=ex };
    }

    public void Logout(string token)
    {
        using var conn = Open();
        var cmd = conn.CreateCommand();
        cmd.CommandText = "DELETE FROM sessions WHERE token=$t";
        cmd.Parameters.AddWithValue("$t", token);
        cmd.ExecuteNonQuery();
    }

    // ── Users ─────────────────────────────────────────────────────────────
    public List<DlpUser> GetUsers()
    {
        using var conn = Open();
        var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT id,username,role,must_change_password," +
            "created_at,created_by,last_login_at FROM users ORDER BY id";
        var list = new List<DlpUser>();
        using var r = cmd.ExecuteReader();
        while (r.Read())
            list.Add(new DlpUser {
                Id=r.GetInt32(0), Username=r.GetString(1), Role=r.GetString(2),
                MustChangePassword=r.GetInt64(3)!=0,
                CreatedAt=r.GetString(4), CreatedBy=r.GetString(5), LastLoginAt=r.GetString(6) });
        return list;
    }

    public (bool Ok, string Error) CreateUser(CreateUserRequest req, string createdBy)
    {
        if (string.IsNullOrWhiteSpace(req.Username)) return (false, "Имя не может быть пустым");
        var pwErr2 = ValidatePassword(req.Password);
        if (pwErr2 != null) return (false, pwErr2);
        if (req.Role != "admin" && req.Role != "viewer") return (false, "Роль: admin или viewer");
        using var conn = Open();
        long exists = Scalar<long>(conn,
            "SELECT COUNT(*) FROM users WHERE username=$u COLLATE NOCASE", ("$u", req.Username));
        if (exists > 0) return (false, "Пользователь уже существует");
        string hash = HashPassword(req.Password, out string salt);
        var cmd = conn.CreateCommand();
        cmd.CommandText = "INSERT INTO users " +
            "(username,password_hash,salt,role,must_change_password,created_at,created_by)" +
            " VALUES ($u,$h,$s,$r,0,$ts,$by)";
        cmd.Parameters.AddWithValue("$u",  req.Username);
        cmd.Parameters.AddWithValue("$h",  hash);
        cmd.Parameters.AddWithValue("$s",  salt);
        cmd.Parameters.AddWithValue("$r",  req.Role);
        cmd.Parameters.AddWithValue("$ts", DateTime.UtcNow.ToString("o"));
        cmd.Parameters.AddWithValue("$by", createdBy);
        cmd.ExecuteNonQuery();
        return (true, "");
    }

    public (bool Ok, string Error) DeleteUser(string username, string requestedBy)
    {
        if (username.Equals("admin", StringComparison.OrdinalIgnoreCase))
            return (false, "Нельзя удалить встроенного администратора");
        if (username.Equals(requestedBy, StringComparison.OrdinalIgnoreCase))
            return (false, "Нельзя удалить самого себя");
        using var conn = Open();
        long isAdmin = Scalar<long>(conn,
            "SELECT COUNT(*) FROM users WHERE username=$u AND role='admin' COLLATE NOCASE",
            ("$u", username));
        if (isAdmin > 0)
        {
            long others = Scalar<long>(conn,
                "SELECT COUNT(*) FROM users WHERE role='admin' AND username!=$u COLLATE NOCASE",
                ("$u", username));
            if (others == 0) return (false, "Нельзя удалить последнего администратора");
        }
        var cmd = conn.CreateCommand();
        cmd.CommandText = "DELETE FROM users WHERE username=$u COLLATE NOCASE";
        cmd.Parameters.AddWithValue("$u", username);
        if (cmd.ExecuteNonQuery() == 0) return (false, "Пользователь не найден");
        var ds = conn.CreateCommand();
        ds.CommandText = "DELETE FROM sessions WHERE username=$u COLLATE NOCASE";
        ds.Parameters.AddWithValue("$u", username);
        ds.ExecuteNonQuery();
        return (true, "");
    }

    public (bool Ok, string Error) ChangePassword(string username, string oldPassword, string newPassword, string keepToken = "")
    {
        var pwErr = ValidatePassword(newPassword);
        if (pwErr != null) return (false, pwErr);
        using var conn = Open();
        var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT password_hash,salt FROM users WHERE username=$u COLLATE NOCASE";
        cmd.Parameters.AddWithValue("$u", username);
        using var r = cmd.ExecuteReader();
        if (!r.Read()) return (false, "Пользователь не найден");
        string ph=r.GetString(0), ps=r.GetString(1);
        r.Close();
        if (!VerifyPassword(oldPassword, ph, ps)) return (false, "Неверный старый пароль");
        string newHash = HashPassword(newPassword, out string newSalt);
        var upd = conn.CreateCommand();
        upd.CommandText = "UPDATE users SET password_hash=$h,salt=$s,must_change_password=0 " +
            "WHERE username=$u COLLATE NOCASE";
        upd.Parameters.AddWithValue("$h", newHash);
        upd.Parameters.AddWithValue("$s", newSalt);
        upd.Parameters.AddWithValue("$u", username);
        upd.ExecuteNonQuery();

        // Инвалидируем ВСЕ сессии пользователя при смене пароля
        var delSess = conn.CreateCommand();
        // Invalidate all OTHER sessions — keep the current one alive
        // (caller passes current token to exclude it from deletion)
        delSess.CommandText = string.IsNullOrEmpty(keepToken)
            ? "DELETE FROM sessions WHERE username=$u COLLATE NOCASE"
            : "DELETE FROM sessions WHERE username=$u COLLATE NOCASE AND token<>$keep";
        delSess.Parameters.AddWithValue("$u", username);
        if (!string.IsNullOrEmpty(keepToken))
            delSess.Parameters.AddWithValue("$keep", keepToken);
        delSess.ExecuteNonQuery();

        return (true, "");
    }

    // ── Events ────────────────────────────────────────────────────────────
    public void InsertBatch(IEnumerable<LogEvent> events, string agentId = "")
    {
        using var conn = Open();
        using var tx   = conn.BeginTransaction();
        var cmd = conn.CreateCommand();
        cmd.CommandText = "INSERT INTO events (ts,host,user_name,module,msg,data,received_at,agent_id) " +
            "VALUES ($ts,$host,$user,$module,$msg,$data,$received,$aid)";
        var pTs   = cmd.Parameters.Add("$ts",       SqliteType.Text);
        var pHost = cmd.Parameters.Add("$host",     SqliteType.Text);
        var pUser = cmd.Parameters.Add("$user",     SqliteType.Text);
        var pMod  = cmd.Parameters.Add("$module",   SqliteType.Text);
        var pMsg  = cmd.Parameters.Add("$msg",      SqliteType.Text);
        var pData = cmd.Parameters.Add("$data",     SqliteType.Text);
        var pRec  = cmd.Parameters.Add("$received", SqliteType.Text);
        var pAid  = cmd.Parameters.Add("$aid",      SqliteType.Text);
        // Only update last_seen for known hosts.
        // New host registration happens in GetPendingCommands (heartbeat).
        var ch = conn.CreateCommand();
        ch.CommandText = "UPDATE hosts SET last_seen=$ts WHERE host=$host";
        var phHost = ch.Parameters.Add("$host", SqliteType.Text);
        var phTs   = ch.Parameters.Add("$ts",   SqliteType.Text);
        string received = DateTime.UtcNow.ToString("o");
        foreach (var ev in events)
        {
            pTs.Value=ev.Ts; pHost.Value=ev.Host; pUser.Value=ev.User;
            pMod.Value=ev.Module; pMsg.Value=ev.Msg;
            pData.Value=ev.Data??""; pRec.Value=received; pAid.Value=agentId;
            cmd.ExecuteNonQuery();
            phHost.Value=ev.Host; phTs.Value=received;
            ch.ExecuteNonQuery();
        }
        tx.Commit();
    }

    public EventsResponse Query(EventFilter f)
    {
        using var conn = Open();
        var (where, parms) = BuildEventsWhere(f);
        var cc = conn.CreateCommand();
        cc.CommandText = "SELECT COUNT(*) FROM events " + where;
        foreach (var (k,v) in parms) cc.Parameters.AddWithValue(k, v);
        long total = (long)(cc.ExecuteScalar() ?? 0L);
        var dc = conn.CreateCommand();
        dc.CommandText = "SELECT id,ts,host,user_name,module,msg,data,received_at FROM events " +
            where + " ORDER BY ts DESC,id DESC LIMIT $lim OFFSET $off";
        foreach (var (k,v) in parms) dc.Parameters.AddWithValue(k, v);
        dc.Parameters.AddWithValue("$lim", f.Limit);
        dc.Parameters.AddWithValue("$off", f.Offset);
        var list = new List<StoredEvent>();
        using var r = dc.ExecuteReader();
        while (r.Read())
            list.Add(new StoredEvent {
                Id=r.GetInt64(0),
                Ts        =r.IsDBNull(1)?"":r.GetString(1),
                Host      =r.IsDBNull(2)?"":r.GetString(2),
                User      =r.IsDBNull(3)?"":r.GetString(3),
                Module    =r.IsDBNull(4)?"":r.GetString(4),
                Msg       =r.IsDBNull(5)?"":r.GetString(5),
                Data      =r.IsDBNull(6)?"":r.GetString(6),
                ReceivedAt=r.IsDBNull(7)?"":r.GetString(7) });
        return new EventsResponse { Events=list, Total=total, Limit=f.Limit, Offset=f.Offset };
    }

    // FIX: SQL строки разбиты на конкатенацию вместо verbatim — убраны переносы в константах
    public string QueryCsv(EventFilter f)
    {
        f.Limit = 100000; f.Offset = 0;
        using var conn = Open();
        var (where, parms) = BuildEventsWhere(f);
        var dc = conn.CreateCommand();
        dc.CommandText = "SELECT ts,host,user_name,module,msg,data,received_at FROM events " +
            where + " ORDER BY ts DESC,id DESC LIMIT 100000";
        foreach (var (k,v) in parms) dc.Parameters.AddWithValue(k, v);
        var sb = new StringBuilder();
        // UTF-8 BOM — нужен для корректного отображения кириллицы в Excel
        sb.Append("\uFEFF");
        sb.AppendLine("Timestamp,Host,User,Module,Message,Data,ReceivedAt");
        using var r = dc.ExecuteReader();
        while (r.Read())
        {
            sb.Append(CsvField(r.IsDBNull(0)?"":r.GetString(0))); sb.Append(',');
            sb.Append(CsvField(r.IsDBNull(1)?"":r.GetString(1))); sb.Append(',');
            sb.Append(CsvField(r.IsDBNull(2)?"":r.GetString(2))); sb.Append(',');
            sb.Append(CsvField(r.IsDBNull(3)?"":r.GetString(3))); sb.Append(',');
            sb.Append(CsvField(r.IsDBNull(4)?"":r.GetString(4))); sb.Append(',');
            sb.Append(CsvField(r.IsDBNull(5)?"":r.GetString(5))); sb.Append(',');
            sb.AppendLine(CsvField(r.IsDBNull(6)?"":r.GetString(6)));
        }
        return sb.ToString();
    }

    public DashboardStats GetStats()
    {
        using var conn = Open();
        long total  = Scalar<long>(conn, "SELECT COUNT(*) FROM events");
        string today = DateTime.UtcNow.ToString("yyyy-MM-dd");
        long alerts = Scalar<long>(conn,
            "SELECT COUNT(*) FROM events WHERE " +
            "(module LIKE '%ALERT%' OR module LIKE '%ERROR%') AND ts>=$d",
            ("$d", today));
        int hosts = (int)Scalar<long>(conn,
            "SELECT COUNT(*) FROM hosts WHERE last_seen>=$d",
            ("$d", DateTime.UtcNow.AddHours(-24).ToString("o")));
        string lastTs = Scalar<string>(conn,
            "SELECT ts FROM events ORDER BY ts DESC LIMIT 1") ?? "";
        long dbSize = File.Exists(_dbPath) ? new FileInfo(_dbPath).Length : 0;
        long ssSize = DirSize(_screenshotDir);
        var topModules = new List<ModuleStat>();
        var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT module,COUNT(*) FROM events " +
            "GROUP BY module ORDER BY COUNT(*) DESC LIMIT 10";
        using var r = cmd.ExecuteReader();
        while (r.Read())
            topModules.Add(new ModuleStat{Module=r.GetString(0),Count=r.GetInt64(1)});
        return new DashboardStats {
            TotalEvents=total, AlertsToday=alerts, ActiveHosts=hosts,
            LastEventTs=lastTs, DbSizeBytes=dbSize, ScreenshotBytes=ssSize,
            TopModules=topModules };
    }

    public List<string> GetHosts()
    {
        using var conn = Open();
        var list = new List<string>();
        var cmd  = conn.CreateCommand();
        cmd.CommandText = "SELECT host FROM hosts ORDER BY last_seen DESC";
        using var r = cmd.ExecuteReader();
        while (r.Read()) list.Add(r.GetString(0));
        return list;
    }

    // ── Screenshots ───────────────────────────────────────────────────────
    public long SaveScreenshot(ScreenshotUpload upload)
    {
        byte[] jpeg = Convert.FromBase64String(upload.Jpeg);
        string dateDir = Path.Combine(_screenshotDir,
            DateTime.UtcNow.ToString("yyyyMMdd"), upload.Host);
        Directory.CreateDirectory(dateDir);
        string filename = DateTime.UtcNow.ToString("HHmmss_fff") + "_" + upload.Trigger + ".jpg";
        File.WriteAllBytes(Path.Combine(dateDir, filename), jpeg);
        using var conn = Open();
        var cmd = conn.CreateCommand();
        cmd.CommandText = "INSERT INTO screenshots " +
            "(ts,host,user_name,trigger,window,resolution,filename,size_bytes,received_at,agent_id) " +
            "VALUES ($ts,$host,$user,$trigger,$window,$res,$file,$size,$rec,$aid); " +
            "SELECT last_insert_rowid();";
        cmd.Parameters.AddWithValue("$ts",      upload.Ts);
        cmd.Parameters.AddWithValue("$host",    upload.Host);
        cmd.Parameters.AddWithValue("$user",    upload.User);
        cmd.Parameters.AddWithValue("$trigger", upload.Trigger);
        cmd.Parameters.AddWithValue("$window",  upload.Window);
        cmd.Parameters.AddWithValue("$res",     upload.Resolution);
        cmd.Parameters.AddWithValue("$file",
            Path.Combine(DateTime.UtcNow.ToString("yyyyMMdd"), upload.Host, filename));
        cmd.Parameters.AddWithValue("$size", jpeg.Length);
        cmd.Parameters.AddWithValue("$rec",  DateTime.UtcNow.ToString("o"));
        cmd.Parameters.AddWithValue("$aid",  upload.AgentId ?? "");
        return (long)(cmd.ExecuteScalar() ?? 0L);
    }

    public ScreenshotsResponse QueryScreenshots(ScreenshotFilter f)
    {
        using var conn = Open();
        var conds = new List<string>(); var parms = new List<(string,object)>();
        if (!string.IsNullOrWhiteSpace(f.Host))
        { conds.Add("host=$host"); parms.Add(("$host", f.Host)); }
        if (!string.IsNullOrWhiteSpace(f.AgentId))
        { conds.Add("agent_id=$agentId"); parms.Add(("$agentId", f.AgentId)); }
        if (!string.IsNullOrWhiteSpace(f.From))
        { conds.Add("ts>=$from"); parms.Add(("$from", f.From)); }
        if (!string.IsNullOrWhiteSpace(f.To))
        { conds.Add("ts<=$to"); parms.Add(("$to", f.To + "T23:59:59")); }
        if (!string.IsNullOrWhiteSpace(f.Search))
        { conds.Add("(LOWER(window) LIKE LOWER($search) OR LOWER(host) LIKE LOWER($search))");
          parms.Add(("$search", "%" + f.Search + "%")); }
        string where = conds.Count > 0 ? "WHERE " + string.Join(" AND ", conds) : "";
        var cc = conn.CreateCommand();
        cc.CommandText = "SELECT COUNT(*) FROM screenshots " + where;
        foreach (var (k,v) in parms) cc.Parameters.AddWithValue(k, v);
        long total = (long)(cc.ExecuteScalar() ?? 0L);
        var dc = conn.CreateCommand();
        dc.CommandText = "SELECT id,ts,host,user_name,trigger,window,resolution,size_bytes,received_at " +
            "FROM screenshots " + where + " ORDER BY ts DESC,id DESC LIMIT $lim OFFSET $off";
        foreach (var (k,v) in parms) dc.Parameters.AddWithValue(k, v);
        dc.Parameters.AddWithValue("$lim", f.Limit);
        dc.Parameters.AddWithValue("$off", f.Offset);
        var list = new List<ScreenshotRecord>();
        using var r = dc.ExecuteReader();
        while (r.Read())
            list.Add(new ScreenshotRecord {
                Id=r.GetInt64(0),
                Ts        =r.IsDBNull(1)?"":r.GetString(1),
                Host      =r.IsDBNull(2)?"":r.GetString(2),
                User      =r.IsDBNull(3)?"":r.GetString(3),
                Trigger   =r.IsDBNull(4)?"":r.GetString(4),
                Window    =r.IsDBNull(5)?"":r.GetString(5),
                Resolution=r.IsDBNull(6)?"":r.GetString(6),
                SizeBytes =r.IsDBNull(7)?0:r.GetInt64(7),
                ReceivedAt=r.IsDBNull(8)?"":r.GetString(8) });
        return new ScreenshotsResponse{Screenshots=list,Total=total,Limit=f.Limit,Offset=f.Offset};
    }

    public string? GetScreenshotPath(long id)
    {
        using var conn = Open();
        var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT filename FROM screenshots WHERE id=$id";
        cmd.Parameters.AddWithValue("$id", id);
        string? rel = cmd.ExecuteScalar() as string;
        return rel == null ? null : Path.Combine(_screenshotDir, rel);
    }

    public bool DeleteScreenshot(long id)
    {
        string? path = GetScreenshotPath(id);
        if (path != null && File.Exists(path))
        {
            try { File.Delete(path); } catch { }
            try { string? d = Path.GetDirectoryName(path);
                  if (d != null && Directory.Exists(d) && !Directory.EnumerateFiles(d).Any())
                      Directory.Delete(d); } catch { }
        }
        using var conn = Open();
        var cmd = conn.CreateCommand();
        cmd.CommandText = "DELETE FROM screenshots WHERE id=$id";
        cmd.Parameters.AddWithValue("$id", id);
        return cmd.ExecuteNonQuery() > 0;
    }

    public int DeleteScreenshotsByHost(string host)
    {
        using var conn = Open();
        var sel = conn.CreateCommand();
        sel.CommandText = "SELECT filename FROM screenshots WHERE host=$host";
        sel.Parameters.AddWithValue("$host", host);
        var files = new List<string>();
        using (var r = sel.ExecuteReader()) while (r.Read()) files.Add(r.GetString(0));
        foreach (var rel in files)
        {
            string full = Path.Combine(_screenshotDir, rel);
            try { if (File.Exists(full)) File.Delete(full); } catch { }
        }
        var del = conn.CreateCommand();
        del.CommandText = "DELETE FROM screenshots WHERE host=$host";
        del.Parameters.AddWithValue("$host", host);
        return del.ExecuteNonQuery();
    }

    public int DeleteEventsByHost(string host)
    {
        using var conn = Open();
        var cmd = conn.CreateCommand();
        cmd.CommandText = "DELETE FROM events WHERE host=$host";
        cmd.Parameters.AddWithValue("$host", host);
        return cmd.ExecuteNonQuery();
    }

    public (int Events, int Screenshots) PurgeHost(string host)
    {
        int ss = DeleteScreenshotsByHost(host);
        int ev = DeleteEventsByHost(host);
        RemoveAgent(host);
        return (ev, ss);
    }

    public int DeleteAllScreenshots()
    {
        try { if (Directory.Exists(_screenshotDir))
            foreach (var f in Directory.GetFiles(_screenshotDir, "*.jpg",
                SearchOption.AllDirectories))
            try { File.Delete(f); } catch { } } catch { }
        using var conn = Open();
        var cmd = conn.CreateCommand();
        cmd.CommandText = "DELETE FROM screenshots";
        return cmd.ExecuteNonQuery();
    }

    public int DeleteAllEvents()
    {
        using var conn = Open();
        var cmd = conn.CreateCommand();
        cmd.CommandText = "DELETE FROM events";
        return cmd.ExecuteNonQuery();
    }

    // ── Commands ──────────────────────────────────────────────────────────
    public long CreateCommand(string host, string command, string payload = "",
                              string agentId = "")
    {
        using var conn = Open();
        var cmd = conn.CreateCommand();
        cmd.CommandText = "INSERT INTO commands (host,command,payload,status,created_at,agent_id) " +
            "VALUES ($host,$cmd,$payload,'pending',$ts,$aid); SELECT last_insert_rowid();";
        cmd.Parameters.AddWithValue("$host",    host);
        cmd.Parameters.AddWithValue("$cmd",     command);
        cmd.Parameters.AddWithValue("$payload", payload ?? "");
        cmd.Parameters.AddWithValue("$ts",      DateTime.UtcNow.ToString("o"));
        cmd.Parameters.AddWithValue("$aid",     agentId);
        return (long)(cmd.ExecuteScalar() ?? 0L);
    }

    public List<AgentCommand> GetPendingCommands(string host, string agentId = "",
                                              string agentStatus = "active")
    {
        using var conn = Open();
        string ts     = DateTime.UtcNow.ToString("o");
        string aid    = string.IsNullOrWhiteSpace(agentId) ? host : agentId;
        string status = agentStatus == "stopped" ? "stopped" : "active";

        // Check if this is a brand-new agent (no row with this agent_id)
        var existCmd = conn.CreateCommand();
        existCmd.CommandText = "SELECT COUNT(*) FROM hosts WHERE agent_id=$aid";
        existCmd.Parameters.AddWithValue("$aid", aid);
        bool isNew = (long)existCmd.ExecuteScalar()! == 0;

        // Heartbeat — upsert by agent_id, store monitoring status
        var hb = conn.CreateCommand();
        hb.CommandText = "INSERT INTO hosts (host, agent_id, last_seen, first_seen, agent_status) " +
            "VALUES ($host, $aid, $ts, $ts, $status) " +
            "ON CONFLICT(agent_id, host) DO UPDATE SET last_seen=excluded.last_seen, " +
            "host=excluded.host, agent_status=excluded.agent_status";
        hb.Parameters.AddWithValue("$host",   host);
        hb.Parameters.AddWithValue("$aid",    aid);
        hb.Parameters.AddWithValue("$ts",     ts);
        hb.Parameters.AddWithValue("$status", status);
        hb.ExecuteNonQuery();

        // Fire AGENT_ONLINE event on first appearance
        if (isNew)
        {
            var ev = conn.CreateCommand();
            ev.CommandText = "INSERT INTO events (ts, host, user_name, module, msg, data, received_at) " +
                "VALUES ($ts, $host, 'system', 'AGENT_ONLINE', 'New agent connected', $data, $ts)";
            ev.Parameters.AddWithValue("$ts",   ts);
            ev.Parameters.AddWithValue("$host", host);
            ev.Parameters.AddWithValue("$data", $"agent_id={aid}|first_seen={ts}");
            ev.ExecuteNonQuery();
        }

        var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT id,host,command,payload,status,created_at FROM commands " +
            "WHERE status='pending' AND (host=$host OR host='*') ORDER BY id ASC LIMIT 10";
        cmd.Parameters.AddWithValue("$host", host);
        var list = new List<AgentCommand>();
        using var r = cmd.ExecuteReader();
        while (r.Read())
            list.Add(new AgentCommand{
                Id=r.GetInt64(0), Host=r.GetString(1), Command=r.GetString(2),
                Payload=r.GetString(3), Status=r.GetString(4), CreatedAt=r.GetString(5) });
        if (list.Count > 0)
        {
            string ids = string.Join(",", list.ConvertAll(c => c.Id));
            var upd = conn.CreateCommand();
            upd.CommandText = "UPDATE commands SET status='delivered',delivered_at=$ts " +
                "WHERE id IN (" + ids + ")";
            upd.Parameters.AddWithValue("$ts", DateTime.UtcNow.ToString("o"));
            upd.ExecuteNonQuery();
        }
        return list;
    }

    public void ReportCommandResult(long id, string status, string error = "")
    {
        using var conn = Open();
        var cmd = conn.CreateCommand();
        cmd.CommandText = "UPDATE commands SET status=$s,executed_at=$ts,error=$err WHERE id=$id";
        cmd.Parameters.AddWithValue("$s",   status);
        cmd.Parameters.AddWithValue("$ts",  DateTime.UtcNow.ToString("o"));
        cmd.Parameters.AddWithValue("$err", error ?? "");
        cmd.Parameters.AddWithValue("$id",  id);
        cmd.ExecuteNonQuery();
    }

    public AgentCommand? GetCommandById(long id)
    {
        using var conn = Open();
        var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT id,host,command,payload,status," +
            "created_at,delivered_at,executed_at,error FROM commands WHERE id=$id";
        cmd.Parameters.AddWithValue("$id", id);
        using var r = cmd.ExecuteReader();
        if (!r.Read()) return null;
        return new AgentCommand{
            Id=r.GetInt64(0), Host=r.GetString(1), Command=r.GetString(2),
            Payload=r.GetString(3), Status=r.GetString(4), CreatedAt=r.GetString(5),
            DeliveredAt=r.GetString(6), ExecutedAt=r.GetString(7), Error=r.GetString(8) };
    }

    public List<AgentCommand> GetCommands(string? host = null, int limit = 50)
    {
        using var conn = Open();
        var cmd = conn.CreateCommand();
        string where = host != null ? "WHERE host=$host OR host='*'" : "";
        cmd.CommandText = "SELECT id,host,command,payload,status," +
            "created_at,delivered_at,executed_at,error FROM commands " +
            where + " ORDER BY id DESC LIMIT $lim";
        if (host != null) cmd.Parameters.AddWithValue("$host", host);
        cmd.Parameters.AddWithValue("$lim", limit);
        var list = new List<AgentCommand>();
        using var r = cmd.ExecuteReader();
        while (r.Read())
            list.Add(new AgentCommand{
                Id=r.GetInt64(0), Host=r.GetString(1), Command=r.GetString(2),
                Payload=r.GetString(3), Status=r.GetString(4), CreatedAt=r.GetString(5),
                DeliveredAt=r.GetString(6), ExecutedAt=r.GetString(7), Error=r.GetString(8) });
        return list;
    }

    public List<AgentStatus> GetAgentStatuses()
    {
        using var conn = Open();
        var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT h.host, h.agent_id, h.first_seen, h.last_seen," +
            "(SELECT COUNT(*) FROM events e WHERE e.host=h.host) as ev_count, " +
            "h.agent_status " +
            "FROM hosts h ORDER BY h.last_seen DESC";
        var now  = DateTimeOffset.UtcNow;
        var list = new List<AgentStatus>();
        using var r = cmd.ExecuteReader();
        while (r.Read())
        {
            // Columns: 0=host, 1=agent_id, 2=first_seen, 3=last_seen, 4=ev_count
            string agentId   = r.IsDBNull(1) ? "" : r.GetString(1);
            string firstSeen = r.IsDBNull(2) ? "" : r.GetString(2);
            string ls        = r.IsDBNull(3) ? "" : r.GetString(3);
            bool online = false;
            if (DateTimeOffset.TryParse(ls, out var dto))
                online = (now - dto).TotalMinutes < 2;
            string agentStatusVal = r.IsDBNull(5) ? "active" : r.GetString(5);
            list.Add(new AgentStatus{
                Host=r.GetString(0), LastSeen=ls,
                AgentId=agentId, FirstSeen=firstSeen,
                Online=online, Events=r.GetInt64(4),
                MonitorStatus=agentStatusVal });
        }
        return list;
    }

    public void RemoveAgent(string host, string agentId = "")
    {
        using var conn = Open();
        using var tx   = conn.BeginTransaction();
        string ts  = DateTime.UtcNow.ToString("o");
        bool   byId = !string.IsNullOrWhiteSpace(agentId);

        // Log AGENT_REMOVED event before deleting
        var ev = conn.CreateCommand();
        ev.CommandText = "INSERT INTO events (ts, host, user_name, module, msg, data, received_at) " +
            "VALUES ($ts, $h, 'system', 'AGENT_REMOVED', 'Agent removed from dashboard', $data, $ts)";
        ev.Parameters.AddWithValue("$ts",   ts);
        ev.Parameters.AddWithValue("$h",    host);
        ev.Parameters.AddWithValue("$data", byId ? $"action=dashboard_remove|agent_id={agentId}" : "action=dashboard_remove");
        ev.ExecuteNonQuery();

        // Delete only the specific agent_id when known — prevents mass-deletion
        // of all agents sharing the same hostname
        var c1 = conn.CreateCommand();
        c1.CommandText = byId
            ? "DELETE FROM hosts WHERE host=$h AND agent_id=$aid"
            : "DELETE FROM hosts WHERE host=$h";
        c1.Parameters.AddWithValue("$h",   host);
        if (byId) c1.Parameters.AddWithValue("$aid", agentId);
        c1.ExecuteNonQuery();

        // Commands are always cleaned up for the host (they don't have agent_id)
        var c2 = conn.CreateCommand();
        c2.CommandText = "DELETE FROM commands WHERE host=$h";
        c2.Parameters.AddWithValue("$h", host);
        c2.ExecuteNonQuery();
        tx.Commit();
    }


    // ── Per-agent API keys ────────────────────────────────────────────────

    /// <summary>Enroll agent: generate unique key, store, return it.</summary>
    public string EnrollAgent(string agentId, string host)
    {
        using var conn = Open();
        // Check if already enrolled and not revoked
        var check = conn.CreateCommand();
        check.CommandText = "SELECT api_key FROM agent_keys WHERE agent_id=$aid AND revoked=0";
        check.Parameters.AddWithValue("$aid", agentId);
        var existing = check.ExecuteScalar() as string;
        if (!string.IsNullOrEmpty(existing)) return existing;

        // Generate new key
        string key = Convert.ToHexString(
            System.Security.Cryptography.RandomNumberGenerator.GetBytes(32));
        var ins = conn.CreateCommand();
        ins.CommandText = "INSERT INTO agent_keys (agent_id, api_key, host, created_at) " +
            "VALUES ($aid, $key, $host, $ts) " +
            "ON CONFLICT(agent_id) DO UPDATE SET api_key=$key, host=$host, " +
            "created_at=$ts, revoked=0";
        ins.Parameters.AddWithValue("$aid",  agentId);
        ins.Parameters.AddWithValue("$key",  key);
        ins.Parameters.AddWithValue("$host", host);
        ins.Parameters.AddWithValue("$ts",   DateTime.UtcNow.ToString("o"));
        ins.ExecuteNonQuery();
        return key;
    }

    /// <summary>Validate agent-specific key. Returns true if valid and not revoked.</summary>
    public bool ValidateAgentKey(string agentId, string agentKey)
    {
        if (string.IsNullOrWhiteSpace(agentId) || string.IsNullOrWhiteSpace(agentKey))
            return false;
        using var conn = Open();
        var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT COUNT(*) FROM agent_keys " +
            "WHERE agent_id=$aid AND api_key=$key AND revoked=0";
        cmd.Parameters.AddWithValue("$aid", agentId);
        cmd.Parameters.AddWithValue("$key", agentKey);
        return (long)(cmd.ExecuteScalar() ?? 0L) > 0;
    }

    /// <summary>Get all enrolled agent keys (for admin dashboard).</summary>
    public List<AgentKeyInfo> GetAgentKeys()
    {
        using var conn = Open();
        var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT agent_id, host, created_at, revoked FROM agent_keys ORDER BY created_at DESC";
        var list = new List<AgentKeyInfo>();
        using var r = cmd.ExecuteReader();
        while (r.Read())
            list.Add(new AgentKeyInfo {
                AgentId   = r.GetString(0),
                Host      = r.GetString(1),
                CreatedAt = r.GetString(2),
                Revoked   = r.GetInt64(3) != 0
            });
        return list;
    }

    /// <summary>Revoke agent key (admin action).</summary>
    public bool RevokeAgentKey(string agentId)
    {
        using var conn = Open();
        var cmd = conn.CreateCommand();
        cmd.CommandText = "UPDATE agent_keys SET revoked=1 WHERE agent_id=$aid";
        cmd.Parameters.AddWithValue("$aid", agentId);
        return cmd.ExecuteNonQuery() > 0;
    }
    // ── System event helper ──────────────────────────────────────────────
    public void InsertSystemEvent(string host, string module, string msg,
                                  string data = "", string agentId = "")
    {
        try
        {
            using var conn = Open();
            string ts = DateTime.UtcNow.ToString("o");
            var cmd = conn.CreateCommand();
            cmd.CommandText = "INSERT INTO events (ts,host,user_name,module,msg,data,received_at,agent_id) " +
                "VALUES ($ts,$host,'system',$mod,$msg,$data,$ts,$aid)";
            cmd.Parameters.AddWithValue("$ts",   ts);
            cmd.Parameters.AddWithValue("$host", host);
            cmd.Parameters.AddWithValue("$mod",  module);
            cmd.Parameters.AddWithValue("$msg",  msg);
            cmd.Parameters.AddWithValue("$data", data);
            cmd.Parameters.AddWithValue("$aid",  agentId);
            cmd.ExecuteNonQuery();
        }
        catch { /* system events must not crash main flow */ }
    }

    // ── Helpers ───────────────────────────────────────────────────────────
    private SqliteConnection Open()
    {
        var conn = new SqliteConnection(_connStr);
        conn.Open();
        return conn;
    }

    private static void Exec(SqliteConnection conn, string sql)
    {
        var cmd = conn.CreateCommand();
        cmd.CommandText = sql;
        cmd.ExecuteNonQuery();
    }

    private static T Scalar<T>(SqliteConnection conn, string sql,
        params (string, object)[] parms)
    {
        var cmd = conn.CreateCommand();
        cmd.CommandText = sql;
        foreach (var (k,v) in parms) cmd.Parameters.AddWithValue(k, v);
        var r = cmd.ExecuteScalar();
        if (r is null || r is DBNull) return default!;
        return (T)Convert.ChangeType(r, typeof(T));
    }

    private static (string, List<(string, object)>) BuildEventsWhere(EventFilter f)
    {
        var conds = new List<string>(); var parms = new List<(string, object)>();
        if (!string.IsNullOrWhiteSpace(f.Module))
        { conds.Add("module=$module"); parms.Add(("$module", f.Module)); }
        if (!string.IsNullOrWhiteSpace(f.Host))
        { conds.Add("host=$host"); parms.Add(("$host", f.Host)); }
        if (!string.IsNullOrWhiteSpace(f.AgentId))
        { conds.Add("agent_id=$agentId"); parms.Add(("$agentId", f.AgentId)); }
        if (!string.IsNullOrWhiteSpace(f.From))
        { conds.Add("ts>=$from"); parms.Add(("$from", f.From)); }
        if (!string.IsNullOrWhiteSpace(f.To))
        { conds.Add("ts<=$to"); parms.Add(("$to", f.To + "T23:59:59")); }
        if (!string.IsNullOrWhiteSpace(f.Search))
        { conds.Add("(msg LIKE $s OR data LIKE $s OR host LIKE $s)");
          parms.Add(("$s", "%" + f.Search + "%")); }
        return (conds.Count > 0 ? "WHERE " + string.Join(" AND ", conds) : "", parms);
    }

    private static long DirSize(string path)
    {
        try { return Directory.Exists(path)
            ? Directory.GetFiles(path, "*", SearchOption.AllDirectories)
                       .Sum(f => new FileInfo(f).Length)
            : 0; }
        catch { return 0; }
    }

    private static string CsvField(string s)
    {
        if (s.Contains(',') || s.Contains('"') || s.Contains('\n'))
            return "\"" + s.Replace("\"", "\"\"") + "\"";
        return s;
    }

    private static string? ValidatePassword(string password)
    {
        if (password.Length < 12)
            return "Пароль минимум 12 символов";
        bool hasUpper   = false, hasLower = false, hasDigit = false, hasSpecial = false;
        foreach (char c in password)
        {
            if (char.IsUpper(c))   hasUpper   = true;
            if (char.IsLower(c))   hasLower   = true;
            if (char.IsDigit(c))   hasDigit   = true;
            if (!char.IsLetterOrDigit(c)) hasSpecial = true;
        }
        if (!hasUpper)   return "Пароль должен содержать заглавные буквы";
        if (!hasLower)   return "Пароль должен содержать строчные буквы";
        if (!hasDigit)   return "Пароль должен содержать цифры";
        if (!hasSpecial) return "Пароль должен содержать спецсимволы (!@#$%^ и т.д.)";
        return null;
    }

    private static string HashPassword(string password, out string salt)
    {
        byte[] sb = new byte[16];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(sb);
        salt = Convert.ToBase64String(sb);
        byte[] hash = Rfc2898DeriveBytes.Pbkdf2(
            Encoding.UTF8.GetBytes(password), sb,
            100_000, HashAlgorithmName.SHA256, 32);
        return Convert.ToBase64String(hash);
    }

    private static bool VerifyPassword(string password, string storedHash, string salt)
    {
        byte[] sb = Convert.FromBase64String(salt);
        byte[] hash = Rfc2898DeriveBytes.Pbkdf2(
            Encoding.UTF8.GetBytes(password), sb,
            100_000, HashAlgorithmName.SHA256, 32);
        return Convert.ToBase64String(hash) == storedHash;
    }

    private static string GenerateToken()
    {
        byte[] b = new byte[32];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(b);
        return Convert.ToHexString(b).ToLower();
    }
}
