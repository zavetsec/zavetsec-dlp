using System;
using System.IO;
using System.Reflection;
using System.Text;

namespace ZavetSec.DlpAgent
{
    // ── Структуры конфига ──────────────────────────────────────────────────

    internal class ScreenshotConfig
    {
        public int    IntervalMinutes            { get; set; } = 5;
        public int    JpegQuality                { get; set; } = 75;
        public bool   OnWindowChange             { get; set; } = true;
        public bool   OnStartup                  { get; set; } = true;
        public int    WindowCheckIntervalSeconds { get; set; } = 1;
        public bool   BlankScreenDetection       { get; set; } = true;
    }

    internal class KeyloggerConfig
    {
        public bool Enabled      { get; set; } = true;
        public int  BufferChars  { get; set; } = 512;
        public int  FlushSeconds { get; set; } = 30;
    }

    internal class ClipboardConfig
    {
        public bool     Enabled          { get; set; } = true;
        public int      PollIntervalMs   { get; set; } = 500;
        public int      MaxContentLength { get; set; } = 4096;
        public string[] SensitiveWords   { get; set; } = new[]
        {
            "password", "пароль", "secret", "token"
        };
    }

    internal class NetworkConfig
    {
        public bool  Enabled                  { get; set; } = true;
        public int   ConnectionCheckSeconds   { get; set; } = 10;
        public int   DnsCheckSeconds          { get; set; } = 30;
        public int[] AlertPorts               { get; set; } = new[]
        {
            22, 23, 3389, 4444, 5900, 6667
        };
    }

    internal class StorageConfig
    {
        public string LogDir                { get; set; } = @"C:\ProgramData\ZavetSec\DLP\Logs";
        public string ScreenshotDir        { get; set; } = @"C:\ProgramData\ZavetSec\DLP\Screenshots";
        public string KeyFile              { get; set; } = @"C:\ProgramData\ZavetSec\DLP\agent.key";
        public int    RetentionLogDays     { get; set; } = 30;
        public int    RetentionScreenshotDays { get; set; } = 7;
        public int    MaxLogMb             { get; set; } = 500;
        public int    MaxScreenshotMb      { get; set; } = 2048;
    }


    internal class ProcessesConfig
    {
        public bool     Enabled               { get; set; } = true;
        public int      CheckIntervalSeconds  { get; set; } = 10;
        public bool     LogProcessEnd         { get; set; } = false;

        // Процессы которые НЕ логируются вообще (системные, антивирус и т.д.)
        public string[] Whitelist             { get; set; } = new[]
        {
            "svchost", "csrss", "lsass", "smss", "wininit", "winlogon",
            "services", "spoolsv", "taskhost", "taskhostw", "dwm",
            "explorer", "sihost", "ctfmon", "conhost", "fontdrvhost",
            "runtimebroker", "searchindexer", "searchhost", "securityhealthservice",
            "microsoftedgeupdate", "trustedinstaller", "tiworker",
            "registry", "system", "idle", "memory compression",
            "antimalware service executable", "mssense", "mscorsvw",
            "wsappx", "wuauclt", "audiodg", "dllhost", "wermgr"
        };

        // Процессы которые вызывают PROCESS_ALERT
        public string[] SuspiciousProcesses  { get; set; } = new[]
        {
            "mimikatz", "procdump", "psexec", "psexesvc",
            "wce", "fgdump", "pwdump", "meterpreter",
            "nc", "ncat", "netcat", "nmap",
            "wireshark", "tshark", "fiddler",
            "processhacker", "procexp", "procexp64",
            "regedit", "reg",
            "torrc", "tor",
            "veracrypt", "truecrypt",
            "teamviewer", "anydesk", "radmin",
            "7z", "winrar", "winzip"
        };
    }

    internal class ScreenshotEncryptConfig
    {
        public bool Enabled { get; set; } = true;
    }

    internal class ShipperConfig
    {
        public bool   Enabled                            { get; set; } = true;
        public string ServerUrl                          { get; set; } = "http://YOUR-SERVER:5000";
        public string ApiKey                             { get; set; } = "";
        public int    BatchSize                          { get; set; } = 50;
        public int    FlushSeconds                       { get; set; } = 30;
        public int    MaxQueueSize                       { get; set; } = 5000;
        public bool   DeleteLocalScreenshotsAfterUpload { get; set; } = true;
        // true = принимать самоподписанные HTTPS сертификаты (для корпоративного HTTPS без CA)
        public bool   AllowInvalidCertificate            { get; set; } = true;
        // Unique ID for this agent installation — auto-generated on first run.
        // Allows identifying agents even when hostnames are duplicated.
        public string AgentId                            { get; set; } = "";
    }

    internal class AgentConfig
    {
        public ScreenshotConfig        Screenshot        { get; set; } = new ScreenshotConfig();
        public KeyloggerConfig         Keylogger         { get; set; } = new KeyloggerConfig();
        public ClipboardConfig         Clipboard         { get; set; } = new ClipboardConfig();
        public NetworkConfig           Network           { get; set; } = new NetworkConfig();
        public StorageConfig           Storage           { get; set; } = new StorageConfig();
        public ProcessesConfig         Processes         { get; set; } = new ProcessesConfig();
        public ScreenshotEncryptConfig ScreenshotEncrypt { get; set; } = new ScreenshotEncryptConfig();
        public ShipperConfig           Shipper           { get; set; } = new ShipperConfig();
    }

    // ── Загрузчик ──────────────────────────────────────────────────────────

    /// <summary>
    /// Читает config.json из папки рядом с exe.
    /// Если файл не найден или повреждён — использует значения по умолчанию.
    /// Не требует внешних зависимостей (ручной парсинг JSON).
    /// </summary>
    internal static class Config
    {
        private static AgentConfig _instance;
        private static readonly object _lock = new object();

        public static AgentConfig Current
        {
            get
            {
                if (_instance == null)
                    lock (_lock)
                        if (_instance == null)
                            _instance = Load(silent: true);
                return _instance;
            }
        }

        /// <summary>
        /// Загрузить конфиг ДО инициализации Logger (без вызова Logger.Write).
        /// Вызывать первым в StartInternal().
        /// </summary>
        public static void InitSilent()
        {
            lock (_lock)
            {
                _instance = Load(silent: true);
            }
        }

        /// <summary>
        /// Перезагрузить конфиг без перезапуска агента.
        /// </summary>
        public static void Reload()
        {
            lock (_lock) { _instance = Load(silent: false); }
        }

        // ── Загрузка ───────────────────────────────────────────────────────
        private static AgentConfig Load(bool silent = false)
        {
            string path = GetConfigPath();

            if (!File.Exists(path))
            {
                WriteDefault(path);
                if (!silent) Logger.Write("CONFIG", $"config.json не найден, создан с умолчаниями: {path}");
                return new AgentConfig();
            }

            try
            {
                string json = File.ReadAllText(path, Encoding.UTF8);
                var cfg = new AgentConfig();
                ParseInto(json, cfg);

                // Auto-generate AgentId on first run if empty
                if (string.IsNullOrWhiteSpace(cfg.Shipper.AgentId))
                {
                    cfg.Shipper.AgentId = Guid.NewGuid().ToString("N").Substring(0, 16);
                    try
                    {
                        // Inject into existing json
                        string newId = cfg.Shipper.AgentId;
                        int shipperIdx = json.IndexOf("\"shipper\"");
                        int closeBrace = shipperIdx >= 0 ? json.IndexOf("}", shipperIdx) : -1;
                        if (closeBrace >= 0)
                        {
                            string inject = $",\n    \"agentId\": \"{newId}\"";
                            json = json.Insert(closeBrace, inject);
                            File.WriteAllText(path, json, Encoding.UTF8);
                        }
                    }
                    catch { /* non-fatal */ }
                }

                if (!silent) { Logger.Write("CONFIG", $"Конфиг загружен: {path}"); LogSettings(cfg); }
                return cfg;
            }
            catch (Exception ex)
            {
                if (!silent) Logger.Write("CONFIG_ERROR", $"Ошибка чтения конфига, используются умолчания: {ex.Message}");
                return new AgentConfig();
            }
        }

        private static string GetConfigPath()
        {
            string exeDir = AppContext.BaseDirectory;
            return Path.Combine(exeDir, "config.json");
        }

        private static void WriteDefault(string path)
        {
            try
            {
                string dir = Path.GetDirectoryName(path);
                if (!string.IsNullOrEmpty(dir))
                    Directory.CreateDirectory(dir);

                // Записать дефолтный конфиг из встроенного шаблона
                File.WriteAllText(path, DefaultJson(), Encoding.UTF8);
            }
            catch { /* нет прав — не страшно, используем умолчания */ }
        }

        // ── Логирование текущих настроек ───────────────────────────────────
        private static void LogSettings(AgentConfig cfg)
        {
            Logger.Write("CONFIG", "Скриншоты",
                $"interval={cfg.Screenshot.IntervalMinutes}m|" +
                $"quality={cfg.Screenshot.JpegQuality}|" +
                $"onWindowChange={cfg.Screenshot.OnWindowChange}");

            Logger.Write("CONFIG", "Keylogger",
                $"enabled={cfg.Keylogger.Enabled}|" +
                $"buffer={cfg.Keylogger.BufferChars}|" +
                $"flush={cfg.Keylogger.FlushSeconds}s");

            Logger.Write("CONFIG", "Сеть",
                $"alertPorts={string.Join(",", cfg.Network.AlertPorts)}|" +
                $"checkInterval={cfg.Network.ConnectionCheckSeconds}s");

            Logger.Write("CONFIG", "Процессы",
                $"enabled={cfg.Processes.Enabled}|" +
                $"interval={cfg.Processes.CheckIntervalSeconds}s|" +
                $"whitelist={cfg.Processes.Whitelist.Length}|" +
                $"suspicious={cfg.Processes.SuspiciousProcesses.Length}");

            Logger.Write("CONFIG", "Шифрование скриншотов",
                $"enabled={cfg.ScreenshotEncrypt.Enabled}");

            Logger.Write("CONFIG", "Хранилище",
                $"logRetention={cfg.Storage.RetentionLogDays}d|" +
                $"ssRetention={cfg.Storage.RetentionScreenshotDays}d|" +
                $"maxLog={cfg.Storage.MaxLogMb}MB|" +
                $"maxSS={cfg.Storage.MaxScreenshotMb}MB");
        }

        // ══════════════════════════════════════════════════════════════════
        //  Минимальный JSON-парсер (без System.Text.Json / Newtonsoft)
        //  Парсит только нужные нам типы: string, int, bool, string[], int[]
        // ══════════════════════════════════════════════════════════════════
        private static void ParseInto(string json, AgentConfig cfg)
        {
            // screenshot секция
            string ss = ExtractObject(json, "screenshot");
            if (ss != null)
            {
                cfg.Screenshot.IntervalMinutes            = GetInt(ss,  "intervalMinutes",            cfg.Screenshot.IntervalMinutes);
                cfg.Screenshot.JpegQuality                = GetInt(ss,  "jpegQuality",                cfg.Screenshot.JpegQuality);
                cfg.Screenshot.OnWindowChange             = GetBool(ss, "onWindowChange",             cfg.Screenshot.OnWindowChange);
                cfg.Screenshot.OnStartup                  = GetBool(ss, "onStartup",                  cfg.Screenshot.OnStartup);
                cfg.Screenshot.WindowCheckIntervalSeconds = GetInt(ss,  "windowCheckIntervalSeconds", cfg.Screenshot.WindowCheckIntervalSeconds);
                cfg.Screenshot.BlankScreenDetection       = GetBool(ss, "blankScreenDetection",       cfg.Screenshot.BlankScreenDetection);
            }

            // keylogger секция
            string kl = ExtractObject(json, "keylogger");
            if (kl != null)
            {
                cfg.Keylogger.Enabled      = GetBool(kl, "enabled",      cfg.Keylogger.Enabled);
                cfg.Keylogger.BufferChars  = GetInt(kl,  "bufferChars",  cfg.Keylogger.BufferChars);
                cfg.Keylogger.FlushSeconds = GetInt(kl,  "flushSeconds", cfg.Keylogger.FlushSeconds);
            }

            // clipboard секция
            string cb = ExtractObject(json, "clipboard");
            if (cb != null)
            {
                cfg.Clipboard.Enabled          = GetBool(cb, "enabled",          cfg.Clipboard.Enabled);
                cfg.Clipboard.PollIntervalMs   = GetInt(cb,  "pollIntervalMs",   cfg.Clipboard.PollIntervalMs);
                cfg.Clipboard.MaxContentLength = GetInt(cb,  "maxContentLength", cfg.Clipboard.MaxContentLength);
                var words = GetStringArray(cb, "sensitiveWords");
                if (words != null && words.Length > 0)
                    cfg.Clipboard.SensitiveWords = words;
            }

            // network секция
            string net = ExtractObject(json, "network");
            if (net != null)
            {
                cfg.Network.Enabled                = GetBool(net, "enabled",                cfg.Network.Enabled);
                cfg.Network.ConnectionCheckSeconds = GetInt(net,  "connectionCheckSeconds", cfg.Network.ConnectionCheckSeconds);
                cfg.Network.DnsCheckSeconds        = GetInt(net,  "dnsCheckSeconds",        cfg.Network.DnsCheckSeconds);
                var ports = GetIntArray(net, "alertPorts");
                if (ports != null && ports.Length > 0)
                    cfg.Network.AlertPorts = ports;
            }

            // storage секция
            string st = ExtractObject(json, "storage");
            if (st != null)
            {
                cfg.Storage.LogDir                   = GetString(st, "logDir",                   cfg.Storage.LogDir);
                cfg.Storage.ScreenshotDir            = GetString(st, "screenshotDir",            cfg.Storage.ScreenshotDir);
                cfg.Storage.KeyFile                  = GetString(st, "keyFile",                  cfg.Storage.KeyFile);
                cfg.Storage.RetentionLogDays         = GetInt(st,    "retentionLogDays",         cfg.Storage.RetentionLogDays);
                cfg.Storage.RetentionScreenshotDays  = GetInt(st,    "retentionScreenshotDays",  cfg.Storage.RetentionScreenshotDays);
                cfg.Storage.MaxLogMb                 = GetInt(st,    "maxLogMb",                 cfg.Storage.MaxLogMb);
                cfg.Storage.MaxScreenshotMb          = GetInt(st,    "maxScreenshotMb",          cfg.Storage.MaxScreenshotMb);
            }

            // processes секция
            string pr = ExtractObject(json, "processes");
            if (pr != null)
            {
                cfg.Processes.Enabled              = GetBool(pr, "enabled",              cfg.Processes.Enabled);
                cfg.Processes.CheckIntervalSeconds = GetInt(pr,  "checkIntervalSeconds", cfg.Processes.CheckIntervalSeconds);
                cfg.Processes.LogProcessEnd        = GetBool(pr, "logProcessEnd",        cfg.Processes.LogProcessEnd);
                var wl = GetStringArray(pr, "whitelist");
                if (wl != null && wl.Length > 0) cfg.Processes.Whitelist = wl;
                var sp = GetStringArray(pr, "suspiciousProcesses");
                if (sp != null && sp.Length > 0) cfg.Processes.SuspiciousProcesses = sp;
            }

            // screenshotEncrypt секция
            string se = ExtractObject(json, "screenshotEncrypt");
            if (se != null)
            {
                cfg.ScreenshotEncrypt.Enabled = GetBool(se, "enabled", cfg.ScreenshotEncrypt.Enabled);
            }

            // shipper секция
            string sh = ExtractObject(json, "shipper");
            if (sh != null)
            {
                cfg.Shipper.Enabled                            = GetBool(sh,   "enabled",                            cfg.Shipper.Enabled);
                cfg.Shipper.ServerUrl                          = GetString(sh, "serverUrl",                          cfg.Shipper.ServerUrl);
                cfg.Shipper.ApiKey                             = GetString(sh, "apiKey",                             cfg.Shipper.ApiKey);
                cfg.Shipper.BatchSize                          = GetInt(sh,    "batchSize",                          cfg.Shipper.BatchSize);
                cfg.Shipper.FlushSeconds                       = GetInt(sh,    "flushSeconds",                       cfg.Shipper.FlushSeconds);
                cfg.Shipper.MaxQueueSize                       = GetInt(sh,    "maxQueueSize",                       cfg.Shipper.MaxQueueSize);
                cfg.Shipper.DeleteLocalScreenshotsAfterUpload = GetBool(sh,   "deleteLocalScreenshotsAfterUpload",  cfg.Shipper.DeleteLocalScreenshotsAfterUpload);
                cfg.Shipper.AllowInvalidCertificate           = GetBool(sh,   "allowInvalidCertificate",            cfg.Shipper.AllowInvalidCertificate);
                cfg.Shipper.AgentId                            = GetString(sh, "agentId",                             cfg.Shipper.AgentId);
            }
        }

        // ── Примитивный парсер значений ────────────────────────────────────

        private static string ExtractObject(string json, string key)
        {
            string search = $"\"{key}\"";
            int ki = json.IndexOf(search, StringComparison.OrdinalIgnoreCase);
            if (ki < 0) return null;
            int ob = json.IndexOf('{', ki + search.Length);
            if (ob < 0) return null;
            int depth = 0, i = ob;
            while (i < json.Length)
            {
                if (json[i] == '{') depth++;
                else if (json[i] == '}') { depth--; if (depth == 0) return json.Substring(ob, i - ob + 1); }
                i++;
            }
            return null;
        }

        private static int GetInt(string json, string key, int def)
        {
            string val = GetRawValue(json, key);
            return val != null && int.TryParse(val.Trim(), out int r) ? r : def;
        }

        private static bool GetBool(string json, string key, bool def)
        {
            string val = GetRawValue(json, key);
            if (val == null) return def;
            val = val.Trim().ToLower();
            if (val == "true")  return true;
            if (val == "false") return false;
            return def;
        }

        private static string GetString(string json, string key, string def)
        {
            string search = $"\"{key}\"";
            int ki = json.IndexOf(search, StringComparison.OrdinalIgnoreCase);
            if (ki < 0) return def;
            int colon = json.IndexOf(':', ki + search.Length);
            if (colon < 0) return def;
            int q1 = json.IndexOf('"', colon + 1);
            if (q1 < 0) return def;
            int q2 = q1 + 1;
            while (q2 < json.Length)
            {
                if (json[q2] == '"' && json[q2 - 1] != '\\') break;
                q2++;
            }
            return json.Substring(q1 + 1, q2 - q1 - 1).Replace("\\\\", "\\").Replace("\\\"", "\"");
        }

        private static string[] GetStringArray(string json, string key)
        {
            string search = $"\"{key}\"";
            int ki = json.IndexOf(search, StringComparison.OrdinalIgnoreCase);
            if (ki < 0) return null;
            int ab = json.IndexOf('[', ki + search.Length);
            int ae = json.IndexOf(']', ab);
            if (ab < 0 || ae < 0) return null;
            string inner = json.Substring(ab + 1, ae - ab - 1);
            var items = new System.Collections.Generic.List<string>();
            int pos = 0;
            while (pos < inner.Length)
            {
                int q1 = inner.IndexOf('"', pos);
                if (q1 < 0) break;
                int q2 = q1 + 1;
                while (q2 < inner.Length && !(inner[q2] == '"' && inner[q2-1] != '\\')) q2++;
                items.Add(inner.Substring(q1 + 1, q2 - q1 - 1));
                pos = q2 + 1;
            }
            return items.ToArray();
        }

        private static int[] GetIntArray(string json, string key)
        {
            string search = $"\"{key}\"";
            int ki = json.IndexOf(search, StringComparison.OrdinalIgnoreCase);
            if (ki < 0) return null;
            int ab = json.IndexOf('[', ki + search.Length);
            int ae = json.IndexOf(']', ab);
            if (ab < 0 || ae < 0) return null;
            string inner = json.Substring(ab + 1, ae - ab - 1);
            var parts = inner.Split(new[] { ',', ' ', '\r', '\n', '\t' },
                StringSplitOptions.RemoveEmptyEntries);
            var nums = new System.Collections.Generic.List<int>();
            foreach (var p in parts)
                if (int.TryParse(p.Trim(), out int n)) nums.Add(n);
            return nums.ToArray();
        }

        private static string GetRawValue(string json, string key)
        {
            string search = $"\"{key}\"";
            int ki = json.IndexOf(search, StringComparison.OrdinalIgnoreCase);
            if (ki < 0) return null;
            int colon = json.IndexOf(':', ki + search.Length);
            if (colon < 0) return null;
            int start = colon + 1;
            while (start < json.Length && (json[start] == ' ' || json[start] == '\t')) start++;
            if (start >= json.Length) return null;
            int end = start;
            while (end < json.Length && json[end] != ',' && json[end] != '}' &&
                   json[end] != '\r' && json[end] != '\n') end++;
            return json.Substring(start, end - start).Trim();
        }

        // ── Дефолтный конфиг ──────────────────────────────────────────────
        private static string DefaultJson() => @"{
  ""screenshot"": {
    ""intervalMinutes"": 5,
    ""jpegQuality"": 75,
    ""onWindowChange"": true,
    ""onStartup"": true,
    ""windowCheckIntervalSeconds"": 1,
    ""blankScreenDetection"": true
  },
  ""keylogger"": {
    ""enabled"": true,
    ""bufferChars"": 512,
    ""flushSeconds"": 30
  },
  ""clipboard"": {
    ""enabled"": true,
    ""pollIntervalMs"": 500,
    ""maxContentLength"": 4096,
    ""sensitiveWords"": [
      ""password"", ""passwd"", ""\u043f\u0430\u0440\u043e\u043b\u044c"",
      ""secret"", ""token"", ""private key"",
      ""confidential"", ""\u043a\u043e\u043d\u0444\u0438\u0434\u0435\u043d\u0446\u0438\u0430\u043b\u044c\u043d\u043e"",
      ""credit"", ""\u043a\u0430\u0440\u0442\u0430"", ""ssn"", ""\u0438\u043d\u043d"", ""\u043f\u0430\u0441\u043f\u043e\u0440\u0442""
    ]
  },
  ""network"": {
    ""enabled"": true,
    ""connectionCheckSeconds"": 10,
    ""dnsCheckSeconds"": 30,
    ""alertPorts"": [22, 23, 3389, 4444, 5900, 6667]
  },
  ""storage"": {
    ""logDir"": ""C:\\ProgramData\\ZavetSec\\DLP\\Logs"",
    ""screenshotDir"": ""C:\\ProgramData\\ZavetSec\\DLP\\Screenshots"",
    ""keyFile"": ""C:\\ProgramData\\ZavetSec\\DLP\\agent.key"",
    ""retentionLogDays"": 30,
    ""retentionScreenshotDays"": 7,
    ""maxLogMb"": 500,
    ""maxScreenshotMb"": 2048
  },
  ""shipper"": {
    ""enabled"": true,
    ""serverUrl"": ""https://YOUR-SERVER:5001"",
    ""apiKey"": """",
    ""batchSize"": 50,
    ""flushSeconds"": 30,
    ""maxQueueSize"": 5000,
    ""deleteLocalScreenshotsAfterUpload"": true,
    ""allowInvalidCertificate"": true,
    ""agentId"": """"
  }
}";
    }
}
