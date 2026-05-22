using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Threading;

namespace ZavetSec.DlpAgent
{
    /// <summary>
    /// Мониторинг запущенных процессов.
    ///
    /// Что делает:
    ///   - Каждые N секунд снимает список всех процессов
    ///   - Фиксирует новые процессы (которых не было в прошлом снимке)
    ///   - Проверяет новые процессы по списку подозрительных имён
    ///   - Уважает whitelist — процессы из него не логируются совсем
    ///
    /// Модули в логе:
    ///   PROCESS_NEW     — запущен новый процесс
    ///   PROCESS_ALERT   — запущен процесс из списка suspiciousProcesses
    ///   PROCESS_END     — процесс завершился (опционально)
    /// </summary>
    internal class ProcessMonitor
    {
        private System.Threading.Timer _timer;
        private readonly object _lock = new object();

        // Снимок предыдущего цикла: PID -> имя процесса
        private Dictionary<int, string> _prevSnapshot = new Dictionary<int, string>();
        private bool _firstRun = true;

        // ── Config defaults (переопределяются из Config.Current) ──────────
        private const int DEFAULT_INTERVAL_SEC = 10;

        public void Start()
        {
            var cfg = Config.Current.Processes;
            if (!cfg.Enabled)
            {
                Logger.Write("PROCESS_MONITOR", "Disabled in config");
                return;
            }

            int intervalMs = cfg.CheckIntervalSeconds * 1000;
            _timer = new System.Threading.Timer(_ => Poll(), null, 0, intervalMs);

            Logger.Write("PROCESS_MONITOR", "Process monitor started",
                $"interval={cfg.CheckIntervalSeconds}s|" +
                $"whitelist={cfg.Whitelist.Length}|" +
                $"suspicious={cfg.SuspiciousProcesses.Length}");
        }

        public void Stop()
        {
            _timer?.Dispose();
            Logger.Write("PROCESS_MONITOR", "Process monitor stopped");
        }

        // ── Основной опрос ────────────────────────────────────────────────
        private void Poll()
        {
            lock (_lock)
            {
                try
                {
                    var cfg = Config.Current.Processes;
                    var current = new Dictionary<int, string>();

                    foreach (var p in Process.GetProcesses())
                    {
                        try { current[p.Id] = p.ProcessName.ToLowerInvariant(); }
                        catch { }
                    }

                    if (_firstRun)
                    {
                        _prevSnapshot = current;
                        _firstRun = false;
                        return;
                    }

                    // Новые процессы
                    foreach (var kv in current)
                    {
                        if (_prevSnapshot.ContainsKey(kv.Key)) continue;

                        string name = kv.Value;

                        // Whitelist — пропустить без следа
                        if (IsWhitelisted(name, cfg.Whitelist)) continue;

                        bool isSuspicious = IsSuspicious(name, cfg.SuspiciousProcesses);
                        string module = isSuspicious ? "PROCESS_ALERT" : "PROCESS_NEW";
                        string msg    = isSuspicious
                            ? $"ALERT: suspicious process [{name}]"
                            : $"New process [{name}]";

                        string path = GetProcessPath(kv.Key);
                        Logger.Write(module, msg,
                            $"pid={kv.Key}|name={name}|path={path}|" +
                            $"user={GetUser()}");
                    }

                    // Завершённые процессы (если включено)
                    if (cfg.LogProcessEnd)
                    {
                        foreach (var kv in _prevSnapshot)
                        {
                            if (current.ContainsKey(kv.Key)) continue;
                            if (IsWhitelisted(kv.Value, cfg.Whitelist)) continue;

                            Logger.Write("PROCESS_END", $"Process ended [{kv.Value}]",
                                $"pid={kv.Key}|name={kv.Value}");
                        }
                    }

                    _prevSnapshot = current;
                }
                catch (Exception ex)
                {
                    Logger.Write("PROCESS_MONITOR_ERROR", ex.Message);
                }
            }
        }

        // ── Helpers ───────────────────────────────────────────────────────
        private static bool IsWhitelisted(string name, string[] whitelist)
        {
            foreach (var w in whitelist)
                if (name.Equals(w.ToLowerInvariant(), StringComparison.Ordinal)) return true;
            return false;
        }

        private static bool IsSuspicious(string name, string[] suspicious)
        {
            foreach (var s in suspicious)
                if (name.Equals(s.ToLowerInvariant(), StringComparison.Ordinal)) return true;
            return false;
        }

        private static string GetProcessPath(int pid)
        {
            try
            {
                var p = Process.GetProcessById(pid);
                return p.MainModule?.FileName ?? "";
            }
            catch { return ""; }
        }

        private static string GetUser()
        {
            try   { return System.Security.Principal.WindowsIdentity.GetCurrent().Name; }
            catch { return "UNKNOWN"; }
        }
    }
}
