using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading;

namespace ZavetSec.DlpAgent
{
    /// <summary>
    /// Опрашивает сервер на наличие команд управления и выполняет их.
    ///
    /// Команды:
    ///   stop          — остановить все мониторы
    ///   restart       — перезапустить агент
    ///   uninstall     — остановить, удалить задачу, exe и ProgramData
    ///   update_config — перезагрузить config.json без перезапуска
    /// </summary>
    internal class CommandPoller
    {
        private System.Threading.Timer _timer;
        private volatile bool _stopping = false;

        // Ленивая инициализация: HttpClient создаётся при первом использовании,
        // когда Config.Current уже точно инициализирован.
        private static HttpClient _httpLazy = null;
        private static readonly object _httpLock = new object();
        private static HttpClient _http {
            get {
                if (_httpLazy == null) {
                    lock (_httpLock) {
                        if (_httpLazy == null) {
                            var handler = new System.Net.Http.HttpClientHandler();
                            if (Config.Current.Shipper.AllowInvalidCertificate)
                                handler.ServerCertificateCustomValidationCallback = (_, _, _, _) => true;
                            _httpLazy = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(15) };
                        }
                    }
                }
                return _httpLazy;
            }
        }

        private readonly Action _stopCallback;
        private readonly Action _startCallback;
        private readonly Action _restartCallback;

        public CommandPoller(Action stopCallback, Action startCallback, Action restartCallback)
        {
            _stopCallback    = stopCallback;
            _startCallback   = startCallback;
            _restartCallback = restartCallback;
        }

        public void Start()
        {
            var cfg = Config.Current.Shipper;
            if (!cfg.Enabled)
            {
                Logger.WriteLocal("COMMAND_POLLER", "Disabled (shipper not enabled)");
                return;
            }

            _http.DefaultRequestHeaders.Clear();
            _http.DefaultRequestHeaders.Add("X-Api-Key", cfg.ApiKey);
            _http.DefaultRequestHeaders.Remove("X-Agent-Id");
            _http.DefaultRequestHeaders.Add("X-Agent-Id", cfg.AgentId);
            _http.DefaultRequestHeaders.Add("User-Agent", "ZavetSec-DlpAgent/2.2");

            int pollMs = Math.Max(15000, cfg.FlushSeconds * 1000);
            _timer = new System.Threading.Timer(_ => Poll(), null, pollMs, pollMs);

            Logger.WriteLocal("COMMAND_POLLER", "Started",
                $"pollInterval={pollMs / 1000}s");
        }

        public void Stop()
        {
            _stopping = true;
            _timer?.Dispose();
        }

        // ── Опрос сервера ─────────────────────────────────────────────────
        private void Poll()
        {
            if (_stopping) return;
            try
            {
                string serverUrl = Config.Current.Shipper.ServerUrl.TrimEnd('/');
                string host      = Uri.EscapeDataString(Environment.MachineName);
                string json      = _http.GetStringAsync($"{serverUrl}/api/commands/{host}").Result;

                var commands = JsonSerializer.Deserialize<List<RemoteCommand>>(json,
                    new JsonSerializerOptions { PropertyNameCaseInsensitive = true });

                if (commands == null || commands.Count == 0) return;

                foreach (var cmd in commands)
                {
                    Logger.Write("COMMAND", $"Received: {cmd.Command}",
                        $"id={cmd.Id}|host={cmd.Host}");
                    ExecuteCommand(cmd);
                }
            }
            catch (Exception ex)
            {
                Logger.WriteLocal("COMMAND_POLLER",
                    "Poll error: " + ex.Message.Split('\n')[0]);
            }
        }

        // ── Выполнение команды ────────────────────────────────────────────
        private void ExecuteCommand(RemoteCommand cmd)
        {
            string error  = "";
            string status = "executed";

            try
            {
                switch (cmd.Command.ToLowerInvariant())
                {
                    case "stop":
                        Logger.Write("COMMAND", "Executing: stop");
                        BackgroundRun(() => _stopCallback?.Invoke());
                        break;

                    case "start":
                        Logger.Write("COMMAND", "Executing: start");
                        // Запускаем мониторы в фоне — они могут требовать STA-потока
                        BackgroundRun(() => _startCallback?.Invoke());
                        break;

                    case "restart":
                        Logger.Write("COMMAND", "Executing: restart");
                        ReportResult(cmd.Id, "executed", "");
                        RestartSelf();
                        return;

                    case "uninstall":
                        Logger.Write("COMMAND", "Executing: uninstall");
                        ReportResult(cmd.Id, "executed", "");
                        Uninstall();
                        return;

                    case "update_config":
                        Logger.Write("COMMAND", "Executing: update_config");
                        Config.Reload();
                        Logger.Write("COMMAND", "Config reloaded");
                        break;

                    default:
                        status = "error";
                        error  = $"Unknown command: {cmd.Command}";
                        Logger.WriteLocal("COMMAND", error);
                        break;
                }
            }
            catch (Exception ex)
            {
                status = "error";
                error  = ex.Message;
                Logger.WriteLocal("COMMAND_ERROR", ex.Message);
            }

            ReportResult(cmd.Id, status, error);
        }

        // ── Отчёт о выполнении ────────────────────────────────────────────
        private void ReportResult(long id, string status, string error)
        {
            try
            {
                string serverUrl = Config.Current.Shipper.ServerUrl.TrimEnd('/');
                string body = "{\"id\":" + id +
                              ",\"status\":\"" + Esc(status) + "\"" +
                              ",\"error\":\"" + Esc(error) + "\"}";
                var content = new StringContent(body, Encoding.UTF8, "application/json");
                _http.PostAsync(serverUrl + "/api/commands/result", content).Wait(5000);
            }
            catch (Exception ex)
            {
                Logger.WriteLocal("COMMAND_POLLER",
                    "ReportResult error: " + ex.Message.Split('\n')[0]);
            }
        }

        // ── restart ───────────────────────────────────────────────────────
        private void RestartSelf()
        {
            try
            {
                string exePath = Process.GetCurrentProcess().MainModule?.FileName ?? "";
                if (string.IsNullOrEmpty(exePath)) return;

                var psi = new ProcessStartInfo("cmd.exe",
                    "/c timeout /t 2 /nobreak >nul && \"" + exePath + "\" --task-mode")
                {
                    UseShellExecute = true,
                    WindowStyle     = ProcessWindowStyle.Hidden
                };
                Process.Start(psi);

                _stopCallback?.Invoke();
                Environment.Exit(0);
            }
            catch (Exception ex)
            {
                Logger.WriteLocal("COMMAND_ERROR", "Restart failed: " + ex.Message);
            }
        }

        // ── uninstall ─────────────────────────────────────────────────────
        // FIX: bat-файл в %TEMP% — надёжнее прямого запуска cmd.
        // UseShellExecute=false + CreateNoWindow=true работают вместе,
        // в отличие от UseShellExecute=true + CreateNoWindow=true (которые
        // противоречат и приводили к тому что удаление не выполнялось).
        private void Uninstall()
        {
            try
            {
                string exeFile = Process.GetCurrentProcess().MainModule?.FileName ?? "";
                string dataDir = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                    "ZavetSec", "DLP");

                // Удаляем задачу планировщика и службу
                RunCmd("schtasks", "/delete /tn \"ZavetSec DLP Agent\" /f");
                RunCmd("sc",       "delete ZavetSecDlpAgent");

                Logger.Write("COMMAND", "Uninstall: cleanup started, stopping agent");

                // Останавливаем все мониторы
                _stopCallback?.Invoke();

                // FIX: удаляем только файлы агента, не всю папку DLP.
                // Если сервер запущен на той же машине, он хранит events.db
                // и серверные скриншоты в той же C:\ProgramData\ZavetSec\DLP\.
                // Удаление всей папки убивало бы данные сервера.
                var lines = new System.Text.StringBuilder();
                lines.AppendLine("@echo off");
                lines.AppendLine("timeout /t 3 /nobreak >nul");

                // Удаляем exe
                if (!string.IsNullOrEmpty(exeFile) && File.Exists(exeFile))
                    lines.AppendLine("del /f /q \"" + exeFile + "\"");

                // Удаляем только папки и файлы АГЕНТА, не весь каталог DLP
                string logsDir  = System.IO.Path.Combine(dataDir, "Logs");
                string ssDir    = System.IO.Path.Combine(dataDir, "Screenshots");
                string agentKey = System.IO.Path.Combine(dataDir, "agent.key");
                string ssKey    = System.IO.Path.Combine(dataDir, "screenshot.key");

                if (Directory.Exists(logsDir))
                    lines.AppendLine("rd /s /q \"" + logsDir + "\"");
                if (Directory.Exists(ssDir))
                    lines.AppendLine("rd /s /q \"" + ssDir + "\"");
                if (File.Exists(agentKey))
                    lines.AppendLine("del /f /q \"" + agentKey + "\"");
                if (File.Exists(ssKey))
                    lines.AppendLine("del /f /q \"" + ssKey + "\"");

                lines.AppendLine("del /f /q \"%~f0\"");

                string batPath = Path.Combine(Path.GetTempPath(), "zavetsec_uninstall.bat");
                File.WriteAllText(batPath, lines.ToString(), Encoding.Default);

                var psi = new ProcessStartInfo("cmd.exe", "/c \"" + batPath + "\"")
                {
                    UseShellExecute = false,
                    CreateNoWindow  = true
                };
                Process.Start(psi);

                Environment.Exit(0);
            }
            catch (Exception ex)
            {
                Logger.WriteLocal("COMMAND_ERROR", "Uninstall failed: " + ex.Message);
            }
        }

        // ── Helpers ───────────────────────────────────────────────────────
        private static void RunCmd(string exe, string args)
        {
            try
            {
                var p = Process.Start(new ProcessStartInfo(exe, args)
                {
                    UseShellExecute        = false,
                    CreateNoWindow         = true,
                    RedirectStandardOutput = true
                });
                p?.WaitForExit(5000);
            }
            catch { }
        }

        private static void BackgroundRun(Action a)
        {
            var t = new Thread(() => { try { a(); } catch { } })
            {
                IsBackground = true
            };
            t.Start();
        }

        private static string Esc(string s) =>
            (s ?? "").Replace("\\", "\\\\").Replace("\"", "\\\"")
                     .Replace("\r", "\\r").Replace("\n", "\\n");
    }

    internal class RemoteCommand
    {
        public long   Id      { get; set; }
        public string Host    { get; set; } = "";
        public string Command { get; set; } = "";
        public string Payload { get; set; } = "";
    }
}
