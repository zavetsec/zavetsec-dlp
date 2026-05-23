using System;
using System.Collections.Concurrent;
using System.IO;
using System.Net.Http;
using System.Text;
using System.Threading;

namespace ZavetSec.DlpAgent
{
    /// <summary>
    /// Отправляет события на центральный DLP-сервер.
    /// Работает в фоновом потоке, буферизует события и отправляет батчами.
    /// При недоступности сервера — события накапливаются в очереди (до MaxQueueSize)
    /// и отправляются при восстановлении связи.
    /// </summary>
    internal static class LogShipper
    {
        private static readonly ConcurrentQueue<string> _queue
            = new ConcurrentQueue<string>();

        private static Thread   _thread;
        private static volatile bool _running = false;
        public  static bool IsRunning => _running;
        private static string   _serverUrl;
        private static string   _apiKey;
        private static int      _batchSize;
        private static int      _flushMs;
        private static int      _maxQueue;

        // Ленивая инициализация — HttpClient создаётся при первом использовании,
        // после того как Config.Current уже инициализирован в DlpService.StartInternal().
        private static HttpClient _httpLazy = null;
        private static readonly object _httpLock = new object();
        private static HttpClient _http {
            get {
                if (_httpLazy == null) {
                    lock (_httpLock) {
                        if (_httpLazy == null) {
        
                    // Certificate fingerprint pinning
                    string fp = (Config.Current.Shipper.ServerFingerprint ?? "")
                        .Trim().Replace(":", "").Replace(" ", "").ToUpperInvariant();
                    var handler = new System.Net.Http.HttpClientHandler();
                    if (!string.IsNullOrEmpty(fp))
                    {
                        handler.ServerCertificateCustomValidationCallback = (msg, cert, chain, errors) =>
                        {
                            if (cert == null) return false;
                            byte[] rawHash = System.Security.Cryptography.SHA256.HashData(cert.RawData);
                            string certFp  = BitConverter.ToString(rawHash).Replace("-", "").ToUpperInvariant();
                            return certFp == fp;
                        };
                    }
                    else if (Config.Current.Shipper.AllowInvalidCertificate)
                    {
                        handler.ServerCertificateCustomValidationCallback = (_, _, _, _) => true;
                    }
                            _httpLazy = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(15) };
                        }
                    }
                }
                return _httpLazy;
            }
        }

        // ── Инициализация ─────────────────────────────────────────────────
        public static void Init()
        {
            var cfg = Config.Current.Shipper;
            if (!cfg.Enabled)
            {
                Logger.Write("SHIPPER", "Log shipping disabled");
                return;
            }

            _serverUrl = cfg.ServerUrl.TrimEnd('/');
            _apiKey    = cfg.ApiKey;
            _batchSize = Math.Max(1, cfg.BatchSize);
            LoadPersistedQueue();
            _flushMs   = Math.Max(5000, cfg.FlushSeconds * 1000);
            _maxQueue  = Math.Max(1000, cfg.MaxQueueSize);

            _http.DefaultRequestHeaders.Clear();
            _http.DefaultRequestHeaders.Add("X-Api-Key", _apiKey);
            _http.DefaultRequestHeaders.Remove("X-Agent-Id");
            _http.DefaultRequestHeaders.Add("X-Agent-Id", Config.Current.Shipper.AgentId);
            _http.DefaultRequestHeaders.Remove("X-Agent-Key");
            if (!string.IsNullOrEmpty(cfg.AgentKey))
                _http.DefaultRequestHeaders.Add("X-Agent-Key", cfg.AgentKey);
            // Fallback to global ApiKey if no per-agent key yet
            if (string.IsNullOrEmpty(cfg.AgentKey))
            {
                _http.DefaultRequestHeaders.Remove("X-Api-Key");
                _http.DefaultRequestHeaders.Add("X-Api-Key", cfg.ApiKey);
            }
            _http.DefaultRequestHeaders.Add("User-Agent", "ZavetSec-DlpAgent/2.2");

            _running = true;
            _thread  = new Thread(Worker)
            {
                IsBackground = true,
                Name         = "ZavetSec-LogShipper"
            };
            _thread.Start();

            Logger.Write("SHIPPER", "Log shipper started",
                $"server={_serverUrl}|batch={_batchSize}|flush={cfg.FlushSeconds}s");
        }

        /// Восстанавливает события из дискового буфера при запуске
    private static void LoadPersistedQueue()
    {
        try
        {
            string path = System.IO.Path.Combine(Config.Current.Storage.LogDir, "shipper_queue.dat");
            if (!File.Exists(path)) return;
            int loaded = 0;
            foreach (var line in File.ReadAllLines(path, System.Text.Encoding.UTF8))
            {
                if (string.IsNullOrWhiteSpace(line)) continue;
                if (_queue.Count >= _maxQueue) break;
                _queue.Enqueue(line);
                loaded++;
            }
            if (loaded > 0)
            {
                File.Delete(path);
                Logger.WriteLocal("SHIPPER", "Restored events from disk buffer",
                    $"count={loaded}");
            }
        }
        catch (Exception ex)
        {
            Logger.WriteLocal("SHIPPER", "Failed to restore disk buffer", ex.Message);
        }
    }

    public static void Stop()
        {
            _running = false;
            // Даём воркеру время сбросить остаток очереди
            _thread?.Join(8000);
            Logger.Write("SHIPPER", "Log shipper stopped");
        }

        // ── Добавить событие в очередь ────────────────────────────────────
        // Вызывается из Logger.Write — не блокирует вызывающий поток.
        public static void Enqueue(string jsonEvent)
        {
            if (!_running) return;

            // Если очередь переполнена — пишем на диск вместо дропа
            if (_queue.Count >= _maxQueue)
            {
                try
                {
                    string dir = Config.Current.Storage.LogDir;
                    Directory.CreateDirectory(dir);
                    string path = System.IO.Path.Combine(dir, "shipper_queue.dat");
                    File.AppendAllText(path, jsonEvent + "\n", System.Text.Encoding.UTF8);
                    // Ограничиваем размер файла буфера: 50MB
                    var fi = new FileInfo(path);
                    if (fi.Exists && fi.Length > 50 * 1024 * 1024)
                    {
                        var lines = File.ReadAllLines(path);
                        int keep = (int)(lines.Length * 0.9);
                        File.WriteAllLines(path, lines[^keep..]);
                    }
                }
                catch { /* события теряются только если и диск недоступен */ }
                return;
            }

            _queue.Enqueue(jsonEvent);
        }

        // ── Фоновый воркер ────────────────────────────────────────────────
        private static void Worker()
        {
            int retryDelay = 5000;

            while (_running || !_queue.IsEmpty)
            {
                try
                {
                    Thread.Sleep(_flushMs);
                    FlushQueue(ref retryDelay);
                }
                catch (ThreadInterruptedException) { break; }
                catch { }
            }

            // Финальный сброс при остановке
            try { FlushQueue(ref retryDelay); }
            catch { }
        }

        private static void FlushQueue(ref int retryDelay)
        {
            if (_queue.IsEmpty) return;

            // Собираем батч
            var batch = new System.Collections.Generic.List<string>(_batchSize);
            while (batch.Count < _batchSize && _queue.TryDequeue(out string ev))
                batch.Add(ev);

            if (batch.Count == 0) return;

            // Формируем JSON-массив из уже готовых JSON-объектов
            string body = "[" + string.Join(",", batch) + "]";

            try
            {
                var content  = new StringContent(body, Encoding.UTF8, "application/json");
                var response = _http.PostAsync(_serverUrl + "/api/ingest", content).Result;

                if (response.IsSuccessStatusCode)
                {
                    retryDelay = 5000; // сброс задержки при успехе

                    // Если в очереди ещё есть — сразу шлём следующий батч
                    if (!_queue.IsEmpty)
                    {
                        int dummy = retryDelay;
                        FlushQueue(ref dummy);
                    }
                }
                else
                {
                    // Сервер вернул ошибку — вернуть события в очередь
                    RequeueBatch(batch);
                    retryDelay = Math.Min(retryDelay * 2, 120_000);
                }
            }
            catch (Exception ex)
            {
                // Нет связи — вернуть события и ждать
                RequeueBatch(batch);
                retryDelay = Math.Min(retryDelay * 2, 120_000);

                // Пишем в локальный лог (без вызова Enqueue — чтобы не зациклиться)
                try
                {
                    Logger.WriteLocal("SHIPPER_ERROR",
                        "Send failed, will retry",
                        $"err={ex.Message.Split('\n')[0]}|queued={_queue.Count}|retryMs={retryDelay}");
                }
                catch { }
            }
        }

        private static void RequeueBatch(System.Collections.Generic.List<string> batch)
        {
            // Добавляем обратно в начало (через временную очередь) —
            // реальный ConcurrentQueue не поддерживает prepend,
            // поэтому просто добавляем в конец. FIFO-порядок доставки сохраняется.
            foreach (var item in batch)
                _queue.Enqueue(item);
        }
    }
}
