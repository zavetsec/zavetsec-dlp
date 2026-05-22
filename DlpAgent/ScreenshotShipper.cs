using System;
using System.Collections.Concurrent;
using System.Drawing;
using System.Drawing.Imaging;
using System.IO;
using System.Net.Http;
using System.Text;
using System.Threading;

namespace ZavetSec.DlpAgent
{
    /// <summary>
    /// Отправляет скриншоты на сервер в виде base64 JPEG.
    /// Вызывается из ScreenshotMonitor после каждого захвата.
    /// Работает асинхронно — не блокирует поток скриншотов.
    /// </summary>
    internal static class ScreenshotShipper
    {
        private static readonly ConcurrentQueue<ScreenshotJob> _queue
            = new ConcurrentQueue<ScreenshotJob>();

        private static Thread   _thread;
        private static volatile bool _running = false;

        // Ленивая инициализация: HttpClient создаётся при первом использовании,
        // когда Config.Current уже точно инициализирован.
        private static HttpClient _httpLazy = null;
        private static readonly object _httpLock = new object();
        private static HttpClient _http {
            get {
                if (_httpLazy == null) {
                    lock (_httpLock) {
                        if (_httpLazy == null) {
                            var h = new System.Net.Http.HttpClientHandler();
                            if (Config.Current.Shipper.AllowInvalidCertificate)
                                h.ServerCertificateCustomValidationCallback = (_, _, _, _) => true;
                            _httpLazy = new HttpClient(h) { Timeout = TimeSpan.FromSeconds(30) };
                        }
                    }
                }
                return _httpLazy;
            }
        }

        public static void Init()
        {
            var cfg = Config.Current.Shipper;
            if (!cfg.Enabled)
            {
                Logger.WriteLocal("SCREENSHOT_SHIPPER", "Disabled (shipper not enabled)");
                return;
            }

            _http.DefaultRequestHeaders.Clear();
            _http.DefaultRequestHeaders.Add("X-Api-Key", cfg.ApiKey);
            _http.DefaultRequestHeaders.Remove("X-Agent-Id");
            _http.DefaultRequestHeaders.Add("X-Agent-Id", cfg.AgentId);
            _http.DefaultRequestHeaders.Add("User-Agent", "ZavetSec-DlpAgent/2.2");

            _running = true;
            _thread  = new Thread(Worker)
            {
                IsBackground = true,
                Name         = "ZavetSec-ScreenshotShipper"
            };
            _thread.Start();

            Logger.WriteLocal("SCREENSHOT_SHIPPER", "Started");
        }

        public static void Stop()
        {
            _running = false;
            _thread?.Join(8000);
        }

        /// <summary>
        /// Поставить скриншот в очередь на отправку.
        /// Принимает путь к файлу (JPEG или .enc) и метаданные.
        /// </summary>
        public static void Enqueue(string filePath, string trigger,
            string window, string resolution)
        {
            if (!_running) return;

            // Максимум 100 скриншотов в очереди — дропаем старые
            while (_queue.Count >= 100)
                _queue.TryDequeue(out _);

            _queue.Enqueue(new ScreenshotJob
            {
                FilePath   = filePath,
                Trigger    = trigger,
                Window     = window,
                Resolution = resolution,
                Ts         = DateTime.UtcNow.ToString("o"),
                Host       = Environment.MachineName,
                User       = NativeHelpers.GetCurrentUser()
            });
        }

        private static void Worker()
        {
            while (_running || !_queue.IsEmpty)
            {
                try
                {
                    if (_queue.TryDequeue(out var job))
                        SendJob(job);
                    else
                        Thread.Sleep(1000);
                }
                catch (ThreadInterruptedException) { break; }
                catch { Thread.Sleep(5000); }
            }
        }

        private static void SendJob(ScreenshotJob job)
        {
            try
            {
                if (!File.Exists(job.FilePath)) return;

                // Читаем файл — если .enc, расшифровываем сначала
                byte[] jpeg = job.FilePath.EndsWith(".enc", StringComparison.OrdinalIgnoreCase)
                    ? DecryptFile(job.FilePath)
                    : File.ReadAllBytes(job.FilePath);

                if (jpeg == null || jpeg.Length == 0) return;

                string base64 = Convert.ToBase64String(jpeg);
                string serverUrl = Config.Current.Shipper.ServerUrl.TrimEnd('/');

                string json = BuildJson(job, base64);
                var content = new StringContent(json, Encoding.UTF8, "application/json");

                var response = _http.PostAsync(
                    serverUrl + "/api/screenshots/upload", content).Result;

                if (response.IsSuccessStatusCode)
                {
                    Logger.WriteLocal("SCREENSHOT_SHIPPER", "Sent",
                        $"trigger={job.Trigger}|size={jpeg.Length / 1024}KB");

                    // Удаляем локальный файл после успешной отправки на сервер.
                    // Сервер хранит скриншот — локальная копия больше не нужна.
                    // Логи НЕ удаляем — они служат зашифрованным бэкапом.
                    if (Config.Current.Shipper.DeleteLocalScreenshotsAfterUpload)
                    {
                        try
                        {
                            if (File.Exists(job.FilePath))
                                File.Delete(job.FilePath);

                            // Удалить пустую папку даты если опустела
                            string dir = Path.GetDirectoryName(job.FilePath);
                            if (!string.IsNullOrEmpty(dir) && Directory.Exists(dir))
                            {
                                var files = Directory.GetFiles(dir, "*", SearchOption.AllDirectories);
                                if (files.Length == 0)
                                    Directory.Delete(dir, recursive: true);
                            }
                        }
                        catch { /* не критично — RetentionManager почистит позже */ }
                    }
                }
                else
                {
                    Logger.WriteLocal("SCREENSHOT_SHIPPER", "Send failed",
                        $"status={response.StatusCode}|trigger={job.Trigger}");
                    // Не возвращаем в очередь — скриншоты хранятся локально до RetentionManager
                }
            }
            catch (Exception ex)
            {
                Logger.WriteLocal("SCREENSHOT_SHIPPER", "Error: " + ex.Message.Split('\n')[0]);
            }
        }

        // Расшифровка .enc файла — тот же формат что в ScreenshotMonitor.EncryptToFile
        private static byte[] DecryptFile(string path)
        {
            try
            {
                byte[] data = File.ReadAllBytes(path);
                if (data.Length < 20) return null;

                int cipherLen = BitConverter.ToInt32(data, 0);
                if (cipherLen <= 0 || cipherLen > data.Length - 20) return null;

                byte[] iv     = new byte[16];
                byte[] cipher = new byte[cipherLen];
                Buffer.BlockCopy(data,  4, iv,     0, 16);
                Buffer.BlockCopy(data, 20, cipher, 0, cipherLen);

                byte[] key = ScreenshotKeyStore.GetKey();

                using (var aes = System.Security.Cryptography.Aes.Create())
                {
                    aes.Key     = key;
                    aes.IV      = iv;
                    aes.Mode    = System.Security.Cryptography.CipherMode.CBC;
                    aes.Padding = System.Security.Cryptography.PaddingMode.PKCS7;
                    using (var dec = aes.CreateDecryptor())
                        return dec.TransformFinalBlock(cipher, 0, cipher.Length);
                }
            }
            catch { return null; }
        }

        private static string BuildJson(ScreenshotJob job, string base64)
        {
            return "{" +
                $"\"ts\":\"{Esc(job.Ts)}\"," +
                $"\"host\":\"{Esc(job.Host)}\"," +
                $"\"user\":\"{Esc(job.User)}\"," +
                $"\"trigger\":\"{Esc(job.Trigger)}\"," +
                $"\"window\":\"{Esc(job.Window)}\"," +
                $"\"resolution\":\"{Esc(job.Resolution)}\"," +
                $"\"jpeg\":\"{base64}\"" +
                "}";
        }

        private static string Esc(string s) =>
            (s ?? "").Replace("\\", "\\\\").Replace("\"", "\\\"")
                     .Replace("\r", "\\r").Replace("\n", "\\n");
    }

    internal class ScreenshotJob
    {
        public string FilePath;
        public string Trigger;
        public string Window;
        public string Resolution;
        public string Ts;
        public string Host;
        public string User;
    }
}
