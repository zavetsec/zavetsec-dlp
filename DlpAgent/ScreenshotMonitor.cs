using System;
using System.Drawing;
using System.Drawing.Imaging;
using System.IO;
using System.Security.Cryptography;
using System.Threading;
using System.Windows.Forms;

namespace ZavetSec.DlpAgent
{
    internal class ScreenshotMonitor
    {
        // Win32 API for interactive desktop access
        // Required when agent runs as SYSTEM (Session 0 isolation)
        [System.Runtime.InteropServices.DllImport("user32.dll", SetLastError = true)]
        private static extern IntPtr OpenWindowStation(string lpszWinSta, bool fInherit, uint dwDesiredAccess);

        [System.Runtime.InteropServices.DllImport("user32.dll", SetLastError = true)]
        private static extern bool SetProcessWindowStation(IntPtr hWinSta);

        [System.Runtime.InteropServices.DllImport("user32.dll", SetLastError = true)]
        private static extern IntPtr GetProcessWindowStation();

        [System.Runtime.InteropServices.DllImport("user32.dll", SetLastError = true)]
        private static extern IntPtr OpenDesktop(string lpszDesktop, uint dwFlags, bool fInherit, uint dwDesiredAccess);

        [System.Runtime.InteropServices.DllImport("user32.dll", SetLastError = true)]
        private static extern IntPtr GetThreadDesktop(uint dwThreadId);

        [System.Runtime.InteropServices.DllImport("user32.dll", SetLastError = true)]
        private static extern bool SetThreadDesktop(IntPtr hDesktop);

        [System.Runtime.InteropServices.DllImport("user32.dll", SetLastError = true)]
        private static extern bool CloseDesktop(IntPtr hDesktop);

        [System.Runtime.InteropServices.DllImport("user32.dll", SetLastError = true)]
        private static extern bool CloseWindowStation(IntPtr hWinSta);

        [System.Runtime.InteropServices.DllImport("kernel32.dll")]
        private static extern uint GetCurrentThreadId();

        private const uint WINSTA_ALL_ACCESS    = 0x037F;
        private const uint DESKTOP_ALL_ACCESS   = 0x01FF;

        private System.Threading.Timer _intervalTimer;
        private System.Threading.Timer _windowWatchTimer;
        private string  _lastWindowTitle = string.Empty;
        private readonly object _capLock = new object();

        public void Start()
        {
            var cfg = Config.Current.Screenshot;
            Directory.CreateDirectory(Config.Current.Storage.ScreenshotDir);

            if (cfg.OnStartup) Capture("STARTUP");

            int intervalMs  = cfg.IntervalMinutes * 60 * 1000;
            int winCheckMs  = cfg.WindowCheckIntervalSeconds * 1000;

            _intervalTimer = new System.Threading.Timer(
                _ => Capture("INTERVAL"), null, intervalMs, intervalMs);

            if (cfg.OnWindowChange)
                _windowWatchTimer = new System.Threading.Timer(
                    CheckWindowChange, null, winCheckMs, winCheckMs);

            Logger.Write("SCREENSHOT", "Monitor started",
                $"interval={cfg.IntervalMinutes}m|quality={cfg.JpegQuality}|" +
                $"onWindowChange={cfg.OnWindowChange}|blankDetect={cfg.BlankScreenDetection}");
        }

        public void Stop()
        {
            _intervalTimer?.Dispose();
            _windowWatchTimer?.Dispose();
            Logger.Write("SCREENSHOT", "Monitor stopped");
        }

        private void CheckWindowChange(object state)
        {
            string current = NativeHelpers.GetActiveWindowTitle();
            if (!string.IsNullOrEmpty(current) && current != _lastWindowTitle)
            {
                _lastWindowTitle = current;
                Capture("WINDOW_CHANGE", current);
            }
        }

        public void Capture(string trigger, string windowHint = null)
        {
            lock (_capLock)
            {
                IntPtr hWinSta    = IntPtr.Zero;
                IntPtr hDesktop   = IntPtr.Zero;
                IntPtr oldWinSta  = IntPtr.Zero;
                IntPtr oldDesktop = IntPtr.Zero;
                bool changedWinSta  = false;
                bool changedDesktop = false;

                try
                {
                    // Skip screenshot if running in Session 0 (SYSTEM / no interactive desktop).
                    // This happens when the ONSTART scheduled task fires before user login.
                    // The ONLOGON task will handle screenshots once a user is logged in.
                    int sessionId = System.Diagnostics.Process.GetCurrentProcess().SessionId;
                    if (sessionId == 0)
                    {
                        Logger.WriteLocal("SCREENSHOT_SKIP",
                            "Session 0 detected — skipping capture (no interactive desktop)");
                        return;
                    }

                    var cfg    = Config.Current.Screenshot;
                    Rectangle bounds = GetVirtualScreen();

                    // Open interactive window station and desktop.
                    // Necessary when running as SYSTEM (Session 0 isolation).
                    // Without this, Graphics.CopyFromScreen throws "Invalid Handle".
                    try
                    {
                        hWinSta  = OpenWindowStation("WinSta0", false, WINSTA_ALL_ACCESS);
                        if (hWinSta != IntPtr.Zero)
                        {
                            oldWinSta = GetProcessWindowStation();
                            changedWinSta = SetProcessWindowStation(hWinSta);
                        }
                        hDesktop = OpenDesktop("Default", 0, false, DESKTOP_ALL_ACCESS);
                        if (hDesktop != IntPtr.Zero)
                        {
                            oldDesktop    = GetThreadDesktop(GetCurrentThreadId());
                            changedDesktop = SetThreadDesktop(hDesktop);
                        }
                    }
                    catch { /* best effort — capture may still work without */ }

                    using (var bmp = new Bitmap(bounds.Width, bounds.Height,
                        System.Drawing.Imaging.PixelFormat.Format32bppArgb))
                    using (var g = Graphics.FromImage(bmp))
                    {
                        g.CopyFromScreen(new Point(bounds.Left, bounds.Top),
                            Point.Empty, new Size(bounds.Width, bounds.Height));

                        if (cfg.BlankScreenDetection && IsBlankScreen(bmp))
                        {
                            Logger.Write("SCREENSHOT_WARN", "Blank frame detected (Session 0?)",
                                $"trigger={trigger}");
                            return;
                        }

                        string ssDir  = Config.Current.Storage.ScreenshotDir;
                        string dateDir = Path.Combine(ssDir, DateTime.UtcNow.ToString("yyyyMMdd"));
                        Directory.CreateDirectory(dateDir);

                        string fname = $"{DateTime.UtcNow:HHmmss_fff}_{trigger}.jpg";
                        string fpath = Path.Combine(dateDir, fname);

                        bool encrypt = Config.Current.ScreenshotEncrypt.Enabled;

                        // Recreate directory just before writing —
                        // ScreenshotShipper may have deleted it after previous upload
                        Directory.CreateDirectory(dateDir);

                        if (encrypt)
                        {
                            // Сохранить во временный буфер, зашифровать, записать как .enc
                            fname  = fname.Replace(".jpg", ".enc");
                            fpath  = Path.Combine(dateDir, fname);
                            byte[] jpegBytes = JpegToBytes(bmp, cfg.JpegQuality);
                            EncryptToFile(jpegBytes, fpath);
                        }
                        else
                        {
                            SaveJpeg(bmp, fpath, cfg.JpegQuality);
                        }

                        string win = windowHint ?? NativeHelpers.GetActiveWindowTitle();
                        Logger.Write("SCREENSHOT", $"Captured [{trigger}]",
                            $"file={fname}|encrypted={encrypt}|window={win}|" +
                            $"monitors={Screen.AllScreens.Length}|" +
                            $"res={bounds.Width}x{bounds.Height}");

                        // Enqueue for upload to server
                        if (Config.Current.Shipper.Enabled)
                        {
                            ScreenshotShipper.Enqueue(
                                filePath:   fpath,
                                trigger:    trigger,
                                window:     win,
                                resolution: $"{bounds.Width}x{bounds.Height}"
                            );
                        }
                    }
                }
                catch (Exception ex)
                {
                    Logger.Write("SCREENSHOT_ERROR", ex.GetType().Name + ": " + ex.Message);
                }
                finally
                {
                    // Restore previous window station and desktop
                    try
                    {
                        if (changedDesktop && oldDesktop != IntPtr.Zero)
                            SetThreadDesktop(oldDesktop);
                        if (changedWinSta && oldWinSta != IntPtr.Zero)
                            SetProcessWindowStation(oldWinSta);
                        if (hDesktop != IntPtr.Zero)
                            CloseDesktop(hDesktop);
                        if (hWinSta != IntPtr.Zero)
                            CloseWindowStation(hWinSta);
                    }
                    catch { }
                }
            }
        }

        private static Rectangle GetVirtualScreen()
        {
            int l = int.MaxValue, t = int.MaxValue, r = int.MinValue, b = int.MinValue;
            foreach (var s in Screen.AllScreens)
            {
                if (s.Bounds.Left   < l) l = s.Bounds.Left;
                if (s.Bounds.Top    < t) t = s.Bounds.Top;
                if (s.Bounds.Right  > r) r = s.Bounds.Right;
                if (s.Bounds.Bottom > b) b = s.Bounds.Bottom;
            }
            return new Rectangle(l, t, r - l, b - t);
        }

        private static bool IsBlankScreen(Bitmap bmp)
        {
            int stepX = Math.Max(1, bmp.Width  / 5);
            int stepY = Math.Max(1, bmp.Height / 5);
            int dark = 0, total = 0;
            for (int x = stepX; x < bmp.Width  - stepX; x += stepX)
            for (int y = stepY; y < bmp.Height - stepY; y += stepY)
            {
                Color c = bmp.GetPixel(x, y);
                if (c.R < 10 && c.G < 10 && c.B < 10) dark++;
                total++;
            }
            return total > 0 && (dark * 100 / total) > 90;
        }

        private static void SaveJpeg(Bitmap bmp, string path, int quality)
        {
            var bytes = JpegToBytes(bmp, quality);
            File.WriteAllBytes(path, bytes);
        }

        private static byte[] JpegToBytes(Bitmap bmp, int quality)
        {
            ImageCodecInfo codec = null;
            foreach (var c in ImageCodecInfo.GetImageEncoders())
                if (c.FormatID == ImageFormat.Jpeg.Guid) { codec = c; break; }

            using (var ms = new MemoryStream())
            {
                if (codec == null)
                {
                    bmp.Save(ms, ImageFormat.Jpeg);
                }
                else
                {
                    var ep = new EncoderParameters(1);
                    ep.Param[0] = new EncoderParameter(
                        System.Drawing.Imaging.Encoder.Quality, (long)quality);
                    bmp.Save(ms, codec, ep);
                }
                return ms.ToArray();
            }
        }

        /// <summary>
        /// Шифрует байты скриншота тем же ключом что и логи (DPAPI machine-scope AES-256).
        /// Формат файла: [4 байта длина][16 байт IV][AES-CBC ciphertext]
        /// Расшифровывается той же утилитой DlpLogReader (режим --screenshots).
        /// </summary>
        private static void EncryptToFile(byte[] plain, string path)
        {
            byte[] key = ScreenshotKeyStore.GetKey();

            using (var aes = Aes.Create())
            {
                aes.Key     = key;
                aes.Mode    = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;
                aes.GenerateIV();

                byte[] iv     = aes.IV;
                byte[] cipher;
                using (var enc = aes.CreateEncryptor())
                    cipher = enc.TransformFinalBlock(plain, 0, plain.Length);

                byte[] record = new byte[4 + 16 + cipher.Length];
                Buffer.BlockCopy(BitConverter.GetBytes(cipher.Length), 0, record, 0,  4);
                Buffer.BlockCopy(iv,     0, record,  4, 16);
                Buffer.BlockCopy(cipher, 0, record, 20, cipher.Length);

                File.WriteAllBytes(path, record);
            }
        }
    }

    /// <summary>
    /// Хранит и кэширует ключ шифрования скриншотов.
    /// Ключ генерируется один раз и хранится в DPAPI machine-scope,
    /// отдельно от ключа логов.
    /// </summary>
    internal static class ScreenshotKeyStore
    {
        private static byte[] _key;
        private static readonly object _lock = new object();
        private static readonly string KeyFile =
            Path.Combine(
                Path.GetDirectoryName(Config.Current.Storage.KeyFile),
                "screenshot.key");

        public static byte[] GetKey()
        {
            if (_key != null) return _key;
            lock (_lock)
            {
                if (_key != null) return _key;
                _key = LoadOrCreate();
            }
            return _key;
        }

        private static byte[] LoadOrCreate()
        {
            if (File.Exists(KeyFile))
            {
                byte[] blob = File.ReadAllBytes(KeyFile);
                return System.Security.Cryptography.ProtectedData.Unprotect(
                    blob, null,
                    System.Security.Cryptography.DataProtectionScope.LocalMachine);
            }

            byte[] key = new byte[32];
            System.Security.Cryptography.RandomNumberGenerator.Create().GetBytes(key);
            byte[] protected_ = System.Security.Cryptography.ProtectedData.Protect(
                key, null,
                System.Security.Cryptography.DataProtectionScope.LocalMachine);
            File.WriteAllBytes(KeyFile, protected_);
            return key;
        }
    }
}
