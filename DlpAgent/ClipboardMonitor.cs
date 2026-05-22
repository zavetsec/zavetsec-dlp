using System;
using System.Runtime.InteropServices;
using System.Windows.Forms;

namespace ZavetSec.DlpAgent
{
    internal class ClipboardMonitor
    {
        private System.Windows.Forms.Timer _timer;
        private string _lastContent = string.Empty;

        public void Start()
        {
            var cfg = Config.Current.Clipboard;
            if (!cfg.Enabled)
            {
                Logger.Write("CLIPBOARD", "Disabled in config");
                return;
            }

            _timer          = new System.Windows.Forms.Timer();
            _timer.Interval = cfg.PollIntervalMs;
            _timer.Tick    += OnTick;
            _timer.Start();

            Logger.Write("CLIPBOARD", "Monitor started",
                $"pollMs={cfg.PollIntervalMs}|sensitiveWords={cfg.SensitiveWords.Length}");
        }

        public void Stop()
        {
            _timer?.Stop();
            _timer?.Dispose();
            Logger.Write("CLIPBOARD", "Monitor stopped");
        }

        private void OnTick(object sender, EventArgs e)
        {
            try
            {
                if (!Clipboard.ContainsText()) return;
                string text = Clipboard.GetText();
                if (string.IsNullOrEmpty(text) || text == _lastContent) return;
                _lastContent = text;

                var cfg = Config.Current.Clipboard;
                string activeWin   = NativeHelpers.GetActiveWindowTitle();
                bool   isSensitive = ContainsSensitiveWord(text, cfg.SensitiveWords);
                string logData     = text.Length > cfg.MaxContentLength
                    ? text.Substring(0, cfg.MaxContentLength) + "[TRUNCATED]"
                    : text;

                Logger.Write("CLIPBOARD",
                    isSensitive ? "SENSITIVE clipboard change" : "Clipboard change",
                    $"window={activeWin}|sensitive={isSensitive}|len={text.Length}|content={logData}");

                if (isSensitive)
                    Logger.Write("CLIPBOARD_ALERT", "Sensitive keyword detected in clipboard",
                        $"window={activeWin}");
            }
            catch (ExternalException) { }
            catch (Exception ex) { Logger.Write("CLIPBOARD_ERROR", ex.Message); }
        }

        private static bool ContainsSensitiveWord(string text, string[] words)
        {
            string lower = text.ToLowerInvariant();
            foreach (var w in words)
                if (lower.Contains(w.ToLowerInvariant())) return true;
            return false;
        }
    }
}
