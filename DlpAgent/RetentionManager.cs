using System;
using System.IO;
using System.Threading;

namespace ZavetSec.DlpAgent
{
    /// <summary>
    /// Автоматическая очистка старых файлов по политике хранения.
    /// Запускается при старте агента и затем раз в сутки.
    ///
    /// Правила из config.json → storage:
    ///   retentionLogDays        — удалять логи старше N дней
    ///   retentionScreenshotDays — удалять скриншоты старше N дней
    ///   maxLogMb                — если папка логов превышает лимит, удалять самые старые
    ///   maxScreenshotMb         — то же для скриншотов
    /// </summary>
    internal class RetentionManager
    {
        private System.Threading.Timer _timer;
        private const int CHECK_INTERVAL_MS = 24 * 60 * 60 * 1000; // раз в сутки

        public void Start()
        {
            // Первый прогон через 30 сек после старта (не мешать инициализации),
            // затем каждые 24 часа
            _timer = new System.Threading.Timer(
                _ => RunCleanup(),
                null,
                30_000,
                CHECK_INTERVAL_MS);

            Logger.Write("RETENTION", "Retention manager started",
                $"logDays={Config.Current.Storage.RetentionLogDays}|" +
                $"ssDays={Config.Current.Storage.RetentionScreenshotDays}|" +
                $"maxLogMb={Config.Current.Storage.MaxLogMb}|" +
                $"maxSsMb={Config.Current.Storage.MaxScreenshotMb}");
        }

        public void Stop()
        {
            _timer?.Dispose();
            Logger.Write("RETENTION", "Retention manager stopped");
        }

        // ── Основной прогон ───────────────────────────────────────────────
        private static void RunCleanup()
        {
            Logger.Write("RETENTION", "Running cleanup");

            var cfg = Config.Current.Storage;

            int logsDeleted = 0, ssDeleted = 0;
            long logsBytesFreed = 0, ssBytesFreed = 0;

            // ── Логи ───────────────────────────────────────────────────────
            if (Directory.Exists(cfg.LogDir))
            {
                // 1. По возрасту
                CleanByAge(cfg.LogDir, "*.log",
                    cfg.RetentionLogDays, false,
                    ref logsDeleted, ref logsBytesFreed);

                // 2. По размеру папки (удалять самые старые пока не влезем)
                CleanBySize(cfg.LogDir, "*.log",
                    (long)cfg.MaxLogMb * 1024 * 1024,
                    ref logsDeleted, ref logsBytesFreed);
            }

            // ── Screenshots ──────────────────────────────────────────────────
            if (Directory.Exists(cfg.ScreenshotDir))
            {
                // 1. По возрасту (рекурсивно — скриншоты в подпапках по датам)
                CleanByAge(cfg.ScreenshotDir, "*.jpg",
                    cfg.RetentionScreenshotDays, recursive: true,
                    ref ssDeleted, ref ssBytesFreed);

                // 2. Удалить пустые подпапки дат
                CleanEmptyDirs(cfg.ScreenshotDir);

                // 3. По размеру папки
                CleanBySize(cfg.ScreenshotDir, "*.jpg",
                    (long)cfg.MaxScreenshotMb * 1024 * 1024,
                    ref ssDeleted, ref ssBytesFreed);
            }

            long totalMb = (logsBytesFreed + ssBytesFreed) / (1024 * 1024);

            Logger.Write("RETENTION", "Cleanup complete",
                $"logsDeleted={logsDeleted}|ssDeleted={ssDeleted}|" +
                $"freedMb={totalMb}");
        }

        // ── Удаление по возрасту ──────────────────────────────────────────
        private static void CleanByAge(
            string dir, string pattern, int maxDays, bool recursive,
            ref int deleted, ref long bytesFreed)
        {
            if (maxDays <= 0) return;

            DateTime cutoff = DateTime.UtcNow.AddDays(-maxDays);

            SearchOption opt = recursive
                ? SearchOption.AllDirectories
                : SearchOption.TopDirectoryOnly;

            foreach (string file in Directory.GetFiles(dir, pattern, opt))
            {
                try
                {
                    var fi = new FileInfo(file);
                    if (fi.LastWriteTimeUtc < cutoff)
                    {
                        long size = fi.Length;
                        fi.Delete();
                        deleted++;
                        bytesFreed += size;
                        Logger.Write("RETENTION", "Old file deleted",
                            $"file={fi.Name}|age={(DateTime.UtcNow - fi.LastWriteTimeUtc).Days}d|" +
                            $"kb={size / 1024}");
                    }
                }
                catch (Exception ex)
                {
                    Logger.Write("RETENTION_ERROR", $"Failed to delete: {file}|err={ex.Message}");
                }
            }
        }

        // ── Удаление по размеру папки (самые старые первыми) ─────────────
        private static void CleanBySize(
            string dir, string pattern, long maxBytes,
            ref int deleted, ref long bytesFreed)
        {
            if (maxBytes <= 0) return;

            // Собрать все файлы, отсортировать по дате (старые первые)
            var files = new System.Collections.Generic.List<FileInfo>();
            foreach (string f in Directory.GetFiles(dir, pattern, SearchOption.AllDirectories))
                files.Add(new FileInfo(f));

            files.Sort((a, b) => a.LastWriteTimeUtc.CompareTo(b.LastWriteTimeUtc));

            // Считаем текущий размер
            long totalSize = 0;
            foreach (var fi in files) totalSize += fi.Length;

            if (totalSize <= maxBytes) return;

            Logger.Write("RETENTION", "Size limit exceeded",
                $"dir={dir}|currentMb={totalSize / (1024 * 1024)}|" +
                $"maxMb={maxBytes / (1024 * 1024)}");

            // Удалять с конца (самые старые) пока не влезем в лимит
            foreach (var fi in files)
            {
                if (totalSize <= maxBytes) break;
                try
                {
                    long size = fi.Length;
                    fi.Delete();
                    totalSize  -= size;
                    deleted++;
                    bytesFreed += size;
                    Logger.Write("RETENTION", "File deleted (size limit)",
                        $"file={fi.Name}|kb={size / 1024}|" +
                        $"remainMb={totalSize / (1024 * 1024)}");
                }
                catch (Exception ex)
                {
                    Logger.Write("RETENTION_ERROR", $"Failed to delete: {fi.Name}|err={ex.Message}");
                }
            }
        }

        // ── Удаление пустых подпапок (для скриншотов) ────────────────────
        private static void CleanEmptyDirs(string rootDir)
        {
            foreach (string dir in Directory.GetDirectories(rootDir))
            {
                try
                {
                    if (Directory.GetFiles(dir).Length == 0 &&
                        Directory.GetDirectories(dir).Length == 0)
                    {
                        Directory.Delete(dir);
                        Logger.Write("RETENTION", "Empty directory removed",
                            $"dir={Path.GetFileName(dir)}");
                    }
                }
                catch { }
            }
        }
    }
}
