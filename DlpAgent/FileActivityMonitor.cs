using System;
using System.Collections.Generic;
using System.IO;
using System.Management;
using System.Threading;

namespace ZavetSec.DlpAgent
{
    /// <summary>
    /// Мониторинг файловых операций на съёмных носителях.
    ///
    /// Принцип работы:
    ///   1. WMI следит за появлением новых томов (Win32_VolumeChangeEvent)
    ///   2. Для каждого съёмного тома создаётся FileSystemWatcher
    ///   3. Watcher перехватывает Created/Changed/Deleted/Renamed на диске
    ///   4. При копировании файлов пишется FILE_COPY с деталями
    ///   5. При отключении носителя watcher снимается
    ///
    /// Фильтрация:
    ///   - Игнорируются системные файлы ($RECYCLE.BIN, System Volume Information)
    ///   - Логируются только файлы (не папки)
    ///   - Крупные пакетные операции группируются (буферизация 3 сек)
    /// </summary>
    internal class FileActivityMonitor
    {
        // ── WMI watchers ──────────────────────────────────────────────────
        private ManagementEventWatcher _volumeConnectWatcher;
        private ManagementEventWatcher _volumeDisconnectWatcher;

        // ── FileSystem watchers per drive letter ──────────────────────────
        private readonly Dictionary<string, FileSystemWatcher> _driveWatchers
            = new Dictionary<string, FileSystemWatcher>(StringComparer.OrdinalIgnoreCase);

        // ── Buffer: группируем события за 3 секунды чтобы не спамить лог ─
        private readonly Dictionary<string, DriveBuffer> _buffers
            = new Dictionary<string, DriveBuffer>(StringComparer.OrdinalIgnoreCase);

        private readonly object _lock = new object();

        // ── Public ────────────────────────────────────────────────────────
        public void Start()
        {
            try
            {
                // Подписаться на появление нового тома
                var connectQuery = new WqlEventQuery(
                    "SELECT * FROM Win32_VolumeChangeEvent WHERE EventType = 2");
                _volumeConnectWatcher = new ManagementEventWatcher(
                    new ManagementScope(@"\\.\root\CIMV2"), connectQuery);
                _volumeConnectWatcher.EventArrived += OnVolumeConnected;
                _volumeConnectWatcher.Start();

                // Подписаться на отключение тома
                var disconnectQuery = new WqlEventQuery(
                    "SELECT * FROM Win32_VolumeChangeEvent WHERE EventType = 3");
                _volumeDisconnectWatcher = new ManagementEventWatcher(
                    new ManagementScope(@"\\.\root\CIMV2"), disconnectQuery);
                _volumeDisconnectWatcher.EventArrived += OnVolumeDisconnected;
                _volumeDisconnectWatcher.Start();

                // Установить watcher на уже подключённые съёмные диски
                AttachExistingRemovableDrives();

                Logger.Write("FILE_MONITOR", "File activity monitor started");
            }
            catch (Exception ex)
            {
                Logger.Write("FILE_MONITOR_ERROR",
                    "FileActivityMonitor start error: " + ex.Message);
            }
        }

        public void Stop()
        {
            try
            {
                _volumeConnectWatcher?.Stop();
                _volumeConnectWatcher?.Dispose();
                _volumeDisconnectWatcher?.Stop();
                _volumeDisconnectWatcher?.Dispose();

                lock (_lock)
                {
                    foreach (var kv in _driveWatchers)
                    {
                        kv.Value.EnableRaisingEvents = false;
                        kv.Value.Dispose();
                    }
                    _driveWatchers.Clear();

                    foreach (var kv in _buffers)
                        kv.Value.Dispose();
                    _buffers.Clear();
                }

                Logger.Write("FILE_MONITOR", "File activity monitor stopped");
            }
            catch { }
        }

        // ── Scan existing removable drives on startup ─────────────────────
        private void AttachExistingRemovableDrives()
        {
            foreach (DriveInfo drive in DriveInfo.GetDrives())
            {
                if (drive.DriveType == DriveType.Removable && drive.IsReady)
                    AttachWatcher(drive.RootDirectory.FullName.TrimEnd('\\'));
            }
        }

        // ── WMI Volume events ─────────────────────────────────────────────
        private void OnVolumeConnected(object sender, EventArrivedEventArgs e)
        {
            try
            {
                string drive = e.NewEvent["DriveName"]?.ToString();
                if (string.IsNullOrEmpty(drive)) return;

                // Подождать пока ОС полностью смонтирует том
                Thread.Sleep(1500);

                string info = GetDriveInfo(drive, out bool isRemovable);

                Logger.Write("FILE_MONITOR", "Removable drive connected",
                    $"drive={drive}|{info}|user={GetUser()}");

                if (isRemovable)
                    AttachWatcher(drive);
            }
            catch (Exception ex)
            {
                Logger.Write("FILE_MONITOR_ERROR", "OnVolumeConnected: " + ex.Message);
            }
        }

        private void OnVolumeDisconnected(object sender, EventArrivedEventArgs e)
        {
            try
            {
                string drive = e.NewEvent["DriveName"]?.ToString();
                if (string.IsNullOrEmpty(drive)) return;

                DetachWatcher(drive);

                Logger.Write("FILE_MONITOR", "Drive disconnected",
                    $"drive={drive}|user={GetUser()}");
            }
            catch { }
        }

        // ── Attach / detach FileSystemWatcher ─────────────────────────────
        private void AttachWatcher(string driveLetter)
        {
            // Нормализовать: "E:" -> "E:\"
            string root = driveLetter.TrimEnd('\\') + "\\";

            lock (_lock)
            {
                if (_driveWatchers.ContainsKey(driveLetter)) return;

                try
                {
                    var fsw = new FileSystemWatcher(root)
                    {
                        IncludeSubdirectories = true,
                        NotifyFilter          = NotifyFilters.FileName
                                              | NotifyFilters.LastWrite
                                              | NotifyFilters.Size,
                        Filter                = "*.*",
                        InternalBufferSize    = 65536
                    };

                    fsw.Created += (s, ev) => OnFileEvent("COPY",    driveLetter, ev.FullPath);
                    fsw.Changed += (s, ev) => OnFileEvent("WRITE",   driveLetter, ev.FullPath);
                    fsw.Deleted += (s, ev) => OnFileEvent("DELETE",  driveLetter, ev.FullPath);
                    fsw.Renamed += (s, ev) => OnFileEvent("RENAME",  driveLetter,
                        ev.FullPath, ev.OldFullPath);
                    fsw.Error   += OnWatcherError;

                    fsw.EnableRaisingEvents = true;
                    _driveWatchers[driveLetter] = fsw;

                    // Создать буфер для этого диска
                    _buffers[driveLetter] = new DriveBuffer(driveLetter);

                    Logger.Write("FILE_MONITOR", $"Watcher attached to {root}");
                }
                catch (Exception ex)
                {
                    Logger.Write("FILE_MONITOR_ERROR",
                        $"Failed to set watcher on {root}: {ex.Message}");
                }
            }
        }

        private void DetachWatcher(string driveLetter)
        {
            lock (_lock)
            {
                if (_driveWatchers.TryGetValue(driveLetter, out var fsw))
                {
                    // Сбросить накопленный буфер перед отключением
                    if (_buffers.TryGetValue(driveLetter, out var buf))
                    {
                        buf.FlushNow();
                        buf.Dispose();
                        _buffers.Remove(driveLetter);
                    }

                    fsw.EnableRaisingEvents = false;
                    fsw.Dispose();
                    _driveWatchers.Remove(driveLetter);
                }
            }
        }

        // ── File event handler ────────────────────────────────────────────
        private void OnFileEvent(string action, string drive,
            string path, string oldPath = null)
        {
            // Игнорировать системные пути
            if (IsSystemPath(path)) return;

            // Получить размер файла
            long size = 0;
            try
            {
                if (action == "COPY" || action == "WRITE")
                {
                    var fi = new FileInfo(path);
                    if (fi.Exists) size = fi.Length;
                }
            }
            catch { }

            lock (_lock)
            {
                if (_buffers.TryGetValue(drive, out var buf))
                    buf.Add(action, path, size, oldPath);
            }
        }

        private static void OnWatcherError(object sender, ErrorEventArgs e)
        {
            Logger.Write("FILE_MONITOR_ERROR",
                "FileSystemWatcher error: " + e.GetException().Message);
        }

        // ── Helpers ───────────────────────────────────────────────────────
        private static bool IsSystemPath(string path)
        {
            if (string.IsNullOrEmpty(path)) return true;
            string lower = path.ToLowerInvariant();
            return lower.Contains("$recycle.bin")
                || lower.Contains("system volume information")
                || lower.Contains("\\recycler\\")
                || lower.Contains("thumbs.db")
                || lower.EndsWith(".tmp")
                || lower.EndsWith(".lnk");
        }

        private static string GetDriveInfo(string drive, out bool isRemovable)
        {
            isRemovable = false;
            try
            {
                var di = new DriveInfo(drive);
                if (!di.IsReady) return $"drive={drive}";
                isRemovable = di.DriveType == DriveType.Removable;
                long gb = di.TotalSize / (1024 * 1024 * 1024);
                return $"label={di.VolumeLabel}|fs={di.DriveFormat}" +
                       $"|size={gb}GB|type={di.DriveType}";
            }
            catch { return ""; }
        }

        private static string GetUser()
        {
            try   { return System.Security.Principal.WindowsIdentity.GetCurrent().Name; }
            catch { return "UNKNOWN"; }
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════
    //  DriveBuffer — группирует файловые события за короткий период
    //  чтобы не писать 1000 строк при копировании папки
    // ═══════════════════════════════════════════════════════════════════════════
    internal class DriveBuffer : IDisposable
    {
        private readonly string _drive;
        private readonly List<FileEventItem> _items = new List<FileEventItem>();
        private readonly object _lock = new object();
        private System.Threading.Timer _timer;
        private const int FLUSH_DELAY_MS = 3000; // группируем за 3 сек

        public DriveBuffer(string drive)
        {
            _drive = drive;
            _timer = new System.Threading.Timer(_ => Flush(), null,
                Timeout.Infinite, Timeout.Infinite);
        }

        public void Add(string action, string path, long size, string oldPath)
        {
            lock (_lock)
            {
                _items.Add(new FileEventItem
                {
                    Action  = action,
                    Path    = path,
                    Size    = size,
                    OldPath = oldPath,
                    Time    = DateTime.UtcNow
                });

                // Взводим/перевзводим таймер
                _timer.Change(FLUSH_DELAY_MS, Timeout.Infinite);
            }
        }

        public void FlushNow()
        {
            _timer.Change(Timeout.Infinite, Timeout.Infinite);
            Flush();
        }

        private void Flush()
        {
            List<FileEventItem> items;
            lock (_lock)
            {
                if (_items.Count == 0) return;
                items = new List<FileEventItem>(_items);
                _items.Clear();
            }

            // Группируем по типу действия
            int copies   = 0, writes = 0, deletes = 0, renames = 0;
            long totalBytes = 0;
            var fileList = new System.Text.StringBuilder();

            foreach (var item in items)
            {
                switch (item.Action)
                {
                    case "COPY":   copies++;  break;
                    case "WRITE":  writes++;  break;
                    case "DELETE": deletes++; break;
                    case "RENAME": renames++; break;
                }
                totalBytes += item.Size;

                // Первые 10 файлов записываем по имени
                if (fileList.Length < 1024)
                {
                    fileList.Append(Path.GetFileName(item.Path));
                    if (item.Action == "RENAME" && item.OldPath != null)
                        fileList.Append($"(from:{Path.GetFileName(item.OldPath)})");
                    fileList.Append(';');
                }
            }

            string totalMb = totalBytes > 0
                ? $"{totalBytes / (1024.0 * 1024):F1}MB"
                : "0MB";

            bool isSuspicious = copies > 5 || totalBytes > 50 * 1024 * 1024;
            string module = isSuspicious ? "FILE_ALERT" : "FILE_COPY";
            string msg    = isSuspicious
                ? $"ALERT: Mass copy to {_drive}"
                : $"File activity on {_drive}";

            Logger.Write(module, msg,
                $"drive={_drive}|" +
                $"copies={copies}|writes={writes}|deletes={deletes}|renames={renames}|" +
                $"files={items.Count}|totalSize={totalMb}|" +
                $"fileList={fileList.ToString().TrimEnd(';')}|" +
                $"user={GetUser()}");
        }

        private static string GetUser()
        {
            try   { return System.Security.Principal.WindowsIdentity.GetCurrent().Name; }
            catch { return "UNKNOWN"; }
        }

        public void Dispose()
        {
            _timer?.Dispose();
        }
    }

    internal class FileEventItem
    {
        public string   Action;
        public string   Path;
        public long     Size;
        public string   OldPath;
        public DateTime Time;
    }
}
