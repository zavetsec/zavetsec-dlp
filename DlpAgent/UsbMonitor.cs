using System;
using System.Management;
using System.Threading;

namespace ZavetSec.DlpAgent
{
    /// <summary>
    /// Мониторинг подключения и отключения USB-устройств через WMI.
    ///
    /// Отслеживает три события:
    ///   - Подключение устройства  (Win32_DeviceChangeEvent / __InstanceCreationEvent)
    ///   - Отключение устройства   (__InstanceDeletionEvent)
    ///   - Появление нового тома   (Win32_VolumeChangeEvent — флешки, внешние диски)
    ///
    /// При подключении съёмного накопителя пишет алерт USB_ALERT.
    /// Для всех устройств пишет USB_CONNECT / USB_DISCONNECT.
    /// </summary>
    internal class UsbMonitor
    {
        // ── WMI watchers ─────────────────────────────────────────────────
        private ManagementEventWatcher _connectWatcher;
        private ManagementEventWatcher _disconnectWatcher;
        private ManagementEventWatcher _volumeWatcher;

        // ── Public ────────────────────────────────────────────────────────
        public void Start()
        {
            try
            {
                // Подключение USB-устройства (создание экземпляра Win32_USBHub)
                _connectWatcher = CreateWatcher(
                    "__InstanceCreationEvent",
                    "Win32_USBHub",
                    OnConnect);

                // Отключение USB-устройства
                _disconnectWatcher = CreateWatcher(
                    "__InstanceDeletionEvent",
                    "Win32_USBHub",
                    OnDisconnect);

                // Появление нового тома (флешка, внешний диск)
                _volumeWatcher = CreateVolumeWatcher();

                Logger.Write("USB", "USB monitor started");
            }
            catch (Exception ex)
            {
                Logger.Write("USB_ERROR", "USB monitor start error: " + ex.Message);
            }
        }

        public void Stop()
        {
            StopWatcher(_connectWatcher);
            StopWatcher(_disconnectWatcher);
            StopWatcher(_volumeWatcher);
            Logger.Write("USB", "USB monitor stopped");
        }

        // ── Watcher factories ─────────────────────────────────────────────
        private static ManagementEventWatcher CreateWatcher(
            string eventClass, string targetClass,
            EventArrivedEventHandler handler)
        {
            var query = new WqlEventQuery(
                $"SELECT * FROM {eventClass} WITHIN 2 " +
                $"WHERE TargetInstance ISA '{targetClass}'");

            var scope   = new ManagementScope(@"\\.\root\CIMV2");
            var watcher = new ManagementEventWatcher(scope, query);
            watcher.EventArrived += handler;
            watcher.Start();
            return watcher;
        }

        private static ManagementEventWatcher CreateVolumeWatcher()
        {
            // Win32_VolumeChangeEvent — срабатывает при появлении нового диска
            var query = new WqlEventQuery(
                "SELECT * FROM Win32_VolumeChangeEvent WHERE EventType = 2");

            var scope   = new ManagementScope(@"\\.\root\CIMV2");
            var watcher = new ManagementEventWatcher(scope, query);
            watcher.EventArrived += OnVolumeArrived;
            watcher.Start();
            return watcher;
        }

        private static void StopWatcher(ManagementEventWatcher w)
        {
            try { w?.Stop(); w?.Dispose(); }
            catch { }
        }

        // ── Event handlers ────────────────────────────────────────────────
        private static void OnConnect(object sender, EventArrivedEventArgs e)
        {
            try
            {
                var target = e.NewEvent["TargetInstance"] as ManagementBaseObject;
                if (target == null) return;

                string deviceId   = target["DeviceID"]?.ToString() ?? "";
                string name       = target["Name"]?.ToString() ?? "";
                string pnpClass   = target["PNPClass"]?.ToString() ?? "";

                Logger.Write("USB_CONNECT", "USB device connected",
                    $"name={name}|deviceId={deviceId}|class={pnpClass}|" +
                    $"user={GetCurrentUser()}");
            }
            catch (Exception ex)
            {
                Logger.Write("USB_ERROR", "OnConnect: " + ex.Message);
            }
        }

        private static void OnDisconnect(object sender, EventArrivedEventArgs e)
        {
            try
            {
                var target = e.NewEvent["TargetInstance"] as ManagementBaseObject;
                if (target == null) return;

                string deviceId = target["DeviceID"]?.ToString() ?? "";
                string name     = target["Name"]?.ToString() ?? "";

                Logger.Write("USB_DISCONNECT", "USB device disconnected",
                    $"name={name}|deviceId={deviceId}|user={GetCurrentUser()}");
            }
            catch (Exception ex)
            {
                Logger.Write("USB_ERROR", "OnDisconnect: " + ex.Message);
            }
        }

        private static void OnVolumeArrived(object sender, EventArrivedEventArgs e)
        {
            try
            {
                // Получить букву диска из события
                string driveName = e.NewEvent["DriveName"]?.ToString() ?? "";

                // Получить детали тома через Win32_LogicalDisk
                string label      = "";
                string driveType  = "";
                string size       = "";
                string fileSystem = "";

                try
                {
                    using (var searcher = new ManagementObjectSearcher(
                        $"SELECT * FROM Win32_LogicalDisk WHERE DeviceID='{driveName}'"))
                    {
                        foreach (ManagementObject disk in searcher.Get())
                        {
                            label      = disk["VolumeName"]?.ToString() ?? "";
                            fileSystem = disk["FileSystem"]?.ToString() ?? "";
                            driveType  = GetDriveTypeName(
                                disk["DriveType"] != null
                                ? Convert.ToUInt32(disk["DriveType"])
                                : 0);
                            ulong bytes = disk["Size"] != null
                                ? Convert.ToUInt64(disk["Size"]) : 0;
                            size = bytes > 0
                                ? $"{bytes / (1024 * 1024 * 1024)} GB"
                                : "unknown";
                        }
                    }
                }
                catch { }

                bool isRemovable = driveType == "Removable" || driveType == "Unknown";

                string msg = isRemovable
                    ? "ALERT: Removable drive connected"
                    : "New volume mounted";

                string module = isRemovable ? "USB_ALERT" : "USB_VOLUME";

                Logger.Write(module, msg,
                    $"drive={driveName}|label={label}|" +
                    $"type={driveType}|size={size}|fs={fileSystem}|" +
                    $"user={GetCurrentUser()}");
            }
            catch (Exception ex)
            {
                Logger.Write("USB_ERROR", "OnVolumeArrived: " + ex.Message);
            }
        }

        // ── Helpers ───────────────────────────────────────────────────────
        private static string GetDriveTypeName(uint t)
        {
            switch (t)
            {
                case 0: return "Unknown";
                case 1: return "NoRootDir";
                case 2: return "Removable";
                case 3: return "Fixed";
                case 4: return "Network";
                case 5: return "CDROM";
                case 6: return "RAM";
                default: return $"Type{t}";
            }
        }

        private static string GetCurrentUser()
        {
            try   { return System.Security.Principal.WindowsIdentity.GetCurrent().Name; }
            catch { return "UNKNOWN"; }
        }
    }
}
