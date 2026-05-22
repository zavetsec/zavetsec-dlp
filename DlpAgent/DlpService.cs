using System;
using System.ServiceProcess;
using System.Threading;
using System.Windows.Forms;

namespace ZavetSec.DlpAgent
{
    public class DlpService : ServiceBase
    {
        private ClipboardMonitor    _clipboard;
        private KeyloggerMonitor    _keylogger;
        private ScreenshotMonitor   _screenshot;
        private NetworkMonitor      _network;
        private RetentionManager    _retention;
        private UsbMonitor          _usb;
        private FileActivityMonitor _fileActivity;
        private ProcessMonitor      _process;
        private CommandPoller       _commandPoller;
        private System.Threading.Timer _heartbeatTimer;

        private Thread _pumpThread;
        private Form   _pumpForm;

        public DlpService()
        {
            ServiceName         = "ZavetSecDlpAgent";
            CanStop             = true;
            CanPauseAndContinue = false;
            AutoLog             = false;
        }

        protected override void OnStart(string[] args)
        {
            StartInternal();
            InitCommandPoller();
        }
        protected override void OnStop() => StopInternal();

        public void StartDebug()
        {
            StartInternal();
            InitCommandPoller();
        }
        public void StopDebug() => StopInternal();

        private void InitCommandPoller()
        {
            if (_commandPoller != null) return; // already running
            _commandPoller = new CommandPoller(
                stopCallback:    () => StopInternal(),
                startCallback:   () => StartInternal(),
                restartCallback: () => { StopInternal(); Thread.Sleep(500); StartInternal(); }
            );
            _commandPoller.Start();
        }

        private void StartInternal()
        {
            Config.InitSilent();

            Logger.Init(
                Config.Current.Storage.LogDir,
                Config.Current.Storage.KeyFile);

            LogShipper.Init();
            ScreenshotShipper.Init();

            Logger.Write("SERVICE", "DLP Agent starting",
                $"mode=task|host={Environment.MachineName}|pid={System.Diagnostics.Process.GetCurrentProcess().Id}|shipping={Config.Current.Shipper.Enabled}");

            _clipboard  = new ClipboardMonitor();
            _keylogger  = new KeyloggerMonitor();
            _screenshot = new ScreenshotMonitor();
            _network    = new NetworkMonitor();

            bool needOwnPump = !Application.MessageLoop;
            if (needOwnPump)
            {
                _pumpThread = new Thread(PumpWorker)
                {
                    IsBackground = true,
                    Name         = "ZavetSec-MessagePump"
                };
                _pumpThread.SetApartmentState(ApartmentState.STA);
                _pumpThread.Start();
            }
            else
            {
                _clipboard.Start();
                _keylogger.Start();
            }

            _screenshot.Start();
            _network.Start();

            _retention = new RetentionManager();
            _retention.Start();

            _usb = new UsbMonitor();
            _usb.Start();

            _fileActivity = new FileActivityMonitor();
            _fileActivity.Start();

            _process = new ProcessMonitor();
            _process.Start();

            // CommandPoller запускается один раз при первом старте (см. ниже в OnStart/StartDebug).
            // При повторном StartInternal (команда start) поллер уже работает — не пересоздаём.

            // Heartbeat каждые 60 сек — обновляет last_seen на сервере
            // чтобы Online-статус в дашборде не мигал при отсутствии активности.
            // Logger.Write отправляет через LogShipper если shipper включён.
            _heartbeatTimer = new System.Threading.Timer(_ =>
            {
                try { Logger.Write("HEARTBEAT", "Agent alive",
                    $"host={Environment.MachineName}"); }
                catch { }
            }, null, 60_000, 60_000);

            Logger.Write("SERVICE", "All monitors started");
        }

        private void StopInternal()
        {
            _heartbeatTimer?.Dispose();
            _heartbeatTimer = null;

            // CommandPoller намеренно НЕ останавливается при Stop —
            // иначе агент не получит команду Start с сервера.
            // Поллер останавливается только при Restart/Uninstall/выходе процесса.

            _clipboard?.Stop();
            _keylogger?.Stop();
            _screenshot?.Stop();
            _network?.Stop();
            _retention?.Stop();
            _usb?.Stop();
            _fileActivity?.Stop();
            _process?.Stop();

            Logger.Write("SERVICE", "DLP Agent stopped");
            Logger.Flush();
            ScreenshotShipper.Stop();
            LogShipper.Stop();

            if (_pumpForm != null && !_pumpForm.IsDisposed)
            {
                try { _pumpForm.BeginInvoke(new Action(() => _pumpForm.Close())); }
                catch { }
            }
            _pumpThread?.Join(5000);
        }

        private void PumpWorker()
        {
            _pumpForm = new Form
            {
                ShowInTaskbar   = false,
                WindowState     = FormWindowState.Minimized,
                FormBorderStyle = FormBorderStyle.None
            };
            _pumpForm.Load += (s, e) =>
            {
                _pumpForm.Hide();
                _clipboard.Start();
                _keylogger.Start();
            };
            Application.Run(_pumpForm);
        }
    }
}
