using System;
using System.Runtime.InteropServices;
using System.ServiceProcess;
using System.Windows.Forms;

namespace ZavetSec.DlpAgent
{
    /// <summary>
    /// ZavetSec DLP Agent entry point.
    ///
    /// Run modes:
    ///   --task-mode   Scheduled Task in user session (RECOMMENDED, no window)
    ///   --console     Debug mode with visible console window
    ///   (no args)     Windows Service via SCM
    ///
    /// OutputType=WinExe hides the console window for --task-mode.
    /// --console mode allocates a console window at runtime via AllocConsole().
    /// </summary>
    internal static class Program
    {
        // AllocConsole creates a console window for a WinExe process
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool AllocConsole();

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool FreeConsole();

        [STAThread]
        static void Main(string[] args)
        {
            string arg = args.Length > 0 ? args[0].ToLower() : string.Empty;

            switch (arg)
            {
                // Scheduled Task: runs in user session, no window, screenshots work
                case "--task-mode":
                    RunAsTask();
                    break;

                // Debug mode: allocate a console window at runtime
                case "--console":
                    AllocConsole();
                    RunAsConsole();
                    FreeConsole();
                    break;

                // Windows Service via SCM (screenshots black under SYSTEM/Session 0)
                default:
                    ServiceBase.Run(new DlpService());
                    break;
            }
        }

        // ── Task mode (Scheduled Task, no window) ─────────────────────────
        private static void RunAsTask()
        {
            var svc = new DlpService();
            svc.StartDebug();
            // Application.Run() keeps process alive and pumps Win32 messages.
            // OS will terminate the process on user logoff.
            Application.ApplicationExit += (s, e) => svc.StopDebug();
            Application.Run();
        }

        // ── Console mode (debug, window allocated at runtime) ─────────────
        private static void RunAsConsole()
        {
            Console.Title = "ZavetSec DLP Agent [CONSOLE DEBUG]";
            Console.WriteLine("╔═══════════════════════════════════════╗");
            Console.WriteLine("║   ZavetSec DLP Agent  v2.2  [DEBUG]  ║");
            Console.WriteLine("╚═══════════════════════════════════════╝");
            Console.WriteLine("Press Enter to stop...");
            Console.WriteLine();

            var svc = new DlpService();
            svc.StartDebug();
            Console.ReadLine();
            svc.StopDebug();

            Console.WriteLine("[ZavetSec DLP] Stopped.");
        }
    }
}
