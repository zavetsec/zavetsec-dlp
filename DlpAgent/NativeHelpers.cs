using System;
using System.Runtime.InteropServices;
using System.Text;

namespace ZavetSec.DlpAgent
{
    internal static class NativeHelpers
    {
        // Returns current Windows user in DOMAIN\username format
        public static string GetCurrentUser()
        {
            try { return System.Security.Principal.WindowsIdentity.GetCurrent().Name; }
            catch { return Environment.UserName; }
        }

        // Returns keyboard layout language code for the active window
        public static string GetKeyboardLayout()
        {
            try
            {
                IntPtr hwnd = GetForegroundWindow();
                uint tid = GetWindowThreadProcessId(hwnd, out _);
                IntPtr hkl = GetKeyboardLayout(tid);
                int lcid = (int)(hkl.ToInt64() & 0xFFFF);
                return new System.Globalization.CultureInfo(lcid).TwoLetterISOLanguageName.ToUpper();
            }
            catch { return "EN"; }
        }
        [DllImport("user32.dll")]
        private static extern IntPtr GetForegroundWindow();

        [DllImport("user32.dll", CharSet = CharSet.Unicode)]
        private static extern int GetWindowText(IntPtr hWnd, StringBuilder text, int count);

        [DllImport("user32.dll")]
        private static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);

        [DllImport("user32.dll")]
        private static extern IntPtr GetKeyboardLayout(uint idThread);

        public static string GetActiveWindowTitle()
        {
            try
            {
                IntPtr hwnd = GetForegroundWindow();
                if (hwnd == IntPtr.Zero) return string.Empty;

                var sb = new StringBuilder(256);
                GetWindowText(hwnd, sb, 256);

                // Also capture owning PID / process name
                GetWindowThreadProcessId(hwnd, out uint pid);
                string procName = string.Empty;
                try
                {
                    procName = System.Diagnostics.Process.GetProcessById((int)pid).ProcessName;
                }
                catch { }

                return $"{sb} [{procName} PID:{pid}]";
            }
            catch
            {
                return string.Empty;
            }
        }
    }
}


