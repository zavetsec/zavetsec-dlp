using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace ZavetSec.DlpAgent
{
    /// <summary>
    /// AES-256-CBC зашифрованный лог.
    ///   system_YYYYMMDD.log  — SERVICE, CLIPBOARD, SCREENSHOT, NETWORK, алерты
    ///   keylog_YYYYMMDD.log  — только KEYLOGGER
    ///
    /// Ключ хранится в DPAPI (machine scope).
    /// Формат записи: [4 байта: длина][16 байт: IV][AES-CBC ciphertext]
    /// </summary>
    internal static class Logger
    {
        private static string _logDir;
        private static string _keyFile;
        private static string LogDir  => _logDir  ?? @"C:\ProgramData\ZavetSec\DLP\Logs";
        private static string KeyFile => _keyFile ?? @"C:\ProgramData\ZavetSec\DLP\agent.key";

        private static byte[] _aesKey;
        private static readonly object _lockSys = new object();
        private static readonly object _lockKey = new object();

        // ── Init ──────────────────────────────────────────────────────────
        public static void Init(string logDir = null, string keyFile = null)
        {
            _logDir  = logDir  ?? @"C:\ProgramData\ZavetSec\DLP\Logs";
            _keyFile = keyFile ?? @"C:\ProgramData\ZavetSec\DLP\agent.key";
            Directory.CreateDirectory(LogDir);
            _aesKey = LoadOrCreateKey();
        }

        // ── Public API ────────────────────────────────────────────────────

        /// <summary>
        /// Записать событие локально И отправить на сервер через LogShipper.
        /// Используется всеми модулями для основных событий.
        /// </summary>
        public static void Write(string module, string message, string data = null)
        {
            string json   = BuildJson(module, message, data);
            bool isKeylog = module.StartsWith("KEYLOGGER", StringComparison.OrdinalIgnoreCase);
            AppendEncrypted(json, isKeylog);
            LogShipper.Enqueue(json); // отправляем на сервер
        }

        /// <summary>
        /// Записать событие ТОЛЬКО локально, не передавая в LogShipper.
        /// Используется самим LogShipper, CommandPoller и ScreenshotShipper
        /// чтобы избежать рекурсии при ошибках отправки.
        /// </summary>
        public static void WriteLocal(string module, string message, string data = null)
        {
            string json   = BuildJson(module, message, data);
            bool isKeylog = module.StartsWith("KEYLOGGER", StringComparison.OrdinalIgnoreCase);
            AppendEncrypted(json, isKeylog);
            // LogShipper.Enqueue НЕ вызываем — нет рекурсии
        }

        public static void Flush() { /* все записи синхронны */ }

        // ── Encryption ────────────────────────────────────────────────────
        private static void AppendEncrypted(string plaintext, bool isKeylog)
        {
            object fileLock = isKeylog ? _lockKey : _lockSys;

            lock (fileLock)
            {
                string date    = DateTime.UtcNow.ToString("yyyyMMdd");
                string prefix  = isKeylog ? "keylog" : "system";
                string logPath = Path.Combine(LogDir, $"{prefix}_{date}.log");

                byte[] plain = Encoding.UTF8.GetBytes(plaintext);

                using (var aes = Aes.Create())
                {
                    aes.Key     = _aesKey;
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

                    using (var fs = new FileStream(logPath,
                        FileMode.Append, FileAccess.Write, FileShare.None))
                        fs.Write(record, 0, record.Length);
                }
            }
        }

        // ── Key management ────────────────────────────────────────────────
        private static byte[] LoadOrCreateKey()
        {
            if (File.Exists(KeyFile))
            {
                byte[] blob = File.ReadAllBytes(KeyFile);
                return ProtectedData.Unprotect(blob, null, DataProtectionScope.LocalMachine);
            }

            byte[] key = new byte[32];
            using (var rng = RandomNumberGenerator.Create())
                rng.GetBytes(key);

            byte[] protectedKey = ProtectedData.Protect(key, null, DataProtectionScope.LocalMachine);
            File.WriteAllBytes(KeyFile, protectedKey);

            LockFileToSystem(KeyFile);
            return key;
        }

        private static void LockFileToSystem(string path)
        {
            try
            {
                var fi  = new FileInfo(path);
                var acl = fi.GetAccessControl();
                acl.SetAccessRuleProtection(true, false);

                // SYSTEM — полный доступ (для запуска как служба / задача планировщика)
                acl.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(
                    @"NT AUTHORITY\SYSTEM",
                    System.Security.AccessControl.FileSystemRights.FullControl,
                    System.Security.AccessControl.AccessControlType.Allow));

                // Administrators — полный доступ (для запуска --console от администратора)
                acl.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(
                    new System.Security.Principal.SecurityIdentifier(
                        System.Security.Principal.WellKnownSidType.BuiltinAdministratorsSid, null),
                    System.Security.AccessControl.FileSystemRights.FullControl,
                    System.Security.AccessControl.AccessControlType.Allow));

                fi.SetAccessControl(acl);
            }
            catch { /* при тесте без Admin — пропустить */ }
        }

        // ── Helpers ───────────────────────────────────────────────────────
        private static string BuildJson(string module, string message, string data)
        {
            var sb = new StringBuilder("{");
            AppendField(sb, "ts",     DateTime.UtcNow.ToString("o"));
            AppendField(sb, "host",   Environment.MachineName);
            AppendField(sb, "user",   NativeHelpers.GetCurrentUser());
            AppendField(sb, "module", module);
            AppendField(sb, "msg",    message);
            AppendField(sb, "data",   data ?? "");
            if (sb[sb.Length - 1] == ',') sb.Length--;
            sb.Append("}");
            return sb.ToString();
        }

        private static void AppendField(StringBuilder sb, string key, string value)
        {
            value = value
                .Replace("\\", "\\\\")
                .Replace("\"", "\\\"")
                .Replace("\r", "\\r")
                .Replace("\n", "\\n")
                .Replace("\t", "\\t");
            sb.Append($"\"{key}\":\"{value}\",");
        }
    }
}
