using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Management;
using System.Net;
using System.Net.NetworkInformation;
using System.Text.RegularExpressions;
using System.Threading;

namespace ZavetSec.DlpAgent
{
    /// <summary>
    /// Network monitor: TCP connections on alert ports + DNS cache tracking.
    ///
    /// DNS tracking uses ipconfig /displaydns but properly parses hostname + IP pairs,
    /// ignoring TTL lines, empty lines, and other noise. Only logs actual new
    /// hostname resolutions with their resolved IPs.
    ///
    /// TCP: checks active connections and listeners against AlertPorts list.
    /// </summary>
    internal class NetworkMonitor
    {
        private System.Threading.Timer _connTimer;
        private System.Threading.Timer _dnsTimer;

        // Known DNS entries: hostname -> set of IPs
        private readonly Dictionary<string, HashSet<string>> _knownDns
            = new Dictionary<string, HashSet<string>>(StringComparer.OrdinalIgnoreCase);

        private bool _dnsFirstRun = true;

        public void Start()
        {
            var cfg = Config.Current.Network;
            if (!cfg.Enabled)
            {
                Logger.Write("NETWORK", "Disabled in config");
                return;
            }

            _connTimer = new System.Threading.Timer(
                _ => PollConnections(), null,
                0, cfg.ConnectionCheckSeconds * 1000);

            _dnsTimer = new System.Threading.Timer(
                _ => PollDnsCache(), null,
                5000, cfg.DnsCheckSeconds * 1000);

            Logger.Write("NETWORK", "Monitor started",
                $"connCheck={cfg.ConnectionCheckSeconds}s|" +
                $"dnsCheck={cfg.DnsCheckSeconds}s|" +
                $"alertPorts={string.Join(",", cfg.AlertPorts)}");
        }

        public void Stop()
        {
            _connTimer?.Dispose();
            _dnsTimer?.Dispose();
            Logger.Write("NETWORK", "Monitor stopped");
        }

        // ── TCP connections ───────────────────────────────────────────────
        private void PollConnections()
        {
            try
            {
                int[] alertPorts = Config.Current.Network.AlertPorts;
                var props = IPGlobalProperties.GetIPGlobalProperties();

                foreach (var conn in props.GetActiveTcpConnections())
                {
                    if (!IsAlertPort(conn.RemoteEndPoint.Port, alertPorts)) continue;
                    string proc = GetProcessByPort(conn.LocalEndPoint.Port);
                    Logger.Write("NETWORK_TCP", "ALERT: suspicious port",
                        $"local={conn.LocalEndPoint}|remote={conn.RemoteEndPoint}|" +
                        $"state={conn.State}|process={proc}");
                }

                foreach (var ep in props.GetActiveTcpListeners())
                {
                    if (!IsAlertPort(ep.Port, alertPorts)) continue;
                    string proc = GetProcessByPort(ep.Port);
                    Logger.Write("NETWORK_LISTENER", "Suspicious listener detected",
                        $"endpoint={ep}|process={proc}");
                }
            }
            catch (Exception ex)
            {
                Logger.Write("NETWORK_ERROR", "PollConnections: " + ex.Message);
            }
        }

        // ── DNS cache tracking ────────────────────────────────────────────
        private void PollDnsCache()
        {
            try
            {
                // Parse hostname->IPs from ipconfig /displaydns output
                var current = ParseDnsCache();
                if (current.Count == 0) return;

                if (_dnsFirstRun)
                {
                    // Baseline snapshot — just remember, don't log
                    foreach (var kv in current)
                        _knownDns[kv.Key] = kv.Value;
                    _dnsFirstRun = false;
                    return;
                }

                // Find truly new hostnames or new IPs for known hostnames
                foreach (var kv in current)
                {
                    string host = kv.Key;
                    HashSet<string> ips = kv.Value;

                    if (!_knownDns.ContainsKey(host))
                    {
                        // Brand new hostname resolved
                        string ipList = string.Join(", ", ips);
                        bool isSuspicious = IsSuspiciousDomain(host);
                        string module = isSuspicious ? "DNS_ALERT" : "DNS_NEW";

                        Logger.Write(module,
                            isSuspicious
                                ? $"ALERT: suspicious domain resolved"
                                : "New DNS resolution",
                            $"host={host}|ip={ipList}");

                        _knownDns[host] = ips;
                    }
                    else
                    {
                        // Known hostname — check for new IPs (CDN rotation etc.)
                        var known = _knownDns[host];
                        var newIps = new List<string>();
                        foreach (var ip in ips)
                            if (!known.Contains(ip)) newIps.Add(ip);

                        if (newIps.Count > 0)
                        {
                            Logger.Write("DNS_IP_CHANGE",
                                "DNS IP changed (CDN rotation or new record)",
                                $"host={host}|new_ip={string.Join(", ", newIps)}|" +
                                $"old_ip={string.Join(", ", known)}");

                            foreach (var ip in newIps) known.Add(ip);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.Write("NETWORK_ERROR", "PollDnsCache: " + ex.Message);
            }
        }

        // ── Parse ipconfig /displaydns into hostname->IPs map ─────────────
        private static Dictionary<string, HashSet<string>> ParseDnsCache()
        {
            var result = new Dictionary<string, HashSet<string>>(
                StringComparer.OrdinalIgnoreCase);

            string output = RunIpconfig();
            if (string.IsNullOrEmpty(output)) return result;

            string currentHost = null;

            // ipconfig /displaydns output format:
            //   Record Name . . . . : example.com
            //   Record Type . . . . : 1
            //   Time To Live  . . . : 300        <- we SKIP this
            //   Data Length . . . . : 4
            //   Section . . . . . . : Answer
            //   A (Host) Record . . : 1.2.3.4    <- we WANT this
            //
            //   Record Name . . . . : something.local
            //   ...

            foreach (string rawLine in output.Split('\n'))
            {
                string line = rawLine.Trim();
                if (string.IsNullOrEmpty(line)) continue;

                // Extract key and value by splitting on ": "
                int sep = line.IndexOf(": ", StringComparison.Ordinal);
                if (sep < 0) continue;

                string key   = line.Substring(0, sep).Trim(' ', '.').ToLowerInvariant();
                string value = line.Substring(sep + 2).Trim();

                if (string.IsNullOrEmpty(value)) continue;

                // Record Name line -> set current hostname
                if (key == "record name")
                {
                    currentHost = value.TrimEnd('.');
                    // Skip localhost, broadcast, mDNS
                    if (IsNoiseHost(currentHost)) currentHost = null;
                    continue;
                }

                // Skip if no active hostname
                if (currentHost == null) continue;

                // A record (IPv4) or AAAA record (IPv6)
                if (key == "a (host) record" || key == "aaaa record" ||
                    key == "a  (host) record")
                {
                    if (!IsValidIp(value)) continue;

                    if (!result.ContainsKey(currentHost))
                        result[currentHost] = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

                    result[currentHost].Add(value);
                }
                // CNAME
                else if (key == "cname record")
                {
                    if (!result.ContainsKey(currentHost))
                        result[currentHost] = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                    result[currentHost].Add($"cname:{value.TrimEnd('.')}");
                }
                // Explicitly skip TTL, Data Length, Section, Record Type
            }

            return result;
        }

        private static string RunIpconfig()
        {
            try
            {
                var psi = new ProcessStartInfo("ipconfig", "/displaydns")
                {
                    RedirectStandardOutput = true,
                    UseShellExecute        = false,
                    CreateNoWindow         = true,
                    StandardOutputEncoding = System.Text.Encoding.GetEncoding(866)
                };
                using (var p = Process.Start(psi))
                {
                    string output = p.StandardOutput.ReadToEnd();
                    p.WaitForExit(5000);
                    return output;
                }
            }
            catch { return string.Empty; }
        }

        // ── Suspicious domain check ────────────────────────────────────────
        private static readonly string[] SuspiciousTlds = {
            ".onion", ".i2p", ".bit", ".exit"
        };

        private static readonly string[] SuspiciousKeywords = {
            "pastebin", "ngrok", "serveo", "pagekite",
            "duckdns", "no-ip", "dynu", "hopto",
            "freedns", "afraid.org", "ddns"
        };

        private static bool IsSuspiciousDomain(string host)
        {
            string lower = host.ToLowerInvariant();
            foreach (var tld in SuspiciousTlds)
                if (lower.EndsWith(tld)) return true;
            foreach (var kw in SuspiciousKeywords)
                if (lower.Contains(kw)) return true;
            return false;
        }

        // ── Noise filter ──────────────────────────────────────────────────
        private static bool IsNoiseHost(string host)
        {
            if (string.IsNullOrEmpty(host)) return true;
            string lower = host.ToLowerInvariant();
            return lower == "localhost"
                || lower == "wpad"
                || lower.EndsWith(".local")
                || lower.EndsWith(".arpa")
                || lower.StartsWith("_");
        }

        private static bool IsValidIp(string s)
        {
            return IPAddress.TryParse(s, out _);
        }

        // ── Helpers ───────────────────────────────────────────────────────
        private static bool IsAlertPort(int port, int[] ports)
        {
            foreach (int p in ports) if (p == port) return true;
            return false;
        }

        private static string GetProcessByPort(int port)
        {
            try
            {
                using (var s = new ManagementObjectSearcher(@"ROOT\StandardCimv2",
                    $"SELECT OwningProcess FROM MSFT_NetTCPConnection WHERE LocalPort={port}"))
                    foreach (ManagementObject o in s.Get())
                    {
                        uint pid = (uint)o["OwningProcess"];
                        try
                        {
                            return Process.GetProcessById((int)pid).ProcessName
                                   + $"(PID:{pid})";
                        }
                        catch { return $"PID:{pid}"; }
                    }
            }
            catch { }
            return "unknown";
        }
    }
}
