"""
Mock Mythic Server for Tier 1 protocol testing.

Speaks the same binary TLV + AES256-CBC protocol as the real Mythic server.
Handles: checkin, get_tasking (with command queue), post_response.

Usage:
    python mock_mythic_server.py [--port 8080] [--aes-key hex] [--uuid UUID]

The server listens on HTTP and processes agent messages at /agent_message.
It logs all protocol exchanges and validates message structure.
"""
import os
import sys
import json
import struct
import base64
import hashlib
import hmac
import argparse
import threading
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from io import BytesIO

# add translator to path for Packer/Parser
sys.path.insert(0, os.path.join(os.path.dirname(__file__),
    "..", "Payload_Type", "Starburst"))

from translator.utils import (
    Packer, Parser,
    ACTION_CHECKIN, ACTION_GET_TASKING, ACTION_POST_RESPONSE,
    ACTION_CHECKIN_RSP, RESPONSE_SUCCESS, RESPONSE_ERROR,
    DOWNLOAD_INIT, DOWNLOAD_CHUNK, UPLOAD_REQUEST, UPLOAD_CHUNK_RSP,
    CMD_MAP,
)

try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad, unpad
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False


# ── Default test values ──

DEFAULT_UUID = "11111111-1111-1111-1111-111111111111"
DEFAULT_AES_KEY = bytes.fromhex(
    "4142434445464748494a4b4c4d4e4f50"
    "5152535455565758595a616263646566"
)
CALLBACK_UUID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"


class MockMythicState:
    """Shared state for the mock server."""

    def __init__(self, payload_uuid, aes_key, callback_uuid=CALLBACK_UUID):
        self.payload_uuid = payload_uuid
        self.aes_key = aes_key
        self.callback_uuid = callback_uuid
        self.checked_in = False
        self.checkin_data = None
        self.task_queue = []
        self.responses = []
        self.exchange_log = []
        self.lock = threading.RLock()

    def queue_task(self, command, params=None):
        """Queue a task for the agent to pick up."""
        import uuid as uuid_mod
        task_uuid = str(uuid_mod.uuid4())
        self.task_queue.append({
            "command": command,
            "id": task_uuid,
            "parameters": params or {},
        })
        return task_uuid

    def encrypt(self, plaintext):
        """AES256-CBC encrypt with HMAC, matching agent format."""
        if not HAS_CRYPTO:
            return plaintext

        iv = os.urandom(16)
        cipher = AES.new(self.aes_key, AES.MODE_CBC, iv)
        padded = pad(plaintext, AES.block_size)
        ciphertext = cipher.encrypt(padded)

        # HMAC-SHA256 over IV + ciphertext
        mac = hmac.new(self.aes_key, iv + ciphertext, hashlib.sha256).digest()

        return iv + ciphertext + mac

    def decrypt(self, blob):
        """AES256-CBC decrypt with HMAC verification."""
        if not HAS_CRYPTO:
            return blob

        if len(blob) < 48:  # 16 IV + 16 min ciphertext + 16 padding... actually 32 HMAC
            raise ValueError(f"blob too short: {len(blob)} bytes")

        iv = blob[:16]
        mac_received = blob[-32:]
        ciphertext = blob[16:-32]

        # verify HMAC
        mac_computed = hmac.new(
            self.aes_key, iv + ciphertext, hashlib.sha256
        ).digest()
        if not hmac.compare_digest(mac_received, mac_computed):
            raise ValueError("HMAC verification failed")

        cipher = AES.new(self.aes_key, AES.MODE_CBC, iv)
        plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
        return plaintext

    def process_message(self, raw_body):
        """Process a raw HTTP body from the agent."""
        # decode base64
        try:
            decoded = base64.b64decode(raw_body)
        except Exception as e:
            return self._error(f"base64 decode failed: {e}")

        # extract UUID prefix (36 bytes)
        if len(decoded) < 37:
            return self._error("message too short for UUID prefix")

        uuid_prefix = decoded[:36].decode("utf-8", errors="replace")
        encrypted_payload = decoded[36:]

        self._log("RECV", f"UUID prefix: {uuid_prefix}")

        # decrypt
        try:
            if HAS_CRYPTO and len(encrypted_payload) >= 48:
                tlv_data = self.decrypt(encrypted_payload)
            else:
                tlv_data = encrypted_payload
        except ValueError as e:
            return self._error(f"decrypt failed: {e}")

        if len(tlv_data) < 1:
            return self._error("empty TLV payload")

        action = tlv_data[0]
        self._log("RECV", f"action=0x{action:02x}, len={len(tlv_data)}")

        # dispatch
        if action == ACTION_CHECKIN:
            response_tlv = self._handle_checkin(tlv_data)
        elif action == ACTION_GET_TASKING:
            response_tlv = self._handle_get_tasking(tlv_data)
        elif action == ACTION_POST_RESPONSE:
            response_tlv = self._handle_post_response(tlv_data)
        else:
            return self._error(f"unknown action: 0x{action:02x}")

        # encrypt response
        if HAS_CRYPTO:
            encrypted_response = self.encrypt(response_tlv)
        else:
            encrypted_response = response_tlv

        # format: base64(UUID + encrypted_response)
        resp_with_uuid = self.callback_uuid.encode("utf-8") + encrypted_response
        return base64.b64encode(resp_with_uuid)

    def _handle_checkin(self, data):
        """Process checkin, return callback UUID."""
        from translator.to_mythic import parse_checkin

        msg = parse_checkin(data)
        self._log("CHECKIN", json.dumps(msg, indent=2))

        with self.lock:
            self.checked_in = True
            self.checkin_data = msg

        pk = Packer()
        pk.add_byte(ACTION_CHECKIN_RSP)
        pk.add_string(self.callback_uuid)
        return pk.build()

    def _handle_get_tasking(self, data):
        """Return queued tasks, parse any piggybacked responses."""
        from translator.to_mythic import parse_get_tasking
        from translator.to_agent import pack_tasking

        msg = parse_get_tasking(data)
        self._log("GET_TASKING", json.dumps(msg, indent=2))

        # store any piggybacked responses
        if "responses" in msg:
            with self.lock:
                for rsp in msg["responses"]:
                    self.responses.append(rsp)
                    self._log("RESPONSE", json.dumps(rsp, indent=2))

        # build tasking response
        with self.lock:
            tasks = list(self.task_queue)
            self.task_queue.clear()

        tasking_msg = {"tasks": tasks}
        self._log("TASKING", f"sending {len(tasks)} tasks")
        return pack_tasking(tasking_msg)

    def _handle_post_response(self, data):
        """Process a standalone post_response."""
        from translator.to_mythic import parse_single_response

        msg = parse_single_response(data)
        self._log("POST_RESPONSE", json.dumps(msg, indent=2))

        with self.lock:
            self.responses.append(msg)

        # ACK with empty tasking
        pk = Packer()
        pk.add_byte(ACTION_GET_TASKING)
        pk.add_int32(0)
        return pk.build()

    def _error(self, msg):
        self._log("ERROR", msg)
        return b"error"

    def _log(self, tag, msg):
        entry = f"[{tag}] {msg}"
        with self.lock:
            self.exchange_log.append(entry)
        print(entry)


class MockMythicHandler(BaseHTTPRequestHandler):
    """HTTP handler for mock Mythic server."""

    server_state: MockMythicState = None

    def do_POST(self):
        content_len = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_len)

        response = self.server_state.process_message(body)

        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.end_headers()
        if isinstance(response, bytes):
            self.wfile.write(response)
        else:
            self.wfile.write(str(response).encode())

    def do_GET(self):
        # health check / status endpoint
        if self.path == "/status":
            status = {
                "checked_in": self.server_state.checked_in,
                "responses_count": len(self.server_state.responses),
                "task_queue_count": len(self.server_state.task_queue),
            }
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(status).encode())
            return

        # queue task via GET for convenience
        if self.path.startswith("/queue/"):
            cmd = self.path.split("/queue/")[1].split("?")[0]
            params_str = self.path.split("?params=")[1] if "?params=" in self.path else "{}"
            try:
                params = json.loads(params_str)
            except:
                params = {}
            task_uuid = self.server_state.queue_task(cmd, params)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"task_id": task_uuid}).encode())
            return

        self.send_response(404)
        self.end_headers()

    def log_message(self, format, *args):
        pass  # suppress default logging


def create_server(port=8080, aes_key=DEFAULT_AES_KEY, uuid=DEFAULT_UUID):
    """Create and return a mock Mythic server."""
    state = MockMythicState(uuid, aes_key)
    MockMythicHandler.server_state = state
    server = HTTPServer(("127.0.0.1", port), MockMythicHandler)
    return server, state


def run_server(port=8080, aes_key=DEFAULT_AES_KEY, uuid=DEFAULT_UUID):
    """Run mock server (blocking)."""
    server, state = create_server(port, aes_key, uuid)
    print(f"Mock Mythic Server listening on http://127.0.0.1:{port}")
    print(f"Payload UUID: {uuid}")
    print(f"AES Key: {aes_key.hex()}")
    print(f"Callback UUID: {CALLBACK_UUID}")
    if not HAS_CRYPTO:
        print("WARNING: pycryptodome not installed - running without encryption")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Mock Mythic Server")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--aes-key", default=DEFAULT_AES_KEY.hex())
    parser.add_argument("--uuid", default=DEFAULT_UUID)
    args = parser.parse_args()

    aes_key = bytes.fromhex(args.aes_key)
    run_server(args.port, aes_key, args.uuid)
