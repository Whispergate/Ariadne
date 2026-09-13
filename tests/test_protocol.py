"""Protocol-level tests for Ariadne wire format and WebshellRPC."""

import asyncio
import base64
import json
import os
import re
import sys
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from aiohttp import web

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "Payload_Type", "ariadne"))

from ariadne.evasion import (
    generate_deformed_alphabet,
    encode_payload,
    decode_payload,
    encrypt_payload,
    decrypt_payload,
)
from ariadne.webshell_rpc import WebshellRPC, WebshellConfig


TEST_PASSWORD = "protocol_test_password"
TEST_AES_KEY_RAW = b"0123456789abcdef0123456789abcdef"
TEST_AES_KEY_B64 = base64.b64encode(TEST_AES_KEY_RAW).decode()
TEST_AUTH_VALUE = "test_auth_12345"


def make_config(url: str) -> WebshellConfig:
    return WebshellConfig(
        url=url,
        auth_method="cookie",
        auth_name="PHPSESSID",
        auth_value=TEST_AUTH_VALUE,
        encoding="deformed_base64",
        deformed_alphabet=generate_deformed_alphabet(TEST_PASSWORD),
        encryption="aes256_cbc",
        aes_key=TEST_AES_KEY_B64,
        request_template="form_post",
        request_param_name="data",
        request_method="POST",
        verify_ssl=False,
        user_agent="AriadneTest/1.0",
        extra_headers={},
    )


class TestWireProtocol:
    def test_command_format(self):
        parts = "shell|task-001|whoami".split("|")
        assert parts[0] == "shell"
        assert parts[1] == "task-001"
        assert parts[2] == "whoami"

    def test_response_success_format(self):
        response = "0|task-001|www-data"
        parts = response.split("|", 2)
        assert parts[0] == "0"
        assert parts[1] == "task-001"
        assert parts[2] == "www-data"

    def test_response_error_format(self):
        response = "1|task-001|Command failed: permission denied"
        parts = response.split("|", 2)
        assert parts[0] == "1"
        assert parts[1] == "task-001"
        assert "permission denied" in parts[2]

    def test_checkin_format(self):
        response = "0|task-001|webserver|Linux|www-data||1234|x86_64|/var/www/html|192.168.1.100"
        parts = response.split("|")
        assert len(parts) >= 9
        assert parts[0] == "0"
        assert parts[2] == "webserver"  # hostname
        assert parts[3] == "Linux"  # os

    def test_tunnel_format(self):
        cmd = "tunnel|MARK123|CONNECT|" + base64.b64encode(b"192.168.1.1:8080").decode()
        parts = cmd.split("|")
        assert parts[0] == "tunnel"
        assert parts[1] == "MARK123"
        assert parts[2] == "CONNECT"

    def test_poll_format(self):
        cmd = "poll|"
        parts = cmd.split("|")
        assert parts[0] == "poll"

    def test_command_with_pipe_in_argument(self):
        cmd = "shell|task-001|echo hello | grep hello"
        parts = cmd.split("|", 2)
        assert parts[0] == "shell"
        assert parts[1] == "task-001"
        assert parts[2] == "echo hello | grep hello"

    def test_ls_response_json(self):
        ls_data = {
            "host": "webserver",
            "parent_path": "/tmp",
            "files": [
                {"name": "test.txt", "is_file": True, "size": 100, "permissions": "0644", "modify_time": "2024-01-01 00:00:00"},
            ],
        }
        response = "0|task-001|" + json.dumps(ls_data)
        parts = response.split("|", 2)
        parsed = json.loads(parts[2])
        assert parsed["host"] == "webserver"
        assert len(parsed["files"]) == 1

    def test_download_response_json(self):
        file_data = {
            "filename": "test.txt",
            "filepath": "/tmp/test.txt",
            "size": 13,
            "data": base64.b64encode(b"Hello, World!").decode(),
        }
        response = "0|task-001|" + json.dumps(file_data)
        parts = response.split("|", 2)
        parsed = json.loads(parts[2])
        assert base64.b64decode(parsed["data"]) == b"Hello, World!"


class TestResponseMarker:
    def test_extract_from_html(self):
        html = '<html><body>Some content<span id="r">ENCODED_DATA_HERE</span></body></html>'
        match = re.search(r'<span id="r">(.*?)</span>', html, re.DOTALL)
        assert match is not None
        assert match.group(1) == "ENCODED_DATA_HERE"

    def test_extract_no_marker(self):
        html = "<html><body>No marker here</body></html>"
        match = re.search(r'<span id="r">(.*?)</span>', html, re.DOTALL)
        assert match is None


class TestEncodingEncryptionPipeline:
    def setup_method(self):
        self.alphabet = generate_deformed_alphabet(TEST_PASSWORD)
        self.key = TEST_AES_KEY_RAW

    def test_full_roundtrip(self):
        original = "shell|task-001|whoami"
        encrypted = encrypt_payload(original.encode(), self.key)
        encoded = encode_payload(encrypted, "deformed_base64", self.alphabet)
        decoded = decode_payload(encoded, "deformed_base64", self.alphabet)
        decrypted = decrypt_payload(decoded, self.key)
        assert decrypted.decode() == original

    def test_hex_encoding_roundtrip(self):
        original = "ls|task-002|/tmp"
        encrypted = encrypt_payload(original.encode(), self.key)
        encoded = encode_payload(encrypted, "hex", "")
        decoded = decode_payload(encoded, "hex", "")
        decrypted = decrypt_payload(decoded, self.key)
        assert decrypted.decode() == original
