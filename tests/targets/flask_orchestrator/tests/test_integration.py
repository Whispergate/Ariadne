"""Integration tests for Ariadne webshell agent against Docker targets."""

import asyncio
import base64
import json
import os
import sys
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "..", ".."))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "..", "..", "Payload_Type", "ariadne"))

from ariadne.evasion import generate_deformed_alphabet, encode_payload, decode_payload, encrypt_payload, decrypt_payload
from ariadne.webshell_rpc import WebshellRPC, WebshellConfig


TARGET_CONFIGS = {
    "php": {
        "url": os.environ.get("PHP_WEBSHELL_URL", "http://localhost:8081/uploads/shell.php"),
        "ext": "php",
    },
    "aspx": {
        "url": os.environ.get("ASPX_WEBSHELL_URL", "http://localhost:8082/uploads/shell.aspx"),
        "ext": "aspx",
    },
    "jsp": {
        "url": os.environ.get("JSP_WEBSHELL_URL", "http://localhost:8083/uploads/shell.jsp"),
        "ext": "jsp",
    },
    "go": {
        "url": os.environ.get("GO_WEBSHELL_URL", "http://localhost:8084/plugins/shell.go"),
        "ext": "go",
    },
}

TEST_PASSWORD = "test_password_12345"
TEST_AES_KEY = base64.b64encode(b"0123456789abcdef0123456789abcdef").decode()
TEST_AUTH_VALUE = "test_auth_value_abc123"


def make_rpc(target_name: str) -> WebshellRPC:
    config = TARGET_CONFIGS[target_name]
    deformed = generate_deformed_alphabet(TEST_PASSWORD)
    return WebshellRPC(WebshellConfig(
        url=config["url"],
        auth_method="cookie",
        auth_name="PHPSESSID",
        auth_value=TEST_AUTH_VALUE,
        encoding="deformed_base64",
        deformed_alphabet=deformed,
        encryption="aes256_cbc",
        aes_key=TEST_AES_KEY,
        request_template="form_post",
        request_param_name="data",
        request_method="POST",
        verify_ssl=False,
        user_agent="Mozilla/5.0 AriadneTest/1.0",
        extra_headers={},
    ))


@pytest.fixture(params=["php"])
def target(request):
    return request.param


@pytest.fixture
def rpc(target):
    return make_rpc(target)


class TestCheckin:
    def test_checkin_returns_system_info(self, rpc):
        loop = asyncio.get_event_loop()
        success, task_id, result = loop.run_until_complete(
            rpc.send_command("checkin", "test-checkin-001")
        )
        assert success, f"Checkin failed: {result}"
        assert task_id == "test-checkin-001"
        assert len(result) > 0


class TestShell:
    def test_shell_whoami(self, rpc):
        loop = asyncio.get_event_loop()
        success, task_id, result = loop.run_until_complete(
            rpc.send_command("shell", "test-shell-001", "whoami")
        )
        assert success, f"Shell failed: {result}"
        assert len(result.strip()) > 0

    def test_shell_echo(self, rpc):
        loop = asyncio.get_event_loop()
        success, task_id, result = loop.run_until_complete(
            rpc.send_command("shell", "test-shell-002", "echo hello_ariadne")
        )
        assert success, f"Shell failed: {result}"
        assert "hello_ariadne" in result


class TestFilesystem:
    def test_pwd(self, rpc):
        loop = asyncio.get_event_loop()
        success, task_id, result = loop.run_until_complete(
            rpc.send_command("pwd", "test-pwd-001")
        )
        assert success, f"PWD failed: {result}"
        assert len(result.strip()) > 0

    def test_ls(self, rpc):
        loop = asyncio.get_event_loop()
        success, task_id, result = loop.run_until_complete(
            rpc.send_command("ls", "test-ls-001", "/tmp")
        )
        assert success, f"LS failed: {result}"
        data = json.loads(result)
        assert "files" in data
        assert "parent_path" in data

    def test_cd(self, rpc):
        loop = asyncio.get_event_loop()
        success, task_id, result = loop.run_until_complete(
            rpc.send_command("cd", "test-cd-001", "/tmp")
        )
        assert success, f"CD failed: {result}"
        assert "/tmp" in result or "tmp" in result.lower()

    def test_upload_download_rm(self, rpc):
        loop = asyncio.get_event_loop()
        test_content = base64.b64encode(b"Ariadne test file content").decode()
        test_path = "/tmp/ariadne_test_file.txt"

        success, _, result = loop.run_until_complete(
            rpc.send_command("upload", "test-upload-001", test_path, test_content)
        )
        assert success, f"Upload failed: {result}"

        success, _, result = loop.run_until_complete(
            rpc.send_command("download", "test-download-001", test_path)
        )
        assert success, f"Download failed: {result}"
        data = json.loads(result)
        assert data["filename"] == "ariadne_test_file.txt"
        downloaded = base64.b64decode(data["data"])
        assert downloaded == b"Ariadne test file content"

        success, _, result = loop.run_until_complete(
            rpc.send_command("rm", "test-rm-001", test_path)
        )
        assert success, f"RM failed: {result}"


class TestCamouflage:
    def test_unauthenticated_returns_camouflage(self, target):
        import requests as req
        config = TARGET_CONFIGS[target]
        resp = req.get(config["url"], timeout=10)
        assert resp.status_code in (404, 200, 403)


class TestEvasion:
    def test_deformed_base64_differs_from_standard(self):
        password = "unique_test_password"
        alphabet = generate_deformed_alphabet(password)
        standard = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        assert alphabet != standard

    def test_encode_decode_roundtrip(self):
        password = "roundtrip_test"
        alphabet = generate_deformed_alphabet(password)
        original = b"Hello, Ariadne! Test data for encoding roundtrip."
        encoded = encode_payload(original, "deformed_base64", alphabet)
        decoded = decode_payload(encoded, "deformed_base64", alphabet)
        assert decoded == original

    def test_encrypt_decrypt_roundtrip(self):
        key = base64.b64decode(TEST_AES_KEY)
        original = b"Secret message for encryption test"
        encrypted = encrypt_payload(original, key)
        decrypted = decrypt_payload(encrypted, key)
        assert decrypted == original
