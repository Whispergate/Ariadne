from pathlib import Path

from mythic_container.C2ProfileBase import *


class AriadneC2(C2Profile):
    name = "ariadne_webshell"
    description = "P2P profile for linking to an Ariadne webshell through Starburst"
    author = "@Lavender-exe"
    is_p2p = True
    is_server_routed = False
    mythic_encrypts = False
    server_folder_path = Path(".") / "c2_code"
    server_binary_path = server_folder_path / "server.py"
    parameters = [
        C2ProfileParameter(
            name="webshell_url",
            parameter_type=ParameterType.String,
            description="URL where the webshell is deployed",
            default_value="https://example.com/uploads/shell.php",
            required=True,
        ),
        C2ProfileParameter(
            name="auth_method",
            parameter_type=ParameterType.ChooseOne,
            description="Authentication method for webshell access",
            default_value="cookie",
            choices=["cookie", "header", "parameter"],
        ),
        C2ProfileParameter(
            name="auth_name",
            parameter_type=ParameterType.String,
            description="Cookie, header, or parameter name used for authentication",
            default_value="session",
        ),
        C2ProfileParameter(
            name="auth_value",
            parameter_type=ParameterType.String,
            description="Authentication value to match",
            default_value="",
            required=False,
        ),
        C2ProfileParameter(
            name="aes_key",
            parameter_type=ParameterType.String,
            description="Base64-encoded AES-256 key (empty for no encryption)",
            default_value="",
            required=False,
        ),
        C2ProfileParameter(
            name="param_name",
            parameter_type=ParameterType.String,
            description="POST parameter name for form data",
            default_value="data",
        ),
    ]

    async def config_check(self, inputMsg: C2ConfigCheckMessage) -> C2ConfigCheckMessageResponse:
        return C2ConfigCheckMessageResponse(Success=True, Message="Success")

    async def redirect_rules(self, inputMsg: C2GetRedirectorRulesMessage) -> C2GetRedirectorRulesMessageResponse:
        return C2GetRedirectorRulesMessageResponse(Success=True, Message="#Not Implemented")

    async def host_file(self, inputMsg: C2HostFileMessage) -> C2HostFileMessageResponse:
        return C2HostFileMessageResponse(Success=False, Error="Can't host files through a P2P profile")
