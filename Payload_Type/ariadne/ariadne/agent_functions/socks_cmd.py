from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class SocksArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="action",
                type=ParameterType.ChooseOne,
                choices=["start", "stop"],
                description="Start or stop the SOCKS5 proxy server",
            ),
            CommandParameter(
                name="port",
                type=ParameterType.Number,
                description="Local port for the SOCKS5 proxy server",
                default_value=1080,
                parameter_group_info=[
                    ParameterGroupInfo(required=False),
                ],
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            try:
                self.load_args_from_json_string(self.command_line)
            except Exception:
                parts = self.command_line.strip().split()
                if len(parts) >= 1:
                    self.add_arg("action", parts[0])
                if len(parts) >= 2:
                    self.add_arg("port", int(parts[1]))


class SocksCommand(CommandBase):
    cmd = "socks"
    needs_admin = False
    help_cmd = "socks [start|stop] [port]"
    description = "Start or stop a local SOCKS5 proxy server that tunnels through the webshell."
    version = 1
    supported_ui_features = []
    author = "@Lavender-exe"
    attackmapping = ["T1572"]
    argument_class = SocksArguments
    attributes = CommandAttributes(builtin=False)

    async def create_go_tasking(
        self, taskData: MythicCommandBase.PTTaskMessageAllData
    ) -> MythicCommandBase.PTTaskCreateTaskingMessageResponse:
        response = MythicCommandBase.PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        action = taskData.args.get_arg("action")
        port = taskData.args.get_arg("port")
        response.DisplayParams = f"{action} on port {port}"
        return response

    async def process_response(
        self, task: PTTaskMessageAllData, response: any
    ) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(
            TaskID=task.Task.ID, Success=True
        )
        return resp
