from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class LinkArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="action",
                type=ParameterType.ChooseOne,
                choices=["start", "stop"],
                description="Start or stop a P2P listener",
            ),
            CommandParameter(
                name="type",
                type=ParameterType.ChooseOne,
                choices=["http", "smb", "tcp"],
                description="P2P transport type",
            ),
            CommandParameter(
                name="address",
                type=ParameterType.String,
                description="Address to connect to (for outbound links)",
                default_value="",
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
                    self.add_arg("type", parts[1])
                if len(parts) >= 3:
                    self.add_arg("address", parts[2])


class LinkCommand(CommandBase):
    cmd = "link"
    needs_admin = False
    help_cmd = "link [start|stop] [http|smb|tcp] [address]"
    description = "Manage P2P agent links (HTTP, SMB named pipe, or TCP socket)."
    version = 1
    supported_ui_features = []
    author = "@Lavender-exe"
    attackmapping = ["T1572"]
    argument_class = LinkArguments
    attributes = CommandAttributes(builtin=False)

    async def create_go_tasking(
        self, taskData: MythicCommandBase.PTTaskMessageAllData
    ) -> MythicCommandBase.PTTaskCreateTaskingMessageResponse:
        response = MythicCommandBase.PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        action = taskData.args.get_arg("action")
        link_type = taskData.args.get_arg("type")
        address = taskData.args.get_arg("address")
        display = f"{action} {link_type}"
        if address:
            display += f" -> {address}"
        response.DisplayParams = display
        return response

    async def process_response(
        self, task: PTTaskMessageAllData, response: any
    ) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(
            TaskID=task.Task.ID, Success=True
        )
        return resp
