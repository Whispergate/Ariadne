from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class CpArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="source",
                type=ParameterType.String,
                description="Source file or directory path",
            ),
            CommandParameter(
                name="destination",
                type=ParameterType.String,
                description="Destination file or directory path",
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            try:
                self.load_args_from_json_string(self.command_line)
            except Exception:
                parts = self.command_line.strip().split(" ", 1)
                if len(parts) == 2:
                    self.add_arg("source", parts[0])
                    self.add_arg("destination", parts[1])
                else:
                    self.add_arg("source", self.command_line.strip())
                    self.add_arg("destination", "")


class CpCommand(CommandBase):
    cmd = "cp"
    needs_admin = False
    help_cmd = "cp [source] [destination]"
    description = "Copy a file or directory."
    version = 1
    supported_ui_features = []
    author = "@Lavender-exe"
    attackmapping = ["T1570"]
    argument_class = CpArguments
    attributes = CommandAttributes(builtin=False)

    async def create_go_tasking(
        self, taskData: MythicCommandBase.PTTaskMessageAllData
    ) -> MythicCommandBase.PTTaskCreateTaskingMessageResponse:
        response = MythicCommandBase.PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        source = taskData.args.get_arg("source")
        destination = taskData.args.get_arg("destination")
        response.DisplayParams = f"{source} -> {destination}"
        return response

    async def process_response(
        self, task: PTTaskMessageAllData, response: any
    ) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(
            TaskID=task.Task.ID, Success=True
        )
        return resp
