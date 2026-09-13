import base64

from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class UploadArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="file",
                type=ParameterType.File,
                description="File to upload to the target",
            ),
            CommandParameter(
                name="remote_path",
                type=ParameterType.String,
                description="Full destination path on the target (including filename)",
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            try:
                self.load_args_from_json_string(self.command_line)
            except Exception:
                raise ValueError("Upload requires JSON arguments with 'file' and 'remote_path'")


class UploadCommand(CommandBase):
    cmd = "upload"
    needs_admin = False
    help_cmd = "upload"
    description = "Upload a file to the target system."
    version = 1
    supported_ui_features = ["file_browser:upload"]
    author = "@Lavender-exe"
    attackmapping = ["T1105"]
    argument_class = UploadArguments
    attributes = CommandAttributes(builtin=False)

    async def create_go_tasking(
        self, taskData: MythicCommandBase.PTTaskMessageAllData
    ) -> MythicCommandBase.PTTaskCreateTaskingMessageResponse:
        response = MythicCommandBase.PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        file_id = taskData.args.get_arg("file")
        remote_path = taskData.args.get_arg("remote_path")
        response.DisplayParams = remote_path

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
