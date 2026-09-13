import json
import base64
import logging

from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *

logger = logging.getLogger("ariadne.download")


class DownloadArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="file",
                type=ParameterType.String,
                description="Full path of the file to download from the target",
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            try:
                self.load_args_from_json_string(self.command_line)
            except Exception:
                self.add_arg("file", self.command_line.strip())


class DownloadCommand(CommandBase):
    cmd = "download"
    needs_admin = False
    help_cmd = "download [file_path]"
    description = "Download a file from the target system."
    version = 1
    supported_ui_features = ["file_browser:download"]
    author = "@Lavender-exe"
    attackmapping = ["T1005"]
    argument_class = DownloadArguments
    attributes = CommandAttributes(builtin=False)
    browser_script = BrowserScript(
        script_name="download", author="@Lavender-exe", for_new_ui=True
    )

    async def create_go_tasking(
        self, taskData: MythicCommandBase.PTTaskMessageAllData
    ) -> MythicCommandBase.PTTaskCreateTaskingMessageResponse:
        response = MythicCommandBase.PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        response.DisplayParams = taskData.args.get_arg("file")
        return response

    async def process_response(
        self, task: PTTaskMessageAllData, response: any
    ) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(
            TaskID=task.Task.ID, Success=True
        )

        try:
            raw = response if isinstance(response, str) else str(response)
            dl_info = json.loads(raw)

            if "data" not in dl_info:
                return resp

            file_data = base64.b64decode(dl_info["data"])
            file_resp = await SendMythicRPCFileCreate(
                MythicRPCFileCreateMessage(
                    TaskID=task.Task.ID,
                    FileContents=file_data,
                    Filename=dl_info.get("filename", "download"),
                    DeleteAfterFetch=False,
                    IsDownloadFromAgent=True,
                    IsScreenshot=False,
                )
            )

            if file_resp.Success:
                resp_data = json.dumps({
                    "agent_file_id": file_resp.AgentFileId,
                    "filename": dl_info.get("filename", ""),
                    "filepath": dl_info.get("filepath", ""),
                    "size": len(file_data),
                })
                await SendMythicRPCResponseCreate(
                    MythicRPCResponseCreateMessage(
                        TaskID=task.Task.ID,
                        Response=resp_data.encode("utf-8"),
                    )
                )
            else:
                logger.error(f"File registration failed: {file_resp.Error}")
        except (json.JSONDecodeError, KeyError):
            pass
        except Exception as e:
            logger.error(f"Download process_response failed: {e}")

        return resp
