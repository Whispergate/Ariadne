import json
import os
import logging

from mythic_container.TranslationBase import *

logger = logging.getLogger("ariadne.translator")


class AriadneTranslator(TranslationContainer):
    name = "AriadneTranslator"
    description = "Translates between Ariadne wire protocol and Mythic JSON"
    author = "@Lavender-exe"

    async def generate_keys(
        self, inputMsg: TrGenerateEncryptionKeysMessage
    ) -> TrGenerateEncryptionKeysMessageResponse:
        response = TrGenerateEncryptionKeysMessageResponse(Success=True)
        if inputMsg.CryptoParamValue == "aes256_hmac":
            key = os.urandom(32)
            response.EncryptionKey = key
            response.DecryptionKey = key
        else:
            response.EncryptionKey = b""
            response.DecryptionKey = b""
        return response

    async def translate_to_c2_format(
        self, inputMsg: TrMythicC2ToCustomMessageFormatMessage
    ) -> TrMythicC2ToCustomMessageFormatMessageResponse:
        response = TrMythicC2ToCustomMessageFormatMessageResponse(Success=True)
        try:
            raw_msg = inputMsg.Message
            if isinstance(raw_msg, dict):
                mythic_msg = raw_msg
            elif isinstance(raw_msg, (str, bytes, bytearray)):
                mythic_msg = json.loads(raw_msg)
            else:
                mythic_msg = json.loads(str(raw_msg))
            action = mythic_msg.get("action", "")

            if action == "checkin":
                pipe_parts = [
                    "checkin",
                    mythic_msg.get("uuid", ""),
                ]
                response.Message = "|".join(pipe_parts).encode("utf-8")
            elif action == "get_tasking":
                tasks = mythic_msg.get("tasks", [])
                if tasks:
                    task = tasks[0]
                    pipe_msg = self._task_to_pipe(task)
                    response.Message = pipe_msg.encode("utf-8")
                else:
                    response.Message = b""
            elif action == "post_response":
                response.Message = b""
            else:
                if "command" in mythic_msg and "id" in mythic_msg:
                    pipe_msg = self._task_to_pipe(mythic_msg)
                    response.Message = pipe_msg.encode("utf-8")
                elif isinstance(inputMsg.Message, dict):
                    response.Message = json.dumps(inputMsg.Message).encode("utf-8")
                else:
                    response.Message = inputMsg.Message
        except Exception as e:
            logger.exception("translate_to_c2_format failed")
            response.Success = False
            response.Error = str(e)
        return response

    def _task_to_pipe(self, task: dict) -> str:
        command = task.get("command", "")
        task_id = task.get("id", "")
        params = task.get("parameters", "")
        if isinstance(params, str) and params:
            try:
                params = json.loads(params)
            except (json.JSONDecodeError, ValueError):
                pass

        if command == "shell":
            cmd = params.get("command", str(params)) if isinstance(params, dict) else str(params)
            return f"shell|{task_id}|{cmd}"
        elif command == "ls":
            path = params.get("path", ".") if isinstance(params, dict) else "."
            return f"ls|{task_id}|{path}"
        elif command == "cd":
            path = params.get("path", ".") if isinstance(params, dict) else "."
            return f"cd|{task_id}|{path}"
        elif command == "pwd":
            return f"pwd|{task_id}"
        elif command == "download":
            fpath = params.get("file", params.get("path", "")) if isinstance(params, dict) else str(params)
            return f"download|{task_id}|{fpath}"
        elif command == "upload":
            if isinstance(params, dict):
                rpath = params.get("remote_path", "")
                data = params.get("file", "")
                return f"upload|{task_id}|{rpath}|{data}"
            return f"upload|{task_id}|{params}"
        elif command == "rm":
            path = params.get("path", params.get("file", "")) if isinstance(params, dict) else str(params)
            return f"rm|{task_id}|{path}"
        elif command == "execute_assembly":
            if isinstance(params, dict):
                assembly_data = params.get("file", "")
                arguments = params.get("arguments", "")
                return f"execute_assembly|{task_id}|{assembly_data}|{arguments}"
            return f"execute_assembly|{task_id}|{params}"
        elif command == "cat":
            fpath = params.get("file", "") if isinstance(params, dict) else str(params)
            return f"cat|{task_id}|{fpath}"
        elif command == "mkdir":
            path = params.get("path", "") if isinstance(params, dict) else str(params)
            return f"mkdir|{task_id}|{path}"
        elif command == "cp":
            if isinstance(params, dict):
                src = params.get("source", "")
                dst = params.get("destination", "")
                return f"cp|{task_id}|{src}|{dst}"
            return f"cp|{task_id}|{params}"
        elif command == "mv":
            if isinstance(params, dict):
                src = params.get("source", "")
                dst = params.get("destination", "")
                return f"mv|{task_id}|{src}|{dst}"
            return f"mv|{task_id}|{params}"
        elif command == "env":
            return f"env|{task_id}"
        elif command == "whoami":
            return f"whoami|{task_id}"
        elif command == "ps":
            return f"ps|{task_id}"
        else:
            if isinstance(params, dict):
                args = "|".join(str(v) for v in params.values())
                return f"{command}|{task_id}|{args}"
            return f"{command}|{task_id}|{params}"

    async def translate_from_c2_format(
        self, inputMsg: TrCustomMessageToMythicC2FormatMessage
    ) -> TrCustomMessageToMythicC2FormatMessageResponse:
        response = TrCustomMessageToMythicC2FormatMessageResponse(Success=True)
        try:
            raw = inputMsg.Message
            if isinstance(raw, bytes):
                raw = raw.decode("utf-8")

            if isinstance(raw, str) and "|" in raw:
                parts = raw.split("|")
                action = parts[0] if parts else ""

                if action == "checkin" and len(parts) >= 8:
                    checkin_data = {
                        "action": "checkin",
                        "uuid": parts[1],
                        "ips": [],
                        "os": parts[3],
                        "user": parts[4],
                        "host": parts[2],
                        "domain": parts[5],
                        "pid": int(parts[6]) if parts[6].isdigit() else 0,
                        "architecture": parts[7],
                        "process_name": "webshell",
                    }
                    response.Message = checkin_data
                elif action in ("0", "1") and len(parts) >= 3:
                    task_id = parts[1]
                    if not task_id:
                        response.Message = {"action": "get_tasking", "tasking_size": -1}
                    else:
                        status = "success" if parts[0] == "0" else "error"
                        result = "|".join(parts[2:])
                        response.Message = {
                            "action": "post_response",
                            "responses": [
                                {
                                    "task_id": task_id,
                                    "user_output": result,
                                    "completed": True,
                                    "status": status,
                                }
                            ],
                        }
                else:
                    response.Message = {"action": "get_tasking", "tasking_size": -1}
            else:
                response.Message = {"action": "get_tasking", "tasking_size": -1}
        except Exception as e:
            logger.exception("translate_from_c2_format failed")
            response.Success = False
            response.Error = str(e)
        return response
