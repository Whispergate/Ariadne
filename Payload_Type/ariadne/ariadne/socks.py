import asyncio
import struct
import uuid
import logging
from typing import Optional

from .webshell_rpc import WebshellRPC

logger = logging.getLogger("ariadne.socks")

SOCKS5_VERSION = 0x05
SOCKS5_AUTH_NONE = 0x00
SOCKS5_CMD_CONNECT = 0x01
SOCKS5_ATYP_IPV4 = 0x01
SOCKS5_ATYP_DOMAIN = 0x03
SOCKS5_ATYP_IPV6 = 0x04
SOCKS5_REP_SUCCESS = 0x00
SOCKS5_REP_FAILURE = 0x01
SOCKS5_REP_NOT_ALLOWED = 0x02


class TunnelSession:
    """Manages a single SOCKS connection proxied through the webshell."""

    def __init__(
        self,
        mark: str,
        rpc: WebshellRPC,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        read_interval: float = 0.1,
        max_read_size: int = 524288,
    ):
        self.mark = mark
        self.rpc = rpc
        self.reader = reader
        self.writer = writer
        self.read_interval = read_interval
        self.max_read_size = max_read_size
        self._running = False
        self._reader_task: Optional[asyncio.Task] = None
        self._writer_task: Optional[asyncio.Task] = None

    async def start(self, target_ip: str, target_port: int) -> bool:
        """Connect to the target through the webshell tunnel."""
        import base64

        connect_data = base64.b64encode(
            f"{target_ip}:{target_port}".encode()
        ).decode()

        success, _ = await self.rpc.send_tunnel_command(
            self.mark, "CONNECT", connect_data
        )

        if not success:
            logger.error(f"Tunnel CONNECT failed for {self.mark}")
            return False

        self._running = True
        self._reader_task = asyncio.create_task(self._read_loop())
        self._writer_task = asyncio.create_task(self._write_loop())
        return True

    async def stop(self):
        """Disconnect the tunnel session."""
        self._running = False

        if self._reader_task and not self._reader_task.done():
            self._reader_task.cancel()
        if self._writer_task and not self._writer_task.done():
            self._writer_task.cancel()

        try:
            await self.rpc.send_tunnel_command(self.mark, "DISCONNECT")
        except Exception:
            pass

        try:
            self.writer.close()
            await self.writer.wait_closed()
        except Exception:
            pass

    async def _read_loop(self):
        """Poll the webshell for data from the tunneled connection."""
        import base64

        while self._running:
            try:
                success, data = await self.rpc.send_tunnel_command(
                    self.mark, "READ"
                )

                if success and data:
                    raw = base64.b64decode(data)
                    if raw:
                        self.writer.write(raw)
                        await self.writer.drain()

                await asyncio.sleep(self.read_interval)

            except asyncio.CancelledError:
                break
            except ConnectionError:
                self._running = False
                break
            except Exception as e:
                logger.error(f"Tunnel read error [{self.mark}]: {e}")
                await asyncio.sleep(self.read_interval)

    async def _write_loop(self):
        """Forward data from the SOCKS client to the webshell tunnel."""
        import base64

        while self._running:
            try:
                data = await asyncio.wait_for(
                    self.reader.read(self.max_read_size),
                    timeout=1.0,
                )

                if not data:
                    self._running = False
                    break

                encoded = base64.b64encode(data).decode()
                await self.rpc.send_tunnel_command(
                    self.mark, "FORWARD", encoded
                )

            except asyncio.TimeoutError:
                continue
            except asyncio.CancelledError:
                break
            except ConnectionError:
                self._running = False
                break
            except Exception as e:
                logger.error(f"Tunnel write error [{self.mark}]: {e}")


class SocksServer:
    """SOCKS5 proxy server that tunnels connections through the webshell."""

    def __init__(
        self,
        rpc: WebshellRPC,
        host: str = "127.0.0.1",
        port: int = 1080,
        read_interval: float = 0.1,
        max_read_size: int = 524288,
    ):
        self.rpc = rpc
        self.host = host
        self.port = port
        self.read_interval = read_interval
        self.max_read_size = max_read_size
        self._server: Optional[asyncio.AbstractServer] = None
        self._sessions: dict[str, TunnelSession] = {}

    async def start(self):
        """Start the SOCKS5 server."""
        self._server = await asyncio.start_server(
            self._handle_client, self.host, self.port
        )
        logger.info(f"SOCKS5 proxy listening on {self.host}:{self.port}")

    async def stop(self):
        """Stop the SOCKS5 server and all tunnel sessions."""
        for session in list(self._sessions.values()):
            await session.stop()
        self._sessions.clear()

        if self._server:
            self._server.close()
            await self._server.wait_closed()
            self._server = None
        logger.info("SOCKS5 proxy stopped")

    async def _handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ):
        """Handle a new SOCKS5 client connection."""
        mark = uuid.uuid4().hex[:16]

        try:
            # SOCKS5 greeting
            header = await reader.readexactly(2)
            if header[0] != SOCKS5_VERSION:
                writer.close()
                return

            nmethods = header[1]
            methods = await reader.readexactly(nmethods)

            # Only support no-auth
            if SOCKS5_AUTH_NONE not in methods:
                writer.write(struct.pack("BB", SOCKS5_VERSION, 0xFF))
                await writer.drain()
                writer.close()
                return

            writer.write(struct.pack("BB", SOCKS5_VERSION, SOCKS5_AUTH_NONE))
            await writer.drain()

            # SOCKS5 request
            req_header = await reader.readexactly(4)
            ver, cmd, _, atyp = struct.unpack("BBBB", req_header)

            if cmd != SOCKS5_CMD_CONNECT:
                self._send_reply(writer, SOCKS5_REP_NOT_ALLOWED)
                writer.close()
                return

            # Parse target address
            if atyp == SOCKS5_ATYP_IPV4:
                addr_bytes = await reader.readexactly(4)
                target_ip = ".".join(str(b) for b in addr_bytes)
            elif atyp == SOCKS5_ATYP_DOMAIN:
                domain_len = (await reader.readexactly(1))[0]
                domain = (await reader.readexactly(domain_len)).decode()
                target_ip = domain
            elif atyp == SOCKS5_ATYP_IPV6:
                addr_bytes = await reader.readexactly(16)
                target_ip = ":".join(
                    f"{addr_bytes[i]:02x}{addr_bytes[i+1]:02x}"
                    for i in range(0, 16, 2)
                )
            else:
                self._send_reply(writer, SOCKS5_REP_FAILURE)
                writer.close()
                return

            port_bytes = await reader.readexactly(2)
            target_port = struct.unpack("!H", port_bytes)[0]

            # Create tunnel session
            session = TunnelSession(
                mark=mark,
                rpc=self.rpc,
                reader=reader,
                writer=writer,
                read_interval=self.read_interval,
                max_read_size=self.max_read_size,
            )

            success = await session.start(target_ip, target_port)

            if success:
                self._sessions[mark] = session
                self._send_reply(writer, SOCKS5_REP_SUCCESS)
                logger.info(f"Tunnel established: {mark} -> {target_ip}:{target_port}")
            else:
                self._send_reply(writer, SOCKS5_REP_FAILURE)
                writer.close()
                return

            # Wait for session to finish
            await asyncio.gather(
                session._reader_task, session._writer_task,
                return_exceptions=True,
            )

        except (asyncio.IncompleteReadError, ConnectionError):
            pass
        except Exception as e:
            logger.error(f"SOCKS handler error [{mark}]: {e}")
        finally:
            session = self._sessions.pop(mark, None)
            if session:
                await session.stop()

    def _send_reply(self, writer: asyncio.StreamWriter, rep: int):
        reply = struct.pack(
            "!BBBB4sH",
            SOCKS5_VERSION,
            rep,
            0x00,
            SOCKS5_ATYP_IPV4,
            b"\x00\x00\x00\x00",
            0,
        )
        writer.write(reply)
        asyncio.ensure_future(writer.drain())
