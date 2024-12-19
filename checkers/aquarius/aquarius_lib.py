from pwn import *
import base64
from typing import Optional, List, Tuple
from checklib import *

context.log_level = "CRITICAL"

PORT = 7117

DEFAULT_RECV_SIZE = 4096
TCP_CONNECTION_TIMEOUT = 5
TCP_OPERATIONS_TIMEOUT = 7


class CheckMachine:

    def __init__(self, checker: BaseChecker):
        self.c = checker
        self.port = PORT

    def connect(self) -> remote:
        io = remote(self.c.host, self.port, timeout=TCP_CONNECTION_TIMEOUT)
        io.settimeout(TCP_OPERATIONS_TIMEOUT)
        return io

    def exit(self, io: remote) -> None:
        io.sendlineafter(b"> ", b"3")

    def upload_vm(
        self,
        io: remote,
        rom: bytes,
        status: Status,
    ) -> str:
        io.sendlineafter(b"> ", b"1")
        io.sendlineafter(b"base64 encoded rom> ", base64.b64encode(rom))
        io.recvuntil(b"id: ")
        return io.recvline().strip().decode()

    def run_vm(self, io: remote, id: string, status: Status) -> Tuple[int, bytes]:
        io.sendlineafter(b"> ", b"2")
        io.sendlineafter(b"id> ", id.encode("ascii"))
