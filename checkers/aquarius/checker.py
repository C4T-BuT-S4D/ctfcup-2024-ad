#!/usr/bin/env python3

import sys
import time
import copy

from checklib import *

argv = copy.deepcopy(sys.argv)

from pwn import *
from aquarius_lib import *
import aquarius_assembler as asm


def machine_with_known_output(output: bytes) -> bytes:
    code = b""
    for i, c in enumerate(output):
        code += asm.str8(i, c)

    code += asm.mov("r0", asm.SYSCALL_WRITE)
    code += asm.mov("r1", 0)
    code += asm.mov("r2", len(output))
    code += asm.syscall()
    return code


def machine_with_password(output: bytes, password: bytes) -> bytes:
    password_promt = machine_with_known_output(b"password: ")
    wrong_password = machine_with_known_output(b"wrong password\n") + asm.hlt()
    output_data = machine_with_known_output(output) + asm.hlt()
    code = b""
    code += password_promt
    code += asm.mov("r0", asm.SYSCALL_READ)
    code += asm.mov("r1", 0)
    code += asm.mov("r2", len(password))
    code += asm.syscall()
    code += asm.mov("r1", 1)
    for i, c in enumerate(password):
        code += asm.ldr8("r3", i)
        code += asm.cmp("r2", asm.CMP_EQ, "r3", c)
        code += asm.band("r1", "r2")
    code += asm.rjmp("r1", len(wrong_password))
    code += wrong_password
    code += output_data
    return code


class Checker(BaseChecker):
    vulns: int = 1
    timeout: int = 5
    uses_attack_data: bool = True

    def __init__(self, *args, **kwargs):
        super(Checker, self).__init__(*args, **kwargs)
        self.mch = CheckMachine(self)

    def action(self, action, *args, **kwargs):
        try:
            super(Checker, self).action(action, *args, **kwargs)
        except (pwnlib.exception.PwnlibException, EOFError):
            self.cquit(Status.DOWN, "got connect error", "got pwntools connect error")
        except UnicodeDecodeError:
            self.cquit(Status.MUMBLE, "got unicode error", "got unicode error")

    def check(self):
        with self.mch.connect() as io:
            output = rnd_string(32).encode()
            rom = machine_with_known_output(output + b"\n") + asm.hlt()
            machine_id = self.mch.upload_vm(io, rom, Status.MUMBLE)
            self.mch.run_vm(io, machine_id, Status.MUMBLE)
            res = io.recvline()
            # raise ValueError(rom)
            self.assert_eq(
                res.strip(), output, f"invalid flag on {rom}", Status.CORRUPT
            )
            self.cquit(Status.OK)

        self.cquit(Status.OK)

    def put(self, flag_id: str, flag: str, vuln: str):
        with self.mch.connect() as io:
            password = rnd_string(32)
            rom = machine_with_password(flag.encode() + b"\n", password.encode())
            machine_id = self.mch.upload_vm(io, rom, Status.MUMBLE)
            self.mch.exit(io)
            self.cquit(Status.OK, f"{machine_id}", f"{machine_id}:{password}")

    def get(self, flag_id: str, flag: str, vuln: str):
        machine_id, password = flag_id.split(":")
        with self.mch.connect() as io:
            self.mch.run_vm(io, machine_id, Status.CORRUPT)
            io.recvuntil(b"password: ")
            io.send(password)
            res = io.recvline()
            self.assert_eq(res.strip(), flag.encode(), "invalid flag", Status.CORRUPT)
            self.cquit(Status.OK)


if __name__ == "__main__":
    # import base64
    #
    # print(base64.b64encode(machine_with_password(b"kek", b"lol")))
    # print(asm.cmp("r2", asm.CMP_EQ, "r3", 1337))
    # exit(0)
    c = Checker(argv[2])

    try:
        c.action(argv[1], *argv[3:])
    except c.get_check_finished_exception():
        cquit(Status(c.status), c.public, c.private)
