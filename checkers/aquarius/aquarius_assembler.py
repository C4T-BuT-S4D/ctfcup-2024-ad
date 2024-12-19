import struct

OP_NOP = 0
OP_ADD = 1
OP_SUB = 2
OP_MUL = 3
OP_DIV = 4
OP_MOD = 5
OP_XOR = 6
OP_AND = 7
OP_OR = 8
OP_RSH = 9
OP_LSH = 10
OP_MOV = 11
OP_NEG = 12
OP_INV = 13
OP_CMP = 14
OP_JMP = 15
OP_RJMP = 16
OP_LDR8 = 17
OP_LDR16 = 18
OP_LDR32 = 19
OP_LDR64 = 20
OP_STR8 = 21
OP_STR16 = 22
OP_STR32 = 23
OP_STR64 = 24
OP_SYSCALL = 25
OP_HLT = 26


CMP_EQ = 0
CMP_NEQ = 1
CMP_ULT = 2
CMP_UGT = 3
CMP_ULEQ = 4
CMP_UGEQ = 5
CMP_SLT = 6
CMP_SGT = 7
CMP_SLEQ = 8
CMP_SGEQ = 9

SYSCALL_READ = 0
SYSCALL_WRITE = 1


def parse_reg(reg):
    reg = int(reg[1:])
    assert 0 <= reg <= 255
    return bytes([reg])


def parse_value(val):
    if isinstance(val, str):
        return parse_reg(val)
    if isinstance(val, int):
        if val <= 0:
            return bytes([0xFF]) + struct.pack("q", val)
        return bytes([0xFF]) + struct.pack("Q", val)
    raise ValueError(f"unkown operand type {type(val)}")


def nop():
    return bytes([OP_NOP])


def add(r, arg):
    return bytes([OP_ADD]) + parse_reg(r) + parse_value(arg)


def sub(r, arg):
    return bytes([OP_SUB]) + parse_reg(r) + parse_value(arg)


def mul(r, arg):
    return bytes([OP_MUL]) + parse_reg(r) + parse_value(arg)


def div(r, arg):
    return bytes([OP_DIV]) + parse_reg(r) + parse_value(arg)


def mod(r, arg):
    return bytes([OP_MOD]) + parse_reg(r) + parse_value(arg)


def xor(r, arg):
    return bytes([OP_XOR]) + parse_reg(r) + parse_value(arg)


def band(r, arg):
    return bytes([OP_AND]) + parse_reg(r) + parse_value(arg)


def bor(r, arg):
    return bytes([OP_OR]) + parse_reg(r) + parse_value(arg)


def rsh(r, arg):
    return bytes([OP_RSH]) + parse_reg(r) + parse_value(arg)


def lsh(r, arg):
    return bytes([OP_LSH]) + parse_reg(r) + parse_value(arg)


def mov(r, arg):
    return bytes([OP_MOV]) + parse_reg(r) + parse_value(arg)


def neg(r):
    return bytes([OP_NEG]) + parse_reg(r)


def inv(r):
    return bytes([OP_INV]) + parse_reg(r)


def ldr8(r, arg):
    return bytes([OP_LDR8]) + parse_value(r) + parse_value(arg)


def ldr16(r, arg):
    return bytes([OP_LDR16]) + parse_value(r) + parse_value(arg)


def ldr32(r, arg):
    return bytes([OP_LDR32]) + parse_value(r) + parse_value(arg)


def ldr64(r, arg):
    return bytes([OP_LDR64]) + parse_value(r) + parse_value(arg)


def str8(r, arg):
    return bytes([OP_STR8]) + parse_value(r) + parse_value(arg)


def str16(r, arg):
    return bytes([OP_STR16]) + parse_value(r) + parse_value(arg)


def str32(r, arg):
    return bytes([OP_STR32]) + parse_value(r) + parse_value(arg)


def str64(r, arg):
    return bytes([OP_STR64]) + parse_value(r) + parse_value(arg)


def syscall():
    return bytes([OP_SYSCALL])


def hlt():
    return bytes([OP_HLT])


def cmp(r, tp, a, b):
    return (
        bytes([OP_CMP]) + parse_reg(r) + bytes([tp]) + parse_value(a) + parse_value(b)
    )


def jmp(cond, val):
    return bytes([OP_JMP]) + parse_value(cond) + parse_value(val)


def rjmp(cond, val):
    return bytes([OP_RJMP]) + parse_value(cond) + parse_value(val)
