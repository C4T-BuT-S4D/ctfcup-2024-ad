#include "vm.h"
#include <iostream>
#include <stdexcept>
#include <unistd.h>

uint8_t &VM::get_ram_byte(uint64_t addr) {
  if (addr >= ram.size()) {
    throw std::runtime_error("out of bounds read/write");
  }
  return ram[addr];
}

uint8_t &VM::get_rom_byte(uint64_t addr) {
  if (addr >= rom.size()) {
    throw std::runtime_error("ran out of rom");
  }
  return rom[addr];
}

uint64_t VM::parse_arg() {

  uint64_t reg = get_rom_byte(rip()++);

  if (reg != 0xff) {
    return registers[reg];
  }

  uint64_t res = 0;
  for (size_t i = 0; i < 8; i++) {
    res |= ((uint64_t)get_rom_byte(rip()++)) << (i * 8);
  }

  return res;
}

void VM::jmp() {
  auto cond = parse_arg();
  auto target = parse_arg();
  if (cond != 0) {
    rip() = target;
  }
}

void VM::rjmp() {
  auto cond = parse_arg();
  auto target = int64_t(parse_arg());
  if (cond != 0) {
    rip() += target;
  }
}

void VM::cmp() {
  auto &receiver = registers[rom[rip()++]];

  auto type = rom[rip()++];
  auto a = parse_arg();
  auto b = parse_arg();

  switch (type) {
  case 0:
    receiver = a == b;
    break;
  case 1:
    receiver = a != b;
    break;
  case 2:
    receiver = a < b;
    break;
  case 3:
    receiver = a > b;
    break;
  case 4:
    receiver = a <= b;
    break;
  case 5:
    receiver = a >= b;
    break;
  case 6:
    receiver = int64_t(a) < int64_t(b);
    break;
  case 7:
    receiver = int64_t(a) > int64_t(b);
    break;
  case 8:
    receiver = int64_t(a) <= int64_t(b);
    break;
  case 9:
    receiver = int64_t(a) >= int64_t(b);
    break;
  }
}

void VM::syscall() {
  switch (registers[0]) {
  case SYSCALL_READ:
    read_syscall();
    break;
  case SYSCALL_WRITE:
    write_syscall();
    break;
  default:
    throw std::runtime_error("invalid syscall");
  }
}

void VM::read_syscall() {
  uint64_t addr = registers[1];
  uint64_t size = registers[2];

  if (addr >= ram.size() || addr + size > ram.size()) {
    throw std::runtime_error("invalid address");
  }

  registers[0] = read(0, ram.data() + addr, size);
}

void VM::write_syscall() {
  uint64_t addr = registers[1];
  uint64_t size = registers[2];

  if (addr >= ram.size() || addr + size > ram.size()) {
    throw std::runtime_error("invalid address");
  }

  registers[0] = write(1, ram.data() + addr, size);
}

void VM::execute_instruction() {
  /*std::cout << (int)rom[rip()] << std::endl;*/
  switch (rom[rip()++]) {
  case OP_NOP:
    break;
  case OP_ADD:
    instruction2args<(
        [](uint64_t a, uint64_t b) -> uint64_t { return a + b; })>();
    break;
  case OP_SUB:
    instruction2args<(
        [](uint64_t a, uint64_t b) -> uint64_t { return a - b; })>();
    break;
  case OP_MUL:
    instruction2args<(
        [](uint64_t a, uint64_t b) -> uint64_t { return a * b; })>();
    break;
  case OP_DIV:
    instruction2args<(
        [](uint64_t a, uint64_t b) -> uint64_t { return a / b; })>();
    break;
  case OP_MOD:
    instruction2args<(
        [](uint64_t a, uint64_t b) -> uint64_t { return a % b; })>();
    break;
  case OP_XOR:
    instruction2args<(
        [](uint64_t a, uint64_t b) -> uint64_t { return a ^ b; })>();
    break;
  case OP_AND:
    instruction2args<(
        [](uint64_t a, uint64_t b) -> uint64_t { return a & b; })>();
    break;
  case OP_OR:
    instruction2args<(
        [](uint64_t a, uint64_t b) -> uint64_t { return a | b; })>();
    break;
  case OP_RSH:
    instruction2args<(
        [](uint64_t a, uint64_t b) -> uint64_t { return a >> b; })>();
    break;
  case OP_LSH:
    instruction2args<(
        [](uint64_t a, uint64_t b) -> uint64_t { return a << b; })>();
    break;
  case OP_MOV:
    instruction2args<([](uint64_t a, uint64_t b) -> uint64_t { return b; })>();
    break;
  case OP_NEG:
    instruction1arg<([](uint64_t a) -> uint64_t { return -a; })>();
    break;
  case OP_INV:
    instruction1arg<([](uint64_t a) -> uint64_t { return ~a; })>();
    break;

  case OP_CMP:
    cmp();
    break;
  case OP_JMP:
    jmp();
    break;
  case OP_RJMP:
    rjmp();
    break;

  case OP_LDR8:
    ldr<1>();
    break;
  case OP_LDR16:
    ldr<2>();
    break;
  case OP_LDR32:
    ldr<4>();
    break;
  case OP_LDR64:
    ldr<8>();
    break;

  case OP_STR8:
    str<1>();
    break;
  case OP_STR16:
    str<2>();
    break;
  case OP_STR32:
    str<4>();
    break;
  case OP_STR64:
    str<8>();
    break;
  case OP_HLT:
    halted = true;
    break;
  case OP_SYSCALL:
    syscall();
    break;
  default:
    throw std::runtime_error("invalid opcode");
  }
}
