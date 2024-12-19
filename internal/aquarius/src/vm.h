#include <array>
#include <cstdint>
#include <span>
#include <vector>

const size_t RAM_SIZE = 31337;

const int RIP = 17;
class VM {

  enum CmpCond {
    CMP_EQ = 0,
    CMP_NEQ = 1,
    CMP_ULT = 2,
    CMP_UGT = 3,
    CMP_ULEQ = 4,
    CMP_UGEQ = 5,
    CMP_SLT = 6,
    CMP_SGT = 7,
    CMP_SLEQ = 8,
    CMP_SGEQ = 9,
  };

  enum Opcodes {
    OP_NOP = 0,
    OP_ADD = 1,
    OP_SUB = 2,
    OP_MUL = 3,
    OP_DIV = 4,
    OP_MOD = 5,
    OP_XOR = 6,
    OP_AND = 7,
    OP_OR = 8,
    OP_RSH = 9,
    OP_LSH = 10,
    OP_MOV = 11,
    OP_NEG = 12,
    OP_INV = 13,
    OP_CMP = 14,
    OP_JMP = 15,
    OP_RJMP = 16,
    OP_LDR8 = 17,
    OP_LDR16 = 18,
    OP_LDR32 = 19,
    OP_LDR64 = 20,
    OP_STR8 = 21,
    OP_STR16 = 22,
    OP_STR32 = 23,
    OP_STR64 = 24,
    OP_SYSCALL = 25,
    OP_HLT = 26,
  };
  enum Syscalls {
    SYSCALL_READ = 0,
    SYSCALL_WRITE = 1,
  };
  std::array<uint64_t, 255> registers;
  std::vector<uint8_t> ram;
  std::vector<uint8_t> rom;

  bool halted = false;

  void execute_instruction();

  inline uint64_t &__attribute__((always_inline)) rip() {
    return registers[RIP];
  }
  inline uint64_t __attribute__((always_inline)) parse_arg();

  template <uint64_t op(uint64_t, uint64_t)>
  void __attribute__((always_inline)) instruction2args() {
    auto &receiver = registers[rom[rip()++]];
    auto arg = parse_arg();

    receiver = op(receiver, arg);
  }

  template <uint64_t op(uint64_t)>
  void __attribute__((always_inline)) instruction1arg() {
    auto &receiver = registers[rom[rip()++]];

    receiver = op(receiver);
  }

  inline uint8_t &__attribute__((always_inline)) get_ram_byte(uint64_t addr);
  inline uint8_t &__attribute__((always_inline)) get_rom_byte(uint64_t addr);

  template <int size> void __attribute__((always_inline)) str() {
    auto a = parse_arg();
    auto b = parse_arg();

    for (size_t i = 0; i < size; i++) {
      get_ram_byte(a + i) = (b >> (i * 8)) & 0xff;
    }
  }

  template <int size> void __attribute__((always_inline)) ldr() {
    auto &receiver = registers[rom[rip()++]];
    auto a = parse_arg();

    uint64_t res = 0;

    for (size_t i = 0; i < size; i++) {
      res |= ((uint64_t)get_ram_byte(a + i)) << (i * 8);
    }
    receiver = res;
  }

  inline void __attribute__((always_inline)) jmp();

  inline void __attribute__((always_inline)) rjmp();

  inline void __attribute__((always_inline)) cmp();
  inline void __attribute__((always_inline)) syscall();
  inline void __attribute__((always_inline)) read_syscall();
  inline void __attribute__((always_inline)) write_syscall();

public:
  VM(std::span<uint8_t> rom) : rom(rom.begin(), rom.end()), ram(RAM_SIZE, 0) {
    for (size_t i = 0; i < 255; i++) {
      registers[i] = 0;
    }
  }

  void run() {
    while (!halted) {
      execute_instruction();
    }
  }
};
