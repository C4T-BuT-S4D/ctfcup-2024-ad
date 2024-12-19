#include "util.h"
#include "vm.h"
#include <iostream>

void run_vm(std::span<uint8_t> rom) {
  VM vm(rom);
  vm.run();
}

int main() {

  while (true) {
    std::cout << "### aquarius vm service ###" << std::endl;
    std::cout << "1: upload vm" << std::endl;
    std::cout << "2: run vm" << std::endl;
    std::cout << "3: exit" << std::endl;
    std::cout << "> ";
    std::cout.flush();
    int choice;
    std::cin >> choice;
    std::string base64_encoded_rom;
    std::vector<uint8_t> rom;
    std::string id;
    try {
      switch (choice) {
      case 1:
        std::cout << "base64 encoded rom> ";
        std::cout.flush();
        std::cin >> base64_encoded_rom;
        rom = base64_decode(trim_whitespace(base64_encoded_rom));
        id = random_id();
        write_file(std::format("machines/{}", id), rom);
        std::cout << "id: " << id << std::endl;
        break;
      case 2:
        std::cout << "id> ";
        std::cout.flush();
        std::cin >> id;
        if (!is_valid_string(id)) {
          std::cout << "invalid id" << std::endl;
          std::cout.flush();
          break;
        }
        rom = read_file(format("machines/{}", id));
        run_vm(rom);
        break;
      case 3:
        return 0;
      default:
        std::cout << "unknown option" << std::endl;
        break;
      }
    } catch (std::exception &e) {
      std::cout << std::format("got exception {}", e.what()) << std::endl;
    }
  }
}
