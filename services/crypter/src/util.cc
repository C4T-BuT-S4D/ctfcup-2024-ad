#include "util.h"
#include <random>

std::string random_id(size_t size) {
  std::random_device device;
  std::mt19937 r(device());
  std::uniform_int_distribution<int> dist(0, ALPHABET.size() - 1);

  std::string res = "";

  for (size_t i = 0; i < size; i++) {
    res += ALPHABET[dist(r)];
  }

  return res;
}
