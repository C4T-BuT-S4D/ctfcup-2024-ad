#include "util.h"
#include <fstream>
#include <iostream>
#include <random>
#include <stdexcept>

inline uint8_t decode_base64_char(char c) {
  if ('A' <= c && c <= 'Z')
    return c - 'A';
  if ('a' <= c && c <= 'z')
    return c - 'a' + 26;
  if ('0' <= c && c <= '9')
    return c - '0' + 52;
  if (c == '+')
    return 62;
  if (c == '/')
    return 63;
  throw std::invalid_argument("Invalid Base64 character");
}

std::vector<uint8_t> base64_decode(const std::string_view base64) {
  std::vector<uint8_t> result;
  size_t padding = 0;

  result.reserve(base64.size() * 3 / 4);

  uint64_t val = 0;
  uint64_t power = 0;
  for (auto base64_char : base64) {
    if (base64_char == '=') {
      break;
    }
    val = (val << 6) | decode_base64_char(base64_char);
    power += 6;
    if (power >= 8) {
      power -= 8;
      result.push_back((val >> power) & 0xff);
    }
  }

  return result;
}

std::string trim_whitespace(const std::string_view input) {
  std::string::size_type start = input.find_first_not_of(" \t\n\r\f\v");
  if (start == std::string::npos) {
    return "";
  }

  std::string::size_type end = input.find_last_not_of(" \t\n\r\f\v");

  return std::string(input.substr(start, end - start + 1));
}

std::vector<uint8_t> read_file(const std::string_view filename) {
  std::ifstream file(std::string(filename), std::ios::binary | std::ios::ate);
  if (!file.is_open()) {
    throw std::runtime_error("Could not open file");
  }

  std::streamsize size = file.tellg();
  if (size < 0) {
    throw std::runtime_error("Error obtaining file size");
  }

  std::vector<uint8_t> buffer(size);

  file.seekg(0, std::ios::beg);

  if (!file.read(reinterpret_cast<char *>(buffer.data()), size)) {
    throw std::runtime_error("Error reading file");
  }

  return buffer;
}

void write_file(const std::string_view filename,
                const std::span<uint8_t> &data) {
  std::ofstream file(std::string(filename), std::ios::binary);
  if (!file.is_open()) {
    throw std::runtime_error("Could not open file for writing");
  }

  file.write(reinterpret_cast<const char *>(data.data()), data.size());
}

std::string random_id(size_t size) {
  std::random_device rd;
  std::seed_seq seed{rd(), rd(), rd(), rd(), rd(), rd(), rd(), rd()};
  std::mt19937 g(seed);
  std::uniform_int_distribution<int> dist(0, ALPHABET.size() - 1);

  std::string res = "";

  for (size_t i = 0; i < size; i++) {
    res += ALPHABET[dist(g)];
  }

  return res;
}

bool is_valid_string(const std::string_view s) {
  for (char c : s) {
    if (!std::isalnum(static_cast<unsigned char>(c))) {
      return false;
    }
  }
  return true;
}
