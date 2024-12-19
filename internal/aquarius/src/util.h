#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

inline uint8_t decode_base64_char(char c);
std::vector<uint8_t> base64_decode(const std::string_view base64);
std::string trim_whitespace(const std::string_view input);
std::vector<uint8_t> read_file(const std::string_view filename);
void write_file(const std::string_view filename,
                const std::span<uint8_t> &data);
std::string random_id(size_t size = 16);
bool is_valid_string(const std::string_view s);

const std::string ALPHABET =
    "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
