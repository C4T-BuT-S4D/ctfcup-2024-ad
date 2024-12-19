#include "crypto.h"
#include <cstdint>
#include <gmp.h>
#include <gmpxx.h>
#include <random>

mpz_class random_integer(size_t words) {
  std::random_device device;
  uint8_t seed = device();
  std::default_random_engine r(seed);
  std::uniform_int_distribution<uint64_t> dist(0, 4294967296llu - 1llu);

  mpz_class res = 0;

  for (int i = 0; i < words; i++) {
    res <<= 32;
    res |= dist(r);
  }

  return res;
}

mpz_class random_prime(size_t words) {
  mpz_class res;
  mpz_nextprime(res.get_mpz_t(), random_integer(words).get_mpz_t());
  return res;
}

mpz_class encrypt(std::string message, mpz_class n) {
  std::vector<char> message_bytes(message.begin(), message.end());
  mpz_class m = 0;
  mpz_import(m.get_mpz_t(), message_bytes.size(), 1, 1, 0, 0,
             message_bytes.data());
  mpz_class r = random_integer(32);
  mpz_class n2 = n * n;
  mpz_class n_plus_one = n + 1;

  mpz_class res1;
  mpz_powm(res1.get_mpz_t(), n_plus_one.get_mpz_t(), m.get_mpz_t(),
           n2.get_mpz_t());
  mpz_class res2;
  mpz_powm(res2.get_mpz_t(), r.get_mpz_t(), n.get_mpz_t(), n2.get_mpz_t());

  return res1 * res2;
}
