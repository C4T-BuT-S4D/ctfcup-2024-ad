#include <gmpxx.h>

mpz_class random_integer(size_t words);
mpz_class random_prime(size_t words);
mpz_class encrypt(std::string message, mpz_class n);
