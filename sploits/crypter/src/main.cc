#pragma GCC optimize(                                                          \
    "O3,Ofast,no-stack-protector,rename-registers,unroll-all-loops,inline-functions,sched-spec")
#pragma GCC target("tune=native")
#include <gmp.h>
#include <gmpxx.h>
#include <grpc++/grpc++.h>
#include <iostream>
#include <proto/crypter.grpc.pb.h>
#include <proto/crypter.pb.h>

mpz_class seeded_integer(size_t words, uint32_t seed) {
  std::default_random_engine r(seed);
  std::uniform_int_distribution<uint64_t> dist(0, 4294967296llu - 1llu);

  mpz_class res = 0;

  for (int i = 0; i < words; i++) {
    res <<= 32;
    res |= dist(r);
  }

  return res;
}

int main(int argc, char *argv[]) {
  if (argc != 3) {
    std::cerr << "usage: " << argv[0] << " [host] [hint]" << std::endl;
    return 1;
  }

  auto stub = crypter::Crypter::NewStub(grpc::CreateChannel(
      std::string(argv[1]) + ":2112", grpc::InsecureChannelCredentials()));

  grpc::ClientContext ctx1;

  ::crypter::GetMessageRequest get_message_req;
  ::crypter::GetMessageResponse get_message_resp;
  get_message_req.set_id(argv[2]);
  stub->GetMessage(&ctx1, get_message_req, &get_message_resp);

  ::crypter::GetUserPublicKeyRequest public_key_req;
  ::crypter::GetUserPublicKeyResponse public_key_resp;
  public_key_req.set_username(get_message_resp.username());
  grpc::ClientContext ctx2;
  stub->GetUserPublicKey(&ctx2, public_key_req, &public_key_resp);

  mpz_class n(public_key_resp.n());
  mpz_class n2 = n * n;
  mpz_class e(get_message_resp.encrypted());
  mpz_class rn;
  mpz_class q;
  mpz_class rem;
  mpz_class rn_inv;
  mpz_class r;
  for (uint64_t i = 0; i < 256; i++) {
    std::cout << i << std::endl;
    r = seeded_integer(32, i);
    mpz_powm(rn.get_mpz_t(), r.get_mpz_t(), n.get_mpz_t(), n2.get_mpz_t());
    mpz_invert(rn_inv.get_mpz_t(), rn.get_mpz_t(), n2.get_mpz_t());
    mpz_class to_divide = (e * rn_inv) % n2 - 1;
    mpz_divmod(q.get_mpz_t(), rem.get_mpz_t(), to_divide.get_mpz_t(),
               n.get_mpz_t());

    if (rem == 0) {
      std::vector<char> data(1024, 0);
      size_t size = 1024;
      mpz_export(data.data(), &size, 1, 1, 0, 0, q.get_mpz_t());

      std::string flag(data.begin(), data.begin() + size);
      std::cout << flag << std::endl;
      return 0;
    }
  }
}
