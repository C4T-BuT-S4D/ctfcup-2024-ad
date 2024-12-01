#include "crypter.h"
#include "crypto.h"
#include "util.h"
#include <grpcpp/support/status.h>

::grpc::Status
CrypterService::Register(::grpc::ServerContext *context,
                         const ::crypter::RegisterRequest *request,
                         ::crypter::RegisterResponse *response) {
  try {
    auto tx = cp::tx(pool);
    auto &work = tx.get();

    auto q = work.exec("select id from users where username=$1",
                       pqxx::params{request->username()});

    if (!q.empty()) {
      return ::grpc::Status(grpc::StatusCode::ALREADY_EXISTS,
                            "username already exists");
    }

    mpz_class P = random_prime(32);
    mpz_class Q = random_prime(32);
    mpz_class N = P * Q;
    mpz_class lambda = (P - 1) * (Q - 1);
    auto id = random_id();
    auto token = random_id();

    work.exec(
        "insert into users (id, username, token, n) values ($1, $2, $3, $4)",
        pqxx::params{id, request->username(), token, N.get_str()});
    work.commit();

    response->set_n(N.get_str());
    response->set_lamba(lambda.get_str());
    response->set_token(token);

    return ::grpc::Status::OK;
  } catch (const std::exception &ex) {
    std::cerr << "Got exception: " << ex.what() << std::endl;

    return ::grpc::Status(grpc::StatusCode::INTERNAL, ex.what());
  }
}

::grpc::Status CrypterService::GetUserPublicKey(
    ::grpc::ServerContext *context,
    const ::crypter::GetUserPublicKeyRequest *request,
    ::crypter::GetUserPublicKeyResponse *response) {
  try {
    auto tx = cp::tx(pool);
    auto &work = tx.get();
    auto q = work.exec("select n from users where username=$1",
                       pqxx::params{request->username()});

    if (q.empty()) {
      return ::grpc::Status(grpc::StatusCode::UNAVAILABLE,
                            "user does not exist");
    }
    auto n_string = q[0][0].get<std::string>().value_or("0");

    response->set_n(n_string);
    return ::grpc::Status::OK;
  } catch (const std::exception &ex) {
    std::cerr << "Got exception: " << ex.what() << std::endl;

    return ::grpc::Status(grpc::StatusCode::INTERNAL, ex.what());
  }
}
