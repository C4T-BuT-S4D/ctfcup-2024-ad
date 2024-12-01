#include "crypter.h"
#include "crypto.h"
#include "util.h"

#include <grpcpp/support/status.h>
#include <iostream>

#include <exception>
#include <stdexcept>
#include <typeinfo>

::grpc::Status
CrypterService::SendMessage(::grpc::ServerContext *context,
                            const ::crypter::SendMessageRequest *request,
                            ::crypter::SendMessageResponse *response) {

  try {
    auto tx = cp::tx(pool);
    auto &work = tx.get();
    auto q_token = work.exec("select username from users where token=$1",
                             pqxx::params{request->token()});

    if (q_token.empty()) {
      return ::grpc::Status(grpc::StatusCode::UNAUTHENTICATED, "invalid token");
    }
    auto from = q_token[0][0].get<std::string>().value_or("kek");

    auto q_n = work.exec("select n from users where username=$1",
                         pqxx::params{request->username()});

    if (q_n.empty()) {
      return ::grpc::Status(grpc::StatusCode::UNAVAILABLE,
                            "user does not exist");
    }
    auto n_string = q_n[0][0].get<std::string>().value_or("0");

    mpz_class n(n_string);

    auto encrypted = encrypt(request->message(), n);

    auto id = random_id();
    work.exec("insert into messages (id, username, from_username, encrypted) "
              "values ($1, $2, $3, $4)",
              pqxx::params{id, request->username(), from, encrypted.get_str()});
    work.commit();
    response->set_id(id);

    return grpc::Status::OK;
  } catch (const std::exception &ex) {
    std::cerr << "Got exception: " << ex.what() << std::endl;

    return ::grpc::Status(grpc::StatusCode::INTERNAL, ex.what());
  }
}

::grpc::Status
CrypterService::ListMessages(::grpc::ServerContext *context,
                             const ::crypter::ListMessagesRequest *request,
                             ::crypter::ListMessagesResponse *response) {
  try {
    auto tx = cp::tx(pool);
    auto &work = tx.get();
    auto q_token = work.exec("select username from users where token=$1",
                             pqxx::params{request->token()});
    if (q_token.empty()) {
      return ::grpc::Status(grpc::StatusCode::UNAUTHENTICATED, "invalid token");
    }
    auto username = q_token[0][0].get<std::string>().value_or("kek");

    auto q = work.exec("select id from messages where username=$1",
                       pqxx::params{username});

    for (auto m : q) {
      auto id = q[0][0].get<std::string>().value_or("kek");
      response->add_id(id);
    }

    return ::grpc::Status::OK;
  } catch (const std::exception &ex) {
    std::cerr << "Got exception: " << ex.what() << std::endl;

    return ::grpc::Status(grpc::StatusCode::INTERNAL, ex.what());
  }
}

::grpc::Status
CrypterService::GetMessage(::grpc::ServerContext *context,
                           const ::crypter::GetMessageRequest *request,
                           ::crypter::GetMessageResponse *response) {
  try {
    auto tx = cp::tx(pool);
    auto &work = tx.get();
    auto q = work.exec(
        "select username, from_username, encrypted from messages where id=$1",
        pqxx::params{request->id()});
    if (q.empty()) {
      return ::grpc::Status(grpc::StatusCode::UNAVAILABLE,
                            "message does not exist");
    }

    auto username = q[0][0].get<std::string>().value_or("kek");
    auto from = q[0][1].get<std::string>().value_or("kek");
    auto encrypted_string = q[0][2].get<std::string>().value_or("0");

    response->set_username(username);
    response->set_from_username(from);
    response->set_encrypted(encrypted_string);
    return ::grpc::Status::OK;

  } catch (const std::exception &ex) {
    std::cerr << "Got exception: " << ex.what() << std::endl;

    return ::grpc::Status(grpc::StatusCode::INTERNAL, ex.what());
  }
}
