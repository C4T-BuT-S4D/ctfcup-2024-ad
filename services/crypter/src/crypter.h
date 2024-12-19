#include "pqxx-connection-pool.hpp"
#include <proto/crypter.grpc.pb.h>
#include <proto/crypter.pb.h>

class CrypterService final : public crypter::Crypter::Service {
  cp::connection_pool pool;

public:
  CrypterService(const cp::connection_options &connection_options);
  virtual ::grpc::Status Register(::grpc::ServerContext *context,
                                  const ::crypter::RegisterRequest *request,
                                  ::crypter::RegisterResponse *response);
  virtual ::grpc::Status
  SendMessage(::grpc::ServerContext *context,
              const ::crypter::SendMessageRequest *request,
              ::crypter::SendMessageResponse *response);
  virtual ::grpc::Status
  ListMessages(::grpc::ServerContext *context,
               const ::crypter::ListMessagesRequest *request,
               ::crypter::ListMessagesResponse *response);
  virtual ::grpc::Status GetMessage(::grpc::ServerContext *context,
                                    const ::crypter::GetMessageRequest *request,
                                    ::crypter::GetMessageResponse *response);
  virtual ::grpc::Status
  GetUserPublicKey(::grpc::ServerContext *context,
                   const ::crypter::GetUserPublicKeyRequest *request,
                   ::crypter::GetUserPublicKeyResponse *response);
};
