#include "crypter.h"
#include <grpc++/grpc++.h>
#include <memory>

int main() {

  cp::connection_options options = {
      .dbname = "crypter",
      .user = "crypter",
      .password = "crypter",
      .host = "postgres",
      .port = 5432,
      .connections_count = 64,
  };

  CrypterService service(options);

  grpc::ServerBuilder builder;
  builder.AddListeningPort("0.0.0.0:2112", grpc::InsecureServerCredentials());
  builder.RegisterService(&service);
  std::unique_ptr<grpc::Server> server(builder.BuildAndStart());

  server->Wait();
}
