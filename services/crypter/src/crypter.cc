#include "crypter.h"

CrypterService::CrypterService(const cp::connection_options &connection_options)
    : pool(connection_options) {}
