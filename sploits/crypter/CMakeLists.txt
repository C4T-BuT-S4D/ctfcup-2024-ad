cmake_minimum_required(VERSION 3.15)
project(crypter CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED TRUE)
set(CMAKE_CXX_FLAGS "-Ofast")

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(CMAKE_MODULE_PATH
    ${CMAKE_CURRENT_LIST_DIR}/cmake
    ${CMAKE_MODULE_PATH}
)

# find_package(Protobuf REQUIRED)
find_package(gRPC REQUIRED)
find_package(GMP REQUIRED)
get_target_property(grpc_cpp_plugin_location gRPC::grpc_cpp_plugin LOCATION)


add_executable(${PROJECT_NAME} src/main.cc proto/crypter.proto)
protobuf_generate(
    TARGET
        ${PROJECT_NAME}
    LANGUAGE
        grpc
    GENERATE_EXTENSIONS
        .grpc.pb.h
        .grpc.pb.cc
    PLUGIN
        "protoc-gen-grpc=${grpc_cpp_plugin_location}"
)
protobuf_generate(
    TARGET
        ${PROJECT_NAME}
    LANGUAGE
        cpp
)
target_link_libraries(${PROJECT_NAME} PUBLIC 
    protobuf::libprotobuf
    gRPC::grpc
    gRPC::grpc++
    gmp
)
target_include_directories(${PROJECT_NAME} PRIVATE ${PROJECT_SOURCE_DIR}/include ${CMAKE_BINARY_DIR})
