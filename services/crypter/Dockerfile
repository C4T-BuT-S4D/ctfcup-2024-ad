FROM ubuntu:24.04

RUN apt update && apt install -y libgrpc++-dev libprotobuf-dev cmake git libpq-dev protobuf-compiler-grpc libgmp-dev

RUN git clone https://github.com/jtv/libpqxx
WORKDIR /libpqxx
RUN mkdir build && cd build && cmake .. && make install

WORKDIR /app
COPY CMakeLists.txt .

COPY cmake cmake
COPY src src
COPY include include
COPY proto proto

RUN mkdir build && cd build && cmake .. -DCMAKE_BUILD_TYPE=Release

RUN cd build && make

CMD ["/app/build/crypter"]
