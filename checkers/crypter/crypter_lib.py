import random
import string
import uuid
from typing import Callable, List, NamedTuple

from checklib import *
import grpc
from contextlib import contextmanager
from crypter_pb2 import (
    RegisterRequest,
    RegisterResponse,
    GetMessageRequest,
    GetMessageResponse,
    SendMessageRequest,
    SendMessageResponse,
    GetUserPublicKeyRequest,
    GetUserPublicKeyResponse,
)
from crypter_pb2_grpc import CrypterStub

PORT = 2112

class User(NamedTuple):
    token: str
    n: int
    lamba: int

class EncryptedMessage(NamedTuple):
    username: string
    from_username: string
    encrypted: int

class CheckMachine:
    def __init__(self, c: BaseChecker):
        self.c = c
        self.addr = f"{self.c.host}:{PORT}"

    def connect(self) -> grpc.Channel:
        channel = grpc.insecure_channel(self.addr)
        return channel

    @staticmethod
    def get_stub(channel): 
        return CrypterStub(channel)

    @staticmethod
    def Register(
             stub: CrypterStub,
                username: string
             ) -> User:
        resp: RegisterResponse = stub.Register(
            RegisterRequest(
                username=username,
            )
        )
        return User(
            token=resp.token,
            n=int(resp.n),
            lamba=int(resp.lamba),
        )

    @staticmethod
    def GetMessage(
             stub: CrypterStub,
            id: string,
             ) -> EncryptedMessage:
        resp: GetMessageResponse = stub.GetMessage(
            GetMessageRequest(
                id=id,
            )
        )
        return EncryptedMessage(
            username=resp.username,
            from_username=resp.from_username,
            encrypted=int(resp.encrypted),
        )

    @staticmethod
    def SendMessage(
             stub: CrypterStub,
            username: string,
            token: string,
        message: string,
             ) -> str:
        resp: SendMessageResponse = stub.SendMessage(
            SendMessageRequest(
                username=username,
                token=token,
                message=message,
            )
        )
        return resp.id

    @staticmethod
    def GetUserPublicKey(
             stub: CrypterStub,
            username: string,
             ) -> str:
        resp: GetUserPublicKeyResponse = stub.GetUserPublicKey(
            GetUserPublicKeyRequest(
                username=username
            )
        )
        return int(resp.n)

    @contextmanager
    def handle_grpc_error(self, status=Status.MUMBLE):
        try:
            yield
        except grpc.RpcError as e:
            if e.code() == grpc.StatusCode.UNAVAILABLE:
                raise
            else:
                self.c.cquit(status, f"grpc error: {e.code()}", f"grpc error: {e}")
        except ValueError as e:
            self.c.cquit(status, f"value error", f"value error: {e}")

    @staticmethod
    def fake_flag() -> str:
        return (
            "B" + rnd_string(31, alphabet=string.ascii_uppercase + string.digits) + "="
        )

    @staticmethod
    def int_to_bytes(n: int) -> bytes:
        return n.to_bytes((n.bit_length() + 7 )// 8, "big")

    @staticmethod
    def decrypt(n: int, lamba: int, e: int):
        return (pow(e, lamba, n ** 2) - 1) // n * pow((pow(n + 1, lamba, n ** 2) - 1) // n, -1, n) % n
