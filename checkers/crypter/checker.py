#!/usr/bin/env python3

import random
import secrets
import sys
import uuid
import json

import grpc
from checklib import *

from crypter_lib import CheckMachine


class Checker(BaseChecker):
    vulns: int = 1
    timeout: int = 15
    uses_attack_data: bool = True

    def __init__(self, *args, **kwargs):
        super(Checker, self).__init__(*args, **kwargs)
        self.c = CheckMachine(self)

    def action(self, action, *args, **kwargs):
        try:
            super(Checker, self).action(action, *args, **kwargs)
        except self.get_check_finished_exception():
            raise
        except grpc.RpcError as e:
            if e.code() == grpc.StatusCode.UNAVAILABLE:
                self.cquit(Status.DOWN, "unavailable", f"grpc error: {e}")
            else:
                self.cquit(Status.MUMBLE, f"grpc error: {e.code()}", f"grpc error: {e}")
        except ConnectionRefusedError:
            self.cquit(Status.DOWN, "Connection refused", "Connection refused")

    def check(self):
        with self.c.connect() as channel, self.c.handle_grpc_error(status=Status.MUMBLE):
            stub = self.c.get_stub(channel)

            username = rnd_username()
            user = self.c.Register(stub, username)

            from_username = rnd_username()
            from_user = self.c.Register(stub, from_username)

            data = rnd_string(32)
            message_id = self.c.SendMessage(stub, username, from_user.token, data)
            n = self.c.GetUserPublicKey(stub, username)

            message = self.c.GetMessage(stub, message_id)

            plaintext = self.c.int_to_bytes(self.c.decrypt(user.n, user.lamba, message.encrypted))

            self.assert_eq(message.username, username, "incorrect username", Status.MUMBLE)
            self.assert_eq(message.from_username, from_username, "incorrect from_username", Status.MUMBLE)
            self.assert_eq(plaintext, data.encode(), "incorrect flag", Status.MUMBLE)

            self.cquit(Status.OK)


    def put(self, flag_id: str, flag: str, vuln: str):
        with self.c.connect() as channel, self.c.handle_grpc_error(status=Status.MUMBLE):
            stub = self.c.get_stub(channel)

            username = rnd_username()
            user = self.c.Register(stub, username)

            from_username = rnd_username()
            from_user = self.c.Register(stub, from_username)

            message_id = self.c.SendMessage(stub, username, from_user.token, flag)
            self.cquit(Status.OK, 
                       json.dumps({
                           "message": message_id,
                       }),
                       json.dumps({   
                           "username": username,
                       "lambda": user.lamba,
                       "from": from_username,
                           "message": message_id,
                       }),
                       )


    def get(self, flag_id: str, flag: str, vuln: str):
        with self.c.connect() as channel, self.c.handle_grpc_error(status=Status.CORRUPT):
            stub = self.c.get_stub(channel)

            flag_data = json.loads(flag_id)

            lamba = flag_data["lambda"]
            username = flag_data["username"]
            from_username = flag_data["from"]
            message_id = flag_data["message"]

            n = self.c.GetUserPublicKey(stub, username)

            message = self.c.GetMessage(stub, message_id)

            plaintext = self.c.int_to_bytes(self.c.decrypt(n, lamba, message.encrypted))

            self.assert_eq(message.username, username, "incorrect username", Status.CORRUPT)
            self.assert_eq(message.from_username, from_username, "incorrect from_username", Status.CORRUPT)
            self.assert_eq(plaintext, flag.encode(), "incorrect flag", Status.CORRUPT)

            self.cquit(Status.OK)



if __name__ == "__main__":
    c = Checker(sys.argv[2])

    try:
        c.action(sys.argv[1], *sys.argv[3:])
    except c.get_check_finished_exception():
        cquit(Status(c.status), c.public, c.private)
