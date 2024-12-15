#!/usr/bin/env python3

import json
import random
import sys

if True:
    saved_args = sys.argv.copy()

from ark_lib import *
from checklib import *  # type: ignore


class Checker(BaseChecker):
    vulns: int = 1
    timeout: int = 20
    uses_attack_data: bool = True

    def __init__(self, *args, **kwargs):
        super(Checker, self).__init__(*args, **kwargs)
        self.mch = CheckMachine(self)

    def check(self):
        # Register a user
        username, password = rnd_username(), rnd_password()
        with (
            self.mch.connect() as r1,
            self.mch.connect() as r2,
            self.mch.connect() as anon_r,
        ):
            def gr():
                return random.choice([r1, r2])

            def ar():
                return random.choice([r1, anon_r])

            self.mch.register(gr(), username, password)

            self.mch.login(r1, username, password)
            self.mch.login(r2, username, password)

            files = [
                (self.mch.random_filename(), rnd_string(random.randint(10, 50)))
                for _ in range(random.randint(1, 10))
            ]
            for file, content in files:
                self.mch.save_file(gr(), file, content)

            random.shuffle(files)
            for file, content in files:
                got_content = self.mch.cat_file(gr(), file, Status.MUMBLE)
                self.assert_eq(got_content, content, "File content mismatch")

            # Test list functionality
            list_output = self.mch.list_user_files(gr(), '')
            for file, _ in files:
                self.assert_in(file, [f.path for f in list_output],
                               "File not found in list")

            # Test suggest_users
            suggest_output = self.mch.suggest_users(gr())
            if len(suggest_output) < 30 and not any(u.username == username for u in suggest_output):
                self.cquit(Status.MUMBLE, "Suggest users failed")

            # Test list_user_files
            user_files = self.mch.list_user_files(ar(), username)
            for file, content in files:
                self.assert_in(file, [f.path for f in user_files],
                               "File not found in user files")
                self.assert_in(len(content), [f.size for f in user_files],
                               "File size mismatch")

            # Register a second user
            # Test second user can copy first user's files
            # Test first user can cat their own files from the second user's account

            username2, password2 = rnd_username(), rnd_password()
            self.mch.register(ar(), username2, password2)
            self.mch.login(r2, username2, password2)

            # Test list_user_files
            user_files = self.mch.list_user_files(ar(), username)
            for file, content in files:
                self.assert_in(file, [f.path for f in user_files],
                               "File not found in user files")
                self.assert_in(len(content), [f.size for f in user_files],
                               "File size mismatch")

            file_to_copy = random.choice(files)
            dst_path = self.mch.random_filename()
            self.mch.copy_file(r2, file_to_copy[0], dst_path)

            # Test second user can list their own files
            user_files = self.mch.list_user_files(r2, username2)
            self.assert_in(dst_path, [f.path for f in user_files],
                           "File not found in user files")

            # Test first user can cat their own files from the second user's quota
            content = self.mch.cat_file(r1, dst_path, Status.MUMBLE)
            self.assert_eq(content, file_to_copy[1], "File content mismatch")

            self.cquit(Status.OK)

    def put(self, flag_id: str, flag: str, vuln: str):
        username1, password1 = rnd_username(), rnd_password()
        username2, password2 = rnd_username(), rnd_password()

        with (
            self.mch.connect() as r1,
            self.mch.connect() as r2,
        ):
            self.mch.register(r1, username1, password1)
            self.mch.register(r2, username2, password2)

            self.mch.login(r1, username1, password1)
            self.mch.login(r2, username2, password2)

            flag_file1 = self.mch.random_filename()
            flag_file2 = self.mch.random_filename()

            self.mch.save_file(r1, flag_file1, flag)
            self.mch.copy_file(r2, flag_file1, flag_file2)

            public = f'u1={username1}:u2={username2}'

            private = json.dumps({
                'username1': username1,
                'password1': password1,
                'username2': username2,
                'password2': password2,
                'flag_file1': flag_file1,
                'flag_file2': flag_file2,
            })

            self.cquit(Status.OK, public=public, private=private)

    def get(self, flag_id: str, flag: str, vuln: str):
        data = json.loads(flag_id)

        with (
            self.mch.connect() as r1,
            self.mch.connect() as r2,
            self.mch.connect() as anon_r,
        ):
            self.mch.login(r1, data['username1'],
                           data['password1'], Status.CORRUPT)
            self.mch.login(r2, data['username2'],
                           data['password2'], Status.CORRUPT)

            for r in [r1, r2, anon_r]:
                file_list = self.mch.list_user_files(r, data['username1'])
                self.assert_in(data['flag_file1'], [f.path for f in file_list],
                               "Flag file not found in user files", Status.CORRUPT)

                file_list = self.mch.list_user_files(r, data['username2'])
                self.assert_in(data['flag_file2'], [f.path for f in file_list],
                               "Flag file not found in user files", Status.CORRUPT)

            content = self.mch.cat_file(r1, data['flag_file1'], Status.CORRUPT)
            self.assert_eq(content, flag, "Flag mismatch", Status.CORRUPT)

            content = self.mch.cat_file(r1, data['flag_file2'], Status.CORRUPT)
            self.assert_eq(content, flag, "Flag mismatch", Status.CORRUPT)

        self.cquit(Status.OK)


if __name__ == '__main__':
    c = Checker(saved_args[2])

    try:
        c.action(saved_args[1], *saved_args[3:])
    except c.get_check_finished_exception():
        cquit(Status(c.status), c.public, c.private)
