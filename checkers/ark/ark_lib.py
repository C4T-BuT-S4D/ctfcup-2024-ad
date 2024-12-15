import random
import re
import string
from dataclasses import dataclass

from checklib import *  # type: ignore
from pwn import context, remote

context.timeout = 10
context.log_level = 'FATAL'

PORT = 13345


@dataclass
class SuggestedUser:
    username: str
    file_count: int
    file_size: int


@dataclass
class UserFile:
    path: str
    size: int


@dataclass
class File:
    path: str
    size: int


class CheckMachine:
    def __init__(self, checker: BaseChecker):
        self.c = checker
        self.port = PORT

    def connect(self) -> remote:
        r = remote(self.c.host, self.port)
        r.recvuntil(b'quit')
        r.recvuntil(b'> ')
        return r

    def register(self, r: remote, username: str, password: str, status: Status = Status.MUMBLE):
        r.sendline(f'register {username} {password}'.encode())
        response = r.recvline().decode()
        r.recvuntil(b'> ')

        self.c.assert_in('Registration successful', response,
                         'Registration failed', status=status)

    def login(self, r: remote, username: str, password: str, status: Status = Status.MUMBLE):
        r.sendline(f'login {username} {password}'.encode())
        response = r.recvline().decode()
        r.recvuntil(b'> ')

        self.c.assert_in('Welcome,', response,
                         'Login failed', status=status)

        return r

    def save_file(self, r: remote, path: str, content: str, status: Status = Status.MUMBLE):
        r.sendline(f'save {path} {content}'.encode())
        response = r.recvuntil(b'> ').decode()

        self.c.assert_in('File saved successfully', response,
                         'Save failed', status=status)

    def cat_file(self, r: remote, path: str, status: Status = Status.MUMBLE) -> str:
        r.sendline(f'cat {path}'.encode())
        response = r.recvuntil(b'> ').decode()

        # Extract content between the command and the next prompt
        lines = response.split('\n')
        self.c.assert_gt(len(lines), 1, 'Cat failed', status=status)
        return lines[0]

    def suggest_users(self, r: remote, status: Status = Status.MUMBLE) -> list[SuggestedUser]:
        r.sendline(b'suggest_users')
        response = r.recvuntil(b'> ').decode()

        self.c.assert_in('Suggested users:', response,
                         'Suggest users failed', status=status)

        users = []
        for line in response.split('\n'):
            if 'Username:' in line:
                # Username: kek, Created At: 2024-12-15 13:10:54.753883 UTC, File Count: 1, Total File Size: 4
                matches = re.match(
                    r'Username: (\w+), .*, File Count: (\d+), Total File Size: (\d+)', line)
                if matches:
                    users.append(SuggestedUser(
                        matches.group(1), int(matches.group(2)), int(matches.group(3))))
        return users

    def list_user_files(self, r: remote, username: str, status: Status = Status.MUMBLE) -> list[UserFile]:
        if username == '':
            r.sendline(b'list')
        else:
            r.sendline(f'list_files {username}'.encode())

        response = r.recvuntil(b'> ').decode()

        files = []
        for line in response.split('\n'):
            if 'ID' in line:
                # ID: 2, Path: /tmp/1, Size: 4 bytes
                matches = re.match(
                    r'ID: (\d+), Path: (\S+), Size: (\d+) bytes', line)
                if matches:
                    files.append(
                        UserFile(matches.group(2), int(matches.group(3))))
        return files

    def copy_file(self, r: remote, src_path: str, dst_path: str, status: Status = Status.MUMBLE):
        r.sendline(f'copy {src_path} {dst_path}'.encode())
        response = r.recvuntil(b'> ').decode()

        self.c.assert_in('File copied successfully', response,
                         'Copy failed', status=status)

    def random_filename(self) -> str:
        d = random.choice(['tmp', 'files'])
        l = random.randint(10, 50)
        a = string.ascii_letters + string.digits + '.,-_=+:|()*[]&^'
        return f"/{d}/test_{rnd_string(l, a)}.txt"
