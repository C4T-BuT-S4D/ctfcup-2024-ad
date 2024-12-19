from typing import Optional

import checklib
from checklib import BaseChecker
import requests

PORT = 8000


class DocsLib:
    @property
    def api_url(self):
        return f'http://{self.host}:{self.port}/api'

    def __init__(self, checker: BaseChecker, port=PORT, host=None):
        self.c = checker
        self.port = port
        self.host = host or self.c.host

    def create_org(self, session: requests.Session, domain: str):
        document = {
            "domain": domain,
        }

        resp = session.post(
            f"{self.api_url}/organizations",
            json=document
        )
        self.c.assert_eq(resp.status_code, 200, 'Failed to create organization')
        response_data = self.c.get_json(resp, 'Failed to create organization: invalid JSON')
        self.c.assert_eq(type(response_data), dict, 'Failed to create organization: invalid JSON')
        return response_data


    def list_orgs(self, session: requests.Session):
        resp = session.get(
            f"{self.api_url}/organizations"
        )
        self.c.assert_eq(resp.status_code, 200, 'Failed to list organization')
        return self.c.get_json(resp, 'Failed to list organization: invalid JSON')

    def create_user(self, session: requests.Session, username: str, password: str, token: str):
        document = {
            "username": username,
            "password": password,
            "token": token
        }
        resp = session.post(
            f"{self.api_url}/users",
            json=document
        )
        self.c.assert_eq(resp.status_code, 200, 'Failed to create user')
        return self.c.get_json(resp, 'Failed to create user: invalid JSON')

    def login(self, session: requests.Session, username: str, password: str, status: checklib.Status = checklib.Status.MUMBLE):
        document = {
            "email": username,
            "password": password
        }

        response = session.post(
            f"{self.api_url}/login",
            json=document
        )
        self.c.assert_eq(response.status_code, 200, 'Failed to login', status=status)
        resp_json = self.c.get_json(response, 'Failed to login: invalid JSON', status=status)
        self.c.assert_eq(type(resp_json), dict, 'Failed to login: invalid JSON', status=status)
        token = resp_json.get('token') or ''
        session.headers['Authorization'] = f"Bearer {token}"
        return session

    def get_user(self, session: requests.Session, status: checklib.Status = checklib.Status.MUMBLE):
        response = session.get(
            f"{self.api_url}/users/me",

        )
        self.c.assert_eq(response.status_code, 200, 'Failed to get user', status=status)
        return self.c.get_json(response, 'Failed to get user: invalid JSON', status=status)


    def create_doc(self, session: requests.Session, title: str, content: str, status: checklib.Status = checklib.Status.MUMBLE):
        document = {
            "title": title,
            "content": content
        }

        response = session.post(
            f"{self.api_url}/documents",
            json=document
        )
        self.c.assert_eq(response.status_code, 200, 'Failed to create document', status=status)
        return self.c.get_json(response, 'Failed to create document: invalid JSON', status=status)

    def update_doc(self, session: requests.Session, doc_id:str, title: str | None, content: str | None = None,
                   status: checklib.Status = checklib.Status.MUMBLE):
        document = {}
        if title:
            document['title'] = title
        if content:
            document['content'] = content

        response = session.patch(
            f"{self.api_url}/documents/{doc_id}",
            json=document
        )
        print(response.text)
        self.c.assert_eq(response.status_code, 200, 'Failed to update document', status=status)
        return self.c.get_json(response, 'Failed to create document: invalid JSON', status=status)

    def get_doc(self, session: requests.Session, doc_id: str, status: checklib.Status = checklib.Status.MUMBLE):
        response = session.get(
            f"{self.api_url}/documents/{doc_id}"
        )
        self.c.assert_eq(response.status_code, 200, 'Failed to get document', status=status)
        return self.c.get_json(response, 'Failed to get document: invalid JSON', status=status)

    def delete_doc(self, session: requests.Session, doc_id: str, status: checklib.Status = checklib.Status.MUMBLE):
        response = session.delete(
            f"{self.api_url}/documents/{doc_id}"
        )
        self.c.assert_eq(response.status_code, 200, 'Failed to delete document', status=status)

    def search(self, session: requests.Session, query: str, status: checklib.Status = checklib.Status.MUMBLE):
        response = session.get(f"{self.api_url}/documents",
                               params={'query': query}
                               )
        print(response.text)
        self.c.assert_eq(response.status_code, 200, 'Failed to search', status=status)
        return self.c.get_json(response, 'Failed to search: invalid JSON', status=status)


    def document_get_txt(self, session: requests.Session, doc_id: str, status: checklib.Status = checklib.Status.MUMBLE):
        response = session.get(
            f"{self.api_url}/document/{doc_id}/text"
        )
        self.c.assert_eq(response.status_code, 200, 'Failed to get txt', status=status)
        return response.text




