#!/usr/bin/env python3
import random
import re
import string
import sys

import checklib
import requests
from checklib import *
from checklib import status

import docs_lib

LEVEL_1_DOMAINS = [
    ".AC", ".AD", ".AE", ".AERO", ".AF", ".AG", ".AI", ".AL", ".AM", ".AN", ".AO", ".AQ", ".AR", ".ARPA", ".AS", ".ASIA",
    ".AT", ".AU", ".AW", ".AX", ".AZ", ".BA", ".BB", ".BD", ".BE", ".BF", ".BG", ".BH", ".BI", ".BIZ", ".BJ", ".BL", ".BM",
    ".BN", ".BO", ".BR", ".BS", ".BT", ".BV", ".BW", ".BY", ".BZ", ".CA", ".CAT", ".CC", ".CD", ".CF", ".CG", ".CH", ".CI",
    ".CK", ".CL", ".CM", ".CN", ".CO", ".COM", ".COOP", ".CR", ".CU", ".CV", ".CX", ".CY", ".CZ", ".DE", ".DJ", ".DK", ".DM",
    ".DO", ".DZ", ".EC", ".EDU", ".EE", ".EG", ".EH", ".ER", ".ES", ".ET", ".EU", ".FI", ".FJ", ".FK", ".FM", ".FO", ".FR",
    ".GA", ".GB", ".GD", ".GE", ".GF", ".GG", ".GH", ".GI", ".GL", ".GM", ".GN", ".GOV", ".GP", ".GQ", ".GR", ".GS", ".GT",
    ".GU", ".GW", ".GY", ".HK", ".HM", ".HN", ".HR", ".HT", ".HU", ".ID", ".IE", ".IL", ".IM", ".IN", ".INFO", ".INT", ".IO",
    ".IQ", ".IR", ".IS", ".IT", ".JE", ".JM", ".JO", ".JOBS", ".JP", ".KE", ".KG", ".KH", ".KI", ".KM", ".KN", ".KP", ".KR",
    ".KW", ".KY", ".KZ", ".LA", ".LB", ".LC", ".LI", ".LK", ".LR", ".LS", ".LT", ".LU", ".LV", ".LY", ".MA", ".MC", ".MD",
    ".ME", ".MF", ".MG", ".MH", ".MIL", ".MK", ".ML", ".MM", ".MN", ".MO", ".MOBI", ".MP", ".MQ", ".MR", ".MS", ".MT", ".MU",
    ".MUSEUM", ".MV", ".MW", ".MX", ".MY", ".MZ", ".NA", ".NAME", ".NC", ".NE", ".NET", ".NF", ".NG", ".NI", ".NL", ".NO",
    ".NP", ".NR", ".NU", ".NZ", ".OM", ".ORG", ".PA", ".PE", ".PF", ".PG", ".PH", ".PK", ".PL", ".PM", ".PN", ".PR", ".PRO",
    ".PS", ".PT", ".PW", ".PY", ".QA", ".RE", ".RO", ".RS", ".RU", ".RW", ".SA", ".SB", ".SC", ".SD", ".SE", ".SG", ".SH",
    ".SI", ".SJ", ".SK", ".SL", ".SM", ".SN", ".SO", ".SR", ".ST", ".SU", ".SV", ".SY", ".SZ", ".TC", ".TD", ".TEL", ".TF",
    ".TG", ".TH", ".TJ", ".TK", ".TL", ".TM", ".TN", ".TO", ".TP", ".TR", ".TRAVEL", ".TT", ".TV", ".TW", ".TZ", ".UA", ".UG",
    ".UK", ".UM", ".US", ".UY", ".UZ", ".VA", ".VC", ".VE", ".VG", ".VI", ".VN", ".VU", ".WF", ".WS"
]


class Checker(BaseChecker):
    vulns: int = 1
    timeout: int = 15
    uses_attack_data: bool = True

    def __init__(self, *args, **kwargs):
        super(Checker, self).__init__(*args, **kwargs)
        self.lib = docs_lib.DocsLib(self)
        self.token_regexp = re.compile(r'^[0-9A-Za-z]{1,80}$')

    def get_random_org(self):
        l = rnd_string(10, alphabet=string.ascii_lowercase)
        r = random.choice(LEVEL_1_DOMAINS)
        return f"{l}{r}".lower()

    def action(self, action, *args, **kwargs):
        try:
            super(Checker, self).action(action, *args, **kwargs)
        except requests.exceptions.ConnectionError:
            self.cquit(Status.DOWN, 'Connection error', 'Got requests connection error')

    def check(self):
        session = checklib.get_initialized_session()
        org = self.get_random_org()

        response = self.lib.create_org(session, org)
        token = response.get('token')
        org_id = response.get('id')

        self.assert_eq(bool(self.token_regexp.fullmatch(token)), True, 'Invalid token format')

        u, p = rnd_username(), rnd_password()
        u1, p1 = rnd_username(), rnd_password()
        self.lib.create_user(session, u, p, token)
        u = f'{u}@{org}'

        session = self.lib.login(session, u, p)

        title = rnd_string(10)
        content = rnd_string(10)

        got_doc = self.lib.create_doc(session, title, content)
        got_doc = self.lib.get_doc(session, got_doc.get('id'))

        self.lib.create_user(session, u1, p1, token)
        u1 = f'{u1}@{org}'

        session_alter = checklib.get_initialized_session()
        self.lib.login(session_alter, u1, p1)

        got_alter_doc = self.lib.get_doc(session_alter, got_doc.get('id'))
        self.assert_eq(got_alter_doc.get('title'), title, 'Failed to get document')
        self.assert_eq(got_alter_doc.get('content'), content, 'Failed to get document')

        new_title = rnd_string(10)
        self.lib.update_doc(session, got_doc.get('id'), title=new_title)

        got_updated_doc = self.lib.get_doc(session, got_doc.get('id'))
        self.assert_eq(got_updated_doc.get('title'), new_title, 'Failed to update document')
        self.assert_eq(got_updated_doc.get('content'), content, 'Failed to update document')

        search_results = self.lib.search(session_alter, new_title)
        self.assert_in(got_updated_doc.get('id'), [x.get('id') for x in search_results], 'Failed to search document')
        self.assert_in(got_updated_doc.get('title'), [x.get('title') for x in search_results],
                       'Failed to search document')
        self.assert_in(got_updated_doc.get('content'), [x.get('content') for x in search_results],
                       'Failed to search document')

        self.cquit(Status.OK)

    def put(self, flag_id: str, flag: str, vuln: str):
        session = checklib.get_initialized_session()
        org_id = self.get_random_org()

        response = self.lib.create_org(session, org_id)
        token = response.get('token')

        self.assert_eq(bool(self.token_regexp.fullmatch(token)), True, 'Invalid token format')

        u, p = rnd_username(), rnd_password()
        self.lib.create_user(session, u, p, token)

        sess = checklib.get_initialized_session()
        u = f'{u}@{org_id}'
        self.lib.login(sess, u, p)
        title = checklib.rnd_string(10)
        created_doc = self.lib.create_doc(sess, title, flag)

        doc_id = created_doc.get('id')
        self.assert_eq(bool(self.token_regexp.fullmatch(doc_id)), True, 'Invalid docid format')

        self.cquit(Status.OK, doc_id, f"{token}:{u}:{p}:{doc_id}")

    def get(self, flag_id: str, flag: str, vuln: str):
        token, u, p, doc_id = flag_id.split(':')
        sess = checklib.get_initialized_session()
        self.lib.login(sess, u, p, status=status.Status.CORRUPT)
        doc = self.lib.get_doc(sess, doc_id, status=status.Status.CORRUPT)
        self.assert_eq(doc.get('content'), flag, 'Invalid content', status=status.Status.CORRUPT)

        sess = checklib.get_initialized_session()
        u1, p1 = rnd_username(), rnd_password()
        created_user = self.lib.create_user(sess, u1, p1, token)

        sess = checklib.get_initialized_session()
        self.lib.login(sess, created_user.get('email'), created_user.get('password'))

        self.lib.search(sess, '', status=status.Status.CORRUPT)

        self.cquit(Status.OK)


if __name__ == '__main__':
    c = Checker(sys.argv[2])

    try:
        c.action(sys.argv[1], *sys.argv[3:])
    except c.get_check_finished_exception() as e:
        cquit(status.Status(c.status), c.public, c.private)
