import logging

import jwt
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi import Request, HTTPException

from app.config import settings

class JWTHelper(object):
    ALGORITHM = "HS256"

    def __init__(self, security_key):
        self.security_key = security_key

    def gen_token(self, data):
        try:
            return jwt.encode(data, self.security_key, algorithm=self.ALGORITHM)
        except Exception as e:
            logging.error("failed to generate jwt token: {}".format(e))
            return ""

    def decode_token(self, cookie):
        try:
            return jwt.decode(cookie, self.security_key, algorithms=[self.ALGORITHM, ])
        except Exception as e:
            logging.error("failed to decode jwt token: {}".format(e))
            return None



class JWTBearer(HTTPBearer):
    def __init__(self, auto_error: bool = True):
        super(JWTBearer, self).__init__(auto_error=auto_error)
        self.jwt_helper = JWTHelper(settings.jwt_key)

    async def __call__(self, request: Request):
        credentials: HTTPAuthorizationCredentials = await super(JWTBearer, self).__call__(request)
        if credentials:
            if not credentials.scheme == "Bearer":
                raise HTTPException(status_code=403, detail="Invalid authentication scheme.")
            payload = self.jwt_helper.decode_token(credentials.credentials)
            if not payload:
                raise HTTPException(status_code=403, detail="Invalid token or expired token.")
            return payload
        else:
            raise HTTPException(status_code=403, detail="Invalid authorization code.")

jwt_helper = JWTHelper(settings.jwt_key)
jwt_bearer = JWTBearer()

