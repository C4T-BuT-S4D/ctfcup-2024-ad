from google.protobuf.internal import containers as _containers
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Iterable as _Iterable, Optional as _Optional

DESCRIPTOR: _descriptor.FileDescriptor

class RegisterRequest(_message.Message):
    __slots__ = ("username",)
    USERNAME_FIELD_NUMBER: _ClassVar[int]
    username: str
    def __init__(self, username: _Optional[str] = ...) -> None: ...

class RegisterResponse(_message.Message):
    __slots__ = ("token", "n", "lamba")
    TOKEN_FIELD_NUMBER: _ClassVar[int]
    N_FIELD_NUMBER: _ClassVar[int]
    LAMBA_FIELD_NUMBER: _ClassVar[int]
    token: str
    n: str
    lamba: str
    def __init__(self, token: _Optional[str] = ..., n: _Optional[str] = ..., lamba: _Optional[str] = ...) -> None: ...

class SendMessageRequest(_message.Message):
    __slots__ = ("token", "username", "message")
    TOKEN_FIELD_NUMBER: _ClassVar[int]
    USERNAME_FIELD_NUMBER: _ClassVar[int]
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    token: str
    username: str
    message: str
    def __init__(self, token: _Optional[str] = ..., username: _Optional[str] = ..., message: _Optional[str] = ...) -> None: ...

class SendMessageResponse(_message.Message):
    __slots__ = ("id",)
    ID_FIELD_NUMBER: _ClassVar[int]
    id: str
    def __init__(self, id: _Optional[str] = ...) -> None: ...

class ListMessagesRequest(_message.Message):
    __slots__ = ("token",)
    TOKEN_FIELD_NUMBER: _ClassVar[int]
    token: str
    def __init__(self, token: _Optional[str] = ...) -> None: ...

class ListMessagesResponse(_message.Message):
    __slots__ = ("id",)
    ID_FIELD_NUMBER: _ClassVar[int]
    id: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, id: _Optional[_Iterable[str]] = ...) -> None: ...

class GetMessageRequest(_message.Message):
    __slots__ = ("id",)
    ID_FIELD_NUMBER: _ClassVar[int]
    id: str
    def __init__(self, id: _Optional[str] = ...) -> None: ...

class GetMessageResponse(_message.Message):
    __slots__ = ("username", "from_username", "encrypted")
    USERNAME_FIELD_NUMBER: _ClassVar[int]
    FROM_USERNAME_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTED_FIELD_NUMBER: _ClassVar[int]
    username: str
    from_username: str
    encrypted: str
    def __init__(self, username: _Optional[str] = ..., from_username: _Optional[str] = ..., encrypted: _Optional[str] = ...) -> None: ...

class GetUserPublicKeyRequest(_message.Message):
    __slots__ = ("username",)
    USERNAME_FIELD_NUMBER: _ClassVar[int]
    username: str
    def __init__(self, username: _Optional[str] = ...) -> None: ...

class GetUserPublicKeyResponse(_message.Message):
    __slots__ = ("n",)
    N_FIELD_NUMBER: _ClassVar[int]
    n: str
    def __init__(self, n: _Optional[str] = ...) -> None: ...
