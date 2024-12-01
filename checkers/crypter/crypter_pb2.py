# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# NO CHECKED-IN PROTOBUF GENCODE
# source: crypter.proto
# Protobuf Python Version: 5.28.2
"""Generated protocol buffer code."""
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import runtime_version as _runtime_version
from google.protobuf import symbol_database as _symbol_database
from google.protobuf.internal import builder as _builder
_runtime_version.ValidateProtobufRuntimeVersion(
    _runtime_version.Domain.PUBLIC,
    5,
    28,
    2,
    '',
    'crypter.proto'
)
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\rcrypter.proto\x12\x07\x63rypter\"#\n\x0fRegisterRequest\x12\x10\n\x08username\x18\x01 \x01(\t\";\n\x10RegisterResponse\x12\r\n\x05token\x18\x01 \x01(\t\x12\t\n\x01n\x18\x02 \x01(\t\x12\r\n\x05lamba\x18\x03 \x01(\t\"F\n\x12SendMessageRequest\x12\r\n\x05token\x18\x01 \x01(\t\x12\x10\n\x08username\x18\x02 \x01(\t\x12\x0f\n\x07message\x18\x03 \x01(\t\"!\n\x13SendMessageResponse\x12\n\n\x02id\x18\x01 \x01(\t\"$\n\x13ListMessagesRequest\x12\r\n\x05token\x18\x01 \x01(\t\"\"\n\x14ListMessagesResponse\x12\n\n\x02id\x18\x01 \x03(\t\"\x1f\n\x11GetMessageRequest\x12\n\n\x02id\x18\x01 \x01(\t\"P\n\x12GetMessageResponse\x12\x10\n\x08username\x18\x01 \x01(\t\x12\x15\n\rfrom_username\x18\x02 \x01(\t\x12\x11\n\tencrypted\x18\x03 \x01(\t\"+\n\x17GetUserPublicKeyRequest\x12\x10\n\x08username\x18\x01 \x01(\t\"%\n\x18GetUserPublicKeyResponse\x12\t\n\x01n\x18\x01 \x01(\t2\x8b\x03\n\x07\x43rypter\x12\x41\n\x08Register\x12\x18.crypter.RegisterRequest\x1a\x19.crypter.RegisterResponse\"\x00\x12J\n\x0bSendMessage\x12\x1b.crypter.SendMessageRequest\x1a\x1c.crypter.SendMessageResponse\"\x00\x12M\n\x0cListMessages\x12\x1c.crypter.ListMessagesRequest\x1a\x1d.crypter.ListMessagesResponse\"\x00\x12G\n\nGetMessage\x12\x1a.crypter.GetMessageRequest\x1a\x1b.crypter.GetMessageResponse\"\x00\x12Y\n\x10GetUserPublicKey\x12 .crypter.GetUserPublicKeyRequest\x1a!.crypter.GetUserPublicKeyResponse\"\x00\x62\x06proto3')

_globals = globals()
_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, _globals)
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, 'crypter_pb2', _globals)
if not _descriptor._USE_C_DESCRIPTORS:
  DESCRIPTOR._loaded_options = None
  _globals['_REGISTERREQUEST']._serialized_start=26
  _globals['_REGISTERREQUEST']._serialized_end=61
  _globals['_REGISTERRESPONSE']._serialized_start=63
  _globals['_REGISTERRESPONSE']._serialized_end=122
  _globals['_SENDMESSAGEREQUEST']._serialized_start=124
  _globals['_SENDMESSAGEREQUEST']._serialized_end=194
  _globals['_SENDMESSAGERESPONSE']._serialized_start=196
  _globals['_SENDMESSAGERESPONSE']._serialized_end=229
  _globals['_LISTMESSAGESREQUEST']._serialized_start=231
  _globals['_LISTMESSAGESREQUEST']._serialized_end=267
  _globals['_LISTMESSAGESRESPONSE']._serialized_start=269
  _globals['_LISTMESSAGESRESPONSE']._serialized_end=303
  _globals['_GETMESSAGEREQUEST']._serialized_start=305
  _globals['_GETMESSAGEREQUEST']._serialized_end=336
  _globals['_GETMESSAGERESPONSE']._serialized_start=338
  _globals['_GETMESSAGERESPONSE']._serialized_end=418
  _globals['_GETUSERPUBLICKEYREQUEST']._serialized_start=420
  _globals['_GETUSERPUBLICKEYREQUEST']._serialized_end=463
  _globals['_GETUSERPUBLICKEYRESPONSE']._serialized_start=465
  _globals['_GETUSERPUBLICKEYRESPONSE']._serialized_end=502
  _globals['_CRYPTER']._serialized_start=505
  _globals['_CRYPTER']._serialized_end=900
# @@protoc_insertion_point(module_scope)