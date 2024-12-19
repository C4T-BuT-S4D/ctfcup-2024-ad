# Generated by the gRPC Python protocol compiler plugin. DO NOT EDIT!
"""Client and server classes corresponding to protobuf-defined services."""
import grpc
import warnings

import crypter_pb2 as crypter__pb2

GRPC_GENERATED_VERSION = '1.65.5'
GRPC_VERSION = grpc.__version__
EXPECTED_ERROR_RELEASE = '1.66.0'
SCHEDULED_RELEASE_DATE = 'August 6, 2024'
_version_not_supported = False

try:
    from grpc._utilities import first_version_is_lower
    _version_not_supported = first_version_is_lower(GRPC_VERSION, GRPC_GENERATED_VERSION)
except ImportError:
    _version_not_supported = True

if _version_not_supported:
    warnings.warn(
        f'The grpc package installed is at version {GRPC_VERSION},'
        + f' but the generated code in crypter_pb2_grpc.py depends on'
        + f' grpcio>={GRPC_GENERATED_VERSION}.'
        + f' Please upgrade your grpc module to grpcio>={GRPC_GENERATED_VERSION}'
        + f' or downgrade your generated code using grpcio-tools<={GRPC_VERSION}.'
        + f' This warning will become an error in {EXPECTED_ERROR_RELEASE},'
        + f' scheduled for release on {SCHEDULED_RELEASE_DATE}.',
        RuntimeWarning
    )


class CrypterStub(object):
    """Missing associated documentation comment in .proto file."""

    def __init__(self, channel):
        """Constructor.

        Args:
            channel: A grpc.Channel.
        """
        self.Register = channel.unary_unary(
                '/crypter.Crypter/Register',
                request_serializer=crypter__pb2.RegisterRequest.SerializeToString,
                response_deserializer=crypter__pb2.RegisterResponse.FromString,
                _registered_method=True)
        self.SendMessage = channel.unary_unary(
                '/crypter.Crypter/SendMessage',
                request_serializer=crypter__pb2.SendMessageRequest.SerializeToString,
                response_deserializer=crypter__pb2.SendMessageResponse.FromString,
                _registered_method=True)
        self.ListMessages = channel.unary_unary(
                '/crypter.Crypter/ListMessages',
                request_serializer=crypter__pb2.ListMessagesRequest.SerializeToString,
                response_deserializer=crypter__pb2.ListMessagesResponse.FromString,
                _registered_method=True)
        self.GetMessage = channel.unary_unary(
                '/crypter.Crypter/GetMessage',
                request_serializer=crypter__pb2.GetMessageRequest.SerializeToString,
                response_deserializer=crypter__pb2.GetMessageResponse.FromString,
                _registered_method=True)
        self.GetUserPublicKey = channel.unary_unary(
                '/crypter.Crypter/GetUserPublicKey',
                request_serializer=crypter__pb2.GetUserPublicKeyRequest.SerializeToString,
                response_deserializer=crypter__pb2.GetUserPublicKeyResponse.FromString,
                _registered_method=True)


class CrypterServicer(object):
    """Missing associated documentation comment in .proto file."""

    def Register(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def SendMessage(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def ListMessages(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def GetMessage(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def GetUserPublicKey(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')


def add_CrypterServicer_to_server(servicer, server):
    rpc_method_handlers = {
            'Register': grpc.unary_unary_rpc_method_handler(
                    servicer.Register,
                    request_deserializer=crypter__pb2.RegisterRequest.FromString,
                    response_serializer=crypter__pb2.RegisterResponse.SerializeToString,
            ),
            'SendMessage': grpc.unary_unary_rpc_method_handler(
                    servicer.SendMessage,
                    request_deserializer=crypter__pb2.SendMessageRequest.FromString,
                    response_serializer=crypter__pb2.SendMessageResponse.SerializeToString,
            ),
            'ListMessages': grpc.unary_unary_rpc_method_handler(
                    servicer.ListMessages,
                    request_deserializer=crypter__pb2.ListMessagesRequest.FromString,
                    response_serializer=crypter__pb2.ListMessagesResponse.SerializeToString,
            ),
            'GetMessage': grpc.unary_unary_rpc_method_handler(
                    servicer.GetMessage,
                    request_deserializer=crypter__pb2.GetMessageRequest.FromString,
                    response_serializer=crypter__pb2.GetMessageResponse.SerializeToString,
            ),
            'GetUserPublicKey': grpc.unary_unary_rpc_method_handler(
                    servicer.GetUserPublicKey,
                    request_deserializer=crypter__pb2.GetUserPublicKeyRequest.FromString,
                    response_serializer=crypter__pb2.GetUserPublicKeyResponse.SerializeToString,
            ),
    }
    generic_handler = grpc.method_handlers_generic_handler(
            'crypter.Crypter', rpc_method_handlers)
    server.add_generic_rpc_handlers((generic_handler,))
    server.add_registered_method_handlers('crypter.Crypter', rpc_method_handlers)


 # This class is part of an EXPERIMENTAL API.
class Crypter(object):
    """Missing associated documentation comment in .proto file."""

    @staticmethod
    def Register(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(
            request,
            target,
            '/crypter.Crypter/Register',
            crypter__pb2.RegisterRequest.SerializeToString,
            crypter__pb2.RegisterResponse.FromString,
            options,
            channel_credentials,
            insecure,
            call_credentials,
            compression,
            wait_for_ready,
            timeout,
            metadata,
            _registered_method=True)

    @staticmethod
    def SendMessage(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(
            request,
            target,
            '/crypter.Crypter/SendMessage',
            crypter__pb2.SendMessageRequest.SerializeToString,
            crypter__pb2.SendMessageResponse.FromString,
            options,
            channel_credentials,
            insecure,
            call_credentials,
            compression,
            wait_for_ready,
            timeout,
            metadata,
            _registered_method=True)

    @staticmethod
    def ListMessages(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(
            request,
            target,
            '/crypter.Crypter/ListMessages',
            crypter__pb2.ListMessagesRequest.SerializeToString,
            crypter__pb2.ListMessagesResponse.FromString,
            options,
            channel_credentials,
            insecure,
            call_credentials,
            compression,
            wait_for_ready,
            timeout,
            metadata,
            _registered_method=True)

    @staticmethod
    def GetMessage(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(
            request,
            target,
            '/crypter.Crypter/GetMessage',
            crypter__pb2.GetMessageRequest.SerializeToString,
            crypter__pb2.GetMessageResponse.FromString,
            options,
            channel_credentials,
            insecure,
            call_credentials,
            compression,
            wait_for_ready,
            timeout,
            metadata,
            _registered_method=True)

    @staticmethod
    def GetUserPublicKey(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(
            request,
            target,
            '/crypter.Crypter/GetUserPublicKey',
            crypter__pb2.GetUserPublicKeyRequest.SerializeToString,
            crypter__pb2.GetUserPublicKeyResponse.FromString,
            options,
            channel_credentials,
            insecure,
            call_credentials,
            compression,
            wait_for_ready,
            timeout,
            metadata,
            _registered_method=True)