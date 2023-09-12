"""Att Exceptions
"""
class AttErrorCode:
    INVALID_HANDLE_VALUE = 0x01
    READ_NOT_PERMITTED = 0x02
    WRITE_NOT_PERMITTED = 0x03
    INVALID_PDU = 0x04
    INSUFFICIENT_AUTHENTICATION = 0x05
    UNSUPPORTED_REQUEST = 0x06
    INVALID_OFFSET = 0x07
    INSUFFICIENT_AUTHORIZATION = 0x08
    PREPARE_QUEUE_FULL = 0x09
    ATTR_NOT_FOUND = 0x0A
    ATTR_NOT_LONG = 0x0B
    INSUFFICIENT_ENC_KEY_SIZE = 0x0C
    INVALID_ATTR_VALUE_LENGTH = 0x0D
    UNLIKELY_ERROR = 0x0E
    INSUFFICIENT_ENC = 0x0F
    UNSUPPORTED_GROUP_TYPES = 0x10
    INSUFFICIENT_RES = 0x11

class AttError(Exception):
    """ATT generic exception
    """

    def __init__(self, request, handle):
        super().__init__()
        self.request = request
        self.handle = handle

class InvalidHandleValueError(AttError):
    """Exception raised when an invalid handle value is provided.
    """
    def __init__(self, request, handle):
        super().__init__(request, handle)

class ReadNotPermittedError(AttError):
    def __init__(self, request, handle):
        super().__init__(request, handle)

class WriteNotPermittedError(AttError):
    def __init__(self, request, handle):
        super().__init__(request, handle)

class InvalidPduError(AttError):
    def __init__(self, request, handle):
        super().__init__(request, handle)

class InsufficientAuthenticationError(AttError):
    def __init__(self, request, handle):
        super().__init__(request, handle)

class UnsupportedRequestError(AttError):
    def __init__(self, request, handle):
        super().__init__(request, handle)

class InvalidOffsetError(AttError):
    def __init__(self, request, handle):
        super().__init__(request, handle)

class InsufficientAuthorizationError(AttError):
    def __init__(self, request, handle):
        super().__init__(request, handle)

class PrepareQueueFullError(AttError):
    def __init__(self, request, handle):
        super().__init__(request, handle)

class AttributeNotFoundError(AttError):
    def __init__(self, request, handle):
        super().__init__(request, handle)

class AttributeNotLongError(AttError):
    def __init__(self, request, handle):
        super().__init__(request, handle)

class InsufficientEncryptionKeySize(AttError):
    def __init__(self, request, handle):
        super().__init__(request, handle)

class InvalidAttrValueLength(AttError):
    def __init__(self, request, handle):
        super().__init__(request, handle)

class UnlikelyError(AttError):
    def __init__(self, request, handle):
        super().__init__(request, handle)

class InsufficientEncryptionError(AttError):
    def __init__(self, request, handle):
        super().__init__(request, handle)

class UnsupportedGroupTypesError(AttError):
    def __init__(self, request, handle):
        super().__init__(request, handle)

class InsufficientResourcesError(AttError):
    def __init__(self, request, handle):
        super().__init__(request, handle)

def error_response_to_exc(error_code, request, handle):
    RESP_TO_EXC = {
        0x01: InvalidHandleValueError,
        0x02: ReadNotPermittedError,
        0x03: WriteNotPermittedError,
        0x04: InvalidPduError,
        0x05: InsufficientAuthenticationError,
        0x06: UnsupportedRequestError,
        0x07: InvalidOffsetError,
        0x08: InsufficientAuthorizationError,
        0x09: PrepareQueueFullError,
        0x0A: AttributeNotFoundError,
        0x0B: AttributeNotLongError,
        0x0C: InsufficientEncryptionKeySize,
        0x0D: InvalidAttrValueLength,
        0x0E: UnlikelyError,
        0x0F: InsufficientEncryptionError,
        0x10: UnsupportedGroupTypesError,
        0x11: InsufficientResourcesError
    }
    if error_code in RESP_TO_EXC:
        return RESP_TO_EXC[error_code](request, handle)
    else:
        return AttError(request, handle)
