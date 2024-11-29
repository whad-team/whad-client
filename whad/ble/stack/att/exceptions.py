"""Att Exceptions
"""
class AttErrorCode:
    """ATT error codes
    """
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

class ReadNotPermittedError(AttError):
    """Exception raised when a read operation is performed while not permitted
    """

class WriteNotPermittedError(AttError):
    """Exception raised when a write operation is performed while not allowed
    """

class InvalidPduError(AttError):
    """Exception raised when an invalid PDU is processed
    """

class InsufficientAuthenticationError(AttError):
    """Authentication required
    """

class UnsupportedRequestError(AttError):
    """Exception raised when an unsupported request is received
    """

class InvalidOffsetError(AttError):
    """Exception raised when an invalid offset is provided to a read or write
    operation
    """

class InsufficientAuthorizationError(AttError):
    """Exception raised if an authorization is required
    """

class PrepareQueueFullError(AttError):
    """Raised when a prepare write queue is full.
    """

class AttributeNotFoundError(AttError):
    """Exception raised when an attribute cannot be found.
    """

class AttributeNotLongError(AttError):
    """Raised a read long operation is performed on a not-long attribute.
    """

class InsufficientEncryptionKeySize(AttError):
    """Raised when wrong key size is used
    """

class InvalidAttrValueLength(AttError):
    """Raised when an invalid length is used on an attribute
    """

class UnlikelyError(AttError):
    """Raised when an unlikely error is triggered
    """

class InsufficientEncryptionError(AttError):
    """Raised on insufficient encryption.
    """

class UnsupportedGroupTypesError(AttError):
    """Raised when an unsupported group type is requested.
    """

class InsufficientResourcesError(AttError):
    """Raised to notify an error of resources
    """

def error_response_to_exc(error_code, request, handle) -> AttError:
    """Convert error code to corresponding exception.

    :param error_code: ATT error code
    :type error_code: int
    :param request: Request that lead to this error code
    :type request: int
    :param handle: related handle
    :type handle: int
    :return: corresponding exception
    :rtype: AttError
    """
    resp_to_exc = {
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
    if error_code in resp_to_exc:
        return resp_to_exc[error_code](request, handle)
    else:
        return AttError(request, handle)
