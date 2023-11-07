"""ATT constants (error and operation codes)
"""
import sys

if sys.version_info[0] == 3 and sys.version_info[1] >= 10:
    # Import UnionType only for Python >= 3.10
    from types import UnionType
    def is_union_type(obj):
        return isinstance(obj, UnionType)
else:
    # UnionType is not available
    def is_union_type(obj):
        return False

class BleAttOpcode:
    """ATT operation codes
    """
    ERROR_RESPONSE = 0x01
    EXCHANGE_MTU_REQUEST = 0x02
    EXCHANGE_MTU_RESPONSE = 0x03
    FIND_INFO_REQUEST = 0x04
    FIND_INFO_RESPONSE = 0x05
    FIND_BY_TYPE_VALUE_REQUEST = 0x06
    FIND_BY_TYPE_VALUE_RESPONSE = 0x07
    READ_BY_TYPE_REQUEST = 0x08
    READ_BY_TYPE_RESPONSE = 0x09
    READ_REQUEST = 0x0A
    READ_RESPONSE = 0x0B
    READ_BLOB_REQUEST = 0x0C
    READ_BLOB_RESPONSE = 0x0D
    READ_MULTIPLE_REQUEST = 0x0E
    READ_MULTIPLE_RESPONSE = 0x0F
    READ_BY_GROUP_TYPE_REQUEST = 0x10
    READ_BY_GROUP_TYPE_RESPONSE = 0x11
    WRITE_REQUEST = 0x12
    WRITE_RESPONSE = 0x13
    WRITE_COMMAND = 0x52
    SIGNED_WRITE_COMMAND = 0xD2
    PREPARE_WRITE_REQUEST = 0x16
    PREPARE_WRITE_RESPONSE = 0x17
    EXECUTE_WRITE_REQUEST = 0x18
    EXECUTE_WRITE_RESPONSE = 0x19
    HANDLE_VALUE_NOTIFICATION = 0x1B
    HANDLE_VALUE_INDICATION = 0x1D
    HANDLE_VALUE_CONFIRMATION = 0x1E

class BleAttErrorCode:
    """ATT error code
    """
    INVALID_HANDLE = 0x01
    READ_NOT_PERMITTED = 0x02
    WRITE_NOT_PERMITTED = 0x03
    INVALID_PDU = 0x04
    INSUFFICIENT_AUTHENT = 0x05
    REQUEST_NOT_SUPP = 0x06
    INVALID_OFFSET = 0x07
    INSUFFICIENT_AUTHOR = 0x08
    PREPARE_QUEUE_FULL = 0x09
    ATTRIBUTE_NOT_FOUND = 0x0A
    ATTRIBUTE_NOT_LONG = 0x0B
    INSUFFICIENT_ENC_KEY_SIZE = 0x0C
    INVALID_ATTR_VALUE_LENGTH = 0x0D
    UNLIKELY_ERROR = 0x0E
    INSUFFICIENT_ENCRYPTION = 0x0F
    UNSUPPORTED_GROUP_TYPE = 0x10
    INSUFFICIENT_RESOURCES = 0x11

class SecurityMode:
    def __init__(self, security_mode=0, security_level=0):
        self.security_mode = security_mode
        self.security_level = security_level

class BleAttSecurityMode:
    NO_ACCESS = SecurityMode(0, 0)
    OPEN = SecurityMode(1, 1)
    ENCRYPTION_NO_AUTHENTICATION = SecurityMode(1, 2)
    ENCRYPTION_WITH_AUTHENTICATION = SecurityMode(1, 3)
    ENCRYPTION_WITH_SECURE_CONNECTIONS = SecurityMode(1, 4)
    DATA_SIGNING_NO_AUTHENTICATION = SecurityMode(2, 1)
    DATA_SIGNING_WITH_AUTHENTICATION = SecurityMode(2, 2)

class BleAttProperties:
    READ = 0x01
    WRITE = 0x02
    DEFAULT = READ | WRITE


class SecurityProperty:
    def __repr__(self):
        return self.__class__.__name__

class Encryption(SecurityProperty):
    pass

class Authentication(SecurityProperty):
    pass

class Authorization(SecurityProperty):
    pass

class SecurityAccess:
    TYPE = ""

    def __init__(self, *args):
        if len(args) > 0:
            if is_union_type(args[0]):
                self.__access = list(args[0].__args__)
            else:
                self.__access = list(args)
        else:
            self.__access = []

    def requires_encryption(self):
        return Encryption in self.__access

    def requires_authentication(self):
        return Authentication in self.__access

    def requires_authorization(self):
        return Authorization in self.__access

    @property
    def access(self):
        return self.__access

    def __repr__(self):
        return "%s (%s)" % (self.__class__.TYPE, " | ".join([a.__name__ for a in self.access]))

    @classmethod
    def generate(cls, val):
        if isinstance(val, list) and all([isinstance(i, SecurityAccess) for i in val]):
            return val
        elif isinstance(val, SecurityAccess):
            return [val]
        else:
            return []

    def __or__(self, other):
        if isinstance(other, SecurityAccess):
            return [self, other]
        else:
            return [self]

    @classmethod
    def accesses_to_int(cls, value):
        return_value = 0
        for access in value:
            if isinstance(access, ReadAccess):
                shift = 0
            elif isinstance(access, WriteAccess):
                shift = 4

            if Encryption in access.access:
                return_value |= (1 << shift)
            if Authentication in access.access:
                return_value |= (2 << shift)
            if Authorization in access.access:
                return_value |= (4 << shift)
        return return_value

    @classmethod
    def int_to_accesses(cls, value):
        accesses = []
        read_properties = []
        if bool(value & 1):
            read_properties.append(Encryption)
        if bool(value & 2):
            read_properties.append(Authentication)
        if bool(value & 4):
            read_properties.append(Authorization)
        if len(read_properties) > 0:
            accesses.append(ReadAccess(*read_properties))

        value = value >> 4
        write_properties = []
        if bool(value & 1):
            write_properties.append(Encryption)
        if bool(value & 2):
            write_properties.append(Authentication)
        if bool(value & 4):
            write_properties.append(Authorization)
        if len(write_properties) > 0:
            accesses.append(WriteAccess(*write_properties))
        return accesses

class ReadAccess(SecurityAccess):
    TYPE = "Read"

class WriteAccess(SecurityAccess):
    TYPE = "Write"

'''
ReadAccess(Encryption, Authentication, Authorization) | WriteAccess(Encryption, Authentication)
'''
