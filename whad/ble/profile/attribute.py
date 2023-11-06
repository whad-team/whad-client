"""BLE Attribute
"""

from whad.ble.exceptions import InvalidHandleValueException, InvalidUUIDException
from whad.ble.stack.gatt.helpers import get_alias_uuid
from struct import pack, unpack
from binascii import unhexlify, hexlify

class UUID:
    """UUID class borrowed from pyBT (c) Mike Ryan
    """
    TYPE_16 = 1
    TYPE_128 = 2

    uuid = None
    packed = None
    type = None

    def __init__(self, uuid):
        if isinstance(uuid, UUID):
            self.uuid = uuid.uuid
            self.packed = uuid.packed
            self.type = uuid.type

        # integer
        elif isinstance(uuid, int):
            if 0 <= uuid <= 65536:
                self.uuid = '%04X' % uuid
                self.packed = pack('<H', uuid)
                self.type = UUID.TYPE_16
            elif 0 <= uuid <= 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:
                self.uuid = '%032X' % uuid
                # modified solution from http://www.codegur.site/6877096/how-to-pack-a-uuid-into-a-struct-in-python
                self.packed = pack('<QQ', uuid & 0xFFFFFFFFFFFFFFFF, (uuid >> 64) & 0xFFFFFFFFFFFFFFFF)
                self.type = UUID.TYPE_128

        elif len(uuid) == 4:
            self.uuid = uuid
            self.packed = unhexlify(uuid)[::-1]
            self.type = UUID.TYPE_16
        elif len(uuid) == 36:
            temp = uuid.replace('-','')

            if len(temp) == 32:
                self.uuid = uuid
                self.packed = unhexlify(temp)[::-1]
                self.type = UUID.TYPE_128
        elif len(uuid) == 32 and "-" not in uuid:
            self.uuid = b'-'.join((uuid[:8], uuid[8:12], uuid[12:16], uuid[16:20], uuid[20:])).decode('latin-1')
            self.packed = uuid.decode("hex")[::-1]
            self.type = UUID.TYPE_128
        # binary
        elif len(uuid) == 2:
            self.uuid = '%04X' % unpack('<H', uuid)[0]
            self.packed = uuid
            self.type = UUID.TYPE_16
        elif len(uuid) == 16:
            r = uuid[::-1]
            self.uuid = b'-'.join(map(lambda x: hexlify(x), (r[0:4], r[4:6], r[6:8], r[8:10], r[10:]))).decode('latin-1')
            self.packed = uuid
            self.type = UUID.TYPE_128

        if self.uuid is None:
            raise InvalidUUIDException(uuid)

    def __eq__(self, other):
        # TODO expand 16 bit UUIDs
        return self.packed == other.packed

    def __repr__(self):
        return self.uuid

    def to_bytes(self):
        return self.packed

    def value(self):
        if self.type == UUID.TYPE_16:
            return unpack('<H', self.packed)[0]
        else:
            raise ValueError

    @classmethod
    def from_name(cls, name):
        return get_alias_uuid(name)

class Attribute(object):
    """GATT Attribute model
    """
    def __init__(self, uuid, handle=None, value=0):
        """Instanciate a GATT Attribute
        """
        self.__uuid = uuid
        self.__handle = handle
        self.__value = value

    def to_pdu(self):
        """Convert attribute to bytes (PDU)
        """
        return pack('<H', self.__handle) + self.__uuid.to_bytes() + self.payload()

    @property
    def payload(self):
        return self.__value

    @property
    def value(self):
        return self.__value

    @value.setter
    def value(self, value):
        self.__value = value

    @property
    def handle(self):
        return self.__handle

    @handle.setter
    def handle(self, new_handle):
        if isinstance(new_handle, int):
            self.__handle = new_handle
        else:
            raise InvalidHandleValueException

    @property
    def type_uuid(self):
        return self.__uuid
