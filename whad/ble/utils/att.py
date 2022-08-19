from whad.ble.stack.att.constants import BleAttSecurityMode
from whad.ble.utils.validators import InvalidUUIDException
from struct import pack, unpack
from binascii import hexlify, unhexlify

def get_att_security_mode_from_mode_and_level(mode, level):
    """
    Generate SecurityMode class instance based on a supplied mode and level.
    :param mode: Security mode
    :type mode: int
    :param level: Security level
    :type level: level
    :return: SecurityMode object corresponding to supplied values or False if DNE
    :rtype: SecurityMode || bool
    """
    if mode == 0 and level == 0:
        return BleAttSecurityMode.NO_ACCESS
    elif mode == 1:
        if level == 1:
            return BleAttSecurityMode.OPEN
        if level == 2:
            return BleAttSecurityMode.ENCRYPTION_NO_AUTHENTICATION
        if level == 3:
            return BleAttSecurityMode.ENCRYPTION_WITH_AUTHENTICATION
        if level == 4:
            return BleAttSecurityMode.ENCRYPTION_WITH_SECURE_CONNECTIONS
    elif mode == 2:
        if level == 1:
            return BleAttSecurityMode.DATA_SIGNING_NO_AUTHENTICATION
        if level == 2:
            return BleAttSecurityMode.DATA_SIGNING_WITH_AUTHENTICATION

    return False


class UUID:
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
                self.packed = pack('<h', uuid)
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
            temp = uuid.translate(None, "-")

            if len(temp) == 32:
                self.uuid = uuid
                self.packed = unhexlify(temp)[::-1]
                self.type = UUID.TYPE_128
        elif len(uuid) == 32 and "-" not in uuid:
            self.uuid = '-'.join((uuid[:8], uuid[8:12], uuid[12:16], uuid[16:20], uuid[20:]))
            self.packed = unhexlify(uuid)[::-1]
            self.type = UUID.TYPE_128
        # binary
        elif len(uuid) == 2:
            self.uuid = '%04X' % unpack('<h', uuid)[0]
            self.packed = uuid
            self.type = UUID.TYPE_16
        elif len(uuid) == 16:
            r = uuid[::-1]
            self.uuid = '-'.join(map(lambda x: hexlify(x), (r[0:4], r[4:6], r[6:8], r[8:10], r[10:])))
            self.packed = uuid
            self.type = UUID.TYPE_128

        if self.uuid is None:
            raise InvalidUUIDException(uuid)

    def __eq__(self, other):
        # TODO expand 16 bit UUIDs
        return self.packed == other.packed

    def __repr__(self):
        return self.uuid