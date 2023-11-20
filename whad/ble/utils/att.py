from whad.ble.stack.att.constants import BleAttSecurityMode
from whad.ble.utils.validators import InvalidUUIDException
from struct import pack, unpack
from binascii import hexlify, unhexlify, Error as BinasciiError

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
