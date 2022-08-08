import re
from binascii import hexlify, unhexlify
from whad.domain.ble.exceptions import InvalidBDAddressException

class BDAddress(object):
    """This class represents a Bluetooth Device address
    """

    def __init__(self, address):
        """Initialize BD address
        """
        if isinstance(address, str):
            if re.match('^([0-9a-fA-F]{2}\:){5}[0-9a-fA-F]{2}$', address) is not None:
                self.__value = unhexlify(address.replace(':',''))[::-1]
            elif re.match('[0-9a-fA-F]{12}$', address) is not None:
                self.__value = unhexlify(address)[::-1]
            else:
                raise InvalidBDAddressException
        else:
            raise InvalidBDAddressException

    def __str__(self):
        return ':'.join(['%02x' % b for b in self.__value[::-1]])

    def __repr__(self):
        return 'BDAddress(%s)' % str(self)

    @property
    def value(self):
        return self.__value