import re, json
from binascii import hexlify, unhexlify

class InvalidBDAddressException(Exception):
    """Invalid BD address used
    """
    def __init__(self):
        super().__init__()

class BDAddress(object):
    """This class represents a Bluetooth Device address.
    """

    PUBLIC = 0x00
    RANDOM = 0x01

    def __init__(self, address, random=False, addr_type=None):
        """Initialize BD address

        By default, BD address is public unless `random` is set to True.

        :param int addr_type: Set BD address type (either BDAddress.PUBLIC or BDAddress.RANDOM). This setting overseeds `random`
        :param bool random: Set BD address as random if set to True. BD address is public by default.
        """
        if addr_type is not None:
            if addr_type in [BDAddress.PUBLIC, BDAddress.RANDOM]:
                self.__type = addr_type
        elif random:
            self.__type = BDAddress.RANDOM
        else:
            self.__type = BDAddress.PUBLIC

        if isinstance(address, str):
            if re.match(r'^([0-9a-fA-F]{2}\:){5}[0-9a-fA-F]{2}$', address) is not None:
                self.__value = unhexlify(address.replace(':',''))[::-1]
            elif re.match('[0-9a-fA-F]{12}$', address) is not None:
                self.__value = unhexlify(address)[::-1]
            else:
                raise InvalidBDAddressException
        elif isinstance(address, bytes) and len(address) == 6:
            self.__value = address
        else:
            raise InvalidBDAddressException

    def __eq__(self, other):
        return (self.__value == other.value) and (self.__type == other.type)

    def __str__(self):
        return ':'.join(['%02x' % b for b in self.__value[::-1]])

    def __repr__(self):
        return 'BDAddress(%s)' % str(self)

    def export_json(self):
        return json.dumps(str(self))

    @property
    def type(self):
        return self.__type

    @property
    def value(self):
        return self.__value

    def is_public(self):
        """Determine if address is public.

        :rtype: bool
        :return: True if BD address is public, False otherwise.
        """
        return (self.__type == BDAddress.PUBLIC)

    def is_random(self):
        """Determine if address is random.

        :rtype: bool
        :return: True if BD address is random, False otherwise.
        """
        return (self.__type == BDAddress.RANDOM)

    @staticmethod
    def from_bytes(bd_addr_bytes, addr_type=None):
        """Convert a 6-byte array into a valid BD address.

        :param bytes bd_addr_bytes: Bluetooth Device address as a bytearray.
        :param addr_type: Bluetooth Device Address type
        :type addr_type: int, optional
        :rtype: BDAddress
        :returns: An instance of BDAddress representing the corresponding BD address.
        """
        if len(bd_addr_bytes) == 6:
            hex_address = hexlify(bd_addr_bytes[::-1])
            address = b':'.join([hex_address[i*2:(i+1)*2] for i in range(int(len(hex_address)/2))])
            return BDAddress(address.decode('utf-8'), addr_type=addr_type)
        else:
            raise InvalidBDAddressException

    @staticmethod

    def check(bd_addr: str) -> bool:
        """Check if a BD address is valid

        :param      bd_addr: BD address to test
        :type       bd_addr: str
        :return:    ``True`` if BD address is valid, ``False`` otherwise
        :rtype:     bool
        """
        return re.match('^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$',bd_addr)
