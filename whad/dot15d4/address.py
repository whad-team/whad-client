import re
from binascii import hexlify, unhexlify
from whad.dot15d4.exceptions import InvalidDot15d4AddressException
from struct import pack, unpack

class Dot15d4Address(object):
    """This class represents a 802.15.4 address.
    """

    SHORT = 0x00
    EXTENDED = 0x01

    def __init__(self, address):
        """Initialize 802.15.4 address

        Adapt to input parameters to represent a 802.15.4 short or extended address.
        """


        if isinstance(address, str):
            if re.match(r'^([0-9a-fA-F]{2}\:){7}[0-9a-fA-F]{2}$', address) is not None:
                self.__type = Dot15d4Address.EXTENDED
                self.__value = unhexlify(address.replace(':',''))
            elif re.match('[0-9a-fA-F]{16}$', address) is not None:
                self.__type = Dot15d4Address.EXTENDED
                self.__value = unhexlify(address)
            elif re.match('[0-9a-fA-F]{4}$', address) is not None:
                self.__type = Dot15d4Address.SHORT
                self.__value = unhexlify(address)
            elif re.match('0x[0-9a-fA-F]{4}$', address) is not None:
                self.__type = Dot15d4Address.SHORT
                self.__value = unhexlify(address[2:])
            else:
                raise InvalidDot15d4AddressException
        elif isinstance(address, int):
            if address <= 0xFFFF:
                self.__type = Dot15d4Address.SHORT
                self.__value = pack('>H', address)
            else:
                self.__type = Dot15d4Address.EXTENDED
                self.__value = pack('>Q', address)
        else:
            raise InvalidDot15d4AddressException

    def __eq__(self, other):

        if not isinstance(other, Dot15d4Address):
            other = Dot15d4Address(other)

        return (self.value == other.value) and (self.__type == other.type)


    def __str__(self):
        if self.__type == Dot15d4Address.EXTENDED:
            return ':'.join(['%02x' % b for b in self.__value])
        else:
            return "0x" + "".join(['%02x' % b for b in self.__value])

    def __repr__(self):
        return 'Dot15d4Address(%s)' % str(self)

    @property
    def type(self):
        return self.__type

    @property
    def value(self):
        if self.__type == Dot15d4Address.EXTENDED:
            return unpack('<Q', self.__value)[0]
        elif self.__type == Dot15d4Address.SHORT:
            return unpack('>H', self.__value)[0]

    def is_extended(self):
        """Determine if address is extended.

        :rtype: bool
        :return: True if 802.15.4 address is extended, False otherwise.
        """
        return (self.__type == Dot15d4Address.EXTENDED)


    @staticmethod
    def from_bytes(addr_bytes):
        """Convert a 2 or 8-byte array into a valid 802.15.4 address.

        :param bytes addr_bytes: Network or Device address as a bytearray.
        :rtype: Dot15d4Address
        :returns: An instance of Dot15d4Address representing the corresponding Dot15d4 address.
        """
        if len(addr_bytes) == 8:
            hex_address = hexlify(addr_bytes[::-1])
            address = b':'.join([hex_address[i*2:(i+1)*2] for i in range(int(len(hex_address)/2))])
            return Dot15d4Address(address.decode('utf-8'))
        elif len(addr_bytes) == 2:
            address = b''.join([hex_address[i*2:(i+1)*2] for i in range(int(len(hex_address)/2))])
            return Dot15d4Address(address.decode('utf-8'))
        else:
            raise InvalidDot15d4AddressException
