"""
WHAD Enhanced ShockBurst

This module provides the `ESBAddress` class that represents
an Enhanced ShockBurst device address.
"""
import re
from whad.esb.exceptions import InvalidESBAddressException

class ESBAddress:
    """This class represents an Enhanced ShockBurst address.
    """

    def __init__(self, address):
        """Initialize ESB address
        """
        if isinstance(address, str):
            if re.match(r'^([0-9a-fA-F]{2}\:){4}[0-9a-fA-F]{2}$', address) is not None:
                self.__value = bytes.fromhex(address.replace(":",""))
            elif re.match('[0-9a-fA-F]{10}$', address) is not None:
                self.__value = bytes.fromhex(address)
            else:
                raise InvalidESBAddressException
        elif isinstance(address, bytes) and len(address) > 1 and len(address) <= 5:
            self.__value = address
        else:
            raise InvalidESBAddressException

    def __eq__(self, other):
        return self.__value == other.value

    def __str__(self):
        return ":".join([f"{b:02x}" for b in self.__value])

    def __repr__(self):
        return f"ESBAddress({self})"

    @property
    def value(self) -> bytes:
        """Return the address value

        :return: ESB address as byte buffer
        :rtype: bytes
        """
        return self.__value

    @property
    def base(self) -> str:
        """Return the 4 MSBytes of this ESB address as string

        :return: ESB base address
        :rtype: str
        """
        return ":".join([f"{b:02x}" % b for b in self.__value[:4]])

    @property
    def prefix(self) -> str:
        """Return the ESB address prefix

        :return: ESB address prefix
        :rtype: str
        """
        return f"{self.__value[4]:02x}"

    @staticmethod
    def from_bytes(esb_addr_bytes):
        """Convert a 5-byte array into a valid ESB address.

        :param bytes bd_addr_bytes: Enhanced ShockBurst address as a bytearray.
        :rtype: ESBAddress
        :return: An instance of ESBAddress representing the corresponding ESB address.
        """
        if len(esb_addr_bytes) == 5:
            hex_address = esb_addr_bytes.hex()
            address = ":".join([hex_address[i*2:(i+1)*2] for i in range(int(len(hex_address)/2))])
            return ESBAddress(address)

        # Raise an error (invalid address size)
        raise InvalidESBAddressException
