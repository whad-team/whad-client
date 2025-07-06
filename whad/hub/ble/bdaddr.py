import json
import re


class InvalidBDAddressException(Exception):
    """Invalid BD address used
    """


class BDAddress(object):
    """This class represents a Bluetooth Device address.
    """

    PUBLIC = 0x00
    RANDOM = 0x01

    def __init__(self, address, random: bool = False, addr_type=None):
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
            if re.match(r"^([0-9a-fA-F]{2}\:){5}[0-9a-fA-F]{2}$", address) is not None:
                self.__value = bytes.fromhex(address.replace(":", ""))[::-1]
            elif re.match("[0-9a-fA-F]{12}$", address) is not None:
                self.__value = bytes.fromhex(address)[::-1]
            else:
                raise InvalidBDAddressException
        elif isinstance(address, bytes) and len(address) == 6:
            self.__value = address
        else:
            raise InvalidBDAddressException

    def __eq__(self, other):
        return (self.__value == other.value) and (self.__type == other.type)

    def __str__(self):
        return ":".join(f"{b:02x}" for b in self.__value[::-1])

    def __repr__(self):
        return f"BDAddress({str(self)})"

    def export_json(self) -> str:
        return json.dumps(str(self))

    @property
    def type(self) -> int:
        return self.__type

    @property
    def value(self) -> bytes:
        return self.__value

    def is_public(self) -> bool:
        """Determine if address is public.

        :rtype: bool
        :return: True if BD address is public, False otherwise.
        """
        return self.__type == BDAddress.PUBLIC

    def is_random(self) -> bool:
        """Determine if address is random.

        :rtype: bool
        :return: True if BD address is random, False otherwise.
        """
        return self.__type == BDAddress.RANDOM

    @staticmethod
    def from_bytes(bd_addr_bytes: bytes, addr_type=None) -> "BDAddress":
        """Convert a 6-byte array into a Bluetooth address.

        :param bytes bd_addr_bytes: Bluetooth Device address as bytes.
        :param addr_type: Bluetooth Device Address type, PUBLIC or RANDOM
        :type addr_type: int, optional
        :rtype: BDAddress
        :return: An instance of BDAddress representing the corresponding BD address.
        """
        if len(bd_addr_bytes) == 6:
            return BDAddress(bd_addr_bytes, addr_type=addr_type)
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
        return bool(re.match("^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$", bd_addr))
