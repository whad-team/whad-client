"""LoRaWAN helpers
"""
import re

from whad.lorawan.exceptions import BadEuiFormat

class EUI(object):
    """Extended Unique Identifier
    """

    def __init__(self, eui : str):
        """Initialize an EUI
        """
        # check EUI format
        if re.match('^([0-9a-fA-F]{2}:){7}[0-9a-fA-F]{2}$', eui):
            values = eui.lower().split(':')[::-1]
            self.__packed = bytes([int(v, 16) for v in values])
        else:
            raise BadEuiFormat()

    @property
    def value(self) -> bytes:
        """Return EUI as a packed value (bytes)

        :returns: bytes
        """
        return self.__packed

    def __repr__(self):
        return ':'.join(['%02x' % b for b in self.__packed][::-1])
    
    def __eq__(self, other) -> bool:
        """Compare two EUIs
        """
        return self.value == other.value

