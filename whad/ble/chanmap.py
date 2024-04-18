"""BLE Channel Map helper
"""

from typing import List, Generator

class ChannelMap(object):
    """BLE Channel Map class
    """

    def __init__(self, channels: List[int] = None):
        """Initialize our channel map

        :param channels: List of channels to include in channel map
        :type channels: list, optional
        """
        self.__map = 0

        # Loop over channels and add them to our map
        if channels is not None:
            for channel in channels:
                
                # Add channel to our channel map
                self.add(channel)
    
    def add(self, channel: int):
        """Add channel to our channel map.

        :param channel: Channel number to add to channel map
        :param channel: int
        """
        # Check channel number validity
        if channel < 0 or channel > 37:
            raise ValueError()
        
        # Add channel to our map
        self.__map |= (1 << channel)

    def remove(self, channel: int):
        """Remove channel from our channel map.

        :param channel: Channel number to remove from channel map
        :param channel: int
        """
        # Check channel number validity
        if channel < 0 or channel > 37:
            raise ValueError()
        
        # Remove channel from map
        if self.has(channel):
            self.__map = self.__map & ((1 << channel) ^ 0xFFFFFFFFFF)

    def has(self, channel: int) -> bool:
        """Check if a given channel is present in channel map.

        :param channel: Channel to check
        :type channel: int
        :return: True if channel is present in channel map, False otherwise
        :return-type: bool
        """
        return (self.__map & (1 << channel)) != 0
        
    def channels(self) -> Generator:
        """Iterate over channels
        """
        for channel in range(38):
            if self.has(channel):
                yield channel

    @property
    def value(self):
        """Retrieve the channel map value
        """
        return self.__map.to_bytes(5, 'little', signed=False)

# Default channel map
DefaultChannelMap = ChannelMap(channels=range(38))