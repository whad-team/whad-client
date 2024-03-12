"""ZigBee utility networks caching module.

This module implements a single class, `ZigbeeNetworksCache`, that keeps track
of discovered devices and their information.
"""
from whad.zigbee.profile.network import Network

class ZigbeeNetworksCache(object):
    """ZigBee Networks cache.
    """

    def __init__(self):
        """Initialize network cache.
        """
        self.__networks = {}

    def iterate(self):
        for network in self.__networks:
            yield self.__networks[network]

    def add(self, network: Network):
        """Add a discovered network to our cache.

        @param network Network: Network to add
        """
        self.__networks[str(network.extended_pan_id).lower()] = {
            'info':network,
            'discovered': False
        }

    def __getitem__(self, extended_pan_id: str):
        """Return an existing network from cache.

        @param extended_pan_id str: Network extended PAN ID (i.e. '00:11:22:33:44:55:66:77')
        """
        if extended_pan_id in self.__networks:
            return self.__networks[str(extended_pan_id).lower()]
        else:
            # If not found, look into networks PAN ID
            try:
                pan_id = int(extended_pan_id, 16)
            except:
                raise IndexError
            for net in self.__networks:
                network = self.__networks[net]
                if network['info'].pan_id is not None and dev['info'].pan_id == pan_id:
                    return self.__networks[net]
            raise IndexError
    '''
    def add_profile(self, address: str, profile: PeripheralDevice):
        """Add profile to a cached device.

        @param address str: Device BD address
        @param profile PeripheralDevice: Device object (obtained when connected)
        """
        address = address.lower()
        if address in self.__devices:
            self.__devices[address.lower()]['profile'] = profile
        else:
            raise IndexError

    def get_profile(self, address: str):
        """Get cached services associated with a specific device.
        """
        address = address.lower()
        if address in self.__devices:
            # Device found, check if we have a cached profile
            return self.__devices[address]['profile']
        else:
            raise IndexError

    def mark_as_discovered(self, address):
        address = address.lower()
        if address in self.__devices:
            # Device found, check if we have a cached profile
            self.__devices[address]['discovered'] = True
        else:
            raise IndexError

    def is_discovered(self, address):
        address = address.lower()
        if address in self.__devices:
            # Device found, check if we have a cached profile
            return self.__devices[address]['discovered']
        else:
            raise IndexError
    '''
