"""BLE utility device caching module.

This module implements a single class, `BleDevicesCache`, that keeps track
of discovered devices and their information.
"""
from whad.ble.scanning import AdvertisingDevice
from whad.ble.profile.device import PeripheralDevice

class BleDevicesCache(object):
    """Bluetooth Low Energy devices cache.
    """

    def __init__(self):
        """Initialize device cache.
        """
        self.__devices = {}

    def __len__(self):
        """Retrieve cache length
        """
        return len(self.__devices.keys())

    def clear(self):
        """Remove device entry from cache.
        """
        self.__devices = {}

    def iterate(self):
        """Iterate over cached devices.
        """
        for address in self.__devices:
            yield self.__devices[address]

    def add(self, device: AdvertisingDevice):
        """Add a discovered device to our cache.

        @param device AdvertisingDevice Device to add
        """
        self.__devices[device.address.lower()] = {
            'info':device,
            'profile': None,
            'discovered': False
        }

    def __getitem__(self, address: str):
        """Return an existing device from cache.

        @param address str Device BD address (i.e. '00:11:22:33:44:55')
        """
        if address in self.__devices:
            return self.__devices[address.lower()]
        else:
            # If not found, look into devices names
            for addr in self.__devices:
                dev = self.__devices[addr]
                if dev['info'].name is not None and dev['info'].name == address:
                    return self.__devices[addr]
            raise IndexError

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