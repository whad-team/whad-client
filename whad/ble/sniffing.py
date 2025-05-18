"""Bluetooth Low Energy sniffing classes used by `wsniff` for generic
sniffing.
"""
from dataclasses import dataclass, field

from whad.ble.exceptions import InvalidAccessAddressException
from whad.ble.utils.phy import is_access_address_valid
from whad.common.sniffing import SniffingEvent
from whad.hub.ble import ChannelMap

@dataclass
class SynchronizedConnection:
    """Synchronized connection data class.
    """
    access_address : int = None
    crc_init : int = None
    hop_interval : int = None
    hop_increment : int = None
    channel_map : ChannelMap = None

class ConnectionConfiguration(SynchronizedConnection):
    """
    Configuration for sniffing an existing Bluetooth Low Energy.

    :param access_address: indicate access address of the targeted connection (aa)
    :param crc_init: indicate CRCInit of the targeted connection (crc)
    :param hop_interval: indicate Hop Interval of the targeted connection (int)
    :param hop_increment: indicate Hop Increment of the targeted connection (inc)
    :param channel_map: indicate Channel Map of the targeted connection (chm)
    """

class SynchronizationEvent(SniffingEvent):
    """Synchronization event
    """

    def __init__(self, connection):
        super().__init__("Connection synchronized")
        self.synchronized_connection = connection

    @property
    def message(self):
        """Readable representation of this event
        """
        return (
            f"access_address=0x{self.synchronized_connection.access_address:08x}, "
            f"crc_init=0x{self.synchronized_connection.crc_init:06x}, "
            f"hop_interval={self.synchronized_connection.hop_interval} "
            f"({self.synchronized_connection.hop_interval*1250} us), "
            f"hop_increment={self.synchronized_connection.hop_increment}, "
            f"channel_map=0x{self.synchronized_connection.channel_map.value.hex()}"
        )


class DesynchronizationEvent(SniffingEvent):
    """Event indicating a desynchronization
    """
    def __init__(self):
        super().__init__("Connection desynchronized")



class KeyExtractedEvent(SniffingEvent):
    """Event indicating that a key has been extracted from pairing
    """
    def __init__(self, key):
        super().__init__("Key extracted")
        self.key = key

    @property
    def message(self):
        return f"key={self.key.hex()}"

@dataclass
class SnifferConfiguration:
    """
    Configuration for the Bluetooth Low Energy sniffer.

    :param show_advertisements: enable advertisement sniffing (a)
    :param follow_connection: enable new connection sniffing (f)
    :param show_empty_packets: display empty packets during connection (e)
    :param access_addresses_discovery: discover access addresses of existing connections
    :param pairing: perform attack on legacy pairing (p)
    :param active_connection: enable and configure existing connection sniffing
    :param channel: select the channel to sniff (c)
    :param filter: display only the packets matching the filter BD address (m)
    :param decrypt: indicate if decryption is enabled (d)
    :param keys: provide decryption keys (k)
    """
    show_advertisements : bool = True
    follow_connection : bool = False
    show_empty_packets : bool = False
    access_addresses_discovery : bool = False
    pairing : bool = False
    active_connection : ConnectionConfiguration = None
    channel : int = 37
    filter : str = "FF:FF:FF:FF:FF:FF"
    decrypt : bool = False
    keys : list = field(default_factory=lambda: [])

class AccessAddress:
    """Bluetooth connection Access Address.
    """

    def __init__(self, access_address, timestamp=None, rssi=None):
        if not is_access_address_valid(access_address):
            raise InvalidAccessAddressException()

        self.__access_address = access_address
        self.__timestamp = timestamp
        self.__rssi = rssi
        self.__count = 1

    def __int__(self) -> int:
        """Integer conversion
        """
        return self.__access_address

    def __eq__(self, other) -> bool:
        """Compare two access addresses.
        """
        return int(other) == int(self)

    def update(self, timestamp=None, rssi=None):
        """Update access address RSSI and timestamp, and
        increment the internal counter for statistics.
        """
        self.__count += 1
        if timestamp is not None:
            self.__timestamp = timestamp
        if rssi is not None:
            self.__rssi = rssi

    @property
    def last_timestamp(self) -> int:
        """Last seen timestamp
        """
        return self.__timestamp

    @property
    def last_rssi(self) -> int:
        """Last RSSI
        """
        return self.__rssi

    @property
    def count(self) -> int:
        """Current count
        """
        return self.__count

    def __repr__(self) -> str:
        """String representation
        """
        rssi = self.__rssi if self.__rssi is not None else ""
        timestamp = self.__timestamp if self.__timestamp is not None else ""
        printable_string =  (
            f"0x{self.__access_address:08x} (seen {self.count} times), "
            f"rssi = {rssi}, last_timestamp = {timestamp})"
        )
        return printable_string
