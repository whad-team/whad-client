from whad.ble.exceptions import InvalidAccessAddressException
from dataclasses import dataclass, field
from whad.ble.utils.phy import is_access_address_valid
from whad.common.sniffing import SniffingEvent

@dataclass
class SynchronizedConnection:
    access_address : int = None
    crc_init : int = None
    hop_interval : int = None
    hop_increment : int = None
    channel_map : bytes = None

class ConnectionConfiguration(SynchronizedConnection):
    """
    Configuration for sniffing an existing Bluetooth Low Energy.

    :param access_address: indicate access address of the targeted connection (aa)
    :param crc_init: indicate CRCInit of the targeted connection (crc)
    :param hop_interval: indicate Hop Interval of the targeted connection (int)
    :param hop_increment: indicate Hop Increment of the targeted connection (inc)
    :param channel_map: indicate Channel Map of the targeted connection (chm)
    """
    pass

class SynchronizationEvent(SniffingEvent):
    def __init__(self, connection):
        super().__init__("Connection synchronized")
        self.synchronized_connection = connection

    @property
    def message(self):
        return "access_address={}, crc_init={}, hop_interval={} ({} us), hop_increment={}, channel_map={}".format(
                    "0x{:08x}".format(self.synchronized_connection.access_address),
                    "0x{:06x}".format(self.synchronized_connection.crc_init),
                    str(self.synchronized_connection.hop_interval), str(self.synchronized_connection.hop_interval*1250),
                    str(self.synchronized_connection.hop_increment),
                    "0x"+self.synchronized_connection.channel_map.hex()
        )


class DesynchronizationEvent(SniffingEvent):
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
        return "key={}".format(self.key.hex())

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
    def __init__(self, access_address, timestamp=None, rssi=None):
        if not is_access_address_valid(access_address):
            raise InvalidAccessAddressException()

        self.__access_address = access_address
        self.__timestamp = timestamp
        self.__rssi = rssi
        self.__count = 1

    def __int__(self):
        return self.__access_address

    def __eq__(self, other):
        return int(other) == int(self)

    def update(self, timestamp=None, rssi=None):
        self.__count += 1
        if timestamp is not None:
            self.__timestamp = timestamp
        if rssi is not None:
            self.__rssi = rssi

    @property
    def last_timestamp(self):
        return self.__timestamp

    @property
    def last_rssi(self):
        return self.__rssi

    @property
    def count(self):
        return self.__count

    def __repr__(self):
        printable_string =  ("0x{:08x}".format(self.__access_address) +
                            " (seen "+str(self.__count)+" times" +
                            (", rssi = "+str(self.__rssi) if self.__rssi is not None else "") +
                            (", last_timestamp = "+str(self.__timestamp) if self.__timestamp is not None else "") +
                            ")")
        return printable_string
