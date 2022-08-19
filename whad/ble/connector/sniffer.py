from dataclasses import dataclass
from whad.ble.exceptions import InvalidAccessAddressException
from whad.ble.connector import BLE, Injector, Hijacker
from whad.ble.utils.phy import is_access_address_valid
from whad.ble import UnsupportedCapability, message_filter

@dataclass
class SynchronizedConnection:
    access_address : int = None
    crc_init : int = None
    hop_interval : int = None
    hop_increment : int = None
    channel_map : int = None

@dataclass
class SnifferConfiguration:
    show_advertisements : bool = True
    follow_connection : bool = False
    show_empty_packets : bool = False
    access_addresses_discovery : bool = False
    channel : int = 37
    filter : str = "FF:FF:FF:FF:FF:FF"

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



class Sniffer(BLE):
    """
    BLE Sniffer interface for compatible WHAD device.
    """
    def __init__(self, device):
        super().__init__(device)
        self.__synchronized = False
        self.__connection = None
        self.__access_addresses = {}
        self.__configuration = SnifferConfiguration()

        # Check if device accepts advertisements or connection sniffing
        if not self.can_sniff_advertisements() and not self.can_sniff_new_connection():
            raise UnsupportedCapability("Sniff")

    def is_synchronized(self):
        return self.__synchronized

    @property
    def access_address(self):
        if self.__connection is None:
            return 0x8e89bed6
        else:
            return self.__connection.access_address

    @property
    def crc_init(self):
        if self.__connection is None:
            return 0x555555
        else:
            return self.__connection.crc_init

    @property
    def hop_interval(self):
        if self.__connection is None:
            return None
        else:
            return self.__connection.hop_interval

    @property
    def hop_increment(self):
        if self.__connection is None:
            return None
        else:
            return self.__connection.hop_interval

    @property
    def channel_map(self):
        if self.__connection is None:
            return None
        else:
            return self.__connection.channel_map

    def on_synchronized(self, access_address=None, crc_init=None, hop_increment=None, hop_interval=None, channel_map=None):
        self.__synchronized = True
        self.__connection = SynchronizedConnection(
            access_address = access_address,
            crc_init = crc_init,
            hop_increment = hop_increment,
            hop_interval = hop_interval,
            channel_map = channel_map
        )
        print("[sniffer] Connection synchronized -> access_address={}, crc_init={}, hop_interval={} ({} us), hop_increment={}, channel_map={}.".format(
                    "0x{:08x}".format(self.__connection.access_address),
                    "0x{:06x}".format(self.__connection.crc_init),
                    str(self.__connection.hop_interval), str(self.__connection.hop_interval*1250),
                    str(self.__connection.hop_increment),
                    "0x"+self.__connection.channel_map.hex()
        ))

    def on_desynchronized(self, access_address=None):
        self.__synchronized = False
        self.__connection = None
        print("[sniffer] Connection lost.")

    def _enable_sniffing(self):
        if self.__configuration.access_addresses_discovery:
            self.discover_access_addresses()

        elif self.__configuration.follow_connection:
            if not self.can_sniff_new_connection():
                raise UnsupportedCapability("Sniff")
            else:
                self.sniff_new_connection(
                    channel=self.__configuration.channel,
                    show_advertisements=self.__configuration.show_advertisements,
                    show_empty_packets=self.__configuration.show_empty_packets,
                    bd_address=self.__configuration.filter
                )
        elif self.__configuration.show_advertisements:
            if not self.can_sniff_advertisements():
                raise UnsupportedCapability("Sniff")
            else:
                self.sniff_advertisements(
                    channel=self.__configuration.channel,
                    bd_address=self.__configuration.filter
                )


    def configure(self, access_addresses_discovery=False, advertisements=True, connection=True, empty_packets=False):
        self.stop()
        self.__configuration.access_addresses_discovery = access_addresses_discovery
        self.__configuration.show_advertisements = advertisements
        self.__configuration.show_empty_packets = empty_packets
        self.__configuration.follow_connection = connection
        self._enable_sniffing()

    @property
    def filter(self):
        return self.__configuration.filter.upper()

    @filter.setter
    def set_filter(self, address="FF:FF:FF:FF:FF:FF"):
        self.stop()
        self.__configuration.filter = address.upper()
        self._enable_sniffing()

    @property
    def channel(self):
        return self.__configuration.channel

    @channel.setter
    def set_channel(self, channel=37):
        self.stop()
        self.__configuration.channel = channel
        self._enable_sniffing()


    def available_actions(self, filter=None):
        actions = []
        if self.__synchronized:
            if self.can_inject():
                actions.append(Injector(self.device, connection=self.__connection))

            if self.can_hijack_both() or self.can_hijack_slave() or self.can_hijack_master():
                actions.append(Hijacker(self.device, connection=self.__connection))

            return [action for action in actions if filter is None or isinstance(action, filter)]

    def sniff(self):
        while True:
            if self.__configuration.access_addresses_discovery:
                message = self.wait_for_message(filter=message_filter('ble', "aa_disc"))
                rssi = None
                timestamp = None
                if message.ble.aa_disc.HasField("rssi"):
                    rssi = message.ble.aa_disc.rssi
                if message.ble.aa_disc.HasField("timestamp"):
                    timestamp = message.ble.aa_disc.timestamp
                aa = message.ble.aa_disc.access_address

                if aa not in self.__access_addresses:
                    self.__access_addresses[aa] = AccessAddress(aa, timestamp=timestamp, rssi=rssi)
                else:
                    self.__access_addresses[aa].update(timestamp=timestamp, rssi=rssi)
                yield self.__access_addresses[aa]
            else:
                if self.support_raw_pdu():
                    message_type = "raw_pdu"
                elif self.__synchronized:
                    message_type = "pdu"
                else:
                    message_type = "adv_pdu"

                message = self.wait_for_message(filter=message_filter('ble', message_type))
                yield self._build_scapy_packet_from_message(message.ble, message_type)
