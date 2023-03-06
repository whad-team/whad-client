from whad.ble.connector import BLE, Injector, Hijacker
from whad.ble.utils.phy import is_access_address_valid
from whad.ble.sniffing import SynchronizedConnection, SnifferConfiguration, AccessAddress
from whad.ble import UnsupportedCapability, message_filter

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

        elif self.__configuration.active_connection is not None:
            access_address = self.__configuration.active_connection.access_address
            crc_init = self.__configuration.active_connection.crc_init
            channel_map = self.__configuration.active_connection.channel_map
            hop_interval = self.__configuration.active_connection.hop_interval
            hop_increment = self.__configuration.active_connection.hop_increment

            self.sniff_active_connection(access_address, crc_init, channel_map, hop_interval, hop_increment)

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


    @property
    def configuration(self):
        return self.__configuration

    @configuration.setter
    def configuration(self, new_configuration):
        self.stop()
        self.__configuration = new_configuration
        self._enable_sniffing()

    def configure(self, active_connection=None, access_addresses_discovery=False, advertisements=True, connection=True, empty_packets=False):
        self.stop()
        self.__configuration.active_connection = active_connection if active_connection is not None else None
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
    def channel(self, channel=37):
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

            elif self.__configuration.active_connection is not None:
                message = self.wait_for_message(filter=message_filter('ble', "synchronized"))
                print(message)
                # TODO : improve the switch
                if message.ble.synchronized.hop_increment > 0:
                    if self.support_raw_pdu():
                        message_type = "raw_pdu"
                    elif self.__synchronized:
                        message_type = "pdu"
                    else:
                        message_type = "adv_pdu"

                    message = self.wait_for_message(filter=message_filter('ble', message_type))
                    yield self.translator.from_message(message.ble, message_type)

            else:
                if self.support_raw_pdu():
                    message_type = "raw_pdu"
                elif self.__synchronized:
                    message_type = "pdu"
                else:
                    message_type = "adv_pdu"

                message = self.wait_for_message(filter=message_filter('ble', message_type))
                yield self.translator.from_message(message.ble, message_type)
