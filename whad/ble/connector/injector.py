from whad.ble.connector import BLE
from whad.ble.exceptions import ConnectionLostException
from whad.ble import UnsupportedCapability, message_filter, BleDirection
from whad.hub.ble import Injected, Synchronized
from whad.ble.sniffing import SynchronizedConnection
from whad.ble.injecting import InjectionConfiguration
from scapy.layers.bluetooth4LE import BTLE, BTLE_ADV, BTLE_DATA
from time import sleep

class Injector(BLE):

    def __init__(self, device, connection=None):
        super().__init__(device)
        self.__connection = connection
        self.__synchronized = connection is not None
        self.__exception = None
        # Check if device accepts injection
        if not self.can_inject():
            raise UnsupportedCapability("Inject")

        self.__configuration = InjectionConfiguration()


    def _enable_configuration(self):
        if self.__configuration.synchonize:
            if self.__configuration.active_connection is not None:
                if not self.can_sniff_active_connection():
                    raise UnsupportedCapability("Sniff")
                # if active connection has been provided, synchronize according to parameters
                access_address = self.__configuration.active_connection.access_address
                crc_init = self.__configuration.active_connection.crc_init
                channel_map = self.__configuration.active_connection.channel_map
                hop_interval = self.__configuration.active_connection.hop_interval
                hop_increment = self.__configuration.active_connection.hop_increment
                self.sniff_active_connection(access_address, crc_init, channel_map, hop_interval, hop_increment)
            else:
                if not self.can_sniff_new_connection():
                    raise UnsupportedCapability("Sniff")

                self.sniff_new_connection(
                    channel=self.__configuration.channel,
                    show_advertisements=False,
                    show_empty_packets=False,
                    bd_address=self.__configuration.filter
                )
            self.start()
            while not self.__synchronized:
                sleep(0.1)
            return True
        return True

    def configure(self, active_connection=None, synchronize=False, channel=37, filter="FF:FF:FF:FF:FF:FF"):
        self.stop()
        self.__configuration.active_connection = active_connection if active_connection is not None else None
        self.__configuration.synchonize = synchronize
        self.__configuration.channel = channel
        self.__configuration.filter = filter
        self._enable_configuration()


    def raw_inject(self, packet):
        if BTLE in packet:
            access_address = packet.access_addr
        elif BTLE_ADV in packet:
            access_address = 0x8e89bed6
        elif BTLE_DATA in packet:
            if self.__connection is not None:
                access_address = self.__connection.access_address
            else:
                access_address = 0x11223344 # default value

        return self.send_pdu(packet, access_address=access_address, conn_handle=channel, direction=BleDirection.UNKNOWN)

    def inject_to_slave(self, packet):
        if self.__connection is not None:
            self.send_pdu(packet, access_address=self.__connection.access_address, direction=BleDirection.INJECTION_TO_SLAVE)
            message = self.wait_for_message(filter=message_filter(Injected))
            return (message.success, message.injection_attempts)
        else:
            raise self.__exception

    def inject_to_master(self, packet):
        if self.__connection is not None:
            self.send_pdu(packet, access_address=self.__connection.access_address, direction=BleDirection.INJECTION_TO_MASTER)
            message = self.wait_for_message(filter=message_filter(Injected))
            return (message.success, message.injection_attempts)
        else:
            raise self.__exception


    def on_synchronized(self, access_address=None, crc_init=None, hop_increment=None, hop_interval=None, channel_map=None):
        self.__connection = SynchronizedConnection(
            access_address = access_address,
            crc_init = crc_init,
            hop_increment = hop_increment,
            hop_interval = hop_interval,
            channel_map = channel_map
        )
        self.__synchronized = True
        print("Connection synchronized -> access_address={}, crc_init={}, hop_interval={} ({} us), hop_increment={}, channel_map={}.".format(
                    "0x{:08x}".format(self.__connection.access_address),
                    "0x{:06x}".format(self.__connection.crc_init),
                    str(self.__connection.hop_interval), str(self.__connection.hop_interval*1250),
                    str(self.__connection.hop_increment),
                    "0x"+self.__connection.channel_map.hex()
        ))

    def on_desynchronized(self, access_address):
        if access_address == self.__connection.access_address:
            self.__exception = ConnectionLostException(self.__connection)
            self.__synchronized = False
            self.__connection = None
