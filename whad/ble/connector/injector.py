from whad.ble.connector import BLE
from whad.ble.exceptions import ConnectionLostException, NotSynchronized
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

        # Check if device accepts injection
        if not self.can_inject():
            raise UnsupportedCapability("Inject")

        self.__configuration = InjectionConfiguration()


    def _enable_configuration(self):
        if self.__configuration.synchronize:
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
                if self.__configuration.channel is not None:
                    channel = self.__configuration.channel
                else:
                    channel = 37 # fallback
                self.sniff_new_connection(
                    channel=channel,
                    show_advertisements=False,
                    show_empty_packets=False,
                    bd_address=self.__configuration.filter
                )
            self.start()
            while not self.__synchronized:
                sleep(1)
            return True
        return True

    def configure(self, active_connection=None, synchronize=False, channel=37, filter="FF:FF:FF:FF:FF:FF"):
        self.stop()
        self.__configuration.active_connection = active_connection if active_connection is not None else None
        self.__configuration.synchonize = synchronize
        self.__configuration.channel = channel
        self.__configuration.filter = filter
        self._enable_configuration()


    @property
    def configuration(self):
        return self.__configuration

    @configuration.setter
    def configuration(self, new_configuration):
        self.stop()
        self.__configuration = new_configuration
        self._enable_configuration()

    def inject(self, packet):
        if self.__configuration.raw:
            return self.raw_inject(packet)
        elif self.__configuration.inject_to_slave:
            return self.inject_to_slave(packet)
        elif self.__configuration.inject_to_master:
            return self.inject_to_master(packet)
        else:
            return False

    def raw_inject(self, packet):
        """
        Inject a raw packet directly, according to the channel provided in configuration or metadata.
        """
        if BTLE in packet:
            access_address = packet.access_addr
        elif BTLE_ADV in packet:
            access_address = 0x8e89bed6
        elif BTLE_DATA in packet:
            if self.__connection is not None:
                access_address = self.__connection.access_address
            else:
                access_address = 0x11223344 # default value

        if self.__configuration.channel is not None:
            channel = self.__configuration.channel
        if hasattr(packet, "metadata") and hasattr(packet.metadata, "channel"):
            channel = packet.metadata.channel
        else:
            channel = 37 # fallback to channel 37

        return self.send_pdu(packet, access_address=access_address, conn_handle=channel, direction=BleDirection.UNKNOWN)

    def inject_to_slave(self, packet):
        if self.__connection is not None:
            self.send_pdu(packet, access_address=self.__connection.access_address, direction=BleDirection.INJECTION_TO_SLAVE)
            message = self.wait_for_message(filter=message_filter(Injected))
            return (message.success, message.injection_attempts)
        else:
            raise NotSynchronized()

    def inject_to_master(self, packet):
        if self.__connection is not None:
            self.send_pdu(packet, access_address=self.__connection.access_address, direction=BleDirection.INJECTION_TO_MASTER)
            message = self.wait_for_message(filter=message_filter(Injected))
            return (message.success, message.injection_attempts)
        else:
            raise NotSynchronized()


    def on_synchronized(self, access_address=None, crc_init=None, hop_increment=None, hop_interval=None, channel_map=None):
        self.__connection = SynchronizedConnection(
            access_address = access_address,
            crc_init = crc_init,
            hop_increment = hop_increment,
            hop_interval = hop_interval,
            channel_map = channel_map
        )
        self.__synchronized = True

    def on_desynchronized(self, access_address):
        if access_address == self.__connection.access_address:
            self.__synchronized = False
            self.__connection = None
