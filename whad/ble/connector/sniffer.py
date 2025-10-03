"""Bluetooth Low Energy sniffing module.
"""
import logging
from typing import List, Generator
from time import sleep, time

from scapy.packet import Packet
from scapy.layers.bluetooth4LE import BTLE_DATA, BTLE

from whad.hub.ble import AccessAddressDiscovered, Synchronized, BleRawPduReceived, \
    BlePduReceived, BleAdvPduReceived

from whad.exceptions import WhadDeviceDisconnected, UnsupportedCapability, WhadDeviceNotReady
from whad.helpers import message_filter
from whad.common.sniffing import EventsManager

from .base import BLE
from .injector import Injector
from .hijacker import Hijacker
from ..exceptions import MissingCryptographicMaterial
from ..sniffing import SynchronizedConnection, SnifferConfiguration, AccessAddress, \
    SynchronizationEvent, DesynchronizationEvent, KeyExtractedEvent
from ..crypto import EncryptedSessionInitialization, LinkLayerDecryptor, \
    LegacyPairingCracking

logger = logging.getLogger(__name__)

class Sniffer(BLE, EventsManager):
    """
    BLE Sniffer interface for compatible WHAD device.
    """

    def __init__(self, device):
        BLE.__init__(self, device)
        EventsManager.__init__(self)
        self.__synchronized = False
        self.__connection = None
        self.__access_addresses = {}
        self.__decryptor = LinkLayerDecryptor()
        self.__encrypted_session_initialization = EncryptedSessionInitialization()
        self.__legacy_pairing_cracking = LegacyPairingCracking()
        self.__configuration = SnifferConfiguration()

        # Check if device accepts advertisements or connection sniffing
        if not self.can_sniff_advertisements() and not self.can_sniff_new_connection():
            raise UnsupportedCapability("Sniff")

    def __enter__(self) -> 'Sniffer':
        """Special method used for context management."""
        if not self.started:
            if not self.start():
                raise WhadDeviceNotReady()
        return self

    def __exit__(self, exc_type, exc_val, exc_traceback):
        """Special method used for context management."""
        if self.started:
            if not self.stop():
                raise WhadDeviceNotReady()

    @property
    def synchronized(self):
        """Synchromization state
        """
        return self.__synchronized

    def wait_new_connection(self, address="FF:FF:FF:FF:FF:FF"):
        """Wait for synchronization on a new connection.
        """
        self.filter = address
        self.configure(advertisements=False, connection=True)
        self.start()
        while not self.synchronized:
            sleep(0.01)
        return self.__connection

    @property
    def access_address(self):
        """Access address
        """
        if self.__connection is None:
            return 0x8e89bed6
        return self.__connection.access_address

    @property
    def crc_init(self):
        """CRC seed value
        """
        if self.__connection is None:
            return 0x555555
        return self.__connection.crc_init

    @property
    def hop_interval(self):
        """Hop interval value
        """
        if self.__connection is None:
            return None
        return self.__connection.hop_interval

    @property
    def hop_increment(self):
        """Hop increment value
        """
        if self.__connection is None:
            return None
        return self.__connection.hop_interval

    @property
    def channel_map(self):
        """Channel map in use
        """
        if self.__connection is None:
            return None
        return self.__connection.channel_map

    def on_synchronized(self, access_address=None, crc_init=None, hop_increment=None,
                        hop_interval=None, channel_map=None):
        """Synchronization callback
        """
        self.__synchronized = True
        self.__connection = SynchronizedConnection(
            access_address = access_address,
            crc_init = crc_init,
            hop_increment = hop_increment,
            hop_interval = hop_interval,
            channel_map = channel_map
        )
        self.trigger_event(SynchronizationEvent(self.__connection))
        logger.info(("Connection synchronized -> access_address=0x%08x,"
                     " crc_init=0x%06x, hop_interval=%d (%d us)"
                     "hop_increment=%d, channel_map=0x%s"),
                    self.__connection.access_address,
                    self.__connection.crc_init,
                    self.__connection.hop_interval,
                    self.__connection.hop_interval*1250,
                    self.__connection.hop_increment,
                    self.__connection.channel_map.value.hex())

    def on_desynchronized(self, access_address=None):
        """Desynchronization callback
        """
        self.__synchronized = False
        self.__connection = None
        self.trigger_event(DesynchronizationEvent())
        logger.info("Connection lost.")

    def _enable_sniffing(self):
        """Enable sniffing
        """
        for key in self.__configuration.keys:
            self.__decryptor.add_key(key)

        if self.__configuration.access_addresses_discovery:
            self.discover_access_addresses()

        elif self.__configuration.active_connection is not None:

            access_address = self.__configuration.active_connection.access_address
            crc_init = self.__configuration.active_connection.crc_init
            channel_map = self.__configuration.active_connection.channel_map
            hop_interval = self.__configuration.active_connection.hop_interval
            hop_increment = self.__configuration.active_connection.hop_increment
            self.sniff_active_connection(access_address, crc_init, channel_map,
                                         hop_interval, hop_increment)

        elif self.__configuration.follow_connection:
            for key in self.__configuration.keys:
                self.__decryptor.add_key(key)

            if not self.can_sniff_new_connection():
                raise UnsupportedCapability("Sniff")

            self.sniff_new_connection(
                channel=self.__configuration.channel,
                show_advertisements=self.__configuration.show_advertisements,
                show_empty_packets=self.__configuration.show_empty_packets,
                bd_address=self.__configuration.filter
            )
        elif self.__configuration.show_advertisements:
            if not self.can_sniff_advertisements():
                raise UnsupportedCapability("Sniff")

            self.sniff_advertisements(
                channel=self.__configuration.channel,
                bd_address=self.__configuration.filter
            )


    def add_key(self, key):
        """Add known encryption key to configured keys
        """
        self.stop()
        self.__configuration.keys.append(key)
        self._enable_sniffing()

    def clear_keys(self):
        """Clear known keys
        """
        self.stop()
        self.__configuration.keys = []
        self._enable_sniffing()

    @property
    def decrypt(self) -> bool:
        """Automatic decryption status
        """
        return self.__configuration.decrypt

    @decrypt.setter
    def decrypt(self, decrypt):
        self.stop()
        self.__configuration.decrypt = decrypt
        self._enable_sniffing()

    @property
    def configuration(self):
        """Sniffing configuration
        """
        return self.__configuration

    @configuration.setter
    def configuration(self, new_configuration):
        self.stop()
        self.__configuration = new_configuration
        self._enable_sniffing()

    def configure(self, active_connection=None, access_addresses_discovery=False,
                  advertisements=True, connection=True, empty_packets=False):
        """Configure sniffer
        """
        self.stop()
        self.__configuration.active_connection = active_connection
        self.__configuration.access_addresses_discovery = access_addresses_discovery
        self.__configuration.show_advertisements = advertisements
        self.__configuration.show_empty_packets = empty_packets
        self.__configuration.follow_connection = connection
        self._enable_sniffing()

    @property
    def filter(self):
        """BD address filter
        """
        return self.__configuration.filter.upper()

    @filter.setter
    def filter(self, address="FF:FF:FF:FF:FF:FF"):
        self.stop()
        self.__configuration.filter = address.upper()
        self._enable_sniffing()

    @property
    def channel(self):
        """BLE channel number
        """
        return self.__configuration.channel

    @channel.setter
    def channel(self, channel=37):
        self.stop()
        self.__configuration.channel = channel
        self._enable_sniffing()


    def available_actions(self, action_filter=None) -> List[BLE]:
        """Determine the actions available once synchronized with a connection.
        """
        actions = []
        if self.__synchronized:
            if self.can_inject():
                actions.append(Injector(self.device, connection=self.__connection))

            if self.can_hijack_both() or self.can_hijack_slave() or self.can_hijack_master():
                actions.append(Hijacker(self.device, connection=self.__connection))

            return [action for action in actions
                    if action_filter is None or isinstance(action, action_filter)]

        # No action available
        return []

    def process_packet(self, packet):
        """Process sniffed packet
        """
        if self.__configuration.decrypt and BTLE_DATA in packet:
            self.__encrypted_session_initialization.process_packet(packet)
            if self.__encrypted_session_initialization.encryption:
                self.__decryptor.add_crypto_material(
                    *self.__encrypted_session_initialization.crypto_material
                )
                self.__encrypted_session_initialization.reset()
            try:
                decrypted, success = self.__decryptor.attempt_to_decrypt(packet[BTLE])
                if success:
                    #packet.decrypted = decrypted
                    decrypted_packet = decrypted
                    decrypted_packet.metadata = packet.metadata
                    packet[BTLE_DATA].remove_payload()
                    packet.payload = decrypted
                    packet.metadata = decrypted_packet.metadata
                    packet.metadata.decrypted = True
                    return packet
            except MissingCryptographicMaterial:
                pass


        if self.__configuration.pairing:
            self.__legacy_pairing_cracking.process_packet(packet[BTLE])
            if self.__legacy_pairing_cracking.ready:
                keys = self.__legacy_pairing_cracking.keys
                if keys is not None:
                    tk, stk = keys
                    logger.info("[i] New temporary key extracted: %s", tk.hex())
                    logger.info("[i] New short term key extracted: %s", stk.hex())
                    self.trigger_event(KeyExtractedEvent(stk))
                    self.__decryptor.add_key(stk)
                    self.__legacy_pairing_cracking.reset()

        return packet

    def sniff(self, timeout: float = None) -> Generator[Packet, None, None]:
        """Main sniffing function

        :param timeout: Number of seconds after which sniffing is stopped.
                        Wait forever if set to `None`.
        :type timeout: float
        """
        # Start hardware interface if not started
        if not self.started:
            if not self.start():
                raise WhadDeviceNotReady()
            stop_on_exit = True
        else:
            stop_on_exit = False

        start = time()
        try:
            if self.__configuration.access_addresses_discovery:
                for message in super().sniff(messages=(AccessAddressDiscovered), timeout=timeout):
                    if message is not None:
                        rssi = None
                        timestamp = None
                        if message.rssi:
                            rssi = message.rssi
                        if message.timestamp:
                            timestamp = message.timestamp
                        aa = message.access_address

                        if aa not in self.__access_addresses:
                            self.__access_addresses[aa] = AccessAddress(
                                aa, timestamp=timestamp,
                                rssi=rssi
                            )
                        else:
                            self.__access_addresses[aa].update(timestamp=timestamp, rssi=rssi)
                        yield self.__access_addresses[aa]

                    # Enforce timeout
                    if timeout is not None and (time() - start) > timeout:
                        break

            elif self.__configuration.active_connection is not None:
                message = self.wait_for_message(keep=message_filter(Synchronized),
                                                timeout=0.1)

                if message is not None:
                    if message.hop_increment > 0:
                        if self.support_raw_pdu():
                            message_type = BleRawPduReceived
                        elif self.__synchronized:
                            message_type = BlePduReceived
                        else:
                            message_type = BleAdvPduReceived

                        for message in super().sniff(messages=(message_type), timeout=timeout):
                            if message is not None:
                                packet = message.to_packet()
                                if packet is not None:
                                    self.monitor_packet_rx(packet)
                                    yield packet

                            # Enforce timeout
                            if timeout is not None and (time() - start) > timeout:
                                break

            else:
                if self.support_raw_pdu():
                    message_type = BleRawPduReceived
                elif self.__synchronized:
                    message_type = BlePduReceived
                else:
                    message_type = BleAdvPduReceived

                for message in super().sniff(messages=(message_type), timeout=timeout):
                    if message is not None:
                        packet = message.to_packet()
                        if packet is not None:
                            packet = self.process_packet(packet)
                            self.monitor_packet_rx(packet)
                            yield packet

                    # Enforce timeout
                    if timeout is not None and (time() - start) > timeout:
                        break


        # Handle device disconnection
        except WhadDeviceDisconnected:
            return

        # Stop current mode if we started it in the first place
        if stop_on_exit:
            if not self.stop():
                raise WhadDeviceNotReady()
