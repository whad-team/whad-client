import struct
import logging

from queue import Queue, Empty

# Scapy
from scapy.layers.bluetooth4LE import BTLE, BTLE_ADV, BTLE_DATA, BTLE_ADV_IND, \
    BTLE_ADV_NONCONN_IND, BTLE_ADV_DIRECT_IND, BTLE_ADV_SCAN_IND, BTLE_SCAN_RSP, \
    BTLE_RF, BTLE_CTRL
from scapy.compat import raw
from scapy.packet import Packet

# Device interface
from whad.device import WhadDeviceConnector
from whad import WhadDomain, WhadCapability
from whad.exceptions import UnsupportedDomain, UnsupportedCapability

# Old protocol stuff (to remove)
from whad.protocol.generic_pb2 import ResultCode

# Protocol hub
from whad.helpers import message_filter
from whad.hub.generic.cmdresult import Success, CommandResult
from whad.hub.ble.bdaddr import BDAddress
from whad.hub.ble.chanmap import ChannelMap
from whad.hub.ble import Commands, AdvType, Direction, BleAdvPduReceived, BlePduReceived, \
    BleRawPduReceived, Synchronized, Desynchronized, Connected, Disconnected, Triggered

# Bluetooth Low Energy dependencies
from whad.common.triggers import ManualTrigger, ConnectionEventTrigger, ReceptionTrigger
from whad.ble.metadata import BLEMetadata
from whad.ble.connector.translator import BleMessageTranslator
from whad.ble.profile.advdata import AdvDataFieldList
from whad.ble.exceptions import ConnectionLostException

# Logging
logger = logging.getLogger(__name__)

class BLE(WhadDeviceConnector):
    """
    BLE protocol connector.

    This connector drives a BLE-capable device with BLE-specific WHAD messages.
    It is required by various role classes to interact with a real device and pre-process
    domain-specific messages.
    """
    domain = "ble"

    # correlation table
    SCAPY_CORR_ADV = {
        AdvType.ADV_IND: BTLE_ADV_IND,
        AdvType.ADV_NONCONN_IND: BTLE_ADV_NONCONN_IND,
        AdvType.ADV_DIRECT_IND: BTLE_ADV_DIRECT_IND,
        AdvType.ADV_SCAN_IND: BTLE_ADV_SCAN_IND,
        AdvType.ADV_SCAN_RSP: BTLE_SCAN_RSP
    }

    def format(self, packet):
        """
        Converts a scapy packet with its metadata to a tuple containing a scapy packet with
        the appropriate header and the timestamp in microseconds.
        """
        return self.translator.format(packet)


    def __init__(self, device=None, synchronous=False):
            """
            Initialize the connector, open the device (if not already opened), discover
            the services (if not already discovered).

            If `auto` is set to False, PDUs must be processed manually and
            won't be forwarded to PDU-related callbacks.
            """
            self.__ready = False
            super().__init__(device)

            # Capability cache
            self.__can_send = None
            self.__can_send_raw = None

            # Link-layer encryption
            self.__encrypted = False

            # List of active triggers
            self.__triggers = []

            # Open device and make sure it is compatible
            self.device.open()
            self.device.discover()

            # Check device supports BLE
            if not self.device.has_domain(WhadDomain.BtLE):
                raise UnsupportedDomain()
            else:
                self.__ready = True

            # Initialize translator
            self.translator = BleMessageTranslator(self.hub)

            # Set synchronous mode if provided
            self.enable_synchronous(synchronous)

    def close(self):
        self.device.close()

    def support_raw_pdu(self):
        """
        Determine if the device supports raw PDU.
        """
        if self.__can_send_raw is None:
            capabilities = self.device.get_domain_capability(WhadDomain.BtLE)
            self.__can_send_raw = not (capabilities & WhadCapability.NoRawData)
        return self.__can_send_raw

    def is_ll_encrypted(self):
        """Determine if the link-layer is encrypted.

        :return: True if link-layer is encrypted, False otherwise
        :rtype: bool
        """

    def can_send(self):
        """
        Determine if the device is able to send PDU
        """
        if self.__can_send is None:
            # Retrieve supported commands
            commands = self.device.get_domain_commands(WhadDomain.BtLE)
            self.__can_send = ((commands & (1 << Commands.SendPDU))>0 or (commands & (1 << Commands.SendRawPDU)))
        return self.__can_send

    def can_scan(self):
        """
        Determine if the device implements a scanner mode.
        """
        # Retrieve supported commands
        commands = self.device.get_domain_commands(WhadDomain.BtLE)
        return (
            (commands & (1 << Commands.ScanMode))>0 and
            (commands & (1 << Commands.Start))>0 and
            (commands & (1 << Commands.Stop))>0
        )

    def can_connect(self):
        """
        Determine if the device can establish a connection as central.
        """
        # Retrieve supported commands
        commands = self.device.get_domain_commands(WhadDomain.BtLE)
        return (commands & (1 << Commands.ConnectTo))>0

    def can_jam_advertisement_on_channel(self):
        """
        Determine if the device can jam advertisements on a specific channel.
        """
        # Retrieve supported commands
        commands = self.device.get_domain_commands(WhadDomain.BtLE)
        return (commands & (1 << Commands.JamAdvOnChannel))>0

    def can_be_central(self):
        """
        Determine if the device implements a central mode.
        """
        # Retrieve supported commands
        commands = self.device.get_domain_commands(WhadDomain.BtLE)
        return (
            (commands & (1 << Commands.CentralMode))>0 and
            (commands & (1 << Commands.Start))>0 and
            (commands & (1 << Commands.Stop))>0
        )

    def can_be_peripheral(self):
        """
        Determine if the device implements a peripheral mode.
        """
        # Retrieve supported commands
        commands = self.device.get_domain_commands(WhadDomain.BtLE)
        return (
            (commands & (1 << Commands.PeripheralMode))>0 and
            (commands & (1 << Commands.Start))>0 and
            (commands & (1 << Commands.Stop))>0
        )

    def can_discover_access_addresses(self):
        """
        Determine if the device implements an access addresses discovery mode.
        """
        commands = self.device.get_domain_commands(WhadDomain.BtLE)
        return (
            (commands & (1 << Commands.SniffAccessAddress)) > 0 and
            (commands & (1 << Commands.Start))>0 and
            (commands & (1 << Commands.Stop))>0
        )

    def can_sniff_active_connection(self):
        """
        Determine if the device allows to sniff an active connection.
        """
        commands = self.device.get_domain_commands(WhadDomain.BtLE)
        return (
            (commands & (1 << Commands.SniffActiveConn)) > 0 and
            (commands & (1 << Commands.Start))>0 and
            (commands & (1 << Commands.Stop))>0
        )

    def can_sniff_advertisements(self):
        """
        Determine if the device implements an advertisements sniffer mode.
        """
        commands = self.device.get_domain_commands(WhadDomain.BtLE)
        return (
            (commands & (1 << Commands.SniffAdv)) > 0 and
            (commands & (1 << Commands.Start))>0 and
            (commands & (1 << Commands.Stop))>0
        )


    def can_sniff_new_connection(self):
        """
        Determine if the device implements a new connection sniffer mode.
        """
        commands = self.device.get_domain_commands(WhadDomain.BtLE)
        return (
            (commands & (1 << Commands.SniffConnReq)) > 0 and
            (commands & (1 << Commands.Start))>0 and
            (commands & (1 << Commands.Stop))>0
        )

    def can_inject(self):
        """
        Determine if the device implements an injection mode.
        """
        capabilities = self.device.get_domain_capability(WhadDomain.BtLE)
        return self.can_send() and (capabilities & (1 << WhadCapability.Inject) > 0)


    def can_hijack_master(self):
        """
        Determine if the device implements a master hijacking mode.
        """
        commands = self.device.get_domain_commands(WhadDomain.BtLE)
        return (commands & (1 << Commands.HijackMaster)) > 0

    def can_hijack_slave(self):
        """
        Determine if the device implements a slave hijacking mode.
        """
        commands = self.device.get_domain_commands(WhadDomain.BtLE)
        return (commands & (1 << Commands.HijackSlave)) > 0

    def can_hijack_both(self):
        """
        Determine if the device implements a slave and master hijacking mode.
        """
        commands = self.device.get_domain_commands(WhadDomain.BtLE)
        return (commands & (1 << Commands.HijackBoth)) > 0


    def can_reactive_jam(self):
        """
        Determine if the device implements a reactive jamming mode.
        """
        commands = self.device.get_domain_commands(WhadDomain.BtLE)
        return (commands & (1 << Commands.ReactiveJam)) > 0


    def can_prepare(self):
        """
        Determine if the device can prepare a sequence of packets associated with a trigger.
        """
        commands = self.device.get_domain_commands(WhadDomain.BtLE)
        return (commands & (1 << Commands.PrepareSequence)) > 0

    def can_trigger(self):
        """
        Determine if the device can manually trigger a sequence of packets.
        """
        commands = self.device.get_domain_commands(WhadDomain.BtLE)
        return (commands & (1 << Commands.TriggerSequence)) > 0

    def trigger(self, trigger):
        '''
        Trigger a sequence of packets linked to a Manual Trigger object.
        '''
        if not self.can_trigger():
            raise UnsupportedCapability("Trigger")

        if not isinstance(trigger, ManualTrigger):
            return False

        if trigger.identifier is None:
            return False

        msg = self.hub.ble.createTrigger(trigger.identifier)
        resp = self.send_command(msg, message_filter(CommandResult))
        return isinstance(resp, Success)

    def can_delete_sequence(self):
        """
        Determine if the device can delete a sequence of packets.
        """
        commands = self.device.get_domain_commands(WhadDomain.BtLE)
        return (commands & (1 << Commands.DeleteSequence)) > 0

    def delete_sequence(self, trigger):
        '''
        Delete a sequence of packets linked to a Trigger object.
        '''
        if not self.can_delete_sequence():
            raise UnsupportedCapability("DeleteSequence")

        if trigger.identifier is None:
            return False

        msg = self.hub.ble.createDeleteSequence(trigger.identifier)

        resp = self.send_command(msg, message_filter(CommandResult))
        return isinstance(resp, Success)


    def prepare(self, *packets, trigger=ManualTrigger(), direction=Direction.MASTER_TO_SLAVE):
        """
        Prepare a sequence of packets and associate a trigger to it.
        """
        if not self.can_prepare():
            raise UnsupportedCapability("Prepare")

        prep_packets = []
        for packet in packets:
            if BTLE_DATA in packet:
                prep_packets.append(bytes(packet[BTLE_DATA:]))
            else:
                # Fail if at least one packet has no BTLE_DATA layer
                return False

        if isinstance(trigger, ManualTrigger):
            # Create a prepared sequence with manual trigger
            msg = self.hub.ble.createPrepareSequenceManual(
                trigger.identifier,
                direction,
                prep_packets
            )
        elif isinstance(trigger, ConnectionEventTrigger):
            # Create a prepared sequence with connection event trigger
            msg = self.hub.ble.createPrepareSequenceConnEvt(
                trigger.identifier,
                direction,
                trigger.connection_event,
                prep_packets
            )
        elif isinstance(trigger, ReceptionTrigger):
            # Create a prepared sequence with reception trigger
            msg = self.hub.ble.createPrepareSequencePattern(
                trigger.identifier,
                direction,
                trigger.pattern,
                trigger.mask,
                trigger.offset,
                prep_packets
            )
        else:
            return False

        resp = self.send_command(msg, message_filter(CommandResult))
        success = isinstance(resp, Success)
        if success:
            self.__triggers.append(trigger)
        return success

    def reactive_jam(self, pattern, position=0, channel=37):
        """
        Performs a reactive jamming attack on provided pattern and channel.
        """
        if not self.can_reactive_jam():
            raise UnsupportedCapability("ReactiveJam")

        # Create a ReactiveJam message
        msg = self.hub.ble.createReactiveJam(channel, pattern, position)

        resp = self.send_command(msg, message_filter(CommandResult))
        return isinstance(resp, Success)

    def jam_advertisement_on_channel(self, channel=37):
        """
        Jam advertisements on a single channel.
        """
        if not self.can_jam_advertisement_on_channel():
            raise UnsupportedCapability("JamAdvOnChannel")

        # Create a JamAdvChan message
        msg = self.hub.ble.createJamAdvChan(channel)

        resp = self.send_command(msg, message_filter(CommandResult))
        return isinstance(resp, Success)

    def hijack_master(self, access_address):
        """
        Hijack the master role.
        """
        if not self.can_hijack_master():
            raise UnsupportedCapability("Hijack")

        # Create a HijackMaster message
        msg = self.hub.ble.createHijackMaster(access_address)

        resp = self.send_command(msg, message_filter(CommandResult))
        return isinstance(resp, Success)

    def discover_access_addresses(self):
        """
        Discover access addresses.
        """
        if not self.can_discover_access_addresses():
            raise UnsupportedCapability("AccessAddressesDiscovery")

        # Create SniffAccessAddress message
        msg = self.hub.ble.createSniffAccessAddress(b"\xFF\xFF\xFF\xFF\x1F")

        resp = self.send_command(msg, message_filter(CommandResult))
        return isinstance(resp, Success)

    def sniff_active_connection(self, access_address: int , crc_init: int = None,
                                channel_map: ChannelMap = None, hop_interval: int = None,
                                hop_increment: int = None):
        """
        Sniff active connection.
        """
        if not self.can_sniff_active_connection():
            raise UnsupportedCapability("ActiveConnectionSniffing")

        # Create a SniffActiveConn message
        msg = self.hub.ble.createSniffActiveConn(
            access_address,
            crc_init=crc_init,
            channel_map=channel_map,
            interval=hop_interval,
            increment=hop_increment,
            channels=b"\xFF\xFF\xFF\xFF\x1F"
        )

        resp = self.send_command(msg, message_filter(CommandResult))
        return isinstance(resp, Success)

    def hijack_slave(self, access_address):
        """
        Hijack the slave role.
        """
        if not self.can_hijack_slave():
            raise UnsupportedCapability("Hijack")

        # Create an HijackSlave message
        msg = self.hub.ble.createHijackSlave(access_address)

        resp = self.send_command(msg, message_filter(CommandResult))
        return isinstance(resp, Success)

    def hijack_both(self, access_address):
        """
        Hijack both roles.
        """
        if not self.can_hijack_both():
            raise UnsupportedCapability("Hijack")

        # Create an HijackBoth message
        msg = self.hub.ble.createHijackBoth(access_address)

        resp = self.send_command(msg, message_filter(CommandResult))
        return isinstance(resp, Success)

    def sniff_advertisements(self, channel=37, bd_address="FF:FF:FF:FF:FF:FF"):
        """
        Sniff Bluetooth Low Energy advertisements (on a single channel).
        """
        if not self.can_sniff_advertisements():
            raise UnsupportedCapability("Sniff")

        # Create a SniffAdv message
        msg = self.hub.ble.createSniffAdv(channel, BDAddress(bd_address))

        resp = self.send_command(msg, message_filter(CommandResult))
        return isinstance(resp, Success)

    def sniff_new_connection(self, channel=37, show_advertisements=True, show_empty_packets=False, bd_address="FF:FF:FF:FF:FF:FF"):
        """
        Sniff Bluetooth Low Energy connection (from initiation).
        """
        if not self.can_sniff_new_connection():
            raise UnsupportedCapability("Sniff")

        # Create a SniffConnReq message
        msg = self.hub.ble.createSniffConnReq(
            channel,
            bd_address=BDAddress(bd_address),
            show_empty=show_empty_packets,
            show_adv=show_advertisements
        )

        resp = self.send_command(msg, message_filter(CommandResult))
        return isinstance(resp, Success)

    def set_bd_address(self, bd_address, public=True):
        """
        Set Bluetooth Low Energy BD address.
        """
        # Ensure we can spoof BD address
        commands = self.device.get_domain_commands(WhadDomain.BtLE)
        if (commands & (1 << Commands.SetBdAddress))>0:

            # Create a SetBdAddress message
            msg = self.hub.ble.createSetBdAddress(BDAddress(
                bd_address,
                random=(not public)
            ))

            resp = self.send_command(msg, message_filter(CommandResult))
            return isinstance(resp, Success)
        else:
            return False

    def enable_scan_mode(self, active=False):
        """
        Enable Bluetooth Low Energy scanning mode.
        """
        # Create a ScanMode message
        msg = self.hub.ble.createScanMode(active=active)

        resp = self.send_command(msg, message_filter(CommandResult))
        return isinstance(resp, Success)

    def enable_central_mode(self):
        """
        Enable Bluetooth Low Energy central mode (acts as master).
        """
        # Create a CentalMode message
        msg = self.hub.ble.createCentralMode()

        resp = self.send_command(msg, message_filter(CommandResult))
        return isinstance(resp, Success)

    def enable_adv_mode(self, adv_data=None, scan_data=None):
        """
        Enable BLE advertising mode (acts as a broadcaster)
        """
        # Create a AdvMode message
        msg = self.hub.ble.createAdvMode(
            adv_data,
            scan_rsp=scan_data
        )

        resp = self.send_command(msg, message_filter(CommandResult))
        return isinstance(resp, Success)

    def enable_peripheral_mode(self, adv_data: bytes = None, scan_data: bytes = None):
        """
        Enable Bluetooth Low Energy peripheral mode (acts as slave).
        """
        # Build advertising data if required
        if isinstance(adv_data, AdvDataFieldList):
            adv_data = adv_data.to_bytes()
        if isinstance(scan_data, AdvDataFieldList):
            scan_data = scan_data.to_bytes()

        # Create a PeriphMode message
        msg = self.hub.ble.createPeriphMode(
            adv_data=adv_data,
            scan_rsp=scan_data
        )

        resp = self.send_command(msg, message_filter(CommandResult))
        return isinstance(resp, Success)

    def connect_to(self, bd_addr: BDAddress, random: bool = False, access_address: int = None, \
                   channel_map: ChannelMap = None, crc_init: int = None, hop_interval: int = None, \
                   hop_increment: int = None):
        """
        Initiate a Bluetooth Low Energy connection.
        """
        # Create a ConnectTo message
        msg = self.hub.ble.createConnectTo(
            bd_address=BDAddress(bd_addr, random=random),
            access_address=access_address,
            channel_map=channel_map,
            interval=hop_interval,
            increment=hop_increment,
            crc_init=crc_init
        )

        resp = self.send_command(msg, message_filter(CommandResult))
        return isinstance(resp, Success)

    def start(self):
        """
        Start currently enabled mode.
        """
        logger.info('starting current BLE mode ...')

        # Create a Start message
        msg = self.hub.ble.createStart()

        resp = self.send_command(msg, message_filter(CommandResult))
        if isinstance(resp, Success):
            logger.info('current BLE mode successfully started')
        else:
            logger.info('an error occured while starting !')
        return isinstance(resp, Success)

    def disconnect(self, conn_handle):
        """Terminate a specific connection.

        :param int conn_handle: Connection handle of the connection to terminate.
        """

        # Create a Disconnect message
        msg = self.hub.ble.createDisconnect(conn_handle)

        resp = self.send_command(msg, message_filter(CommandResult))
        return isinstance(resp, Success)


    def stop(self):
        """
        Stop currently enabled mode.
        """

        # Create a Stop message
        msg = self.hub.ble.createStop()

        resp = self.send_command(msg, message_filter(CommandResult))

        # Remove all triggers
        for trigger in self.__triggers:
            trigger.connector = None
        self.__triggers = []

        return isinstance(resp, Success)

    def set_encryption(self, conn_handle, enabled=False, ll_key=None, ll_iv=None, key=None, rand=None, ediv=None):
        """Notify WHAD device about encryption status
        """

        print("set_encryption", enabled, ll_key.hex(), ll_iv.hex(), key.hex(), rand, ediv)

        # Create a SetEncryption message
        msg = self.hub.ble.createSetEncryption(
            conn_handle,
            ll_key if ll_key is not None else b"",
            ll_iv if ll_iv is not None else b"",
            key if key is not None else b"",
            struct.pack('<Q', rand) if rand is not None else b"",
            struct.pack('<H', ediv) if ediv is not None else b"",
            enabled
        )

        resp = self.send_command(msg, message_filter(CommandResult))

        # Update LL encryption status
        if isinstance(resp, Success):
            self.__encrypted = enabled
            logger.info('[ble connector] encryption is now: %s' % self.__encrypted)

        # Return command result
        return isinstance(resp, Success)

    def on_generic_msg(self, message):
        logger.info('generic message: %s' % message)
        pass

    def on_discovery_msg(self, message):
        logger.info('discovery message: %s' % message)
        pass

    def on_domain_msg(self, domain, message):
        if not self.__ready:
            return

        # Ensure forwarded message is BLE related
        assert domain == 'ble'

        if isinstance(message, BleAdvPduReceived):
            packet = self.translator.from_message(message)
            if packet is not None:
                self.monitor_packet_rx(packet)

                # Forward to advertising PDU callback if synchronous mode is set.
                if self.is_synchronous():
                    self.add_pending_pdu(packet)
                else:
                    self.on_adv_pdu(packet)
        elif isinstance(message, BlePduReceived):
            if message.processed:
                packet = self.translator.from_message(message)
                if packet is not None:
                    self.monitor_packet_rx(packet)
                    logger.info('[ble PDU log-only]')
            else:
                packet = self.translator.from_message(message)
                if packet is not None:
                    self.monitor_packet_rx(packet)

                    # Forward to generic PDU callback if auto mode is set.
                    if self.is_synchronous():
                        self.add_pending_pdu(packet)
                    else:
                        self.on_pdu(packet)
        elif isinstance(message, BleRawPduReceived):
            if message.processed:
                packet = self.translator.from_message(message)
                if packet is not None:
                    self.monitor_packet_rx(packet)
                    logger.info('[ble PDU log-only]')
            else:
                # Extract scapy packet
                packet = self.translator.from_message(message)
                if packet is not None:
                    self.monitor_packet_rx(packet)

                    # Forward to raw pdu callback if auto mode is set.
                    if self.is_synchronous():
                        self.add_pending_pdu(packet)
                    else:
                        self.on_raw_pdu(packet)
        elif isinstance(message, Synchronized):
            self.on_synchronized(
                access_address = message.access_address,
                crc_init = message.crc_init,
                hop_interval = message.hop_interval,
                hop_increment = message.hop_increment,
                channel_map = message.channel_map
            )
        elif isinstance(message, Desynchronized):
            self.on_desynchronized(access_address=message.access_address)
        elif isinstance(message, Connected):
            self.on_connected(message)
        elif isinstance(message, Disconnected):
            self.on_disconnected(message)
        elif isinstance(message, Triggered):
            self.on_triggered(message.id)


    def on_synchronized(self, access_address=None, crc_init=None, hop_increment=None, hop_interval=None, channel_map=None):
        pass

    def on_desynchronized(self, access_address=None):
        pass

    def on_adv_pdu(self, packet):
        logger.info('received an advertisement PDU')

    def on_connected(self, connection_data):
        logger.info('a connection has been established')
        logger.debug(
            'connection handle: %d' % connection_data.conn_handle if connection_data.conn_handle is not None else 0
        )

    def on_triggered(self, identifier):
        for trigger in self.__triggers:
            if trigger.identifier == identifier:
                trigger.triggered = True

    def on_disconnected(self, disconnection_data):
        logger.info('a connection has been terminated')
        for trigger in self.__triggers:
            self.delete_sequence(trigger)

    def on_raw_pdu(self, packet):

        if BTLE_ADV in packet:
            adv_pdu = packet[BTLE_ADV:]
            adv_pdu.metadata = packet.metadata
            self.on_adv_pdu(adv_pdu)

        elif BTLE_DATA in packet:
            conn_pdu = packet[BTLE_DATA:]
            conn_pdu.metadata = packet.metadata
            self.on_pdu(conn_pdu)

    def on_pdu(self, packet):
        if packet.LLID == 3:
            self.on_ctl_pdu(packet)
        elif packet.LLID in (1,2):
            self.on_data_pdu(packet)
        else:
            self.on_error_pdu(packet)

    def on_data_pdu(self, pdu):
        logger.info('received a data PDU')
        pass

    def on_ctl_pdu(self, pdu):
        logger.info('received a control PDU')
        pass

    def on_error_pdu(self, pdu):
        pass

    def send_ctrl_pdu(self, pdu, conn_handle=0, direction=Direction.MASTER_TO_SLAVE, access_address=0x8e89bed6, encrypt=None):
        """
        Send CTRL PDU
        """
        logger.info('send control PDU to connection (handle:%d)' % conn_handle)
        return self.send_pdu(pdu, conn_handle=conn_handle, direction=direction, access_address=access_address, encrypt=encrypt)

    def send_data_pdu(self, data, conn_handle=0, direction=Direction.MASTER_TO_SLAVE, access_address=0x8e89bed6, encrypt=None):
        """
        Send data (L2CAP) PDU.
        """
        logger.info('send data PDU to connection (handle:%d)' % conn_handle)
        return self.send_pdu(data, conn_handle=conn_handle, direction=direction, access_address=access_address, encrypt=encrypt)

    def send_pdu(self, pdu, conn_handle=0, direction=Direction.MASTER_TO_SLAVE, access_address=0x8e89bed6, encrypt=None):
        """
        Send generic PDU.
        """
        if self.can_send():
            if self.support_raw_pdu():
                packet = BTLE(access_addr=access_address)/pdu
            else:
                packet = pdu
            packet.metadata = BLEMetadata()
            packet.metadata.direction = direction
            packet.metadata.connection_handle = conn_handle
            self.monitor_packet_tx(packet)

            # If encrypt is provided, take it into account
            # otherwise consider using the internal link-layer encryption status
            if encrypt is not None and isinstance(encrypt, bool):
                logger.info('[ble connector] encrypt is specified (%s)' % encrypt)
                #msg = self._build_message_from_scapy_packet(packet, encrypt)
                msg = self.translator.from_packet(packet, encrypt)
            else:
                logger.info('[ble connector] link-layer encryption: %s' % self.__encrypted)
                #msg = self._build_message_from_scapy_packet(packet, self.__encrypted)
                msg = self.translator.from_packet(packet, self.__encrypted)

            resp = self.send_command(msg, message_filter(CommandResult))
            logger.info('[ble connector] Command sent, result: %s' % resp)
            if resp is None:
                raise ConnectionLostException(None)
            else:
                return isinstance(resp, Success)
        else:
            return False

from whad.ble.connector.peripheral import Peripheral, PeripheralClient
from whad.ble.connector.central import Central
from whad.ble.connector.injector import Injector
from whad.ble.connector.hijacker import Hijacker
from whad.ble.connector.sniffer import Sniffer
from whad.ble.connector.scanner import Scanner
