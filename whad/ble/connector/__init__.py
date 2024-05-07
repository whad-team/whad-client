import struct

from scapy.layers.bluetooth4LE import BTLE, BTLE_ADV, BTLE_DATA, BTLE_ADV_IND, \
    BTLE_ADV_NONCONN_IND, BTLE_ADV_DIRECT_IND, BTLE_ADV_SCAN_IND, BTLE_SCAN_RSP, \
    BTLE_RF, BTLE_CTRL
from scapy.compat import raw
from scapy.packet import Packet
from queue import Queue, Empty

from whad.hub.ble.bdaddr import BDAddress
from whad.device import WhadDeviceConnector
from whad.protocol.ble.ble_pb2 import BleDirection, CentralMode, SetEncryptionCmd, StartCmd, StopCmd, \
    ScanMode, Start, Stop, BleAdvType, ConnectTo, CentralModeCmd, PeripheralMode, \
    PeripheralModeCmd, SetBdAddress, SendPDU, SniffAdv, SniffConnReq, HijackMaster, \
    HijackSlave, HijackBoth, SendRawPDU, AdvModeCmd, BleAdvType, SniffAccessAddress, \
    SniffAccessAddressCmd, SniffActiveConn, SniffActiveConnCmd, BleAddrType, ReactiveJam, \
    JamAdvOnChannel, PrepareSequence, PrepareSequenceCmd, TriggerSequence, DeleteSequence
from whad.protocol.whad_pb2 import Message
from whad.protocol.generic_pb2 import ResultCode
from whad import WhadDomain, WhadCapability
from whad.exceptions import UnsupportedDomain, UnsupportedCapability
from whad.ble.metadata import generate_ble_metadata, BLEMetadata
from whad.ble.connector.translator import BleMessageTranslator
from whad.helpers import message_filter, bd_addr_to_bytes
from whad.ble.profile.advdata import AdvDataFieldList
from whad.common.triggers import ManualTrigger, ConnectionEventTrigger, ReceptionTrigger
from whad.ble.exceptions import ConnectionLostException

# Logging
import logging
logger = logging.getLogger(__name__)

class BLE(WhadDeviceConnector):
    """
    BLE protocol connector.

    This connector drives a BLE-capable device with BLE-specific WHAD messages.
    It is required by various role classes to interact with a real device and pre-process
    domain-specific messages.
    """
    # correlation table
    SCAPY_CORR_ADV = {
        BleAdvType.ADV_IND: BTLE_ADV_IND,
        BleAdvType.ADV_NONCONN_IND: BTLE_ADV_NONCONN_IND,
        BleAdvType.ADV_DIRECT_IND: BTLE_ADV_DIRECT_IND,
        BleAdvType.ADV_SCAN_IND: BTLE_ADV_SCAN_IND,
        BleAdvType.ADV_SCAN_RSP: BTLE_SCAN_RSP
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
            self.translator = BleMessageTranslator()

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
            self.__can_send = ((commands & (1 << SendPDU))>0 or (commands & (1 << SendRawPDU)))
        return self.__can_send

    def can_scan(self):
        """
        Determine if the device implements a scanner mode.
        """
        # Retrieve supported commands
        commands = self.device.get_domain_commands(WhadDomain.BtLE)
        return (
            (commands & (1 << ScanMode))>0 and
            (commands & (1 << Start))>0 and
            (commands & (1 << Stop))>0
        )

    def can_connect(self):
        """
        Determine if the device can establish a connection as central.
        """
        # Retrieve supported commands
        commands = self.device.get_domain_commands(WhadDomain.BtLE)
        return (commands & (1 << ConnectTo))>0

    def can_jam_advertisement_on_channel(self):
        """
        Determine if the device can jam advertisements on a specific channel.
        """
        # Retrieve supported commands
        commands = self.device.get_domain_commands(WhadDomain.BtLE)
        return (commands & (1 << JamAdvOnChannel))>0

    def can_be_central(self):
        """
        Determine if the device implements a central mode.
        """
        # Retrieve supported commands
        commands = self.device.get_domain_commands(WhadDomain.BtLE)
        return (
            (commands & (1 << CentralMode))>0 and
            (commands & (1 << Start))>0 and
            (commands & (1 << Stop))>0
        )

    def can_be_peripheral(self):
        """
        Determine if the device implements a peripheral mode.
        """
        # Retrieve supported commands
        commands = self.device.get_domain_commands(WhadDomain.BtLE)
        return (
            (commands & (1 << PeripheralMode))>0 and
            (commands & (1 << Start))>0 and
            (commands & (1 << Stop))>0
        )

    def can_discover_access_addresses(self):
        """
        Determine if the device implements an access addresses discovery mode.
        """
        commands = self.device.get_domain_commands(WhadDomain.BtLE)
        return (
            (commands & (1 << SniffAccessAddress)) > 0 and
            (commands & (1 << Start))>0 and
            (commands & (1 << Stop))>0
        )

    def can_sniff_active_connection(self):
        """
        Determine if the device allows to sniff an active connection.
        """
        commands = self.device.get_domain_commands(WhadDomain.BtLE)
        return (
            (commands & (1 << SniffActiveConn)) > 0 and
            (commands & (1 << Start))>0 and
            (commands & (1 << Stop))>0
        )

    def can_sniff_advertisements(self):
        """
        Determine if the device implements an advertisements sniffer mode.
        """
        commands = self.device.get_domain_commands(WhadDomain.BtLE)
        return (
            (commands & (1 << SniffAdv)) > 0 and
            (commands & (1 << Start))>0 and
            (commands & (1 << Stop))>0
        )


    def can_sniff_new_connection(self):
        """
        Determine if the device implements a new connection sniffer mode.
        """
        commands = self.device.get_domain_commands(WhadDomain.BtLE)
        return (
            (commands & (1 << SniffConnReq)) > 0 and
            (commands & (1 << Start))>0 and
            (commands & (1 << Stop))>0
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
        return (commands & (1 << HijackMaster)) > 0

    def can_hijack_slave(self):
        """
        Determine if the device implements a slave hijacking mode.
        """
        commands = self.device.get_domain_commands(WhadDomain.BtLE)
        return (commands & (1 << HijackSlave)) > 0

    def can_hijack_both(self):
        """
        Determine if the device implements a slave and master hijacking mode.
        """
        commands = self.device.get_domain_commands(WhadDomain.BtLE)
        return (commands & (1 << HijackBoth)) > 0


    def can_reactive_jam(self):
        """
        Determine if the device implements a reactive jamming mode.
        """
        commands = self.device.get_domain_commands(WhadDomain.BtLE)
        return (commands & (1 << ReactiveJam)) > 0


    def can_prepare(self):
        """
        Determine if the device can prepare a sequence of packets associated with a trigger.
        """
        commands = self.device.get_domain_commands(WhadDomain.BtLE)
        return (commands & (1 << PrepareSequence)) > 0

    def can_trigger(self):
        """
        Determine if the device can manually trigger a sequence of packets.
        """
        commands = self.device.get_domain_commands(WhadDomain.BtLE)
        return (commands & (1 << TriggerSequence)) > 0

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
        resp = self.send_command(msg, message_filter('generic', 'cmd_result'))
        return resp.generic.cmd_result.result == ResultCode.SUCCESS

    def can_delete_sequence(self):
        """
        Determine if the device can delete a sequence of packets.
        """
        commands = self.device.get_domain_commands(WhadDomain.BtLE)
        return (commands & (1 << DeleteSequence)) > 0

    def delete_sequence(self, trigger):
        '''
        Delete a sequence of packets linked to a Trigger object.
        '''
        if not self.can_delete_sequence():
            raise UnsupportedCapability("DeleteSequence")

        if trigger.identifier is None:
            return False

        msg = Message()
        msg.ble.delete_seq.id = trigger.identifier
        resp = self.send_command(msg, message_filter('generic', 'cmd_result'))
        return resp.generic.cmd_result.result == ResultCode.SUCCESS


    def prepare(self, *packets, trigger=ManualTrigger(), direction=BleDirection.MASTER_TO_SLAVE):
        """
        Prepare a sequence of packets and associate a trigger to it.
        """
        if not self.can_prepare():
            raise UnsupportedCapability("Prepare")
        msg = Message()
        msg.ble.prepare.direction = direction
        msg.ble.prepare.id = trigger.identifier
        if isinstance(trigger, ManualTrigger):
            msg.ble.prepare.trigger.manual.CopyFrom(PrepareSequenceCmd.ManualTrigger())
        elif isinstance(trigger, ConnectionEventTrigger):
            msg.ble.prepare.trigger.connection_event.connection_event = trigger.connection_event
        elif isinstance(trigger, ReceptionTrigger):
            msg.ble.prepare.trigger.reception.pattern = trigger.pattern
            msg.ble.prepare.trigger.reception.mask = trigger.mask
            msg.ble.prepare.trigger.reception.offset = trigger.offset
        else:
            return False

        trigger.connector = self
        for packet in packets:
            if BTLE_DATA in packet:
                packet = packet[BTLE_DATA:]
                pkt_msg = msg.ble.prepare.sequence.add()
                pkt_msg.packet = bytes(packet)
            else:
                return False

        resp = self.send_command(msg, message_filter('generic', 'cmd_result'))
        success = resp.generic.cmd_result.result == ResultCode.SUCCESS
        if success:
            self.__triggers.append(trigger)
        return success

    def reactive_jam(self, pattern, position=0, channel=37):
        """
        Performs a reactive jamming attack on provided pattern and channel.
        """
        if not self.can_reactive_jam():
            raise UnsupportedCapability("ReactiveJam")

        # Create message
        msg = self.hub.ble.createReactiveJam(channel, pattern, position)

        resp = self.send_command(msg, message_filter('generic', 'cmd_result'))
        return (resp.generic.cmd_result.result == ResultCode.SUCCESS)



    def jam_advertisement_on_channel(self, channel=37):
        """
        Jam advertisements on a single channel.
        """
        if not self.can_jam_advertisement_on_channel():
            raise UnsupportedCapability("JamAdvOnChannel")

        msg = Message()
        msg.ble.jam_adv_chan.channel = channel
        resp = self.send_command(msg, message_filter('generic', 'cmd_result'))
        return (resp.generic.cmd_result.result == ResultCode.SUCCESS)



    def hijack_master(self, access_address):
        """
        Hijack the master role.
        """
        if not self.can_hijack_master():
            raise UnsupportedCapability("Hijack")

        msg = Message()
        msg.ble.hijack_master.access_address = access_address
        resp = self.send_command(msg, message_filter('generic', 'cmd_result'))
        return (resp.generic.cmd_result.result == ResultCode.SUCCESS)

    def discover_access_addresses(self):
        """
        Discover access addresses.
        """
        if not self.can_discover_access_addresses():
            raise UnsupportedCapability("AccessAddressesDiscovery")

        msg = Message()
        msg.ble.sniff_aa.monitored_channels = b"\xFF\xFF\xFF\xFF\x1F"
        resp = self.send_command(msg, message_filter('generic', 'cmd_result'))
        return (resp.generic.cmd_result.result == ResultCode.SUCCESS)

    def sniff_active_connection(self, access_address, crc_init=None, channel_map=None, hop_interval=None, hop_increment=None):
        """
        Sniff active connection.
        """
        if not self.can_sniff_active_connection():
            raise UnsupportedCapability("ActiveConnectionSniffing")

        msg = Message()
        msg.ble.sniff_conn.access_address = access_address

        if crc_init is not None:
            msg.ble.sniff_conn.crc_init = crc_init

        if channel_map is not None:
            msg.ble.sniff_conn.channel_map = channel_map

        if hop_interval is not None:
            msg.ble.sniff_conn.hop_interval = hop_interval

        if hop_increment is not None:
            msg.ble.sniff_conn.hop_increment = hop_increment

        msg.ble.sniff_conn.monitored_channels = b"\xFF\xFF\xFF\xFF\x1F"

        resp = self.send_command(msg, message_filter('generic', 'cmd_result'))
        return (resp.generic.cmd_result.result == ResultCode.SUCCESS)


    def hijack_slave(self, access_address):
        """
        Hijack the slave role.
        """
        if not self.can_hijack_slave():
            raise UnsupportedCapability("Hijack")

        msg = Message()
        msg.ble.hijack_slave.access_address = access_address
        resp = self.send_command(msg, message_filter('generic', 'cmd_result'))
        return (resp.generic.cmd_result.result == ResultCode.SUCCESS)


    def hijack_both(self, access_address):
        """
        Hijack both roles.
        """
        if not self.can_hijack_both():
            raise UnsupportedCapability("Hijack")

        msg = Message()
        msg.ble.hijack_both.access_address = access_address
        resp = self.send_command(msg, message_filter('generic', 'cmd_result'))
        return (resp.generic.cmd_result.result == ResultCode.SUCCESS)

    def sniff_advertisements(self, channel=37, bd_address="FF:FF:FF:FF:FF:FF"):
        """
        Sniff Bluetooth Low Energy advertisements (on a single channel).
        """
        if not self.can_sniff_advertisements():
            raise UnsupportedCapability("Sniff")

        msg = self.hub.ble.createSniffAdv(channel, BDAddress(bd_address))
        resp = self.send_command(msg, message_filter('generic', 'cmd_result'))
        return (resp.generic.cmd_result.result == ResultCode.SUCCESS)


    def sniff_new_connection(self, channel=37, show_advertisements=True, show_empty_packets=False, bd_address="FF:FF:FF:FF:FF:FF"):
        """
        Sniff Bluetooth Low Energy connection (from initiation).
        """
        if not self.can_sniff_new_connection():
            raise UnsupportedCapability("Sniff")

        msg = Message()
        msg.ble.sniff_connreq.show_advertisements = show_advertisements
        msg.ble.sniff_connreq.show_empty_packets = show_empty_packets
        msg.ble.sniff_connreq.channel = channel
        msg.ble.sniff_connreq.bd_address = bd_addr_to_bytes(bd_address)
        resp = self.send_command(msg, message_filter('generic', 'cmd_result'))
        return (resp.generic.cmd_result.result == ResultCode.SUCCESS)

    def set_bd_address(self, bd_address, public=True):
        """
        Set Bluetooth Low Energy BD address.
        """
        # Ensure we can spoof BD address
        commands = self.device.get_domain_commands(WhadDomain.BtLE)
        if (commands & (1 << SetBdAddress))>0:
            msg = Message()
            msg.ble.set_bd_addr.bd_address = bd_addr_to_bytes(bd_address)
            msg.ble.set_bd_addr.addr_type = BleAddrType.PUBLIC if public else BleAddrType.RANDOM
            resp = self.send_command(msg, message_filter('generic', 'cmd_result'))
            return (resp.generic.cmd_result.result == ResultCode.SUCCESS)
        else:
            return False

    def enable_scan_mode(self, active=False):
        """
        Enable Bluetooth Low Energy scanning mode.
        """
        msg = self.hub.ble.createScanMode(active=active)
        resp = self.send_command(msg, message_filter('generic', 'cmd_result'))

    def enable_central_mode(self):
        """
        Enable Bluetooth Low Energy central mode (acts as master).
        """
        msg = self.hub.ble.createCentralMode()
        resp = self.send_command(msg, message_filter('generic', 'cmd_result'))

    def enable_adv_mode(self, adv_data=None, scan_data=None):
        """
        Enable BLE advertising mode (acts as a broadcaster)
        """
        msg = Message()
        if adv_data is not None and isinstance(adv_data, bytes):
            msg.ble.adv_mode.scan_data = adv_data
        if scan_data is not None and isinstance(scan_data, bytes):
            msg.ble.adv_mode.scanrsp_data = scan_data
        if adv_data is None and scan_data is None:
            msg.ble.adv_mode.CopyFrom(AdvModeCmd())
        resp = self.send_command(msg, message_filter('generic', 'cmd_result'))

    def enable_peripheral_mode(self, adv_data=None, scan_data=None):
        """
        Enable Bluetooth Low Energy peripheral mode (acts as slave).
        """
        # Build advertising data if required
        if isinstance(adv_data, AdvDataFieldList):
            adv_data = adv_data.to_bytes()
        if isinstance(scan_data, AdvDataFieldList):
            scan_data = scan_data.to_bytes()

        msg = Message()
        if adv_data is not None and isinstance(adv_data, bytes):
            msg.ble.periph_mode.scan_data = adv_data
        if scan_data is not None and isinstance(scan_data, bytes):
            msg.ble.periph_mode.scanrsp_data = scan_data
        if adv_data is None and scan_data is None:
            msg.ble.periph_mode.CopyFrom(PeripheralModeCmd())
        resp = self.send_command(msg, message_filter('generic', 'cmd_result'))

    def connect_to(self, bd_addr, random=False, access_address=None, channel_map=None, crc_init=None, hop_interval=None, hop_increment=None):
        """
        Initiate a Bluetooth Low Energy connection.
        """
        msg = Message()
        msg.ble.connect.bd_address = bd_addr_to_bytes(bd_addr)
        if random:
            msg.ble.connect.addr_type = BleAddrType.RANDOM
        else:
            msg.ble.connect.addr_type = BleAddrType.PUBLIC

        if access_address is not None:
            msg.ble.connect.access_address = access_address
        if channel_map is not None and channel_map >= 1 and channel_map <= 0x1fffffffff:
            msg.ble.connect.channel_map = struct.pack("<Q", channel_map)[:5]
        if crc_init is not None:
            msg.ble.connect.crc_init = crc_init
        if hop_interval is not None:
            msg.ble.connect.hop_interval = hop_interval
        if hop_increment is not None:
            msg.ble.connect.hop_increment = hop_increment
        return self.send_command(msg, message_filter('generic', 'cmd_result'))

    def start(self):
        """
        Start currently enabled mode.
        """
        logger.info('starting current BLE mode ...')
        #msg = Message()
        #msg.ble.start.CopyFrom(StartCmd())
        msg = self.hub.ble.createStart()
        resp = self.send_command(msg, message_filter('generic', 'cmd_result'))
        if (resp.generic.cmd_result.result == ResultCode.SUCCESS):
            logger.info('current BLE mode successfully started')
        else:
            logger.info('an error occured while starting !')
        return (resp.generic.cmd_result.result == ResultCode.SUCCESS)

    def disconnect(self, conn_handle):
        """Terminate a specific connection.

        :param int conn_handle: Connection handle of the connection to terminate.
        """
        #msg = Message()
        #msg.ble.disconnect.conn_handle = conn_handle
        msg = self.hub.ble.createDisconnect(conn_handle)
        resp = self.send_command(msg, message_filter('generic', 'cmd_result'))
        return (resp.generic.cmd_result.result == ResultCode.SUCCESS)


    def stop(self):
        """
        Stop currently enabled mode.
        """
        #msg = Message()
        #msg.ble.stop.CopyFrom(StopCmd())
        msg = self.hub.ble.createStop()
        resp = self.send_command(msg, message_filter('generic', 'cmd_result'))

        # Remove all triggers
        for trigger in self.__triggers:
            trigger.connector = None
        self.__triggers = []
        return (resp.generic.cmd_result.result == ResultCode.SUCCESS)

    def set_encryption(self, conn_handle, enabled=False, ll_key=None, ll_iv=None, key=None, rand=None, ediv=None):
        """Notify WHAD device about encryption status
        """
        print("set_encryption", enabled, ll_key.hex(), ll_iv.hex(), key.hex(), rand, ediv)
        # Send SetEncryptionCmd to device
        msg = Message()
        msg.ble.encryption.enabled = enabled
        msg.ble.encryption.conn_handle = conn_handle
        if ll_key is not None:
            msg.ble.encryption.ll_key = ll_key
        if ll_iv is not None:
            msg.ble.encryption.ll_iv = ll_iv
        if key is not None:
            msg.ble.encryption.key = key
        if rand is not None:
            msg.ble.encryption.rand = struct.pack('<Q', rand)
        if ediv is not None:
            msg.ble.encryption.ediv = struct.pack('<H', ediv)
        resp = self.send_command(msg, message_filter('generic', 'cmd_result'))

        # Update LL encryption status
        if (resp.generic.cmd_result.result == ResultCode.SUCCESS):
            self.__encrypted = enabled
            logger.info('[ble connector] encryption is now: %s' % self.__encrypted)

        # Return command result
        return (resp.generic.cmd_result.result == ResultCode.SUCCESS)

    def on_generic_msg(self, message):
        logger.info('generic message: %s' % message)
        pass

    def on_discovery_msg(self, message):
        logger.info('discovery message: %s' % message)
        pass

    def on_domain_msg(self, domain, message):
        if not self.__ready:
            return

        if domain == 'ble':
            msg_type = message.WhichOneof('msg')
            if msg_type == 'adv_pdu':
                packet = self.translator.from_message(message, msg_type)
                if packet is not None:
                    self.monitor_packet_rx(packet)

                    # Forward to advertising PDU callback if synchronous mode is set.
                    if self.is_synchronous():
                        self.add_pending_pdu(packet)                        
                    else:
                        self.on_adv_pdu(packet)

            elif msg_type == 'pdu':
                if message.pdu.processed:
                    packet = self.translator.from_message(message, msg_type)
                    if packet is not None:
                        self.monitor_packet_rx(packet)
                        logger.info('[ble PDU log-only]')
                else:
                    packet = self.translator.from_message(message, msg_type)
                    if packet is not None:
                        self.monitor_packet_rx(packet)

                        # Forward to generic PDU callback if auto mode is set.
                        if self.is_synchronous():
                            self.add_pending_pdu(packet)
                        else:
                            self.on_pdu(packet)

            elif msg_type == 'raw_pdu':
                if message.raw_pdu.processed:
                    packet = self.translator.from_message(message, msg_type)
                    if packet is not None:
                        self.monitor_packet_rx(packet)
                        logger.info('[ble PDU log-only]')
                else:
                    # Extract scapy packet
                    packet = self.translator.from_message(message, msg_type)
                    if packet is not None:
                        self.monitor_packet_rx(packet)

                        # Forward to raw pdu callback if auto mode is set.
                        if self.is_synchronous():
                            self.add_pending_pdu(packet)
                        else:
                            self.on_raw_pdu(packet)

            elif msg_type == 'synchronized':
                self.on_synchronized(
                    access_address = message.synchronized.access_address,
                    crc_init = message.synchronized.crc_init,
                    hop_interval = message.synchronized.hop_interval,
                    hop_increment = message.synchronized.hop_increment,
                    channel_map = message.synchronized.channel_map
                )

            elif msg_type == 'desynchronized':
                self.on_desynchronized(access_address=message.desynchronized.access_address)

            elif msg_type == 'connected':
                self.on_connected(message.connected)

            elif msg_type == 'disconnected':
                self.on_disconnected(message.disconnected)

            elif msg_type == 'triggered':
                self.on_triggered(message.triggered.id)


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

    def send_ctrl_pdu(self, pdu, conn_handle=0, direction=BleDirection.MASTER_TO_SLAVE, access_address=0x8e89bed6, encrypt=None):
        """
        Send CTRL PDU
        """
        logger.info('send control PDU to connection (handle:%d)' % conn_handle)
        return self.send_pdu(pdu, conn_handle=conn_handle, direction=direction, access_address=access_address, encrypt=encrypt)

    def send_data_pdu(self, data, conn_handle=0, direction=BleDirection.MASTER_TO_SLAVE, access_address=0x8e89bed6, encrypt=None):
        """
        Send data (L2CAP) PDU.
        """
        logger.info('send data PDU to connection (handle:%d)' % conn_handle)
        return self.send_pdu(data, conn_handle=conn_handle, direction=direction, access_address=access_address, encrypt=encrypt)

    def send_pdu(self, pdu, conn_handle=0, direction=BleDirection.MASTER_TO_SLAVE, access_address=0x8e89bed6, encrypt=None):
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

            resp = self.send_command(msg, message_filter('generic', 'cmd_result'))
            logger.info('[ble connector] Commant sent, result: %s' % resp)
            if resp is None:
                raise ConnectionLostException(None)
            else:
                return (resp.generic.cmd_result.result == ResultCode.SUCCESS)
        else:
            return False

from whad.ble.connector.peripheral import Peripheral, PeripheralClient
from whad.ble.connector.central import Central
from whad.ble.connector.injector import Injector
from whad.ble.connector.hijacker import Hijacker
from whad.ble.connector.sniffer import Sniffer
from whad.ble.connector.scanner import Scanner
