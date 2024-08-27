import struct
import logging

# Scapy
from scapy.layers.bluetooth4LE import BTLE, BTLE_ADV, BTLE_DATA, BTLE_ADV_IND, \
    BTLE_ADV_NONCONN_IND, BTLE_ADV_DIRECT_IND, BTLE_ADV_SCAN_IND, BTLE_SCAN_RSP
from scapy.packet import Packet

# Device interface
from whad.device import WhadDeviceConnector
from whad import WhadDomain, WhadCapability
from whad.exceptions import UnsupportedDomain, UnsupportedCapability

# Protocol hub
from whad.helpers import message_filter
from whad.hub.generic.cmdresult import Success, CommandResult
from whad.hub.ble.bdaddr import BDAddress
from whad.hub.ble.chanmap import ChannelMap
from whad.hub.ble import Commands, AdvType, Direction, BLEMetadata
from whad.hub.events import ConnectionEvt, DisconnectionEvt, SyncEvt, DesyncEvt, \
    TriggeredEvt, WhadEvent

# Bluetooth Low Energy dependencies
from whad.common.triggers import ManualTrigger, ConnectionEventTrigger, ReceptionTrigger
from whad.ble.profile.advdata import AdvDataFieldList

# Logging
logger = logging.getLogger(__name__)

class BLE(WhadDeviceConnector):
    """
    BLE protocol connector.

    This connector drives a BLE-capable device with BLE-specific WHAD messages.
    It is required by various role classes to interact with a real device and pre-process
    domain-specific messages.
    """
    domain = 'ble'

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
        if isinstance(packet, bytes):
            packet = BTLE(packet)
        return self.hub.ble.format(packet)

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
            raise UnsupportedDomain("Bluetooth Low Energy")
        else:
            self.__ready = True

        # Set synchronous mode if provided
        self.enable_synchronous(synchronous)

    def close(self):
        """Close BLE device
        """
        self.device.close()

    def support_raw_pdu(self) -> bool:
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
            self.__can_send = (
                (commands & (1 << Commands.SendPDU))>0 or
                (commands & (1 << Commands.SendRawPDU))
            )
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

        msg = self.hub.ble.create_trigger(trigger.identifier)
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

        msg = self.hub.ble.create_delete_sequence(trigger.identifier)

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
            msg = self.hub.ble.create_prepare_sequence_manual(
                trigger.identifier,
                direction,
                prep_packets
            )
        elif isinstance(trigger, ConnectionEventTrigger):
            # Create a prepared sequence with connection event trigger
            msg = self.hub.ble.create_prepare_sequence_conn_evt(
                trigger.identifier,
                direction,
                trigger.connection_event,
                prep_packets
            )
        elif isinstance(trigger, ReceptionTrigger):
            # Create a prepared sequence with reception trigger
            msg = self.hub.ble.create_prepare_sequence_pattern(
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
        msg = self.hub.ble.create_reactive_jam(channel, pattern, position)

        resp = self.send_command(msg, message_filter(CommandResult))
        return isinstance(resp, Success)

    def jam_advertisement_on_channel(self, channel=37):
        """
        Jam advertisements on a single channel.
        """
        if not self.can_jam_advertisement_on_channel():
            raise UnsupportedCapability("JamAdvOnChannel")

        # Create a JamAdvChan message
        msg = self.hub.ble.create_jam_adv_chan(channel)

        resp = self.send_command(msg, message_filter(CommandResult))
        return isinstance(resp, Success)

    def hijack_master(self, access_address):
        """
        Hijack the master role.
        """
        if not self.can_hijack_master():
            raise UnsupportedCapability("Hijack")

        # Create a HijackMaster message
        msg = self.hub.ble.create_hijack_master(access_address)

        resp = self.send_command(msg, message_filter(CommandResult))
        return isinstance(resp, Success)

    def discover_access_addresses(self):
        """
        Discover access addresses.
        """
        if not self.can_discover_access_addresses():
            raise UnsupportedCapability("AccessAddressesDiscovery")

        # Create SniffAccessAddress message
        msg = self.hub.ble.create_sniff_access_address(range(37))

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
        msg = self.hub.ble.create_sniff_active_conn(
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
        msg = self.hub.ble.create_hijack_slave(access_address)

        resp = self.send_command(msg, message_filter(CommandResult))
        return isinstance(resp, Success)

    def hijack_both(self, access_address):
        """
        Hijack both roles.
        """
        if not self.can_hijack_both():
            raise UnsupportedCapability("Hijack")

        # Create an HijackBoth message
        msg = self.hub.ble.create_hijack_both(access_address)

        resp = self.send_command(msg, message_filter(CommandResult))
        return isinstance(resp, Success)

    def sniff_advertisements(self, channel=37, bd_address="FF:FF:FF:FF:FF:FF"):
        """
        Sniff Bluetooth Low Energy advertisements (on a single channel).
        """
        if not self.can_sniff_advertisements():
            raise UnsupportedCapability("Sniff")

        # Create a SniffAdv message
        msg = self.hub.ble.create_sniff_adv(channel, BDAddress(bd_address))

        resp = self.send_command(msg, message_filter(CommandResult))
        return isinstance(resp, Success)

    def sniff_new_connection(self, channel=37, show_advertisements=True,
                             show_empty_packets=False, bd_address="FF:FF:FF:FF:FF:FF"):
        """
        Sniff Bluetooth Low Energy connection (from initiation).
        """
        if not self.can_sniff_new_connection():
            raise UnsupportedCapability("Sniff")

        # Create a SniffConnReq message
        msg = self.hub.ble.create_sniff_connreq(
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
            msg = self.hub.ble.create_set_bd_address(BDAddress(
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
        msg = self.hub.ble.create_scan_mode(active=active)

        resp = self.send_command(msg, message_filter(CommandResult))
        return isinstance(resp, Success)

    def enable_central_mode(self):
        """
        Enable Bluetooth Low Energy central mode (acts as master).
        """
        # Create a CentalMode message
        msg = self.hub.ble.create_central_mode()

        resp = self.send_command(msg, message_filter(CommandResult))
        return isinstance(resp, Success)

    def enable_adv_mode(self, adv_data=None, scan_data=None):
        """
        Enable BLE advertising mode (acts as a broadcaster)
        """
        # Create a AdvMode message
        msg = self.hub.ble.create_adv_mode(
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
        msg = self.hub.ble.create_periph_mode(
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
        msg = self.hub.ble.create_connect_to(
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
        msg = self.hub.ble.create_start()

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
        msg = self.hub.ble.create_disconnect(conn_handle)

        resp = self.send_command(msg, message_filter(CommandResult))
        return isinstance(resp, Success)


    def stop(self):
        """
        Stop currently enabled mode.
        """

        # Create a Stop message
        msg = self.hub.ble.create_stop()

        resp = self.send_command(msg, message_filter(CommandResult))

        # Remove all triggers
        for trigger in self.__triggers:
            trigger.connector = None
        self.__triggers = []

        return isinstance(resp, Success)

    def set_encryption(self, conn_handle, enabled=False, ll_key=None, ll_iv=None,
                       key=None, rand=None, ediv=None):
        """Notify WHAD device about encryption status
        """

        #print("set_encryption", enabled, ll_key.hex(), ll_iv.hex(), key.hex(), rand, ediv)

        # Create a SetEncryption message
        msg = self.hub.ble.create_set_encryption(
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
            logger.info('[ble connector] encryption is now: %s', self.__encrypted)

        # Return command result
        return isinstance(resp, Success)

    def on_generic_msg(self, message):
        """Generic message callback.
        """
        logger.info('generic message: %s', message)

    def on_discovery_msg(self, message):
        """Discovery message callback.
        """
        logger.info('discovery message: %s', message)

    def on_domain_msg(self, domain, message):
        """Domain-related message callback.
        """
        return

    def on_synchronized(self, access_address=None, crc_init=None, hop_increment=None,
                        hop_interval=None, channel_map=None):
        """Connection synchronization event callback.
        """
        return

    def on_desynchronized(self, access_address=None):
        """Connection desynchronization callback.
        """
        return

    def on_event(self, event: WhadEvent):
        """WHAD event callback handler.

        :param event: WHAD event to process
        :type event: :class:`whad.hub.events.WhadEvent`
        """
        # Don't process if connector is not ready
        if not self.__ready:
            return

        # Dispatch event
        if isinstance(event, ConnectionEvt):
            self.on_connected(event)
        elif isinstance(event, DisconnectionEvt):
            self.on_disconnected(event)
        elif isinstance(event, SyncEvt):
            self.on_synchronized(
                access_address = event.access_address,
                crc_init = event.crc_init,
                hop_interval = event.hop_interval,
                hop_increment = event.hop_increment,
                channel_map = event.channel_map
            )
        elif isinstance(event, DesyncEvt):
            self.on_desynchronized(access_address=event.access_address)
        elif isinstance(event, TriggeredEvt):
            self.on_triggered(event.id)

    def on_packet(self, packet: Packet):
        """Dispatch incoming packet.

        :param packet: Incoming packet
        :type packet: :class:`scapy.packet.Packet`
        """
        logger.debug('[BLE connector] on_packet')
        # discard processed packets or if we're not ready
        if hasattr(packet, "processed") and packet.metadata.processed or not self.__ready:
            return

        if BTLE_ADV in packet:
            adv_pdu = packet[BTLE_ADV:]
            adv_pdu.metadata = packet.metadata
            self.on_adv_pdu(adv_pdu)
        elif BTLE_DATA in packet:
            conn_pdu = packet[BTLE_DATA:]
            conn_pdu.metadata = packet.metadata
            if packet.LLID == 3:
                self.on_ctl_pdu(conn_pdu)
            elif packet.LLID in (1,2):
                self.on_data_pdu(conn_pdu)
            else:
                self.on_error_pdu(conn_pdu)

    def on_adv_pdu(self, packet: Packet):
        """Advertisement PDU callback
        """
        logger.info("received an advertisement PDU")

    def on_connected(self, connection_data: dict):
        """Connection event callback
        """
        logger.info("a connection has been established")
        logger.debug(
            "connection handle: %d" % connection_data.conn_handle if connection_data.conn_handle is not None else 0
        )

    def on_triggered(self, identifier):
        """Prepare sequence triggered event callback
        """
        for trigger in self.__triggers:
            if trigger.identifier == identifier:
                trigger.triggered = True

    def on_disconnected(self, disconnection_data: dict):
        """Disconnection event handler.
        """
        logger.info("a connection has been terminated")
        for trigger in self.__triggers:
            self.delete_sequence(trigger)

    def on_data_pdu(self, pdu):
        """Data PDU handler.
        """
        logger.info("received a data PDU")

    def on_ctl_pdu(self, pdu):
        """Control PDU handler.
        """
        logger.info("received a control PDU")

    def on_error_pdu(self, pdu):
        """Error PDU handler
        """
        return

    def send_ctrl_pdu(self, pdu, conn_handle=0, direction=Direction.MASTER_TO_SLAVE,
                      access_address=0x8e89bed6, encrypt=None):
        """Send control PDU
        """
        logger.info("send control PDU to connection (handle:%d)", conn_handle)
        return self.send_pdu(pdu, conn_handle=conn_handle, direction=direction,
                             access_address=access_address, encrypt=encrypt)

    def send_data_pdu(self, data, conn_handle=0, direction=Direction.MASTER_TO_SLAVE,
                      access_address=0x8e89bed6, encrypt=None):
        """Send data (L2CAP) PDU.
        """
        logger.info("send data PDU to connection (handle:%d)", conn_handle)
        return self.send_pdu(data, conn_handle=conn_handle, direction=direction, access_address=access_address, encrypt=encrypt)

    def send_pdu(self, pdu, conn_handle=0, direction=Direction.MASTER_TO_SLAVE,
                 access_address=0x8e89bed6, encrypt=None):
        """Send a generic BLE PDU.
        """
        if self.can_send():
            if self.support_raw_pdu():
                packet = BTLE(access_addr=access_address)/pdu
                send_raw = True
            else:
                packet = pdu
                send_raw = False

            # Build packet metadata in order to get this packet correctly
            # translated into the corresponding WHAD message.
            packet.metadata = BLEMetadata()
            packet.metadata.direction = direction
            packet.metadata.connection_handle = conn_handle
            packet.metadata.raw = send_raw

            # If encrypt is provided, take it into account
            # otherwise consider using the internal link-layer encryption status
            if encrypt is not None and isinstance(encrypt, bool):
                logger.info('[ble connector] encrypt is specified (%s)' % encrypt)
                packet.metadata.encrypt = True
            else:
                logger.info('[ble connector] link-layer encryption: %s' % self.__encrypted)
                packet.metadata.encrypt = False

            # Send BLE packet
            return super().send_packet(packet)
        else:
            return False

    def send_packet(self, packet: Packet):
        """Packet send hook

        This hook makes sure we are using a valid WHAD message when sending
        a packet, if this method is called from outside.

        :param packet: Packet to send
        :type packet: :class:`scapy.packet.Packet`
        :return: True if packet has correctly been sent, False otherwise.
        """

        if self.support_raw_pdu():
            # We expect a BTLE header for raw packets
            if BTLE not in packet and BTLE_DATA in packet:
                # Add a BTLE layer, copy metadata and mark packet
                # as raw.
                packet_ = BTLE(access_addr=0x11223344) / packet[BTLE_DATA]
                packet_.metadata = packet.metadata
                packet_.metadata.raw = True
        else:
            # We don't expect BTLE headers for non-raw packets
            if BTLE in packet:
                # Extract the BTLE_DATA layer, copy metadata and mark
                # packet as non-raw.
                packet_ = packet[BTLE_DATA]
                packet_.metadata = packet.metadata
                packet_.metadata.raw = False

        # Send BLE packet
        return super().send_packet(packet)

from whad.ble.connector.peripheral import Peripheral, PeripheralClient
from whad.ble.connector.central import Central
from whad.ble.connector.injector import Injector
from whad.ble.connector.hijacker import Hijacker
from whad.ble.connector.sniffer import Sniffer
from whad.ble.connector.scanner import Scanner
