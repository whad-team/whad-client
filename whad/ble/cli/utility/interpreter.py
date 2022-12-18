"""Bluetooth Low Energy PCAP Interpreter.

This module provide some classes and functions to parse a PCAP file containing
BLE packets. 

The main function is `interpret_pcap()` which implements all the logic. All the
interesting information is output to screen for now, but future version may
provide it as a specific class instance.

The approach is the following:

1. We look for a connection request packet in order to retrieve the initiator
   and advertiser BD addresses, as well as other useful information.
2. We also look for exchange of features through LL_FEATURE_REQ/LL_FEATURE_RESP
   and LL_SLAVE_FEATURE_REQ packets, since they provide useful information about
   the capabilities of each device
3. We also track LL_VERSION_IND packets as they convey very interesting info such
   as baseband vendor, firmware version and supported BLE version. Note that we
   suppose the first LL_VERSION_IND is sent by the master, but this is not always
   the case. Therefore, we may end up with the wrong version information assigned
   to the initiator and the advertiser (so be careful when interpreting it).
4. We parse all the ATT requests and responses to gather services and characteristics
   information and rebuild a `GenericProfile` instance (that serves as a DB)
5. We parse all GATT operations (read/write/notify/indicate) and seek information
   for each handle from the recovered profile, in order to display as much valuable
   information as possible.

NB: Control PDUs are not processed for the moment.
"""

from scapy.all import rdpcap
from scapy.layers.bluetooth4LE import BTLE_CONNECT_REQ, LL_FEATURE_REQ, \
    LL_FEATURE_RSP, LL_SLAVE_FEATURE_REQ, LL_VERSION_IND, BTLE_ADV, \
    BTLE_DATA, BTLE
from scapy.layers.bluetooth import ATT_Read_Request, ATT_Read_Blob_Request, \
    ATT_Write_Command, ATT_Write_Request, ATT_Write_Response, \
    ATT_Read_Blob_Response, ATT_Read_Response, \
    ATT_Read_By_Group_Type_Response, ATT_Read_By_Type_Response, \
    ATT_Find_Information_Response, ATT_Read_By_Group_Type_Request, \
    ATT_Error_Response, ATT_Read_By_Type_Request, \
    ATT_Find_Information_Request, L2CAP_Hdr, ATT_Hdr, \
    ATT_Handle_Value_Indication, ATT_Handle_Value_Notification
from struct import unpack, pack
from prompt_toolkit import print_formatted_text, HTML
from hexdump import hexdump

# Whad imports
import whad.scapy.layers.nordic
from whad.ble.profile import GenericProfile
from whad.ble.profile.characteristic import Characteristic, CharacteristicDescriptor, \
    ClientCharacteristicConfig
from whad.ble.profile.service import PrimaryService
from whad.ble.stack.gatt import GattReadByGroupTypeResponse, GattReadByTypeResponse, \
    GattFindInfoResponse
from whad.ble.stack.constants import BT_MANUFACTURERS, BT_VERSIONS
from whad.ble.stack.att.constants import BleAttErrorCode
from whad.ble.utils.att import UUID

# Logging
import logging
logger = logging.getLogger(__name__)

def le2be(v):
    return unpack('>I', pack('<I', v))[0]

class PeerInfo(object):
    """BLE Peer information

    This class is used to store information about a BLE peer.
    """

    def __init__(self, bd_address, addr_type, features, version):
        self.__bd_address = bd_address
        self.__addr_type = addr_type
        self.__features = features
        
        # Parse version if provided
        if version is not None:
            self.__company = version.company
            self.__ble_version = version.version
            self.__fw_version = version.subversion
        else:
            self.__company = None
            self.__ble_version = None
            self.__fw_version = None

    def support_lesc(self):
        """Determine if peer supports LE Secure Connection
        """
        if self.__features is not None:
            return self.__features.feature_set.le_encryption

    def support_ping(self):
        """Determine if peer supports LE Ping procedure
        """
        if self.__features is not None:
            return self.__features.feature_set.le_ping

    def support_le_2m_phy(self):
        """Determine if peer supports 2M PHY (BLE 5.x)
        """
        if self.__features is not None:
            return self.__features.feature_set.le_2m_phy

    def support_ll_privacy(self):
        """Determine if peer supports LE LL privacy
        """
        if self.__features is not None:
            return self.__features.feature_set.ll_privacy

    def support_csa2(self):
        """Determine if peer supports Channel Selection Algorithm #2
        """
        if self.__features is not None:
            return self.__features.feature_set.ch_sel_alg

    def support_coded_phy(self):
        """Determine if peer supports Coded PHY (BLE 5.x)
        """
        if self.__features is not None:
            return self.__features.feature_set.le_coded_phy

    def support_conn_param_req(self):
        """Determine if peer supports Connection Parameter Request procedure
        """
        if self.__features is not None:
            return self.__features.feature_set.conn_par_req_proc

    @property
    def address(self):
        return self.__bd_address

    @property
    def address_type(self):
        return self.__addr_type

    @property
    def company(self):
        return self.__company
    
    @property
    def ble_version(self):
        return self.__ble_version
    
    @property
    def fw_version(self):
        return self.__fw_version


class ConnectionInfo(object):
    """BLE Connection information

    Holds all the required information about a connection, its master and slave.
    """

    def __init__(self, conn_req, conn_req_meta, feature_req, feature_resp, slave_feature_req, slave_feature_resp, master_version, slave_version):
        if conn_req_meta is not None:
            txadd = conn_req_meta.TxAdd
            rxadd = conn_req_meta.RxAdd
        else:
            txadd = 0
            rxadd = 0

        if conn_req is not None:
            txadd = conn_req
            # Save master information
            if feature_req is not None:
                self.master = PeerInfo(conn_req.InitA, txadd, feature_req, master_version)
            elif slave_feature_req is not None:
                self.master = PeerInfo(conn_req.InitA, txadd, slave_feature_req, master_version)
            else:
                self.master = PeerInfo(conn_req.InitA, txadd, None, master_version)

            # Save slave information
            if feature_resp is not None:
                self.slave = PeerInfo(conn_req.AdvA, rxadd, feature_resp, slave_version)
            elif slave_feature_resp is not None:
                self.slave = PeerInfo(conn_req.AdvA, rxadd, slave_feature_resp, slave_version)
            else:
                self.slave = PeerInfo(conn_req.AdvA, rxadd, None, slave_version)
            
            # Save access address
            self.access_address = le2be(conn_req.AA)
        else:
            # Save master information
            if feature_req is not None:
                self.master = PeerInfo(None, txadd, feature_req, master_version)
            elif slave_feature_req is not None:
                self.master = PeerInfo(None, txadd, slave_feature_req, master_version)
            else:
                self.master = PeerInfo(None, txadd, None, master_version)
            
            # Save slave information
            if feature_resp is not None:
                self.slave = PeerInfo(None, rxadd, feature_resp, slave_version)
            elif slave_feature_resp is not None:
                self.slave = PeerInfo(None, rxadd, slave_feature_resp, slave_version)
            else:
                self.slave = PeerInfo(None, rxadd, None, slave_version)
            
            # No access address
            self.access_address = None


    def __repr__(self):
        desc  = 'BLE Connection information:\n'
        desc += ' Access Address: %08x\n' % self.access_address
        desc += '\n'
        if self.master.address is not None:
            desc += ' Master info:\n'
            desc += '  - BD address: %s (%s)\n' % (
                self.master.address,
                'public' if self.master.address_type == 0 else 'random'
            )
        if self.master.company is not None:
            desc += '  - Company: %04x\n' % self.master.company
            desc += '  - BLE version: %02x\n' % self.master.ble_version
            desc += '  - FW version: %04x\n' % self.master.fw_version

        if self.slave.address is not None:
            desc += '\n'
            desc += ' Slave info:\n'
            desc += '  - BD address: %s (%s)\n' % (
                self.slave.address,
                'public' if self.slave.address_type == 0 else 'random'
            )
        if self.slave.company is not None:
            desc += '  - Company: %04x\n' % self.slave.company
            desc += '  - BLE version: %02x\n' % self.slave.ble_version
            desc += '  - FW version: %04x\n' % self.slave.fw_version

        return desc
        

def find_conn_info(packets):
    """Find information about master and slave based on captured packets,
    as well as connection information.
    """
    connections = []

    conn_request = None
    conn_request_meta = None
    feature_req = None
    feature_resp = None
    slave_feature_req = None
    slave_feature_resp = None
    master_version_ind = None
    slave_version_ind = None

    # We extract every interesting packet that may be useful to gather
    # information about the connection
    for packet in packets:
        # Do we have a connection request ?
        if packet.haslayer(BTLE_CONNECT_REQ):
            logger.info('found CONN_REQ packet')

            if conn_request is not None:
                logger.debug('a connection was already detected, save it')

                # A new connection has started, store information about
                # the previous connection
                connections.append(ConnectionInfo(
                    conn_request,
                    conn_request_meta,
                    feature_req,
                    feature_resp,
                    slave_feature_req,
                    slave_feature_resp,
                    master_version_ind,
                    slave_version_ind
                ))
                
            # Keep track of master device and connreq
            conn_request = packet[BTLE_CONNECT_REQ]
            conn_request_meta = packet[BTLE_ADV]

            # Reset other tracked packets
            feature_req = None
            feature_resp = None
            slave_feature_req = None
            slave_feature_resp = None
            master_version_ind = None
            slave_version_ind = None

        elif packet.haslayer(LL_VERSION_IND):
            # Usually, version is queried by the master.
            if master_version_ind is None:
                logger.debug('found an LL_VERSION_IND control PDU, assumed to be from initiator')
                master_version_ind = packet[LL_VERSION_IND]
            else:
                logger.debug('found an LL_VERSION_IND control PDU, assumed to be from advertiser')
                slave_version_ind = packet[LL_VERSION_IND]
        elif packet.haslayer(LL_FEATURE_REQ):
            logger.debug('found an LL_FEATURE_REQ control PDU')
            feature_req = packet[LL_FEATURE_REQ]
        elif packet.haslayer(LL_SLAVE_FEATURE_REQ):
            logger.debug('found an LL_SLAVE_FEATURE_REQ control PDU')
            slave_feature_req = packet[LL_SLAVE_FEATURE_REQ]
        elif packet.haslayer(LL_FEATURE_RSP):
            logger.debug('found an LL_FEATURE_RSP control PDU')
            if slave_feature_req is not None and slave_feature_resp is None:
                slave_feature_resp = packet[LL_FEATURE_RSP]
            else:
                feature_resp = packet[LL_FEATURE_RSP]

    connections.append(ConnectionInfo(
        conn_request,
        conn_request_meta,
        feature_req,
        feature_resp,
        slave_feature_req,
        slave_feature_resp,
        master_version_ind,
        slave_version_ind
    ))

    return connections


def recover_profile(connection, packets):
    """Parse BLE packets and try to rebuild the device profile.

    This method parses the provided BLE packets to identify service
    and characteristics discovery procedures, and build a GATT profile
    based on this information.

    We are looking for specific ATT packets:
    - ATT_Read_By_Group_Type_Response
    - ATT_Read_By_Type_Response
    - ATT_Find_Information_Response

    We follow the packet flow and use a very small state machine to
    analyze the GATT procedures and deduce services, characteristics and CCCD.
    """
    logging.debug('recovering GATT profile for connection with AA 0x%08x' % (
        connection.access_address)
    )

    in_service_discovery = False
    in_charac_discovery = False
    in_desc_discovery = False
    end_handle = -1
    services = []
    characs = {}

    def find_service_by_char_handle(handle: int):
        """Find cached service by handle.
        """
        for service in services:
            if handle >= service.handle and handle <= service.end_handle:
                return service
        return None

    # We build a generic profile, it will be populated later.
    profile = GenericProfile()
    for packet in packets:

        # Do not track packets that do not match our connection Access Address
        if packet.haslayer(BTLE):
            access_address = packet[BTLE].access_addr
            if access_address != connection.access_address:
                logger.debug('packet access address does not match')
                continue

        if packet.haslayer(ATT_Read_By_Group_Type_Request):
            logger.debug('found ATT_Read_By_group_Type_Request')
            req:ATT_Read_By_Group_Type_Request = packet[ATT_Read_By_Group_Type_Request]

            # Are we looking for services ?
            if req.uuid == 0x2800:
                logger.debug('client is looking for primary services declaration')
                logger.debug('switch state to service discovery')
                in_service_discovery = True
            else:
                logger.debug('request does not search for services (%s)' % (
                    UUID(req.uuid)
                ))

        elif packet.haslayer(ATT_Read_By_Group_Type_Response) and in_service_discovery:
            logger.debug('found ATT_Read_By_Group_Type_Response during service discovery')

            # Parse response if we are currently searching for services
            resp = packet[ATT_Read_By_Group_Type_Response]
            gatt_resp = GattReadByGroupTypeResponse.from_bytes(
                resp.length,
                resp.data
            )

            # Iterate over services
            logger.debug('iterate over service declarations')
            for item in gatt_resp:
                services.append(PrimaryService(
                    uuid=UUID(item.value),
                    handle=item.handle,
                    end_handle=item.end
                ))
            
            # Stop processing this type of packet if end_handle == 0xffff
            if item.end == 0xffff:
                logger.debug('service has end handle 0xffff, service discovery done.')
                in_service_discovery = False

        elif packet.haslayer(ATT_Read_By_Type_Request) and not in_charac_discovery:
            logger.debug('found ATT_Read_By_Type_Request')
            # Read by type request, we check if it is dealing with characteristics
            req = packet[ATT_Read_By_Type_Request]
            if req.uuid == 0x2803:
                logger.debug('client is looking for characterstic declarations')
                logger.debug('switch state to characteristic discovery')
                # Yes, keep track of end handle and enable characteristic discovery
                end_handle = req.end
                in_charac_discovery = True

        elif packet.haslayer(ATT_Read_By_Type_Response) and in_charac_discovery:
            logger.debug('found ATT_Read_By_Type_Response packet')
            # Read by type response received
            resp = packet[ATT_Read_By_Type_Response]

            # Must rebuild handles payload as bytes, since scapy parsed it :(
            handles = b''.join([item.build() for item in resp.handles])
            gatt_resp = GattReadByTypeResponse.from_bytes(
                resp.len,
                handles
            )

            # Iterate over items
            logger.debug('iterate over characteristic declarations')
            for item in gatt_resp:
                # Build characteristic object
                charac_properties = item.value[0]
                charac_handle = item.handle
                charac_value_handle = unpack('<H', item.value[1:3])[0]
                charac_uuid = UUID(item.value[3:])
                charac = Characteristic(
                    uuid=charac_uuid,
                    properties=charac_properties
                )
                charac.handle = charac_handle
                charac.value_handle = charac_value_handle

                # Find service where this characteristic belongs
                service = find_service_by_char_handle(charac_handle)
                if service is not None:
                    # cache characteristic
                    characs[charac.handle] = charac
                    service.add_characteristic(charac)
                
                # Consider charac discovery done when we reach the request
                # end handle
                if item.handle == end_handle:
                    logger.debug('characteristic discovery done')
                    in_charac_discovery = False

        elif packet.haslayer(ATT_Find_Information_Request):
            logger.debug('found ATT_Find_Information_Request')
            # Generally used to discover descriptors
            req = packet[ATT_Find_Information_Request]
            if req.start not in characs:
                # Are we discovering a descriptor of a known characteristic ?
                if req.start - 2 in characs:
                    logger.debug('client is looking for information on descriptors')
                    in_desc_discovery = True

        elif packet.haslayer(ATT_Find_Information_Response) and in_desc_discovery:
            logger.debug('found ATT_Find_Information_Response packet')

            # Parse characteristic descriptors
            resp = packet[ATT_Find_Information_Response]
            handles = b''.join([item.build() for item in resp.handles])
            gatt_resp = GattFindInfoResponse.from_bytes(
                resp.format,
                handles
            )

            # Iterate over information, keep only CCCD descriptors.
            logger.debug('iterate over descriptors declaration')
            for descriptor in gatt_resp:
                handle = descriptor.handle
                if descriptor.uuid == UUID(0x2902) and (handle-2) in characs:
                    charac = characs[handle - 2]
                    
                    # Add CCCD
                    charac.add_descriptor(
                        ClientCharacteristicConfig(
                            charac,
                            handle=descriptor.handle
                        )
                    )
                # End discovery if returned handle is Ending Handle (0xFFFF)
                if handle == 0xFFFF:
                    logger.debug('descriptor discovery done')
                    in_desc_discovery = False

        elif packet.haslayer(ATT_Error_Response):
            logger.debug('found ATT_Error_Response packet')
            # We received an error message
            error = packet[ATT_Error_Response]

            # If we were trying to discover a service, then consider discovery over
            if error.ecode == BleAttErrorCode.ATTRIBUTE_NOT_FOUND and in_service_discovery:
                logger.debug('Received ATTRIBUTE_NOT_FOUND, service discovery done')
                in_service_discovery = False
            # If we were trying to discover a characteristic, then consider discovery over
            elif error.ecode == BleAttErrorCode.ATTRIBUTE_NOT_FOUND and in_charac_discovery:
                logger.debug('Received ATTRIBUTE_NOT_FOUND, characteristic discovery done')
                in_charac_discovery = False
            # If we were trying to discover a descriptor, then consider discovery over
            elif error.ecode == BleAttErrorCode.ATTRIBUTE_NOT_FOUND and in_desc_discovery:
                logger.debug('Received ATTRIBUTE_NOT_FOUND, descriptor discovery done')
                in_desc_discovery = False

    # Add discovered services and characteristics
    for service in services:
        profile.add_service(service)

    # Return GATT profile
    return profile


def conn_summary(conn_meta, profile, packets):
    """Iterate over packets and analyze characteristics read/write/subscribe operations.

    This function prints on screen all the valuable information we gathered so far,
    and process packets to reconstruct GATT operations and display them on screen as
    well. 

    :param ConnectionInfo conn_meta: Connection information
    :param GattProfile profile: Recovered GATT profile for the device
    :param list packets: list of packets extracted from PCAP
    """
    # First, we display a small summary about peers.
    print_formatted_text(HTML('<b><ansigreen>Information about peers</ansigreen></b>'))
    print('')

    if conn_meta.master.address is not None:
        logger.debug('initiator is known, display BD address')
        print_formatted_text(HTML('<ansicyan>Initiator</ansicyan>'))
        print_formatted_text(HTML('<b>BD address:</b> %s <b>(%s)</b>' % (
            conn_meta.master.address,
            'public' if conn_meta.master.address_type == 0 else 'random'
        )))
        
        if conn_meta.master.company is not None:
            logger.debug('initiator has version information, showing company and fw/ble versions')
            print_formatted_text(HTML('<b>Baseband vendor:</b> %s (%04x)' %(
                BT_MANUFACTURERS[conn_meta.master.company],
                conn_meta.master.company
            )))
            print_formatted_text(HTML('<b>Supported BLE version:</b> %s' % (
                BT_VERSIONS[conn_meta.master.ble_version]
            )))
            print_formatted_text(HTML('<b>Firmware version:</b> %04x' % (
                conn_meta.master.fw_version
            )))
        print('')

    if conn_meta.slave.address is not None:
        logger.debug('advertiser is known, display BD address')
        print_formatted_text(HTML('<ansicyan>Advertiser</ansicyan>'))
        print_formatted_text(HTML('<b>BD address:</b> %s <b>(%s)</b>' % (
            conn_meta.slave.address,
            'public' if conn_meta.slave.address_type == 0 else 'random'
        )))
        if conn_meta.slave.company is not None:
            logger.debug('advertiser has version information, showing company and fw/ble versions')
            print_formatted_text(HTML('<b>Baseband vendor:</b> %s (%04x)' %(
                BT_MANUFACTURERS[conn_meta.slave.company],
                conn_meta.slave.company
            )))
            print_formatted_text(HTML('<b>Supported BLE version:</b> %s' % (
                BT_VERSIONS[conn_meta.slave.ble_version]
            )))
            print_formatted_text(HTML('<b>Firmware version:</b> %04x' % (
                conn_meta.slave.fw_version
            )))
        print('')

    # Then, displayed recovered profile (if any)
    if len(list(profile.services())) > 0:
        logger.debug('at least one service has been detected, display GATT profile')
        print_formatted_text(HTML('<ansigreen><b>GATT Profile</b></ansigreen>\n'))
        print(profile)

    print_formatted_text(HTML('<ansigreen><b>GATT operations</b></ansigreen>\n'))

    # Last, parse read/write/subscribe/notify operations
    l2cap_pending_pkt = None
    l2cap_exp_len = -1
    cur_att_handle = None

    for ble_packet in packets:

        packet = None

        # Check packet is complete, rerassemble if required
        if ble_packet.haslayer(BTLE_DATA):
            btle_hdr = ble_packet[BTLE_DATA]

            if btle_hdr.LLID == 2:
                logger.debug('L2CAP start of fragment received')
                l2cap_hdr = ble_packet[L2CAP_Hdr]
                if l2cap_hdr.len == len(l2cap_hdr.payload):
                    logger.debug('L2CAP packet is complete')
                    # Packet is complete.
                    packet = ble_packet
                else:
                    logger.debug('L2CAP packet is incomplete, missing %d bytes' % (
                        l2cap_exp_len - len(ble_packet[L2CAP_Hdr].payload)
                    ))
                    # Start of fragmented packet
                    l2cap_pending_pkt = ble_packet[L2CAP_Hdr]
                    l2cap_exp_len = l2cap_pending_pkt.len
            elif btle_hdr.LLID == 1:
                logger.debug(
                    'L2CAP packet continuation received (%d bytes)' % (
                        len(btle_hdr.payload)
                    )
                )
                logger.debug(
                    'L2CAP packet reassembled fragment size: %d bytes' % (
                        len(l2cap_pending_pkt.payload) + len(btle_hdr.payload)
                    )
                )

                # Packet continuation, update packet
                l2cap_pending_pkt = L2CAP_Hdr(
                    len=len(l2cap_pending_pkt.payload) + len(btle_hdr.payload),
                    cid=l2cap_pending_pkt.cid,
                )/ (bytes(l2cap_pending_pkt.payload) + bytes(btle_hdr.payload))

                # Do we have a complete packet ?
                if len(l2cap_pending_pkt.payload) == l2cap_exp_len:
                    logger.debug('L2CAP packet reassembled, process it')
                    packet = L2CAP_Hdr(
                        len=l2cap_pending_pkt.len,
                        cid=l2cap_pending_pkt.cid,
                    ) / ATT_Hdr(bytes(l2cap_pending_pkt.payload))

        # Process packet
        if packet is not None:

            # Read request
            if packet.haslayer(ATT_Read_Request):
                req = packet[ATT_Read_Request]
                logger.debug('received an ATT_Read_Request packet')
                logger.debug('update current ATT handle to %d' % req.gatt_handle)
                cur_att_handle = req.gatt_handle

            # Read response
            elif packet.haslayer(ATT_Read_Response) and cur_att_handle is not None:
                logger.debug('received an ATT_Read_Response packet')
                resp = packet[ATT_Read_Response]
                try:
                    logger.debug('resolving characteristic from handle ...')
                    # Find the characteristic this value belongs to
                    charac = profile.find_object_by_handle(cur_att_handle - 1)
                    logger.debug('found matching characteristic with UUID %s' % (
                        charac.uuid
                    ))

                    # Are we reading a characteristic ?
                    if isinstance(charac, Characteristic):
                        service = profile.find_service_by_characteristic_handle(charac.handle)
                        print_formatted_text(HTML('<ansimagenta>Reading</ansimagenta> characteristic <ansicyan>%s</ansicyan> from service <ansicyan>%s</ansicyan>' % (
                            charac.uuid, 
                            service.uuid
                        )))
                        hexdump(resp.value)

                    cur_att_handle = None
                except IndexError as oopsie:
                    logger.debug('no characteristic found, considering handle only')
                    # Characteristic is unknown, consider attribute handle only
                    print_formatted_text(HTML('<ansimagenta>Reading</ansimagenta> handle <ansicyan>%d</ansicyan>' % (
                        cur_att_handle
                    )))
                    hexdump(resp.value)

                    cur_att_handle = None

            # Write command
            elif packet.haslayer(ATT_Write_Command):
                logger.debug('received an ATT_Write_Command packet')
                req = packet[ATT_Write_Command]
                try:
                    logger.debug('resolving characteristic from handle %d' % req.gatt_handle)
                    is_cccd = False
                    try:
                        # Find the characteristic this value belongs to
                        charac = profile.find_object_by_handle(req.gatt_handle - 1)
                        logger.debug('found matching characteristic with UUID %s' % (
                            charac.uuid
                        ))
                    except IndexError as not_value:
                        logger.debug('no characteristic found, looking for CCCD')
                        # Is it a CCCD ?
                        charac = profile.find_object_by_handle(req.gatt_handle - 2)
                        logger.debug('found matching CCCD for characteristic %s' % (
                            charac.uuid
                        ))
                        is_cccd = True

                    if is_cccd:
                        service = profile.find_service_by_characteristic_handle(charac.handle - 2)

                        # Writing to CCCD
                        value = unpack('<H', bytes(req.data)[:2])[0]
                        if value == 0x0002:
                            logger.debug('client wrote 0x0002 to CCCD: indication')

                            # Client subscribes for indication
                            print_formatted_text(HTML('<ansimagenta>Subscribe for indication</ansimagenta> to characteristic <ansicyan>%s</ansicyan> from service <ansicyan>%s</ansicyan>' % (
                                charac.uuid, 
                                service.uuid 
                            )))
                        elif value == 0x0001:
                            logger.debug('client wrote 0x0001 to CCCD: notification')

                            # Client subscribes for notification
                            print_formatted_text(HTML('<ansimagenta>Subscribe for notification</ansimagenta> to characteristic <ansicyan>%s</ansicyan> from service <ansicyan>%s</ansicyan>' % (
                                charac.uuid, 
                                service.uuid 
                            )))
                        elif value == 0x0000:
                            logger.debug('client wrote 0x0000 to CCCD: disabled')

                            # Client unsubscribes
                            print_formatted_text(HTML('<ansimagenta>Unsubscribe</ansimagenta> from characteristic <ansicyan>%s</ansicyan> from service <ansicyan>%s</ansicyan>' % (
                                charac.uuid, 
                                service.uuid 
                            )))
                    elif isinstance(charac, Characteristic):
                        service = profile.find_service_by_characteristic_handle(charac.handle)
                        print_formatted_text(HTML('<ansimagenta>Writing</ansimagenta> to characteristic <ansicyan>%s</ansicyan> from service <ansicyan>%s</ansicyan> (without response)' % (
                            charac.uuid, 
                            service.uuid
                        )))
                        hexdump(req.data)

                    cur_att_handle = None
                except IndexError as oops:
                    logger.debug('unable to find a matching characteristic or CCCD for handle %d' % (
                        req.gatt_handle
                    ))

                    # Characteristic is unknown, consider attribute handle only
                    print_formatted_text(HTML('<ansimagenta>Writing</ansimagenta> to handle <ansicyan>%d</ansicyan> (without response)' % (
                        req.gatt_handle
                    )))
                    hexdump(req.data)

                    cur_att_handle = None

            # Write request
            elif packet.haslayer(ATT_Write_Request):
                logger.debug('received an ATT_Write_Request packet')
                req = packet[ATT_Write_Request]
                try:
                    logger.debug('resolving characteristic from handle %d' % req.gatt_handle)
                    is_cccd = False
                    try:
                        # Find the characteristic this value belongs to
                        charac = profile.find_object_by_handle(req.gatt_handle - 1)
                        
                        logger.debug('found matching characteristic with UUID %s' % (
                            charac.uuid
                        ))
                    except IndexError as not_value:
                        # Is it a CCCD ?
                        charac = profile.find_object_by_handle(req.gatt_handle - 2)
                        logger.debug('found matching CCCD for characteristic %s' % (
                            charac.uuid
                        ))
                        is_cccd = True

                    if is_cccd:
                        service = profile.find_service_by_characteristic_handle(charac.handle - 2)

                        # Writing to CCCD
                        value = unpack('<H', bytes(req.data)[:2])[0]
                        if value == 0x0002:
                            logger.debug('client wrote 0x0002 to CCCD: indication')

                            # Client subscribes for indication
                            print_formatted_text(HTML('<ansimagenta>Subscribe for indication</ansimagenta> to characteristic <ansicyan>%s</ansicyan> from service <ansicyan>%s</ansicyan>' % (
                                charac.uuid, 
                                service.uuid 
                            )))
                        elif value == 0x0001:
                            logger.debug('client wrote 0x0001 to CCCD: notification')

                            # Client subscribes for notification
                            print_formatted_text(HTML('<ansimagenta>Subscribe for notification</ansimagenta> to characteristic <ansicyan>%s</ansicyan> from service <ansicyan>%s</ansicyan>' % (
                                charac.uuid, 
                                service.uuid 
                            )))
                        elif value == 0x0000:
                            logger.debug('client wrote 0x0000 to CCCD: disabled')

                            # Client unsubscribes
                            print_formatted_text(HTML('<ansimagenta>Unsubscribe</ansimagenta> from characteristic <ansicyan>%s</ansicyan> from service <ansicyan>%s</ansicyan>' % (
                                charac.uuid, 
                                service.uuid 
                            )))
                    elif isinstance(charac, Characteristic):
                        service = profile.find_service_by_characteristic_handle(charac.handle)
                        print_formatted_text(HTML('<ansimagenta>Writing</ansimagenta> to characteristic <ansicyan>%s</ansicyan> from service <ansicyan>%s</ansicyan>' % (
                            charac.uuid, 
                            service.uuid
                        )))
                        hexdump(req.data)
                except IndexError as oops:
                    logger.debug('unable to find a matching characteristic or CCCD for handle %d' % (
                        req.gatt_handle
                    ))

                    # Characteristic is unknown, consider attribute handle only
                    print_formatted_text(HTML('<ansimagenta>Writing</ansimagenta> to handle <ansicyan>%d</ansicyan>' % (
                        req.gatt_handle
                    )))
                    hexdump(req.data)

            # Indication
            elif packet.haslayer(ATT_Handle_Value_Indication):
                indicate = packet[ATT_Handle_Value_Indication]
                try:
                    # Find service and characteristic
                    charac = profile.find_object_by_handle(indicate.gatt_handle - 1)
                    service = profile.find_service_by_characteristic_handle(charac.handle)

                    # Show notification
                    print_formatted_text(HTML('<ansired>Indication</ansired> for characteristic <ansicyan>%s</ansicyan> from service <ansicyan>%s</ansicyan>' % (
                                charac.uuid, 
                                service.uuid
                            )))
                    hexdump(bytes(indicate.value))
                except IndexError as oopsie:
                    # Show notification
                    print_formatted_text(HTML('<ansired>Indication</ansired> for handle <ansicyan>%d</ansicyan>' % (
                                indicate.gatt_handle
                            )))
                    hexdump(bytes(indicate.value))

            # Notification
            elif packet.haslayer(ATT_Handle_Value_Notification):
                notify = packet[ATT_Handle_Value_Notification]
                try:
                    # Find service and characteristic
                    charac = profile.find_object_by_handle(notify.gatt_handle - 1)
                    service = profile.find_service_by_characteristic_handle(charac.handle)

                    # Show notification
                    print_formatted_text(HTML('<ansired>Notification</ansired> for characteristic <ansicyan>%s</ansicyan> from service <ansicyan>%s</ansicyan>' % (
                                charac.uuid, 
                                service.uuid
                            )))
                    hexdump(bytes(notify.value))
                except IndexError as oopsie:
                    # Show notification
                    print_formatted_text(HTML('<ansired>Notification</ansired> for handle <ansicyan>%d</ansicyan>' % (
                                notify.gatt_handle
                            )))
                    hexdump(bytes(notify.value))


def interpret_pcap(pcap_file: str):
    """Interpret BLE operations in the provided PCAP file.

    This function parses a PCAP file and recovers a BLE connection's parameters,
    services/characteristics structure (GATT profile), and decodes all GATT
    operations performed. Everything is output to screen.

    :param str pcap_file: Path to a valid PCAP file containing BLE packets
    """
    # Read pcap packets
    logger.info('read packets from PCAP ...')
    packets = rdpcap(pcap_file)    

    # First, look for connection-related packets:
    # - connection request
    # - feature request/response
    # - slave feature request/response
    # - version_ind
    logger.info('analyzing global connections and deduce information about peers')
    connections = find_conn_info(packets)
    logger.info('found %d connections in PCAP' % len(connections))

    for conn_id, connection in enumerate(connections):
        logger.info('processing connection %d with AA %08x' % (
            conn_id, connection.access_address
        ))

        print_formatted_text(HTML("<ansiblue><b><u>Connection #%d</u></b></ansiblue>\n" % (
            conn_id + 1
        )))

        # Then, we look for services/characteristics discovery packets
        logger.info('retrieving GATT profile from our analysis')
        profile = recover_profile(connection, packets)

        # Based on the recovered profile, interpret all the characteristics
        # and descriptors operations
        logger.info('displaying a connection summary')
        conn_summary(connection, profile, packets)
