from whad.dot15d4.stack.manager import Dot15d4Manager
from whad.dot15d4.stack.service import Dot15d4Service
from whad.dot15d4.stack.mac.constants import MACAddressMode
from whad.dot15d4.stack.mac.helpers import is_short_address

from whad.zigbee.stack.aps.exceptions import APSTimeoutException
from whad.zigbee.stack.aps.database import APSIB
from whad.zigbee.stack.aps.security import APSApplicationLinkKeyData, \
    APSNetworkKeyData, APSTrustCenterLinkKeyData
from whad.zigbee.stack.aps.constants import APSSecurityStatus, \
    APSSourceAddressMode, APSDestinationAddressMode, APSKeyType
from whad.zigbee.stack.nwk.constants import NWKAddressMode
from whad.zigbee.crypto import ApplicationSubLayerCryptoManager

from whad.zigbee.stack.apl import APLManager
from whad.common.stack import alias, source, state

from scapy.layers.zigbee import ZigbeeSecurityHeader, ZigbeeAppDataPayload, \
    ZigbeeAppCommandPayload, ZigbeeClusterLibrary, ZigbeeDeviceProfile

from whad.exceptions import RequiredImplementation

import logging

logger = logging.getLogger(__name__)


class APSService(Dot15d4Service):
    """
    This class represents an APS service, exposing a standardized API.
    """
    def __init__(self, manager, name=None):
        super().__init__(manager, name=name, timeout_exception_class=APSTimeoutException)


class APSDataService(APSService):
    """
    APS service processing Data frames.
    """
    def __init__(self, manager):
        super().__init__(manager, name="aps_data")

    @Dot15d4Service.request("APSDE-DATA")
    def data(
                self,
                asdu,
                destination_address_mode,
                destination_address,
                destination_endpoint,
                profile_id,
                cluster_id,
                source_endpoint,
                alias_address=None,
                alias_sequence_number=0,
                radius=30,
                security_enabled_transmission=False,
                use_network_key=False,
                acknowledged_transmission=False,
                fragmentation_permitted=False,
                include_extended_nonce=False
    ):
        """
        Implements the APSDE-DATA Request.

        Processes and transmits Data PDU to lowest layers.
        """
        multicast = False
        # If transmission must be secured, select the key pair, encrypt and add a security header accordingly
        if security_enabled_transmission:
            apsDeviceKeyPairSet = self.database.get("apsDeviceKeyPairSet")
            candidate_keys = apsDeviceKeyPairSet.select(destination_address, unverified=False)
            if len(candidate_keys) == 0:
                return False
            candidate_key = candidate_keys[0]
            key_identifier = 0
            asdu = ZigbeeSecurityHeader(
                key_type=key_identifier,
                extended_nonce=int(include_extended_nonce),
                fc=candidate_key.outgoing_frame_counter,
                data=bytes(asdu)
            )
            if asdu.extended_nonce:
                asdu.source=self.manager.get_layer('nwk').database.get("nwkIeeeAddress")

            crypto_manager = ApplicationSubLayerCryptoManager(candidate_key.key, None)
            asdu = crypto_manager.encrypt(asdu)


        if destination_address_mode == APSDestinationAddressMode.DST_ADDRESS_AND_DST_ENDPOINT_NOT_PRESENT:
            raise RequiredImplementation("BindingTableSearch")

        elif destination_address_mode == APSDestinationAddressMode.SHORT_ADDRESS_DST_ENDPOINT_PRESENT:
            apdu = ZigbeeAppDataPayload(
                delivery_mode = 0,
                dst_endpoint = destination_endpoint,
                src_endpoint = source_endpoint,
                profile=profile_id,
                cluster=cluster_id,
                counter=self.manager.database.get("apsCounter")
            )/asdu

        elif destination_address_mode == APSDestinationAddressMode.EXTENDED_ADDRESS_DST_ENDPOINT_PRESENT:
            nwkAddressMap = self.manager.get_layer('nwk').database.get("nwkAddressMap")
            short_destination_address = None
            if destination_address in nwkAddressMap:
                destination_address = nwkAddressMap[destination_address]
            else:
                return False
            apdu = ZigbeeAppDataPayload(
                dst_endpoint=destination_endpoint,
                cluster=cluster_id,
                profile=profile_id,
                src_endpoint=source_endpoint,
                counter=self.manager.database.get("apsCounter")
            )/asdu
        elif destination_address_mode == APSDestinationAddressMode.SHORT_GROUP_ADDRESS_DST_ENDPOINT_NOT_PRESENT:
            apdu = ZigbeeAppDataPayload(
                delivery_mode = 3,
                group_addr = destination_address,
                src_endpoint = source_endpoint,
                profile=profile_id,
                cluster=cluster_id,
                counter=self.manager.database.get("apsCounter")
            )/asdu
            if self.manager.database.get("nwkUseMulticast"):
                multicast = True
                apdu = ZigbeeAppDataPayload(
                    delivery_mode = 2,
                    dst_endpoint = 0xFF,
                    src_endpoint = source_endpoint,
                    profile=profile_id,
                    cluster=cluster_id,
                    counter=self.manager.database.get("apsCounter")
                )/asdu

            else:
                multicast = False
                destination_address = 0xFFFD
                apdu = ZigbeeAppDataPayload(
                    delivery_mode = 3,
                    group_addr = destination_address,
                    src_endpoint = source_endpoint,
                    profile=profile_id,
                    cluster=cluster_id,
                    counter=self.manager.database.get("apsCounter")
                )/asdu

        if alias_address is not None and acknowledged_transmission:
            return False

        if acknowledged_transmission:
            apdu.frame_control.ack_req = True
            raise RequiredImplementation("APSAckImplementation")
        else:
            apdu.frame_control.ack_req = False

        if security_enabled_transmission:
            apdu.frame_control.security = True
        else:
            apdu.frame_control.security = False

        counter = self.manager.database.get("apsCounter")
        self.manager.database.set("apsCounter", counter+1)
        return self.manager.get_layer('nwk').get_service("data").data(
            apdu,
            nsdu_handle=0,
            alias_address=alias_address,
            alias_sequence_number=alias_sequence_number,
            destination_address_mode=NWKAddressMode.MULTICAST if multicast else NWKAddressMode.UNICAST,
            destination_address=destination_address,
            radius=radius,
            non_member_radius=self.database.get("apsNonmemberRadius"),
            discover_route=False,
            security_enable=use_network_key
        )

    @Dot15d4Service.indication("APSDE-DATA")
    def indicate_data(
                        self,
                        apdu,
                        destination_address_mode,
                        destination_address,
                        source_address,
                        security_status,
                        link_quality
    ):
        """
        Implements the APSDE-DATA Indication.

        Processes and transmits an ASDU to upper layer.
        """
        if ZigbeeSecurityHeader in apdu:
            asdu = ZigbeeAppDataPayload(apdu.data)
        else:
            asdu = apdu

        if 'extended_hdr' in asdu.frame_control and asdu.aps_frametype in (0, 2):
            raise RequiredImplementation("Fragmentation")

        if hasattr(asdu, "dst_endpoint"):
            dst_endpoint = asdu.dst_endpoint
        else:
            dst_endpoint = None

        if hasattr(asdu, "src_endpoint"):
            src_endpoint = asdu.src_endpoint
        else:
            src_endpoint = None

        if hasattr(asdu, "profile"):
            profile_id = asdu.profile
        else:
            profile_id = None

        if hasattr(asdu, "cluster"):
            cluster_id = asdu.cluster
        else:
            cluster_id = None

        nwkAddressMap = self.manager.get_layer('nwk').database.get("nwkAddressMap")
        selected_extended_address = None
        '''
        for extended_address, short_address in nwkAddressMap.items():
            if short_address == source_address:
                selected_extended_address = extended_address
                break
        '''
        source = None
        source_address_mode = None

        if selected_extended_address is None:
            source = source_address
            source_address_mode = APSSourceAddressMode.SHORT_ADDRESS_SRC_ENDPOINT_PRESENT
        else:
            source = selected_extended_address
            if src_endpoint is None:
                source_address_mode = APSSourceAddressMode.EXTENDED_ADDRESS_SRC_ENDPOINT_NOT_PRESENT
            else:
                source_address_mode = APSSourceAddressMode.EXTENDED_ADDRESS_SRC_ENDPOINT_PRESENT

        destination = destination_address
        if destination_address_mode == NWKAddressMode.MULTICAST:
            destination_mode = APSDestinationAddressMode.SHORT_GROUP_ADDRESS_DST_ENDPOINT_NOT_PRESENT
        else:
            if is_short_address(destination_address):
                destination_mode = APSDestinationAddressMode.SHORT_ADDRESS_DST_ENDPOINT_PRESENT
            else:
                if dst_endpoint is not None:
                    destination_mode = APSDestinationAddressMode.EXTENDED_ADDRESS_DST_ENDPOINT_PRESENT
                else:
                    destination_mode = APSDestinationAddressMode.EXTENDED_ADDRESS_DST_ENDPOINT_NOT_PRESENT

        if profile_id == 0x0000:
            payload = asdu[ZigbeeDeviceProfile]
        else:
            payload = asdu[ZigbeeClusterLibrary]

        if 'ack_req' in asdu.frame_control:
            acknowledgement = ZigbeeAppDataPayload(
                frame_control = 0,
                delivery_mode = 0,
                aps_frametype = 2,
                dst_endpoint = src_endpoint,
                src_endpoint = dst_endpoint,
                profile=profile_id,
                cluster=cluster_id,
                counter=asdu.counter
            )

            self.manager.get_layer('nwk').get_service("data").data(
                acknowledgement,
                nsdu_handle=0,
                destination_address_mode=NWKAddressMode.UNICAST,
                destination_address=source_address,
                radius=30,
                non_member_radius=self.database.get("apsNonmemberRadius"),
                discover_route=False,
                security_enable=True
            )

        return (
                    payload,
                    {
                        "destination_address":destination,
                        "destination_address_mode":destination_mode,
                        "destination_endpoint":dst_endpoint,
                        "source_address":source,
                        "source_address_mode":source_address_mode,
                        "source_endpoint":src_endpoint,
                        "profile_id":profile_id,
                        "cluster_id":cluster_id,
                        "security_status":security_status,
                        "link_quality":link_quality
                    }
        )

    def on_data_apdu(
                        self,
                        apdu,
                        destination_address_mode,
                        destination_address,
                        source_address,
                        security_status,
                        link_quality
    ):
        """
        Callback processing APDU data forwarded by the APS Manager.
        """
        self.indicate_data(
                            apdu,
                            destination_address_mode,
                            destination_address,
                            source_address,
                            security_status,
                            link_quality
        )

class APSManagementService(APSService):
    """
    APS service processing Management operations.
    """
    def __init__(self, manager):
        super().__init__(manager, name="aps_management")


    @Dot15d4Service.request("APSME-GET")
    def get(self, attribute):
        """
        Implement the APSME-GET request operation.

        Gets an attribute value from the APSIB database.
        """
        return self.database.get(attribute)

    @Dot15d4Service.request("APSME-SET")
    def set(self, attribute, value):
        """
        Implement the APSME-SET request operation.

        Sets an attribute value from the APSIB database.
        """
        return self.database.set(attribute, value)

    @Dot15d4Service.indication("APSME-TRANSPORT-KEY")
    def indicate_transport_key(self, source_address, standard_key_type, transport_key_data):
        """
        Implement the APSME-TRANSPORT-KEY indication operation.

        Indicates to upper layer that a transport key has been received.
        """
        return (
            transport_key_data,
            {
                "standard_key_type":standard_key_type,
                "source_address":source_address
            }
        )

    @Dot15d4Service.request("APSME-TRANSPORT-KEY")
    def transport_key(self, destination_address, standard_key_type, transport_key_data):
        
        if standard_key_type == APSKeyType.TRUST_CENTER_LINK_KEY:
            raise RequiredImplementation("TrustCenterLinkKey")
        elif standard_key_type == APSKeyType.STANDARD_NETWORK_KEY:
            nwkAddressMap = self.manager.get_layer('nwk').database.get("nwkAddressMap")
            selected_destination_address = None
            for extended_address, short_address in nwkAddressMap.items():
                if short_address == destination_address:
                    selected_destination_address = extended_address
                    break

            apdu = ZigbeeAppDataPayload(
                delivery_mode=0,
                frame_control=['security'],
                aps_frametype=1
            )
            asdu = ZigbeeAppCommandPayload(
                cmd_identifier = 5,
                key_type = 1,
                key = transport_key_data.key,
                key_seqnum = transport_key_data.key_sequence_number,
                dest_addr = selected_destination_address,
                src_addr = self.manager.get_layer('nwk').database.get("nwkIeeeAddress")
            )
            print(self.manager.get_layer('nwk').database.get("nwkIeeeAddress"))
            #asdu.show()

            apsDeviceKeyPairSet = self.database.get("apsDeviceKeyPairSet")
            candidate_keys = apsDeviceKeyPairSet.select(destination_address, unverified=False)

            if len(candidate_keys) == 0:
                return False
            candidate_key = candidate_keys[0]

            asdu = apdu / ZigbeeSecurityHeader(
                key_type=2,
                extended_nonce=1,
                fc=candidate_key.outgoing_frame_counter,
                nwk_seclevel=5,
                data=bytes(asdu)
            )


            asdu.source=self.manager.get_layer('nwk').database.get("nwkIeeeAddress")
            crypto_manager = ApplicationSubLayerCryptoManager(candidate_key.key, 0x00)
            asdu = crypto_manager.encrypt(asdu)

            return self.manager.get_layer('nwk').get_service("data").data(
                asdu,
                nsdu_handle=0,
                destination_address_mode=NWKAddressMode.UNICAST,
                destination_address=(
                    transport_key_data.parent_address if
                    transport_key_data.use_parent else
                    destination_address
                ),
                discover_route=False,
                security_enable=False
            )
        elif standard_key_type == APSKeyType.APPLICATION_LINK_KEY:
            apdu = ZigbeeAppDataPayload(
                delivery_mode=0,
            ) / ZigbeeAppCommandPayload(
                cmd_identifier = 5,
                key_type = standard_key_type,
                key = transport_key_data.key,
                partner_addr = transport_key_data.partner_address,
                dest_addr = destination_address,
                initiator = 1,
                src_addr = self.manager.get_layer('nwk').database.get("nwkNetworkAddress")
            )
            return self.manager.get_layer('nwk').get_service("data").data(
                apdu,
                nsdu_handle=0,
                destination_address_mode=NWKAddressMode.UNICAST,
                destination_address=(
                    transport_key_data.parent_address if
                    transport_key_data.use_parent else
                    destination_address
                ),
                discover_route=False,
                security_enable=False
            )

    def process_transport_key(self, nsdu, source_address, security_status):
        """
        Extract the transport key from the provided NSDU and process it.
        """
        # Check if the key matches the security policy
        authorized = self.database.get("apsTrustCenterAddress") is not None
        if ZigbeeSecurityHeader in nsdu:
            asdu = ZigbeeAppCommandPayload(nsdu.data)
        else:
            asdu = nsdu[ZigbeeAppCommandPayload]

        if (
                (
                    asdu.key_type in (APSKeyType.APPLICATION_LINK_KEY, APSKeyType.TRUST_CENTER_LINK_KEY) and
                    authorized and security_status != APSSecurityStatus.SECURED_LINK_KEY
                ) or
                (asdu.key_type == 1 and security_status != APSSecurityStatus.SECURED_LINK_KEY)
            ):
            logger.info("[aps_management] transport key doesn't match the security policy, discarding.")
            return

        # If we got an APS Application Link Key, indicate transport key using APSME-TRANSPORT-KEY
        if asdu.key_type == APSKeyType.APPLICATION_LINK_KEY:
            source = source_address
            standard_key_type = asdu.key_type
            transport_key_data = APSApplicationLinkKeyData(asdu.key, asdu.src_addr)

            return self.indicate_transport_key(source, standard_key_type, transport_key_data)

        # If we got a Trust Center Link Key (1) or a Network Key (2) AND it is transmitted to us,
        # indicate key to upper layer using APSME-TRANSPORT-KEY indication.
        if (
                (
                    asdu.key_type in (APSKeyType.STANDARD_NETWORK_KEY, APSKeyType.TRUST_CENTER_LINK_KEY) and
                    asdu.dest_addr == self.manager.get_layer('nwk').database.get("nwkIeeeAddress")
                )
                or
                ( asdu.key_type == APSKeyType.STANDARD_NETWORK_KEY and asdu.dest_addr == 0x0000000000000000 )
        ):

            source = asdu.src_addr
            standard_key_type = asdu.key_type

            if asdu.key_type == APSKeyType.STANDARD_NETWORK_KEY:
                transport_key_data = APSNetworkKeyData(asdu.key, asdu.key_seqnum, False)
            else:
                transport_key_data = APSTrustCenterLinkKeyData(asdu.key)

            return self.indicate_transport_key(source, standard_key_type, transport_key_data)

        # If we got a Network key and dest address equals to 0xFFFFFFFFFFFFFFFF (distributed security network),
        # update APS Trust Center Address and indicate to upper layer using APSME-TRANSPORT-KEY indication.
        if asdu.key_type == APSKeyType.STANDARD_NETWORK_KEY and asdu.dest_addr == 0xFFFFFFFFFFFFFFFF:

            source = asdu.src_addr
            standard_key_type = asdu.key_type
            transport_key_data = APSNetworkKeyData(asdu.key, asdu.key_seqnum, False)
            self.database.set("apsTrustCenterAddress", 0xFFFFFFFFFFFFFFFF)

            return self.indicate_transport_key(source, standard_key_type, transport_key_data)

        # If the packet is not indicated for us, let's just route it to the destination using data service.
        if (
            asdu.key_type in (APSKeyType.STANDARD_NETWORK_KEY,APSKeyType.TRUST_CENTER_LINK_KEY) and
            asdu.dest_addr != self.manager.get_layer('nwk').database.get("nwkIeeeAddress")
        ):

            # Forward to destination device
            self.manager.get_layer('nwk').get_service("data").data(
                asdu,
                destination_address=asdu.dest_addr,
                security_enable=False
            )


    def on_command_apdu(
                        self,
                        nsdu,
                        destination_address_mode,
                        destination_address,
                        source_address,
                        security_status,
                        link_quality
    ):
        """
        Callback processing APDU commands transmitted by the APS Manager.
        """
        # Format APDU command to facilitate parsing
        if ZigbeeSecurityHeader in nsdu:
            asdu = ZigbeeAppCommandPayload(nsdu.data)
        else:
            asdu = nsdu[ZigbeeAppCommandPayload]

        # Forwards command to the right handler

        if asdu.cmd_identifier == 5: # APS_CMD_TRANSPORT_KEY
            self.process_transport_key(nsdu, source_address, security_status)
        # Some processing for other commands is missing here

    @Dot15d4Service.indication("APSME-JOIN")
    def indicate_join(
                        self,
                        network_address,
                        extended_address,
                        capability_information,
                        rejoin=False,
                        secure_rejoin=False
    ):
        return (network_address,
            {
                "extended_address":extended_address,
                "capability_information":capability_information,
                "rejoin":rejoin,
                "secure_rejoin":secure_rejoin
            }
        )

class APSInterpanPseudoService(APSService):
    """
    APS pseudo service forwarding InterPAN operations.

    This service is only there to forward InterPAN to upper layers.
    """
    def __init__(self, manager):
        super().__init__(manager, name="aps_interpan")

    @Dot15d4Service.request("INTRP-DATA")
    def interpan_data(
                        self,
                        asdu,
                        asdu_handle=0,
                        source_address_mode=MACAddressMode.SHORT,
                        destination_address_mode=MACAddressMode.SHORT,
                        destination_pan_id=0xFFFF,
                        destination_address=0xFFFF,
                        profile_id=0,
                        cluster_id=0,
                        acknowledged_transmission=False
    ):
        """
        Implements the INTRP-DATA Request.

        Transmits an InterPAN PDU using network layer.
        """
        return self.manager.get_layer('nwk').get_service("interpan").interpan_data(
            asdu,
            asdu_handle=asdu_handle,
            source_address_mode=source_address_mode,
            destination_pan_id=destination_pan_id,
            destination_address=destination_address,
            destination_address_mode=destination_address_mode,
            profile_id=profile_id,
            cluster_id=cluster_id,
            acknowledged_transmission=acknowledged_transmission
        )

    @Dot15d4Service.indication("INTRP-DATA")
    def indicate_interpan_data(
                                self,
                                asdu,
                                profile_id=0,
                                cluster_id=0,
                                destination_pan_id=0xFFFF,
                                destination_address=0xFFFF,
                                source_pan_id=0xFFFF,
                                source_address=0xFFFF,
                                link_quality=255
    ):
        """
        Implements INTRP-DATA indication.

        Indicates to upper layer that an InterPAN PDU has been received and processed by NWK & APS layers.
        """
        return (
            asdu,
            {
                "profile_id":profile_id,
                "cluster_id":cluster_id,
                "destination_pan_id":destination_pan_id,
                "destination_address":destination_address,
                "source_pan_id":source_pan_id,
                "source_address":source_address,
                "link_quality":link_quality
            }
        )

@state(APSIB)
@alias('aps')
class APSManager(Dot15d4Manager):
    """
    This class implements the Zigbee Application Support Sub-layer manager (APS).
    It provides a framework for application.

    It exposes two services providing the appropriate API + 1 pseudo service to forward InterPAN PDU.
    """
    def init(self):
        self.add_service("data", APSDataService(self))
        self.add_service("management", APSManagementService(self))
        self.add_service("interpan", APSInterpanPseudoService(self))


    def decrypt(self, pdu):
        """
        This method decrypts a PDU if the corresponding security material is found in the database.
        """
        # Check the presence of a security header
        if ZigbeeSecurityHeader not in pdu:
            logger.info("[aps] decryption failure - missing security header.")
            return pdu, False

        # Check if we have frame counter, source and key sequence number, mandatory for decryption
        if (
                not hasattr(pdu[ZigbeeSecurityHeader], "fc") or
                not hasattr(pdu[ZigbeeSecurityHeader], "source") or
                not hasattr(pdu[ZigbeeSecurityHeader], "key_seqnum")
        ):
            logger.info("[aps] decryption failure - missing mandatory data in security header.")
            return pdu, False

        # Extract mandatory informations from packet
        received_frame_count = pdu[ZigbeeSecurityHeader].fc
        key_sequence_number = pdu[ZigbeeSecurityHeader].key_seqnum
        sender_address = pdu[ZigbeeSecurityHeader].source
        key_identifier = pdu[ZigbeeSecurityHeader].key_type

        # Collect short address from network layer
        nwkAddressMap = self.get_layer('nwk').database.get("nwkAddressMap")
        short_address = None
        if sender_address in nwkAddressMap:
            short_address = nwkAddressMap[sender_address]

        # Extracty the KeyPair
        apsDeviceKeyPairSet = self.database.get("apsDeviceKeyPairSet")
        candidate_keys = apsDeviceKeyPairSet.select(short_address)
        for candidate_key in candidate_keys:
            if key_identifier == 0:
                input = None
            elif key_identifier == 2:
                input = 0x00
            elif key_identifier == 3:
                input = 0x02

            # Decryption process, implementation in ApplicationSubLayerCryptoManager
            crypto_manager = ApplicationSubLayerCryptoManager(candidate_key.key, input)
            decrypted, success = crypto_manager.decrypt(pdu)
            if success:
                return decrypted, True

        logger.info("[aps] decryption failure - no key found.")
        return pdu, False

    @source('nwk', 'NLDE-DATA')
    def on_nlde_data(
                        self,
                        nsdu,
                        destination_address_mode,
                        destination_address,
                        source_address,
                        security_use,
                        link_quality
    ):
        # Check that we got an App Data Payload here
        if ZigbeeAppDataPayload in nsdu:
            # Verify the security status
            security_status = (
                                APSSecurityStatus.SECURED_NWK_KEY if
                                security_use else
                                APSSecurityStatus.UNSECURED
            )
            # Check if a Security Header is present and attempt to decrypt packet if needed
            if (
                ZigbeeSecurityHeader in nsdu and
                nsdu[ZigbeeSecurityHeader].underlayer.__class__ is ZigbeeAppDataPayload
            ):
                security_status = APSSecurityStatus.SECURED_LINK_KEY
                decrypted, success = self.decrypt(nsdu)

                if success:
                    nsdu = decrypted
                else:
                    return

            # According to APS frametype, forward to the right service
            if nsdu.aps_frametype == 0: # data
                self.get_service("data").on_data_apdu(
                    nsdu,
                    destination_address_mode,
                    destination_address,
                    source_address,
                    security_status,
                    link_quality
                )
            elif nsdu.aps_frametype == 1: # command
                self.get_service("management").on_command_apdu(
                    nsdu,
                    destination_address_mode,
                    destination_address,
                    source_address,
                    security_status,
                    link_quality
                )
            elif nsdu.aps_frametype == 2: # ack
                pass

    @source('nwk', 'NLME-JOIN')
    def on_join(
                        self,
                        network_address,
                        extended_address,
                        capability_information,
                        rejoin=False,
                        secure_rejoin=False
    ):
        self.get_service("management").indicate_join(
            network_address,
            extended_address,
            capability_information,
            rejoin=rejoin,
            secure_rejoin=secure_rejoin
        )

    @source('nwk', 'INTRP-DATA')
    def on_intrp_data(
                        self,
                        asdu,
                        profile_id=0,
                        cluster_id=0,
                        destination_pan_id=0xFFFF,
                        destination_address=0xFFFF,
                        source_pan_id=0xFFFF,
                        source_address=0xFFFF,
                        link_quality=255
    ):
        """
        Callback processing NWK InterPAN Data indication.
        """
        self.get_service("interpan").indicate_interpan_data(
            asdu,
            profile_id=profile_id,
            cluster_id=cluster_id,
            destination_pan_id=destination_pan_id,
            destination_address=destination_address,
            source_pan_id=source_pan_id,
            source_address=source_address,
            link_quality=link_quality
        )

APSManager.add(APLManager)
