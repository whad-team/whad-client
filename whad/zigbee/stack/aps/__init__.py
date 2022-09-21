from scapy.layers.zigbee import ZigbeeSecurityHeader, ZigbeeAppDataPayload, \
    ZigbeeAppCommandPayload, ZigbeeClusterLibrary, ZigbeeDeviceProfile
from whad.zigbee.stack.service import Dot15d4Service
from whad.zigbee.stack.manager import Dot15d4Manager
from whad.zigbee.stack.database import Dot15d4Database
from whad.zigbee.stack.apl import APLManager
from whad.zigbee.stack.nwk.constants import NWKAddressMode
from whad.zigbee.stack.mac.helpers import is_short_address
from whad.zigbee.stack.mac.constants import MACAddressMode
from whad.zigbee.crypto import ApplicationSubLayerCryptoManager
from whad.exceptions import RequiredImplementation
from .exceptions import APSTimeoutException
from .constants import APSKeyPairSet, APSSecurityStatus, APSTrustCenterLinkKeyData, \
    APSApplicationLinkKeyData, APSSourceAddressMode, APSDestinationAddressMode, \
    APSNetworkKeyData

import logging

logger = logging.getLogger(__name__)

class APSIB(Dot15d4Database):
    def reset(self):
        self.apsDeviceKeyPairSet = APSKeyPairSet(preinstalled_keys=[bytes.fromhex("814286865dc1c8b2c8cbc52e5d65d1b8"), b"ZigBeeAlliance09"])
        self.apsTrustCenterAddress = None
        self.apsSecurityTimeOutPeriod = None
        self.trustCenterPolicies = None

        self.apsDesignatedCoordinator = False
        self.apsChannelMask = 0x7fff800
        self.apsUseExtendedPANID = 0x0000000000000000
        self.apsUseInsecureJoin = False

        self.apsNonmemberRadius = 7
        self.apsCounter = 0

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
    def data(self, asdu, destination_address_mode, destination_address, destination_endpoint, profile_id, cluster_id, source_endpoint, alias_address=None, alias_sequence_number=0, radius=30, security_enabled_transmission=False, use_network_key=False, acknowledged_transmission=False, fragmentation_permitted=False, include_extended_nonce=False):
        multicast = False
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
                asdu.source=self.manager.nwk.database.get("nwkIeeeAddress")
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
            nwkAddressMap = self.manager.nwk.database.get("nwkAddressMap")
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
        return self.manager.nwk.get_service("data").data(
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
    def indicate_data(self, apdu, destination_address_mode, destination_address, source_address, security_status, link_quality):
        if ZigbeeSecurityHeader in apdu:
            asdu = ZigbeeAppDataPayload(apdu.data)
        else:
            asdu = apdu

        if 'extended_hdr' in asdu.frame_control and asdu.aps_frametype in [0, 2]:
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

        nwkAddressMap = self.manager.nwk.database.get("nwkAddressMap")
        selected_extended_address = None
        for extended_address, short_address in nwkAddressMap.items():
            if short_address == source_address:
                selected_extended_address = extended_address
                break

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

        return {
            "asdu":payload,
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

    def on_data_apdu(self, apdu, destination_address_mode, destination_address, source_address, security_status, link_quality):
        self.indicate_data(apdu, destination_address_mode, destination_address, source_address, security_status, link_quality)

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
        """
        return self.database.get(attribute)

    @Dot15d4Service.request("APSME-SET")
    def set(self, attribute, value):
        """
        Implement the APSME-SET request operation.
        """
        return self.database.set(attribute, value)

    @Dot15d4Service.indication("APSME-TRANSPORT-KEY")
    def indicate_transport_key(self, source_address, standard_key_type, transport_key_data):
        """
        Implement the APSME-TRANSPORT-KEY indication operation.
        """
        return {
            "source_address":source_address,
            "standard_key_type":standard_key_type,
            "transport_key_data":transport_key_data
        }

    def process_transport_key(self, nsdu, source_address, security_status):
        authorized = self.database.get("apsTrustCenterAddress") is not None
        if ZigbeeSecurityHeader in nsdu:
            asdu = ZigbeeAppCommandPayload(nsdu.data)
        else:
            asdu = nsdu[ZigbeeAppCommandPayload]

        if (
                (asdu.key_type in (3, 4) and authorized and security_status != APSSecurityStatus.SECURED_LINK_KEY) or
                (asdu.key_type == 1 and security_status != APSSecurityStatus.SECURED_LINK_KEY)
            ):
            logger.info("[aps_management] transport key doesn't match the security policy, discarding.")
            return

        if asdu.key_type == 3:
            source = source_address
            standard_key_type = asdu.key_type
            transport_key_data = APSApplicationLinkKeyData(asdu.key, asdu.src_addr)

        if (
                (asdu.key_type in (1,4) and asdu.dest_addr == self.manager.nwk.database.get("nwkIeeeAddress")) or
                (asdu.key_type == 1 and asdu.dest_addr == 0x0000000000000000)
        ):
            source = asdu.src_addr
            standard_key_type = asdu.key_type
            if asdu.key_type == 1:
                transport_key_data = APSNetworkKeyData(asdu.key, asdu.key_seqnum, False)
            else:
                transport_key_data = APSTrustCenterLinkKeyData(asdu.key)
            return self.indicate_transport_key(source, standard_key_type, transport_key_data)

        if asdu.key_type == 1 and asdu.dest_addr == 0xFFFFFFFFFFFFFFFF:
            source = asdu.src_addr
            standard_key_type = asdu.key_type
            transport_key_data = APSNetworkKeyData(asdu.key, asdu.key_seqnum, False)
            self.database.set("apsTrustCenterAddress", 0xFFFFFFFFFFFFFFFF)
            return self.indicate_transport_key(source, standard_key_type, transport_key_data)

        if asdu.key_type in (1,4) and asdu.dest_addr != self.manager.nwk.database.get("nwkIeeeAddress"):
            # Forward to destination device
            self.manager.nwk.get_service("data").data(asdu, destination_address=asdu.dest_addr, security_enable=False)


    def on_command_apdu(self, nsdu, destination_address_mode, destination_address, source_address, security_status, link_quality):
        if ZigbeeSecurityHeader in nsdu:
            asdu = ZigbeeAppCommandPayload(nsdu.data)
        else:
            asdu = nsdu[ZigbeeAppCommandPayload]

        if asdu.cmd_identifier == 5: # APS_CMD_TRANSPORT_KEY
            self.process_transport_key(nsdu, source_address, security_status)

class APSInterpanPseudoService(APSService):
    """
    APS pseudo service forwarding interpan operations.
    """
    @Dot15d4Service.request("INTRP-DATA")
    def interpan_data(self,asdu, asdu_handle=0, source_address_mode=MACAddressMode.SHORT, destination_pan_id=0xFFFF, destination_address=0xFFFF, profile_id=0, cluster_id=0):
        return self.manager.nwk.get_service("interpan").interpan_data(asdu, asdu_handle=asdu_handle, source_address_mode=source_address_mode, destination_pan_id=destination_pan_id, destination_address=destination_address, profile_id=profile_id, cluster_id=cluster_id)

    @Dot15d4Service.indication("INTRP-DATA")
    def indicate_interpan_data(self, asdu, profile_id=0, cluster_id=0, destination_pan_id=0xFFFF, destination_address=0xFFFF, source_pan_id=0xFFFF, source_address=0xFFFF, link_quality=255):
        return {
            "asdu":asdu,
            "profile_id":profile_id,
            "cluster_id":cluster_id,
            "destination_pan_id":destination_pan_id,
            "destination_address":destination_address,
            "source_pan_id":source_pan_id,
            "source_address":source_address,
            "link_quality":link_quality
        }


class APSManager(Dot15d4Manager):
    """
    This class implements the Zigbee Application Support Sub-layer manager (APS).
    It provides a framework for application.

    It exposes two services providing the appropriate API.
    """

    def __init__(self, nwk=None):
        super().__init__(
            services={
                        "management": APSManagementService(self),
                        "data": APSDataService(self),
                        "interpan": APSInterpanPseudoService(self)

            },
            database=APSIB(),
            upper_layer=APLManager(self),
            lower_layer=nwk
        )


    @property
    def apl(self):
        return self.upper_layer

    @property
    def nwk(self):
        return self.lower_layer

    def decrypt(self, pdu):
        if ZigbeeSecurityHeader not in pdu:
            logger.info("[aps] decryption failure - missing security header.")
            return pdu, False

        if (
                not hasattr(pdu[ZigbeeSecurityHeader], "fc") or
                not hasattr(pdu[ZigbeeSecurityHeader], "source") or
                not hasattr(pdu[ZigbeeSecurityHeader], "key_seqnum")
        ):
            logger.info("[aps] decryption failure - missing mandatory data in security header.")
            return pdu, False


        received_frame_count = pdu[ZigbeeSecurityHeader].fc
        key_sequence_number = pdu[ZigbeeSecurityHeader].key_seqnum
        sender_address = pdu[ZigbeeSecurityHeader].source
        key_identifier = pdu[ZigbeeSecurityHeader].key_type

        nwkAddressMap = self.nwk.database.get("nwkAddressMap")
        short_address = None
        if sender_address in nwkAddressMap:
            short_address = nwkAddressMap[sender_address]

        apsDeviceKeyPairSet = self.database.get("apsDeviceKeyPairSet")
        candidate_keys = apsDeviceKeyPairSet.select(short_address)
        for candidate_key in candidate_keys:
            if key_identifier == 0:
                input = None
            elif key_identifier == 2:
                input = 0x00
            elif key_identifier == 3:
                input = 0x02

            crypto_manager = ApplicationSubLayerCryptoManager(candidate_key.key, input)
            decrypted, success = crypto_manager.decrypt(pdu)
            if success:
                return decrypted, True

        logger.info("[aps] decryption failure - no key found.")
        return pdu, False

    def on_nlde_data(self, nsdu, destination_address_mode, destination_address, source_address, security_use, link_quality):
        if ZigbeeAppDataPayload in nsdu:
            security_status = APSSecurityStatus.SECURED_NWK_KEY if security_use else APSSecurityStatus.UNSECURED
            if ZigbeeSecurityHeader in nsdu and nsdu[ZigbeeSecurityHeader].underlayer.__class__ is ZigbeeAppDataPayload:
                security_status = APSSecurityStatus.SECURED_LINK_KEY
                decrypted, success = self.decrypt(nsdu)
                if success:
                    nsdu = decrypted
                else:
                    return
            if nsdu.aps_frametype == 0: # data
                self.get_service("data").on_data_apdu(nsdu, destination_address_mode, destination_address, source_address, security_status, link_quality)
            elif nsdu.aps_frametype == 1: # command
                self.get_service("management").on_command_apdu(nsdu, destination_address_mode, destination_address, source_address, security_status, link_quality)
            elif nsdu.aps_frametype == 2: # ack
                pass

    def on_intrp_data(self, asdu, profile_id=0, cluster_id=0, destination_pan_id=0xFFFF, destination_address=0xFFFF, source_pan_id=0xFFFF, source_address=0xFFFF, link_quality=255):
        self.get_service("interpan").indicate_interpan_data(asdu, profile_id=profile_id, cluster_id=cluster_id, destination_pan_id=destination_pan_id, destination_address=destination_address, source_pan_id=source_pan_id, source_address=source_address, link_quality=link_quality)
