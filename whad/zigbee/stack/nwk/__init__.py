from scapy.layers.zigbee import ZigBeeBeacon, ZigbeeNWKStub, ZigbeeNWK, \
    ZigbeeSecurityHeader, ZigbeeNWKCommandPayload, ZigbeeAppDataPayload
from scapy.fields import FlagValueIter
from whad.zigbee.crypto import NetworkLayerCryptoManager
from .exceptions import NWKTimeoutException
from .constants import ZigbeeNetwork, NWKAddressMode, BROADCAST_ADDRESSES, \
    NetworkSecurityMaterial
from whad.zigbee.stack.mac.constants import MACScanType, MACAddressMode
from whad.zigbee.stack.service import Dot15d4Service
from whad.zigbee.stack.manager import Dot15d4Manager
from whad.zigbee.stack.database import Dot15d4Database
from whad.exceptions import RequiredImplementation
from queue import Queue, Empty
from copy import copy
from time import time
import logging

logger = logging.getLogger(__name__)

class NWKIB(Dot15d4Database):
    def reset(self):
        self.nwkSequenceNumber = 0
        #self.nwkPassiveAckTimeout = None
        self.nwkMaxBroadcastRetries = 3
        #self.nwkMaxChildren = None
        self.nwkMaxDepth = 30 # ?
        #self.nwkMaxRouters = None
        self.nwkNeighborTable = []
        #self.nwkNetworkBroadcastDeliveryTime = None
        self.nwkReportConstantCost = 0
        self.nwkRouteTable = []
        self.nwkSymLink = False
        self.nwkCapabilityInformation = 0
        self.nwkAddrAlloc = 0
        self.nwkUseTreeRouting = True
        self.nwkManagerAddr = 0
        self.nwkMaxSourceRoute = 0xc
        self.nwkUpdateId = 0
        self.nwkNetworkAddress = 0xFFFF
        self.nwkStackProfile = None
        self.nwkExtendedPANID = 0x0000000000000000
        self.nwkPANId = 0xFFFF
        self.nwkIeeeAddress = None
        self.nwkLeaveRequestAllowed = True
        self.nwkTxTotal = 0

        self.nwkSecurityLevel = 0
        self.nwkSecurityMaterialSet = []
        self.nwkActiveKeySeqNumber = 0

class NWKService(Dot15d4Service):
    """
    This class represents a NWK service, exposing a standardized API.
    """
    def __init__(self, manager, name=None):
        super().__init__(manager, name=name, timeout_exception_class=NWKTimeoutException)


class NWKDataService(NWKService):
    """
    NWK service processing Data packets.
    """
    @Dot15d4Service.request("NLDE-DATA")
    def data(self,nsdu,nsdu_handle=0, alias_address=None, alias_sequence_number=0, destination_address_mode=NWKAddressMode.UNICAST, destination_address=0xFFFF, radius=0, non_member_radius=7, discover_route=False, security_enable=False):
        if alias_address is not None:
            source_address = alias_address
            sequence_number = self.database.get("nwkSequenceNumber")
            self.database.set("nwkSequenceNumber", sequence_number+1)
        else:
            self.manager.mac.get_service("management").get("macShortAddress")
            sequence_number = alias_sequence_number
        if radius == 0:
            radius = self.database.get("nwkMaxDepth") * 2

        flags = []
        if destination_address_mode == NWKAddressMode.MULTICAST:
            flags.append("multicast")
            raise RequiredImplementation("Routing/Multicasting")

        npdu = ZigbeeNWK(
            discover_route=int(discover_route),
            seqnum=sequence_number,
            radius=radius,
            flags=flags,
            destination=destination_address,
            source=alias_address if alias_address is not None else self.database.nwkMac
        )
        if destination_address in BROADCAST_ADDRESSES.keys():
            destination_pan_id = self.database.get("nwkPANId")
            acknowledged = False
        else:
            destination_pan_id = self.database.get("nwkPANId")
            acknowledged = True

        if self.database.get("nwkSecurityLevel") != 0 and security_enable:
            npdu.flags.append("security")
            selected_key_material = None
            for key_material in security_material_set:
                if key_material.key_sequence_number == self.database.get("nwkActiveKeySeqNumber"):
                    selected_key_material = key_material
                    break
            if selected_key_material is None:
                return False

            msdu = npdu / ZigbeeSecurityHeader(
                nwk_seclevel = self.database.get("nwkSecurityLevel"),
                source = self.database.get("nwkIeeeAddress"),
                key_type=1,
                key_seqnum=self.database.get("nwkActiveKeySeqNumber"),
                fc=selected_key_material.outgoing_frame_counter,
                data=bytes(nsdu)
            )
            crypto_manager = NetworkLayerCryptoManager(selected_key_material.key)
            msdu = crypto_manager.encrypt(msdu)
            selected_key_material.outgoing_frame_counter += 1
        else:
            msdu = npdu / nsdu

        return self.manager.mac.get_service("data").data(
                    msdu,
                    msdu_handle=0,
                    source_address_mode=MACAddressMode.SHORT,
                    destination_pan_id=destination_pan_id,
                    destination_address=destination_address,
                    pan_id_suppressed=False,
                    sequence_number_suppressed=False,
                    wait_for_ack=acknowledged
        )

    def on_data_npdu(self, npdu):
        self.indicate_data(npdu)

    @Dot15d4Service.indication("NLDE-DATA")
    def indicate_data(self, npdu):
        destination_address_mode = (
            NWKAddressMode.MULTICAST if "multicast" in npdu.flags else
            NWKAddressMode.UNICAST
        )
        destination_address = npdu.destination
        source_address = npdu.source
        security_use = ZigbeeSecurityHeader in npdu
        if security_use:
            nsdu = ZigbeeAppDataPayload(npdu.data)
        else:
            nsdu = npdu[ZigbeeAppDataPayload]

        nsdu.show()
        return {
            "nsdu":nsdu,
            "destination_address_mode":destination_address_mode,
            "destination_address":destination_address,
            "source_address":source_address,
            "security_use":security_use
        }
class NWKManagementService(NWKService):
    """
    NWK service processing Management packets.
    """

    @Dot15d4Service.request("NLME-RESET")
    def reset(self, warm_start=False):
        if warm_start:
            self.database.set("nwkNeighborTable",[])
            self.database.set("nwkRouteTable",[])
            return True
        else:
            confirm = self.manager.mac.get_service("management").reset(set_default_pib=True)
            if confirm:
                self.database.reset()
                return True
        return False

    @Dot15d4Service.request("NLME-GET")
    def get(self, attribute):
        """
        Implement the NLME-GET request operation.
        """
        return self.database.get(attribute)

    @Dot15d4Service.request("NLME-SET")
    def set(self, attribute, value):
        """
        Implement the NLME-SET request operation.
        """
        return self.database.set(attribute, value)

    @Dot15d4Service.request("NLME-ED-SCAN")
    def ed_scan(self, scan_channels=0x7fff800, scan_duration=2):
        """
        Implements the NLME-ED-SCAN request.
        """
        confirm = self.manager.mac.get_service("management").scan(
            scan_type=MACScanType.ENERGY_DETECTION,
            channel_page=0,
            scan_channels=scan_channels,
            scan_duration=scan_duration
        )
        return confirm

    @Dot15d4Service.request("NLME-NETWORK-DISCOVERY")
    def network_discovery(self, scan_channels=0x7fff800, scan_duration=2):
        """
        Implements the NLME-NETWORK-DISCOVERY request.
        """
        confirm = self.manager.mac.get_service("management").scan(
            scan_type=MACScanType.ACTIVE,
            channel_page=0,
            scan_channels=scan_channels,
            scan_duration=scan_duration
        )
        zigbee_networks = []
        notifications_left = True
        while notifications_left:
            try:
                beacon = self.wait_for_packet(lambda pkt:ZigBeeBeacon in pkt, timeout=0.1)
                if beacon.pan_descriptor in confirm:
                    zigbee_networks.append(ZigbeeNetwork(beacon))
            except NWKTimeoutException:
                notifications_left = False
        return zigbee_networks

    def on_beacon_npdu(self, pan_descriptor, beacon_payload):
        beacon_payload.pan_descriptor = pan_descriptor
        self.add_packet_to_queue(beacon_payload)

    def on_command_npdu(self, npdu):
        pass

class NWKInterpanService(NWKService):
    @Dot15d4Service.request("INTRP-DATA")
    def interpan_data(self,asdu, asdu_handle=0, source_address_mode=MACAddressMode.SHORT, destination_pan_id=0xFFFF, destination_address=0xFFFF, profile_id=0, cluster_id=0):
        data = ZigbeeNWKStub()/ZigbeeAppDataPayloadStub(
            cluster=cluster_id,
            profile=profile_id,
            data=asdu
        )
        self.manager.mac.get_service("data").data(
            data,
            source_address_mode=source_address_mode,
            destination_pan_id=destination_pan_id,
            destination_address=destination_address,
            wait_for_ack=False
        )

    def on_interpan_npdu(self, pdu, destination_pan_id, destination_address, source_pan_id, source_address):
        profile_id = pdu.profile
        cluster_id = pdu.cluster
        asdu = pdu[ZigbeeAppDataPayloadStub].data
        self.indicate_interpan_data(asdu, profile_id=profile_id, cluster_id=cluster_id, destination_pan_id=destination_pan_id, destination_address=destination_address, source_pan_id=source_pan_id, source_address=source_address)

    @Dot15d4Service.indication("INTRP-DATA")
    def indicate_interpan_data(self, asdu, profile_id=0, cluster_id=0, destination_pan_id=0xFFFF, destination_address=0xFFFF, source_pan_id=0xFFFF, source_address=0xFFFF):
        return {
            "asdu":asdu,
            "profile_id":profile_id,
            "cluster_id":cluster_id,
            "destination_pan_id":destination_pan_id,
            "destination_address":destination_address,
            "source_pan_id":source_pan_id,
            "source_address":source_address
        }

class NWKManager(Dot15d4Manager):
    """
    This class implements the Zigbee Network manager (NWK) and the Inter-PAN APS.
    It handles network-level operations, such as discovery, association or network initiation.

    It exposes two services providing the appropriate API.
    """

    def __init__(self, mac=None):
        super().__init__(
            services={
                        "management": NWKManagementService(self),
                        "data": NWKDataService(self),
                        "interpan":NWKInterpanService(self)
            },
            database=NWKIB(),
            upper_layer=None,
            lower_layer=mac
        )
        self._crypto_managers = []

    @property
    def mac(self):
        return self.lower_layer

    def add_key(self, key, key_sequence_number=None, outgoing_frame_counter=0):
        networkSecurityMaterialSet = self.database.get("nwkSecurityMaterialSet")
        securityMaterial = NetworkSecurityMaterial(
            key,
            key_sequence_number=key_sequence_number,
            outgoing_frame_counter=outgoing_frame_counter
        )
        networkSecurityMaterialSet.append(securityMaterial)
        logger.info("[nwk] new security material added: {}".format(str(securityMaterial)))
        self.database.set("nwkSecurityMaterialSet", networkSecurityMaterialSet)

    def decrypt(self, pdu):
        if ZigbeeSecurityHeader not in pdu:
            logger.info("[nwk] decryption failure - missing security header.")
            return pdu, False

        securityLevel = self.database.get("nwkSecurityLevel")

        if securityLevel == 0:
            logger.info("[nwk] decryption failure - attempt to decrypt a pdu with nwkSecurityLevel set to 0.")
            return pdu, False
        else:
            pdu.nwk_seclevel = securityLevel

        if (
                not hasattr(pdu[ZigbeeSecurityHeader], "fc") or
                not hasattr(pdu[ZigbeeSecurityHeader], "source") or
                not hasattr(pdu[ZigbeeSecurityHeader], "key_seqnum")
        ):
            logger.info("[nwk] decryption failure - missing mandatory data in security header.")
            return pdu, False

        received_frame_count = pdu[ZigbeeSecurityHeader].fc
        key_sequence_number = pdu[ZigbeeSecurityHeader].key_seqnum
        sender_address = pdu[ZigbeeSecurityHeader].source

        security_material_set = self.database.get("nwkSecurityMaterialSet")

        selected_key_material = None
        for key_material in security_material_set:
            if key_material.key_sequence_number == key_sequence_number:
                selected_key_material = key_material
                break
        if selected_key_material is None:
            logger.info("[nwk] decryption failure - no matching key found.")
            return pdu, False

        if (
            sender_address in selected_key_material.incoming_frame_counters and
            received_frame_count < selected_key_material.incoming_frame_counters[sender_address]
        ):
            logger.info("[nwk] decryption failure - bad frame counter.")
            return pdu, False

        network_crypto_manager = NetworkLayerCryptoManager(selected_key_material.key)
        cleartext, status = network_crypto_manager.decrypt(pdu)
        if status:
            selected_key_material.add_incoming_frame_counter(sender_address, received_frame_count+1)
            return cleartext, True
        else:
            logger.info("[nwk] decryption failure - MIC not matching.")
            return pdu, False

    def on_mcps_data(self, pdu, destination_pan_id, destination_address, source_pan_id, source_address):
        if ZigbeeNWKStub in pdu and ZigbeeAppDataPayloadStub in pdu:
            self.get_service("interpan").on_interpan_npdu(pdu, destination_pan_id, destination_address, source_pan_id, source_address)
        elif ZigbeeNWK in pdu:
            if ZigbeeSecurityHeader in pdu:
                decrypted, success = self.decrypt(pdu)
                if success:
                    pdu = decrypted
                else:
                    print("failure during decryption.")
            if pdu.frametype == 0:
                self.get_service("data").on_data_npdu(pdu)
            elif pdu.frametype == 1:
                self.get_service("management").on_command_npdu(pdu)
            else:
                self.get_service("interpan").on_interpan_npdu(pdu)

    def on_mlme_beacon_notify(self, pan_descriptor, beacon_payload):
        if isinstance(beacon_payload, bytes):
            beacon_payload = ZigBeeBeacon(beacon_payload)
        # Check if this is a Zigbee beacon
        if hasattr(beacon_payload, "proto_id") and beacon_payload.proto_id == 0:
            self.get_service("management").on_beacon_npdu(pan_descriptor, beacon_payload)
