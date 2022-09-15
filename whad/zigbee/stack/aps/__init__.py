from scapy.layers.zigbee import ZigbeeSecurityHeader, ZigbeeAppDataPayload, \
    ZigbeeAppCommandPayload
from whad.zigbee.stack.service import Dot15d4Service
from whad.zigbee.stack.manager import Dot15d4Manager
from whad.zigbee.stack.database import Dot15d4Database
from whad.zigbee.crypto import ApplicationSubLayerCryptoManager
from .exceptions import APSTimeoutException
from .constants import APSKeyPairSet, APSSecurityStatus, APSTrustCenterLinkKeyData, \
    APSApplicationLinkKeyData, APSNetworkKeyData
import logging

logger = logging.getLogger(__name__)

class APSIB(Dot15d4Database):
    def reset(self):
        self.apsDeviceKeyPairSet = APSKeyPairSet()
        self.apsTrustCenterAddress = None
        self.apsSecurityTimeOutPeriod = None
        self.trustCenterPolicies = None


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

    def on_data_apdu(self, apdu, destination_address_mode, destination_address, source_address, security_status, link_quality):
        pass

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

    @Dot15d4Service.request("APSME-TRANSPORT-KEY")
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
                        "data": APSDataService(self)
            },
            database=APSIB(),
            upper_layer=None,
            lower_layer=nwk
        )

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
