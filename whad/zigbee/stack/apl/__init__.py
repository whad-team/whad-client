from whad.zigbee.stack.service import Dot15d4Service
from whad.zigbee.stack.manager import Dot15d4Manager
from whad.zigbee.stack.database import Dot15d4Database
from whad.zigbee.stack.nwk.constants import NWKJoinMode, NetworkSecurityMaterial
from .constants import LogicalDeviceType
from .exceptions import APLTimeoutException
from whad.zigbee.stack.constants import SYMBOL_DURATION, Dot15d4Phy
from time import sleep
import logging

logger = logging.getLogger(__name__)

class AttributesDatabase(Dot15d4Database):
    def reset(self):
        self.configNWKScanAttempts = 5
        self.configNWKTimeBetweenScans = 0xc35


class APLObject(Dot15d4Service):
    """
    This class represents an APL service (named "object"), exposing a standardized API.
    """
    def __init__(self, manager, name=None, endpoint=None):
        super().__init__(manager, name=name, timeout_exception_class=APLTimeoutException)
        self.endpoint = endpoint

class ZDOObject:
    def __init__(self, zdo):
        self.zdo = zdo


class ZDODeviceAndServiceDiscovery(ZDOObject):
    pass

class ZDONetworkManager(ZDOObject):
    def start(self):
        nwkExtendedPANID = self.zdo.nwk_management.get("nwkExtendedPANID")
        apsDesignatedCoordinator = self.zdo.aps_management.get("apsDesignatedCoordinator")
        apsUseExtendedPANID = self.zdo.aps_management.get("apsUseExtendedPANID")
        apsUseInsecureJoin = self.zdo.aps_management.get("apsUseInsecureJoin")
        apsChannelMask = self.zdo.aps_management.get("apsChannelMask")
        if nwkExtendedPANID != 0:
            # we are already connected :) don't do anything
            return True

        if apsDesignatedCoordinator:
            # We are a coordinator not connected, start NLME-NETWORK-FORMATION
            raise RequiredImplementation("ZigbeeNetworkFormation")

        else:
            # We are a router or an end device, attempt to join or rejoin a network
            if apsUseExtendedPANID != 0:
                rejoin_success = self.zdo.nwk_management.join(
                    apsUseExtendedPANID,
                    association_type=NWKJoinMode.REJOIN,
                    scan_channels=apsChannelMask
                )
                if rejoin_success:
                    return True

                # We failed to rejoin, try to join
                selected_zigbee_network = None
                for attempt in range(self.zdo.attributes.get("configNWKScanAttempts")):
                    zigbee_networks = self.zdo.nwk_management.network_discovery(scan_channels=apsChannelMask)
                    for zigbee_network in zigbee_networks:
                        if zigbee_network.extended_pan_id == apsUseExtendedPANID:
                            selected_zigbee_network = zigbee_network
                    if selected_zigbee_network is not None:
                        break
                    else:
                        sleep(self.zdo.attributes.get("configNWKTimeBetweenScans") * SYMBOL_DURATION[Dot15d4Phy.OQPSK] * 2)
                if selected_zigbee_network is None:
                    logger.info("[zdo_network_manager] target network not found, exiting.")
                    return False

                join_success = self.zdo.nwk_management.join(
                    apsUseExtendedPANID,
                    association_type=NWKJoinMode.NEW_JOIN,
                    scan_channels=apsChannelMask
                )
                if not join_success:
                    logger.info("[zdo_network_manager] failure during network join, exiting.")

                return join_success

            else:
                # join the best available network
                selected_zigbee_network = None
                for attempt in range(self.zdo.attributes.get("configNWKScanAttempts")):
                    zigbee_networks = self.zdo.nwk_management.network_discovery(scan_channels=apsChannelMask)
                    for zigbee_network in zigbee_networks:
                        if zigbee_network.joining_permit:
                            selected_zigbee_network = zigbee_network
                    if selected_zigbee_network is not None:
                        break
                    else:
                        sleep(self.zdo.attributes.get("configNWKTimeBetweenScans") * SYMBOL_DURATION[Dot15d4Phy.OQPSK] * 2)

                if selected_zigbee_network is None:
                    logger.info("[zdo_network_manager] no target network found, exiting.")
                    return False

                join_success = self.zdo.nwk_management.join(
                    selected_zigbee_network.extended_pan_id,
                    association_type=NWKJoinMode.NEW_JOIN,
                    scan_channels=apsChannelMask
                )
                if not join_success:
                    logger.info("[zdo_network_manager] failure during network join, exiting.")

                return join_success

class ZDOSecurityManager(ZDOObject):
    def on_transport_key(self, source_address, standard_key_type, transport_key_data):
        if standard_key_type == 1: # process network key
            nwkSecurityMaterialSet = self.zdo.nwk_management.get("nwkSecurityMaterialSet")
            nwkSecurityMaterialSet.append(
                NetworkSecurityMaterial(
                    transport_key_data.key,
                    transport_key_data.key_sequence_number
                )
            )
            self.zdo.nwk_management.set("nwkSecurityMaterialSet", nwkSecurityMaterialSet)
            logger.info("[zdo_security_manager] new network key provisioned.")
            self.zdo.nwk_management.set("nwkSecurityLevel", 5)

            self.zdo.aps_management.set("apsTrustCenterAddress", source_address)
            logger.info("[zdo_security_manager] new trust center address set.")

class ZigbeeDeviceObjects(APLObject):
    def __init__(self, manager, endpoint=0):
        super().__init__(manager, name="zdo")
        self.logical_device_type = LogicalDeviceType.END_DEVICE # TODO: make it configurable
        self.security_manager = ZDOSecurityManager(self)
        self.network_manager = ZDONetworkManager(self)
        self.device_and_service_discovery = ZDODeviceAndServiceDiscovery(self)
        self.attributes = AttributesDatabase()

    @property
    def nwk_management(self):
        return self.manager.nwk.get_service("management")

    @property
    def aps_management(self):
        return self.manager.aps.get_service("management")

    def configure(self):
        if self.logical_device_type == LogicalDeviceType.END_DEVICE:
            self.manager.nwk.database.set("nwkExtendedPANID", 0x0000000000000000)
            self.manager.aps.database.set("apsDesignatedCoordinator", False)
            self.manager.aps.database.set("apsChannelMask", 0x7fff800)
            self.manager.aps.database.set("apsUseExtendedPANID", 0x0000000000000000)
            self.manager.aps.database.set("apsUseInsecureJoin", True)

    def on_transport_key(self, source_address, standard_key_type, transport_key_data):
        self.security_manager.on_transport_key(source_address, standard_key_type, transport_key_data)

class APLManager(Dot15d4Manager):
    """
    This class implements the Zigbee Application layer manager (APL).
    It exposes Zigbee Device Object and Application Object.
    """

    def __init__(self, aps):
        super().__init__(
            services={
                "zdo":ZigbeeDeviceObjects(self, endpoint=0)
            },
            upper_layer=None,
            lower_layer=aps
        )
        print(self.lower_layer)

    @property
    def aps(self):
        return self.lower_layer

    @property
    def nwk(self):
        return self.lower_layer.nwk

    def get_service_by_endpoint(self, endpoint):
        for service in self._services.values():
            if service.endpoint == endpoint:
                return service
        return None

    def on_apsme_transport_key(self, source_address, standard_key_type, transport_key_data):
        # Forward to ZDO
        self.get_service("zdo").on_transport_key(source_address, standard_key_type, transport_key_data)
