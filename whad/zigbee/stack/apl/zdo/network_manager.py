from whad.zigbee.stack.apl.zdo.object import ZDOObject
from whad.zigbee.stack.nwk.constants import NWKJoinMode
from whad.zigbee.stack.apl.constants import LogicalDeviceType
from whad.zigbee.stack.constants import SYMBOL_DURATION, Dot15d4Phy

from time import sleep
from random import randint
import logging
# Wrappers
from whad.zigbee.profile.network import Network
from whad.zigbee.profile.device import Coordinator, EndDevice, Router

logger = logging.getLogger(__name__)

class ZDONetworkManager(ZDOObject):

    def configure_extended_address(self, extended_address):
        self.zdo.manager.nwk.database.set("nwkIeeeAddress", extended_address)
        self.zdo.manager.nwk.mac.database.set("macExtendedAddress", extended_address)
        self.zdo.manager.nwk.mac.stack.set_extended_address(extended_address)

    def configure_short_address(self, short_address):
        self.zdo.manager.nwk.database.set("nwkNetworkAddress", short_address)
        self.zdo.manager.nwk.mac.database.set("macShortAddress", short_address)
        self.zdo.manager.nwk.mac.stack.set_short_address(short_address)

    def configure_extended_pan_id(self, extended_pan_id):
        self.zdo.manager.nwk.database.set("nwkExtendedPANID", extended_pan_id)

    def initialize(self):
        self.network = None
        self.authorized = False
        if self.zdo.configuration.get("configNodeDescriptor").logical_type == LogicalDeviceType.END_DEVICE:
            # TODO: refactor to simplify access to different stack layers
            self.configure_extended_address(randint(0, 0xffffffffffffffff))
            self.configure_short_address(0xFFFF)
            self.configure_extended_pan_id(0x0000000000000000)
            self.zdo.manager.aps.database.set("apsDesignatedCoordinator", False)
            self.zdo.manager.aps.database.set("apsChannelMask", 0x7fff800)
            self.zdo.manager.aps.database.set("apsUseExtendedPANID", 0x0000000000000000)
            self.zdo.manager.aps.database.set("apsUseInsecureJoin", True)

    def on_authorization(self):
        self.authorized = True
        self.zdo.device_and_service_discovery.device_annce()

    def discover_networks(self):
        logger.info("[zdo_network_manager] Discovering networks.")
        networks = {}
        for network in self.zdo.nwk_management.network_discovery():
            # Create a wrapper for network

            networks[network.extended_pan_id] = Network(
                    network,
                    stack = self.zdo.manager.nwk.mac.stack
            )
            # Loop over identified neighbors matching the current network
            for device_address, device in self.zdo.manager.nwk.database.get("nwkNeighborTable").table.items():
                if device.extended_pan_id == network.extended_pan_id:
                    if device.address == 0:
                        networks[network.extended_pan_id].coordinator = Coordinator(
                            device.address,
                            extended_address=device.extended_address,
                            network=networks[network.extended_pan_id]
                        )
                    else:
                        networks[network.extended_pan_id].routers.append(
                            Router(
                                device.address,
                                extended_address=device.extended_address,
                                network=networks[network.extended_pan_id]
                            )
                        )
        return networks.values()

    def join(self, network):
        nwkExtendedPANID = self.zdo.nwk_management.get("nwkExtendedPANID")
        apsDesignatedCoordinator = self.zdo.aps_management.get("apsDesignatedCoordinator")
        apsUseInsecureJoin = self.zdo.aps_management.get("apsUseInsecureJoin")
        apsChannelMask = self.zdo.aps_management.get("apsChannelMask")

        self.zdo.manager.aps.database.set("apsUseExtendedPANID", network.extended_pan_id)
        apsUseExtendedPANID = self.zdo.aps_management.get("apsUseExtendedPANID")
        logger.info("[zdo_network_manager] Joining specific network: %s.", repr(network))

        join_success = self.zdo.nwk_management.join(
            apsUseExtendedPANID,
            association_type=NWKJoinMode.NEW_JOIN,
            scan_channels=apsChannelMask
        )
        if not join_success:
            logger.info("[zdo_network_manager] failure during network join, exiting.")
            return False

        self.network = network
        return True

    def leave(self):
        return self.zdo.nwk_management.leave()

    def startup(self):
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
                for attempt in range(self.zdo.configuration.get("configNWKScanAttempts")):
                    zigbee_networks = self.zdo.nwk_management.network_discovery(scan_channels=apsChannelMask)
                    for zigbee_network in zigbee_networks:
                        if zigbee_network.extended_pan_id == apsUseExtendedPANID:
                            selected_zigbee_network = zigbee_network
                    if selected_zigbee_network is not None:
                        break
                    else:
                        sleep(self.zdo.configuration.get("configNWKTimeBetweenScans") * SYMBOL_DURATION[Dot15d4Phy.OQPSK] * 2)
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
                self.network = Network(
                        selected_zigbee_network,
                        stack = self.zdo.manager.nwk.mac.stack
                )
                return join_success

            else:
                # join the best available network
                selected_zigbee_network = None
                for attempt in range(self.zdo.configuration.get("configNWKScanAttempts")):
                    zigbee_networks = self.zdo.nwk_management.network_discovery(scan_channels=apsChannelMask)
                    for zigbee_network in zigbee_networks:
                        if zigbee_network.joining_permit:
                            selected_zigbee_network = zigbee_network
                    if selected_zigbee_network is not None:
                        break
                    else:
                        sleep(self.zdo.configuration.get("configNWKTimeBetweenScans") * SYMBOL_DURATION[Dot15d4Phy.OQPSK] * 2)

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
                self.network = Network(
                        selected_zigbee_network,
                        stack = self.zdo.manager.nwk.mac.stack
                )
                return join_success
