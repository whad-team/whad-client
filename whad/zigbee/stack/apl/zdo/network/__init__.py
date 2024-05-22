from whad.zigbee.stack.apl.zdo.object import ZDOObject
from whad.zigbee.stack.nwk.constants import NWKJoinMode
from whad.zigbee.stack.apl.constants import LogicalDeviceType

from whad.exceptions import RequiredImplementation

# Wrappers
from whad.zigbee.profile.network import Network
from whad.zigbee.profile.nodes import CoordinatorNode, EndDeviceNode, RouterNode

from time import sleep
from random import randint

import logging
logger = logging.getLogger(__name__)

class ZDONetworkManager(ZDOObject):
    """
    ZDO Device Object handling the network-related operations.
    """

    def configure_short_address(self, short_address):
        """
        Configure the short address to use.
        """
        phy_layer = self.zdo.manager.get_layer('phy')
        mac_layer = self.zdo.manager.get_layer('mac')
        nwk_layer = self.zdo.manager.get_layer('nwk')

        nwk_layer.database.set("nwkNetworkAddress", short_address)
        mac_layer.database.set("macShortAddress", short_address)
        phy_layer.set_short_address(short_address)

    def configure_extended_address(self, extended_address):
        """
        Configure the extended address to use.
        """
        phy_layer = self.zdo.manager.get_layer('phy')
        mac_layer = self.zdo.manager.get_layer('mac')
        nwk_layer = self.zdo.manager.get_layer('nwk')

        nwk_layer.database.set("nwkIeeeAddress", extended_address)
        mac_layer.database.set("macExtendedAddress", extended_address)
        phy_layer.set_extended_address(extended_address)

    def configure_extended_pan_id(self, extended_pan_id):
        """
        Configure the extended PanID of the network.
        """
        nwk_layer = self.zdo.manager.get_layer('nwk')

        nwk_layer.database.set("nwkExtendedPANID", extended_pan_id)

    def initialize(self, logical_type=LogicalDeviceType.END_DEVICE):
        """
        Initialize the network manager according to current configuration.
        """
        aps_layer = self.zdo.manager.get_layer('aps')

        # Network profile wrapper
        self.network = None
        # By default we are unauthorized on the network
        self.authorized = False

        # Get the logical type
        logical_type = self.zdo.configuration.get("configNodeDescriptor").logical_type

        # Check if we are an end device
        if logical_type == LogicalDeviceType.END_DEVICE:
            self.configure_extended_address(randint(0, 0xffffffffffffffff))
            self.configure_short_address(0xFFFF)
            self.configure_extended_pan_id(0x0000000000000000)
            aps_layer.database.set("apsDesignatedCoordinator", False)
            aps_layer.database.set("apsChannelMask", 0x7fff800)
            aps_layer.database.set("apsUseExtendedPANID", 0x0000000000000000)
            aps_layer.database.set("apsUseInsecureJoin", True)

        elif logical_type == LogicalDeviceType.COORDINATOR:
            self.configure_extended_address(randint(0, 0xffffffffffffffff))
            self.configure_short_address(0x0000)
            aps_layer.database.set("apsDesignatedCoordinator", True)
            aps_layer.database.set("apsUseExtendedPANID", randint(0, 0xffffffffffffffff))
            self.configure_extended_pan_id(0x0000000000000000)
            aps_layer.database.set("apsUseInsecureJoin", True)
            aps_layer.database.set(
                "apsTrustCenterAddress",
                self.zdo.nwk_management.get("nwkIeeeAddress")
            )

    def on_authorization(self):
        """
        Callback called when we are authorized.
        """
        # Mark the network as authorized.
        self.authorized = True
        # Indicate the device presence with a device announce.
        self.zdo.device_and_service_discovery.device_annce()

    def discover_networks(self):
        """
        Discover the surrounding networks.
        """
        phy_layer = self.zdo.manager.get_layer('phy')
        nwk_layer = self.zdo.manager.get_layer('nwk')
        nwk_management = nwk_layer.get_service('management')

        logger.info("[zdo_network_manager] Discovering networks.")
        networks = {}
        for network in nwk_management.network_discovery():
            # Create a wrapper for network
            networks[network.extended_pan_id] = Network(
                    network,
                    stack = phy_layer
            )
            # Loop over identified neighbors matching the current network
            for device_address, device in nwk_layer.database.get("nwkNeighborTable").table.items():
                if device.extended_pan_id == network.extended_pan_id:
                    if device.address == 0:
                        networks[network.extended_pan_id].coordinator = CoordinatorNode(
                            device.address,
                            extended_address=device.extended_address,
                            network=networks[network.extended_pan_id]
                        )
                    else:
                        networks[network.extended_pan_id].routers.append(
                            RouterNode(
                                device.address,
                                extended_address=device.extended_address,
                                network=networks[network.extended_pan_id]
                            )
                        )
        return networks.values()

    def join(self, network):
        """
        Join a specific network.
        """
        nwk_layer = self.zdo.manager.get_layer('nwk')
        nwk_management = nwk_layer.get_service('management')
        aps_layer = self.zdo.manager.get_layer('aps')
        aps_management = aps_layer.get_service('management')

        nwkExtendedPANID = nwk_management.get("nwkExtendedPANID")
        apsDesignatedCoordinator = aps_management.get("apsDesignatedCoordinator")
        apsUseInsecureJoin = aps_management.get("apsUseInsecureJoin")
        apsChannelMask = aps_management.get("apsChannelMask")

        aps_layer.database.set("apsUseExtendedPANID", network.extended_pan_id)
        apsUseExtendedPANID = aps_management.get("apsUseExtendedPANID")
        logger.info("[zdo_network_manager] Joining specific network: %s.", repr(network))

        join_success = nwk_management.join(
            apsUseExtendedPANID,
            association_type=NWKJoinMode.NEW_JOIN,
            scan_channels=apsChannelMask
        )
        if not join_success:
            logger.info("[zdo_network_manager] failure during network join, exiting.")
            return False

        self.network = network
        return True



    def rejoin(self, network):
        """
        Rejoin a specific network.
        """
        nwk_layer = self.zdo.manager.get_layer('nwk')
        nwk_management = nwk_layer.get_service('management')
        aps_layer = self.zdo.manager.get_layer('aps')
        aps_management = aps_layer.get_service('management')

        nwkExtendedPANID = nwk_management.get("nwkExtendedPANID")
        apsDesignatedCoordinator = aps_management.get("apsDesignatedCoordinator")
        apsUseInsecureJoin = aps_management.get("apsUseInsecureJoin")
        apsChannelMask = aps_management.get("apsChannelMask")

        aps_layer.database.set("apsUseExtendedPANID", network.extended_pan_id)
        apsUseExtendedPANID = aps_management.get("apsUseExtendedPANID")
        logger.info("[zdo_network_manager] Rejoining specific network: %s.", repr(network))
        print(apsUseExtendedPANID)
        join_success = nwk_management.join(
            apsUseExtendedPANID,
            association_type=NWKJoinMode.REJOIN,
            scan_channels=apsChannelMask,
            security_enable=True
        )
        if not join_success:
            logger.info("[zdo_network_manager] failure during network rejoin, exiting.")
            return False

        self.network = network
        self.on_authorization()
        return True

    def leave(self):
        """
        Leave the network if we are currently associated.
        """
        nwk_layer = self.zdo.manager.get_layer('nwk')
        nwk_management = nwk_layer.get_service('management')

        return nwk_management.leave()

    def startup(self):
        nwk_layer = self.zdo.manager.get_layer('nwk')
        nwk_management = nwk_layer.get_service('management')
        aps_layer = self.zdo.manager.get_layer('aps')
        aps_management = aps_layer.get_service('management')
        phy_layer = self.zdo.manager.get_layer('phy')


        nwkExtendedPANID = nwk_management.get("nwkExtendedPANID")
        apsDesignatedCoordinator = aps_management.get("apsDesignatedCoordinator")
        apsUseExtendedPANID = aps_management.get("apsUseExtendedPANID")
        apsUseChannel = aps_management.get("apsUseChannel")

        apsUseInsecureJoin = aps_management.get("apsUseInsecureJoin")
        apsChannelMask = aps_management.get("apsChannelMask")
        if nwkExtendedPANID != 0:
            # we are already connected :) don't do anything
            return True

        if apsDesignatedCoordinator:
            # We are a coordinator not connected, start NLME-NETWORK-FORMATION
            if apsUseExtendedPANID != 0:
                nwk_management.set("nwkExtendedPANID", apsUseExtendedPANID)

            nwk_management.network_formation(
                pan_id=None,
                channel=apsUseChannel,
                scan_channels=apsChannelMask,
            )

            self.network = Network(
                nwk_management.get("nwkOwnNetwork"), phy_layer
            )
            self.authorized = True
            return True
        else:
            # We are a router or an end device, attempt to join or rejoin a network
            if apsUseExtendedPANID != 0:
                rejoin_success = nwk_management.join(
                    apsUseExtendedPANID,
                    association_type=NWKJoinMode.REJOIN,
                    scan_channels=apsChannelMask
                )
                if rejoin_success:
                    return True

                # We failed to rejoin, try to join
                selected_zigbee_network = None
                for attempt in range(self.zdo.configuration.get("configNWKScanAttempts")):
                    zigbee_networks = nwk_management.network_discovery(scan_channels=apsChannelMask)
                    for zigbee_network in zigbee_networks:
                        if zigbee_network.extended_pan_id == apsUseExtendedPANID:
                            selected_zigbee_network = zigbee_network
                    if selected_zigbee_network is not None:
                        break
                    else:
                        sleep(
                                self.zdo.configuration.get("configNWKTimeBetweenScans") *
                                phy_layer.symbol_duration * 2
                        )
                if selected_zigbee_network is None:
                    logger.info("[zdo_network_manager] target network not found, exiting.")
                    return False

                join_success = nwk_management.join(
                    apsUseExtendedPANID,
                    association_type=NWKJoinMode.NEW_JOIN,
                    scan_channels=apsChannelMask
                )
                if not join_success:
                    logger.info("[zdo_network_manager] failure during network join, exiting.")
                self.network = Network(
                        selected_zigbee_network,
                        stack = phy_layer
                )
                return join_success

            else:
                # join the best available network
                selected_zigbee_network = None
                for attempt in range(self.zdo.configuration.get("configNWKScanAttempts")):
                    zigbee_networks = nwk_management.network_discovery(scan_channels=apsChannelMask)
                    for zigbee_network in zigbee_networks:
                        if zigbee_network.joining_permit:
                            selected_zigbee_network = zigbee_network
                    if selected_zigbee_network is not None:
                        break
                    else:
                        sleep(
                                self.zdo.configuration.get("configNWKTimeBetweenScans") *
                                phy_layer.symbol_duration * 2
                        )
                if selected_zigbee_network is None:
                    logger.info("[zdo_network_manager] no target network found, exiting.")
                    return False

                join_success = nwk_management.join(
                    selected_zigbee_network.extended_pan_id,
                    association_type=NWKJoinMode.NEW_JOIN,
                    scan_channels=apsChannelMask
                )
                if not join_success:
                    logger.info("[zdo_network_manager] failure during network join, exiting.")
                self.network = Network(
                        selected_zigbee_network,
                        stack = phy_layer
                )
                return join_success
