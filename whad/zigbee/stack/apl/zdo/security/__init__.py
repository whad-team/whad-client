from whad.zigbee.stack.apl.zdo.object import ZDOObject
from whad.zigbee.stack.nwk.security import NetworkSecurityMaterial

import logging
logger = logging.getLogger(__name__)

class ZDOSecurityManager(ZDOObject):
    """
    ZDO Device Object handling the security-related operations.
    """
    def configure_trust_center(self, trust_center_address):
        """
        Configure the Trust Center address.
        """
        self.zdo.aps_management.set(
            "apsTrustCenterAddress",
            trust_center_address
        )

    def provision_network_key(self, key, key_sequence_number=0):
        """
        Provision a new network key in the NWK layer.
        """
        # Get the Security Material set
        nwkSecurityMaterialSet = set.zdo.nwk_management.get("nwkSecurityMaterialSet")

        # Create a new Network key Material, and add it to the set if it's new
        new_key = NetworkSecurityMaterial(
            key,
            key_sequence_number
        )
        if new_key not in nwkSecurityMaterialSet:
            nwkSecurityMaterialSet.append(new_key)

        # Update the set and configure security level
        self.zdo.nwk_management.set("nwkSecurityMaterialSet", nwkSecurityMaterialSet)
        logger.info("[zdo_security_manager] new network key provisioned.")
        self.zdo.nwk_management.set("nwkSecurityLevel", 5)

    def on_transport_key(self, source_address, standard_key_type, transport_key_data):
        """
        Process all transport keys forwarded by the ZDO.
        """
        # If the key is a network key, provision it and configure the trust center
        if standard_key_type == 1: # process network key
            self.provision_network_key(
                transport_key_data.key,
                transport_key_data.key_sequence_number
            )
            self.configure_trust_center(source_address)

            # Wait until we got an address assigned, then notify authorization to network manager
            while self.zdo.manager.get_layer('nwk').database.get("nwkNetworkAddress") == 0xFFFF:
                pass

            self.zdo.network_manager.on_authorization()
