from whad.zigbee.stack.apl.zdo.object import ZDOObject
from whad.zigbee.stack.nwk.security import NetworkSecurityMaterial
from whad.zigbee.stack.aps.security import APSNetworkKeyData

from whad.exceptions import RequiredImplementation

from time import sleep
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
        nwkSecurityMaterialSet = self.zdo.nwk_management.get("nwkSecurityMaterialSet")

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

    def send_transport_key(self, destination_address):
        """
        Transmit the transport key to a new joining device.
        """
        apsTrustCenterAddress = self.zdo.aps_management.get("apsTrustCenterAddress")
        nwkIeeeAddress = self.zdo.nwk_management.get("nwkIeeeAddress")
        # maybe this test  should be in network manager instead of security manager,
        # since it processes not only transport key but also dev update.
        if apsTrustCenterAddress != 0xFFFFFFFFFFFFFFFF:
            # Centralized network
            if apsTrustCenterAddress == nwkIeeeAddress:
                # We are the trust center, implement 4.6.3.2.2 (p431)
                if self.zdo.configuration.get("allowsJoins"):
                    nwkSecurityMaterialSet = self.zdo.nwk_management.get("nwkSecurityMaterialSet")
                    if len(nwkSecurityMaterialSet) > 0:
                        selected_key = nwkSecurityMaterialSet[0]
                    else:
                        # inject default key if nothing is provided
                        self.provision_network_key(
                            bytes.fromhex("11223344556677881122334455667788"),
                            key_sequence_number = 0
                        )
                        selected_key = nwkSecurityMaterialSet[0]
                    sleep(0.5)
                    self.zdo.aps_management.transport_key(
                        destination_address=destination_address,
                        standard_key_type=1,
                        transport_key_data = APSNetworkKeyData(
                            key=selected_key.key,
                            key_sequence_number=selected_key.key_sequence_number,
                            use_parent=False # assume we are the router
                        )
                    )
                else:
                    # - APSME-REMOVE-DEVICE with:
                    #   + parentAddress = address of the router
                    #   + childAddress = address of the joining non authorized device
                    raise RequiredImplementation("RemoveDeviceFromNetwork")
            else:
                # Here we should trigger:
                # - APSME-UPDATE-DEVICE with:
                #    + destAddr = apsTrustCenterAddress
                #    + deviceAddr = address of the new device
                raise RequiredImplementation("TransportKeyTrustCenterAddress")
        else:
            # Distributed security network
            raise RequiredImplementation("TransportKeyDistributedSecurityNetwork")

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
