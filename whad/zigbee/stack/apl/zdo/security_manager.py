from whad.zigbee.stack.apl.zdo.object import ZDOObject
from whad.zigbee.stack.nwk.constants import NetworkSecurityMaterial
import logging

logger = logging.getLogger(__name__)

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
            while self.zdo.manager.nwk.database.get("nwkNetworkAddress") == 0xFFFF:
                pass
            self.zdo.network_manager.on_authorization()
