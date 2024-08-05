"""
Generic Provisioning Layer

Handles the creaton of a Link, acks and fragmentation for the Provisoning Layer
"""

import logging

from whad.scapy.layers.bt_mesh import BTMesh_Generic_Provisioning_Hdr
from whad.common.stack import ContextualLayer, alias

logger = logging.getLogger(__name__)


@alias("gen_prov")
class ProvisioningLayer(ContextualLayer):
    """Generic Provisioning Provisioner/Device base class"""

    def configure(self, options):
        """Configure the Generic Provisioning Layer"""
 
