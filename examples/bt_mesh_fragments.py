from scapy.layers.bluetooth4LE import BTLE
from  whad.bt_mesh.utils.assemble_frag import GenericFragmentsAssembler
from whad.scapy.layers.bt_mesh import EIR_PB_ADV_PDU, BTMesh_Provisioning_Hdr

"""
pkt1 = BTLE(bytes.fromhex("d6be898e42259a234ba950341e29c72db67a0504002284073513c8f711c8b9b70949e1d2a96b9fb6cd13c611cbd7"))
pkt2 = BTLE(bytes.fromhex("d6be898e421c04bd7d630b221529c72db67a05064a5a9d08210f772839581ca32b8b16809b"))

assembler = GenericFragmentsAssembler()
assembler.add_next_packet(pkt1)
assembler.add_next_packet(pkt2)
res = assembler.reassemble()

res.show()
"""


pkt1 = EIR_PB_ADV_PDU(bytes.fromhex("23af585002080041d1032c31a47b5779809ef44cb5eaaf5c3e43d5f8fa"))
pkt2 = EIR_PB_ADV_PDU(bytes.fromhex("23af58500206ad4a8794cb987e9b03745c78dd919512183898dfbecd52"))
pkt3 = EIR_PB_ADV_PDU(bytes.fromhex("23af5850020ae2408e43871fd021109117bd3ed4eaf8437743715d4f"))

assembler = GenericFragmentsAssembler()
assembler.add_next_packet(pkt1)
assembler.add_next_packet(pkt2)
assembler.add_next_packet(pkt3)

res = assembler.reassemble()

print("\nREASSEMBLED\n")
res.show()

print("\nEXPECTED\n")

expected_packet = BTMesh_Provisioning_Hdr(bytes.fromhex("032c31a47b5779809ef44cb5eaaf5c3e43d5f8faad4a8794cb987e9b03745c78dd919512183898dfbecd52e2408e43871fd021109117bd3ed4eaf8437743715d4f"))

expected_packet.show()
