from scapy.all import Dot15d4,conf
from whad.zigbee.crypto import TouchlinkKeyManager
from Cryptodome.Cipher import AES
from struct import pack

'''
ZLL Master Key 9F5595F10257C8A469CBF42BC93FEE31 ZigBee
'''
#conf.dot15d4_protocol = "zigbee"

scan_request = Dot15d4(bytes.fromhex("01c8befffffffff4ec2a9d20feff570b000b000b00105ec011fe00ecde68830292"))
scan_response = Dot15d4(bytes.fromhex("21cc0dffff2a9d20feff570b00b21e2c1a11feff570b000b000300105ec0198001ecde688300058110008d9c7c87146387ba36141122000fb21effff010001040120020200"))
network_router_join_request = Dot15d4(bytes.fromhex("21ccc2ffff2c1a11feff570b00f4ec2a9d20feff570b000b000300105ec0118112ecde6883e33a7768bac3a27804e2f6732703366660d2643000f6b2c2280019f4ec1b00000000000000000000000000"))

scan_request.show()
scan_response.show()
network_router_join_request.show()
mgr = TouchlinkKeyManager()
mgr.process_packet(scan_request)
mgr.process_packet(scan_response)
mgr.process_packet(network_router_join_request)
print(":".join("{:02x}".format(i) for i in mgr.encrypted_key))
