from scapy.all import Dot15d4,conf
from whad.scapy.layers.zll import *
'''
ZLL Master Key 9F5595F10257C8A469CBF42BC93FEE31 ZigBee
'''
conf.dot15d4_protocol = "zigbee"

scan_request = Dot15d4(bytes.fromhex("01c8adfffffffff4ec2a9d20feff570b000b000b00105ec011da00b3aec5e20292"))
scan_response = Dot15d4(bytes.fromhex("21cc33ffff2a9d20feff570b00b76a2c1a11feff570b000b000300105ec01980013f10aa2a0005811000fa193b56adbe51485bbbb3e10019b76affff010001040120020200"))
identify_request = Dot15d4(bytes.fromhex("21ccb6ffff2c1a11feff570b00f4ec2a9d20feff570b000b000300105ec0112f063f10aa2a0a00"))
network_router_join_request = Dot15d4(bytes.fromhex("21ccb7ffff2c1a11feff570b00f4ec2a9d20feff570b000b000300105ec011e3123f10aa2ae33a7768bac3a2780494a6708173d44fedc2110e92030c023d0019f4ec1800000000000000000000000000"))
network_router_join_response = Dot15d4(bytes.fromhex("21cc34ffff2a9d20feff570b00b76a2c1a11feff570b000b000300105ec01981133f10aa2a00"))

for i in (scan_request, scan_response, identify_request, network_router_join_request, network_router_join_response):
    i.show()
