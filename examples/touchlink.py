from scapy.all import Dot15d4,conf
from whad.zigbee.crypto import TouchlinkKeyManager
from Cryptodome.Cipher import AES
from struct import pack

'''
ZLL Master Key 9F5595F10257C8A469CBF42BC93FEE31 ZigBee
'''
#conf.dot15d4_protocol = "zigbee"

scan_request = Dot15d4(bytes.fromhex("01c8b5fffffffff4ec2a9d20feff570b000b000b00105ec011e2003f10aa2a0292"))
scan_response = Dot15d4(bytes.fromhex("21cc33ffff2a9d20feff570b00b76a2c1a11feff570b000b000300105ec01980013f10aa2a0005811000fa193b56adbe51485bbbb3e10019b76affff010001040120020200"))
network_router_join_request = Dot15d4(bytes.fromhex("21ccb7ffff2c1a11feff570b00f4ec2a9d20feff570b000b000300105ec011e3123f10aa2ae33a7768bac3a2780494a6708173d44fedc2110e92030c023d0019f4ec1800000000000000000000000000"))

mgr = TouchlinkKeyManager(unencrypted_key=b"\xac\xbe\xf1Dp'\xd8\xd9Z\xfaB\xb0w\xe4\x88\xa5", transaction_id=0xea9cd138, response_id=0x8f8dbab4, key_index=0)
print(mgr.encrypted_key)
