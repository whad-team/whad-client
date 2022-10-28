from whad.scapy.layers.esb import *
from whad.scapy.layers.unifying import *

bind()
pr1 = ESB_Hdr(bytes.fromhex("aabb0adca575580faf80fbf74bb50d042026820100a38000000000004f682f00"))
pr2 = ESB_Hdr(bytes.fromhex("aabb0adca5755a0f8f80cd85482141044404020080838000000000001198b900"))
pr3 = ESB_Hdr(bytes.fromhex("aa9b0a9042825b0faf8118d362831e44fd980f20000004800000000043e7a980"))
pr4 = ESB_Hdr(bytes.fromhex("aa9b0a9042825b0f8f813577043b9e44fd980f20000004800000000049491900"))
pr5 = ESB_Hdr(bytes.fromhex("aa9b0a90428259002f818084a59a18181028363ab98000000000000078cb1b80"))
pr6 = ESB_Hdr(bytes.fromhex("aa9b0a904282290007830101843b9e44d1769e00"))
pr7 = ESB_Hdr(bytes.fromhex("aa9b0a9042822b002783008000000000553a3c80"))
pr8 = ESB_Hdr(bytes.fromhex("aa9b0a904282280007828093ea00fd98625e3300"))
pr9 = ESB_Hdr(bytes.fromhex("aa9b0a9042822900070000000000000079394980"))

device_nonce = None
dongle_nonce = None
device_wpid = None
dongle_wpid = None
device_serial = None
dongle_serial = None

for i in (pr1, pr2, pr3, pr4, pr5, pr6, pr7, pr8, pr9):
    print(bytes(i[ESB_Payload_Hdr:]).hex())
    i.show()
    if hasattr(i, "rf_address"):
        print(i.rf_address)
    if hasattr(i, "device_nonce"):
        device_nonce = i.device_nonce
    if hasattr(i, "dongle_nonce"):
        dongle_nonce = i.dongle_nonce
    if hasattr(i, "device_wpid"):
        device_wpid = i.device_wpid
    if hasattr(i, "dongle_wpid"):
        dongle_wpid = i.dongle_wpid
    if hasattr(i, "device_serial"):
        device_serial = i.device_serial
    if hasattr(i, "dongle_serial"):
        dongle_serial = i.dongle_serial

print("Device nonce:", device_nonce.hex())
print("Dongle nonce:", dongle_nonce.hex())
print("Device wpid:", pack("H", device_wpid).hex())
print("Dongle wpid:", pack("H", dongle_wpid).hex())
print("Device serial:", device_serial.hex())
print("Dongle serial:", dongle_serial.hex())


# 000f0602030877 3c89 a2
#           0877 (last two bytes of dongle nonce) 3c89 (first two bytes of dongle serial)

# 000f050127 d401 fb30 c4

'''
Device nonce: 31a6c506
Dongle nonce: 6aee0877
Device wpid: 4d40
Dongle wpid: 0888
Device serial: 3c89fb30
Dongle serial: 3c89fb30
'''
