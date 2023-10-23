from whad.ble import Central, ConnectionEventTrigger, ReceptionTrigger, ManualTrigger
from whad.ble.profile import UUID
from whad.ble import BDAddress
from whad.device import WhadDevice
from whad.ble.stack.smp import Pairing, IOCAP_KEYBD_ONLY, IOCAP_NOINPUT_NOOUTPUT, CryptographicDatabase
from time import sleep
from scapy.all import BTLE_DATA, ATT_Hdr, L2CAP_Hdr, ATT_Read_Request, ATT_Write_Request, ATT_Error_Response, BTLE_EMPTY_PDU, BTLE_CTRL, LL_ENC_REQ
import logging

logging.basicConfig(level=logging.WARNING)
logging.getLogger('whad.ble.stack.smp').setLevel(logging.INFO)

def show(packet):
    print(packet.metadata, repr(packet))

security_database = CryptographicDatabase()
'''
security_database.add(
    BDAddress('F8:9E:94:56:35:91', random=False),
    ltk=bytes.fromhex("fe393733041a1e50144c8b7f9c0f7a07"),
    rand=bytes.fromhex("0000000000000000"),
    ediv=0x0000
)'''
central = Central(WhadDevice.create('hci0'), security_database=security_database)
central.attach_callback(show)



print("New connection")
#print('Using device: %s' % central.device.device_id)

device = central.connect('F8:9E:94:56:35:91', random=False)#, random=False, hop_interval=56, channel_map=0x00000300)
# Discover
device.discover()
for service in device.services():
    print('-- Service %s' % service.uuid)
    for charac in service.characteristics():
        print(' + Characteristic %s' % charac.uuid)

# Read Device Name characteristic (Generic Access Service)
input()

print(device.pairing(pairing=
    Pairing(
        lesc=False,
        mitm=False,
        bonding=True,
        iocap=IOCAP_NOINPUT_NOOUTPUT,
        sign_key=False,
        id_key=False,
        link_key=False,
        enc_key=True
    )
))

print(central.security_database)
try:
    while True:
        sleep(1)
except KeyboardInterrupt:
    pass
# Disconnect
print("Stop connection")
device.disconnect()
device2 = central.connect('F8:9E:94:56:35:91', random=False)#, random=False, hop_interval=56, channel_map=0x00000300)
device2.start_encryption()
try:
    while True:
        sleep(1)
except KeyboardInterrupt:
    pass

device2.disconnect()

central.stop()
central.close()
