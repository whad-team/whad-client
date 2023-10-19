from whad.ble import Central, ConnectionEventTrigger, ReceptionTrigger, ManualTrigger
from whad.ble.profile import UUID
from whad.device import WhadDevice
from whad.ble.stack.smp import Pairing, IOCAP_KEYBD_ONLY, CryptographicDatabase
from time import sleep
from scapy.all import BTLE_DATA, ATT_Hdr, L2CAP_Hdr, ATT_Read_Request, ATT_Write_Request, ATT_Error_Response, BTLE_EMPTY_PDU, BTLE_CTRL, LL_ENC_REQ
import logging

logging.basicConfig(level=logging.WARNING)
logging.getLogger('whad.ble.stack.smp').setLevel(logging.INFO)

def show(packet):
    print(packet.metadata, repr(packet))

security_database = CryptographicDatabase()

central = Central(WhadDevice.create('hci0'), security_database=security_database)
central.attach_callback(show)

print("New connection")
#print('Using device: %s' % central.device.device_id)
device = central.connect('54:b0:93:21:73:d3', random=True)#, random=False, hop_interval=56, channel_map=0x00000300)
# Discover
device.discover()
for service in device.services():
    print('-- Service %s' % service.uuid)
    for charac in service.characteristics():
        print(' + Characteristic %s' % charac.uuid)

# Read Device Name characteristic (Generic Access Service)
c = device.get_characteristic(UUID('1800'), UUID('2A00'))
print(c.value)
input()

device.pairing(pairing=
    Pairing(
        lesc=False,
        mitm=True,
        iocap=IOCAP_KEYBD_ONLY
    )
)

print(central.security_database)
while True:
    sleep(1)
# Disconnect
print("Stop connection")
device.disconnect()
central.stop()
central.close()
