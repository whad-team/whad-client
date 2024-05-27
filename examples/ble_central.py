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
    BDAddress('6e:36:c4:60:fa:b2', random=True),
    ltk=bytes.fromhex("f80fcaf8884bcc70e8135ecf53f09c8b"),
    rand=bytes.fromhex("170dee04a32ee3fa"),
    ediv=0x87e9
)
'''
central = Central(WhadDevice.create('uart0'), security_database=security_database)
central.attach_callback(show)


print("New connection")

device = central.connect('F4:9E:F2:6D:37:85',  random=True, hop_interval=9)

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

# Connect again and start encryption
device2 = central.connect('43:1B:16:A6:E6:D6', random=True)
device2.start_encryption()
try:
    while True:
        sleep(1)
except KeyboardInterrupt:
    pass

device2.disconnect()

central.stop()
central.close()
