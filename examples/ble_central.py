from whad.ble import Central, ConnectionEventTrigger, ReceptionTrigger, ManualTrigger
from whad.ble.profile import UUID
from whad.device import WhadDevice
from time import sleep
from scapy.all import BTLE_DATA, ATT_Hdr, L2CAP_Hdr, ATT_Read_Request, ATT_Write_Request, ATT_Error_Response, BTLE_EMPTY_PDU, BTLE_CTRL, LL_ENC_REQ
import logging

logging.getLogger('whad.ble.stack.smp').setLevel(logging.DEBUG)

def show(packet):
    print(packet.metadata, repr(packet))

central = Central(WhadDevice.create('uart0'))
central.attach_callback(show)

print("New connection")
#print('Using device: %s' % central.device.device_id)
device = central.connect('74:DA:EA:91:47:E3', random=False)#, random=False, hop_interval=56, channel_map=0x00000300)
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
device.pairing()
input()
# Disconnect
print("Stop connection")
device.disconnect()
central.stop()
central.close()
