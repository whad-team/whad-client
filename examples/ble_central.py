from whad.ble import Central, ConnectionEventTrigger, ReceptionTrigger, ManualTrigger
from whad.ble.profile import UUID
from whad.device import WhadDevice
from time import sleep
from scapy.all import BTLE_DATA, ATT_Hdr, L2CAP_Hdr, ATT_Read_Request, ATT_Write_Request, ATT_Error_Response, BTLE_EMPTY_PDU, BTLE_CTRL, LL_ENC_REQ

def show(packet):
    print(packet.metadata, repr(packet))

central = Central(WhadDevice.create('uart0'))
central.attach_callback(show)

while True:
    print("New connection")
    #print('Using device: %s' % central.device.device_id)
    device = central.connect('C9:31:40:92:AD:F6', random=False, hop_interval=56, channel_map=0x00000300)
    input()
    # Discover
    device.discover()
    for service in device.services():
        print('-- Service %s' % service.uuid)
        for charac in service.characteristics():
            print(' + Characteristic %s' % charac.uuid)

    # Read Device Name characteristic (Generic Access Service)
    c = device.get_characteristic(UUID('1800'), UUID('2A00'))
    print(c.value)

    # Disconnect
    print("Stop connection")
    device.disconnect()
central.stop()
central.close()
