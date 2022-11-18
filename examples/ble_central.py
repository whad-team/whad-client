from whad.ble import Central, ConnectionEventTrigger, ReceptionTrigger, ManualTrigger
from whad.ble.profile import UUID
from whad.device import WhadDevice
from time import sleep
from scapy.all import BTLE_DATA, ATT_Hdr, L2CAP_Hdr, ATT_Read_Request, ATT_Write_Request, ATT_Error_Response

def show(packet):
    print(packet.metadata, repr(packet))

central = Central(WhadDevice.create('uart0'))
central.attach_callback(show)


prepared_packets = [
    BTLE_DATA()/L2CAP_Hdr()/ATT_Hdr()/ATT_Write_Request(gatt_handle=2, data=b"ABCDABCDABCD"),
    BTLE_DATA()/L2CAP_Hdr()/ATT_Hdr()/ATT_Read_Request(gatt_handle=42)
]


prepared_packets2 = [
    BTLE_DATA()/L2CAP_Hdr()/ATT_Hdr()/ATT_Write_Request(gatt_handle=1, data=b"AfterReception"),
    BTLE_DATA()/L2CAP_Hdr()/ATT_Hdr()/ATT_Write_Request(gatt_handle=2, data=b"AfterReception"),
    BTLE_DATA()/L2CAP_Hdr()/ATT_Hdr()/ATT_Write_Request(gatt_handle=3, data=b"AfterReception"),
    BTLE_DATA()/L2CAP_Hdr()/ATT_Hdr()/ATT_Write_Request(gatt_handle=4, data=b"AfterReception"),
]

trigger1 = ManualTrigger()
central.prepare(*prepared_packets, trigger=trigger1)

trigger = ReceptionTrigger(packet=BTLE_DATA()/L2CAP_Hdr()/ATT_Hdr()/ATT_Error_Response(handle=42), selected_fields=("cid", "opcode", "handle"))
central.prepare(*prepared_packets2, trigger=trigger)
input()

#print('Using device: %s' % central.device.device_id)
device = central.connect('A4:C1:38:22:01:64', random=False)
print("here")
input()
#trigger1.trigger()
central.trigger(trigger1)
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
device.disconnect()
central.stop()
central.close()
