from whad.ble import Central, ConnectionEventTrigger, ReceptionTrigger, ManualTrigger
from whad.ble.profile import UUID
from whad.device import WhadDevice
from time import sleep
from scapy.all import BTLE_DATA,BTLE_CTRL,ATT_Hdr,ATT_Read_Request, L2CAP_Hdr, SM_Hdr, SM_Pairing_Request, LL_PAUSE_ENC_REQ

def show(pkt):
    print(pkt.metadata, repr(pkt))

print("Create central from uart0")
central = Central(WhadDevice.create('uart0'))
central.attach_callback(show)

device = central.connect('20:73:5b:19:3e:41')
input()
central.send_pdu(BTLE_DATA()/BTLE_CTRL()/LL_PAUSE_ENC_REQ())

input()
device.disconnect()
central.stop()
central.close()
