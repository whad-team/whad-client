from whad.ble import Central, ConnectionEventTrigger, ReceptionTrigger, ManualTrigger
from whad.ble.profile import UUID
from whad.device import WhadDevice
from time import sleep
from scapy.all import BTLE_DATA, ATT_Hdr, L2CAP_Hdr, ATT_Read_Request, ATT_Write_Request, ATT_Error_Response, BTLE_EMPTY_PDU, BTLE_CTRL, LL_ENC_REQ

def show(packet):
    print(packet.metadata, repr(packet))

print("Create central from uart0")
central = Central(WhadDevice.create('uart0'))
#central.attach_callback(show)

while True:
    trigger_radio = ConnectionEventTrigger(10)
    central.prepare(
        BTLE_DATA()/BTLE_EMPTY_PDU(),
        trigger=trigger_radio
    )
    trigger_read_enc = ConnectionEventTrigger(20)
    central.prepare(
        BTLE_DATA()/L2CAP_Hdr()/ATT_Hdr()/ATT_Read_Request(gatt_handle=3),
        BTLE_DATA(MD=1)/BTLE_CTRL()/LL_ENC_REQ(rand=0x26e9429fd727c6f3, ediv=0x6c51, skdm=0xf3681496c43831bb, ivm=0x99e664e3),
        trigger=trigger_read_enc
    )
    state1 = False
    state2 = False
    device = central.connect('C9:31:40:92:AD:F6', random=False, hop_interval=56, channel_map=0x00000300)

    while central.is_connected():
        if trigger_radio.triggered and not state1:
            print("[RADIO ON]")
            state1 = True

        if trigger_read_enc.triggered and not state2:
            print("[ENC_REQ SEND]")
            state2 = True

        if state1 and state2:
            device.disconnect()
            print("[RADIO OFF]")
            sleep(1)

central.stop()
central.close()
