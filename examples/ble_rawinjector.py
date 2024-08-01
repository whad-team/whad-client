from whad.ble import Sniffer, Injector, ReceptionTrigger, ManualTrigger, ConnectionEventTrigger, BleDirection
from whad.device import WhadDevice
from whad.exceptions import WhadDeviceNotFound
from whad.ble.exceptions import ConnectionLostException
from time import time,sleep
from scapy.all import BTLE_ADV, BTLE_ADV_IND, BTLE, BTLE_CTRL, LL_UNKNOWN_RSP,LL_REJECT_IND,  BTLE_DATA, L2CAP_Hdr, ATT_Hdr, ATT_Write_Request,ATT_Read_Request, ATT_Read_Response, SM_Hdr, SM_Pairing_Response, LL_ENC_REQ
import sys

def show(pkt):
    print(repr(pkt.metadata), repr(pkt))
    print(bytes(pkt).hex())
if __name__ == '__main__':
    if len(sys.argv) >= 2:
        # Retrieve target interface
        interface = sys.argv[1]

        try:
            dev = WhadDevice.create(interface)
            injector = Injector(dev)
            while True:
                print(injector.raw_inject(BTLE()/BTLE_ADV()/BTLE_ADV_IND(AdvA='11:22:33:11:22:33', data=b"\x41"*20)))
                #print(injector.inject_to_slave(BTLE_DATA()/L2CAP_Hdr()/ATT_Hdr()/ATT_Write_Request(gatt_handle=0x21, data=b"\x55\x10\x00\x0d\x0a")))
                sleep(1)
                print(injector.raw_inject(BTLE()/BTLE_ADV()/BTLE_ADV_IND(AdvA='11:22:33:11:22:33', data=b"\x42"*20)))
                #print(injector.inject_to_slave(BTLE_DATA()/L2CAP_Hdr()/ATT_Hdr()/ATT_Write_Request(gatt_handle=0x21, data=b"\x55\x10\x01\x0d\x0a")))
                sleep(1)
        except ConnectionLostException as e:
            print("Connection lost", e)

        except (KeyboardInterrupt, SystemExit):
            dev.close()

        except WhadDeviceNotFound:
            print('[e] Device not found')
            exit(1)
    else:
        print('Usage: %s [device]' % sys.argv[0])
