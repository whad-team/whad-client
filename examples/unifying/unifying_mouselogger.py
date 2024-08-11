from whad.unifying import Keylogger, Mouselogger
from whad.device import WhadDevice
from whad.exceptions import WhadDeviceNotFound
import sys,time

def show(pkt):
    print(repr(pkt))

if __name__ == '__main__':
    if len(sys.argv) >= 2:
        # Retrieve target interface
        interface = sys.argv[1]

        try:
            # Create a WHAD device
            dev = WhadDevice.create(interface)

            # Create & configure the mouselogger
            connector = Mouselogger(dev)
            connector.address = "ca:e9:06:ec:a4"
            connector.scanning = True
            connector.decrypt = True

            # Start and iterate over mouse stream
            connector.start()
            out = ""
            for i in connector.stream():
                print(i)

        except (KeyboardInterrupt, SystemExit):
            dev.close()

        except WhadDeviceNotFound:
            print('[e] Device not found')
            exit(1)
    else:
        print('Usage: %s [device]' % sys.argv[0])
