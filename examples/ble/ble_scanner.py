from whad.ble import Scanner
from whad.device import Device
from whad.exceptions import WhadDeviceNotFound
import sys

if __name__ == '__main__':
    if len(sys.argv) >= 2:
        # Retrieve target interface
        interface = sys.argv[1]
        dev = None

        try:
            # Access our interface
            dev = Device.create(interface)

            # Attach a scanner role and scan devices
            with Scanner(dev) as scanner:
                for remote_dev in scanner.discover_devices():
                    print(remote_dev)

        # Handle interruptions (user or system)
        except (KeyboardInterrupt, SystemExit):
            if dev is not None:
                dev.close()

        # Device not found ?
        except WhadDeviceNotFound:
            print('[e] Device not found')
            exit(1)
    else:
        print('Usage: %s [device]' % sys.argv[0])

