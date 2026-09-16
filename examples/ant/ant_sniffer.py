from whad.ant import ANT, Sniffer
from whad.ant.crypto import ANT_PLUS_NETWORK_KEY
from whad.device import WhadDevice
from whad.exceptions import WhadDeviceNotFound
import sys
from time import sleep

if __name__ == '__main__':
    if len(sys.argv) >= 2:
        # Retrieve target interface
        interface = sys.argv[1]

        try:
            # Create the WHAD Device
            dev = WhadDevice.create(interface)

            # Create the sniffer ANT connector
            sniffer = Sniffer(dev)

            # Configure the sniffer
            sniffer.network_key =  ANT_PLUS_NETWORK_KEY
            sniffer.channel = 57
            sniffer.device_number = 8130
            sniffer.device_type = 0
            sniffer.transmission_type = 0

            sniffer.start()

            # Iterate over received packets            
            for i in sniffer.sniff():
                print(repr(i))

        except (KeyboardInterrupt, SystemExit):
            dev.close()

        except WhadDeviceNotFound:
            print('[e] Device not found')
            exit(1)
    else:
        print('Usage: %s [device]' % sys.argv[0])
