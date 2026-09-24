from whad.ant import ANT, Slave
from whad.scapy.layers.ant import ANT_Hdr
from whad.ant.crypto import ANT_PLUS_NETWORK_KEY
from whad.device import WhadDevice
from whad.exceptions import WhadDeviceNotFound
from whad.ant.stack.app.profiles.antplus.hrm import HeartRateDisplay

import sys
import time

if __name__ == '__main__':
    if len(sys.argv) >= 2:
        # Retrieve target interface
        interface = sys.argv[1]

        try:
            # Create the WHAD Device
            dev = WhadDevice.create(interface)

            # Create the slave ANT connector
            profile = HeartRateDisplay()

            slave = Slave(dev, profile=profile)
            profile.start()
            
            channel = slave.search_channel()
            if channel is not None:
                for heart_rate in profile.heart_rates():
                    print(heart_rate)

        except (KeyboardInterrupt, SystemExit):
            dev.close()

        except WhadDeviceNotFound:
            print('[e] Device not found')
            exit(1)
    else:
        print('Usage: %s [device]' % sys.argv[0])