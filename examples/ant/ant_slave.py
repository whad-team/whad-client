from whad.ant import ANT, Slave
from whad.scapy.layers.ant import ANT_Hdr
from whad.ant.channel import ChannelDirection
from whad.ant.crypto import ANT_PLUS_NETWORK_KEY
from whad.device import WhadDevice
from whad.exceptions import WhadDeviceNotFound
from whad.ant.stack.app.profiles.antplus.hrm import HeartRateDisplay
import sys

from time import sleep

if __name__ == '__main__':
    if len(sys.argv) >= 2:
        # Retrieve target interface
        interface = sys.argv[1]

        try:
            # Create the WHAD Device
            dev = WhadDevice.create(interface)

            # Create the slave ANT connector
            profile = HeartRateDisplay()

            slave = Slave(dev)
            channel = slave.search_channel(0, 120, 1)
            channel.app.set_profile(profile)
            print("Chan:", channel)

            base_heart_rate = None
            while True:
                if base_heart_rate != profile.computed_heart_rate:
                    base_heart_rate = profile.computed_heart_rate
                    print(profile.computed_heart_rate, profile.heart_beat_count)
            # Start the slave and iterate over packets

            while True:
                input()
                print(slave.stack.get_layer('ll').broadcast(0,b"SLAVE"))

                input()
                print(slave.stack.get_layer('ll').ack(0,b"SLAVEACK"))

                input()
                print(slave.stack.get_layer('ll').burst(0,b"SLAVEBURSTBURSTBURSTBURS"))

        except (KeyboardInterrupt, SystemExit):
            dev.close()

        except WhadDeviceNotFound:
            print('[e] Device not found')
            exit(1)
    else:
        print('Usage: %s [device]' % sys.argv[0])
