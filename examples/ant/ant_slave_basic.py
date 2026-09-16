from whad.ant import Slave
from whad.ant.stack.app.profiles import AntProfile
from whad.scapy.layers.ant import ANT_Hdr
from whad.ant.channel import ChannelDirection
from whad.ant.crypto import ANT_PLUS_NETWORK_KEY
from whad.device import WhadDevice
from whad.exceptions import WhadDeviceNotFound
import sys

from time import sleep

class MyProfile(AntProfile):


    DEVICE_NUMBER = 1234
    DEVICE_TYPE = 1
    TRANSMISSION_TYPE = 1
    CHANNEL_PERIOD = 8070
    SEARCH_TIMEOUT = 0
    DEFAULT_RF_CHANNEL = 50
    NETWORK_KEY = ANT_PLUS_NETWORK_KEY    

    def on_broadcast(self, broadcast):
        print("Received broadcast: ")
        print(repr(broadcast))

    def on_ack_burst(self, ack_burst):
        print("Received ack / burst: ")
        print(repr(ack_burst))
        
if __name__ == '__main__':
    if len(sys.argv) >= 2:
        # Retrieve target interface
        interface = sys.argv[1]

        try:
            profile = MyProfile()
            # Create the WHAD Device
            dev = WhadDevice.create(interface)

            # Create the slave ANT connector
            slave = Slave(dev, profile=profile)
            profile.start()
            
            channel = slave.search_channel()
            
            print("Available channels: ", slave.list_channels())
            print("Available networks: ", slave.list_networks())
            
            while channel.is_opened():
                # Transmit burst packet
                profile.burst("B" * 20)
                input()


            
        except (KeyboardInterrupt, SystemExit):
            dev.close()

        except WhadDeviceNotFound:
            print('[e] Device not found')
            exit(1)
    else:
        print('Usage: %s [device]' % sys.argv[0])
