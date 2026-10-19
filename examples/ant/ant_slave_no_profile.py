from whad.ant import Slave
from whad.ant.stack.app.profiles import AntProfile
from whad.scapy.layers.ant import ANT_Hdr
from whad.ant.channel import ChannelDirection
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

            # Create the slave ANT connector
            slave = Slave(dev)
            slave.start()
            channel = slave.search_channel(
                device_number = 0xABCD, 
                device_type = 1,
                transmission_type = 1,
                channel_period = 8070,
                rf_channel = 57, 
                network_key = ANT_PLUS_NETWORK_KEY,
                unidirectional = False, 
                shared = False, 
                background = False
            )
            
            print("Available channels: ", slave.list_channels())
            print("Available networks: ", slave.list_networks())
            if channel is not None:
                channel.on_broadcast = lambda p:p.show()
                channel.on_ack_burst = lambda p:p.show()
                while channel.is_opened():
                    # Transmit burst packet
                    channel.burst(b"B" * 20)
                    input()


            
        except (KeyboardInterrupt, SystemExit):
            dev.close()

        except WhadDeviceNotFound:
            print('[e] Device not found')
            exit(1)
    else:
        print('Usage: %s [device]' % sys.argv[0])
