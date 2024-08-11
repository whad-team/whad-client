from whad.zigbee import Sniffer
from whad.device import WhadDevice
from whad.exceptions import WhadDeviceNotFound
from whad.common.monitors import PcapWriterMonitor, WiresharkMonitor
from time import time,sleep
import sys

if __name__ == '__main__':
    if len(sys.argv) >= 2:
        # Retrieve target interface
        interface = sys.argv[1]

        try:
            # Create the WHAD device
            dev = WhadDevice.create(interface)
            # Instantiate a sniffer
            sniffer = Sniffer(dev)

            # Configure & start a wireshark monitor
            monitor = WiresharkMonitor()
            monitor.attach(sniffer)
            monitor.start()

            # Configure the channel
            sniffer.channel = 25

            # Iterate over the received packets
            sniffer.start()
            for i in sniffer.sniff():
                print(repr(i))



        except (KeyboardInterrupt, SystemExit):
            monitor.detach()
            monitor.close()
            dev.close()

        except WhadDeviceNotFound:
            print('[e] Device not found')
            exit(1)
    else:
        print('Usage: %s [device]' % sys.argv[0])
