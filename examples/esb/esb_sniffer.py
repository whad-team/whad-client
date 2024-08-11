from whad.esb import Sniffer
from whad.device import WhadDevice
from whad.exceptions import WhadDeviceNotFound
from whad.scapy.layers.esb import ESB_Hdr
from scapy.compat import raw
import sys

if __name__ == '__main__':
    if len(sys.argv) >= 2:
        # Retrieve target interface
        interface = sys.argv[1]

        try:
            # Create the WHAD Device
            dev = WhadDevice.create(interface)

            # Create the sniffer connector
            sniffer = Sniffer(dev)

            # Configure channel & adress
            sniffer.address = "ca:e9:06:ec:a4"
            sniffer.channel = 41
            # Start the sniffer and iterate over packets
            sniffer.start()
            for pkt in sniffer.sniff():
                print(repr(pkt))

        except (KeyboardInterrupt, SystemExit):
            dev.close()

        except WhadDeviceNotFound:
            print('[e] Device not found')
            exit(1)
    else:
        print('Usage: %s [device]' % sys.argv[0])
