from whad.esb import ESB, PRX, PTX
from whad.device import WhadDevice
from whad.exceptions import WhadDeviceNotFound
from whad.scapy.layers.esb import ESB_Hdr
from scapy.compat import raw
import sys

def show(pkt):
    if hasattr(pkt, "metadata"):
        print(pkt.metadata, bytes(pkt).hex(), repr(pkt))

if __name__ == '__main__':
    if len(sys.argv) >= 2:
        # Retrieve target interface
        interface = sys.argv[1]

        try:
            # Create the WHAD device
            dev = WhadDevice.create(interface)

            # Instantiate a Primary receiver connector
            connector = PRX(dev)
            # Configure address & channel
            connector.address = "ca:e9:06:ec:a4"
            connector.channel = 5
            connector.start()

            # When a packet is received, display it & prepare a payload for acknowledgements every 5 packets
            for pkt in connector.stream():
                pkt.show()
                if ((bytes(pkt)[3] % 5) == 0):
                    connector.prepare_acknowledgment(b"PRX")

            connector.stop()

        except (KeyboardInterrupt, SystemExit):
            dev.close()

        except WhadDeviceNotFound:
            print('[e] Device not found')
            exit(1)
    else:
        print('Usage: %s [device]' % sys.argv[0])
