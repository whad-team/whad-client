from whad.device import WhadDevice
from whad.btmesh.connector.sniffer import BTMeshSniffer
from whad.exceptions import WhadDeviceNotFound
import sys


if __name__ == "__main__":
    if len(sys.argv) >= 2:
        # Retrieve target interface
        interface = sys.argv[1]

        # Connect to target device and performs discovery
        try:
            dev = WhadDevice.create(interface)
            sniffer = BTMeshSniffer(dev)
            sniffer.configure()
            sniffer.start()
            print("Sniffer started")

            for pkt in sniffer.sniff(timeout=30):
                pkt.show()
                print(pkt.metadata)

        except (KeyboardInterrupt, SystemExit):
            dev.close()

        except WhadDeviceNotFound:
            print("[e] Device not found")
            exit(1)
    else:
        print("Usage: %s [device]" % sys.argv[0])
