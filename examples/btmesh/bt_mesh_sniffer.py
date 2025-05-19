from whad.device import WhadDevice
from whad.btmesh.connectors.sniffer import BTMeshSniffer
from whad.exceptions import WhadDeviceNotFound
import sys


if __name__ == "__main__":
    if len(sys.argv) >= 2:
        # Retrieve target interface
        interface = sys.argv[1]

        # Connect to target device and performs discovery
        try:
            dev = WhadDevice.create(interface)
            sniffer = BTMeshSniffer(
                dev, net_key=bytes.fromhex("f7a2a44f8e8a8029064f173ddc1e2b00")
            )
            sniffer.configure(advertisements=True, connection=False)
            sniffer.start()

        except (KeyboardInterrupt, SystemExit):
            dev.close()

        except WhadDeviceNotFound:
            print("[e] Device not found")
            exit(1)
    else:
        print("Usage: %s [device]" % sys.argv[0])
