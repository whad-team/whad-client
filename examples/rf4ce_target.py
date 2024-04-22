from whad.device import WhadDevice
from whad.rf4ce import Target
from whad.dot15d4.address import Dot15d4Address
from whad.common.monitors import WiresharkMonitor
from whad.exceptions import WhadDeviceNotFound
from scapy.compat import raw
from whad.scapy.layers.rf4ce import RF4CE_Vendor_MSO_Hdr, \
    RF4CE_Vendor_MSO_Get_Attribute_Response, RF4CE_Vendor_MSO_Check_Validation_Response

from random import randint
import sys
import logging

def show(pkt):
    if hasattr(pkt, "metadata"):
        print(pkt.metadata, bytes(pkt).hex(), repr(pkt))

if __name__ == '__main__':
    if len(sys.argv) >= 2:
        # Retrieve target interface

        interface = sys.argv[1]

        try:
            monitor = WiresharkMonitor()

            dev = WhadDevice.create(interface)

            target = Target(dev)
            target.set_channel(15)
            monitor.attach(target)
            monitor.start()
            target.start()

            target.auto_discovery()
            input()
            # temp: let's start a pairing resp here
            target.stack.get_layer('nwk').get_service('management').pair_response(
                pan_id=0x1234,
                destination_address=Dot15d4Address("02:70:0D:35:AE:D1:19:C4").value,
                application_capability=0,
                accept=True,
                list_of_device_types=[9],
                list_of_profiles=[192],
                pairing_reference=0
            )
            input()
            while True:
                
                input()
                '''
                print('success')
                while not target.stack.get_layer('nwk').get_service('data').data(
                    RF4CE_Vendor_MSO_Hdr()/RF4CE_Vendor_MSO_Check_Validation_Response(
                        check_validation_status=0
                    ),
                    pairing_reference = 0,
                    profile_id = 0xc0,
                    vendor_id = 4417,
                    tx_options = (
                     0 | (1 << 1) | (0 << 2) | (1 << 3) | (0 << 4)| (0 << 5) | (1 << 6)
                    )
                ):
                    pass

                input()
                '''
            #target.discovery_response(True, destination_address="C4:19:D1:AE:35:0D:70:02")
        except (KeyboardInterrupt, SystemExit):
            dev.close()

        except WhadDeviceNotFound:
            print('[e] Device not found')
            exit(1)
    else:
        print('Usage: %s [device]' % sys.argv[0])
