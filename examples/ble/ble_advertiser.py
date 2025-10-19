import sys
import logging
from whad.hub.ble import AdvType
from whad.ble.connector.advertiser import Advertiser
from whad.ble.profile.advdata import AdvCompleteLocalName, AdvDataFieldList, AdvFlagsField
from whad.device import WhadDevice

if len(sys.argv) >= 2:
    # Create the connector & the profile
    advertiser = Advertiser(
        WhadDevice.create(sys.argv[1]),
        AdvDataFieldList(
            AdvCompleteLocalName(b'Advertising demo'),
            AdvFlagsField()
        ),
        None,
        adv_type=AdvType.ADV_NONCONN_IND,
        interval=(0x20, 0x40)
    )
    advertiser.start()
    print("Device is now advertising ...")

    # Wait for a key press
    try:
        print("Press enter to update device name.")
        input()
        advertiser.update(
            adv_data=AdvDataFieldList(
                AdvCompleteLocalName(b'Updated'),
                AdvFlagsField()
            ),
        )
        print("Device name has been changed to 'Updated'.\nPress enter to stop advertising.")
        input()
        advertiser.close()
    except KeyboardInterrupt:
        advertiser.close()

else:
    print("Usage:", sys.argv[0], "<interface>")
