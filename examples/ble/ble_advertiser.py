import sys
import logging
from whad.hub.ble import AdvType
from whad.ble.connector.advertiser import Advertiser
from whad.ble.profile.advdata import AdvCompleteLocalName, AdvDataFieldList, AdvFlagsField
from whad.device import WhadDevice

logging.basicConfig(level=logging.DEBUG)

if len(sys.argv) >= 2:
    # Create the connector & the profile
    adv = Advertiser(
        WhadDevice.create(sys.argv[1]),
        AdvDataFieldList(
            AdvCompleteLocalName(b'TestMe!'),
            AdvFlagsField()
        ),
        None,
        adv_type=AdvType.ADV_NONCONN_IND,
        inter_min=0x20, inter_max=0x40
    )
    adv.start()
    print("Device is now advertising ...")

    # Wait for a key press
    try:
        print("Press enter to update device name.")
        input()
        adv.update(
            adv_data=AdvDataFieldList(
                AdvCompleteLocalName(b'Updated'),
                AdvFlagsField()
            ),
        )
        input()
        adv.close()
    except KeyboardInterrupt:
        adv.close()

else:
    print("Usage:", sys.argv[0], "<interface>")
