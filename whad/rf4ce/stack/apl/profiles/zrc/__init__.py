from whad.rf4ce.stack.apl.profile import APLProfile

class ZRCProfile(APLProfile):
    """
    APL service implementing the Zigbee Remote Control (ZRC) Profile.
    """

    def __init__(self):
        super().__init__(name="zrc", profile_id=0x01)


    def on_data(self, npdu, pairing_reference, vendor_id, link_quality, rx_flags):
        """
        Callback processing incoming data for the profile.
        """
        pass
