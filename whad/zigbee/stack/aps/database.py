from whad.dot15d4.stack.database import Dot15d4Database
from whad.zigbee.stack.aps.security import APSKeyPairSet

class APSIB(Dot15d4Database):
    """
    ZigBee APSIB Database of attributes.
    """
    def reset(self):
        self.apsDeviceKeyPairSet = APSKeyPairSet(
            preinstalled_keys=[
                bytes.fromhex("814286865dc1c8b2c8cbc52e5d65d1b8"),
                b"ZigBeeAlliance09"
            ]
        )
        self.apsTrustCenterAddress = None
        self.apsSecurityTimeOutPeriod = None
        self.trustCenterPolicies = None

        self.apsDesignatedCoordinator = False
        self.apsChannelMask = 0x7fff800
        self.apsUseExtendedPANID = 0x0000000000000000
        self.apsUseInsecureJoin = False

        self.apsNonmemberRadius = 7
        self.apsCounter = 0
        self.apsUseChannel = None
