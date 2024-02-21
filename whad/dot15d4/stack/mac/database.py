from whad.dot15d4.stack.database import Dot15d4Database

class MACPIB(Dot15d4Database):
    """
    802.15.4 MAC PIB Database of attributes.
    """

    def reset(self):
        """
        Reset the PIB database to its default value.
        """
        self.macExtendedAddress = 0xababababcdcdcdcd
        self.macAssociatedPanCoord = False
        self.macAssociationPermit = False
        self.macAutoRequest = False
        self.macDataSequenceNumber = 0
        self.macBeaconSequenceNumber = 0
        self.macBeaconOrder = 15
        self.macRxOnWhenIdle = True
        self.macPanId = 0xFFFF
        self.macShortAddress = 0xFFFF
        self.macCoordShortAddress = 0
        self.macCoordExtendedAddress = 0
        self.macPromiscuousMode = False
        self.macImplicitBroadcast = False
        self.macResponseWaitTime = 32
