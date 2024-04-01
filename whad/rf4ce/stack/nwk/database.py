from whad.dot15d4.stack.database import Dot15d4Database

class NWKIB(Dot15d4Database):
    """
    RF4CE NWKIB Database of attributes.
    """

    def reset(self):
        """
        Reset the NWKIB database to its default value.
        """
        self.nwkActivePeriod = 0x00041a
        self.nwkBaseChannel = 15
        self.nwkDiscoveryLQIThreshold = 0xFF
        self.nwkDiscoveryRepetitionInterval = 0x0030d4
        self.nwkDutyCycle = 0x000000
        self.nwkFrameCounter = 0x00000001
        self.nwkIndicateDiscoveryRequests = False
        self.nwkInPowerSave = False
        self.nwkPairingTable = []
        self.nwkMaxDiscoveryRepetitions = 1
        self.nwkMaxFirstAttemptCSMABackoffs = 4
        self.nwkMaxFirstAttemptFrameRetries = 3
        self.nwkMaxReportedNodeDescriptors = 3
        self.nwkResponseWaitTime = 0x00186a
        self.nwkScanDuration = 6
        self.nwkUserString = "WhadRF4CEStack"
