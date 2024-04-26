from whad.dot15d4.stack.database import Dot15d4Database

class APLIB(Dot15d4Database):
    """
    RF4CE APLIB Database of attributes.
    """

    def reset(self):
        """
        Reset the APL database to its default value.
        """
        self.aplcMaxKeyRepeatInterval = 120 # (ms)
        self.aplcMaxRIBAttributeSize = 92
        self.aplcResponseIdleTime = 50 # (ms)
        self.aplcBlackOutTime = 100 # (ms)
        self.aplcMinKeyExchangeTransferCount = 3

        self.aplKeyRepeatInterval = 0.5 * self.aplcMaxKeyRepeatInterval
        self.aplKeyRepeatWaitTime = self.aplcMaxKeyRepeatInterval
        self.aplResponseWaitTime = 0x186a # (symbols ~ 16us, default = 100ms)
        self.aplMaxPairingCandidates = 3
        self.aplLinkLostWaitTime = 0x02710 # (symbols ~ 16us, default = 10000ms)
        self.aplAutoCheckValidationPeriod = 0x01f4 # (symbols ~ 16us, default = 500ms)
        self.aplValidationWaitTime = 0x0 # (infinity, or 0x7530 symbols / 30000 ms for button based validation)
        self.aplValidationInitialWatchdogTime = 0x1f40 # (symbols ~ 16us, default = 8000ms or 0 (infinity) for button based validation)
        self.aplUserString = "WHAD"
        self.aplKeyExchangeTransferCount = 4

        self.aplDeviceType = 9
