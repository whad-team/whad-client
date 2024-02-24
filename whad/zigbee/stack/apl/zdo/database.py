from whad.zigbee.stack.apl.zdo.descriptors import NodeDescriptor
from whad.dot15d4.stack.database import Dot15d4Database

class ConfigurationDatabase(Dot15d4Database):
    """
    ZigBee Device Objects configuration database.
    """
    def reset(self):
        self.configNodeDescriptor = NodeDescriptor()
        self.configNWKScanAttempts = 5
        self.configNWKTimeBetweenScans = 0xc35

        self.allowsJoins = True
        self.useWhiteList = False
        self.allowInstallCodes = False
        self.updateTrustCenterLinkKeys = True
        self.allowRejoins = False
        self.allowTrustCenterLinkKeyRequests = 0x01
        self.networkKeyUpdatePeriod = 0
        self.networkkeyUpdateMethod = 0
        self.allowApplicationKeyRequests = 1
        self.applicationKeyRequestList = []
        self.allowRemoteTcPolicyChange = False
