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
