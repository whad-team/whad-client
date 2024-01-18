from whad.dot15d4.stack.manager import Dot15d4Manager
from whad.dot15d4.stack.database import Dot15d4Database
from whad.dot15d4.stack.service import Dot15d4Service
from whad.common.stack import Layer, alias, source, state


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
        self.macPanId = 0xFFFF
        self.macShortAddress = 0xFFFF
        self.macCoordShortAddress = 0
        self.macCoordExtendedAddress = 0
        self.macPromiscuousMode = False
        self.macImplicitBroadcast = False
        self.macResponseWaitTime = 32



class Dot15d4ManagementService(Dot15d4Service):
    @Dot15d4Service.indication("TEST")
    def indicate_test(self):
        return (b"\x01\x02", {
            "a" : 1 ,
            "b" : 2,
            "c" : 3
        })

@state(MACPIB)
@alias('mac')
class MACManager(Dot15d4Manager):

    def init(self):
        self.add_service("management", Dot15d4ManagementService(self))
        self.add_service("data", None)

    def show(self):
        print(self.upper_layer.alias, self.lower_layer.alias)
        print(self.database)
        print(self.database.get("macResponseWaitTime"))
        self.get_service('management').indicate_test()


@alias('nwk')
class NWKManager(Dot15d4Manager):

    @source('mac', 'TEST')
    def on_test(self, pdu, a, b, c):
        print(pdu)
        print("a = ", a)
        print("b = ", b)
        print("c = ", c)



MACManager.add(NWKManager)
