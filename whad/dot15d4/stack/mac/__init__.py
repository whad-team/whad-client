from whad.dot15d4.stack.manager import Dot15d4Manager
from whad.dot15d4.stack.service import Dot15d4Service
from whad.dot15d4.stack.mac.database import MACPIB
from whad.dot15d4.stack.mac.exceptions import MACTimeoutException, MACAssociationFailure
from whad.common.stack import Layer, alias, source, state


class MACService(Dot15d4Service):
    """
    This class represents a MAC service, exposing a standardized API.
    """
    def __init__(self, manager, name=None):
        super().__init__(
            manager,
            name=name,
            timeout_exception_class=MACTimeoutException
        )

class MACDataService(MACService):
    pass


class MACManagementService(MACService):
    """
    MAC service processing Management packets.
    """
    pass

@state(MACPIB)
@alias('mac')
class MACManager(Dot15d4Manager):

    def init(self):
        self.add_service("management", Dot15d4ManagementService(self))
        self.add_service("data", None)

    def show(self):
        #print(self.upper_layer.alias, self.lower_layer.alias)
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



#MACManager.add(NWKManager)
