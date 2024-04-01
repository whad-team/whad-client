from whad.dot15d4.stack import Dot15d4Stack
from whad.zigbee.stack.nwk import NWKManager

Dot15d4Stack.add(NWKManager)
print(Dot15d4Stack.export())
