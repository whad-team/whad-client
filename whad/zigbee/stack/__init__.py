from .mac import MACManager

"""
Pythonic ZigBee stack
"""
class ZigbeeStack:
    """
    This class holds the main components of a (hackable) ZigBee stack:

    - the Medium Access Control Manager (MAC - defined in 802.15.4 specification)
    - the Network manager (NWK)
    - the Application manager (APS)

    The Medium Access Control manager handles all the low-level operations:
    - 802.15.4 management control (handles beaconing, frame validation, timeslots and associations)
    - 802.15.4 data (forward to upper layer, i.e. NWK)
    """
    def __init__(self, connector):
        """
        Create an instance of ZigbeeStack associated with a specific connector. This
        connector provides the transport layer.

        :param WhadDeviceConnector connector: Connector to use with this stack.
        """
        self.__connector = connector

        # Instanciate all the required controllers
        self.__mac = MACManager(self)



    #############################
    # Incoming messages
    #############################


    ############################
    # Interact
    ############################
