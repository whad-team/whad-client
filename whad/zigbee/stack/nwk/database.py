from whad.dot15d4.stack.database import Dot15d4Database
from whad.zigbee.stack.nwk.neighbors import NWKNeighborTable

class NWKIB(Dot15d4Database):
    """
    ZigBee NWKIB Database of attributes.
    """

    def reset(self):
        """
        Reset the NWKIB database to its default value.
        """
        self.nwkSequenceNumber = 0
        #self.nwkPassiveAckTimeout = None
        self.nwkMaxBroadcastRetries = 3
        #self.nwkMaxChildren = None
        self.nwkMaxDepth = 30 # ?
        #self.nwkMaxRouters = None
        self.nwkNeighborTable = NWKNeighborTable()
        #self.nwkNetworkBroadcastDeliveryTime = None
        self.nwkReportConstantCost = 0
        self.nwkRouteTable = []
        self.nwkSymLink = False
        self.nwkCapabilityInformation = 0
        self.nwkAddrAlloc = 0
        self.nwkUseTreeRouting = True
        self.nwkManagerAddr = 0
        self.nwkMaxSourceRoute = 0xc
        self.nwkUpdateId = 0
        self.nwkNetworkAddress = 0xFFFF
        self.nwkStackProfile = None
        self.nwkExtendedPANID = 0x0000000000000000
        self.nwkPANId = 0xFFFF
        self.nwkIeeeAddress = 0x6055f90000f714e4
        self.nwkLeaveRequestAllowed = True
        self.nwkTxTotal = 0

        self.nwkStackProfile = 3
        self.nwkcProtocolVersion = 3

        self.nwkSecurityLevel = 0
        self.nwkSecurityMaterialSet = []
        self.nwkActiveKeySeqNumber = 0
        self.nwkSecureAllFrames = False
        self.nwkAllFresh = False
        self.nwkLinkStatusPeriod = 0x0f
        self.nwkRouterAgeLimit = 3

        self.nwkParentInformation = 0
        self.nwkCapabilityInformation = None
        self.nwkAddressMap = {}

        self.nwkUseMulticast = True
