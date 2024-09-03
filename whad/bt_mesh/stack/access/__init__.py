"""
Accces Layer

Manages which Element, Model gets a Message and forwards it to the Model handler.
Manages checks on whether or not the conditions of a message to a Model in an Element are ok (which key is used, addr...)
Allows other layers to internally fetch State data from Foundation Models (SAR informations, keys, ...)
"""

import logging
from whad.common.stack import Layer, alias, source
from whad.bt_mesh.stack.utils import MeshMessageContext
from whad.bt_mesh.models import Element


logger = logging.getLogger(__name__)


class CompositionData0(object):
    """
    Composition Data page 0 (Mesh PRT Spec Section 4.2.2.1).
    Contain general information about the node
    """

    def __init__(
        self,
        cid=0x0059,
        pid=0x01,
        vid=0x02,
        crpl=100,
        is_relay=False,
        is_proxy=False,
        is_friend=False,
        is_lpn=False,
    ):
        """
        Initializes the Comoposition Data 0 object

        :param cid: Company ID
        :type cid: Int
        :param pid: Product ID
        :type pid: int
        :param vid: Vendor ID
        :type vid: int
        :param crpl: Max number of replay protection entries
        :type crpl: int
        :param is_relay: Does this node support replay feature ?
        :type is_relay: boolean
        :param is_proxy: Does this node support proxy feature ?
        :type is_proxy: boolean
        :param is_friend: Does this node support friend feature ?
        :type is_friend: boolean
        :param is_lpn: Does this node support Low Power Node feature ?
        :type is_lpn: boolean
        """
        self.cid = cid
        self.pid = pid
        self.vid = vid
        self.crpl = crpl
        self.is_relay = is_relay
        self.is_proxy = is_proxy
        self.is_friend = is_friend
        self.is_lpn = is_lpn

        # contain tuples of (loc, Element).
        self.elements = []

    def add_element(self, element: Element, loc):
        """
        Adds an element to the Composition Data page 0.

        :param element: The element to add
        :type element: Element
        :param loc: Location Descriptor, defaults to 0
        :type loc: int, optional
        """
        self.elements.append((loc, Element))

    def get_composition_page0(self):
        """
        Retrieves the correctly formated Composition Page 0 for exchange (Data in a
        Config Composition Data Status, Mesh PRT spec Section 4.3.2.5)
        """
        data = b""
        data = self.cid.to_bytes(2, "little")
        data += self.pid.to_bytes(2, "little")
        data += self.vid.to_bytes(2, "little")
        data += self.crpl.to_bytes(2, "little")
        data += (
            int(self.is_relay)
            | (int(self.is_proxy) << 1)
            | (int(self.is_friend) << 2)
            | (int(self.is_lpn) << 3)
        ).to_bytes(2, "little")
        for loc,element in self.elements:
            data += loc.to_bytes(2, "little")
            data += loc.to_bytes("")


@alias("access")
class AccessLayer(Layer):
    def __init__(self, options={}):
        """
        AccessLayer. One for all the networks.
        """

        super().__init__(options=options)

        # List of elements of the Device. Addr -> element instance
        self.state.elements = {}

    def config_primary_element(self, unicast_addr):
        """
        Configures the primary element of the device with necessary foundation models

        :param unicast_addr: [TODO:description]
        :type unicast_addr: [TODO:type]
        """
