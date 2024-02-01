from whad.zigbee.stack.manager import Dot15d4Manager
from whad.common.stack import alias, source, state # state may not be necessary ?
import logging

logger = logging.getLogger(__name__)


@alias('apl')
class APLManager(Dot15d4Manager):
    """
    This class implements the Zigbee Application layer manager (APL).
    It exposes Zigbee Device Object and Application Object.

    Note: this component is a bit particular in ZigBee stack since it
    implements Applications instead of Services. The design adopted here
    keeps the Manager as Layer / Entry point and override Services by Applications.
    We also introduce a dictionnary mapping endpoints to applications and
    methods facilitating applications selection & management.
    """

    def init(self):
        """
        Initialize the APL layer.
        """
        # Initialize Endpoints
        self.endpoints = {}
