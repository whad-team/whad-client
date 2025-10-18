"""WHAD generic injection configuration for BTMesh.

This module defines the :class:`whad.btmesh.injecting.InjectionConfiguration`
used by `winject` to determine the parameters required for packet injection.
"""

from dataclasses import dataclass
from whad.ble.sniffing import ConnectionConfiguration


@dataclass
class InjectionConfiguration:
    """
    Configuration for the BTMesh injector.

    :param channel: select the channel to sniff and send (c)
    """

    channel: int = None
