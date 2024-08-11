from dataclasses import dataclass
from whad.ble.sniffing import ConnectionConfiguration


@dataclass
class InjectionConfiguration:
    """
    Configuration for the Bluetooth Low Energy injector.

    :param inject_to_master: inject packet to master in a synchronized connection
    :param inject_to_slave: inject packet to slave in a synchronized connection
    :param raw: inject a packet directly
    :param synchronize: synchronize before injection (s)
    :param active_connection: enable and configure existing connection synchronization
    :param channel: select the channel to sniff (c)
    :param filter: display only the packets matching the filter BD address (m)
    """
    raw : bool = False
    inject_to_slave : bool = False
    inject_to_master : bool = False
    synchronize : bool = False
    active_connection : ConnectionConfiguration = None
    channel : int = None
    filter : str = "FF:FF:FF:FF:FF:FF"
