from dataclasses import dataclass
from whad.ble.sniffing import ConnectionConfiguration


@dataclass
class InjectionConfiguration:
    """
    Configuration for the Bluetooth Low Energy injector.

    :param synchronize: synchronize before injection (s)
    :param active_connection: enable and configure existing connection synchronization
    :param channel: select the channel to sniff (c)
    :param filter: display only the packets matching the filter BD address (m)
    """
    synchronize : bool = False
    active_connection : ConnectionConfiguration = None
    channel : int = 37
    filter : str = "FF:FF:FF:FF:FF:FF"
