from dataclasses import dataclass, field

@dataclass
class InjectionConfiguration:
    """
    Configuration for injecting in a Logitech Unifying communication.

    :param channel: select the channel to use (c)
    :param address: provide address to use (f)
    :param synchronize: enable synchronization (s)
    """
    channel : int = 0
    address : str = None
    synchronize : bool = False
