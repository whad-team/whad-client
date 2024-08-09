from dataclasses import dataclass, field

@dataclass
class InjectionConfiguration:
    """
    Configuration for injecting into ZigBee communication.

    :param channel: select the channel to use for injection (c)

    """
    channel : int = None
