from dataclasses import dataclass

@dataclass
class InjectionConfiguration:
    """Configuration for injecting into WirelessHART communication.

    :param channel: select the channel to use for injection (c)
    """
    channel: int = None