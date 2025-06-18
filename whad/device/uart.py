"""This module provides a UartIface class that can be used with a WhadDeviceConnector
to interact with a WHAD-enable firmware device that uses UART as its transport layer.

This class handles device connection, disconnection and read/write operations. All the
parsing magic is performed in our WhadDevice class.
"""

from whad.hw.uart import Uart as UartDevice, get_port_info, SUPPORTED_UART_DEVICES

__all__ = [
    "UartDevice",
    "get_port_info",
    "SUPPORTED_UART_DEVICES"
]