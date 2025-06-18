"""
WHAD default device connector module.

This module provides a default connector class `WhadDeviceConnector` that
implements all the basic features of a device connector.
"""

from whad.hw import Interface, IfaceEvt, Disconnected, MessageReceived, Connector, \
    Event, LockedConnector, WhadDeviceConnector
