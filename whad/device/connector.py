"""
WHAD default device connector module.

This module provides a default connector class `WhadDeviceConnector` that
implements all the basic features of a device connector.
"""
import logging
import contextlib
from time import time
from queue import Queue, Empty
from threading import Thread, Lock, Event as ThreadEvent
from typing import Generator, Callable, Union, List

from whad.helpers import message_filter
from whad.hub import ProtocolHub
from whad.hub.message import AbstractPacket, AbstractEvent, HubMessage
from whad.hub.generic.cmdresult import CommandResult, Success
from whad.exceptions import WhadDeviceError, WhadDeviceDisconnected, \
    RequiredImplementation, UnsupportedDomain

from whad.hw import Interface, IfaceEvt, Disconnected, MessageReceived, Connector, \
    Event, LockedConnector, WhadDeviceConnector
