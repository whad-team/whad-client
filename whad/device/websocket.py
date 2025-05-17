"""This module provides a WebSocketDevice class that can be used with a WhadDeviceConnector
to interact with a WebSocket connected to a Whad-enable device. This class implements
a WebSocket client that connects to a remote device through a WebSocket.

It also provides a dedicated connector to be used as a WebSocket server.

This class handles device connection, disconnection and read/write operations. All the
parsing magic is performed in our WhadDevice class.
"""
