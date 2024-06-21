"""LoRaWAN application module

This module provides a main class, `LWApplication` that can be used to implement LoRaWAN compatible applications
that will run on an emulated LoRaWAN gateway. Applications must inherit from this base class.

The `LWApplication provides some useful features:
- it supports over-the-air device activation and keeps track of devices that joined the network ;
- it also supports activated by personalization (ABP) devices as well ;
- it provides a set of callbacks that can be overriden by the application

Registered nodes state is kept in a JSON file named by default on the name of the application's EUI, and stored in
the working directory. This file is managed by the `LWNodeRegistry` class.
"""
import sys
import json
from os import unlink
from os.path import exists, isfile
from binascii import hexlify, unhexlify

# Including type hint Iterator based on python version
if sys.version_info[0] == 3 and sys.version_info[1] >= 9:
    from collections.abc import Iterator
else:
    from typing import Iterator

from whad.lorawan.exceptions import InvalidNodeRegistryError

import logging
logger = logging.getLogger(__name__)

class LWNode(object):
    """LoRaWAN node
    """

    def __init__(self, dev_eui, dev_addr=0, appskey=b'', nwkskey=b'', upcount=0, dncount=0):
        """Initialize a LoRaWAN node (device)

        :param dev_eui: Device extended unique identifier (in the following format: `00:11:22:33:44:55:66:77`)
        :type dev_eui: str
        :param dev_addr: Device address on the network
        :type dev_addr: int, optional
        :param appskey: Device application session key
        :type appskey: bytes, optional
        :param nwkskey: Device network session encryption key
        :type nwkskey: bytes, optional
        :param upcount: Device current uplink frame counter (default: 0)
        :type upcount: int, optional
        :param dncount: Device current downlink frame counter (default: 0)
        :type dncount: int, optional
        """
        self.__dev_eui = str(dev_eui).lower()
        self.__dev_addr = dev_addr
        self.__appskey = appskey
        self.__nwkskey = nwkskey
        self.__upcount = upcount
        self.__dncount = dncount

    def __repr__(self):
        return 'LWNode(eui:%s, address:%s, appskey:%s, nwkskey:%s, uplink_count:%d, downlink_count:%d)' % (
            self.dev_eui,
            self.dev_addr,
            hexlify(self.__appskey).decode('ascii') if self.__appskey is not None else None,
            hexlify(self.__nwkskey).decode('ascii') if self.__nwkskey is not None else None,
            self.__upcount,
            self.__dncount
        )

    @property
    def dev_eui(self) -> str:
        """Device EUI getter
        """
        return self.__dev_eui
    
    @property
    def dev_addr(self) -> int:
        """Device network address getter

        :return: Device address
        :rtype: int
        """
        return self.__dev_addr
    
    @property
    def appskey(self) -> bytes:
        """Device application session key getter

        :return: Device application session key
        :rtype: bytes
        """
        return self.__appskey
    
    @property
    def nwkskey(self) -> bytes:
        """Device network session encryption key

        :return: Device network session encryption key
        :rtype: bytes
        """
        return self.__nwkskey
    
    @property
    def upcount(self) -> int:
        """Uplink frame counter getter

        :return: Current device uplink frame counter
        :rtype: int
        """
        return self.__upcount
    
    @upcount.setter
    def upcount(self, value: int):
        """Uplink frame counter setter

        :param value: New uplink frame counter value for the device
        :type value: int
        """
        self.__upcount = value
    
    @property
    def dncount(self) -> int:
        """Downlink frame counter getter

        :return: Current device downlink frame counter
        :rtype: int
        """
        return self.__dncount

    @dncount.setter
    def dncount(self, value: int):
        """Downlink frame counter setter

        :param value: New downlink frame counter value for the device
        :type value: int
        """
        self.__upcount = value

    @property
    def joined(self) -> bool:
        """Check if the device has joined a network

        :return: `True` if the device has joined a network, `False` otherwise.
        :rtype: bool
        """
        return (self.appskey is not None and self.nwkskey is not None and self.dev_addr is not None)

    def inc_up(self):
        """Increment device's uplink frame counter
        """
        self.__upcount = (self.__upcount + 1) & 0xffffffff

    def inc_down(self):
        """Increment device's downlink frame counter
        """
        self.__dncount = (self.__dncount + 1) & 0xffffffff

    def toDict(self) -> dict:
        """Return this node as a dictionary

        :return: Device properties as a dictionary
        :rtype: dict
        """
        return {
            'dev_eui': self.dev_eui,
            'dev_addr': self.dev_addr,
            'appskey': hexlify(self.appskey).decode('ascii'),
            'nwkskey': hexlify(self.nwkskey).decode('ascii'),
            'upcount': self.upcount,
            'dncount': self.dncount
        }
    
    @staticmethod
    def fromJSON(data):
        """Create a `LWNode` instance from a node saved state (JSON).

        :param data: JSON data representing the device state
        :type data: str
        :return: An instance of `LWNode` corresponding to the serialized device state
        :rtype: LWNode
        """
        return LWNode(
            data['dev_eui'],
            data['dev_addr'],
            unhexlify(data['appskey']),
            unhexlify(data['nwkskey']),
            data['upcount'],
            data['dncount']
        )
    

class LWNodeRegistry(object):
    """LoRaWAN node registry.

    This class holds a list of allowed devices EUI and
    associated addresses and encryption keys for persistent
    purpose.

    Data is stored in a flat json file.
    """

    def __init__(self, path:str ='default_node.json'):
        """Load node registry file.

        :param path: Default registry file
        :type path: str
        """
        self.__path = path
        self.__nodes = {}
        if exists(path) and isfile(path):
            try:
                # File exists, load it as json
                with open(path, 'r') as registry:
                    nodes = json.load(registry)

                    # Loop on nodes and load our lookup table
                    for node in nodes:
                        node_ = LWNode.fromJSON(node)
                        self.__nodes[node_.dev_eui] = node_
                    registry.close()
            except IOError as file_err:
                raise InvalidNodeRegistryError(path)
            except Exception as other_err:
                # Oops, error while loading registry. Unlink file.
                logger.error('Error while loading registry file %s, removing file.' % path)
                unlink(path)
        else:
            # File does not exist, create it.
            try:
                self.save()
            except IOError as file_err:
                raise InvalidNodeRegistryError(path)
            
    def add_node(self, node: LWNode):
        """Register a LoRaWAN node.

        :param node: Node to add to this registry
        :type node: LWNode
        """
        if node.dev_eui in self.__nodes:
            logger.warning('Device %s is already present in node registry' % (
                node.dev_eui
            ))
            self.__nodes[node.dev_eui] = node
        else:
            logger.debug('adding node %s' % node)
            self.__nodes[node.dev_eui] = node

    def get_node(self, eui:str = None) -> LWNode:
        """Retrieve node by DEV EUI.

        :param eui: Node EUI
        :type eui: str
        :return: Corresponding device instance if found, `None` if not.
        :rtype: LWNode
        """
        if str(eui) in self.__nodes:
            return self.__nodes[str(eui)]
        else:
            return None

    def iterate(self) -> Iterator[LWNode]:
        """Iterate over registered nodes.
        """
        for dev_eui in self.__nodes:
            yield self.__nodes[dev_eui]

    def save(self):
        """Save registry to file
        """
        try:
            with open(self.__path, 'w') as registry:
                nodes = []
                for node_eui in self.__nodes:
                    nodes.append(self.__nodes[node_eui].toDict())
                json.dump(nodes, registry)
                registry.close()
        except IOError as file_err:
            raise InvalidNodeRegistryError(self.__path)

    
class LWApplication(object):
    """LoRaWAN application class
    """

    def __init__(self, eui=None, key=None, node_db_path=None, devices:[LWNode] = []):
        """Initialize a LoRaWAN application

        :param eui: Application EUI
        :type eui: str
        :param key: Application key in hexadecimal form
        :type key: str
        :param node_db_path: Application database path, default is named <APP_EUI>.json
        :type node_db_path: str
        :param devices: Allowed devices
        :type devices: list
        """
        # Save application EUI and main key
        self.__eui = str(eui).lower()
        self.__key = key

        # Initialize node registry
        if node_db_path is not None:
            self.__registry = LWNodeRegistry(path=node_db_path)
        else:
            self.__registry = LWNodeRegistry(
                path='%s.json' % self.__eui.replace(':','')
            )

        # Load registry with devices
        for device in devices:
            self.__registry.add_node(device)

        # Initialize downlink data buffer
        self.__pending_data = b''

    @property
    def eui(self) -> str:
        """Application EUI getter

        :return: Application EUI
        :rtype: str
        """
        return self.__eui
    
    @property
    def key(self) -> str:
        """Application key getter

        :return: Application key as an hexadecimal string
        :rtype: str
        """
        return self.__key
    
    def nodes(self) -> Iterator[LWNode]:
        """Iterate over registered nodes.
        """
        for node in self.__registry.iterate():
            yield node

    def add_node(self, node: LWNode = None):
        """Dynamically add a node to application registry.

        :param node: Node to add to this application
        :type node: LWNode
        """
        if node is not None:
            self.__registry.add_node(node)

    def stop(self):
        """Stop this application.

        Stopping the application will save the current node registry status into the application state JSON file.
        """
        # Save node registry.
        self.__registry.save()

    def is_authorized(self, dev_eui) -> bool:
        """Determine if device is authorized to join the network.

        This method can be overriden to implement additional checks on device.

        :param dev_eui: Device EUI
        :type dev_eui: EUI
        :return: True if device is authorized, False otherwise
        :rtype: bool
        """
        # Basically, if we have a node registered for this device that's ok.
        return (self.__registry.get_node(dev_eui) is not None)

    def on_device_joined(self, dev_eui, dev_addr, appskey, nwkskey):
        """Handles device join procedure

        This method is called whenever a device has joined the network through OTAA.

        :param dev_eui: Device EUI
        :type dev_eui: str
        :param dev_addr: Device network address
        :type dev_addr: int
        :param appskey: Device's application session key
        :type appskey: bytes
        :param nwkskey: Device's network session encryption key
        :type nwkskey: int
        """
        # Add this device to our registry
        self.__registry.add_node(LWNode(
            dev_eui,
            dev_addr,
            appskey,
            nwkskey
        ))

    def on_device_data(self, dev_eui, dev_addr, data:bytes, upcount=0):
        """Handles data sent by a device.

        :param dev_eui: Device EUI
        :type dev_eui: EUI
        :param dev_addr: Device address
        :type dev_addr: int
        :param data: Data sent by device
        :type data: bytes
        :param upcount: uplink frame counter
        :type upcount: int
        """
        node = self.__registry.get_node(dev_eui)
        if node is not None:
            # Update uplink frame counter
            node.upcount = upcount

            # Make sure device has joined
            if node.joined:
                # We ask our specific callback
                return self.on_data(node, data)
            else:
                # If not, we should not have received somthing
                return None
        else:
            return None


    def on_data(self, node: LWNode, data: bytes) -> bytes:
        """This callback handles data coming from a device.

        If it returns some bytes, these bytes will be sent back
        to the device through a downlink transmission.

        If None is returned, nothing is sent back to the device.

        :param node: Node that sent the data
        :type node: LWNode
        :param data: Data sent by the node
        :type data: bytes

        :return: Data to send back to the device
        :rtype: bytes
        """
        return None