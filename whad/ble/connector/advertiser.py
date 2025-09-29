"""
Bluetooth Low Energy advertiser connector
=========================================

This module provides the :py:class:`~whad.ble.connector.advertiser.Advertiser`
class that implements the *Advertiser* role as defined in the Bluetooth
specification.
"""
import logging
from typing import Optional, List, Tuple, Union

from whad.ble.profile.advdata import AdvDataFieldList
from whad.exceptions import UnsupportedCapability
from whad.hub.ble import AdvType, ChannelMap

from .base import BLE


logger = logging.getLogger(__name__)

class Advertiser(BLE):
    """This connector provides a BLE advertiser role."""

    def __init__(self, device, adv_data: Union[AdvDataFieldList, bytes], scanrsp_data: Optional[Union[AdvDataFieldList, bytes]] = None,
                 adv_type: AdvType = AdvType.ADV_IND, channels: Optional[list] = None, interval: Optional[Tuple[int, int]] = None):
        """Advertiser initialization"""
        super().__init__(device)

        # Ensure advertiser mode is supported
        if not self.can_be_advertiser():
            raise UnsupportedCapability("Advertiser")

        # Set advertising type
        if adv_type in (AdvType.ADV_IND, AdvType.ADV_DIRECT_IND, AdvType.ADV_SCAN_IND, AdvType.ADV_NONCONN_IND):
            self.__adv_type = adv_type
        else:
            raise ValueError()

        # Set default channels if not set 
        if channels is None:
            self.__channels = [37, 38, 39]
        else:
            self.__channels = list(filter(lambda x: x in (37, 38, 39), channels))
        # Ensure interval is a tuple of two ints
        if interval is None:
            self.__inter_min = 0x20
            self.__inter_max = 0x4000
        else:
            try:
                if not isinstance(interval, tuple):
                    raise ValueError()
                if not len(interval) == 2:
                    raise ValueError()
                if not isinstance(interval[0], int) and not isinstance(interval[1], int):
                    raise ValueError()
                self.__inter_min, self.__inter_max = interval
            except ValueError as interval_error:
                logger.error("advertising interval must be a tuple of two integers.")
                raise ValueError() from interval_error

        # Save parameters
        self.__adv_data = adv_data
        self.__scanrsp_data = scanrsp_data

        # Configure the device advertising parameters
        self.__configure()

    @property
    def adv_type(self) -> AdvType:
        """Advertisement type"""
        return self.__adv_type

    @adv_type.setter
    def adv_type(self, adv_type: AdvType):
        """Advertisement type setter."""
        # If device is currently started, raise an error
        if self.__adv_type != adv_type:
            self.__adv_type = adv_type
            self.__configure()

    @property
    def adv_data(self) -> Union[AdvDataFieldList, bytes]:
        """Advertisement data"""
        return self.__adv_data

    @property
    def scanrsp_data(self) -> Optional[Union[AdvDataFieldList, bytes]]:
        """Scan response data"""
        return self.__scanrsp_data

    @property
    def channels(self) -> List[int]:
        """List of enabled advertising channels"""
        return self.__channels

    @channels.setter
    def channels(self, channels: List[int]):
        """Update channel map"""
        if set(channels) != set(self.__channels):
            self.__channels = channels
            self.__configure()

    @property
    def channel_map(self) -> ChannelMap:
        """Advertising channel map"""
        return ChannelMap(self.__channels)

    @property
    def interval(self) -> Tuple[int, int]:
        """Advertising interval"""
        return (self.__inter_min, self.__inter_max)

    @interval.setter
    def interval(self, interval: Tuple[int,int]):
        """Update interval"""
        if interval != (self.__inter_min, self.__inter_max):
            if isinstance(interval, tuple) and len(interval) == 2:
                self.__inter_min, self.__inter_max = interval
                self.__configure()

    def __configure(self) -> bool:
        """Configure the main advertising parameters.

        This method will set the specified advertising parameters (advertising data, scan response data, advertisement type,
        advertising channel map, interval min and max values) into the associated device. Advertising data and scan response
        data can be updated at any time, other parameters require the device to stop advertising to be changed.
        """
        # Configure the device advertising parameters
        adv_data = self.adv_data if isinstance(self.adv_data, bytes) else self.adv_data.to_bytes()
        if isinstance(self.scanrsp_data, bytes):
            scanrsp_data = self.scanrsp_data
        elif isinstance(self.scanrsp_data, AdvDataFieldList):
            scanrsp_data = self.scanrsp_data.to_bytes()
        else:
            scanrsp_data = None
        result = self.enable_adv_mode(
            adv_data=adv_data,
            scan_data=scanrsp_data,
            adv_type=self.adv_type,
            channel_map=self.channel_map,
            inter_min=self.__inter_min, inter_max=self.__inter_max)

        # Display a warning if an error occurred
        if not result:
            logger.warning("[Advertiser] an error occurred while trying to reconfigure the advertiser's core parameters.")
        return result

    def update(self, adv_data: Optional[AdvDataFieldList] = None, scanrsp_data: Optional[AdvDataFieldList] = None) -> bool:
        """Update advertising data.

        :param adv_data: Advertising data
        :type  adv_data: AdvDataFieldList, optional
        :param scanrsp_data: Scan response data
        :type  scanrsp_data: AdvDataFieldList, optional
        :return: `True` if parameters have been successfully update, `False` otherwise.
        """
        # Save advertising info
        if adv_data is not None:
            self.__adv_data = adv_data
        if scanrsp_data is not None:
            self.__scanrsp_data = scanrsp_data

        # Reconfigure
        return self.set_adv_data(self.__adv_data, self.__scanrsp_data)

