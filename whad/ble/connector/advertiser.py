"""
Bluetooth Low Energy advertiser connector
=========================================

This module provides the :py:class:`~whad.ble.connector.advertiser.Advertiser`
class that implements the *Advertiser* role as defined in the Bluetooth
specification.
"""
import logging
from typing import Optional

from whad.ble.profile.advdata import AdvDataFieldList
from whad.exceptions import UnsupportedCapability
from whad.hub.ble import AdvType, ChannelMap

from .base import BLE


logger = logging.getLogger(__name__)

class Advertiser(BLE):
    """This connector provides a BLE advertiser role."""

    def __init__(self, device, adv_data: AdvDataFieldList, scanrsp_data: Optional[AdvDataFieldList] = None,
                 adv_type: AdvType = AdvType.ADV_IND, channels: Optional[list] = None, inter_min: int = 0x20,
                 inter_max: int = 0x4000):
        """Advertiser initialization"""
        super().__init__(device)

        # Set default channels if not set 
        if channels is None:
            channels = [37, 38, 39]
        else:
            channels = list(filter(lambda x: x in (37, 38, 39), channels))

        # Save parameters
        self.__adv_type = adv_type
        self.__adv_data = adv_data
        self.__scanrsp_data = scanrsp_data
        self.__channels = channels
        self.__inter_min = inter_min
        self.__inter_max = inter_max

        # Configure the device advertising parameters
        self.__configure()

    def __configure(self) -> bool:
        """Configure the main advertising parameters.

        This method will set the specified advertising parameters (advertising data, scan response data, advertisement type,
        advertising channel map, interval min and max values) into the associated device. Advertising data and scan response
        data can be updated at any time, other parameters require the device to stop advertising to be changed.
        """
        # Configure the device advertising parameters
        return self.enable_adv_mode(adv_data=self.__adv_data.to_bytes(), scan_data=self.__scanrsp_data.to_bytes(),
                                    adv_type=self.__adv_type, channel_map=ChannelMap(self.__channels),
                                    inter_min=self.__inter_min, inter_max=self.__inter_max)


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
        return self.__configure()

