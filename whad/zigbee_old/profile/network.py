from whad.zigbee.stack.nwk.constants import ZigbeeDeviceType
from whad.zigbee.profile.device import Coordinator, EndDevice, Router
from time import sleep

class JoiningForbidden(Exception):
    pass

class NotAssociated(Exception):
    pass

class NotAuthorized(Exception):
    pass

class Network:
    def __init__(self, nwkObject=None, stack = None):
        self.__nwk_object = nwkObject
        self.coordinator = None
        self.routers = []
        self.end_devices = []
        self.__stack = stack

    @property
    def devices(self):
        return ([self.coordinator] if self.coordinator is not None else []) + self.routers + self.end_devices

    @property
    def stack(self):
        return self.__stack

    @property
    def pan_id(self):
        return self.__nwk_object.dot15d4_pan_network.coord_pan_id

    @property
    def extended_pan_id(self):
        return self.__nwk_object.extended_pan_id

    @property
    def channel(self):
        return self.__nwk_object.channel

    def discover(self):
        if not self.is_associated():
            raise NotAssociated
        if not self.is_authorized():
            raise NotAuthorized
        devices = self.stack.apl.get_application_by_name("zdo").device_and_service_discovery.discover_devices()
        return self.devices

    def join(self):
        if self.is_joining_permitted():
            join_success = self.stack.apl.get_application_by_name("zdo").network_manager.join(self)
            if join_success:
                while not self.is_authorized():
                    sleep(0.1)
                return True
            return False
        else:
            raise JoiningForbidden

    def is_joining_permitted(self):
        return self.__nwk_object.joining_permit

    def is_associated(self):
        return self.stack.nwk.database.get("nwkExtendedPANID") == self.extended_pan_id

    def is_authorized(self):
        return self.stack.apl.get_application_by_name("zdo").network_manager.authorized

    @property
    def network_key(self):
        nwk_material = self.stack.nwk.database.get("nwkSecurityMaterialSet")
        if len(nwk_material) > 0:
            return nwk_material[0].key
        else:
            return None

    def leave(self):
        return self.stack.apl.get_application_by_name("zdo").network_manager.leave()

    def __eq__(self, other):
        return self.extended_pan_id == other.extended_pan_id

    def __repr__(self):
        return (
            "Network(" +
            "pan_id=" + hex(self.pan_id) + ", " +
            "extended_pan_id=" + hex(self.extended_pan_id) + ", " +
            "channel="+str(self.channel) + ", " +
            "joining="+ ("allowed" if self.is_joining_permitted() else "forbidden") + ", " +
            "associated="+ ("yes" if self.is_associated() else "no") + ", "
            "authorized="+ ("yes" if self.is_authorized() else "no") +

            ")"
        )
