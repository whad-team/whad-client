from whad.zigbee.stack.nwk.constants import ZigbeeRelationship, ZigbeeDeviceType
from time import time
class ZigbeeNode:
    """
    Class representing a Zigbee device.
    """
    def __init__(
                    self,
                    address,
                    device_type,
                    extended_address=None,
                    rx_on_when_idle=False,
                    end_device_configuration=0,
                    timeout_counter=None,
                    device_timeout=None,
                    transmit_failure=0,
                    lqi=None,
                    outgoing_cost=0,
                    age=0,
                    keepalive_received=False,
                    extended_pan_id=None,
                    logical_channel=None,
                    depth=None,
                    beacon_order=None,
                    permit_joining=None,
                    potential_parent=None,
                    update_id=None,
                    pan_id=None,
                    relationship=ZigbeeRelationship.NONE
    ):
        self.address = address
        self.device_type = device_type
        self.extended_address = extended_address
        self.rx_on_when_idle = rx_on_when_idle
        self.end_device_configuration = end_device_configuration
        self.timeout_counter = timeout_counter
        self.device_timeout = device_timeout
        self.transmit_failure = transmit_failure
        self.lqi = lqi
        self.outgoing_cost = outgoing_cost
        self.age = age
        self.update_id=update_id
        self.keepalive_received = keepalive_received
        self.extended_pan_id = extended_pan_id
        self.logical_channel = logical_channel
        self.depth = depth
        self.beacon_order = beacon_order
        self.permit_joining = permit_joining
        self.potential_parent = potential_parent
        self.relationship = relationship
        self.pan_id = pan_id
        self.lqis = [lqi] if lqi is not None else []
        self.last_update = time()

    def link_cost(self):
        pl = sum(self.lqis) / len(self.lqis)
        result = min(7,round(1/(pl ** 4)))
        self.__dict__["outgoing_cost"] = result
        return link_cost

    def __setattr__(self, name, value):
        if hasattr(self, "last_update"):
            if name == "lqi":
                self.__dict__["lqis"].append(value)
                if len(self.__dict__["lqis"]) > 20:
                    self.__dict__["lqis"] = self.__dict__["lqis"][1:]
                    self.link_cost()
            self.__dict__["last_update"] = time()

        self.__dict__[name] = value

    def __repr__(self):
        if self.device_type == ZigbeeDeviceType.END_DEVICE:
            role = "ZigbeeEndDevice"
        elif self.device_type == ZigbeeDeviceType.COORDINATOR:
            role = "ZigbeeCoordinator"
        elif self.device_type == ZigbeeDeviceType.ROUTER:
            role = "ZigbeeRouter"

        return "{}(address={:04x}, extended_pan_id={:04x} - last update {} seconds ago)".format(
                    role,
                    self.address,
                    self.extended_pan_id,
                    round(time() - self.last_update, 2)
        )

class ZigbeeEndDevice(ZigbeeNode):
    def __init__(
                    self,
                    address,
                    extended_address=None,
                    rx_on_when_idle=False,
                    end_device_configuration=0,
                    timeout_counter=None,
                    device_timeout=None,
                    transmit_failure=0,
                    lqi=0,
                    outgoing_cost=0,
                    age=0,
                    keepalive_received=False,
                    extended_pan_id=None,
                    logical_channel=None,
                    depth=None,
                    beacon_order=None,
                    permit_joining=None,
                    potential_parent=None,
                    update_id=None,
                    pan_id=None,
                    relationship=ZigbeeRelationship.NONE
    ):
        super().__init__(
                            address,
                            device_type=ZigbeeDeviceType.END_DEVICE,
                            extended_address=extended_address,
                            rx_on_when_idle=rx_on_when_idle,
                            end_device_configuration=end_device_configuration,
                            timeout_counter=timeout_counter,
                            device_timeout=device_timeout,
                            transmit_failure=transmit_failure,
                            lqi=lqi,
                            outgoing_cost=outgoing_cost,
                            age=age,
                            keepalive_received=keepalive_received,
                            extended_pan_id=extended_pan_id,
                            logical_channel=logical_channel,
                            depth=depth,
                            beacon_order=beacon_order,
                            permit_joining=permit_joining,
                            potential_parent=potential_parent,
                            update_id=update_id,
                            pan_id=pan_id,
                            relationship=relationship
        )

class ZigbeeCoordinator(ZigbeeNode):
    def __init__(
                    self,
                    address,
                    extended_address=None,
                    rx_on_when_idle=False,
                    end_device_configuration=0,
                    timeout_counter=None,
                    device_timeout=None,
                    transmit_failure=0,
                    lqi=0,
                    outgoing_cost=0,
                    age=0,
                    keepalive_received=False,
                    extended_pan_id=None,
                    logical_channel=None,
                    depth=None,
                    beacon_order=None,
                    permit_joining=None,
                    potential_parent=None,
                    update_id=None,
                    pan_id=None,
                    relationship=ZigbeeRelationship.NONE
    ):
        super().__init__(
                            address,
                            device_type=ZigbeeDeviceType.COORDINATOR,
                            extended_address=extended_address,
                            rx_on_when_idle=rx_on_when_idle,
                            end_device_configuration=end_device_configuration,
                            timeout_counter=timeout_counter,
                            device_timeout=device_timeout,
                            transmit_failure=transmit_failure,
                            lqi=lqi,
                            outgoing_cost=outgoing_cost,
                            age=age,
                            keepalive_received=keepalive_received,
                            extended_pan_id=extended_pan_id,
                            logical_channel=logical_channel,
                            depth=depth,
                            beacon_order=beacon_order,
                            permit_joining=permit_joining,
                            potential_parent=potential_parent,
                            update_id=update_id,
                            pan_id=pan_id,
                            relationship=relationship
        )

class ZigbeeRouter(ZigbeeNode):
    def __init__(
                    self,
                    address,
                    extended_address=None,
                    rx_on_when_idle=False,
                    end_device_configuration=0,
                    timeout_counter=None,
                    device_timeout=None,
                    transmit_failure=0,
                    lqi=0,
                    outgoing_cost=0,
                    age=0,
                    keepalive_received=False,
                    extended_pan_id=None,
                    logical_channel=None,
                    depth=None,
                    beacon_order=None,
                    permit_joining=None,
                    potential_parent=None,
                    update_id=None,
                    pan_id=None,
                    relationship=ZigbeeRelationship.NONE
    ):
        super().__init__(
                            address,
                            device_type=ZigbeeDeviceType.ROUTER,
                            extended_address=extended_address,
                            rx_on_when_idle=rx_on_when_idle,
                            end_device_configuration=end_device_configuration,
                            timeout_counter=timeout_counter,
                            device_timeout=device_timeout,
                            transmit_failure=transmit_failure,
                            lqi=lqi,
                            outgoing_cost=outgoing_cost,
                            age=age,
                            keepalive_received=keepalive_received,
                            extended_pan_id=extended_pan_id,
                            logical_channel=logical_channel,
                            depth=depth,
                            beacon_order=beacon_order,
                            permit_joining=permit_joining,
                            potential_parent=potential_parent,
                            update_id=update_id,
                            pan_id=pan_id,
                            relationship=relationship
        )
