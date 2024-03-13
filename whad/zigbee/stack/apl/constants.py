from enum import IntEnum
"""
Constants implemented as Enum for Zigbee APL layer.
"""

class LogicalDeviceType(IntEnum):
    """
    Represents the logical device type of a node.
    """
    COORDINATOR = 0
    ROUTER = 1
    END_DEVICE = 2

# Human Readable string for Zigbee Profile IDs
ZIGBEE_PROFILE_IDENTIFIERS = {
    0x0101 : "Industrial plant monitoring",
    0x0104 : "Home Automation",
    0x0105 : "Commercial Building Automation",
    0x0107 : "Telecom Applications",
    0x0108 : "Personal Home and Hospital Care",
    0x0109 : "Advanced Metering Initiative",
}

# Human Readable string for Zigbee Device IDs
ZIGBEE_DEVICE_IDENTIFIERS = {
    0x0000 : "ON/OFF Switch",
    0x0001 : "Level Control Switch",
    0x0002 : "ON/OFF Output",
    0x0003 : "Level Controllable Output",
    0x0004 : "Scene Selector",
    0x0005 : "Configuration Tool",
    0x0006 : "Remote control",
    0x0007 : "Combined Interface",
    0x0008 : "Range Extender",
    0x0009 : "Mains Power Outlet",
    0x0100 : "ON/OFF Light",
    0x0101 : "Dimmable Light",
    0x0102 : "Color Dimmable Light",
    0x0103 : "ON/OFF Light Switch",
    0x0104 : "Dimmer Switch",
    0x0105 : "Color Dimmer Switch",
    0x0106 : "Light Sensor",
    0x0107 : "Occupancy Sensor",
    0x0200 : "Shade",
    0x0201 : "Shade Controller",
    0x0300 : "Heating/Cooling Unit",
    0x0301 : "Thermostat",
    0x0302 : "Temperature Sensor",
    0x0303 : "Pump",
    0x0304 : "Pump Controller",
    0x0305 : "Pressure Sensor",
    0x0306 : "Flow sensor",
    0x0400 : "IAS Control and Indicating Equipment",
    0x0401 : "IAS Ancillary Control Equipment",
    0x0402 : "IAS Zone",
    0x0403 : "IAS Warning Device",
}

# Human readable list of Zigbee Cluster IDs
ZIGBEE_CLUSTER_IDENTIFIERS = {
    0x0000 : ("Generic", "Basic"),
    0x0001 : ("Generic", "Power configuration"),
    0x0002 : ("Generic", "Device temperature configuration"),
    0x0003 : ("Generic", "Identify"),
    0x0004 : ("Generic", "Groups"),
    0x0005 : ("Generic", "Scenes"),
    0x0006 : ("Generic", "ON/OFF"),
    0x0007 : ("Generic", "ON/OFF Switch configuration"),
    0x0008 : ("Generic", "Level Control"),
    0x0009 : ("Generic", "Alarms"),
    0x000A : ("Generic", "Time"),
    0x000B : ("Generic", "RSSI Location"),
    0x0100 : ("Closures", "Shade Configuration"),
    0x0200 : ("HVAC", "Pump Configuration and Control"),
    0x0201 : ("HVAC","Thermostat"),
    0x0202 : ("HVAC","Fan control"),
    0x0203 : ("HVAC","Dehumidification Control"),
    0x0204 : ("HVAC","Thermostat User Interface Configuration"),
    0x0300 : ("Lighting","Color Control"),
    0x0301 : ("Lighting","Ballast Configuration"),
    0x0400 : ("Measurement and sensing","Luminance Measurement"),
    0x0401 : ("Measurement and sensing","Luminance Level Sensing"),
    0x0402 : ("Measurement and sensing","Temperature Measurement"),
    0x0403 : ("Measurement and sensing","Pressure Measurement"),
    0x0404 : ("Measurement and sensing","Flow Measurement"),
    0x0405 : ("Measurement and sensing","Relative Humidity Measurement"),
    0x0406 : ("Measurement and sensing","Occupancy Sensing"),
    0x0500 : ("Security and Safety","IAS Zone"),
    0x0501 : ("Security and Safety","IAS ACE"),
    0x0502 : ("Security and Safety","IAS WD"),
}
