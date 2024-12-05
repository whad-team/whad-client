"""
Provisioning Constants
"""
from whad.scapy.layers.btmesh import (
    BTMesh_Provisioning_Invite,
    BTMesh_Provisioning_Capabilities,
    BTMesh_Provisioning_Start,
    BTMesh_Provisioning_Public_Key,
    BTMesh_Provisioning_Input_Complete,
    BTMesh_Provisioning_Confirmation,
    BTMesh_Provisioning_Random,
    BTMesh_Provisioning_Data,
    BTMesh_Provisioning_Complete,
    BTMesh_Provisioning_Failed,
    BTMesh_Provisioning_Record_Request,
    BTMesh_Provisioning_Records_Get,
    BTMesh_Provisioning_Records_List,
    BTMesh_Provisioning_Record_Response,
)

PROVISIONING_ERROR_CODES = {
    0x00: "Prohibited",
    0x01: "Invalid PDU",
    0x02: "Invalid Format",
    0x03: "Unexpected PDU",
    0x04: "Confirmation Failed",
    0x05: "Out of Resources",
    0x06: "Decryption Failed",
    0x07: "Unexpected Error",
    0x08: "Cannot Assign Addresses",
    0x09: "Invalid Data",
}

PROVISIONING_TYPES = {
    BTMesh_Provisioning_Invite : 0x00,
    BTMesh_Provisioning_Capabilities : 0x01,
    BTMesh_Provisioning_Start : 0x02,
    BTMesh_Provisioning_Public_Key: 0x03,
    BTMesh_Provisioning_Input_Complete : 0x04,
    BTMesh_Provisioning_Confirmation : 0x05,
    BTMesh_Provisioning_Random : 0x06,
    BTMesh_Provisioning_Data : 0x07,
    BTMesh_Provisioning_Complete : 0x08,
    BTMesh_Provisioning_Failed : 0x09,
    BTMesh_Provisioning_Record_Request : 0x0A,
    BTMesh_Provisioning_Record_Response : 0x0B,
    BTMesh_Provisioning_Records_Get : 0x0C,
    BTMesh_Provisioning_Records_List : 0x0D
}

