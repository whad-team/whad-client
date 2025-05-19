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

# ARBITRARY, ONLY FOR INTERNAL USE IN WHAD
VIRTUAL_ADDR_TYPE = 0x00
GROUP_ADDR_TYPE = 0x01
UNICAST_ADDR_TYPE = 0x02
UNASSIGNED_ADDR_TYPE = 0x03


# CREDENTIALS FOR THE NETWORK LAYER
MANAGED_FLOODING_CREDS = 0x00
FRIEND_CREDS = 0x01
DIRECTED_FORWARDING_CREDS = 0x02

# OOB AUTHENTICATION METHODS PROVISIONNING (FOR INTERNAL USE ONLY)
NO_OOB_AUTH = 0x00
STATIC_OOB_AUTH = 0x01
OUTPUT_OOB_AUTH = 0x02
INPUT_OOB_AUTH = 0x03

# OOB AUTHENTICATION ACTIONS PROVISIONNING (FOR INTERNAL USE ONLY)
OUTPUT_BLINK_AUTH = 0x00
OUTPUT_BEEP_AUTH = 0x01
OUTPUT_VIBRATE_AUTH = 0x02
OUTPUT_NUMERIC_AUTH = 0x03
OUTPUT_ALPHANUM_AUTH = 0x04

INPUT_PUSH_AUTH = 0x00
INPUT_TWIST_AUTH = 0x01
INPUT_NUMERIC_AUTH = 0x02
INPUT_ALPHANUM_AUTH = 0x03


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
    BTMesh_Provisioning_Invite: 0x00,
    BTMesh_Provisioning_Capabilities: 0x01,
    BTMesh_Provisioning_Start: 0x02,
    BTMesh_Provisioning_Public_Key: 0x03,
    BTMesh_Provisioning_Input_Complete: 0x04,
    BTMesh_Provisioning_Confirmation: 0x05,
    BTMesh_Provisioning_Random: 0x06,
    BTMesh_Provisioning_Data: 0x07,
    BTMesh_Provisioning_Complete: 0x08,
    BTMesh_Provisioning_Failed: 0x09,
    BTMesh_Provisioning_Record_Request: 0x0A,
    BTMesh_Provisioning_Record_Response: 0x0B,
    BTMesh_Provisioning_Records_Get: 0x0C,
    BTMesh_Provisioning_Records_List: 0x0D,
}
