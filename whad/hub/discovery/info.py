"""WHAD Protocol Discovery info messages abstraction layer.
"""
from whad.hub.message import pb_bind, PbFieldInt, PbFieldBytes, PbMessageWrapper, \
    PbFieldArray
from whad.hub.discovery import Discovery

@pb_bind(Discovery, 'info_query', 1)
class InfoQuery(PbMessageWrapper):
    """Device info query message class
    """
    proto_ver = PbFieldInt('discovery.info_query.proto_ver')

@pb_bind(Discovery, 'info_resp', 1)
class InfoQueryResp(PbMessageWrapper):
    """Device info query response message class
    """
    type = PbFieldInt('discovery.info_resp.type')
    device_id = PbFieldBytes('discovery.info_resp.devid')
    proto_min_ver = PbFieldInt('discovery.info_resp.proto_min_ver')
    max_speed = PbFieldInt('discovery.info_resp.max_speed')
    fw_author = PbFieldBytes('discovery.info_resp.fw_author')
    fw_url = PbFieldBytes('discovery.info_resp.fw_url')
    fw_version_major = PbFieldInt('discovery.info_resp.fw_version_major')
    fw_version_minor = PbFieldInt('discovery.info_resp.fw_version_minor')
    fw_version_rev = PbFieldInt('discovery.info_resp.fw_version_rev')
    capabilities = PbFieldArray('discovery.info_resp.capabilities')
