"""WHAD Protocol Discovery info messages abstraction layer.
"""
from whad.protocol.whad_pb2 import Message
from whad.protocol.generic_pb2 import ResultCode
from whad.protocol.hub.message import HubMessage
from whad.protocol.hub import pb_bind, PbFieldInt, PbMessageWrapper
from whad.protocol.hub.discovery import Discovery

@pb_bind(Discovery, 'domain_query', 1)
class DomainInfoQuery(PbMessageWrapper):
    """Device info domain query message class
    """
    domain = PbFieldInt('discovery.domain_query.domain')

@pb_bind(Discovery, 'domain_resp', 1)
class DomainInfoQueryResp(PbMessageWrapper):
    """Device info domain query response message class
    """
    domain = PbFieldInt('discovery.domain_resp.domain')
    supported_commands = PbFieldInt('discovery.domain_resp.supported_commands')