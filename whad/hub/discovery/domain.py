"""WHAD Protocol Discovery info messages abstraction layer.
"""
from whad.hub.message import pb_bind, PbFieldInt, PbMessageWrapper
from whad.hub.discovery import Discovery

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