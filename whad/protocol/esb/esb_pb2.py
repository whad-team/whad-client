# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: protocol/esb/esb.proto
"""Generated protocol buffer code."""
from google.protobuf.internal import enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\x16protocol/esb/esb.proto\x12\x03\x65sb\"$\n\x11SetNodeAddressCmd\x12\x0f\n\x07\x61\x64\x64ress\x18\x01 \x01(\x0c\"K\n\x08SniffCmd\x12\x0f\n\x07\x63hannel\x18\x01 \x01(\r\x12\x0f\n\x07\x61\x64\x64ress\x18\x02 \x01(\x0c\x12\x1d\n\x15show_acknowledgements\x18\x03 \x01(\x08\"\x19\n\x06JamCmd\x12\x0f\n\x07\x63hannel\x18\x01 \x01(\r\"\'\n\x07SendCmd\x12\x0f\n\x07\x63hannel\x18\x01 \x01(\r\x12\x0b\n\x03pdu\x18\x02 \x01(\x0c\"*\n\nSendRawCmd\x12\x0f\n\x07\x63hannel\x18\x01 \x01(\r\x12\x0b\n\x03pdu\x18\x02 \x01(\x0c\")\n\x16PrimaryReceiverModeCmd\x12\x0f\n\x07\x63hannel\x18\x01 \x01(\r\",\n\x19PrimaryTransmitterModeCmd\x12\x0f\n\x07\x63hannel\x18\x01 \x01(\r\"\n\n\x08StartCmd\"\t\n\x07StopCmd\"\x1b\n\x06Jammed\x12\x11\n\ttimestamp\x18\x01 \x01(\r\"\xbe\x01\n\x0eRawPduReceived\x12\x0f\n\x07\x63hannel\x18\x01 \x01(\r\x12\x11\n\x04rssi\x18\x02 \x01(\x05H\x00\x88\x01\x01\x12\x16\n\ttimestamp\x18\x03 \x01(\rH\x01\x88\x01\x01\x12\x19\n\x0c\x63rc_validity\x18\x04 \x01(\x08H\x02\x88\x01\x01\x12\x14\n\x07\x61\x64\x64ress\x18\x05 \x01(\x0cH\x03\x88\x01\x01\x12\x0b\n\x03pdu\x18\x06 \x01(\x0c\x42\x07\n\x05_rssiB\x0c\n\n_timestampB\x0f\n\r_crc_validityB\n\n\x08_address\"\xbb\x01\n\x0bPduReceived\x12\x0f\n\x07\x63hannel\x18\x01 \x01(\r\x12\x11\n\x04rssi\x18\x02 \x01(\x05H\x00\x88\x01\x01\x12\x16\n\ttimestamp\x18\x03 \x01(\rH\x01\x88\x01\x01\x12\x19\n\x0c\x63rc_validity\x18\x04 \x01(\x08H\x02\x88\x01\x01\x12\x14\n\x07\x61\x64\x64ress\x18\x05 \x01(\x0cH\x03\x88\x01\x01\x12\x0b\n\x03pdu\x18\x06 \x01(\x0c\x42\x07\n\x05_rssiB\x0c\n\n_timestampB\x0f\n\r_crc_validityB\n\n\x08_address\"\xc1\x03\n\x07Message\x12/\n\rset_node_addr\x18\x01 \x01(\x0b\x32\x16.esb.SetNodeAddressCmdH\x00\x12\x1e\n\x05sniff\x18\x02 \x01(\x0b\x32\r.esb.SniffCmdH\x00\x12\x1a\n\x03jam\x18\x03 \x01(\x0b\x32\x0b.esb.JamCmdH\x00\x12\x1c\n\x04send\x18\x04 \x01(\x0b\x32\x0c.esb.SendCmdH\x00\x12#\n\x08send_raw\x18\x05 \x01(\x0b\x32\x0f.esb.SendRawCmdH\x00\x12*\n\x03prx\x18\x06 \x01(\x0b\x32\x1b.esb.PrimaryReceiverModeCmdH\x00\x12-\n\x03ptx\x18\x07 \x01(\x0b\x32\x1e.esb.PrimaryTransmitterModeCmdH\x00\x12\x1e\n\x05start\x18\x08 \x01(\x0b\x32\r.esb.StartCmdH\x00\x12\x1c\n\x04stop\x18\t \x01(\x0b\x32\x0c.esb.StopCmdH\x00\x12\x1d\n\x06jammed\x18\n \x01(\x0b\x32\x0b.esb.JammedH\x00\x12&\n\x07raw_pdu\x18\x0b \x01(\x0b\x32\x13.esb.RawPduReceivedH\x00\x12\x1f\n\x03pdu\x18\x0c \x01(\x0b\x32\x10.esb.PduReceivedH\x00\x42\x05\n\x03msg*\x95\x01\n\nESBCommand\x12\x12\n\x0eSetNodeAddress\x10\x00\x12\t\n\x05Sniff\x10\x01\x12\x07\n\x03Jam\x10\x02\x12\x08\n\x04Send\x10\x03\x12\x0b\n\x07SendRaw\x10\x04\x12\x17\n\x13PrimaryReceiverMode\x10\x05\x12\x1a\n\x16PrimaryTransmitterMode\x10\x06\x12\t\n\x05Start\x10\x07\x12\x08\n\x04Stop\x10\x08\x62\x06proto3')

_ESBCOMMAND = DESCRIPTOR.enum_types_by_name['ESBCommand']
ESBCommand = enum_type_wrapper.EnumTypeWrapper(_ESBCOMMAND)
SetNodeAddress = 0
Sniff = 1
Jam = 2
Send = 3
SendRaw = 4
PrimaryReceiverMode = 5
PrimaryTransmitterMode = 6
Start = 7
Stop = 8


_SETNODEADDRESSCMD = DESCRIPTOR.message_types_by_name['SetNodeAddressCmd']
_SNIFFCMD = DESCRIPTOR.message_types_by_name['SniffCmd']
_JAMCMD = DESCRIPTOR.message_types_by_name['JamCmd']
_SENDCMD = DESCRIPTOR.message_types_by_name['SendCmd']
_SENDRAWCMD = DESCRIPTOR.message_types_by_name['SendRawCmd']
_PRIMARYRECEIVERMODECMD = DESCRIPTOR.message_types_by_name['PrimaryReceiverModeCmd']
_PRIMARYTRANSMITTERMODECMD = DESCRIPTOR.message_types_by_name['PrimaryTransmitterModeCmd']
_STARTCMD = DESCRIPTOR.message_types_by_name['StartCmd']
_STOPCMD = DESCRIPTOR.message_types_by_name['StopCmd']
_JAMMED = DESCRIPTOR.message_types_by_name['Jammed']
_RAWPDURECEIVED = DESCRIPTOR.message_types_by_name['RawPduReceived']
_PDURECEIVED = DESCRIPTOR.message_types_by_name['PduReceived']
_MESSAGE = DESCRIPTOR.message_types_by_name['Message']
SetNodeAddressCmd = _reflection.GeneratedProtocolMessageType('SetNodeAddressCmd', (_message.Message,), {
  'DESCRIPTOR' : _SETNODEADDRESSCMD,
  '__module__' : 'protocol.esb.esb_pb2'
  # @@protoc_insertion_point(class_scope:esb.SetNodeAddressCmd)
  })
_sym_db.RegisterMessage(SetNodeAddressCmd)

SniffCmd = _reflection.GeneratedProtocolMessageType('SniffCmd', (_message.Message,), {
  'DESCRIPTOR' : _SNIFFCMD,
  '__module__' : 'protocol.esb.esb_pb2'
  # @@protoc_insertion_point(class_scope:esb.SniffCmd)
  })
_sym_db.RegisterMessage(SniffCmd)

JamCmd = _reflection.GeneratedProtocolMessageType('JamCmd', (_message.Message,), {
  'DESCRIPTOR' : _JAMCMD,
  '__module__' : 'protocol.esb.esb_pb2'
  # @@protoc_insertion_point(class_scope:esb.JamCmd)
  })
_sym_db.RegisterMessage(JamCmd)

SendCmd = _reflection.GeneratedProtocolMessageType('SendCmd', (_message.Message,), {
  'DESCRIPTOR' : _SENDCMD,
  '__module__' : 'protocol.esb.esb_pb2'
  # @@protoc_insertion_point(class_scope:esb.SendCmd)
  })
_sym_db.RegisterMessage(SendCmd)

SendRawCmd = _reflection.GeneratedProtocolMessageType('SendRawCmd', (_message.Message,), {
  'DESCRIPTOR' : _SENDRAWCMD,
  '__module__' : 'protocol.esb.esb_pb2'
  # @@protoc_insertion_point(class_scope:esb.SendRawCmd)
  })
_sym_db.RegisterMessage(SendRawCmd)

PrimaryReceiverModeCmd = _reflection.GeneratedProtocolMessageType('PrimaryReceiverModeCmd', (_message.Message,), {
  'DESCRIPTOR' : _PRIMARYRECEIVERMODECMD,
  '__module__' : 'protocol.esb.esb_pb2'
  # @@protoc_insertion_point(class_scope:esb.PrimaryReceiverModeCmd)
  })
_sym_db.RegisterMessage(PrimaryReceiverModeCmd)

PrimaryTransmitterModeCmd = _reflection.GeneratedProtocolMessageType('PrimaryTransmitterModeCmd', (_message.Message,), {
  'DESCRIPTOR' : _PRIMARYTRANSMITTERMODECMD,
  '__module__' : 'protocol.esb.esb_pb2'
  # @@protoc_insertion_point(class_scope:esb.PrimaryTransmitterModeCmd)
  })
_sym_db.RegisterMessage(PrimaryTransmitterModeCmd)

StartCmd = _reflection.GeneratedProtocolMessageType('StartCmd', (_message.Message,), {
  'DESCRIPTOR' : _STARTCMD,
  '__module__' : 'protocol.esb.esb_pb2'
  # @@protoc_insertion_point(class_scope:esb.StartCmd)
  })
_sym_db.RegisterMessage(StartCmd)

StopCmd = _reflection.GeneratedProtocolMessageType('StopCmd', (_message.Message,), {
  'DESCRIPTOR' : _STOPCMD,
  '__module__' : 'protocol.esb.esb_pb2'
  # @@protoc_insertion_point(class_scope:esb.StopCmd)
  })
_sym_db.RegisterMessage(StopCmd)

Jammed = _reflection.GeneratedProtocolMessageType('Jammed', (_message.Message,), {
  'DESCRIPTOR' : _JAMMED,
  '__module__' : 'protocol.esb.esb_pb2'
  # @@protoc_insertion_point(class_scope:esb.Jammed)
  })
_sym_db.RegisterMessage(Jammed)

RawPduReceived = _reflection.GeneratedProtocolMessageType('RawPduReceived', (_message.Message,), {
  'DESCRIPTOR' : _RAWPDURECEIVED,
  '__module__' : 'protocol.esb.esb_pb2'
  # @@protoc_insertion_point(class_scope:esb.RawPduReceived)
  })
_sym_db.RegisterMessage(RawPduReceived)

PduReceived = _reflection.GeneratedProtocolMessageType('PduReceived', (_message.Message,), {
  'DESCRIPTOR' : _PDURECEIVED,
  '__module__' : 'protocol.esb.esb_pb2'
  # @@protoc_insertion_point(class_scope:esb.PduReceived)
  })
_sym_db.RegisterMessage(PduReceived)

Message = _reflection.GeneratedProtocolMessageType('Message', (_message.Message,), {
  'DESCRIPTOR' : _MESSAGE,
  '__module__' : 'protocol.esb.esb_pb2'
  # @@protoc_insertion_point(class_scope:esb.Message)
  })
_sym_db.RegisterMessage(Message)

if _descriptor._USE_C_DESCRIPTORS == False:

  DESCRIPTOR._options = None
  _ESBCOMMAND._serialized_start=1235
  _ESBCOMMAND._serialized_end=1384
  _SETNODEADDRESSCMD._serialized_start=31
  _SETNODEADDRESSCMD._serialized_end=67
  _SNIFFCMD._serialized_start=69
  _SNIFFCMD._serialized_end=144
  _JAMCMD._serialized_start=146
  _JAMCMD._serialized_end=171
  _SENDCMD._serialized_start=173
  _SENDCMD._serialized_end=212
  _SENDRAWCMD._serialized_start=214
  _SENDRAWCMD._serialized_end=256
  _PRIMARYRECEIVERMODECMD._serialized_start=258
  _PRIMARYRECEIVERMODECMD._serialized_end=299
  _PRIMARYTRANSMITTERMODECMD._serialized_start=301
  _PRIMARYTRANSMITTERMODECMD._serialized_end=345
  _STARTCMD._serialized_start=347
  _STARTCMD._serialized_end=357
  _STOPCMD._serialized_start=359
  _STOPCMD._serialized_end=368
  _JAMMED._serialized_start=370
  _JAMMED._serialized_end=397
  _RAWPDURECEIVED._serialized_start=400
  _RAWPDURECEIVED._serialized_end=590
  _PDURECEIVED._serialized_start=593
  _PDURECEIVED._serialized_end=780
  _MESSAGE._serialized_start=783
  _MESSAGE._serialized_end=1232
# @@protoc_insertion_point(module_scope)