# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: whad/protocol/ble/ble.proto
"""Generated protocol buffer code."""
from google.protobuf.internal import builder as _builder
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\x1bwhad/protocol/ble/ble.proto\x12\x03\x62le\"J\n\x0fSetBdAddressCmd\x12\x12\n\nbd_address\x18\x01 \x01(\x0c\x12#\n\taddr_type\x18\x02 \x01(\x0e\x32\x10.ble.BleAddrType\"L\n\x0bSniffAdvCmd\x12\x18\n\x10use_extended_adv\x18\x01 \x01(\x08\x12\x0f\n\x07\x63hannel\x18\x02 \x01(\r\x12\x12\n\nbd_address\x18\x03 \x01(\x0c\"\x0b\n\tJamAdvCmd\"%\n\x12JamAdvOnChannelCmd\x12\x0f\n\x07\x63hannel\x18\x01 \x01(\r\"o\n\x0fSniffConnReqCmd\x12\x1a\n\x12show_empty_packets\x18\x01 \x01(\x08\x12\x1b\n\x13show_advertisements\x18\x02 \x01(\x08\x12\x0f\n\x07\x63hannel\x18\x03 \x01(\r\x12\x12\n\nbd_address\x18\x04 \x01(\x0c\"3\n\x15SniffAccessAddressCmd\x12\x1a\n\x12monitored_channels\x18\x06 \x01(\x0c\"\x9c\x01\n\x12SniffActiveConnCmd\x12\x16\n\x0e\x61\x63\x63\x65ss_address\x18\x01 \x01(\r\x12\x10\n\x08\x63rc_init\x18\x02 \x01(\r\x12\x13\n\x0b\x63hannel_map\x18\x03 \x01(\x0c\x12\x14\n\x0chop_interval\x18\x04 \x01(\r\x12\x15\n\rhop_increment\x18\x05 \x01(\r\x12\x1a\n\x12monitored_channels\x18\x06 \x01(\x0c\"$\n\nJamConnCmd\x12\x16\n\x0e\x61\x63\x63\x65ss_address\x18\x01 \x01(\r\"\"\n\x0bScanModeCmd\x12\x13\n\x0b\x61\x63tive_scan\x18\x01 \x01(\x08\"5\n\nAdvModeCmd\x12\x11\n\tscan_data\x18\x01 \x01(\x0c\x12\x14\n\x0cscanrsp_data\x18\x02 \x01(\x0c\"8\n\rSetAdvDataCmd\x12\x11\n\tscan_data\x18\x01 \x01(\x0c\x12\x14\n\x0cscanrsp_data\x18\x02 \x01(\x0c\"\x10\n\x0e\x43\x65ntralModeCmd\"\x9f\x02\n\x0c\x43onnectToCmd\x12\x12\n\nbd_address\x18\x01 \x01(\x0c\x12#\n\taddr_type\x18\x02 \x01(\x0e\x32\x10.ble.BleAddrType\x12\x1b\n\x0e\x61\x63\x63\x65ss_address\x18\x03 \x01(\rH\x00\x88\x01\x01\x12\x18\n\x0b\x63hannel_map\x18\x04 \x01(\x0cH\x01\x88\x01\x01\x12\x19\n\x0chop_interval\x18\x05 \x01(\rH\x02\x88\x01\x01\x12\x1a\n\rhop_increment\x18\x06 \x01(\rH\x03\x88\x01\x01\x12\x15\n\x08\x63rc_init\x18\x07 \x01(\rH\x04\x88\x01\x01\x42\x11\n\x0f_access_addressB\x0e\n\x0c_channel_mapB\x0f\n\r_hop_intervalB\x10\n\x0e_hop_incrementB\x0b\n\t_crc_init\"\x8d\x01\n\rSendRawPDUCmd\x12$\n\tdirection\x18\x01 \x01(\x0e\x32\x11.ble.BleDirection\x12\x13\n\x0b\x63onn_handle\x18\x02 \x01(\r\x12\x16\n\x0e\x61\x63\x63\x65ss_address\x18\x03 \x01(\r\x12\x0b\n\x03pdu\x18\x04 \x01(\x0c\x12\x0b\n\x03\x63rc\x18\x05 \x01(\r\x12\x0f\n\x07\x65ncrypt\x18\x06 \x01(\x08\"e\n\nSendPDUCmd\x12$\n\tdirection\x18\x01 \x01(\x0e\x32\x11.ble.BleDirection\x12\x13\n\x0b\x63onn_handle\x18\x02 \x01(\r\x12\x0b\n\x03pdu\x18\x03 \x01(\x0c\x12\x0f\n\x07\x65ncrypt\x18\x04 \x01(\x08\"$\n\rDisconnectCmd\x12\x13\n\x0b\x63onn_handle\x18\x01 \x01(\x05\"<\n\x11PeripheralModeCmd\x12\x11\n\tscan_data\x18\x01 \x01(\x0c\x12\x14\n\x0cscanrsp_data\x18\x02 \x01(\x0c\"\n\n\x08StartCmd\"\t\n\x07StopCmd\")\n\x0fHijackMasterCmd\x12\x16\n\x0e\x61\x63\x63\x65ss_address\x18\x01 \x01(\r\"(\n\x0eHijackSlaveCmd\x12\x16\n\x0e\x61\x63\x63\x65ss_address\x18\x01 \x01(\r\"\'\n\rHijackBothCmd\x12\x16\n\x0e\x61\x63\x63\x65ss_address\x18\x01 \x01(\r\"\x80\x01\n\x10SetEncryptionCmd\x12\x13\n\x0b\x63onn_handle\x18\x01 \x01(\x05\x12\x0f\n\x07\x65nabled\x18\x02 \x01(\x08\x12\x0e\n\x06ll_key\x18\x03 \x01(\x0c\x12\r\n\x05ll_iv\x18\x04 \x01(\x0c\x12\x0b\n\x03key\x18\x05 \x01(\x0c\x12\x0c\n\x04rand\x18\x06 \x01(\x0c\x12\x0c\n\x04\x65\x64iv\x18\x07 \x01(\x0c\"D\n\x0eReactiveJamCmd\x12\x0f\n\x07\x63hannel\x18\x01 \x01(\r\x12\x0f\n\x07pattern\x18\x02 \x01(\x0c\x12\x10\n\x08position\x18\x03 \x01(\r\"\xb5\x04\n\x12PrepareSequenceCmd\x12\x30\n\x07trigger\x18\x01 \x01(\x0b\x32\x1f.ble.PrepareSequenceCmd.Trigger\x12\n\n\x02id\x18\x02 \x01(\r\x12$\n\tdirection\x18\x03 \x01(\x0e\x32\x11.ble.BleDirection\x12\x37\n\x08sequence\x18\x04 \x03(\x0b\x32%.ble.PrepareSequenceCmd.PendingPacket\x1a\x41\n\x10ReceptionTrigger\x12\x0f\n\x07pattern\x18\x01 \x01(\x0c\x12\x0c\n\x04mask\x18\x02 \x01(\x0c\x12\x0e\n\x06offset\x18\x03 \x01(\r\x1a\x32\n\x16\x43onnectionEventTrigger\x12\x18\n\x10\x63onnection_event\x18\x01 \x01(\r\x1a\x0f\n\rManualTrigger\x1a\xd8\x01\n\x07Trigger\x12=\n\treception\x18\x01 \x01(\x0b\x32(.ble.PrepareSequenceCmd.ReceptionTriggerH\x00\x12J\n\x10\x63onnection_event\x18\x02 \x01(\x0b\x32..ble.PrepareSequenceCmd.ConnectionEventTriggerH\x00\x12\x37\n\x06manual\x18\x03 \x01(\x0b\x32%.ble.PrepareSequenceCmd.ManualTriggerH\x00\x42\t\n\x07trigger\x1a\x1f\n\rPendingPacket\x12\x0e\n\x06packet\x18\x01 \x01(\x0c\" \n\x12TriggerSequenceCmd\x12\n\n\x02id\x18\x01 \x01(\r\"\x1f\n\x11\x44\x65leteSequenceCmd\x12\n\n\x02id\x18\x01 \x01(\r\"\x17\n\tTriggered\x12\n\n\x02id\x18\x01 \x01(\r\"s\n\x17\x41\x63\x63\x65ssAddressDiscovered\x12\x16\n\x0e\x61\x63\x63\x65ss_address\x18\x01 \x01(\r\x12\x11\n\x04rssi\x18\x02 \x01(\x05H\x00\x88\x01\x01\x12\x16\n\ttimestamp\x18\x03 \x01(\x04H\x01\x88\x01\x01\x42\x07\n\x05_rssiB\x0c\n\n_timestamp\"\x8c\x01\n\x0e\x41\x64vPduReceived\x12!\n\x08\x61\x64v_type\x18\x01 \x01(\x0e\x32\x0f.ble.BleAdvType\x12\x0c\n\x04rssi\x18\x02 \x01(\x05\x12\x12\n\nbd_address\x18\x03 \x01(\x0c\x12\x10\n\x08\x61\x64v_data\x18\x04 \x01(\x0c\x12#\n\taddr_type\x18\x05 \x01(\x0e\x32\x10.ble.BleAddrType\"\xb2\x01\n\tConnected\x12\x11\n\tinitiator\x18\x01 \x01(\x0c\x12\x12\n\nadvertiser\x18\x02 \x01(\x0c\x12\x16\n\x0e\x61\x63\x63\x65ss_address\x18\x03 \x01(\r\x12\x13\n\x0b\x63onn_handle\x18\x08 \x01(\r\x12\'\n\radv_addr_type\x18\t \x01(\x0e\x32\x10.ble.BleAddrType\x12(\n\x0einit_addr_type\x18\n \x01(\x0e\x32\x10.ble.BleAddrType\"3\n\x0c\x44isconnected\x12\x0e\n\x06reason\x18\x01 \x01(\r\x12\x13\n\x0b\x63onn_handle\x18\x02 \x01(\r\"z\n\x0cSynchronized\x12\x16\n\x0e\x61\x63\x63\x65ss_address\x18\x01 \x01(\r\x12\x10\n\x08\x63rc_init\x18\x02 \x01(\r\x12\x14\n\x0chop_interval\x18\x03 \x01(\r\x12\x15\n\rhop_increment\x18\x04 \x01(\r\x12\x13\n\x0b\x63hannel_map\x18\x05 \x01(\x0c\"(\n\x0e\x44\x65synchronized\x12\x16\n\x0e\x61\x63\x63\x65ss_address\x18\x01 \x01(\r\"3\n\x08Hijacked\x12\x0f\n\x07success\x18\x01 \x01(\x08\x12\x16\n\x0e\x61\x63\x63\x65ss_address\x18\x02 \x01(\r\"O\n\x08Injected\x12\x0f\n\x07success\x18\x01 \x01(\x08\x12\x16\n\x0e\x61\x63\x63\x65ss_address\x18\x02 \x01(\r\x12\x1a\n\x12injection_attempts\x18\x03 \x01(\r\"\xda\x02\n\x0eRawPduReceived\x12$\n\tdirection\x18\x01 \x01(\x0e\x32\x11.ble.BleDirection\x12\x0f\n\x07\x63hannel\x18\x02 \x01(\r\x12\x11\n\x04rssi\x18\x03 \x01(\x05H\x00\x88\x01\x01\x12\x16\n\ttimestamp\x18\x04 \x01(\x04H\x01\x88\x01\x01\x12\x1f\n\x12relative_timestamp\x18\x05 \x01(\x04H\x02\x88\x01\x01\x12\x19\n\x0c\x63rc_validity\x18\x06 \x01(\x08H\x03\x88\x01\x01\x12\x16\n\x0e\x61\x63\x63\x65ss_address\x18\x07 \x01(\r\x12\x0b\n\x03pdu\x18\x08 \x01(\x0c\x12\x0b\n\x03\x63rc\x18\t \x01(\r\x12\x13\n\x0b\x63onn_handle\x18\n \x01(\r\x12\x11\n\tprocessed\x18\x0b \x01(\x08\x12\x11\n\tdecrypted\x18\x0c \x01(\x08\x42\x07\n\x05_rssiB\x0c\n\n_timestampB\x15\n\x13_relative_timestampB\x0f\n\r_crc_validity\"{\n\x0bPduReceived\x12$\n\tdirection\x18\x01 \x01(\x0e\x32\x11.ble.BleDirection\x12\x0b\n\x03pdu\x18\x02 \x01(\x0c\x12\x13\n\x0b\x63onn_handle\x18\x03 \x01(\r\x12\x11\n\tprocessed\x18\x04 \x01(\x08\x12\x11\n\tdecrypted\x18\x05 \x01(\x08\"\xbc\x0c\n\x07Message\x12+\n\x0bset_bd_addr\x18\x01 \x01(\x0b\x32\x14.ble.SetBdAddressCmdH\x00\x12%\n\tsniff_adv\x18\x02 \x01(\x0b\x32\x10.ble.SniffAdvCmdH\x00\x12!\n\x07jam_adv\x18\x03 \x01(\x0b\x32\x0e.ble.JamAdvCmdH\x00\x12/\n\x0cjam_adv_chan\x18\x04 \x01(\x0b\x32\x17.ble.JamAdvOnChannelCmdH\x00\x12-\n\rsniff_connreq\x18\x05 \x01(\x0b\x32\x14.ble.SniffConnReqCmdH\x00\x12.\n\x08sniff_aa\x18\x06 \x01(\x0b\x32\x1a.ble.SniffAccessAddressCmdH\x00\x12-\n\nsniff_conn\x18\x07 \x01(\x0b\x32\x17.ble.SniffActiveConnCmdH\x00\x12#\n\x08jam_conn\x18\x08 \x01(\x0b\x32\x0f.ble.JamConnCmdH\x00\x12%\n\tscan_mode\x18\t \x01(\x0b\x32\x10.ble.ScanModeCmdH\x00\x12#\n\x08\x61\x64v_mode\x18\n \x01(\x0b\x32\x0f.ble.AdvModeCmdH\x00\x12*\n\x0cset_adv_data\x18\x0b \x01(\x0b\x32\x12.ble.SetAdvDataCmdH\x00\x12+\n\x0c\x63\x65ntral_mode\x18\x0c \x01(\x0b\x32\x13.ble.CentralModeCmdH\x00\x12$\n\x07\x63onnect\x18\r \x01(\x0b\x32\x11.ble.ConnectToCmdH\x00\x12*\n\x0csend_raw_pdu\x18\x0e \x01(\x0b\x32\x12.ble.SendRawPDUCmdH\x00\x12#\n\x08send_pdu\x18\x0f \x01(\x0b\x32\x0f.ble.SendPDUCmdH\x00\x12(\n\ndisconnect\x18\x10 \x01(\x0b\x32\x12.ble.DisconnectCmdH\x00\x12-\n\x0bperiph_mode\x18\x11 \x01(\x0b\x32\x16.ble.PeripheralModeCmdH\x00\x12\x1e\n\x05start\x18\x12 \x01(\x0b\x32\r.ble.StartCmdH\x00\x12\x1c\n\x04stop\x18\x13 \x01(\x0b\x32\x0c.ble.StopCmdH\x00\x12-\n\rhijack_master\x18\x14 \x01(\x0b\x32\x14.ble.HijackMasterCmdH\x00\x12+\n\x0chijack_slave\x18\x15 \x01(\x0b\x32\x13.ble.HijackSlaveCmdH\x00\x12)\n\x0bhijack_both\x18\x16 \x01(\x0b\x32\x12.ble.HijackBothCmdH\x00\x12+\n\nencryption\x18! \x01(\x0b\x32\x15.ble.SetEncryptionCmdH\x00\x12+\n\x0creactive_jam\x18\" \x01(\x0b\x32\x13.ble.ReactiveJamCmdH\x00\x12*\n\x07prepare\x18# \x01(\x0b\x32\x17.ble.PrepareSequenceCmdH\x00\x12*\n\x07trigger\x18$ \x01(\x0b\x32\x17.ble.TriggerSequenceCmdH\x00\x12,\n\ndelete_seq\x18& \x01(\x0b\x32\x16.ble.DeleteSequenceCmdH\x00\x12/\n\x07\x61\x61_disc\x18\x17 \x01(\x0b\x32\x1c.ble.AccessAddressDiscoveredH\x00\x12&\n\x07\x61\x64v_pdu\x18\x18 \x01(\x0b\x32\x13.ble.AdvPduReceivedH\x00\x12#\n\tconnected\x18\x19 \x01(\x0b\x32\x0e.ble.ConnectedH\x00\x12)\n\x0c\x64isconnected\x18\x1a \x01(\x0b\x32\x11.ble.DisconnectedH\x00\x12)\n\x0csynchronized\x18\x1b \x01(\x0b\x32\x11.ble.SynchronizedH\x00\x12!\n\x08hijacked\x18\x1c \x01(\x0b\x32\r.ble.HijackedH\x00\x12\x1f\n\x03pdu\x18\x1d \x01(\x0b\x32\x10.ble.PduReceivedH\x00\x12&\n\x07raw_pdu\x18\x1e \x01(\x0b\x32\x13.ble.RawPduReceivedH\x00\x12!\n\x08injected\x18\x1f \x01(\x0b\x32\r.ble.InjectedH\x00\x12-\n\x0e\x64\x65synchronized\x18  \x01(\x0b\x32\x13.ble.DesynchronizedH\x00\x12#\n\ttriggered\x18% \x01(\x0b\x32\x0e.ble.TriggeredH\x00\x42\x05\n\x03msg*\xcf\x03\n\nBleCommand\x12\x10\n\x0cSetBdAddress\x10\x00\x12\x0c\n\x08SniffAdv\x10\x01\x12\n\n\x06JamAdv\x10\x02\x12\x13\n\x0fJamAdvOnChannel\x10\x03\x12\x0f\n\x0bReactiveJam\x10\x04\x12\x10\n\x0cSniffConnReq\x10\x05\x12\x16\n\x12SniffAccessAddress\x10\x06\x12\x13\n\x0fSniffActiveConn\x10\x07\x12\x0b\n\x07JamConn\x10\x08\x12\x0c\n\x08ScanMode\x10\t\x12\x0b\n\x07\x41\x64vMode\x10\n\x12\x0e\n\nSetAdvData\x10\x0b\x12\x0f\n\x0b\x43\x65ntralMode\x10\x0c\x12\r\n\tConnectTo\x10\r\x12\x0e\n\nSendRawPDU\x10\x0e\x12\x0b\n\x07SendPDU\x10\x0f\x12\x0e\n\nDisconnect\x10\x10\x12\x12\n\x0ePeripheralMode\x10\x11\x12\t\n\x05Start\x10\x12\x12\x08\n\x04Stop\x10\x13\x12\x11\n\rSetEncryption\x10\x14\x12\x10\n\x0cHijackMaster\x10\x15\x12\x0f\n\x0bHijackSlave\x10\x16\x12\x0e\n\nHijackBoth\x10\x17\x12\x13\n\x0fPrepareSequence\x10\x18\x12\x13\n\x0fTriggerSequence\x10\x19\x12\x12\n\x0e\x44\x65leteSequence\x10\x1a*w\n\nBleAdvType\x12\x0f\n\x0b\x41\x44V_UNKNOWN\x10\x00\x12\x0b\n\x07\x41\x44V_IND\x10\x01\x12\x12\n\x0e\x41\x44V_DIRECT_IND\x10\x02\x12\x13\n\x0f\x41\x44V_NONCONN_IND\x10\x03\x12\x10\n\x0c\x41\x44V_SCAN_IND\x10\x04\x12\x10\n\x0c\x41\x44V_SCAN_RSP\x10\x05*v\n\x0c\x42leDirection\x12\x0b\n\x07UNKNOWN\x10\x00\x12\x13\n\x0fMASTER_TO_SLAVE\x10\x01\x12\x13\n\x0fSLAVE_TO_MASTER\x10\x02\x12\x16\n\x12INJECTION_TO_SLAVE\x10\x03\x12\x17\n\x13INJECTION_TO_MASTER\x10\x04*%\n\x0b\x42leAddrType\x12\n\n\x06PUBLIC\x10\x00\x12\n\n\x06RANDOM\x10\x01\x62\x06proto3')

_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, globals())
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, 'whad.protocol.ble.ble_pb2', globals())
if _descriptor._USE_C_DESCRIPTORS == False:

  DESCRIPTOR._options = None
  _BLECOMMAND._serialized_start=5287
  _BLECOMMAND._serialized_end=5750
  _BLEADVTYPE._serialized_start=5752
  _BLEADVTYPE._serialized_end=5871
  _BLEDIRECTION._serialized_start=5873
  _BLEDIRECTION._serialized_end=5991
  _BLEADDRTYPE._serialized_start=5993
  _BLEADDRTYPE._serialized_end=6030
  _SETBDADDRESSCMD._serialized_start=36
  _SETBDADDRESSCMD._serialized_end=110
  _SNIFFADVCMD._serialized_start=112
  _SNIFFADVCMD._serialized_end=188
  _JAMADVCMD._serialized_start=190
  _JAMADVCMD._serialized_end=201
  _JAMADVONCHANNELCMD._serialized_start=203
  _JAMADVONCHANNELCMD._serialized_end=240
  _SNIFFCONNREQCMD._serialized_start=242
  _SNIFFCONNREQCMD._serialized_end=353
  _SNIFFACCESSADDRESSCMD._serialized_start=355
  _SNIFFACCESSADDRESSCMD._serialized_end=406
  _SNIFFACTIVECONNCMD._serialized_start=409
  _SNIFFACTIVECONNCMD._serialized_end=565
  _JAMCONNCMD._serialized_start=567
  _JAMCONNCMD._serialized_end=603
  _SCANMODECMD._serialized_start=605
  _SCANMODECMD._serialized_end=639
  _ADVMODECMD._serialized_start=641
  _ADVMODECMD._serialized_end=694
  _SETADVDATACMD._serialized_start=696
  _SETADVDATACMD._serialized_end=752
  _CENTRALMODECMD._serialized_start=754
  _CENTRALMODECMD._serialized_end=770
  _CONNECTTOCMD._serialized_start=773
  _CONNECTTOCMD._serialized_end=1060
  _SENDRAWPDUCMD._serialized_start=1063
  _SENDRAWPDUCMD._serialized_end=1204
  _SENDPDUCMD._serialized_start=1206
  _SENDPDUCMD._serialized_end=1307
  _DISCONNECTCMD._serialized_start=1309
  _DISCONNECTCMD._serialized_end=1345
  _PERIPHERALMODECMD._serialized_start=1347
  _PERIPHERALMODECMD._serialized_end=1407
  _STARTCMD._serialized_start=1409
  _STARTCMD._serialized_end=1419
  _STOPCMD._serialized_start=1421
  _STOPCMD._serialized_end=1430
  _HIJACKMASTERCMD._serialized_start=1432
  _HIJACKMASTERCMD._serialized_end=1473
  _HIJACKSLAVECMD._serialized_start=1475
  _HIJACKSLAVECMD._serialized_end=1515
  _HIJACKBOTHCMD._serialized_start=1517
  _HIJACKBOTHCMD._serialized_end=1556
  _SETENCRYPTIONCMD._serialized_start=1559
  _SETENCRYPTIONCMD._serialized_end=1687
  _REACTIVEJAMCMD._serialized_start=1689
  _REACTIVEJAMCMD._serialized_end=1757
  _PREPARESEQUENCECMD._serialized_start=1760
  _PREPARESEQUENCECMD._serialized_end=2325
  _PREPARESEQUENCECMD_RECEPTIONTRIGGER._serialized_start=1939
  _PREPARESEQUENCECMD_RECEPTIONTRIGGER._serialized_end=2004
  _PREPARESEQUENCECMD_CONNECTIONEVENTTRIGGER._serialized_start=2006
  _PREPARESEQUENCECMD_CONNECTIONEVENTTRIGGER._serialized_end=2056
  _PREPARESEQUENCECMD_MANUALTRIGGER._serialized_start=2058
  _PREPARESEQUENCECMD_MANUALTRIGGER._serialized_end=2073
  _PREPARESEQUENCECMD_TRIGGER._serialized_start=2076
  _PREPARESEQUENCECMD_TRIGGER._serialized_end=2292
  _PREPARESEQUENCECMD_PENDINGPACKET._serialized_start=2294
  _PREPARESEQUENCECMD_PENDINGPACKET._serialized_end=2325
  _TRIGGERSEQUENCECMD._serialized_start=2327
  _TRIGGERSEQUENCECMD._serialized_end=2359
  _DELETESEQUENCECMD._serialized_start=2361
  _DELETESEQUENCECMD._serialized_end=2392
  _TRIGGERED._serialized_start=2394
  _TRIGGERED._serialized_end=2417
  _ACCESSADDRESSDISCOVERED._serialized_start=2419
  _ACCESSADDRESSDISCOVERED._serialized_end=2534
  _ADVPDURECEIVED._serialized_start=2537
  _ADVPDURECEIVED._serialized_end=2677
  _CONNECTED._serialized_start=2680
  _CONNECTED._serialized_end=2858
  _DISCONNECTED._serialized_start=2860
  _DISCONNECTED._serialized_end=2911
  _SYNCHRONIZED._serialized_start=2913
  _SYNCHRONIZED._serialized_end=3035
  _DESYNCHRONIZED._serialized_start=3037
  _DESYNCHRONIZED._serialized_end=3077
  _HIJACKED._serialized_start=3079
  _HIJACKED._serialized_end=3130
  _INJECTED._serialized_start=3132
  _INJECTED._serialized_end=3211
  _RAWPDURECEIVED._serialized_start=3214
  _RAWPDURECEIVED._serialized_end=3560
  _PDURECEIVED._serialized_start=3562
  _PDURECEIVED._serialized_end=3685
  _MESSAGE._serialized_start=3688
  _MESSAGE._serialized_end=5284
# @@protoc_insertion_point(module_scope)
