DISCOVERY_SAMPLE_MESSAGES = {
        "reset_query":"""
        discovery {
          reset_query {
          }
        }
        """,
        "ready_resp":"""
        discovery {
          ready_resp {
          }
        }
        """,
        "info_query":"""
        discovery {
          info_query {
            proto_ver: 256
          }
        }
        """,
        "info_resp":"""
        discovery {
          info_resp {
            type: 1
            devid: "aabbccddeeffaabbccddeeff"
            proto_min_ver: 256
            fw_version_major: 1
            capabilities: 50331862
            capabilities: 67108878
          }
        }
        """,
        "domain_query":"""
        discovery {
          domain_query {
            domain: 50331648
          }
        }
        """,
        "domain_resp":"""
        discovery {
          domain_resp {
            domain: 50331648
            supported_commands: 4155410
          }
        }
        """,
}

GENERIC_SAMPLE_MESSAGES = {
        "cmd_result" : """
            generic {
                cmd_result {
                }
            }""",
}

BLE_SAMPLE_MESSAGES = {
        "stop":"""
        ble {
          stop {
          }
        }""",
        "sniff_adv":"""
        ble {
          sniff_adv {
            channel: 37
            bd_address: ""
          }
        }
        """,
        "sniff_connreq":"""
        ble {
          sniff_connreq {
            channel: 37
            bd_address: ""
          }
        }
        """,

        "start":"""
        ble {
          start {
          }
        }
        """,
        "raw_pdu":"""
        ble {
          raw_pdu {
            channel: 37
            rssi: -76
            timestamp: 2309056938
            crc_validity: true
            access_address: 2391391958
            pdu: ""
            crc: 13516492
          }
        }
        """
}
