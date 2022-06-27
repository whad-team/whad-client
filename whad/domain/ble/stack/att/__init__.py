"""
BLE ATT layer manager
"""

from scapy.layers.bluetooth import ATT_Error_Response, ATT_Exchange_MTU_Request, \
    ATT_Exchange_MTU_Response, ATT_Execute_Write_Request, ATT_Execute_Write_Response, \
    ATT_Find_By_Type_Value_Request, ATT_Find_By_Type_Value_Response, ATT_Find_Information_Request, \
    ATT_Find_Information_Response, ATT_Prepare_Write_Request, ATT_Prepare_Write_Response, \
    ATT_Read_Blob_Request, ATT_Handle_Value_Indication, ATT_Handle_Value_Notification, \
    ATT_Read_Blob_Response, ATT_Read_By_Group_Type_Request, ATT_Read_By_Group_Type_Response, \
    ATT_Read_By_Type_Request, ATT_Read_By_Type_Response, ATT_Read_Multiple_Request, ATT_Read_Multiple_Response, \
    ATT_Read_Request, ATT_Read_Response, ATT_Write_Command, ATT_Write_Response, ATT_Write_Request, \
    ATT_Read_By_Type_Request_128bit, ATT_Hdr


class BleATT(object):

    def __init__(self, l2cap):
        self.__l2cap = l2cap

    def on_packet(self, att_pkt):
        """Dispatch ATT packet.
        """
        if ATT_Error_Response in att_pkt:
            self.on_error_response(att_pkt.getlayer(ATT_Error_Response))
        elif ATT_Exchange_MTU_Request in att_pkt:
            self.on_exch_mtu_request(att_pkt.getlayer(ATT_Exchange_MTU_Request))
        elif ATT_Exchange_MTU_Response in att_pkt:
            self.on_exch_mtu_response(att_pkt.getlayer(ATT_Exchange_MTU_Response))
        elif ATT_Read_By_Type_Request in att_pkt:
            self.on_read_by_type_request(att_pkt.getlayer(ATT_Read_By_Type_Request))

    def on_error_response(self, error_resp):
        pass

    def on_exch_mtu_request(self, mtu_req):
        """Handle ATT Exchange MTU request, update L2CAP TX MTU and returns
        our MTU.

        :param mtu_req ATT_Exchange_MTU_Request: MTU request
        """

        # Update L2CAP Client MTU
        self.__l2cap.remote_mtu = mtu_req.mtu
        
        # Send back our MTU.
        self.__l2cap.send(ATT_Hdr()/ATT_Exchange_MTU_Response(
            mtu=self.__l2cap.local_mtu
        ))

    def on_exch_mtu_response(self, mtu_resp):
        """Update L2CAP remote MTU based on ATT_Exchange_MTU_Response.

        :param mtu_resp ATT_Exchange_MTU_Response: MTU response
        """
        self.__l2cap.remote_mtu = mtu_resp.mtu

