# AEM :2210
# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Two OpenFlow 1.0 L3 Static Routers and two OpenFlow 1.0 L2 learning switches.
"""


from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_0
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
from ryu.lib.packet import ether_types

BROADCAST = "FF:FF:FF:FF:FF:FF"
LAN1 = "192.168.10.0"
LAN2 = "192.168.20.0"
ROUTER1_IP_LEFT = "192.168.10.1"
ROUTER1_MAC_LEFT = "00:00:00:00:10:01"
ROUTER1_MAC_RIGHT = "00:00:00:00:30:01"
ROUTER2_IP_RIGHT = "192.168.20.1"
ROUTER2_MAC_LEFT = "00:00:00:00:30:02"
ROUTER2_MAC_RIGHT = "00:00:00:00:20:01"





"""
fill in the code here for any used constant (optional)
"""

class SimpleSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

    def add_flow(self, datapath, match, actions):
        ofproto = datapath.ofproto

        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=ofproto.OFP_DEFAULT_PRIORITY,
            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        ofproto = datapath.ofproto

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        dst = eth.dst
        src = eth.src

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, msg.in_port)

        if dpid == 0x2 or dpid == 0x3:
            self.mac_to_port.setdefault(dpid, {})
            # learn a mac address to avoid FLOOD next time.
            self.mac_to_port[dpid][src] = msg.in_port
            if dst in self.mac_to_port[dpid]:
                out_port = self.mac_to_port[dpid][dst]
            else:
                out_port = ofproto.OFPP_FLOOD
            match = datapath.ofproto_parser.OFPMatch(
                in_port=msg.in_port, dl_dst=haddr_to_bin(dst))
            actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]
            # install a flow to avoid packet_in next time
            if out_port != ofproto.OFPP_FLOOD:
                self.add_flow(datapath, match, actions)
            data = None
            if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                data = msg.data
            out = datapath.ofproto_parser.OFPPacketOut(
                datapath=datapath, buffer_id=msg.buffer_id, in_port=msg.in_port,
                actions=actions, data=data)
            datapath.send_msg(out)
            return
        if dpid == 0x1A:
            if eth.ethertype == ether_types.ETH_TYPE_ARP: # this packet is ARP packet
                arp_pkt = pkt.get_protocol(arp.arp)
                if arp_pkt.opcode == 1 and arp_pkt.dst_ip == ROUTER1_IP_LEFT:
                        self.send_arp_reply(datapath,ROUTER1_MAC_LEFT,ROUTER1_IP_LEFT,src,arp_pkt.src_ip,msg.in_port)
                return
            elif eth.ethertype == ether_types.ETH_TYPE_IP: # this packet is IP packet
                ip_pkt = pkt.get_protocol(ipv4.ipv4)
                src_ip = ip_pkt.src
                dst_ip = ip_pkt.dst
                if msg.in_port == 2:
                        if dst_ip[:10] == LAN1[:10]:
                           
                            match = datapath.ofproto_parser.OFPMatch(dl_type = 0x0800,in_port = 2,nw_dst_mask = 24,nw_dst = LAN1)
                            actions =[datapath.ofproto_parser.OFPActionSetDlSrc(ROUTER1_MAC_LEFT),datapath.ofproto_parser.OFPActionSetDlDst(BROADCAST),
                                      datapath.ofproto_parser.OFPActionOutput(1)]
                elif msg.in_port == 1:
                        if dst_ip[:10] == LAN2[:10]:
                           
                                if dst == ROUTER2_MAC_LEFT:
                                
                                    match = datapath.ofproto_parser.OFPMatch(dl_type = 0x0800,in_port = 1,nw_dst_mask = 24,nw_dst = LAN2)
                                    actions =[datapath.ofproto_parser.OFPActionSetDlSrc(ROUTER1_MAC_LEFT),datapath.ofproto_parser.OFPActionSetDlDst(ROUTER2_MAC_LEFT),
                                              datapath.ofproto_parser.OFPActionOutput(3)]
                                    self.add_flow(datapath,match,actions)
                                    return   
                                
                                match = datapath.ofproto_parser.OFPMatch(dl_type = 0x0800,in_port = 1,nw_dst_mask = 24,nw_dst = LAN2)
                                actions = [datapath.ofproto_parser.OFPActionSetDlSrc(ROUTER1_MAC_RIGHT),datapath.ofproto_parser.OFPActionSetDlDst(ROUTER2_MAC_LEFT),
                                           datapath.ofproto_parser.OFPActionOutput(2)]

                self.add_flow(datapath,match,actions)
                out = datapath.ofproto_parser.OFPPacketOut(datapath=datapath,buffer_id=0xffffffff,in_port=msg.in_port,
							   actions=actions,data=msg.data)
                datapath.send_msg(out)
                return
            return
        if dpid == 0x1B:
            if eth.ethertype == ether_types.ETH_TYPE_ARP: # this packet is ARP packet
                arp_pkt = pkt.get_protocol(arp.arp)
                if arp_pkt.opcode == 1 and arp_pkt.dst_ip == ROUTER2_IP_RIGHT:
                        self.send_arp_reply(datapath,ROUTER2_MAC_RIGHT,ROUTER2_IP_RIGHT,src,arp_pkt.src_ip,msg.in_port)
                return
            elif eth.ethertype == ether_types.ETH_TYPE_IP: # this packet is IP packet
                if msg.in_port == 2:
                        match = datapath.ofproto_parser.OFPMatch(dl_type = 0x0800,in_port = 2,nw_dst_mask = 24,nw_dst = LAN2)
                        actions = [datapath.ofproto_parser.OFPActionSetDlSrc(ROUTER2_MAC_RIGHT),datapath.ofproto_parser.OFPActionSetDlDst(BROADCAST),
                                   datapath.ofproto_parser.OFPActionOutput(1)]
                elif msg.in_port == 1:
                    
                    
                        if dst == ROUTER1_MAC_LEFT :
                                
                                    match = datapath.ofproto_parser.OFPMatch(dl_type = 0x0800,in_port = 1,nw_dst_mask = 24,nw_dst = LAN1)
                                    actions =[datapath.ofproto_parser.OFPActionSetDlSrc(ROUTER2_MAC_LEFT),datapath.ofproto_parser.OFPActionSetDlDst(ROUTER1_MAC_LEFT),
                                              datapath.ofproto_parser.OFPActionOutput(3)]
                                    
                                    self.add_flow(datapath,match,actions)
                                    return             
                                    
                        
                        match = datapath.ofproto_parser.OFPMatch(dl_type = 0x0800,in_port = 1,nw_dst_mask = 24,nw_dst = LAN1)
                        actions = [datapath.ofproto_parser.OFPActionSetDlSrc(ROUTER2_MAC_LEFT),datapath.ofproto_parser.OFPActionSetDlDst(ROUTER1_MAC_RIGHT),
                                   datapath.ofproto_parser.OFPActionOutput(2)]

                self.add_flow(datapath,match,actions)
                out = datapath.ofproto_parser.OFPPacketOut(datapath=datapath,buffer_id=0xffffffff,in_port=msg.in_port,
							   actions=actions,data=msg.data)
                datapath.send_msg(out)
                return
            return

    """
    fill in the code here for the ARP reply functions.
    """
    
    
    
    
    def send_arp_reply(self, datapath, srcMac, srcIp, dstMac, dstIp, outPort):
        e = ethernet.ethernet(dstMac, srcMac, ether_types.ETH_TYPE_ARP)
        a = arp.arp(1, 0x0800, 6, 4, 2, srcMac, srcIp, dstMac, dstIp)
        p = packet.Packet()
        p.add_protocol(e)
        p.add_protocol(a)
        p.serialize()

        actions = [datapath.ofproto_parser.OFPActionOutput(outPort, 0)]
        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=0xffffffff,
            in_port=datapath.ofproto.OFPP_CONTROLLER,
            actions=actions,
            data=p.data)
        datapath.send_msg(out)

    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def _port_status_handler(self, ev):
        msg = ev.msg
        reason = msg.reason
        port_no = msg.desc.port_no

        ofproto = msg.datapath.ofproto
        if reason == ofproto.OFPPR_ADD:
            self.logger.info("port added %s", port_no)
        elif reason == ofproto.OFPPR_DELETE:
            self.logger.info("port deleted %s", port_no)
        elif reason == ofproto.OFPPR_MODIFY:
            self.logger.info("port modified %s", port_no)
        else:
            self.logger.info("Illeagal port state %s %s", port_no, reason)
