# -*- coding: UTF-8 -*-
#import time
# Copyright (C) 2016 Li Cheng at Beijing University of Posts
# and Telecommunications. www.muzixing.com
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# conding=utf-8

import numpy as np
import networkx as nx 
import sys
from threading import Timer
from copy import deepcopy
from ryu.base import app_manager
#引入openFlow 版本库
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto.ofproto_v1_3_parser import OFPActionSetField
#引入事件相关库
from ryu.controller import ofp_event, dpset
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
#引入报文解析相关的库
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
from ryu.lib.packet import ether_types
#...
from collections import defaultdict
#引入拓扑发现的相关库
from ryu.topology.api import get_switch,get_link
from ryu.topology import event,switches
from ryu.controller import handler
from ryu.app import client_ryu1

adjacency = defaultdict(lambda: defaultdict(lambda: [None, None, None, True]))
path_map = defaultdict(lambda: defaultdict(lambda: (None, None)))
sws = []
switches={}
mac_map={} 
DpPortMacList = defaultdict(lambda: defaultdict(lambda: None))
RouteInfoOfMac = {}

RET_ERROR = -1
RET_OK = 0
ARP = arp.arp.__name__
ETHERNET_MULTICAST = "ff:ff:ff:ff:ff:ff"

class L2Switch(app_manager.RyuApp):    
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {"Controller_multi":client_ryu1.Controller}
    
    def __init__(self, *args, **kwargs):        
        super(L2Switch, self).__init__(*args, **kwargs)
	self.network = kwargs["Controller_multi"]
        self.mac_to_port = {}
        self.arp_table = {} 
        self.datapaths = {}
        self.datapath_list={}
        self.arpBroadPkgTable = {}
        self.topology_api_app=self

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        instruction = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        self.add_flow(datapath, 0, 0, match, instruction)
        self.add_flow(datapath, 1, 0, match, instruction)
        return
	
    def add_flow(self, datapath, tableID, priority, match, instruction, hardTimeout = 0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        mod = parser.OFPFlowMod(datapath=datapath, table_id=tableID, priority=priority,
                                    hard_timeout=hardTimeout,
                                    match=match, instructions=instruction)   
        datapath.send_msg(mod)
        return

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
      
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes", ev.msg.msg_len, ev.msg.total_len)
            
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = datapath.id - 17592186044416;
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth1 = pkt.get_protocols(ethernet.ethernet)[0]
        eth2 = None

        if len(pkt.get_protocols(ethernet.ethernet(ethertype=0x88E7))) == 2:
            eth2 = pkt.get_protocols(ethernet.ethernet(ethertype=0x88E7))[1]

        if eth1.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        if eth1.ethertype ==  ether_types.ETH_TYPE_IPV6:
            # ignore IPV6 packet
            return
        
        ethDst = None
        ethSrc = None     
        if eth2:
            ethSrc = eth2.src
            ethDst = eth2.dst
        else:
            ethSrc = eth1.src
            ethDst = eth1.dst

        self.logger.info("packet in %s %s %s %s", dpid, ethSrc, ethDst, in_port)
        #self.mac_to_port.setdefault(dpid, {})
       
        header_list = dict((p.protocol_name, p) for p in pkt.protocols if type(p) != str)
	if ARP in header_list:
            arp_dst_ip = header_list[ARP].dst_ip
            self.arp_table[header_list[ARP].src_ip] = ethSrc
            if ethDst == ETHERNET_MULTICAST:
                if (dpid, ethSrc, arp_dst_ip) in self.arpBroadPkgTable and self.arpBroadPkgTable[(dpid, ethSrc, arp_dst_ip)] != in_port:
                        return
                else:
                    self.arpBroadPkgTable[(dpid, ethSrc, arp_dst_ip)] = in_port
        a = 2 # 域个数
        b = 2 # 每个域点个数 
        mac_map = {}
        for i in range(1, a+1):
            for j in range(1, b+1):
                if (i-1)*b+j < 16:
                    mac_map['00:00:00:00:00:0' + hex((i-1)*b+j)[2:] ] = ((i-1)*b+j, 1)
                else:
                    mac_map['00:00:00:00:00:' + hex((i-1)*b+j)[2:] ] = ((i-1)*b+j, 1)

        for i in range(1, a+1):
            for j in range(1, b+1):
                self.mac_to_port.setdefault((i-1)*b+j, {})
                for k in range(1, a*b+1):
                    if (i-1)*b+j < 16:
                        if k == (i-1)*b+j:
                            self.mac_to_port[(i-1)*b+j]['00:00:00:00:00:0' + hex(k)[2:]] = 1
                        else:
                            self.mac_to_port[(i-1)*b+j]['00:00:00:00:00:0' + hex(k)[2:]] = 2
                    else:
                        if k == (i-1)*b+j:
                            self.mac_to_port[(i-1)*b+j]['00:00:00:00:00:' + hex(k)[2:]] = 1
                        else:
                            self.mac_to_port[(i-1)*b+j]['00:00:00:00:00:' + hex(k)[2:]] = 2
        
	
        if ethDst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][ethDst]
            temp_src=mac_map[ethSrc]
            temp_dst=mac_map[ethDst]
            
            self.InstallPath(ethDst, temp_src[0],temp_dst[0], temp_src[1], temp_dst[1], ev)
            
        else:
            out_port = ofproto.OFPP_FLOOD
            
        actions = [parser.OFPActionOutput(out_port)]

        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=ethDst)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port, actions=actions, data=data)
        print "send_msg out: ", out
        datapath.send_msg(out)
        return

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def state_change_handler(self, ev):
        datapath = ev.datapath
        dpid = datapath.id - 17592186044416
        if ev.state == MAIN_DISPATCHER:
            self.logger.info("[INFO]: State-Change Message (MAIN_DISPATCHER) Received! From dp=0x%016x", dpid)
            if dpid == 1:
                self.datapaths[dpid] = datapath
            if not dpid in self.datapath_list:
                self.datapath_list[dpid]=datapath
                
        elif ev.state == DEAD_DISPATCHER:
            self.logger.info("[INFO]: State-Change Message (DEAD_DISPATCHER) Received! From dp=0x%016x", dpid)
            if dpid in self.datapaths:
                del self.datapaths[dpid]

    def InstallPath(self, dstMac, src_sw, dst_sw, in_port, last_port, ev):
        global sws
        global adjacency
        global DpPortMacList
        
        dp_port = {}
        a = 2 # 域个数 
        b = 2 # 每个域点个数
        for i in range(1, a+1):
            for j in range(1, b+1):
                dp_port.setdefault((i-1)*b+j,{})
                dp_port[(i-1)*b+j]['port'] = 2
                if ((i-1)*b+j-1)*2 < 16:
                    dp_port[(i-1)*b+j]['mac'] = '02:00:00:00:0'+ hex(((i-1)*b+j-1)*2)[2:] +':00'
                else:
                    dp_port[(i-1)*b+j]['mac'] = '02:00:00:00:'+ hex(((i-1)*b+j-1)*2)[2:] +':00'

        topo = self.network.get_whole_graph()

        sws = topo.nodes(data=True)

        links = topo.edges()
        for sw_src, sw_dst in links:
            disable = topo[sw_src][sw_dst].get('disable', False)
            
            weight = 1
            
            src_port = dp_port.get(sw_src, {}).get('port', None)
            dst_port = dp_port.get(sw_dst, {}).get('port', None)
            adjacency[sw_src][sw_dst]=[src_port, dst_port, weight, disable]
            DpPortMacList[sw_src][src_port]=dp_port.get(sw_src, {}).get('mac', None)
            DpPortMacList[sw_dst][dst_port]=dp_port.get(sw_dst, {}).get('mac', None)
        print(links, src_sw, dst_sw)
	pcp = 1
	if pcp == 1:
	    path = nx.shortest_path(topo, src_sw, dst_sw, weight = 'rssi')
	    print("path1")
	    print(path)    
	else:
	    path = nx.bellman_ford_path(topo, src_sw, dst_sw)
	    print("path2")
	    print(path)
        if path is None:
            return RET_ERROR

	p = []
        
        for s1, s2 in zip(path[:-1], path[1:]):
            out_port = adjacency[s1][s2][0]
            p.append((s1, in_port, out_port))
            in_port = adjacency[s1][s2][1]
        p.append((dst_sw, in_port, last_port))
        print(p)
        
        
        self.DoInstallPath(dstMac, p, ev, pcp)
        return RET_OK

    def DoInstallPath(self, dstMac, p, ev, pcp):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        print "[INFO]: Install the Path to switch......"
        
        pNum = len(p)
        pCnt = 1
        for sw, in_port, out_port in p:
            

            if sw in self.datapath_list.keys():


                datapath=self.datapath_list[sw]
                tableID = 0
                # 获取自己 “出端口” 的MAC地址
                selfSwitchMac = DpPortMacList[sw][out_port]
                if pCnt == 1:
                    # 获取下一跳对方 “入端口” 的MAC地址
                    if pNum == 1:
                        continue
                    routInfo = p[pCnt]
                    nextSwitchMac = DpPortMacList[routInfo[0]][routInfo[1]]
                    print "[INFO]: 0x%016x is \"First\" Node,   Next_Node's Mac (0x%016x,%d): %s" %(sw, routInfo[0], routInfo[1], nextSwitchMac)
                
                    match = parser.OFPMatch(in_port=in_port, eth_dst=dstMac)
                    actions = [parser.OFPActionPushPbb(0x88e7),parser.OFPActionPushVlan(0x8100),OFPActionSetField(eth_src=selfSwitchMac), OFPActionSetField(eth_dst=nextSwitchMac),OFPActionSetField(vlan_vid=1), OFPActionSetField(vlan_pcp=pcp), parser.OFPActionOutput(out_port)]
                
                    instruction = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
                    self.add_flow(datapath, tableID, 1, match, instruction)
                elif pCnt == pNum:
                    # 1. 获取上一跳对方 “出端口” 的MAC地址
                    preNode = pCnt - 2
                    routInfo = p[preNode]
                    preSwitchMac = DpPortMacList[routInfo[0]][routInfo[2]]
                    print "[INFO]: 0x%016x is \"Last\" Node,    Pre_Node's Mac(0x%016x,%d): %s" %(sw, routInfo[0], routInfo[2], preSwitchMac)
                
                    # 2. 如果是上一跳送过来的报文，先去掉PBB头，再转table1处理
                    # 2.1 如果是上一跳送过来的报文，先去掉PBB头
                    match = parser.OFPMatch(in_port=in_port, eth_src=preSwitchMac, eth_type=0x88E7,vlan_vid=1,vlan_pcp=pcp)
                    actions = [parser.OFPActionPopPbb(),parser.OFPActionPopVlan()]
                    instruction = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions), parser.OFPInstructionGotoTable(1)]
                    self.add_flow(datapath, tableID, 1, match, instruction)
                    # 2.2 table1处理
                    tableID = 1
                    match = parser.OFPMatch(in_port=in_port, eth_dst=dstMac)
                    if in_port == out_port:
                        out_port = ofproto_v1_3.OFPP_IN_PORT
                    actions = [parser.OFPActionOutput(out_port)]
                    instruction = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
                    self.add_flow(datapath, tableID, 1, match, instruction)
                else:
                    # 1. 获取上一跳对方 “出端口” 的MAC地址
                    preNode = pCnt - 2
                    preRoutInfo = p[preNode]
                    preSwitchMac = DpPortMacList[preRoutInfo[0]][preRoutInfo[2]]
                    # 2. 获取下一跳对方 “入端口” 的MAC地址
                    routInfo = p[pCnt]
                    nextSwitchMac = DpPortMacList[routInfo[0]][routInfo[1]]
                    print "[INFO]: 0x%016x is \"Middle\" Node,  Pre_Node is Mac(0x%016x,%d): %s , Next_Node's Mac(0x%016x,%d): %s" %(sw, preRoutInfo[0], preRoutInfo[2], preSwitchMac, routInfo[0], routInfo[1], nextSwitchMac)
                
                    # 3. 如果是上一跳送来的报文先去掉PBB头， 然后转Table1处理
                    match = parser.OFPMatch(in_port=in_port, eth_src=preSwitchMac, eth_type=0x88E7,vlan_vid=1,vlan_pcp=pcp)
                    actions = [parser.OFPActionPopPbb()]
                    instruction = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions), parser.OFPInstructionGotoTable(1)]
                    self.add_flow(datapath, tableID, 1, match, instruction)
                    # 4. table1的处理: 先加上PBB头部
                    tableID = 1
                    # 2.3 匹配原始报文、压头，并修改头部的mac, 然后从指定端口输出
                    match = parser.OFPMatch(in_port=in_port, eth_dst=dstMac)
                    if in_port == out_port:
                        out_port = ofproto_v1_3.OFPP_IN_PORT

                    actions = [parser.OFPActionPushPbb(0x88e7), parser.OFPActionPushVlan(0x8100),OFPActionSetField(eth_src=selfSwitchMac), OFPActionSetField(eth_dst=nextSwitchMac),OFPActionSetField(vlan_vid=1),OFPActionSetField(vlan_pcp=pcp), parser.OFPActionOutput(out_port)]
                    instruction = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
                    self.add_flow(datapath, tableID, 1, match, instruction)
                
            pCnt = pCnt + 1
        print "[INFO]: Install the Path to switch......[END]"
        return

   
