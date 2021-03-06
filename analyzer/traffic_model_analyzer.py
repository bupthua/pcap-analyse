#! /usr/bin/python
# -*- coding: utf-8 -*-

from parse.Pcap_packet_container import *

import os

from parse.protocol import *

class Traffic_model_analyzer():
    """a class for cal traffic over tcp and protocols"""
    
    def __init__(self, pcap_container):
        self.pcap_container = pcap_container
        
        self.tcp_conn_duration = {}
        self.tcp_conn_all_traffic = {}
        self.tcp_conn_effective_traffic = {}    #the network traffic over tcp layer(means the sum of tcp payload length)
        self.tcp_conn_throughput_rate = {}

        self.udp_all_traffic = 0
        self.tcp_all_traffic = 0
        self.app_layer_all_traffic = {
            "FTP" : 0,  #port:21
            "SSH" : 0,  #port:22
            "TELNET" : 0,   #port:23
            "SMTP" : 0, #port:25
            "HTTP" : 0, #port:80
            "DNS" : 0,  #port:53
            "known":0
        }

    def cal_tcp_conn_statistics(self):
        """a method to cal all tcp connection statistics"""
        
        for sockets in self.pcap_container.tcp_stream_container.keys():
            self._cal_tcp_conn_duration(sockets)
            self._cal_tcp_conn_traffic(sockets)
            if self.tcp_conn_duration[sockets] == 0:
                self.tcp_conn_throughput_rate[sockets] = 0
            else:
                self.tcp_conn_throughput_rate[sockets] = self.tcp_conn_effective_traffic[sockets] / self.tcp_conn_duration[sockets]
    
    def cal_protocol_statistics(self):
        """a method to cal:
           1, all traffic in transfer layer
           2, all traffic in application layer()"""
           
        for pcap_packet in self.pcap_container.pcap_packets:
            if (pcap_packet.top_layer < 2):
                continue
            
            #cal all traffic in transfer layer
            if (pcap_packet.ip.protocol == "TCP"):
                self.tcp_all_traffic += self.pcap_container.packet_headers[pcap_packet.pcap_num-1]["cap_len"]
            elif (pcap_packet.ip.protocol == "UDP"):
                self.udp_all_traffic += self.pcap_container.packet_headers[pcap_packet.pcap_num-1]["cap_len"]
            else:
                continue    #skip the packets that is not tcp or udp packets
                
            #cal all traffic in transfer layer
            message = pcap_packet.ip.packet[pcap_packet.ip.header_len: pcap_packet.ip.header_len+4]
            src_port = int(data_to_hex_str(message[0:2]), 16)
            dst_port = int(data_to_hex_str(message[2:4]), 16)
            transfer_layer_proto = self._get_transfer_proto(src_port, dst_port)
            self.app_layer_all_traffic[transfer_layer_proto] += self.pcap_container.packet_headers[pcap_packet.pcap_num-1]["cap_len"]
    
    def _get_transfer_proto(self, src_port, dst_port):
        """a method to get transfer layer protocol according to the src_port and the dst_port"""
        
        if (src_port == 21 or dst_port == 21):
            return "FTP"
        if (src_port == 22 or dst_port == 22):
            return "SSH"
        if (src_port == 23 or dst_port == 23):
            return "TELNET"
        if (src_port == 25 or dst_port == 25):
            return "SMTP"
        if (src_port == 80 or dst_port == 80):
            return "HTTP"
        if (src_port == 53 or dst_port == 53):
            return "DNS"
        return "known"
    
    def _cal_tcp_conn_duration(self, sockets):
        """a method to cal tcp connection duration of all tcp streams in pcap_container.tcp_stream_container"""
        
        tcp_stream = self.pcap_container.tcp_stream_container[sockets]
        min_time = None
        max_time = None
        for num in tcp_stream.pcap_num_list:
            num = self.pcap_container.pcap_packets[num].pcap_num
            ts = self.pcap_container.packet_headers[num]['ts']
            if not min_time:
                min_time = ts
                max_time = ts
                continue
            if ts > max_time:
                max_time = ts
            if ts < min_time:
                min_time = ts
        if min_time:
            self.tcp_conn_duration[sockets] = max_time - min_time
        return
        min_pcap_num = min(tcp_stream.pcap_num_list)
        max_pcap_num = max(tcp_stream.pcap_num_list)
        if (max_pcap_num >= len(self.pcap_container.packet_headers)):
            max_pcap_num = len(self.pcap_container.packet_headers) - 1
        self.tcp_conn_duration[sockets] = self.pcap_container.packet_headers[max_pcap_num]['ts'] - \
            self.pcap_container.packet_headers[min_pcap_num]['ts']
        if self.tcp_conn_duration[sockets] < 0:
            print "Get negetive duration, min_pcap_num = %d, max = %d" % (min_pcap_num, max_pcap_num)
            print self.pcap_container.packet_headers[max_pcap_num]['ts']
            print self.pcap_container.packet_headers[min_pcap_num]['ts']
                
    def _cal_tcp_conn_traffic(self, sockets):
        """a method to cal tcp connection traffic of all tcp streams in pcap_container.tcp_stream_container"""
        
        tcp_stream = self.pcap_container.tcp_stream_container[sockets]
        self.tcp_conn_all_traffic[sockets] = 0
        self.tcp_conn_effective_traffic[sockets] = 0
        for pcap_num in tcp_stream.pcap_num_list:
            rpcap_num = self.pcap_container.pcap_packets[pcap_num].pcap_num
            if (rpcap_num >= len(self.pcap_container.packet_headers)):
                continue
            self.tcp_conn_all_traffic[sockets] += self.pcap_container.packet_headers[rpcap_num]['cap_len']
            if (self.pcap_container.pcap_packets[pcap_num].tcp != None):
                self.tcp_conn_effective_traffic[sockets] += (len(self.pcap_container.pcap_packets[pcap_num].tcp.message) - \
                    self.pcap_container.pcap_packets[pcap_num].tcp.header_len)

