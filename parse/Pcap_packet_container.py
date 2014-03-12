#! /usr/bin/python
# -*- coding: utf-8 -*-

from rd_pcap import *
from ethernet import *
from ip import *
from tcp import *
from Pcap_packet import *
from tcp_stream_container import *
from tcp_stream import *
from message import *
from http import *

import codecs, re

SERVER_IP = "10.108.115.9"
SERVER_IP = "10.108.112.253"

#global var for tcp reassemble
_tcp_buf = None

#global var for self device ip
_device_ip = "192.168.1.101"
#_device_ip = "192.168.123.4"
_device_ip = None

class Pcap_packet_container():
    """a class to contain the packets in a pcap file"""
    
    _device_ip = None

    def __init__(self, file_name, enableFilter = True):
        global _device_ip
        _device_ip = None
        self.pattern_single = re.compile(r"'([^' ]*\.\w+)'")
        self.pattern_double = re.compile(r'"([^" ]*\.\w+)"')
        self.pattern_withurl = re.compile(r"url\(['\"]?([^\(\)]*)['\"]?\)")
        self.response_links = []
        self.enableFilter = enableFilter

        self.pcap_file_name = file_name
        #read in the pcap_file and get the info below
        #raw_packets: the packet reads from pcap file, it hasn't been parsed, it only hases the origin hex data
        #pcap_packets: a Pcap_packet obj, it contains the data that has been parsed into layers
        #tcp_stream_container: dispatch the tcp packets in the pcap file into tcp streams, and the packets in the tcp stream 
        #                      should be http packet(at least on port is 80)
        #msg_list: the http messages list, after tcp reassemble
        self.pcap_header, \
        self.packet_headers, \
        self.raw_packets = rd_pcap(self.pcap_file_name)
        self.pcap_packets = []
        self.tcp_stream_container = Tcp_stream_container()
        #msg_list and http_list are parallel
        self.msg_list = []
        self.http_list = []
        if len(self.packet_headers) > 0:
            self._ts_base = self.packet_headers[0]['ts']
        self._parse()

        # HUA 将HTTP消息按时间排序（为什么会出现乱序？因为一个HTTP消息的判断条件是TCP的下一个ACK不同，那么就有可能出现交叉
        def byts(http):
            return http.ts
        self.http_list = sorted(self.http_list, key=byts)

        # HUA 重新对HTTP进行编号
        reqCount = 0
        allCount = 0
        for http in self.http_list:
            http.allindex = allCount
            allCount += 1
            if not http.legal: continue
            if http.http_type == 'request':
                http.index = reqCount
                reqCount += 1
            else:
                http.index = 0

        self.check_dependency()

    #endof def
    
    def _parse(self):
        """parse the data in the pcap file, get the container"""
        
        # HUA determine the host ip address
        # read 20 packages and set the most frequent one
        ips_dict = {}
        count = 0
        for raw_packet in self.raw_packets:
            if count > 100: break
            ethernet = Ethernet(raw_packet[0:14])
            if(ethernet.type != 'IP'):
                continue
            ip = Ip(raw_packet[14:])
            if(ip.protocol != 'TCP') :
                continue
            if(ip.src not in ips_dict):
                ips_dict[ip.src] = 0
            ips_dict[ip.src] += 1
            if(ip.dst not in ips_dict):
                ips_dict[ip.dst] = 0
            ips_dict[ip.dst] += 1
        # get the most frequent one
        max_appear = 0
        ip = None
        for key, value in ips_dict.items():
            if value > max_appear:
                ip = key
                max_appear = value

        global _device_ip
        if not self.enableFilter or not _device_ip:
            _device_ip = ip

        global _tcp_buf
        _tcp_buf = {}
        number = 0
        self.begin_ts = self.packet_headers[-1]['ts']
        rcount = 0
        for raw_packet in self.raw_packets:
            pcap_packet = Pcap_packet()
            pcap_packet.pcap_num = rcount#number # add one to be consistent with wireshark
            pcap_packet.top_layer = 1
            pcap_packet.ethernet = Ethernet(raw_packet[0:14])
            
            #skip the packet that is not ip packet
            
            rcount += 1

            if (pcap_packet.ethernet.type != 'IP'):
                continue

            pcap_packet.top_layer = 2
            pcap_packet.ip = Ip(raw_packet[14:])




            # just collect the packets between 
            
            if self.enableFilter and not (pcap_packet.ip.src == _device_ip and pcap_packet.ip.dst == SERVER_IP) \
                and not (pcap_packet.ip.dst == _device_ip and pcap_packet.ip.src == SERVER_IP):
                #print "Ignore ip not ok"
                continue
            '''
            if rcount < 10 or rcount > 2600:
                print 'rcount %d, time %d ---: %f' % (rcount, number, self.packet_headers[rcount - 1]['ts'] - self._ts_base)
            '''
            
            self.pcap_packets.append(pcap_packet)
            

            #skip the packet that is not tcp message
            if (pcap_packet.ip.protocol != 'TCP'):
                continue
            


            pcap_packet.top_layer = 3
            pcap_packet.tcp = Tcp(pcap_packet.ip, number)

            if pcap_packet.ip.src == _device_ip:
                pcap_packet.tcp.direction = "out"
            else:
                pcap_packet.tcp.direction = "in"


            #dispatch the tcp into tcp streams
            self._add_pkt_into_tcp_stream(pcap_packet, number)
            
            #reassemble tcp packet
            self._tcp_reassemble(pcap_packet.pcap_num, pcap_packet.ip.src, pcap_packet.ip.dst, pcap_packet.tcp)
            number += 1
        #endof for
        #flush the tcp_buf, other wise it will lose some http response
        for sockets in _tcp_buf.keys():
            self._tcp_flush(sockets)
            del _tcp_buf[sockets]
    #endof def
    
    def _add_pkt_into_tcp_stream(self, pcap_packet, num):
        """a method to add a pcap_packet into a tcp stream, if it does not belong to any existing tcp stream, 
        create a new one"""
        
        # the src is server, remote(dst) is client
        if (pcap_packet.ip.dst == _device_ip): # HUA use ip (not 80 port) as direction judgement
            server_addr = pcap_packet.ip.src
            server_port = pcap_packet.tcp.src_port
            client_addr = pcap_packet.ip.dst
            client_port = pcap_packet.tcp.dst_port
        else:
            server_addr = pcap_packet.ip.dst
            server_port = pcap_packet.tcp.dst_port
            client_addr = pcap_packet.ip.src
            client_port = pcap_packet.tcp.src_port
        socket_tuple = (client_addr, client_port, server_addr, server_port)
        if (socket_tuple not in self.tcp_stream_container):
            self.tcp_stream_container[socket_tuple] = Tcp_stream()
        pcap_packet.tcp.stream_index = self.tcp_stream_container[socket_tuple].stream_index
        self.tcp_stream_container[socket_tuple].pcap_num_list.append(num)

    def _tcp_reassemble(self, number, src_addr, dst_addr, tcp):
        """a method to reassemble tcp packet, and append the message after reassemble to the msg_list"""
        
        pld = tcp.message[tcp.header_len : tcp.header_len + tcp.segement_len]
        src_socket  = (src_addr, tcp.src_port)
        dst_socket  = (dst_addr, tcp.dst_port)
        sockets     = (src_socket, dst_socket)

        def debug_cond(tcp):
            return False
            return True
            return tcp.stream_index == 710

        #check the other side of the tcp connection, flush the complete pdu to the msg_list
        if sockets in _tcp_buf and tcp.ack_num != _tcp_buf[sockets].ack:   
            self._tcp_flush(sockets)
            del _tcp_buf[sockets]
            if debug_cond(tcp):
                print "get a new http, decide by %d" % number

        if debug_cond(tcp):
            print "_tcp_reassemble, number= %d, sequence_num=%d, ack = %d, pldlen=%d, msglen=%d， opt_paddings=%d, iptotal_len=%d, ipheader_len=%d, tcpheader_len=%d" % (number, tcp.ack_num, len(pld), len(tcp.message), len(tcp.opt_paddings), tcp.ip.total_len, tcp.ip.header_len, tcp.header_len)
            pass

        if pld:
            if not sockets in _tcp_buf:
                if debug_cond(tcp):
                    print " add a new message, begin with %d" % number
                _tcp_buf[sockets] = Message({
                    'pcap_num_list':    [],
                    'ts':               self.packet_headers[number]['ts'] - self._ts_base,
                    'ip_proto':         'TCP',
                    'src_addr':         src_addr,
                    'dst_addr':         dst_addr,
                    'src_port':         tcp.src_port,
                    'dst_port':         tcp.dst_port,
                    #'seq':              tcp.sequence_num, HUA tcp disorder will generate error
                    'tcp_list':         [],
                    'seq_min':          0,
                    'ack':              tcp.ack_num,
                    'payload':          [],
                    'stream_index':     tcp.stream_index, # HUA add a stream index to message
                    'direction':        tcp.direction, # HUA add to determin the http is request or response
                    'flag':             False
                })
            try:
                _tcp_buf[sockets].ts = self.packet_headers[number]['ts'] - self._ts_base # HUA we should update ts and set it to last
            except:
                print number
                print len(self.packet_headers)
            _tcp_buf[sockets].pcap_num_list.append(number)
            if number == 2246:
                _tcp_buf[sockets].flag = False
            _tcp_buf[sockets].tcp_list.append(tcp)
            #offset = tcp.sequence_num - _tcp_buf[sockets].seq # seq 是相对的
            #_tcp_buf[sockets].payload[offset:offset+len(pld)] = list(pld)
        
        
        
    def _tcp_flush(self, sockets):
        """a method to flush the complete(after strict reassemble) pdus to the msg_list"""
        
        msg = _tcp_buf[sockets]

        # HUA: find the smallest sequence number
        seq_list = []
        for (index, tcp) in enumerate(msg['tcp_list']):
            seq_list.append(tcp.sequence_num)
            if index == 0:
                seq_min = tcp.sequence_num
            else:
                if tcp.sequence_num < seq_min:
                    seq_min = tcp.sequence_num
        msg['seq_min'] = seq_min
        
        # copy the data to payload
        for tcp in msg['tcp_list']:
            offset = tcp.sequence_num - seq_min
            if False:#msg.flag:
                print "_tcp_reassemble, number= %d, sequence_num=%d, ack = %d, pldlen=%d, msglen=%d， opt_paddings=%d, iptotal_len=%d, ipheader_len=%d, tcpheader_len=%d" % (tcp.number, tcp.sequence_num, tcp.ack_num, tcp.segement_len, len(tcp.message), len(tcp.opt_paddings), tcp.ip.total_len, tcp.ip.header_len, tcp.header_len)
                print "offset=%d, len=%d" % (offset, tcp.segement_len)
                print "------------------------------"
                print repr(tcp.message[tcp.header_len : tcp.header_len + tcp.segement_len])
                print "------------------------------"
            #HUA: bug fix: 如果长度不够，需要先填充
            cur_len = len(msg.payload)
            if cur_len < offset:
                msg.payload[cur_len : offset] = (offset - cur_len) * ['']
            msg.payload[offset : offset + tcp.segement_len] = list(tcp.message[tcp.header_len : tcp.header_len + tcp.segement_len])

        msg['payload'] = ''.join(msg.payload)
        if msg.flag:
            print repr(msg.payload)
        self.msg_list.append(msg)

        self._trans_msg_to_http_obj(msg)
        #TODO: need to store the msg_number into the tcp_stream????then the tcp_stream know what msgs it has
        
    def _trans_msg_to_http_obj(self, msg):
        """a method to transfer the msg to a http obj, append a None obj to the http_list if the msg's payload is empty"""
        
        if (len(msg.payload) == 0):
            self.http_list.append(None)
            return
        
        self.http_list.append(Http(msg))
    
    def print_info(self):
        """a method to print all the packets in a container to the stander output"""
        
        i = 1
        for pcap_packet in self.pcap_packets:
            print '----------------frame: %d------------' % i
            i += 1
            pcap_packet.ethernet.print_info()
            
            #skip the packet that is not ip packet
            if (pcap_packet.ethernet.type != 'IP'):
                continue
                
            print '#################   packet in the frame  ################'
            pcap_packet.ip.print_info()
            
            #skp the packet that is not tcp message
            if (pcap_packet.ip.protocol != 'TCP'):
                continue
            
            print '@@@@@@@@@@@@@@@@@@@  tcp fields  @@@@@@@@@@@@@@@@@@@@'
            pcap_packet.tcp.print_info()
            
            print
        #endof for

    def get_configure(self):
        http_report = ''
        count = 0
        reqCount = 0
        http_report =  Http.get_configure_header() + "\r\n"
        for http in self.http_list:
            #print http.__dict__
            if http.legal and http.http_type == 'request':
                count += 1
                #print http.get_report() 
                r = http.get_configure_report()
                try:
                    http_report +=  r
                except:
                    print "Add to configure error: " + r
        return http_report

    def get_count_len(self):
        total = 0
        count = 0
        for http in self.http_list:
            if http.legal and http.http_type == 'request':
                count += 1
                one_len = http.get_reqreslen() 
                total += one_len

        return (count, total)

    def get_print_http(self):
        http_report = ''
        count = 0
        reqCount = 0
        http_report =  Http.get_tostr_header() + "\n"
        for http in self.http_list:
            if http.legal:
                count += 1
                #print http.get_report() 
                r = http.get_report()
                try:
                    http_report +=  r
                    http_report += "\n"
                except:
                    print "Add error: " + r
                if http.http_type == 'request':
                    reqCount += 1
                
        http_report +=  "Total " + str(count) + ", request = " + str(reqCount) + ", response = " + str(count - reqCount) + "\n"
        return http_report

    def extract_url(self, content):
        urls = set(self.pattern_single.findall(content))
        urls |= set(self.pattern_double.findall(content))
        urls |= set(self.pattern_withurl.findall(content))
        return list(urls)


    def check_dependency(self):
        #return
        total = len(self.http_list)
        _response_links = []
        for http in self.http_list:
            if not http.legal: continue
            cur_http = None
            if http.http_type == 'request': # 发送
                # 检查当前链接是否存在与 response_links， 如果是，则这个请求依赖于上一个请求
                for (url, index, allindex) in self.response_links:
                    if http.header_fields['uri'] and url.find(http.header_fields['uri']) >= 0:
                        http.depend_index = index
                        self.http_list[allindex].be_depended_list.append(http.index)
                        self.response_links.remove((url, index, allindex))
                        break
                # 找到当前链接的响应
                index = http.allindex
                while index < total:
                    cur_http = self.http_list[index]
                    if cur_http.http_type == 'response' and cur_http.stream_index == http.stream_index \
                        and not cur_http.req_index:
                        cur_http.req_index = http.index
                        http.res_index = cur_http.allindex
                        http.response = cur_http
                        break
                    index += 1
                #将当前请求的响应中的链接加入到 response_links
                if index != total:
                    #find response, extract all url and add to the dependency list
                    try:
                        if cur_http.decoding_content:
                            c = cur_http.decoding_content
                        else:
                            c = cur_http.content
                    except:
                        c = '!!!!!!!!!!!!!!!!!!!!!!!!!   encode error'
                    #print c
                    urls = self.extract_url(c)
                    #print urls
                    for url in urls:
                        _response_links.append(url)
                        self.response_links.append((url, http.index, http.allindex))

        #outfile = codecs.open("reslist.txt" , "w", "utf-8")
        #outfile.write('\n'.join(_response_links))
        #outfile.close()


