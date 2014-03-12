#! /usr/bin/python
# -*- coding: utf-8 -*-

from parse.Pcap_packet_container import *

from parse.protocol import *
import time

def cal_ip_throughput(pcap_container):
    """a method for calculating ip throughput rate
    all ip_packet_len_sum / (last_ip_timestamp - first_ip_time_stamp)"""

    ip_packet_len_sum = 0
    first = 1
    pos = 0
    start_pos = 0
    start_time = 99999999
    for pcap_packet in pcap_container.pcap_packets:
        if pcap_packet.top_layer >= 2:
            if (first == 1):
                start_time = pcap_container.packet_headers[pcap_packet.pcap_num]["ts"]
                start_pos = pos
                first = 0
            '''
            if start_time > pcap_container.packet_headers[pos]["ts"]:
                start_time = pcap_container.packet_headers[pos]["ts"]
            '''
            ip_packet_len_sum += pcap_packet.ip.total_len
        pos += 1

    pos -= 1
    end_time = 0
    while (pos >= 0):
        rcount = pcap_container.pcap_packets[pos].pcap_num
        if (pcap_container.pcap_packets[pos].top_layer >= 2):
            if pcap_container.packet_headers[rcount]["ts"] > end_time:
                end_time = pcap_container.packet_headers[rcount]["ts"]
            end_time = pcap_container.packet_headers[rcount]["ts"]
            break
        pos -= 1

    if (start_pos == pos or ip_packet_len_sum == 0):
        print "no ip packets or there is only one ip packet, packet len: %d" % ip_packet_len_sum
        return (0, 0, 0)
    else:
        print "ip throughput rate: %f (bytes per second)" % (ip_packet_len_sum / (end_time - start_time))
        return (ip_packet_len_sum / (end_time - start_time), ip_packet_len_sum, end_time - start_time)
    print "%d" % ip_packet_len_sum

def cal_app_layer_throughput(pcap_container):
    """a method for calculating application layer tcp throughput rate(only http)
    for each sockets:
    all_tcp_payload_len / (last_request_timestamp - first_request_timestamp)
    use the msg_list to build sockets dict, and cal the throughput"""

    pos = 0
    app_layer_statistics = {}
    for msg in pcap_container.msg_list:
        if pcap_container.http_list[pos] == None:
            pos += 1
            continue;

        #get sockets
        if msg['src_port'] == 80:
            sockets = (msg['dst_addr'], msg['dst_port'], msg['src_addr'], msg['src_port'])
        else:
            sockets = (msg['src_addr'], msg['src_port'], msg['dst_addr'], msg['dst_port'])
        if sockets not in app_layer_statistics.keys():
            app_layer_statistics[sockets] = {}
            app_layer_statistics[sockets]['payload_sum'] = 0
            app_layer_statistics[sockets]['first_get_ts'] = -1
            app_layer_statistics[sockets]['last_ok_ts'] = -1
            app_layer_statistics[sockets]['req_cnt'] = 0
            app_layer_statistics[sockets]['resp_cnt'] = 0
            app_layer_statistics[sockets]['ok_cnt'] = 0
            app_layer_statistics[sockets]['num_lists'] = []
        app_layer_statistics[sockets]['num_lists'].append(msg['pcap_num_list'])

        if app_layer_statistics[sockets]['first_get_ts'] == -1 and pcap_container.http_list[pos].http_type == 1:
            app_layer_statistics[sockets]['first_get_ts'] = pcap_container.packet_headers[min(msg['pcap_num_list'])]['ts']
        if pcap_container.http_list[pos].http_type == 2 and pcap_container.http_list[pos].header_fields['status_code'] == 200:
            app_layer_statistics[sockets]['last_ok_ts'] = pcap_container.packet_headers[max(msg['pcap_num_list'])]['ts']
            app_layer_statistics[sockets]['ok_cnt'] += 1
        if pcap_container.http_list[pos].http_type == 1:
            app_layer_statistics[sockets]['req_cnt'] += 1
        elif pcap_container.http_list[pos].http_type == 2:
            app_layer_statistics[sockets]['resp_cnt'] += 1
        app_layer_statistics[sockets]['payload_sum'] += len(msg.payload)
        
        pos += 1

    for sockets in app_layer_statistics:
        if (app_layer_statistics[sockets]['first_get_ts'] == -1 or app_layer_statistics[sockets]['last_ok_ts'] == -1):
            print "incomplete http stream(lack of 'http-request or http-response'): " + repr(sockets)
        else:
            print "sockets: %s app layer throughput: %f(Bps)" % (repr(sockets), app_layer_statistics[sockets]['payload_sum'] / (app_layer_statistics[sockets]['last_ok_ts'] - app_layer_statistics[sockets]['first_get_ts']))

    return app_layer_statistics
