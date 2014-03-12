#! /usr/bin/python 
# -*- coding: utf-8 -*- 

import sys, codecs, locale, urllib
from parse.Pcap_packet_container import *
from analyzer.traffic_model_analyzer import *
from analyzer.congestion_control_analyzer import *
from analyzer.cal_throughput import *       


try:
    fName = raw_input("please input the pcap file name: \n")
except:
    
    fName = "on.pcap"
    fName = "off.pcap"
    print "Using default:  %s" % fName

def analyse_onecap(fName):
    pcap_container = Pcap_packet_container(fName)
    traffic_model_analyzer = Traffic_model_analyzer(pcap_container)
    traffic_model_analyzer.cal_tcp_conn_statistics()

    congestion_control_analyzer = Congestion_control_analyzer(pcap_container)
    congestion_control_analyzer.analyze()

    print "---------------------ip throughput--------------------"
    ip_output = cal_ip_throughput(pcap_container)
    print "------------------------------------------------------"
    print

    print '---------------------tcp throughput-------------------'
    tcp_count = 0
    tcp_outputtotal = 0
    for sockets in traffic_model_analyzer.tcp_conn_throughput_rate:
        print "sockets: %s tcp rate: %f (bytes per second), %d %f" % (repr(sockets), traffic_model_analyzer.tcp_conn_throughput_rate[sockets], traffic_model_analyzer.tcp_conn_effective_traffic[sockets], traffic_model_analyzer.tcp_conn_duration[sockets])
        tcp_count += 1
        tcp_outputtotal += traffic_model_analyzer.tcp_conn_throughput_rate[sockets]
    print '------------------------------------------------------'
    print 


    print '--------------------avg rtt---------------------------'
    print str(congestion_control_analyzer.avg_rtt) + ' seconds'
    print '------------------------------------------------------'
    print


    print '--------------------tcp retransmittion prob-----------'
    print congestion_control_analyzer.retransmission_prob
    print '------------------------------------------------------'
    print

    return (ip_output, tcp_count, tcp_outputtotal / tcp_count, congestion_control_analyzer.avg_rtt, congestion_control_analyzer.retransmission_prob)

result = analyse_onecap(fName)
print repr(result)

sys.exit(0)

print '--------------------app layer throughput--------------'
app_layer_stats = cal_app_layer_throughput(pcap_container)
print '------------------------------------------------------'
print 

print '--------------------app layer avg rtt-----------------'
for sockets in app_layer_stats.keys():
    if app_layer_stats[sockets]['req_cnt'] == 0 or app_layer_stats[sockets]['resp_cnt'] == 0:
        print "sockets: %s is incomplete, it has no request or response."
    else:
        print "sockets: %s avg rtt: %f seconds" % (sockets, (app_layer_stats[sockets]['last_ok_ts'] - app_layer_stats[sockets]['first_get_ts'])/min(app_layer_stats[sockets]['req_cnt'], app_layer_stats[sockets]['resp_cnt']))
print '------------------------------------------------------'
print 



print '--------------------request success rate--------------'
for sockets in app_layer_stats.keys():
    if app_layer_stats[sockets]['req_cnt'] == 0:
        print "sockets: %s is incomplete, it has no request."
    else:
        print "sockets: %s request success rate is %f" % (sockets, app_layer_stats[sockets]['ok_cnt'] / app_layer_stats[sockets]['req_cnt'])
print '------------------------------------------------------'
print
