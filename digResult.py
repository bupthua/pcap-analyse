#! /usr/bin/python 
# -*- coding: utf-8 -*- 

import sys, codecs, locale, urllib
from parse.Pcap_packet_container import *
from analyzer.traffic_model_analyzer import *
from analyzer.congestion_control_analyzer import *
from analyzer.cal_throughput import *       

def analyse_onecap(fName):
    pcap_container = Pcap_packet_container(fName)
    traffic_model_analyzer = Traffic_model_analyzer(pcap_container)
    traffic_model_analyzer.cal_tcp_conn_statistics()

    congestion_control_analyzer = Congestion_control_analyzer(pcap_container)
    congestion_control_analyzer.analyze()

    print "---------------------ip throughput--------------------"
    ip_output_rate, ip_sum_len, ip_total_time = cal_ip_throughput(pcap_container)
    print "------------------------------------------------------"
    print

    print '---------------------tcp throughput-------------------'
    tcp_count = 0
    tcp_outputtotal = 0
    for sockets in traffic_model_analyzer.tcp_conn_throughput_rate:
        if traffic_model_analyzer.tcp_conn_throughput_rate[sockets] < 10:
            continue
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

    return (ip_total_time, ip_output_rate, ip_sum_len, tcp_count, tcp_outputtotal / tcp_count, congestion_control_analyzer.avg_rtt, congestion_control_analyzer.retransmission_prob)  

def write_utf8file(path, content):
    outfile = codecs.open(path , "w", "utf-8")
    outfile.write(content)
    outfile.close()

try:
    root = raw_input("please input the pcap files dir: \n")
except:
    root = "../data/Filter"
    root = "../data/21.45"
    #root = "../data/21.45-filter"
    #root = "../data/n"
    root = "../data/test/1-0-0-398064-0.pcap"
    root = "../data/final/pcap4report/xunlei-38-373394/3-on"
    root = "../data/final/real-bupt"
    print "Using default:  %s" % root

if not os.path.isdir(root):
    print "%s 不是一个目录，尝试解析为一个文件！" % root
    if not os.path.isfile(root):
        print "%s 既不是文件也不是目录，退出" % root
        sys.exit(1)
    result = analyse_onecap(root)
    print repr(result)
    sys.exit()

output = open(root + "/_report.txt", "w")


all_result = u'名称, 总时间, ip吞吐率, ip总字节数,tcp链接个数,tcp平均吞吐率,平均rtt,重传率\r\n'
dirs = os.listdir(root)
for pcap in dirs:
    if pcap[0:1] == '_': continue
    print u"Analyse %s" % pcap
    result = analyse_onecap(root + '/' + pcap)
    all_result += u'%s, '  % pcap
    all_result += u', '.join('%s' % value for value in result)
    all_result += u"\r\n"
print u"All done!!"
print u"Result is"
print all_result

output = codecs.open(root + "/_report.txt", 'w', 'utf-8')
output.write(all_result)
output.close()
sys.exit()

