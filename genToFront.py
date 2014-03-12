#! /usr/bin/python 
# -*- coding: utf-8 -*- 
# 为最终的页面展示生成数据
'''
输入文件格式
所有的pcap文件都在一个根目录下，假设为 root
root 下有多个文件夹,命名为：应用名称-请求个数-请求总字节数
应用文件夹里面有多个文件夹，命名为 连接个数-是否开启优化（off/on)，例如 3-on
对于root下的每一个文件夹，存放不同条件下记录的pcap文件，格式为 压缩算法(0/1)-时延-丢包率-应用参考时间-失败个数-N个耗电量

最后生成的数据文件格式
5,8
优化是否开启*,0,1
时延,0,500,1000
丢包率,0,1,2
压缩算法,0,1
连接个数,1,3,10
应用,weibo,xunlei,lingxi,south,internet
是否开启优化，时延，丢包，压缩算法，连接个数， 应用， IP吞吐率,    TCP吞吐率,    应用层吞吐率,    应用层时延,    TCP重传率,    应用层请求成功率,    耗电量3G,    耗电量2G
0,0,0,1,3,weibo,    5886.332025,    9058.737093,    5993.480963,    1.453784091,    0.14996115,     1,    262.0,  274.1
0,500,0,1,3,weibo,    5314.722491,    172.09067,    4656.155212,    1.871335227,    0.190991771,    1,    387.7,    357.3
0,1000,0,1,3,weibo,    4465.243819,    115.5658121,    3976.981387,    2.190914773,    0.174630756,   1,    469.6,    426.9
'''

#记录的pcap文件，格式为 压缩算法(0/1)-时延-丢包率-应用参考时间-失败个数-N个耗电量
PARAM_COMPRESS = 0
PARAM_IP_DELAY = 1
PARAM_PACKET_LOST = 2
PARAM_APP_TIME_RECORD = 3
PARAM_FAILURE = 4

import sys, codecs, locale, urllib, traceback
from parse.Pcap_packet_container import *
from analyzer.traffic_model_analyzer import *
from analyzer.congestion_control_analyzer import *
from analyzer.cal_throughput import *       

def analyse_onecap(fName):
    print "Analyse onepcap : %s" % fName
    if not os.path.isfile(fName):
        print "!!!!!!!!!! %s is not a pcap file" % fName
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

def analyse_case_group(root, app, group_base):
    '''
    app = name-request_total-request_sizetotal
    group_base = tcpnum-on/off
    pcap_filename = compresstype(0/1)-delay-lostrate-apptime-failurecount-energycost
    '''
    app_params = app.split('-')
    if len(app_params) < 3:
        #print "%s不符合命名格式：应用名称-请求个数-请求总字节数" % app
        return u"%s不符合命名格式：应用名称-请求个数-请求总字节数\r\n" % app
    app_name = app_params[0]
    request_total = app_params[1]
    request_chartotal = app_params[2]
    print group_base
    tcpnum, sep, status = group_base.partition('-')
    result = u''
    pcap_dir = root + "/" + app + "/" + group_base
    pcap_files = os.listdir(pcap_dir)
    for p in pcap_files:
        params = p.partition('.pcap')[0].split('-')
        try:
            analyse_result = analyse_onecap(pcap_dir + "/" +p) #'总时间, ip吞吐率, ip总字节数,tcp链接个数,tcp平均吞吐率,平均rtt,重传率'
        except:
            print "Encounter failure where analyse case group %s, %s, %s, %s" % (root, app, group_base, p)
            traceback.print_exc()
            sys.exit()
        #是否开启优化，配置时延，丢包，压缩算法，连接个数， 应用， IP吞吐率,    TCP吞吐率,    应用层吞吐率,    应用层时延,    TCP重传率,    应用层请求成功率,    耗电量3G,    耗电量2G
        entryList = []
        entryList.append(app + "/" + group_base + "/" + p)
        entryList.append(status) # 是否开启优化
        entryList.append(params[PARAM_IP_DELAY]) # 配置时延
        entryList.append(params[PARAM_PACKET_LOST]) # 丢包
        entryList.append(params[PARAM_COMPRESS]) # 压缩算法
        entryList.append(tcpnum) # 连接个数
        entryList.append(app_name) # 应用
        entryList.append(analyse_result[1]) # IP吞吐率
        entryList.append(analyse_result[4]) # TCP吞吐率
        try:
            entryList.append(float(request_chartotal) / analyse_result[0]) # 应用层吞吐率
        except:
            entryList.append('E')
        entryList.append(analyse_result[0]) # 应用层时延
        entryList.append(analyse_result[6]) # TCP重传率
        try:
            entryList.append((float(request_total) - float(params[PARAM_FAILURE]))/float(request_total)) # 应用层请求成功率
        except:
            entryList.append('E')
        #entryList.append() # 耗电量
        result += u"\t".join(str(e) for e in entryList)
        result += u"\r\n"

    return result

file_header = u'''
5,8\r\n
优化是否开启*,0,1\r\n
时延,0,500,1000\r\n
丢包率,0,1,2\r\n
压缩算法,0,1\r\n
连接个数,1,3,10\r\n
应用,%s\r\n
是否开启优化,时延,丢包,压缩算法,连接个数,应用,IP吞吐率,TCP吞吐率,应用层吞吐率,应用层时延,TCP重传率,应用层请求成功率,耗电量3G,耗电量2G\r\n
'''

try:
    root = raw_input("please input the pcap files dir: \n")
except:
    root = "../data/Filter"
    root = "../data/21.45"
    #root = "../data/21.45-filter"
    #root = "../data/n"
    root = "../data/final/pcap4report"
    #root = "../data/test"
    print "Using default:  %s" % root

if not os.path.isdir(root):
    print "%s 不是一个目录，程序退出！" % root    
    sys.exit(1)


root_subdirs = os.listdir(root)
app_dirs = []
for d in root_subdirs:
    if os.path.isdir(root + '/' + d) and d[0] != '_':
        app_dirs.append(d)

result_content = file_header % u",".join(app_dirs)

for app in app_dirs:
    cases_dir = os.listdir(root + '/' + app)
    for c in cases_dir:
        if not os.path.isdir(root + '/' + app + '/' + c): continue
        try:
            result_content += analyse_case_group(root, app, c)
        except:
            print "Encounter failure where analyse case group %s, %s, %s" % (root, app, c)
            traceback.print_exc()


write_utf8file(root + "/_final.txt", result_content)
sys.exit(0)

