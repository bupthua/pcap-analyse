#! /usr/bin/python 
# -*- coding: utf-8 -*- 

import sys, codecs, locale, urllib, os
from parse.Pcap_packet_container import *
from analyzer.traffic_model_analyzer import *
from analyzer.congestion_control_analyzer import *
from analyzer.cal_throughput import *   

def write_utf8file(path, content):
	outfile = codecs.open(path , "w", "utf-8")
	outfile.write(content)
	outfile.close()

try:
	root_dir = raw_input("please input the pcap file name: \n")
except:
	root_dir = "../data/final/pcap4conf"
	#print "Use %s as default" % root_dir

conf_root = "%s/_config" % root_dir

print "The result configure files will be located to: %s" % conf_root

if not os.path.isdir(conf_root):
	os.mkdir(conf_root)

# foreach directory xxx in the root_dir, read the pcaps in it and generate configure respectively

if not os.path.isdir(root_dir):
	print "%s is not a directory" % root_dir


dirs = os.listdir(root_dir)
for app in dirs:
	if app[0:1] == "_": continue   # ignore the dir begin with _
	app_dir = "%s/%s" % (root_dir, app)
	if not os.path.isdir(app_dir):
		continue
	print "\nIn app: " + app
	if not os.path.isdir("%s/%s" % (conf_root, app)):
		os.mkdir("%s/%s" % (conf_root, app))
	groups = os.listdir(app_dir)
	size_result = u''
	for g in groups:
		if len(g) < 5 or g[-5:] != ".pcap": continue  # only deal with .pcap file
		gpath = "%s/%s" % (app_dir, g)

		print "generate configure for %s" % gpath
		pcap_container = Pcap_packet_container(gpath, False)
		configure = pcap_container.get_configure()
		count, total = pcap_container.get_count_len()
		size_result += u'%s: reqtotal: %d, all http size: %d\r\n' % (g[:-5], count, total)

		write_utf8file("%s/%s/%s.txt" % (conf_root, app, g[:-5]), configure)
		del pcap_container
	write_utf8file("%s/%s/_size.txt" % (conf_root, app), size_result)

