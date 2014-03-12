#! /usr/bin/python 
# -*- coding: utf-8 -*-

from protocol import *
from gzip import *
from StringIO import *
import sys, os

#type of http
HTTP_REQUEST = 1
HTTP_RESPONSE = 2

# fixed header
FIX_HEADER = ['host', 'accept']

class Http(Protocol):
    """a class for http, derived from class Protocol(an empty class)"""
    _index = 0
    _allindex = 0

    def __init__(self, msg):
        data = msg.payload

        self.ts = msg.ts # HUA add the time
        self.stream_index = msg.stream_index # HUA add a stream index
        self.legal = True
        self.frames = msg.pcap_num_list

        self.seq_min = msg.seq_min

        self.req_index = None
        self.res_index = None
        self.request = None
        self.index = None
        self.allindex = Http._allindex
        Http._allindex += 1

        self.response = None

        self.depend_index = None
        self.be_depended_list = []

        if msg.direction == 'in':
            self.http_type = 'response'
        else:
            self.http_type = 'request'
        
        try:
            self.header_len = data.index("\r\n\r\n")
        except:
            #print "illegal http header format"
            self.legal = False
            return
        self.index = 0
        self.http_header = "".join(data[0:self.header_len])  #without the "\r\n\r\n"
        self.content = "".join(data[self.header_len+4:])
        self.decoding_content = None    #if the http content isnot encoding, this field will be None
        
        #all fields in a http header(HTTP/1.1)
        self.header_fields = {}
        
        #only handle the HTTP/1.1
        self.header_fields["http_version"] = "HTTP/1.1"
        
        #only http response has such fields
        self.header_fields["status_code"] = 0
        self.header_fields["status"] = ''
        
        #only http request has such fields
        self.header_fields["request_method"] = ''
        self.header_fields["uri"] = ''
        self.header_fields["host"] = ''
        
        self._get_header_fields()


        #gather chunked data first
        
        if self.header_fields.has_key("transfer-encoding") and self.header_fields['transfer-encoding'] == "chunked":
            try:
                c = self._parse_chunked_data(self.content)
                self.content = c
            except:
                print "----------------------!!!>>>>>>>   PARSE_CHUNKED_DATA ERROR"
                print self.get_report()

        

        #decode http content if necessary
        if (self.http_type == 'response' and self.header_fields.has_key("content-encoding") and 
            self.header_fields["content-encoding"] == "gzip"):
            try:
                gf = GzipFile(fileobj=StringIO(self.content), mode="r")
                self.decoding_content = gf.read()
            except:
                self.decoding_content = gf.extrabuf

        

        try:
            #print self.content.encode('utf-8')
            pass
        except:
            print "ENCODE ERROR"

    def _parse_chunked_data(self, content):
        #print "_parse_chunked_data: "
        #print "[%s]" % content

        result = ''
        cur = 0
        while True:
            index = content.find("\r\n", cur)
            if(index < 0):
                #print "Index < 0"
                break   
            size = int(content[cur:index], 16)
            #print "Size= %d, Cur=%d, index=%d" % (size, cur, index)
            if size == 0: break
            part= content[index + 2: index + 2 + size]
            #print "part of size(%d): [%s]" % (size, part)
            result += part
            cur = index + 2 + size + 1
        #print "_parse_chunked_data result: [%s]" % result
        return result

        

    def _get_header_fields(self):
        """a method to fill in the fields above"""
        #if (self.http_header[0:6] == "HTTP/1"):
        if self.http_type == 'response':
            try:
                self.header_fields["status_code"] = int(self.http_header[9:12])
                self.header_fields["status"] = str(self.http_header[13:15])
            except:
                #print "illegal http request format"
                pass
        else:
            #self.http_type = 'request'
            self.header_fields["request_method"] = str(self.http_header[0:4]).strip()
            try:
                pos = self.http_header.rindex(" HTTP")
                self.header_fields["uri"] = str(self.http_header[4:pos]).strip()
            except:
                #print "illegal http request format"
                pass
        
        header_lines = self.http_header.split("\r\n")
        for line in header_lines[1:]:
            line_split = line.split(": ")
            field_name = str.lower(line_split[0])
            try:
                self.header_fields[field_name] = line_split[1]
            except:
                self.header_fields[field_name] = ""

    def get_report(self):
        if(not self.legal): return "illegal"
        output_list = []
        output_list.append(str(self.index))
        output_list.append(str(self.stream_index))
        output_list.append(str(self.ts))
        output_list.append(str(self.frames))
        output_list.append(str(self.http_type))
        output_list.append(str(self.header_fields['host']) + str(self.header_fields['uri']))
        output_list.append(str(self.header_fields['request_method']))
        output_list.append(str(len(self.content)))
        output_list.append(str(self.res_index))
        output_list.append(str(self.depend_index))
        output_list.append(str(self.be_depended_list))

        
        result = ';'.join(output_list)
        try:
            result.decode('utf-8')
            #return ''
            return result
        except:
            print repr(result)
            #return ''

    @staticmethod
    def get_tostr_header():
        output_list = []
        output_list.append("index")
        output_list.append("stream_index")
        output_list.append("timestamp")
        output_list.append("frames")
        output_list.append("httptype")
        output_list.append("url")
        output_list.append("method")
        output_list.append("content length")
        output_list.append("response index")
        output_list.append("depend index")
        output_list.append("be depended index")
        return ';'.join(output_list)

    def get_filename(self):
        uri = self.header_fields['uri'].strip()
        #print uri
        if not uri: return "Unknown_%d" % self.allindex
        basename = os.path.basename(uri)
        # basename may have ?xxx=xxx or #xxx
        index = basename.find('?')
        index_a = basename.find('#')
        if index < 0:
            index = index_a
        else:
            if index_a > 0 and index_a < index:
                index = index_a
        if index < 0:
            return basename
        return basename[0:index]

    def get_resource_type(self):
        filename = self.get_filename()
        index = filename.find(".")
        if index < 0:
            return 'html'
        return filename[index + 1 : ]

    @staticmethod
    def get_configure_header():
        output_list = []
        output_list.append("index")
        output_list.append("time")
        output_list.append("depend")
        output_list.append("be depend")
        output_list.append("url")
        output_list.append("method")
        output_list.append("header len")
        output_list.append("body len")
        output_list.append("fixed headers")
        output_list.append("expect len")
        return ';'.join(output_list)

    def get_fixed_header(self):
        headers = []
        for h in FIX_HEADER:
            if self.header_fields.has_key(h):
                headers.append('%s=%s' % (h, self.header_fields[h]))
        return '#'.join(headers)

    def get_configure_report(self):
        output_list = []
        output_list.append(str(self.index))
        output_list.append(str(int(self.ts)))
        if self.depend_index:
            output_list.append(str(self.depend_index))
        else:
            output_list.append(str(-1))
        output_list.append(','.join('%s' % id for id in self.be_depended_list))
        output_list.append(str(self.header_fields['host']) + str(self.header_fields['uri']))
        output_list.append(str(self.header_fields['request_method']))
        output_list.append(str(self.header_len))
        output_list.append(str(len(self.content)))
        output_list.append(self.get_fixed_header())
        if self.response and self.response.legal:
            output_list.append(str(len(self.response.content)))
        else:
            output_list.append(str(-1))
        return ' _FLAG_ '.join(output_list) + "\r\n"

    def get_reqreslen(self):
        total = 0
        total += self.header_len
        total += len(self.content)
        if self.response and self.response.legal:
            total += len(self.response.content)
            total += self.response.header_len
        return total





        


            
