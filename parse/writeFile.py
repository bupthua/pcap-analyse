#! /usr/bin/python 
# coding=utf-8 

strs="test"

output = open("output", "w")
print type(strs)
output.write(strs)
output.close()