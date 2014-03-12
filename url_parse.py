

import re,sys
import urllib

url = 'http://www.baidu.com'

content = urllib.urlopen(url).read()
#content = content.replace(' ', '')

pattern_single = re.compile(r"'([^' ]*\.\w+)'")
pattern_double = re.compile(r'"([^" ]*\.\w+)"')
pattern_withurl = re.compile(r"url\(['\"]?([^\(\)]*)['\"]?\)")

print pattern_double.findall(content)
print pattern_single.findall(content)
print pattern_withurl.findall(content)
sys.exit(0)
