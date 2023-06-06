#!/usr/bin/env python

from igo_whois import WhoisData, getDomainNameByUrl
import sys

if len(sys.argv) not in [2, 3]:
    print('Usage: igo-whois-cl.py domain [whois-server]')
    sys.exit(0)
elif len(sys.argv) == 2:
    w = WhoisData(sys.argv[1])
else:
    w = WhoisData(sys.argv[1], sys.argv[2])

print(w.raw_info)