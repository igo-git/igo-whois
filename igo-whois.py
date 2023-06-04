#!/usr/bin/env python

import socket
import time
from datetime import datetime
from ipaddress import IPv4Address, AddressValueError
from pprint import pprint
import sys

def ianna(domain):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("whois.iana.org", 43))
    s.send((domain + "\r\n").encode())
    response = b""
    while True:
        data = s.recv(4096)
        response += data
        if not data:
            break
    s.close()
    whois = ''
    for resp in response.decode().splitlines():
        if resp.startswith('%') or not resp.strip():
            continue
        elif resp.startswith('whois'):
            whois = resp.split(":")[1].strip()
            break
    print(whois)
    print('----------------')
    return whois if whois else False

def get_whois(domain, whois):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((whois, 43))
    s.send((domain + "\r\n").encode())
    response = b""
    while True:
        data = s.recv(4096)
        response += data
        if not data:
            break
    s.close()
    whois_ip = dict()
    num = 0
    print(whois + ' response:')
    print(response.decode())
    print('----------------')
    for ln in response.decode().splitlines():
        if ln.strip().startswith("%") or not ln.strip():
            continue
        else:
            try:
                whois_ip.update({ln.strip().split(": ")[0].strip(): ln.strip().split(": ")[1].strip()})
            except Exception: 
                pass
#            if ln.strip().split(": ")[0].strip() in ['created', 'last-modified']:
#                dt = datetime.fromisoformat(ln.strip().split(": ")[1].strip()).strftime("%Y-%m-%d %H:%M:%S")
#                whois_ip.update({f'{ln.strip().split(": ")[0].strip()}_{num}': dt})
#                num += 1
#            else:
#                whois_ip.update({ln.strip().split(": ")[0].strip(): ln.strip().split(": ")[1].strip()})
    if 'Registrar WHOIS Server' in whois_ip.keys():
        if whois_ip['Registrar WHOIS Server'] != whois:
            whois_ip = get_whois(domain, whois_ip['Registrar WHOIS Server'])
    return whois_ip if whois_ip else False

def validate_request(ip):
    try:
#        IPv4Address(ip)
        if whois := ianna(ip):
            time.sleep(1)
            if info := get_whois(ip, whois):
                pprint(info)
            else:
                print("No IP address/domain data has been received.")
        else:
            print("I can't get information about the registrar. The registrar whois.ripe.net will be used.")
            if info := get_whois(ip, 'whois.ripe.net'):
                pprint(info)
            else:
                print("No IP address data has been received.")
    except AddressValueError:
        print("IP-address not valid")
    except ConnectionResetError as ex:
        print(ex)

if len(sys.argv) < 2:
  print('Shit')
  exit(0)
validate_request(sys.argv[1])
