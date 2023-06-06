import socket
import time
from urllib.parse import urlparse

def getDomainNameByUrl(url):
    print(url)
    if (idx := url.find('://')) > -1:
        url = url[idx + 3:]
    if (idx := url.find(':')) > 0:
        url = url[:idx]
    if (idx := url.find('/')) > 0:
        url = url[:idx]
    return url.lower()

def encodeDomainName(domain_name):
    return domain_name.lower().encode('idna').decode('utf-8')

def decodeDomainName(domain_name):
    return domain_name.lower().encode('utf-8').decode('idna')

class WhoisData():
    def __init__(self, domain_name, whois_server=''):
        self.domain_name = domain_name.lower().encode('idna').decode('utf-8')
        self.raw_info = ''
        self.owner = {}
        self.info_dict = {}
        self.response_from = ''
        self._getWhoisInfo(whois_server)

    def getDomainName(self):
        return self.domain_name.encode('utf-8').decode('idna')

    def _get_whois(self, whois, domain=''):
        if domain == '':
            domain = self.domain_name
        else:
            self.domain_name=domain
        whois = whois.lower()
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.connect((whois, 43))
        except Exception:
            print('Error connecting to ', whois)
            return False
        s.send((domain + "\r\n").encode())
        response = b""
        self.response_from = whois
        while True:
            data = s.recv(4096)
            response += data
            if not data:
                break
        s.close()
        whois_ip = dict()
        self.raw_info += whois + ' response for domain ' + decodeDomainName(domain) + ':\n\n'
        self.raw_info += response.decode()
        self.raw_info += '----------------\n\n'
        for ln in response.decode().splitlines():
            if ln.strip().startswith("%") or not ln.strip():
                continue
            else:
                try:
                    if len(ln.strip().split(": ")) > 1:
                        whois_ip.update({ln.strip().split(": ", 1)[0].strip(): ln.strip().split(": ", 1)[1].strip()})
                    else:
                        whois_ip.update({ln.strip().split(":\t", 1)[0].strip(): ln.strip().split(":\t", 1)[1].strip()})
                except Exception: 
                    pass
        if whois_ip:
            for key in whois_ip.keys():
                if key in self.info_dict.keys():
                    if whois_ip[key].lower() not in self.info_dict[key].lower():
                        self.info_dict[key] += ' | ' + whois_ip[key]
                else:
                    self.info_dict[key] = whois_ip[key]
        if 'Registrar WHOIS Server' in whois_ip.keys():
            if getDomainNameByUrl(whois_ip['Registrar WHOIS Server']) != whois:
                whois_ip = self._get_whois(getDomainNameByUrl(whois_ip['Registrar WHOIS Server']))
        return whois_ip if whois_ip else False

    def _getWhoisInfo(self, whois_server):
        if whois_server == '':
            if whois := ianna(self.domain_name):
                time.sleep(1)
                w = self._get_whois(whois)
                while not w and len(self.domain_name.split('.')) > 2:
                    w = self._get_whois(whois, self.domain_name.split('.', 1)[1])
            else:
                w = self._get_whois('whois.ripe.net')
                while not w and len(self.domain_name.split('.')) > 2:
                    w = self._get_whois(whois, self.domain_name.split('.', 1)[1])
        else:
            w = self._get_whois(whois_server)
            while not w and len(self.domain_name.split('.')) > 2:
                w = self._get_whois(whois, self.domain_name.split('.', 1)[1])
        for key in self.info_dict.keys():
            if key.lower() in ['org', 'organization', 'registrant organization', 'organisation', 'registrant organisation']:
                self.owner['org'] = self.info_dict[key]
            if key.lower() in ['name', 'registrant name', 'registrant']:
                self.owner['name'] = self.info_dict[key]
            if key.lower() in ['person', 'registrant person']:
                self.owner['person'] = self.info_dict[key]
        if 'name' not in self.owner.keys():
            self.owner['name'] = 'None'
        if 'org' not in self.owner.keys():
            self.owner['org'] = 'None'
        if 'person' not in self.owner.keys():
            self.owner['person'] = 'None'


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
    return whois if whois else False
