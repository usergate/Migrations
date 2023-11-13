#!/usr/bin/python3
from dataclasses import dataclass

@dataclass(frozen = True)
class ServicePorts:
    tcp = {
        '1': 'tcpmux',
        '7': 'echo-tcp',
        '9': 'discard-udp',
        '11': 'systat',
        '13': 'daytime-tcp',
        '15': 'netstat',
        '17': 'qotd',
        '19': 'chargen-tcp',
        '20': 'ftp-data',
        '21': 'ftp-control',
        '22': 'SSH',
        '23': 'Telnet',
        '25': 'SMTP',
        '37': 'time-tcp',
        '43': 'whois',
        '49': 'tacacs-tcp',
        '53': 'DNS-tcp',
        '67': 'DHCP-tcp',
        '70': 'gopher',
        '79': 'finger',
        '80': 'HTTP',
        '88': 'kerberos-tcp',
        '102': 'iso-tsap',
        '104': 'acr-nema',
        '106': 'poppassd',
        '109': 'pop2',
        '110': 'POP3',
        '111': 'RPC portmapper-tcp',
        '113': 'auth tap ident',
        '119': 'nntp',
        '135':  'epmap',
        '139': 'Netbios session service',
        '143': 'IMAP',
        '161': 'SNMP-tcp',
        '162': 'SNMPTRAP-tcp',
        '163': '',
        '443': 'HTTPS',
        '445': 'SMB',
        '465': 'SMTPS',
        '873': 'Rsync',
        '993': 'IMAPS',
        '995': 'POP3S',
        '1194': 'OpenVPN-tcp',
        '1433-1434': 'MS SQL',
        '1494': 'Citrix',
        '1503': 'NetMeeting',
        '1645-1646': 'Radius-tcp',
        '1723': 'VPN PPTP - tcp',
        '2041-2042': 'Mail Agent',
        '2404': 'SCADA',
        '2598': 'Citrix',
        '3050': 'Firebird',
        '3306': 'MySQL',
        '3389': 'RDP',
        '3690': 'SVN-tcp',
        '4899': 'Radmin',
        '5000': 'UPnP',
        '5004-5005': 'RTP-tcp',
        '5060': 'SIP-tcp-5090',
        '5061': 'SIP auth',
        '5060-5061': 'SIP-tcp',
        '5190': 'ICQ',
        '5222': 'XMPP-CLIENT',
        '5269': 'XMPP-SERVER',
        '5432': 'Postgres SQL',
        '6665-6669': 'IRC',
        '6881-6999': 'Torrents-tcp',
        '8080': 'CheckPoint Proxy',
        '8090': 'HTTP Proxy',
        '8091': 'HTTPS Proxy',
        '1000-65535': 'TCP 1000-65535',
        '10053': 'DNS Proxy-tcp',
        }
    udp = {
        '7': 'echo-udp',
        '9': 'discard-udp',
        '13': 'daytime-udp',
        '19': 'chargen-udp',
        '37': 'time-udp',
        '49': 'tacacs-udp',
        '53': 'DNS-udp',
        '67': 'DHCP bootps',
        '68': 'DHCP bootpc',
        '69': 'TFTP',
        '80': 'Quick UDP Internet Connections (port 80)',
        '87': 'Client-Bank Sberbank',
        '88': 'kerberos-udp',
        '111': 'RPC portmapper-udp',
        '123': 'NTP',
        '137': 'Netbios Name Service',
        '138': 'Netbios Datagram Service',
        '161': 'SNMP-udp',
        '162': 'SNMPTRAP-udp',
        '443': 'Quick UDP Internet Connections (port 443)',
        '1194': 'OpenVPN-udp',
        '1645-1646': 'Radius-udp',
        '3690': 'SVN-udp',
        '4500': 'IPSec-udp',
        '5004-5005': 'RTP-udp',
        '5060': 'SIP-udp',
        '5777': 'VipNet Client (port 5777)',
        '6881-6999': 'Torrents-udp',
        '1000-65535': 'UDP 1000-65535',
        '10053': 'DNS Proxy-udp',
        '55777': 'VipNet Client (port 55777)',
        }

    @classmethod
    def get_dict_by_port(cls, proto, service_port, service_name):
        try:
            if proto == 'tcp':
                return {'type': 'service', 'name': cls.tcp[service_port]}
            else:
                return {'type': 'service', 'name': cls.udp[service_port]}
        except KeyError:
            return {'type': 'service', 'name': service_name}

    @classmethod
    def get_name_by_port(cls, proto, service_port, service_name):
        try:
            if proto == 'tcp':
                return cls.tcp[service_port]
            else:
                return cls.udp[service_port]
        except KeyError:
            return service_name

dict_risk = {
    'Very Low': 1,
    'Low': 2,
    'Medium': 3,
    'High': 4,
    'Critical': 5,
    'Unknown': 1,
}

character_map = {
    ord('\n'): None,
    ord('\t'): None,
    ord('\r'): None,
    ' ': '_',
    '/': '_',
    '\\': '_',
    '.': '_',
}

character_map_file_name = {
    ord('\n'): None,
    ord('\t'): None,
    ord('\r'): None,
    ord(' '): '_',
    '#': None,
    '=': '_',
    ':': '_',
    '"': None,
    "'": None,
    '!': '_',
    '?': '_',
    '@': '_',
    ';': None,
    '$': None,
    '%': None,
    '&': None,
    '?': None,
    '[': None,
    ']': None,
    '{': None,
    '}': None,
    '*': '_',
    '+': '_',
    '<': None,
    '>': None,
    '|': None,
    '/': '_',
    '\\': None,
}

character_map_for_name = {
    '#': None,
    '=': ' ',
    ':': '_',
    '"': None,
    "'": None,
    '!': None,
    '@': None,
    ';': " ",
    '%': None,
    '$': None,
    '&': ",",
    '^': None,
    '*': None,
    '?': None,
    '[': None,
    ']': None,
    '{': None,
    '}': None,
    '<': None,
    '>': None,
    '|': "_",
    '+': " ",
    '\\': None,
}

ip_proto = {
    '0': 'ip',          # ASA
    '1': 'icmp',        # ASA
    '2': 'igmp',        # ASA
    '3': 'ggp',
    '4': 'ipip',        # ASA
    '5': 'st',
    '8': 'egp',
    '9': 'igp',
    "11": 'pup',
    '20': 'hmp',
    '22': 'xns-idp',
    '27': 'rdp',
    '29': 'iso-tp4',
    '33': 'dccp',
    '36': 'xtp',
    '37': 'ddp',
    '38': 'idpr-cmtp',
    '41': 'ipv6',
    '43': 'ipv6-route',
    '44': 'ipv6-frag',
    '45': 'idrp',
    '46': 'rsvp',
    '47': 'gre',        # ASA
    '50': 'esp',        # ASA
    '51': 'ah',         # ASA
    '57': 'skip',
    '58': 'ipv6-icmp',  # ASA
    '59': 'ipv6-nonxt',
    '60': 'ipv6-opts',
    '81': 'vmtp',
    '88': 'eigrp',      # ASA
    '89': 'ospf',       # ASA
    '93': 'ax.25',
    '94': 'nos',        # ASA
    '97': 'etherip',
    '98': 'encap',
    '103': 'pim',       # ASA
    '108': 'ipcomp',
    '109': 'snp',        # ASA
    '112': 'vrrp',
    '115': 'l2tp',
    '124': 'isis',
    '132': 'sctp',
    '133': 'fc',
    '135': 'mobility-header',
    '136': 'udplite',
    '137': 'mpls-in-ip',
    '138': 'manet',
    '139': 'hip',
    '140': 'shim6',
    '141': 'wesp',
    '142': 'rohc'
}

ug_services = {
    'https': 'HTTPS',
    'imap4': 'IMAP',
    'ntp': 'NTP',
    'pop3': 'POP3',
    'postgresql': 'Postgres SQL',
    'smtp': 'SMTP',
    'snmp': 'SNMP',
    'ssh': 'SSH',
    'www': 'HTTP',
    '873': 'Rsync',
    '80': 'HTTP',
    '5432': 'Postgres SQL',
}
