#!/usr/bin/python3
#
# asa_convert_config (convert Cisco ASA configuration to NGFW UserGate).
#
# Copyright @ 2021-2022 UserGate Corporation. All rights reserved.
# Author: Aleksei Remnev <ran1024@yandex.ru>
# License: GPLv3
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License along
# with this program; if not, contact the site <https://www.gnu.org/licenses/>.
#
#--------------------------------------------------------------------------------------------------- 
# Модуль переноса конфигурации с устройств Fortigate на NGFW UserGate.
# Версия 0.1
#

import os, sys, json
import ipaddress
import copy
import common_func as func
from datetime import datetime as dt
from PyQt6.QtCore import QThread, pyqtSignal
from services import zone_services, character_map, character_map_for_name, character_map_file_name, ug_services


trans_table = str.maketrans(character_map)
trans_filename = str.maketrans(character_map_file_name)
trans_name = str.maketrans(character_map_for_name)

class ConvertFortigateConfig(QThread):
    """Преобразуем файл конфигурации Fortigate в формат UserGate NGFW."""
    stepChanged = pyqtSignal(str)

    def __init__(self, current_fg_path, current_ug_path):
        super().__init__()
        self.current_fg_path = current_fg_path
        self.current_ug_path = current_ug_path
        self.error = 0

    def run(self):
#        convert_config_file(self, self.current_fg_path)

        json_file = os.path.join(self.current_fg_path, 'config.json')
        err, data = func.read_json_file(self, json_file)
        if err:
            self.error = 1
        else:
            convert_vpn_interfaces(self, self.current_ug_path, data['config system interface'])
            convert_dns_servers(self, self.current_ug_path, data['config system dns'])
            convert_url_list(self, self.current_ug_path, data['config wanopt content-delivery-network-rule'])

        if self.error:
            self.stepChanged.emit('iORANGE|Конвертация конфигурации Fortigate в формат UserGate NGFW прошла с ошибками.')
        else:
            self.stepChanged.emit('iGREEN|Конвертация конфигурации Fortigate в формат UserGate NGFW прошла успешно.')


def convert_config_file(parent, path):
    """Преобразуем файл конфигурации Fortigate в формат json."""
    parent.stepChanged.emit('BLUE|Конвертация файла конфигурации Fortigate в формат json.')
    if not os.path.isdir(path):
        parent.stepChanged.emit('RED|    Не найден каталог с конфигурацией Fortigate.')
        parent.error = 1
        return
    error = 0
    data = {}
    config_file = 'fortigate.cfg'
    bad_cert_block = {'config firewall ssh local-key',
                      'config firewall ssh local-ca',
                      'config vpn certificate ca',
                      'config vpn certificate local'}
    fg_config_file = os.path.join(path, config_file)
    try:
        with open(fg_config_file, "r") as fh:
            line = fh.readline()
            while line:
                x = line.translate(trans_table).split(' ')
                if x[0].startswith('config'):
                    key = ' '.join(x).replace('"', '')
                    config_block = []
                    line = fh.readline()
                    x = line.translate(trans_table).split(' ')
                    while x[0] != 'end':
                        for i, y in enumerate(x):
                            x[i] = y.replace('"', '')
                        config_block.append(x)
                        line = fh.readline()
                        x = line.translate(trans_table).split(' ')
                        if len(x) == 2 and x[1] == 'end':
                            break
                    if key not in bad_cert_block:
                        block = make_conf_block(parent, config_block)
                        data[key] = block
                line = fh.readline()
    except FileNotFoundError:
        parent.stepChanged.emit(f'RED|    Не найден файл "{config_file}" в каталоге "{path}" с конфигурацией Fortigate.')
        parent.error = 1
        return

    json_file = os.path.join(path, 'config.json')
    with open(json_file, 'w') as fh:
        json.dump(data, fh, indent=4, ensure_ascii=False)

    if parent.error:
        error = 1
    out_message = f'BLACK|    Конфигурация Fortigate в формате json выгружена в файл "{json_file}".'
    parent.stepChanged.emit('ORANGE|    Ошибка экспорта конфигурации Fortigate в формат json.' if error else out_message)

def make_edit_block(parent, data):
    """Конвертируем блок edit"""
#    print('\n--- make_edit_block ---')
#    for x in data:
#        print(x)
    edit_block = {}
    while data:
        item = data.pop(0)[4:]
        match item[0]:
            case 'set':
                edit_block[item[1]] = ' '.join(item[2:])
            case 'config':
                conf_block = []
                conf_key = ' '.join(item[1:])
                item = data.pop(0)[4:]
#                    while item[0] != 'end':
                while len(item) > 4:
                    conf_block.append(item)
                    item = data.pop(0)[4:]
                result = make_conf_block(parent, conf_block)
#                    print('result - ', result)
                edit_block[conf_key] = result
    return edit_block

def make_conf_block(parent, data):
    """Конвертируем блок config"""
#        print('\n--- make_config_block ---')
#        for x in data:
#            print(x)
    block = {}
    name = {}
    while data:
        item = data.pop(0)[4:]
#        print('\nitem conf_block -', item)
        match item[0]:
            case 'set':
                block[item[1]] = ' '.join(item[2:])
            case 'edit':
                edit_block = []
                edit_key = ' '.join(item[1:])
                if edit_key in name:
                    name[edit_key] += 1
                    edit_key += str(name[edit_key])
                else:
                    name[edit_key] = 0
                item = data.pop(0)[4:]
                try:
                    while item[0] != 'next':
                        edit_block.append(item)
                        item = data.pop(0)[4:]
                except IndexError:
                    parent.stepChanged.emit(f'RED|    Не корректная структура блока "{edit_key}". Исправьте формат блока и повторите попытку.')
                    parent.error = 1
                    break
                result = make_edit_block(parent, edit_block)
#                print('result edit - ', result)
                block[edit_key] = result
            case 'config':
#                print('Зашли в config:')
                conf_block = []
                conf_key = ' '.join(item[1:])
                item = data.pop(0)[4:]
#                while item[0] != 'end':
                while len(item) > 4:
                    conf_block.append(item)
                    item = data.pop(0)[4:]
#                print('conf_block -', conf_block)
                result = make_conf_block(parent, conf_block)
#                print('result config - ', result)
                block[conf_key] = result
    return block


def convert_vpn_interfaces(parent, path, interfaces):
    """Конвертируем интерфейсы VLAN."""
    parent.stepChanged.emit('BLUE|Конвертация интерфейсов VLAN.')
    section_path = os.path.join(path, 'Network')
    current_path = os.path.join(section_path, 'Interfaces')
    err, msg = func.create_dir(current_path)
    if err:
        parent.stepChanged.emit(f'RED|    {msg}.')
        parent.error = 1
        return

    ifaces = []
    for ifname, ifblock in interfaces.items():
        if 'vlanid' in ifblock:
            ip, mask = ifblock['ip'].split(' ')
            iface = {
                "name": ifname,
                "kind": "vlan",
                "enabled": False,
                "description": "",
                "zone_id": 0,
                "master": False,
                "netflow_profile": "undefined",
                "lldp_profile": "undefined",
                "ipv4": [pack_ip_address(ip, mask)],
                "ifalias": ifblock.get('alias', ''),
                "flow_control": False,
                "mode": "static",
                "mtu": 1500,
                "tap": False,
                "dhcp_relay": {
                    "enabled": False,
                    "host_ipv4": "",
                    "servers": []
                },
                "vlan_id": int(ifblock.get('vlanid', 0)),
                "link": ifblock.get('interface', '')
            }
            ifaces.append(iface)

    json_file = os.path.join(current_path, 'config_interfaces.json')
    with open(json_file, 'w') as fh:
        json.dump(ifaces, fh, indent=4, ensure_ascii=False)

    out_message = f'BLACK|    Интерфейсы VLAN выгружены в файл "{json_file}".'
    parent.stepChanged.emit('GRAY|    Нет интерфейсов VLAN для экспорта.' if not ifaces else out_message)


def convert_dns_servers(parent, path, dns_info):
    """Заполняем список системных DNS"""
    parent.stepChanged.emit('BLUE|Конвертация серверов DNS.')
    section_path = os.path.join(path, 'Network')
    current_path = os.path.join(section_path, 'DNS')
    err, msg = func.create_dir(current_path, delete='no')
    if err:
        parent.stepChanged.emit(f'RED|    {msg}.')
        parent.error = 1
        return

    dns_servers = []
    for key, value in dns_info.items():
        if key in {'primary', 'secondary'}:
            dns_servers.append({'dns': value, 'is_bad': False})
        
    json_file = os.path.join(current_path, 'config_dns_servers.json')
    with open(json_file, 'w') as fh:
        json.dump(dns_servers, fh, indent=4, ensure_ascii=False)

    out_message = f'BLACK|    Настройки серверов DNS выгружены в файл "{json_file}".'
    parent.stepChanged.emit('GRAY|    Нет серверов DNS для экспорта.' if not dns_servers else out_message)

def convert_url_list(parent, path, urls_block):
    """Конвертируем URL-листы."""
    parent.stepChanged.emit('BLUE|Конвертация списков URL.')
    section_path = os.path.join(path, 'Libraries')
    current_path = os.path.join(section_path, 'URLLists')
    print(current_path)
    err, msg = func.create_dir(current_path)
    if err:
        parent.stepChanged.emit(f'RED|    {msg}.')
        parent.error = 1
        return

    urls_list = []
    for key, value in urls_block.items():
        _, pattern = key.split(':')
        if pattern == '//':
            list_name = 'All URLs (default)'
        else:
            list_name = pattern.replace('/', '')

        if 'host-domain-name-suffix' not in value and list_name != 'All URLs (default)':
            parent.stepChanged.emit(f'rNOTE|    Запись "{key}" не конвертирована так как не имеет host-domain-name-suffix.')
            continue
        for suffix in value.get('host-domain-name-suffix', '').split(' '):
            print('    ', suffix)

    return        

    url_list = {
        "name": name,
        "description": "",
        "type": "url",
        "url": "",
        "list_type_update": "static",
        "schedule": "disabled",
        "attributes": {"list_compile_type": "case_sensitive", "threat_level": 3},
        "content": [{"value": url}]
    }

    json_file = os.path.join(current_path, 'config_dns_servers.json')
    with open(json_file, 'w') as fh:
        json.dump(dns_servers, fh, indent=4, ensure_ascii=False)

    out_message = f'BLACK|    Настройки серверов DNS выгружены в файл "{json_file}".'
    parent.stepChanged.emit('GRAY|    Нет серверов DNS для экспорта.' if not dns_servers else out_message)

#    err, protocol_names = utm.get_ip_protocol_list()
#    exit_if_error(err, protocol_names)
    # default_vrf = {
        # "name": "default",
        # "descriprion": "",
        # "interfaces": [],
        # "routes": [],
        # "ospf": {},
        # "bgp": {},
        # "rip": {},
        # "pimsm": {}
    # }
    # time_zone = {
        # "2": "Europe/Kaliningrad",
        # "3": "Europe/Moscow",
        # "4": "Europe/Samara",
        # "5": "Asia/Yekaterinburg",
        # "6": "Asia/Omsk",
        # "7": "Asia/Krasnoyarsk",
        # "8": "Asia/Irkutsk",
        # "9": "Asia/Yakutsk",
        # "10": "Asia/Vladivostok",
        # "11": "Asia/Magadan",
        # "12": "Asia/Kamchatka"
    # }
    # ntp = {
        # "ntp_servers": [],
        # "ntp_enabled": True,
        # "ntp_synced": True
    # }

def convert_modules(x):
    """Выгружаем UserGate->Настройки->Модули"""
    data = {
        "auth_captive": f"auth.{x[1]}",
        "logout_captive": f"logout.{x[1]}",
        "block_page_domain": f"block.{x[1]}",
        "ftpclient_captive": f"ftpclient.{x[1]}",
        "ftp_proxy_enabled": False,
        "http_cache_mode": "off",
        "http_cache_docsize_max": 1,
        "http_cache_precache_size": 64,
    }
    if not os.path.isdir('data/UserGate/GeneralSettings'):
        os.makedirs('data/UserGate/GeneralSettings')
    with open('data/UserGate/GeneralSettings/config_settings.json', 'w') as fh:
        json.dump(data, fh, indent=4, ensure_ascii=False)

def convert_zone(zone_name, mtu):
    """Создаём зону"""
    if x[1].lower() != 'management':
        zone = {
            "name": zone_name.translate(trans_name),
            "description": "",
            "dos_profiles": [
                {
                    "enabled": True,
                    "kind": "syn",
                    "alert_threshold": 3000,
                    "drop_threshold": 6000,
                    "aggregate": False,
                    "excluded_ips": []
                },
                {
                    "enabled": True,
                    "kind": "udp",
                    "alert_threshold": 3000,
                    "drop_threshold": 6000,
                    "aggregate": False,
                    "excluded_ips": []
                },
                {
                    "enabled": True,
                    "kind": "icmp",
                    "alert_threshold": 100,
                    "drop_threshold": 200,
                    "aggregate": False,
                    "excluded_ips": []
                }
            ],
            "services_access": [
                {
                    'enabled': True,
                    'service_id': 1,
                    'allowed_ips': []
                },
                {
                    'enabled': False,
                    'service_id': 2,
                    'allowed_ips': []
                },
                {
                    'enabled': False,
                    'service_id': 4,
                    'allowed_ips': []
                },
                {
                    'enabled': False,
                    'service_id': 5,
                    'allowed_ips': []
                },
                {
                    'enabled': False,
                    'service_id': 6,
                    'allowed_ips': []
                },
                {
                    'enabled': False,
                    'service_id': 7,
                    'allowed_ips': []
                },
                {
                    'enabled': False,
                    'service_id': 8,
                    'allowed_ips': []
                },
                {
                    'enabled': False,
                    'service_id': 9,
                    'allowed_ips': []
                },
                {
                    'enabled': False,
                    'service_id': 10,
                    'allowed_ips': []
                },
                {
                    'enabled': False,
                    'service_id': 11,
                    'allowed_ips': []
                },
                {
                    'enabled': False,
                    'service_id': 12,
                    'allowed_ips': []
                },
                {
                    'enabled': False,
                    'service_id': 13,
                    'allowed_ips': []
                },
                {
                    'enabled': False,
                    'service_id': 14,
                    'allowed_ips': []
                },
                {
                    'enabled': False,
                    'service_id': 15,
                    'allowed_ips': []
                },
                {
                    'enabled': False,
                    'service_id': 16,
                    'allowed_ips': []
                },
                {
                    'enabled': False,
                    'service_id': 17,
                    'allowed_ips': []
                },
                {
                    'enabled': False,
                    'service_id': 18,
                    'allowed_ips': []
                },
                {
                    'enabled': False,
                    'service_id': 19,
                    'allowed_ips': []
                },
                {
                    'enabled': False,
                    'service_id': 20,
                    'allowed_ips': []
                },
                {
                    'enabled': False,
                    'service_id': 21,
                    'allowed_ips': []
                },
                {
                    'enabled': False,
                    'service_id': 22,
                    'allowed_ips': []
                },
                {
                    'enabled': False,
                    'service_id': 23,
                    'allowed_ips': []
                },
                {
                    'enabled': False,
                    'service_id': 24,
                    'allowed_ips': []
                },
                {
                    'enabled': False,
                    'service_id': 25,
                    'allowed_ips': []
                },
                {
                    'enabled': False,
                    'service_id': 26,
                    'allowed_ips': []
                },
                {
                    'enabled': False,
                    'service_id': 27,
                    'allowed_ips': []
                },
                {
                    'enabled': False,
                    'service_id': 28,
                    'allowed_ips': []
                },
                {
                    'enabled': False,
                    'service_id': 29,
                    'allowed_ips': []
                },
                {
                    'enabled': False,
                    'service_id': 30,
                    'allowed_ips': []
                }
            ],
            "readonly": False,
            "enable_antispoof": False,
            "antispoof_invert": False,
            "networks": [],
            "sessions_limit_enabled": False,
            "sessions_limit_threshold": 0,
            "sessions_limit_exclusions": [],
        }
        zones[zone_name] = zone
        iface_mtu[zone_name] = int(mtu)

def convert_zone_access(array):
    """Устанавливаем контроль доступа для зоны"""
    match array:
        case [service, 'domain-lookup', zone_name]:
            if zone_name in zones:
                for service in zones[zone_name]['services_access']:
                    if service['service_id'] == 9:
                        service['enabled'] = True
        case ['telnet' | 'ssh', ip, mask, zone_name]:
            if zone_name in zones:
                if ip in ('version', 'key-exchange', 'cipher'):
                    return
                ipv4 = pack_ip_address(ip, mask)
                for service in zones[zone_name]['services_access']:
                    if service['service_id'] == 14:
                        service['enabled'] = True
                        service['allowed_ips'].append(ipv4)
        case ['http', ip, mask, zone_name]:
            if zone_name in zones:
                ipv4 = pack_ip_address(ip, mask)
                for service in zones[zone_name]['services_access']:
                    if service['service_id'] == 4:
                        service['enabled'] = True
                    elif service['service_id'] == 8:
                        service['enabled'] = True
                        service['allowed_ips'].append(ipv4)

def convert_dns_rules(rule_name, tmp_block):
    """Создаём правило DNS прокси Сеть->DNS->DNS-прокси->Правила DNS"""
    dns_rule = {
        "name": rule_name,
        "description": "",
        "enabled": True,
        "domains": [],
        "dns_servers": [],
    }
    for item in tmp_block:
        match item[0]:
            case 'name-server':
                dns_rule['dns_servers'].append(item[1])
            case 'domain-name':
                dns_rule['domains'].append(f'*.{item[1]}')
    if dns_rule['domains']:
        dns_rules.append(dns_rule)
    else:
        for x in dns_rule['dns_servers']:
            system_dns.append({'dns': x, 'is_bad': False})

def convert_route(array):
    """Конвертируем шлюзы и статические маршруты в VRF по умолчанию"""
    [iface, network, mask, next_hop, *other] = array[1:]
    iface = iface.translate(trans_name)
    if network == '0':
        network = '0.0.0.0'
    if mask == '0':
        mask = '0.0.0.0'
    if network == mask == '0.0.0.0':
        gateway = {
            "name": f"{iface} (backup)" if gateways and gateways[0]['name'] == iface else iface,
            "enabled": True,
            "description": "",
            "ipv4": next_hop,
            "vrf": "default",
            "weight": int(other[0]),
            "multigate": False,
            "default": False if gateways else True,
            "iface": "undefined",
            "is_automatic": False,
            "active": True
        }
        gateways.append(gateway)
    else:
        network_dest = pack_ip_address(network, mask)
        route = {
            "name": f"Route for {network_dest}",
            "description": "",
            "enabled": False,
            "dest": network_dest,
            "gateway": next_hop,
            "ifname": "undefined",
            "kind": "unicast",
            "metric": int(other[0])
        }
        default_vrf['routes'].append(route)

def convert_auth_servers(x, tmp_block):
    """Конвертируем сервера авторизации"""
    match x:
        case ['aaa-server', auth_server_name, 'protocol', protocol]:
            if protocol.startswith('tacacs'):
                auth_servers[auth_server_name] = {
                    "name": f"{auth_server_name} (tacacs)",
                    "description": "tacacs",
                    "enabled": True,
                    "use_single_connection": False,
                    "timeout": 4,
                    "address": "",
                    "port": 49,
                    "secret": "",
            }
            if protocol == 'radius':
                auth_servers[auth_server_name] = {
                    "name": f"{auth_server_name} (radius)",
                    "description": "radius",
                    "enabled": True,
                    "secret": "",
                    "addresses": []
            }
            if protocol == 'ldap':
                auth_servers[auth_server_name] = {
                    "name": f"{auth_server_name} (ldap)",
                    "description": "ldap",
                    "enabled": True,
                    "ssl": False,
                    "address": "",
                    "bind_dn": "",
                    "password": "",
                    "domains": [],
                    "roots": [],
                    "keytab_exists": False
            }
            if protocol == 'kerberos':
                auth_servers[auth_server_name] = {
                    "name": f"{auth_server_name} (kerberos)",
                    "description": "ldap",
                    "enabled": True,
                    "ssl": False,
                    "address": "",
                    "bind_dn": "",
                    "password": "",
                    "domains": [],
                    "roots": [],
                    "keytab_exists": False
            }
        case ['aaa-server', auth_server_name, zone_name, 'host', ip]:
            if auth_server_name in auth_servers:
                if auth_servers[auth_server_name]['description'] == 'tacacs':
                    auth_servers[auth_server_name]['address'] = ip
                    for item in tmp_block:
                        if item[0] == 'key':
                            auth_servers[auth_server_name]['secret'] = item[1]
                        if item[0] == 'timeout':
                            auth_servers[auth_server_name]['timeout'] = int(item[1])
                        if item[0] == 'server-port':
                            auth_servers[auth_server_name]['port'] = item[1]
                if auth_servers[auth_server_name]['description'] == 'radius':
                    address = {'host': ip, 'port': 1812}
                    for item in tmp_block:
                        if item[0] == 'key':
                            auth_servers[auth_server_name]['secret'] = item[1]
                        elif item[0] == 'authentication-port':
                            address['port'] = item[1]
                    auth_servers[auth_server_name]['addresses'].append(address)
                if auth_servers[auth_server_name]['description'] == 'ldap':
                    if not auth_servers[auth_server_name]['address']:
                        auth_servers[auth_server_name]['address'] = ip
                        dn = ''
                        for item in tmp_block:
                            if item[0] == 'ldap-base-dn':
                                dn = ".".join([y[1] for y in [x.split("=") for x in item[1].split(",")]]).lower()
                                auth_servers[auth_server_name]['domains'].append(dn)
                                auth_servers[auth_server_name]['roots'].append(item[1])
                            elif item[0] == 'ldap-login-dn':
                                login = item[1] if '=' in item[1] else f"{item[1]}@{dn}"
                                auth_servers[auth_server_name]['bind_dn'] = login
                            elif item[0] == 'ldap-login-password':
                                auth_servers[auth_server_name]['password'] = item[1]
                            elif item[0] == 'ldap-over-ssl' and item[1] == 'enable':
                                auth_servers[auth_server_name]['ssl'] = True
                            elif item[0] == 'kerberos-realm':
                                auth_servers[auth_server_name]['domains'].append(item[1])
                                auth_servers[auth_server_name]['roots'].append(item[1])
                                auth_servers[auth_server_name]['bind_dn'] = f"login@{item[1]}"
                                auth_servers[auth_server_name]['password'] = "secret"
                    else:
                        convert_auth_servers(['aaa-server', f'{auth_server_name} ({ip})', 'protocol', 'ldap'], [])
                        convert_auth_servers(['aaa-server', f'{auth_server_name} ({ip})', zone_name, 'host', ip], tmp_block)

def convert_time_sets(rule_name, tmp_block):
    """Конвертируем time set (календари)"""
    week = {
        "Monday": 1,
        "Tuesday": 2,
        "Wednesday": 3,
        "Thursday": 4,
        "Friday": 5,
        "Saturday": 6,
        "Sunday": 7
    }
    timerestrictiongroup[rule_name] = {
        "name": rule_name.translate(trans_name),
        "description": "",
        "type": "timerestrictiongroup",
        "url": "",
        "list_type_update": "static",
        "schedule": "disabled",
        "attributes": {},
        "content": []
    }
    i = 0
    for item in tmp_block:
        i += 1
        time_restriction = {
            "name": f"{timerestrictiongroup[rule_name]['name']} {i}",
            "type": "span" if item[0] == "absolute" else "weekly"
        }
        match item:
            case ['absolute', 'start' | 'end', time, day, month, year]:
                if item[1] == 'start':
                    time_restriction['time_from'] = time
                    time_restriction['fixed_date_from'] = dt.strptime(f"{day}-{month}-{year}", '%d-%B-%Y').strftime('%Y-%m-%dT%H:%M:%S')
                elif item[1] == 'end':
                    time_restriction['time_to'] = time
                    time_restriction['fixed_date_to'] = dt.strptime(f"{day}-{month}-{year}", '%d-%B-%Y').strftime('%Y-%m-%dT%H:%M:%S')
            case ['absolute', 'start', start_time, start_day, start_month, start_year, 'end', end_time, end_day, end_month, end_year]:
                time_restriction['time_from'] = start_time
                time_restriction['fixed_date_from'] = dt.strptime(f"{start_day}-{start_month}-{start_year}", '%d-%B-%Y').strftime('%Y-%m-%dT%H:%M:%S')
                time_restriction['time_to'] = end_time
                time_restriction['fixed_date_to'] = dt.strptime(f"{end_day}-{end_month}-{end_year}", '%d-%B-%Y').strftime('%Y-%m-%dT%H:%M:%S')
            case ['absolute', 'end', end_time, end_day, end_month, end_year, 'start', start_time, start_day, start_month, start_year]:
                time_restriction['time_from'] = start_time
                time_restriction['fixed_date_from'] = dt.strptime(f"{start_day}-{start_month}-{start_year}", '%d-%B-%Y').strftime('%Y-%m-%dT%H:%M:%S')
                time_restriction['time_to'] = end_time
                time_restriction['fixed_date_to'] = dt.strptime(f"{end_day}-{end_month}-{end_year}", '%d-%B-%Y').strftime('%Y-%m-%dT%H:%M:%S')
            case ['periodic', *time_set]:
                if time_set[0] in ('weekend', 'weekdays', 'daily'):
                    time_restriction['time_from'] = time_set[1] if time_set[1] != 'to' else '00:00'
                    time_restriction['time_to'] = time_set[len(time_set)-1]
                    if time_set[0] == 'daily':
                        time_restriction['type'] = 'daily'
                    else:
                        time_restriction['days'] = [6, 7] if time_set[0] == 'weekend' else [1, 2, 3, 4, 5]
                else:
                    start, end = time_set[:time_set.index('to')], time_set[time_set.index('to')+1:]
                    days = set()
                    for x in start:
                        if week.get(x, None):
                            days.add(week[x])
                        else:
                            time_restriction['time_from'] = x
                    for x in end:
                        if week.get(x, None):
                            days = {y for y in range(min(days), week[x]+1)}
                        else:
                            time_restriction['time_to'] = x
                    if not time_restriction.get('time_from', None):
                        time_restriction['time_from'] = "00:00"
                    if not time_restriction.get('time_to', None):
                        time_restriction['time_to'] = "23:59"
                    if days:
                        time_restriction['days'] = sorted(list(days))
                    else:
                        time_restriction['type'] = 'daily'

        timerestrictiongroup[rule_name]['content'].append(time_restriction)

def convert_settings_ui(x):
    """Конвертируем часовой пояс и настройки интерфейса"""
    data = {
        "ui_timezone": time_zone.get(x[3], "Europe/Moscow"),
        "ui_language": "ru",
        "web_console_ssl_profile_id": "Default SSL profile (web console)",
        "response_pages_ssl_profile_id": "Default SSL profile",
        "webui_auth_mode": "password"
    }

    if not os.path.isdir('data/UserGate/GeneralSettings'):
        os.makedirs('data/UserGate/GeneralSettings')
    with open('data/UserGate/GeneralSettings/config_settings_ui.json', 'w') as fh:
        json.dump(data, fh, indent=4, ensure_ascii=False)

def convert_ntp_settings(x):
    """Конвертируем настройки для NTP"""
    match x:
        case ['ntp', 'server', ip, *other]:
            if len(ntp['ntp_servers']) < 2:
                ntp['ntp_servers'].append(ip)

#def convert_dhcp_settings(line):
#    """Конвертируем настройки DHCP"""
#    nonlocal dhcp_enabled
#    if not dhcp_enabled:
#        while True:
#            task = input('\033[36mКонвертировать настройки DHCP subnets? ["yes", "no"]: \033[0m')
#            if task == "no":
#                dhcp_enabled = 1
#                return
#            elif task == "yes":
#                dhcp_enabled = 2
#                break
#    elif dhcp_enabled == 1:
#        return
#    
#    match line:
#        case ['dhcp', 'address', ip_range, zone_name]:
#            err, data = utm.get_interfaces_list()
#            exit_if_error(err, data)
#            dst_ports = {x['name']: x.get('ipv4', None) for x in data if not x['name'].startswith('tunnel')}
#
#            print(f"\n\033[36mКонвертируется DHCP subnet\033[0m {ip_range} \033[36mУкажите порт UG-NGFW для него.\033[0m")
#            print(f"\033[36mСуществуют следующие порты:\033[0m {sorted(dst_ports.keys())}")
#            while True:
#                port = input("\033[36mВведите имя порта:\033[0m ")
#                if port not in dst_ports:
#                    print("\033[31m\tВы ввели несуществующий порт.\033[0m")
#                else:
#                    break
#
#            ips = ip_range.split('-')
#
#            if dst_ports[port]:
#                gateway = ipaddress.ip_interface(dst_ports[port][0])
#            else:
#                while True:
#                    gateway = input(f"\n\033[36mУ данного порта нет IP-адреса. Введите IP шлюза для subnet\033[0m {ip_range} [{ips[0]}/24]: ")
#                    try:
#                        gateway = ipaddress.ip_interface(gateway)
#                    except ValueError:
#                        print("\033[31m Введённый адрес не является IP-адресом.\033[0m")
#                    else:
#                        break
#            while True:
#                if ipaddress.ip_address(ips[0]) not in gateway.network:
#                    print(f"\033[31mIP-адреса диапазона {ip_range} не принадлежат подсети {gateway.network}\033[0m")
#                    gateway = input(f"\n\033[36mВведите IP шлюза для subnet\033[0m {ip_range} [{ips[0]}/24]: ")
#                    gateway = ipaddress.ip_interface(gateway)
#                else:
#                    break
#
#            dhcp[zone_name] = {
#                "node_name": utm.node_name,
#                "name": f"DHCP server for {zone_name}",
#                "enabled": False,
#                "description": "Перенесено с Cisco ASA",
#                "start_ip": ips[0],
#                "end_ip": ips[1],
#                "lease_time": 3600,
#                "domain": "",
#                "gateway": str(gateway.ip),
#                "boot_filename": "",
#                "boot_server_ip": "",
#                "iface_id": port,
#                "netmask": str(gateway.netmask),
#                "nameservers": [],
#                "ignored_macs": [],
#                "hosts": [],
#                "options": [],
#                "cc": 0
#            }
#        case ['dhcp', 'reserve-address', ip, mac, zone_name]:
#            dhcp[zone_name]['cc'] += 1
#            mac_address = ":".join([f"{x[:2]}:{x[2:]}" for x in mac.split('.')])
#            dhcp[zone_name]['hosts'].append({"mac": mac_address.upper(), "ipv4": ip, "hostname": f"any{dhcp[zone_name]['cc']}"})
#        case ['dhcp', 'dns', *ips]:
#            for item in dhcp:
#                for name_server in ips:
#                    dhcp[item]['nameservers'].append(name_server)
#        case ['dhcp', 'lease', lease]:
#            for item in dhcp:
#                dhcp[item]['lease_time'] = int(lease) if (120 < int(lease) < 3600000) else 3600
#        case ['dhcp', 'domain', name]:
#            for item in dhcp:
#                dhcp[item]['domain'] = name
#        case ['dhcp', 'option', code, 'ip'|'ascii', *ips]:
#            for item in dhcp:
#                dhcp[item]['options'].append([int(code), ", ".join(ips)])
#########################################################################################
#                    if code == '3':
#                        dhcp[item]['gateway'] = ips[0]
#                    else:

def convert_local_users(user_name, attribute):
    """Конвертируем локального пользователя"""
    if attribute == 'password':
        trans_table_for_users = str.maketrans(character_map_for_users)
        local_user = {
            "groups": [],
            "name": user_name,
            "enabled": True,
            "auth_login": user_name.translate(trans_table_for_users),
            "icap_clients": [],
            "is_ldap": False,
            "static_ip_addresses": [],
            "ldap_dn": "",
            "emails": [],
            "first_name": "",
            "last_name": "",
            "phones": []
        }
        users[user_name] = local_user

def convert_user_identity_domains(line):
    """Определяем домены идентификации"""
    match line:
        case ['domain', domain, 'aaa-server', server]:
            domain = domain.split(".")
            identity_domains[domain[0]] = auth_servers[server]['domains'][0]
        case ['default-domain', domain]:
            if domain != 'LOCAL':
                domain = domain.split(".")
                identity_domains['default'] = identity_domains[domain[0]]

def convert_user_groups_object_group(name, object_block):
    """Конвертируем локальные группы пользователей"""
    group = {
        "name": name,
        "description": "",
        "is_ldap": False,
        "is_transient": False,
        "users": []
    }
    for item in object_block:
        match item:
            case ['user', user]:
                user_list = user.split("\\")
                if user_list[0] == 'LOCAL' and user_list[1] in users:
                    group['users'].append(user_list[1])
                elif user_list[0] in identity_domains:
                    group['users'].append(f"{user_list[1]} ({identity_domains[user_list[0]]}\\{user_list[1]})")
                else:
                    if len(user_list) == 1:
                        if 'default' in identity_domains:
                            group['users'].append(f"{user_list[0]} ({identity_domains['default']}\\{user_list[0]})")
                        else:
                            group['users'].append(user_list[0])
            case ['group-object', group_name]:
                group['users'].extend(groups[group_name]['users'])
            case ['description', *content]:
                group['description'] = " ".join(content)

    groups[name] = group

def get_service_number(service):
    """Получить цифровое значение сервиса из его имени"""
    if service.isdigit():
        return service
    elif service in service_ports:
        return service_ports.get(service, service)

def convert_service_object(name, object_block):
    """Конвертируем сетевой сервис"""
    service = {
        "name": name,
        "description": "",
        "protocols": []
    }
    port = ''
    source_port = ''
    proto = ''

    for item in object_block:
        match item:
            case ['service', protocol]:
                if protocol.isdigit():
                    protocol = ip_proto.get(protocol, None)
                if protocol and protocol in ip_protocol_list:
                    proto = protocol
                else:
                    print(f"\033[31m\tСервис {name} не конвертирован. Протокол {protocol} не поддерживается в UG NGFW.\033[0m")
                    return
            case ['service', 'icmp', *other]:
                proto = 'icmp'
            case ['service', 'sctp', *other]:
                proto = 'sctp'
            case ['service', 'tcp' | 'udp', *other]:
                proto = item[1]
                match other:
                    case ['source', 'eq', src_port]:
                        source_port = get_service_number(src_port)
                    case ['source', 'range', port1, port2]:
                        source_port = f'{get_service_number(port1)}-{get_service_number(port2)}'
                    case ['destination', 'eq', dst_port]:
                        port = get_service_number(dst_port)
                    case ['destination', 'range', port1, port2]:
                        port = f'{get_service_number(port1)}-{get_service_number(port2)}'
                    case ['source', 'eq', src_port, 'destination', protocol, *dst_ports]:
                        source_port = get_service_number(src_port)
                        port = get_service_number(dst_ports[0]) if protocol == 'eq' else f'{get_service_number(dst_ports[0])}-{get_service_number(dst_ports[1])}'
                    case ['source', 'range', port1, port2, 'destination', protocol, *dst_ports]:
                        source_port = f'{get_service_number(port1)}-{get_service_number(port2)}'
                        port = get_service_number(dst_ports[0]) if protocol == 'eq' else f'{get_service_number(dst_ports[0])}-{get_service_number(dst_ports[1])}'
                    case _:
                        print(f"\033[31m\tСервис {name} не конвертирован. Операторы lt, gt, neq не поддерживаются в UG NGFW.\033[0m")
            case ['description', *content]:
                service['description'] = " ".join(content)

    service['protocols'].append(
        {
            'proto': proto,
            'port': port,
            'source_port': source_port,
         }
    )
    services[name] = service

def convert_network_object(name, object_block):
    """Конвертируем object network в список IP-адресов"""
    tmp_dict = {
        "name": name,
        "description": "",
        "type": "network",
        "url": "",
        "attributes": {"threat_level": 3},
        "content": []
    }
    for item in object_block:
        match item:
            case ['nat', *other]:
                convert_dnat_rule(name, item)
                return
            case ['subnet', ip, mask]:
                subnet = ipaddress.ip_network(f'{ip}/{mask}')
                tmp_dict['content'].append({'value': f'{ip}/{subnet.prefixlen}'})
                tmp_dict['type'] = 'network'
            case ['host', ip]:
                tmp_dict['content'].append({'value': ip})
                tmp_dict['type'] = 'network'
            case ['range', start_ip, end_ip]:
                tmp_dict['content'].append({'value': f'{start_ip}-{end_ip}'})
                tmp_dict['type'] = 'network'
            case ['fqdn', domain_name]:
                tmp_dict['content'].append({'value': domain_name})
                tmp_dict['type'] = 'url'
            case ['fqdn', 'v4', domain_name]:
                tmp_dict['content'].append({'value': domain_name})
                tmp_dict['type'] = 'url'
            case ['description', *content]:
                tmp_dict['description'] = " ".join(content)
            case _:
                print("Error:", name, object_block)

    if tmp_dict['type'] == 'url':
        url_dict[name] = tmp_dict
    else:
        ip_dict[name] = tmp_dict

def convert_network_object_group(name, object_block):
    """Конвертируем object-group network в список IP-адресов и список URL если object-group содержит объект с FQDN"""
    ip_list = {
        'name': name,
        'description': '',
        'type': 'network',
        'url': '',
        'attributes': {'threat_level': 3},
        'content': []
    }
    url_list = {
        'name': name,
        'description': '',
        'type': 'url',
        'url': '',
        'attributes': {'threat_level': 3},
        'content': []
    }
    for item in object_block:
        match item:
            case ['network-object', 'host', ip]:
                ip_list['content'].append({'value': ip})
            case ['network-object', 'object', object_name]:
                try:
                    ip_list['content'].extend(ip_dict[object_name]['content'])
                except KeyError:
                    url_list['content'].extend(url_dict[object_name]['content'])
            case ['network-object', ip, mask]:
                subnet = ipaddress.ip_network(f'{ip}/{mask}')
                ip_list['content'].append({'value': f'{ip}/{subnet.prefixlen}'})
            case ['group-object', group_name]:
                try:
                    ip_list['content'].extend(ip_dict[group_name]['content'])
                except KeyError:
                    pass
                try:
                    url_list['content'].extend(url_dict[group_name]['content'])
                except KeyError:
                    pass
            case ['description', *content]:
                ip_list['description'] = ' '.join(content)
                url_list['description'] = ' '.join(content)

    if ip_list['content']:
        ip_dict[name] = ip_list
    if url_list['content']:
        url_dict[name] = url_list

def convert_service_object_group(descr, object_block):
    """Конвертируем object-group service в список сервисов"""
    service = {
        "name": descr[0],
        "description": "",
        "protocols": []
    }

    for item in object_block:
        proto_array = []
        source_port = ''
        port = ''
        match item:
            case ['service-object', 'object', object_name]:
                service['protocols'].extend(services[object_name]['protocols'])
            case ['service-object', 'icmp', *other]:
                proto_array.insert(0, 'icmp')
            case ['service-object', 'icmp6', *other]:
                proto_array.insert(0, 'ipv6-icmp')
            case ['service-object', 'sctp', *other]:
                proto_array.insert(0, 'sctp')
            case ['service-object', 'tcp'|'udp'|'tcp-udp', *other]:
                proto_array = item[1].split('-')
                match other:
                    case ['source', 'eq', src_port]:
                        source_port = get_service_number(src_port)
                    case ['source', 'range', port1, port2]:
                        source_port = f'{get_service_number(port1)}-{get_service_number(port2)}'
                    case ['destination', 'eq', dst_port]:
                        port = get_service_number(dst_port)
                    case ['destination', 'range', port1, port2]:
                        port = f'{get_service_number(port1)}-{get_service_number(port2)}'
                    case ['source', 'eq', src_port, 'destination', protocol, *dst_ports]:
                        source_port = get_service_number(src_port)
                        port = get_service_number(dst_ports[0]) if protocol == 'eq' else f'{get_service_number(dst_ports[0])}-{get_service_number(dst_ports[1])}'
                    case ['source', 'range', port1, port2, 'destination', protocol, *dst_ports]:
                        source_port = f'{get_service_number(port1)}-{get_service_number(port2)}'
                        port = get_service_number(dst_ports[0]) if protocol == 'eq' else f'{get_service_number(dst_ports[0])}-{get_service_number(dst_ports[1])}'
                    case ['source'|'destination', 'lt'|'gt'|'neq', *tmp]:
                        print(f"\033[33mСервис {item} в правиле {descr[0]} не конвертирован.\n\tОператоры lt, gt, neq не поддерживаются в UG NGFW.\033[0m")
                        continue
            case ['service-object', protocol]:
                if protocol.isdigit():
                    protocol = ip_proto.get(protocol, None)
                if protocol and protocol in ip_protocol_list:
                    proto_array.insert(0, protocol)
                else:
                    print(f"\033[33mСервис {item} в {descr[0]} не конвертирован.\n\tНельзя задать протокол {protocol} в UG NGFW.\033[0m")
                    continue
            case ['port-object', 'eq'|'range', *dst_ports]:
                proto_array = descr[1].split('-')
                port = get_service_number(dst_ports[0]) if item[1] == 'eq' else f'{get_service_number(dst_ports[0])}-{get_service_number(dst_ports[1])}'
            case ['group-object', group_name]:
                service['protocols'].extend(services[group_name]['protocols'])
            case ['description', *content]:
                service['description'] = " ".join(content)

        for proto in proto_array:
            service['protocols'].append(
                {
                    "proto": proto,
                    "port": port,
                    "source_port": source_port,
                 }
            )

    services[descr[0]] = service

def convert_protocol_object_group(name, object_block):
    """Конвертируем object-group protocol в список сервисов"""
    service = {
        "name": name,
        "description": "",
        "protocols": []
    }

    for item in object_block:
        proto = set()
        match item:
            case ['protocol-object', protocol]:
                if protocol.isdigit():
                    protocol = ip_proto.get(protocol, None)
                if protocol and protocol in ip_protocol_list:
                    proto.add(protocol)
                elif protocol == 'ip':
                    proto.update({'tcp', 'udp'})
                else:
                    print(f"\033[33mСервис {item} в {name} не конвертирован.\n\tНельзя задать протокол {protocol} в UG NGFW.\033[0m")
                    continue
            case ['description', *content]:
                service['description'] = " ".join(content)
        for x in proto:
            service['protocols'].append(
                {
                    "proto": x,
                    "port": "",
                    "source_port": "",
                }
            )
    services[name] = service

def convert_icmp_object_group(name):
    """Конвертируем object-group icmp в список сервисов"""
    service = {
        'name': 'Any ICMP',
        'description': '',
        'protocols': [
            {
                'proto': 'icmp',
                'port': '',
                'source_port': '',
            }
        ]
    }
    services[name] = service

def convert_access_group(x):
    """
    Конвертируе access-group. Сопоставляем имя access-list с зоной интерфейса и определяем источник это или назначение.
    """
    if x[0] not in direction:
        direction[x[0]] = {
            "src_zones": [],
            "dst_zones": []
        }
    match x:
        case [access_list_name, 'in', 'interface', zone_name]:
            direction[access_list_name]['src_zones'].append(zone_name.translate(trans_name))
        case [access_list_name, 'out', 'interface', zone_name]:
            direction[access_list_name]['dst_zones'].append(zone_name.translate(trans_name))
        case [access_list_name, 'interface', ifname, 'global']:
            pass
        case _:
            direction.pop(x[0], None)

def create_ip_list(ip, mask=None):
    """Возвращает имя IP листа в функцию get_ips()"""
    ip_list = {
        "name": f"host {ip}",
        "description": "",
        "type": "network",
        "url": "",
        "attributes": {"thread_level": 3},
        "content": []
    }
    if mask:
        subnet = ipaddress.ip_network(f'{ip}/{mask}')
        ip_list['content'].append({"value": f'{ip}/{subnet.prefixlen}'})
        ip_list['name'] = f'subnet {ip}_{subnet.prefixlen}'
    else:
        ip_list['content'].append({"value": ip})

    ip_dict[ip_list['name']] = ip_list
    return ["list_id", ip_list['name']]

def get_ips(ips_mode, address, rule, deq):
    match address:
        case 'any'|'any4'|'any6':
            pass
        case 'object'|'object-group':
            ip_or_service_list = deq.popleft()
            if ip_or_service_list in ip_dict:
                rule[ips_mode].append(["list_id", ip_or_service_list])
            elif ip_or_service_list in url_dict:
                rule[ips_mode].append(["urllist_id", ip_or_service_list])
            elif ip_or_service_list in services:
                rule['services'].clear()
                rule['services'].append(["service", ip_or_service_list])
        case 'host':
            ip = deq.popleft()
            rule[ips_mode].append(create_ip_list(ip))
        case 'interface':
            ip = deq.popleft()
        case _:
            try:
                ipaddress.ip_address(address)   # проверяем что это IP-адрес или получаем ValueError
                mask = deq.popleft()
                rule[ips_mode].append(create_ip_list(address, mask))
            except (ValueError, IndexError):
                pass

def create_service(name, ips_mode, protocol, port1, port2=None):
    """Для ACE. Создаём сервис, заданный непосредственно в правиле, а не в сервисной группе."""
    if port2:
        port = f'{get_service_number(port1)}-{get_service_number(port2)}'
    else:
        port = get_service_number(port1)
    if protocol in {'tcp', 'udp','sctp'}:
            service = {
                "name": name,
                "description": "",
                "protocols": [
                    {
                        "proto": protocol,
                        "port": "",
                        "source_port": ""
                    }
                ]
            }
            if ips_mode == 'src_ips':
                service['protocols'][0]['source_port'] = port
            else:
                service['protocols'][0]['port'] = port
    elif protocol in services:
        service = copy.deepcopy(services[protocol])
        service['name'] = name
        for item in service['protocols']:
            if ips_mode == 'src_ips':
                item['source_port'] = port
            else:
                item['port'] = port

    services[name] = service

#def convert_ace(acs_name, rule_block, remark):
#    """
#    Конвертируем ACE в правило МЭ.
#    Не активные ACE пропускаются. ACE не назначенные интерфейсам пропускаются.
#    ACE с именами ASA интерфейсов пропускаются.
#    ACE c security-group и object-group-security пропускаются.
#    """
#        if (acs_name not in direction) or ('inactive' in rule_block) or ('interface' in rule_block):
#    if acs_name not in direction:
#        return
#    for value in ('inactive', 'interface', 'security-group', 'object-group-security'):
#        if value in rule_block:
#            print(f'\033[36mACE: {" ".join(rule_block)} - не пропущено так как содержит параметр: "{value}".\033[0m')
#            return#
#
#    nonlocal rule_number
#    rule_number += 1
#    deq = deque(rule_block)
#    rule = {
#        "name": f"Rule {rule_number} ({acs_name})",
#        "description": ", ".join(remark),
#        "action": "drop" if deq.popleft() == 'deny' else "accept",
#        "position": "last",
#        "scenario_rule_id": False,     # При импорте заменяется на UID или "0". 
#        "src_zones": [],
#        "dst_zones": [],
#        "src_ips": [],
#        "dst_ips": [],
#        "services": [],
#        "apps": [],
#        "users": [],
#        "enabled": False,
#        "limit": True,
#        "limit_value": "3/h",
#        "limit_burst": 5,
#        "log": False,
#        "log_session_start": True,
#        "src_zones_negate": False,
#        "dst_zones_negate": False,
#        "src_ips_negate": False,
#        "dst_ips_negate": False,
#        "services_negate": False,
#        "apps_negate": False,
#        "fragmented": "ignore",
#        "time_restrictions": [],
#        "send_host_icmp": "",
#    }
#    rule['src_zones'].extend(direction[acs_name]['src_zones'])
#    rule['dst_zones'].extend(direction[acs_name]['dst_zones'])
#
#    protocol = deq.popleft()
#    match protocol:
#        case 'object'|'object-group':
#            protocol = deq.popleft()
#            rule['services'].append(["service", protocol])
#        case 'ip':
#            pass
#        case 'icmp':
#            rule['services'].append(["service", "Any ICMP"])
#        case 'tcp':
#            rule['services'].append(["service", "Any TCP"])
#        case 'udp':
#            rule['services'].append(["service", "Any UDP"])
#        case 'sctp':
#            if 'Any SCTP' not in services:
#                service = {
#                    "name": 'Any SCTP',
#                    "description": "",
#                    "protocols": [{"proto": "sctp", "port": "", "source_port": ""}]
#                }
#                services['Any SCTP'] = service
#            rule['services'].append(["service", "Any SCTP"])
#
#    argument = deq.popleft()
#    match argument:
#        case 'object-group-user':
#            rule['users'].append(['group', deq.popleft()])
#        case 'user':
#            user = deq.popleft()
#            match user:
#                case 'any':
#                    rule['users'].append(['special', 'known_user'])
#                case 'none':
#                    rule['users'].append(['special', 'unknown_user'])
#                case _:
#                    user_list = user.split("\\")
#                    if user_list[0] == 'LOCAL' and user_list[1] in users:
#                        rule['users'].append(['user', user_list[1]])
#                    elif user_list[0] in identity_domains:
#                        rule['users'].append(["user", f"{identity_domains[user_list[0]]}\\{user_list[1]}"])
#        case 'user-group':
#            group = deq.popleft()
#            group_list = group.split("\\\\")
#            if group_list[0] in identity_domains:
#                rule['users'].append(["group", f"{identity_domains[group_list[0]]}\\{group_list[1]}"])
##            case 'interface':
##                zone = deq.popleft()
##                if zone in zones:
##                    rule['dst_zones'].append(zone)
#        case _:
#            ips_mode = 'src_ips'
#            get_ips(ips_mode, argument, rule, deq)
#    while deq:
#        argument = deq.popleft()
#        match argument:
#            case 'lt'|'gt'|'neq':
#                return
#            case 'eq':
#                port = deq.popleft()
#                service_name = f'Eq {port} (Rule {rule_number})'
#                create_service(service_name, ips_mode, protocol, port)
#                rule['services'].clear()
#                rule['services'].append(["service", service_name])
#            case 'range':
#                port1 = deq.popleft()
#                port2 = deq.popleft()
#                service_name = f'Range {port1}-{port2} (Rule {rule_number})'
#                create_service(service_name, ips_mode, protocol, port1, port2)
#                rule['services'].clear()
#                rule['services'].append(["service", service_name])
#            case 'object-group':
#                ips_mode = 'dst_ips'
#                get_ips(ips_mode, argument, rule, deq)
#            case 'log':
#                other = list(deq)
#                deq.clear()
#                if 'time-range' in other:
#                    time_object = other.index('time-range') + 1
#                    rule['time_restrictions'].append(time_object)
#            case 'time-range':
#                rule['time_restrictions'].append(deq.popleft())
##                case 'interface':
##                    zone = deq.popleft()
##                    if zone in zones:
##                        rule['dst_zones'].append(zone)
#            case _:
#                ips_mode = 'dst_ips'
#                get_ips(ips_mode, argument, rule, deq)
#
#    fw_rules.append(rule)

#def convert_webtype_ace(acs_name, rule_block, remark):
#    """
#    Конвертируем ACE webtype в правило КФ. Не активные ACE пропускаются.
#    """
#    if 'inactive' in rule_block:
#        return
#
#    nonlocal cfrule_number
#    cfrule_number += 1
#    deq = deque(rule_block)
#    action = deq.popleft()
#    rule = {
#        "name": f"Rule {cfrule_number} ({acs_name})",
#        "description": ", ".join(remark),
#        "position": "last",
#        "action": "drop" if action == 'deny' else "accept",
#        "public_name": "",
#        "enabled": True,
#        "enable_custom_redirect": False,
#        "blockpage_template_id": -1,
#        "users": [],
#        "url_categories": [],
#        "src_zones": [],
#        "dst_zones": [],
#        "src_ips": [],
#        "dst_ips": [],
#        "morph_categories": [],
#        "urls": [],
#        "referers": [],
#        "referer_categories": [],
#        "user_agents": [],
#        "time_restrictions": [],
#        "content_types": [],
#        "http_methods": [],
#        "src_zones_negate": False,
#        "dst_zones_negate": False,
#        "src_ips_negate": False,
#        "dst_ips_negate": False,
#        "url_categories_negate": False,
#        "urls_negate": False,
#        "content_types_negate": False,
#        "user_agents_negate": False,
#        "custom_redirect": "",
#        "enable_kav_check": False,
#        "enable_md5_check": False,
#        "rule_log": False,
#        "scenario_rule_id": False,
#        "users_negate": False
#    }
#
#    while deq:
#        parameter = deq.popleft()
#        match parameter:
#            case 'url':
#                url = deq.popleft()
#                url_list_name = f"For {acs_name}-{cfrule_number}"
#                if not create_url_list(url, url_list_name, rule):
#                    return
#            case 'tcp':
#                address = deq.popleft()
#                get_ips('dst_ips', address, rule, deq)
#            case 'time_range':
#                rule['time_restrictions'].append(deq.popleft())
#            case 'time-range':
#                rule['time_restrictions'].append(deq.popleft())
#
#    cf_rules.append(rule)

#def convert_dnat_rule(ip_list, rule_block):
#    """Конвертируем object network в правило DNAT или Port-форвардинг"""
##        print(ip_dict[ip_list]['content'][0]['value'], "\t", rule_block)
#    if ('inactive' in rule_block) or ('interface' in rule_block):
#        print(f'\033[36mПравило NAT "{rule_block}" пропущено так как не активно или содержит интерфейс.\033[0m')
#        return
#
#    nonlocal natrule_number
#    natrule_number += 1
#    rule = {
#        "name": f"Rule {natrule_number} ({ip_list})",
#        "description": "",
#        "action": "dnat",
#        "position": "last",
#        "zone_in": [],
#        "zone_out": [],
#        "source_ip": [],
#        "dest_ip": [],
#        "service": [],
#        "target_ip": ip_dict[ip_list]['content'][0]['value'],
#        "gateway": "",
#        "enabled": False,
#        "log": False,
#        "log_session_start": True,
#        "target_snat": False,
#        "snat_target_ip": "",
#        "zone_in_nagate": False,
#        "zone_out_nagate": False,
#        "source_ip_nagate": False,
#        "dest_ip_nagate": False,
#        "port_mappings": [],
#        "direction": "input",
#        "users": [],
#        "scenario_rule_id": False
#    }
#    zone_out, zone_in = rule_block[1][1:-1].split(',')
#    if len(rule_block) == 3 or 'net-to-net' in rule_block:
#        rule['zone_in'] = [zone_in] if zone_in != 'any' else []
#    if rule_block[2] == 'static':
#        if rule_block[3] in ip_dict:
#            rule['dest_ip'].append(["list_id", rule_block[3]])
#            rule['snat_target_ip'] = ip_dict[rule_block[3]]['content'][0]['value']
#        elif f"host {rule_block[3]}" in ip_dict:
#            rule['dest_ip'].append(["list_id", f"host {rule_block[3]}"])
#            rule['snat_target_ip'] = ip_dict[f"host {rule_block[3]}"]['content'][0]['value']
#        else:
#            rule['dest_ip'].append(create_ip_list(rule_block[3]))
#            rule['snat_target_ip'] = rule_block[3]
#
#        if 'service' in rule_block:
#            i = rule_block.index('service')
#            proto = rule_block[i+1]
#            src_port = rule_block[i+3]
#            dst_port = rule_block[i+2]
#            if src_port == dst_port:
#                if dst_port in ug_services:
#                    rule['service'].append(["service", ug_services[dst_port]])
#                elif dst_port in services:
#                    rule['service'].append(["service", dst_port])
#                else :
#                    service = {
#                        "name": dst_port,
#                        "description": f'Service for DNAT rule (Rule {natrule_number})',
#                        "protocols": [{"proto": proto, "port": service_ports.get(dst_port, dst_port), "source_port": ""}]
#                    }
#                    services[dst_port] = service
#                    rule['service'].append(["service", dst_port])
#            else:
#                rule['action'] = 'port_mapping'
#                rule['port_mappings'].append({"proto": proto,
#                                              "src_port": int(service_ports.get(src_port, src_port)),
#                                              "dst_port": int(service_ports.get(dst_port, dst_port))})
#    else:
#        return
#
#    nat_rules.append(rule)

#def convert_nat_rule(rule_block):
#    """Конвертируем правило NAT"""
#    if ('inactive' in rule_block) or ('interface' in rule_block):
#        print(f'\033[36mПравило NAT "{rule_block}" пропущено так как не активно или содержит интерфейс.\033[0m')
#        return
#
#    nonlocal natrule_number
#    natrule_number += 1
#    rule = {
#        "name": f"Rule {natrule_number} NAT",
#        "description": "",
#        "action": "nat",
#        "position": "last",
#        "zone_in": [],
#        "zone_out": [],
#        "source_ip": [],
#        "dest_ip": [],
#        "service": [],
#        "target_ip": "",
#        "gateway": "",
#        "enabled": False,
#        "log": False,
#        "log_session_start": True,
#        "target_snat": False,
#        "snat_target_ip": "",
#        "zone_in_nagate": False,
#        "zone_out_nagate": False,
#        "source_ip_nagate": False,
#        "dest_ip_nagate": False,
#        "port_mappings": [],
#        "direction": "input",
#        "users": [],
#        "scenario_rule_id": False
#    }
#    zone_in, zone_out = rule_block[1][1:-1].split(',')
#    rule['zone_in'] = [zone_in.translate(trans_name)] if zone_in != 'any' else []
#    rule['zone_out'] = [zone_out.translate(trans_name)] if zone_out != 'any' else []
#    
#    if 'dynamic' in rule_block:
#        i = rule_block.index('dynamic')
#        if rule_block[i+1] != 'any':
#            if rule_block[i+1] == 'pat-pool':
#                i += 1
#            if rule_block[i+1] in ip_dict:
#                rule['source_ip'].append(["list_id", rule_block[i+1]])
#            elif f"host {rule_block[i+1]}" in ip_dict:
#                rule['source_ip'].append(["list_id", f"host {rule_block[i+1]}"])
#            else:
#                rule['source_ip'].append(create_ip_list(rule_block[i+1]))
#        if rule_block[i+2] != 'any':
#            if rule_block[i+2] == 'pat-pool':
#                i += 1
#            if rule_block[i+2] in ip_dict:
#                rule['dest_ip'].append(["list_id", rule_block[i+2]])
#            elif f"host {rule_block[i+2]}" in ip_dict:
#                rule['dest_ip'].append(["list_id", f"host {rule_block[i+2]}"])
#            else:
#                rule['dest_ip'].append(create_ip_list(rule_block[i+2]))
#        if 'description' in rule_block:
#            i = rule_block.index('description')
#            rule['description'] = " ".join(rule_block[i+1:])
#    else:
#        return
#
#    nat_rules.append(rule)

#----------------------------------------------------------------------------------------
def aaa():
    with open(f"data_ca/{file_name}.txt", "r") as fh:
        line = fh.readline()
        while line:
            if line[:1] in {':', '!'}:
                line = fh.readline()
                continue
            tmp_block = []
            x = line.translate(trans_table).rsplit(' ')
            match x[0]:
                case 'domain-name':
                    convert_modules(x)
                    line = fh.readline()
                case 'dns':
                    match x[1]:
                        case 'domain-lookup':
                            convert_zone_access(x)
                            line = fh.readline()
                        case 'forwarder':
                            convert_dns_servers(x)
                            line = fh.readline()
                        case 'server-group':
                            line, tmp_block = make_block_of_line(fh)
                            convert_dns_rules(x[2], tmp_block)
                case 'interface':
                    line, tmp_block = make_block_of_line(fh)
                    convert_interface(tmp_block)
                case 'route':
                    convert_route(x)
                    line = fh.readline()
                case 'telnet' | 'ssh'| 'http':
                    convert_zone_access(x)
                    line = fh.readline()
                case 'aaa-server':
                    line, tmp_block = make_block_of_line(fh)
                    convert_auth_servers(x, tmp_block)
                case 'time-range':
                    line, tmp_block = make_block_of_line(fh)
                    convert_time_sets(x[1], tmp_block)
                case 'clock':
                    convert_settings_ui(x)
                    line = fh.readline()
                case 'ntp':
                    convert_ntp_settings(x)
                    line = fh.readline()
                case 'dhcp':
                    convert_dhcp_settings(x)
                    line = fh.readline()
                case 'username':
                    convert_local_users(x[1], x[2])
                    line = fh.readline()
                case 'user-identity':
                    convert_user_identity_domains(x[1:])
                    line = fh.readline()
                case 'object':
                    match x[1]:
                        case 'service':
                            line, tmp_block = make_block_of_line(fh)
                            convert_service_object(x[2], tmp_block)
                        case 'network':
                            line, tmp_block = make_block_of_line(fh)
                            convert_network_object(x[2], tmp_block)
                case 'object-group':
                    match x[1]:
                        case 'network':
                            line, tmp_block = make_block_of_line(fh)
                            convert_network_object_group(x[2], tmp_block)
                        case 'service':
                            line, tmp_block = make_block_of_line(fh)
                            convert_service_object_group(x[2:], tmp_block)
                        case 'protocol':
                            line, tmp_block = make_block_of_line(fh)
                            convert_protocol_object_group(x[2], tmp_block)
                        case 'user':
                            line, tmp_block = make_block_of_line(fh)
                            convert_user_groups_object_group(x[2], tmp_block)
                        case 'icmp-type':
                            line, tmp_block = make_block_of_line(fh)
                            convert_icmp_object_group(x[2])
                        case _:
                            line = fh.readline()
                case 'access-group':
                    convert_access_group(x[1:])
                    line = fh.readline()
                case _:
                    line = fh.readline()

    if not os.path.isdir('data/UserGate/GeneralSettings'):
        os.makedirs('data/UserGate/GeneralSettings')
    with open('data/UserGate/GeneralSettings/config_ntp.json', 'w') as fh:
        json.dump(ntp, fh, indent=4, ensure_ascii=False)
    
    if not os.path.isdir('data/Network/Zones'):
        os.makedirs('data/Network/Zones')
    with open('data/Network/Zones/config_zones.json', 'w') as fh:
        json.dump([x for x in zones.values()], fh, indent=4, ensure_ascii=False)
    
    if not os.path.isdir('data/Network/DNS'):
        os.makedirs('data/Network/DNS')
    with open('data/Network/DNS/config_dns_servers.json', 'w') as fh:
        json.dump(system_dns, fh, indent=4, ensure_ascii=False)
    
    if not os.path.isdir('data/Network/DNS'):
        os.makedirs('data/Network/DNS')
    with open('data/Network/DNS/config_dns_rules.json', 'w') as fh:
        json.dump(dns_rules, fh, indent=4, ensure_ascii=False)
    
    if not os.path.isdir('data/Network/Interfaces'):
        os.makedirs('data/Network/Interfaces')
    with open('data/Network/Interfaces/config_interfaces.json', 'w') as fh:
        json.dump(interfaces, fh, indent=4, ensure_ascii=False)
    
    if not os.path.isdir('data/Network/Gateways'):
        os.makedirs('data/Network/Gateways')
    with open('data/Network/Gateways/config_gateways.json', 'w') as fh:
        json.dump(gateways, fh, indent=4, ensure_ascii=False)
    
    if not os.path.isdir('data/Network/VRF'):
        os.makedirs('data/Network/VRF')
    with open('data/Network/VRF/config_routers.json', 'w') as fh:
        json.dump([default_vrf], fh, indent=4, ensure_ascii=False)
    
    if not os.path.isdir('data/Network/DHCP'):
        os.makedirs('data/Network/DHCP')
    with open('data/Network/DHCP/config_dhcp_subnets.json', 'w') as fh:
        for x in dhcp.values():
            x.pop('cc', None)
        json.dump([x for x in dhcp.values()], fh, indent=4, ensure_ascii=False)
    
    if not os.path.isdir('data/UsersAndDevices/AuthServers'):
        os.makedirs('data/UsersAndDevices/AuthServers')
    tacacs_servers = []
    radius_servers = []
    ldap_servers = []
    for key, auth_server in auth_servers.items():
        if auth_server['description'] == 'tacacs':
            tacacs_servers.append(auth_server)
        if auth_server['description'] == 'radius':
            radius_servers.append(auth_server)
        if auth_server['description'] == 'ldap':
            ldap_servers.append(auth_server)
    with open('data/UsersAndDevices/AuthServers/config_tacacs_servers.json', 'w') as fh:
        json.dump(tacacs_servers, fh, indent=4, ensure_ascii=False)
    with open('data/UsersAndDevices/AuthServers/config_radius_servers.json', 'w') as fh:
        json.dump(radius_servers, fh, indent=4, ensure_ascii=False)
    with open('data/UsersAndDevices/AuthServers/config_ldap_servers.json', 'w') as fh:
        json.dump(ldap_servers, fh, indent=4, ensure_ascii=False)
    
    if not os.path.isdir('data/UsersAndDevices/Users'):
        os.makedirs('data/UsersAndDevices/Users')
    with open('data/UsersAndDevices/Users/config_users.json', 'w') as fh:
        json.dump(list(users.values()), fh, indent=4, ensure_ascii=False)
    
    if not os.path.isdir('data/UsersAndDevices/Groups'):
        os.makedirs('data/UsersAndDevices/Groups')
    with open('data/UsersAndDevices/Groups/config_groups.json', 'w') as fh:
        json.dump(list(groups.values()), fh, indent=4, ensure_ascii=False)
    
    if not os.path.isdir('data/Libraries/TimeSets'):
        os.makedirs('data/Libraries/TimeSets')
    with open('data/Libraries/TimeSets/config_calendars.json', 'w') as fh:
        json.dump(list(timerestrictiongroup.values()), fh, indent=4, ensure_ascii=False)
    
    if not os.path.isdir('data/Libraries/Services'):
        os.makedirs('data/Libraries/Services')
    with open('data/Libraries/Services/config_services.json', 'w') as fh:
        json.dump(list(services.values()), fh, indent=4, ensure_ascii=False)
    
    if not os.path.isdir('data/Libraries/URLLists'):
        os.makedirs('data/Libraries/URLLists')
    for list_name, value in url_dict.items():
        with open(f'data/Libraries/URLLists/{list_name}.json', 'w') as fh:
            json.dump(value, fh, indent=4, ensure_ascii=False)
    
    if not os.path.isdir('data/Libraries/IPAddresses'):
        os.makedirs('data/Libraries/IPAddresses')
    for list_name, value in ip_dict.items():
        with open(f'data/Libraries/IPAddresses/{list_name}.json', 'w') as fh:
            json.dump(value, fh, indent=4, ensure_ascii=False)
    
    if not os.path.isdir('data/NetworkPolicies/Firewall'):
        os.makedirs('data/NetworkPolicies/Firewall')
    with open('data/NetworkPolicies/Firewall/config_firewall_rules.json', 'w') as fh:
        json.dump(fw_rules, fh, indent=4, ensure_ascii=False)
    
    if not os.path.isdir('data/SecurityPolicies/ContentFiltering'):
        os.makedirs('data/SecurityPolicies/ContentFiltering')
    with open('data/SecurityPolicies/ContentFiltering/config_content_rules.json', 'w') as fh:
        json.dump(cf_rules, fh, indent=4, ensure_ascii=False)
    
    if not os.path.isdir('data/NetworkPolicies/NATandRouting'):
        os.makedirs('data/NetworkPolicies/NATandRouting')
    with open('data/NetworkPolicies/NATandRouting/config_nat_rules.json', 'w') as fh:
        json.dump(nat_rules, fh, indent=4, ensure_ascii=False)

############################################# Служебные функции ###################################################
def pack_ip_address(ip, mask):
    if ip == '0':
        ip = '0.0.0.0'
    if mask == '0':
        mask = '128.0.0.0'
    ip_address = ipaddress.ip_interface(f'{ip}/{mask}')
    return f'{ip}/{ip_address.network.prefixlen}'

def get_guids_users_and_groups(utm, item):
    """
    Получить GUID-ы групп и пользователей по их именам.
    Заменяет имена локальных и доменных пользователей и групп на GUID-ы.
    """
    if item['users']:
        users = []
        for x in item['users']:
            if x[0] == 'user' and x[1]:
                i = x[1].partition("\\")
                if i[2]:
                    err, result = utm.get_ldap_user_guid(i[0], i[2])
                    if err != 0:
                        print(f"\033[31m{result}\033[0m")
                    elif not result:
                        print(f'\t\033[31mНет LDAP-коннектора для домена "{i[0]}"!\n\tИмпортируйте и настройте LDAP-коннектор. Затем повторите импорт.\033[0m')
                    else:
                        x[1] = result
                        users.append(x)
                else:
                    try:
                        x[1] = utm.list_users[x[1]]
                    except KeyError:
                        print(f'\t\033[31mНе найден пользователь "{x[1]}" для правила "{item["name"]}".\n\tИмпортируйте локальных пользователей и повторите импорт правил.\033[0m')
                    else:
                        users.append(x)

            elif x[0] == 'group' and x[1]:
                i = x[1].partition("\\")
                if i[2]:
                    err, result = utm.get_ldap_group_guid(i[0], i[2])
                    if err != 0:
                        print(f"\033[31m{result}\033[0m")
                    elif not result:
                        print(f'\t\033[31mНет LDAP-коннектора для домена "{i[0]}"!\n\tИмпортируйте и настройте LDAP-коннектор. Затем повторите импорт групп.\033[0m')
                    else:
                        x[1] = result
                        users.append(x)
                else:
                    try:
                        x[1] = utm.list_groups[x[1]]
                    except KeyError:
                        print(f'\t\033[31mНе найдена группа "{x[1]}" для правила "{item["name"]}".\n\tИмпортируйте локальные группы и повторите импорт правил.\033[0m')
                    else:
                        users.append(x)
            elif x[0] == 'special' and x[1]:
                users.append(x)
        item['users'] = users

def get_zones(utm, zones, rule_name):
    """Получить UID-ы зон. Если зона не существует на NGFW, то она пропускается."""
    new_zones = []
    for zone in zones:
        try:
            new_zones.append(utm.zones[zone])
        except KeyError as err:
            print(f'\t\033[33mЗона {err} для правила "{rule_name}" не найдена.\n\tЗагрузите список зон и повторите попытку.\033[0m')
    return new_zones

def get_ips(utm, rule_ips, rule_name):
    """Получить UID-ы списков IP-адресов и URL-листов. Если списки не существует на NGFW, то они пропускается."""
    new_rule_ips = []
    for ips in rule_ips:
        try:
            if ips[0] == 'list_id':
                new_rule_ips.append(['list_id', utm.list_ip[ips[1]]])
            elif ips[0] == 'urllist_id':
                new_rule_ips.append(['urllist_id', utm.list_url[ips[1]]])
        except KeyError as err:
            print(f'\t\033[33mНе найден адрес источника/назначения {err} для правила "{rule_name}".\n\tЗагрузите списки IP-адресов и URL и повторите попытку.\033[0m')
    return new_rule_ips

def set_time_restrictions(utm, item):
    if item['time_restrictions']:
        try:
            item['time_restrictions'] = [utm.list_calendar[x] for x in item['time_restrictions']]
        except KeyError as err:
            print(f'\t\033[33mНе найден календарь {err} для правила "{item["name"]}".\n\tЗагрузите календари в библиотеку и повторите попытку.\033[0m')
            item['time_restrictions'] = []

def get_services(utm, rule_services, rule_name):
    new_service_list = []
    for service in rule_services:
        try:
            new_service_list.append(['service', utm.services[service[1]]])
        except KeyError as err:
            print(f'\t\033[33mНе найден сервис "{service[1]}" для правила "{rule_name}".\033[0m')
    return new_service_list

def set_urls_and_categories(utm, item):
    if item['urls']:
        try:
            item['urls'] = [utm.list_url[x] for x in item['urls']]
        except KeyError as err:
            print(f'\t\033[33mНе найден URL {err} для правила "{item["name"]}".\n\tЗагрузите списки URL и повторите попытку.\033[0m')
            item['urls'] = []

def main():
    convert_file()

if __name__ == '__main__':
    main()
