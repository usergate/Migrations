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
# Модуль переноса конфигурации с устройств Huawei на NGFW UserGate.
# Версия 1.9  03.04.2025
#

import os, sys, json
import copy, re
from common_classes import MyConv
from PyQt6.QtCore import QThread, pyqtSignal
from applications import app_compliance, l7_categories, l7_categories_compliance
from services import zone_services, ug_services, ip_proto


pattern = re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
ug_proto = {x for x in ip_proto.values()}


class ConvertHuaweiConfig(QThread, MyConv):
    """Преобразуем файл конфигурации Huawei в формат UserGate NGFW."""
    stepChanged = pyqtSignal(str)

    def __init__(self, current_vendor_path, current_ug_path):
        super().__init__()
        self.current_vendor_path = current_vendor_path
        self.current_ug_path = current_ug_path
        self.error = 0
        self.vendor = 'Huawei'

        self.huawei_services = set()
        self.ip_lists = set()
        self.local_users = set()
        self.local_groups = set()
        self.dnat_ip = {}
        self.snat_ip = {}
        self.application_groups = []
        self.new_services = []
        self.vrf = {
            'name': 'default',
            'descriprion': '',
            'interfaces': [],
            'routes': [],
            'ospf': {},
            'bgp': {},
            'rip': {},
            'pimsm': {}
        }

    def run(self):
        self.stepChanged.emit(f'GREEN|{"Конвертация конфигурации Huawei в формат UserGate NGFW.":>110}')
        self.stepChanged.emit(f'ORANGE|{"="*110}')
        self.convert_config_file()
        if self.error:
            self.stepChanged.emit('iRED|Конвертация конфигурации Huawei в формат UserGate NGFW прервана.')
        else:
            json_file = os.path.join(self.current_vendor_path, 'config.json')
            err, self.data = self.read_json_file(json_file)
            if err:
                self.stepChanged.emit('iRED|Конвертация конфигурации Huawei в формат UserGate NGFW прервана.')
            else:
                self.convert_time_zone()
                self.convert_zone()
                self.convert_vlan_interfaces()
                self.convert_dns_servers()
                self.convert_static_routes()
                self.convert_notification_profile()
                self.convert_services()
                self.convert_service_groups()
                self.convert_ip_lists()
                self.convert_url_lists()
                self.convert_time_sets()
                self.convert_shapers_list()
                self.convert_shaper_rules()
                self.convert_nat_rules()
                self.convert_firewall_rules()

                self.save_application_groups()
                self.save_new_services()

                if self.error:
                    self.stepChanged.emit('iORANGE|Конвертация конфигурации Huawei в формат UserGate NGFW прошла с ошибками.')
                else:
                    self.stepChanged.emit('iGREEN|Конвертация конфигурации Huawei в формат UserGate NGFW прошла успешно.')


    def convert_config_file(self):
        """Преобразуем файл конфигурации Huawei в формат json."""
        self.stepChanged.emit('BLUE|Конвертация файла конфигурации Huawei в формат json.')
        if not os.path.isdir(self.current_vendor_path):
            self.stepChanged.emit('RED|    Не найден каталог с конфигурацией Huawei.')
            self.error = 1
            return
        error = 0
        data = {}

        config_file = os.path.join(self.current_vendor_path, 'huawei.cfg')
        try:
            with open(config_file, "r") as fh:
                line = fh.readline().translate(self.trans_table).strip()
                if not line:
                    line = fh.readline().translate(self.trans_table).strip()
                while line:
                    if line == '#':
                        config_block = []
                        line = fh.readline().translate(self.trans_table).strip()
                        while line != '#':
                            x = line.split(' ')
                            if x[0] == 'return':
                                break
                            config_block.append(x)
                            line = fh.readline().translate(self.trans_table).strip()
                        else:
                            if config_block:
                                key, value = self.make_block(config_block)
                                if key:
                                    if key in data:
                                        if isinstance(data[key], list):
                                            data[key].extend(value)
                                        elif isinstance(data[key], dict):
                                            data[key].update(value)
                                    else:
                                        data[key] = value
                    else:
                        line = fh.readline().translate(self.trans_table).strip()
                    
        except FileNotFoundError:
            self.stepChanged.emit(f'RED|    Error: Не найден файл "{config_file}" с конфигурацией Huawei.')
            self.error = 1
            return

        json_file = os.path.join(self.current_vendor_path, 'config.json')
        with open(json_file, 'w') as fh:
            json.dump(data, fh, indent=4, ensure_ascii=False)

        if self.error:
            self.stepChanged.emit('ORANGE|    Ошибка экспорта конфигурации Huawei в формат json.')
        else:
            self.stepChanged.emit(f'GREEN|    Конфигурация Huawei в формате json выгружена в файл "{json_file}".')
    

    def make_block(self, data):
        """Конвертируем блок в словарь"""
        match data[0]:
            case ['clock', 'timezone', name, _, offset]:
                return 'timezone', {'name': name, 'offset': offset}
            case ['firewall', 'blacklist', *_]:
                value = {
                    'blacklist': {'source-ip': set(), 'destination-ip': set()},
                    'whitelist': {'source-ip': set(), 'destination-ip': set()},
                }
                for item in data:
                    match item:
                        case ['firewall', 'blacklist', 'item', src_dst, ip, *_]:
                            value['blacklist'][src_dst].add(ip)
                        case ['firewall', 'whitelist', 'item', src_dst, ip, *_]:
                            value['whitelist'][src_dst].add(ip)
                value['blacklist']['source-ip'] = list(value['blacklist']['source-ip'])
                value['blacklist']['destination-ip'] = list(value['blacklist']['destination-ip'])
                value['whitelist']['source-ip'] = list(value['whitelist']['source-ip'])
                value['whitelist']['destination-ip'] = list(value['whitelist']['destination-ip'])
                return 'firewall', value
            case ['smtp', 'server', server, port]:
                value = {
                    'smtp_server': server,
                    'smtp_server_port': int(port),
                    'user': '',
                    'password': '',
                    'sender': '',
                    'recipient': ''
                }
                for item in data:
                    match item:
                        case ['smtp', 'authentication', user_name, password]:
                            value['user'] = user_name
                            value['password'] = password
                        case ['mail', 'sender', user_name]:
                            value['sender'] = user_name
                        case ['mail', 'recipient', user_name]:
                            value['recipient'] = user_name
                return 'smtp_settings', value
            case ['dns', 'resolve', *_]:
                value = []
                for item in data:
                    match item:
                        case ['dns', 'server', server]:
                            value.append(server)
                return 'dns_servers', value
            case ['ip', 'address-set', name, 'type', 'object']:
                value = {
                    'name': name,
                    'description': '',
                    'content': []
                }
                self.ip_lists.add(value['name'])
                for item in data:
                    match item:
                        case ['address', _, ip, 'mask', mask]:
                            err, pack_ip = self.pack_ip_address(ip, mask)
                            if err:
                                self.stepChanged.emit(f'RED|    Error: [IP-лист "{name}"] Не корректный IP-адрес. {pack_ip}')
                            else:
                                value['content'].append(pack_ip)
                        case ['address', _, ip, mask]:
                            err, pack_ip = self.pack_ip_address(ip, mask)
                            if err:
                                self.stepChanged.emit(f'RED|    Error: [IP-лист "{name}"] Не корректный IP-адрес. {pack_ip}')
                            else:
                                value['content'].append(pack_ip)
                        case ['address', _, 'range', ip1, ip2]:
                            value['content'].append(f'{ip1}-{ip2}')
                        case ['description', *descr]:
                            value['description'] = ' '.join(descr)
                return 'ip_lists', {value['name']: value}
            case ['ip', 'address-set', name, 'type', 'group']:
                value = {
                    'name': name,
                    'description': '',
                    'content': []
                }
                for item in data:
                    match item:
                        case ['address', _, 'address-set', list_name]:
                            value['content'].append(list_name)
                        case ['description', *descr]:
                            value['description'] = ' '.join(descr)
                return 'ip_lists_group', {value['name']: value}

            case ['ip', 'service-set', name, 'type', 'object', *_]:
                self.huawei_services.add(name)
                value = {
                    'name': name,
                    'description': '',
                    'protocols': []
                }
                for item in data:
                    match item:
                        case ['service', _, _, proto, 'source-port', port1, 'to', port2, 'destination-port', port3, *other]:
                            if other:
                                tmp = other.pop(0)
                                if tmp == 'to':
                                    value['protocols'].append({'proto': proto, 'port': f'{port3}-{other.pop(0)}', 'source_port': f'{port1}-{port2}'})
                                else:
                                    value['protocols'].append({'proto': proto, 'port': port3, 'source_port': f'{port1}-{port2}'})
                                    value['protocols'].append({'proto': proto, 'port': tmp, 'source_port': f'{port1}-{port2}'})
                                for x in other:
                                    value['protocols'].append({'proto': proto, 'port': x, 'source_port': f'{port1}-{port2}'})
                            else:
                                value['protocols'].append({'proto': proto, 'port': port3, 'source_port': f'{port1}-{port2}'})
                        case ['service', _, _, proto, 'source-port', port, 'destination-port', port3, *other]:
                            if other:
                                tmp = other.pop(0)
                                if tmp == 'to':
                                    value['protocols'].append({'proto': proto, 'port': f'{port3}-{other.pop(0)}', 'source_port': port})
                                else:
                                    value['protocols'].append({'proto': proto, 'port': port3, 'source_port': port})
                                    value['protocols'].append({'proto': proto, 'port': tmp, 'source_port': port})
                                for x in other:
                                    value['protocols'].append({'proto': proto, 'port': x, 'source_port': port})
                            else:
                                value['protocols'].append({'proto': proto, 'port': port3, 'source_port': port})
                        case ['service', _, _, proto, 'destination-port', port, *other]:
                            if other:
                                tmp = other.pop(0)
                                if tmp == 'to':
                                    value['protocols'].append({'proto': proto, 'port': f'{port}-{other.pop(0)}'})
                                else:
                                    value['protocols'].append({'proto': proto, 'port': tmp})
                                for x in other:
                                    value['protocols'].append({'proto': proto, 'port': x})
                            else:
                                value['protocols'].append({'proto': proto, 'port': port})
                        case ['service', _, _, proto, 'source-port', port]:
                            value['protocols'].append({'proto': proto, 'source_port': port})
                        case ['service', _, _, proto, 'source-port', port1, 'to', port2]:
                            value['protocols'].append({'proto': proto, 'source_port': f'{port1}-{port2}'})
                        case ['service', _, 'protocol', proto]:
                            if proto in ug_proto:
                                value['protocols'].append({'proto': proto, 'port': ''})
                        case ['description', *descr]:
                            value['description'] = ' '.join(descr)
                return 'services', {value['name']: value}

            case ['ip', 'service-set', name, 'type', 'group', *_]:
                value = {
                    'name': name,
                    'description': '',
                    'content': []
                }
                for item in data:
                    match item:
                        case ['service', _, 'service-set', service_name]:
                            value['content'].append(service_name)
                return 'service_groups', {value['name']: value}

            case ['time-range', name]:
                value = {}
                time_set = None
                for item in data:
                    match item:
                        case ['time-range', name]:
                            if time_set:
                                value[time_set['name']] = time_set
                            time_set = {
                                'name': name,
                                'content': []
                            }
                        case ['absolute-range', time_from, date_from, 'to', time_to, date_to]:
                            time_set['content'].append({
                                'time_to': time_to,
                                'time_from': time_from,
                                'fixed_date_to': date_to,
                                'fixed_date_from': date_from,   
                            })
                        case ['period-range', time_from, 'to', time_to, days]:
                            time_set['content'].append({
                                'type': 'weekly',
                                'time_to': time_to,
                                'time_from': time_from,
                                'days': [1, 2, 3, 4, 5] if days == 'working-day' else [6, 7],
                            })
                if time_set:
                    value[time_set['name']] = time_set
                return 'calendars', value

            case ['interface', name]:
                value = {
                    name: {
                        'name': name,
                        'description': '',
                        'ipv4': [],
                        'ifalias': '',
                        'vlan_id': 0
                    }
                }
                for item in data[1:]:
                    match item:
                        case ['vlan-type', 'dot1q', vlan_number]:
                            value[name]['vlan_id'] = vlan_number
                        case ['ip', 'address', ip, mask]:
                            err, pack_ip = self.pack_ip_address(ip, mask)
                            if err:
                                self.stepChanged.emit(f'RED|    Error: [Interface "{name}"] Не корректный IP-адрес. {pack_ip}')
                            else:
                                value[name]['ipv4'].append(pack_ip)
                        case ['alias', *descr]:
                            value[name]['ifalias'] = ' '.join(descr)
                        case ['description', *descr]:
                            value[name]['description'] = ' '.join(descr)
                return 'ifaces' if value[name]['vlan_id'] else 0, value

            case ['destination-nat', 'address-group', name, _]:
                dnat_name = None
                for item in data:
                    match item:
                        case ['destination-nat', 'address-group', name, _]:
                            dnat_name = name
                        case ['section', ip1, ip2]:
                            self.dnat_ip[dnat_name] = ip1
                return 0, ''

            case ['nat', 'address-group', name, _]:
#               nat_mode = None
                for item in data[1:]:
                    match item:
#                        case ['mode', mode]:
#                            nat_mode = mode
                        case ['section', '0', ip1, ip2]:
#                            if nat_mode == 'pat':
                            self.snat_ip[name] = ip1
                return 0, ''

            case ['firewall', 'zone', name]:
                value = {
                    'name': name,
                    'description': '',
                    'interface': ''
                }
                for item in data[1:]:
                    match item:
                        case ['add', 'interface', ifname]:
                            value['interface'] = ifname
                        case ['description', *descr]:
                            value['description'] = ' '.join(descr)
                return 'zones', [value]

            case ['firewall', 'zone', 'name', name, 'id', zone_id]:
                value = {
                    'name': name,
                    'description': '',
                    'interface': ''
                }
                for item in data[1:]:
                    match item:
                        case ['add', 'interface', ifname]:
                            value['interface'] = ifname
                        case ['description', *descr]:
                            value['description'] = ' '.join(descr)
                return 'zones', [value]

            case ['ip', 'route-static', ip, mask, port_name, gateway, *other]:
                routes = []
                for item in data:
                    match item:
                        case ['ip', 'route-static', 'vpn-instance', *other]:
                            continue
                        case ['ip', 'route-static', ip, mask, gateway_ip]:
                            err, pack_ip = self.pack_ip_address(ip, mask)
                            if err:
                                self.stepChanged.emit(f'RED|    Error: [Route-static "{gateway_ip}"] Не корректный IP-адрес. {pack_ip}')
                            else:
                                if pattern.match(gateway_ip):
                                    gateway = gateway_ip
                                else:
                                    continue
                                routes.append({'dest': pack_ip, 'gateway': gateway, 'description': ''})
                        case ['ip', 'route-static', ip, mask, port_name, gateway_ip, *other]:
                            err, pack_ip = self.pack_ip_address(ip, mask)
                            if err:
                                self.stepChanged.emit(f'RED|    Error: [Route-static "{port_name}"] Не корректный IP-адрес. {pack_ip}')
                            else:
                                if pattern.match(gateway_ip):
                                    gateway = gateway_ip
                                elif pattern.match(port_name):
                                    gateway = port_name
                                else:
                                    continue
                                descr = ''
                                if 'description' in other:
                                    i = other.index('description')
                                    descr = ' '.join(other[i+1:])
                                elif gateway_ip == 'description':
                                    descr = ' '.join(other)
                                routes.append({'dest': pack_ip, 'gateway': gateway, 'description': descr})
                return 'routes', routes

            case ['profile', 'type', 'dns-filter', 'name', *name]:
                value = {
                    'name': ' '.join(name),
                    'description': '',
                    'content': []
                }
                for item in data[1:]:
                    match item:
                        case ['add', 'blacklist', url]:
                            value['content'].append(url)
                        case ['description', *descr]:
                            value['description'] = ' '.join(descr)
                return 'url_list', {value['name']: value}
            case ['domain-set', 'name', *name]:
                value = {}
                url_list = None
                for item in data:
                    match item:
                        case ['domain-set', 'name', *name]:
                            if url_list:
                                value[url_list['name']] = url_list
                            url_list = {
                                'name': ' '.join(name),
                                'description': '',
                                'content': []
                            }
                        case ['add', 'domain', url]:
                            url_list['content'].append(url)
                        case ['description', *descr]:
                            url_list['description'] = ' '.join(descr)
                if url_list:
                    value[url_list['name']] = url_list
                return 'url_list', value
            case ['geo-location', 'user-defined', *name]:
                value = {}
                ip_list = None
                for item in data:
                    match item:
                        case ['geo-location', 'user-defined', *name]:
                            if ip_list:
                                value[ip_list['name']] = ip_list
                            ip_list = {
                                'name': ' '.join(name),
                                'description': '',
                                'content': []
                            }
                            self.ip_lists.add(ip_list['name'])
                        case ['add', 'address', 'range', ip1, ip2]:
                            if ip1 == ip2:
                                ip_list['content'].append(ip1)
                            else:
                                ip_list['content'].append(f'{ip1}-{ip2}')
                        case ['description', *descr]:
                            ip_list['description'] = ' '.join(descr)
                if ip_list:
                    value[ip_list['name']] = ip_list
                return 'ip_lists', value
            case ['geo-location-set', *name]:
                value = {}
                ip_list = None
                for item in data:
                    match item:
                        case ['geo-location-set', *name]:
                            if ip_list and ip_list['content']:
                                value[ip_list['name']] = ip_list
                                self.ip_lists.add(ip_list['name'])
                            ip_list = {
                                'name': ' '.join(name),
                                'description': '',
                                'content': []
                            }
                        case ['add', 'geo-location', *name]:
                            if ' '.join(name) in self.ip_lists:
                                ip_list['content'].append({'list': ' '.join(name)})
                        case ['description', *descr]:
                            ip_list['description'] = ' '.join(descr)
                if ip_list and ip_list['content']:
                    value[ip_list['name']] = ip_list
                    self.ip_lists.add(ip_list['name'])
                return 'ip_lists', value
            case ['security-policy']:
                value = []
                fw_rule = None
                for item in data[1:]:
                    match item:
                        case ['rule', 'name', *name]:
                            if fw_rule: value.append(fw_rule)
                            fw_rule = {
                                'name': ' '.join(name),
                                'description': '',
                                'action': '',
                                'src_zones': [],
                                'dst_zones': [],
                                'src_ips': [],
                                'dst_ips': [],
                                'services': [],
                                'apps': [],
                                'log': False,
                                'src_ips_negate': False,
                                'dst_ips_negate': False,
                                'time_restrictions': [],
                            }
                        case ['source-zone', zone_name]:
                            fw_rule['src_zones'].append(zone_name)
                        case ['destination-zone', zone_name]:
                            fw_rule['dst_zones'].append(zone_name)
                        case ['action', action]:
                            fw_rule['action'] = 'accept' if action == 'permit' else 'drop'
                        case ['policy', 'logging']:
                            fw_rule['log'] = True
                        case ['source-address', 'address-set', ip_list]:
                            fw_rule['src_ips'].append(['list_id', ip_list])
                        case ['source-address-exclude', 'address-set', ip_list]:
                            fw_rule['src_ips'].append(['list_id', ip_list])
                            fw_rule['src_ips_negate'] = True
                        case ['source-address-exclude', ip, 'mask', mask]:
                            err, pack_ip = self.pack_ip_address(ip, mask)
                            if err:
                                self.stepChanged.emit(f'RED|    Error: [FW rule "{fw_rule["name"]}"] Не корректный IP-адрес. {pack_ip}')
                            else:
                                fw_rule['source_ip'].append(['ip_address', pack_ip])
                                fw_rule['src_ips_negate'] = True
                        case ['source-address', 'domain-set', *url_list]:
                            fw_rule['src_ips'].append(['urllist_id', ' '.join(url_list)])
                        case ['source-address', ip, 'mask', mask]:
                            err, pack_ip = self.pack_ip_address(ip, mask)
                            if err:
                                self.stepChanged.emit(f'RED|    Error: [FW rule "{fw_rule["name"]}"] Не корректный IP-адрес. {pack_ip}')
                            else:
                                fw_rule['src_ips'].append(['ip_address', pack_ip])
                        case ['source-address', 'geo-location-set', geo_ip]:
                            if geo_ip in self.ip_lists:
                                fw_rule['src_ips'].append(['list_id', geo_ip])
                            else:
                                fw_rule['src_ips'].append(['geoip_code', geo_ip])
                        case ['destination-address', 'address-set', ip_list]:
                            fw_rule['dst_ips'].append(['list_id', ip_list])
                        case ['destination-address-exclude', 'address-set', ip_list]:
                            fw_rule['dst_ips'].append(['list_id', ip_list])
                            fw_rule['dst_ips_negate'] = True
                        case ['destination-address', 'domain-set', *url_list]:
                            fw_rule['dst_ips'].append(['urllist_id', ' '.join(url_list)])
                        case ['destination-address', ip, 'mask', mask]:
                            err, pack_ip = self.pack_ip_address(ip, mask)
                            if err:
                                self.stepChanged.emit(f'RED|    Error: [FW rule "{fw_rule["name"]}"] Не корректный destination-address. {pack_ip}')
                            else:
                                fw_rule['dst_ips'].append(['ip_address', pack_ip])
                        case ['destination-address', 'geo-location-set', geo_ip]:
                            if geo_ip in self.ip_lists:
                                fw_rule['dst_ips'].append(['list_id', geo_ip])
                            else:
                                fw_rule['dst_ips'].append(['geoip_code', geo_ip])
                        case ['service', service_name]:
                            if service_name in ug_services:
                                fw_rule['services'].append(['service', ug_services[service_name]])
                            elif service_name in self.huawei_services:
                                fw_rule['services'].append(['service', service_name])
                            else:
                                fw_rule['services'].append(['new', {'name': service_name}])
                        case ['service', 'protocol', proto, 'source-port', port1, 'to', port2, 'destination-port', port3]:
                            fw_rule['services'].append(['new', {'proto': proto, 'src': f'{port1}-{port2}', 'dst': port3}])
                        case ['service', 'protocol', proto, 'source-port', port1, 'to', port2, 'destination-port', port3, 'to', port4]:
                            fw_rule['services'].append(['new', {'proto': proto, 'src': f'{port1}-{port2}', 'dst': f'{port3}-{port4}'}])
                        case ['service', 'protocol', proto, 'destination-port', port]:
                            fw_rule['services'].append(['new', {'proto': proto, 'src': '', 'dst': port}])
                        case ['application', 'app', app]:
                            fw_rule['apps'].append(['app', app])
                        case ['application', 'category', *categories]:
                            fw_rule['apps'].extend([['ro_group', category] for category in categories])
                        case ['time-range', schedule_name]:
                            fw_rule['time_restrictions'].append(schedule_name)

                        case ['description', *descr]:
                            fw_rule['description'] = ' '.join(descr)
                if fw_rule: value.append(fw_rule)
                return 'firewall_rules', value
            case ['traffic-policy']:
                dscp_table = {
                    'cs0': 0,
                    'cs1': 8,
                    'af11': 10,
                    'af12': 12,
                    'af13': 14,
                    'cs2': 16,
                    'af21': 18,
                    'af22': 20,
                    'af23': 22,
                    'cs3': 24,
                    'af31': 26,
                    'af32': 28,
                    'af33': 30,
                    'cs4': 32,
                    'af41': 34,
                    'af42': 36,
                    'af43': 38,
                    'cs5': 40,
                    'ef': 46,
                    'cs6': 48,
                    'cs7': 56,
                }
                value = {'shapers': {}, 'rules': []}
                shaper = None
                rule = None
                for item in data[1:]:
                    match item:
                        case ['profile', *name]:
                            if shaper:
                                value['shapers'][shaper['name']] = shaper
                            shaper = {
                                'name': ' '.join(name),
                                'rate': 0,
                                'dscp': 0,
                            }
                        case ['bandwidth', _, _, _, rate]:
                            if not shaper['rate']:
                                shaper['rate'] = int(rate)
                        case ['rule', 'name', *name]:
                            if rule:
                                value['rules'].append(rule)
                                if 'dscp' in rule:
                                    for key in value['shapers']:
                                        if key == rule['pool']:
                                            value['shapers'][key]['dscp'] = rule.pop('dscp')
                            rule = {
                                'name': ' '.join(name),
                                'description': '',
                                'src_zones': [],
                                'dst_zones': [],
                                'src_ips': [],
                                'dst_ips': [],
                                'services': [],
                                'apps': [],
                                'pool': '',
                                'time_restrictions': [],
                            }
                        case ['source-zone', zone_name]:
                            rule['src_zones'].append(zone_name)
                        case ['source-address', 'address-set', ip_list]:
                            rule['src_ips'].append(['list_id', ip_list])
                        case ['source-address', ip, 'mask', mask]:
                            err, pack_ip = self.pack_ip_address(ip, mask)
                            if err:
                                self.stepChanged.emit(f'RED|    Error: [Saper rule "{rule["name"]}"] Не корректный source-address. {pack_ip}')
                            else:
                                rule['src_ips'].append(['ip_address', pack_ip])
                        case ['destination-zone', zone_name]:
                            rule['dst_zones'].append(zone_name)
                        case ['destination-address', 'address-set', ip_list]:
                            rule['dst_ips'].append(['list_id', ip_list])
                        case ['destination-address', ip, 'mask', mask]:
                            err, pack_ip = self.pack_ip_address(ip, mask)
                            if err:
                                self.stepChanged.emit(f'RED|    Error: [Saper rule "{rule["name"]}"] Не корректный destination-address. {pack_ip}')
                            else:
                                rule['dst_ips'].append(['ip_address', pack_ip])
                        case ['application', 'app', app]:
                            rule['apps'].append(['app', app])
                        case ['time-range', schedule_name]:
                            rule['time_restrictions'].append(schedule_name)
                        case ['action', _, _, *profile]:
                            rule['pool'] = ' '.join(profile)
                        case ['service', service_name]:
                            if service_name in ug_services:
                                rule['services'].append(['service', ug_services[service_name]])
                            elif service_name in self.huawei_services:
                                rule['services'].append(['service', service_name])
                            else:
                                rule['services'].append(['new', {'name': service_name}])
                        case ['dscp', dscp_name]:
                            rule['dscp'] = dscp_table[dscp_name]
                        case ['description', *descr]:
                            rule['description'] = ' '.join(descr)
                if shaper:
                    value['shapers'][shaper['name']] = shaper
                if rule:
                    value['rules'].append(rule)
                    if 'dscp' in rule:
                        for key in value['shapers']:
                            if key == rule['pool']:
                                value['shapers'][key]['dscp'] = rule.pop('dscp')
                return 'traffic_shaping', value
            case ['nat-policy']:
                value = []
                nat_rule = None
                for item in data[1:]:
                    match item:
                        case ['rule', 'name', *name]:
                            if nat_rule: value.append(nat_rule)
                            nat_rule = {
                                'name': ' '.join(name),
                                'description': '',
                                'action': '',
                                'zone_in': [],
                                'zone_out': [],
                                'source_ip': [],
                                'dest_ip': [],
                                'service': [],
                                'target_ip': '',
                                'target_snat': False,
                                'snat_target_ip': '',
                                'source_ip_negate': False,
                                'dest_ip_negate': False,
                                'port_mappings': [],
                            }
                        case ['source-zone', zone_name]:
                            nat_rule['zone_in'].append(zone_name)
                        case ['destination-zone', zone_name]:
                            nat_rule['zone_out'].append(zone_name)
                        case ['action', action]:
                            nat_rule['action'] = action
                        case ['action', 'destination-nat', 'address-group', group]:
                            nat_rule['target_ip'] = self.dnat_ip[group]
                            nat_rule['action'] = 'dnat'
                        case ['action', 'destination-nat', 'static', 'port-to-address', 'address-group', group, *port]:
                            nat_rule['target_ip'] = self.dnat_ip[group]
                            nat_rule['action'] = 'dnat'
                        case ['action', 'destination-nat', 'static', 'address-to-address', 'address-group', group, *port]:
                            nat_rule['target_ip'] = self.dnat_ip[group]
                            nat_rule['action'] = 'dnat'
                        case ['action', 'source-nat', 'easy-ip']:
                            nat_rule['action'] = 'nat'
                        case ['action', 'source-nat', 'address-group', group]:
                            nat_rule['action'] = 'nat'
                            nat_rule['target_snat'] = True
                            nat_rule['snat_target_ip'] = self.snat_ip[group]
                        case ['source-address', 'address-set', ip_list]:
                            nat_rule['source_ip'].append(['list_id', ip_list])
                        case ['source-address-exclude', 'address-set', ip_list]:
                            nat_rule['source_ip'].append(['list_id', ip_list])
                            nat_rule['source_ip_negate'] = True
                        case ['source-address-exclude', ip, 'mask', mask]:
                            err, pack_ip = self.pack_ip_address(ip, mask)
                            if err:
                                self.stepChanged.emit(f'RED|    Error: [NAT rule "{nat_rule["name"]}"] Не корректный source-address-exclude. {pack_ip}')
                            else:
                                nat_rule['source_ip'].append(['ip_address', pack_ip])
                                nat_rule['source_ip_negate'] = True
                        case ['source-address', 'domain-set', *url_list]:
                            nat_rule['src_ips'].append(['urllist_id', ' '.join(url_list)])
                        case ['source-address', ip, 'mask', mask]:
                            err, pack_ip = self.pack_ip_address(ip, mask)
                            if err:
                                self.stepChanged.emit(f'RED|    Error: [NAT rule "{nat_rule["name"]}"] Не корректный source-address. {pack_ip}')
                            else:
                                nat_rule['source_ip'].append(['ip_address', pack_ip])
                        case ['source-address', 'geo-location-set', geo_ip]:
                            if geo_ip in self.ip_lists:
                                nat_rule['source_ip'].append(['list_id', geo_ip])
                        case ['destination-address', 'address-set', ip_list]:
                            nat_rule['dest_ip'].append(['list_id', ip_list])
                        case ['destination-address-exclude', 'address-set', ip_list]:
                            nat_rule['dest_ip'].append(['list_id', ip_list])
                            nat_rule['dest_ip_negate'] = True
                        case ['destination-address', 'domain-set', *url_list]:
                            nat_rule['dest_ip'].append(['urllist_id', ' '.join(url_list)])
                        case ['destination-address', ip, 'mask', mask]:
                            err, pack_ip = self.pack_ip_address(ip, mask)
                            if err:
                                self.stepChanged.emit(f'RED|    Error: [NAT rule "{nat_rule["name"]}"] Не корректный destination-address. {pack_ip}')
                            else:
                                nat_rule['dest_ip'].append(['ip_address', pack_ip])
                        case ['service', service_name]:
                            if service_name in ug_services:
                                nat_rule['service'].append(['service', ug_services[service_name]])
                            elif service_name in self.huawei_services:
                                nat_rule['service'].append(['service', service_name])
                            else:
                                nat_rule['service'].append(['new', {'name': service_name}])
                        case ['service', 'protocol', proto, 'source-port', port1, 'to', port2, 'destination-port', port3]:
                            nat_rule['service'].append(['new', {'proto': proto, 'src': f'{port1}-{port2}', 'dst': port3}])
                        case ['service', 'protocol', proto, 'source-port', port1, 'to', port2, 'destination-port', port3, 'to', port4]:
                            nat_rule['service'].append(['new', {'proto': proto, 'src': f'{port1}-{port2}', 'dst': f'{port3}-{port4}'}])
                        case ['service', 'protocol', proto, 'destination-port', port]:
                            nat_rule['service'].append(['new', {'proto': proto, 'src': '', 'dst': port}])

                        case ['description', *descr]:
                            nat_rule['description'] = ' '.join(descr)
                if nat_rule: value.append(nat_rule)
                return 'nat_rules', value

            case _:
                return 0, ''

#---------------------------------------------------------------------------------------------------------------------
    def convert_time_zone(self):
        """Конвертируем часовой пояс."""
        if 'timezone' not in self.data:
            return

        self.stepChanged.emit('BLUE|Конвертация часового пояса.')
        time_zone = {}
        timezones = {
            '2': 'Europe/Kaliningrad',
            '3': 'Europe/Moscow',
            '4': 'Europe/Samara',
            '5': 'Asia/Yekaterinburg',
            '6': 'Asia/Omsk',
            '7': 'Asia/Krasnoyarsk',
            '8': 'Asia/Irkutsk',
            '9': 'Asia/Yakutsk',
            '10': 'Asia/Vladivistok',
            '11': 'Asia/Magadan',
            '12': 'Asia/Kamchatka'
        }
        if (offset := self.data['timezone'].get('offset', None)):
            x = offset[:2]
            zone_number = x if x[0] != '0' else x[1]
            time_zone['ui_timezone'] = timezones[zone_number]

        if time_zone:
            current_path = os.path.join(self.current_ug_path, 'UserGate', 'GeneralSettings')
            err, msg = self.create_dir(current_path)
            if err:
                self.stepChanged.emit(f'RED|    {msg}')
                self.error = 1
                return

            json_file = os.path.join(current_path, 'config_settings_ui.json')
            with open(json_file, 'w') as fh:
                json.dump(time_zone, fh, indent=4, ensure_ascii=False)
            self.stepChanged.emit(f'GREEN|    Настройка часового пояса выгружена в файл "{json_file}".')
        else:
            self.stepChanged.emit('GRAY|    Нет настроек часового пояса для экспорта.')


    def convert_dns_servers(self):
        """Заполняем список системных DNS"""
        if 'dns_servers' not in self.data:
            return
        self.stepChanged.emit('BLUE|Конвертация настроек DNS.')

        dns_servers = []
        for value in self.data['dns_servers']:
            dns_servers.append({'dns': value, 'is_bad': False})
        
        if dns_servers:
            current_path = os.path.join(self.current_ug_path, 'Network', 'DNS')
            err, msg = self.create_dir(current_path, delete='no')
            if err:
                self.stepChanged.emit(f'RED|    {msg}')
                self.error = 1
                return

            json_file = os.path.join(current_path, 'config_dns_servers.json')
            with open(json_file, 'w') as fh:
                json.dump(dns_servers, fh, indent=4, ensure_ascii=False)
            self.stepChanged.emit(f'GREEN|    Настройки серверов DNS выгружены в файл "{json_file}".')
        else:
            self.stepChanged.emit('GRAY|    Нет серверов DNS для экспорта.')


    def convert_notification_profile(self):
        """Конвертируем почтовый адрес и профиль оповещения"""
        if 'smtp_settings' not in self.data:
            return
        self.stepChanged.emit('BLUE|Конвертация почтовых адресов и профиля оповещения.')

        smtp_settings = self.data.get('smtp_settings', [])

        if 'smtp_server' in smtp_settings:
            current_path = os.path.join(self.current_ug_path, 'Libraries', 'NotificationProfiles')
            err, msg = self.create_dir(current_path)
            if err:
                self.stepChanged.emit(f'RED|    {msg}')
                self.error = 1
                return

            notification = [{
                'type': 'smtp',
                'name': 'System email-server',
                'description': 'Перенесено с Huawei',
                'host': smtp_settings['smtp_server'],
                'port': smtp_settings.get('smtp_server_port', '25'),
                'security': 'none',
                'authentication': True,
                'login': smtp_settings.get('user', 'example'),
                'password': smtp_settings.get('password', 'password'),
            }]

            json_file = os.path.join(current_path, 'config_notification_profiles.json')
            with open(json_file, 'w') as fh:
                json.dump(notification, fh, indent=4, ensure_ascii=False)
            self.stepChanged.emit(f'BLACK|    Профиль оповещения SMTP выгружен в файл "{json_file}".')
        else:
            self.stepChanged.emit('GRAY|    Нет профиля оповещения для экспорта.')

        email_groups = []
        if 'sender' in smtp_settings:
            email_groups.append(self.set_email_group(smtp_settings['sender']))
        if 'recipient' in smtp_settings:
            email_groups.append(self.set_email_group(smtp_settings['recipient']))

        if email_groups:
            current_path = os.path.join(self.current_ug_path, 'Libraries', 'Emails')
            err, msg = self.create_dir(current_path)
            if err:
                self.stepChanged.emit(f'RED|    {msg}')
                self.error = 1
                return

            json_file = os.path.join(current_path, 'config_email_groups.json')
            with open(json_file, 'w') as fh:
                json.dump(email_groups, fh, indent=4, ensure_ascii=False)
            self.stepChanged.emit(f'BLACK|    Почтовые адреса выгружены в файл "{json_file}".')
        else:
            self.stepChanged.emit('GRAY|    Нет почтовых адресов для экспорта.')

        self.stepChanged.emit('GREEN|    Конвертация почтовых адресов и профиля оповещения завершена.')


    def convert_services(self):
        """Конвертируем сетевые сервисы."""
        self.stepChanged.emit('BLUE|Конвертация сетевых сервисов.')
        current_path = os.path.join(self.current_ug_path, 'Libraries', 'Services')
        err, msg = self.create_dir(current_path)
        if err:
            self.stepChanged.emit(f'RED|    {msg}')
            self.error = 1
            return

        if 'services' in self.data:
            services_proto = {'110': 'pop3', '995': 'pop3s', '25': 'smtp', '465': 'smtps'}
            for service in self.data['services'].values():
                _, service['name'] = self.get_transformed_name(service['name'], descr='Имя сервиса')
                service['description'] = f"Перенесено с Huawei.\n{service['description']}"
                for protocol in service['protocols']:
                    protocol['port'] = protocol.get('port', '')   # Это поле может отсутствовать.
                    protocol['app_proto'] = ''
                    protocol['alg'] = ''
                    if protocol['proto'] == 'tcp':
                        protocol['proto'] = services_proto.get(protocol['port'], 'tcp')
                        protocol['app_proto'] = services_proto.get(protocol['port'], '')
                    if protocol['port'] == '0-65535':
                        protocol['port'] = ''
                    protocol['source_port'] = protocol.get('source_port', '')   # Это поле может отсутствовать.
                    if protocol['source_port'] == '0-65535':
                        protocol['source_port'] = ''
        else:
            self.data['services'] = {}
        for ug_service in self.create_ug_services():
            self.data['services'].update({ug_service['name']: ug_service})

        json_file = os.path.join(current_path, 'config_services_list.json')
        with open(json_file, 'w') as fh:
            json.dump([x for x in self.data['services'].values()], fh, indent=4, ensure_ascii=False)
        self.stepChanged.emit(f'GREEN|    Сервисы выгружены в файл "{json_file}".')


    def convert_service_groups(self):
        """Конвертируем группы сервисов."""
        self.stepChanged.emit('BLUE|Конвертация групп сервисов.')
        if 'service_groups' not in self.data:
            self.stepChanged.emit('GRAY|    Нет групп сервисов для экспорта.')
            return

        error = 0
        for srv_group in self.data['service_groups'].values():
            _, srv_group['name'] = self.get_transformed_name(srv_group['name'], descr='Имя группы сервисов')
            srv_group['description'] = 'Портировано с Huawei.'
            srv_group['type'] = 'servicegroup'
            srv_group['url'] = ''
            srv_group['list_type_update'] = 'static'
            srv_group['schedule'] = 'disabled'
            srv_group['attributes'] = {}

            new_content = []
            for item in srv_group['content']:
                service = copy.deepcopy(self.data['services'].get(item, None))
                if service:
                    for x in service['protocols']:
                        x['src_port'] = x.pop('source_port', '')
                    new_content.append(service)
                else:
                    self.stepChanged.emit(f'RED|    Error: Не найден сервис "{item}" для группы сервисов "{srv_group["name"]}".')
                    error = 1
            srv_group['content'] = new_content

        current_path = os.path.join(self.current_ug_path, 'Libraries', 'ServicesGroups')
        err, msg = self.create_dir(current_path)
        if err:
            self.stepChanged.emit(f'RED|    {msg}')
            self.error = 1
            return

        json_file = os.path.join(current_path, 'config_services_groups_list.json')
        with open(json_file, 'w') as fh:
            json.dump([x for x in self.data['service_groups'].values()], fh, indent=4, ensure_ascii=False)
        if error:
            self.stepChanged.emit(f'ORANGE|    Конвертация прошла с ошибками. Группы сервисов выгружены в файл "{json_file}".')
            self.error = 1
        else:
            self.stepChanged.emit(f'GREEN|    Группы сервисов выгружены в файл "{json_file}".')


    def convert_ip_lists(self):
        """Конвертируем списки IP-адресов"""
        self.stepChanged.emit('BLUE|Конвертация списков IP-адресов.')
        current_path = os.path.join(self.current_ug_path, 'Libraries', 'IPAddresses')
        err, msg = self.create_dir(current_path)
        if err:
            self.stepChanged.emit(f'RED|    {msg}')
            self.error = 1
            return

        error = 0
        n = 1
        indicator = [1, 1, 1]
        if 'ip_lists' in self.data:
            for ip_list in self.data['ip_lists'].values():
                _, ip_list['name'] = self.get_transformed_name(ip_list['name'], descr='Имя списка IP-адресов')
                ip_list['description'] = f"Перенесено с Huawei.\n{ip_list['description']}"
                ip_list['type'] = 'network'
                ip_list['url'] = ''
                ip_list['list_type_update'] = 'static'
                ip_list['schedule'] = 'disabled'
                ip_list['attributes'] = {'threat_level': 3}
                content = []
                for value in ip_list['content']:
                    if isinstance(value, str) and '.' in value:
                        content.append({'value': value})
                    else:
                        content.append(value)
                ip_list['content'] = content

                json_file = os.path.join(current_path, f'{ip_list["name"].translate(self.trans_filename)}.json')
                with open(json_file, 'w') as fh:
                    json.dump(ip_list, fh, indent=4, ensure_ascii=False)
                self.stepChanged.emit(f'BLACK|    {n} - Список IP-адресов "{ip_list["name"]}" выгружен в файл "{json_file}".')
                n += 1
        else:
            indicator.pop()

        if 'ip_lists_group' in self.data:
            for ip_list in self.data['ip_lists_group'].values():
                _, ip_list['name'] = self.get_transformed_name(ip_list['name'], descr='Имя списка групп IP-адресов')
                ip_list['description'] = f"Перенесено с Huawei.\n{ip_list['description']}"
                ip_list['type'] = 'network'
                ip_list['url'] = ''
                ip_list['list_type_update'] = 'static'
                ip_list['schedule'] = 'disabled'
                ip_list['attributes'] = {'threat_level': 3}
                content = []
                for value in ip_list['content']:
                    if value in self.data['ip_lists_group']:
                        content.append({'list': self.data['ip_lists_group'][value]['name']})
                    else:
                        try:
                            content.append({'list': self.data['ip_lists'][value]['name']})
                        except KeyError:
                            self.stepChanged.emit(f'RED|    Error: [Группа IP-адресов "{ip_list["name"]}"] Не найден IP-лист "{value}".')
                            ip_list['description'] = f'Error: Не найден IP-лист "{value}".\n{ip_list["description"]}'
                            error = 1
                ip_list['content'] = content

                json_file = os.path.join(current_path, f'{ip_list["name"].translate(self.trans_filename)}.json')
                with open(json_file, 'w') as fh:
                    json.dump(ip_list, fh, indent=4, ensure_ascii=False)
                self.stepChanged.emit(f'BLACK|    {n} - Список IP-адресов "{ip_list["name"]}" выгружен в файл "{json_file}".')
                n += 1
        else:
            indicator.pop()

        if 'firewall' in self.data:
            ip_list = {
                'name': '',
                'description': 'Перенесено с Huawei.',
                'type': 'network',
                'url': '',
                'list_type_update': 'static',
                'schedule': 'disabled',
                'attributes': {'threat_level': 3},
            }
            for key1, val1 in self.data['firewall'].items():
                for key2, val2 in val1.items():
                    ip_list['name'] = f'firewall_{key1}_{key2}'
                    ip_list['content'] = [{'value': value} for value in val2 if '.' in value]

                    json_file = os.path.join(current_path, f'{ip_list["name"].strip().translate(self.trans_filename)}.json')
                    with open(json_file, 'w') as fh:
                        json.dump(ip_list, fh, indent=4, ensure_ascii=False)
                    self.stepChanged.emit(f'BLACK|    {n} - Список IP-адресов "{ip_list["name"]}" выгружен в файл "{json_file}".')
                    n += 1
        else:
            indicator.pop()

        if indicator:
            if error:
                self.stepChanged.emit(f'ORANGE|    Конвертация прошла с ошибками. Списки IP-адресов выгружены в каталог "{current_path}".')
                self.error = 1
            else:
                self.stepChanged.emit(f'GREEN|    Списки IP-адресов выгружены в каталог "{current_path}".')
        else:
            self.stepChanged.emit('GRAY|    Нет списков IP-адресов для экспорта.')


    def convert_url_lists(self):
        """Конвертируем списки URL"""
        self.stepChanged.emit('BLUE|Конвертация списков URL.')

        if 'url_list' in self.data:
            current_path = os.path.join(self.current_ug_path, 'Libraries', 'URLLists')
            err, msg = self.create_dir(current_path)
            if err:
                self.stepChanged.emit(f'RED|    {msg}')
                self.error = 1
                return

            n = 1
            for url_list in self.data['url_list'].values():
                _, url_list['name'] = self.get_transformed_name(url_list['name'], descr='Имя списка URL')
                url_list['description'] = f"Перенесено с Huawei.\n{url_list['description']}"
                url_list['type'] = 'url'
                url_list['url'] = ''
                url_list['list_type_update'] = 'static'
                url_list['schedule'] = 'disabled'
                url_list['attributes'] = {'list_compile_type': 'case_insensitive'}
                url_list['content'] = [{'value': value} for value in url_list['content']]

                json_file = os.path.join(current_path, f'{url_list["name"].translate(self.trans_filename)}.json')
                with open(json_file, 'w') as fh:
                    json.dump(url_list, fh, indent=4, ensure_ascii=False)
                self.stepChanged.emit(f'BLACK|    {n} - Список URL "{url_list["name"]}" выгружен в файл "{json_file}".')
                n += 1
            self.stepChanged.emit(f'GREEN|    Списки URL выгружены в каталог "{current_path}".')
        else:
            self.stepChanged.emit('GRAY|    Нет списков URL для экспорта.')


    def convert_time_sets(self):
        """Конвертируем time set (календари)"""
        self.stepChanged.emit('BLUE|Конвертация календарей.')

        if 'calendars' in self.data:
            current_path = os.path.join(self.current_ug_path, 'Libraries', 'TimeSets')
            err, msg = self.create_dir(current_path)
            if err:
                self.stepChanged.emit(f'RED|    {msg}')
                self.error = 1
                return

            for cal in self.data['calendars'].values():
                _, cal['name'] = self.get_transformed_name(cal['name'], descr='Имя календаря')
                cal['description'] = 'Перенесено с Huawei.'
                cal['type'] = 'timerestrictiongroup'
                cal['url'] = ''
                cal['list_type_update'] = 'static'
                cal['schedule'] = 'disabled'
                cal['attributes'] = {}
                num = 1
                for item in cal['content']:
                    item['time_to'] = item['time_to'][:5]
                    item['time_from'] = item['time_from'][:5]
                    if 'type' not in item:
                        item['type'] = 'span'
                        year, month, day = item['fixed_date_to'].split('/')
                        item['fixed_date_to'] = f'{year}-{int(month):02d}-{int(day):02d}T00:00:00'
                        year, month, day = item['fixed_date_from'].split('/')
                        item['fixed_date_from'] = f'{year}-{int(month):02d}-{int(day):02d}T00:00:00'
                    item['name'] = f'{item["type"]}-{num}'
                    num += 1
#                self.time_restrictions.add(cal['name'])

            json_file = os.path.join(current_path, 'config_calendars.json')
            with open(json_file, 'w') as fh:
                json.dump([x for x in self.data['calendars'].values()], fh, indent=4, ensure_ascii=False)
            self.stepChanged.emit(f'GREEN|    Список календарей выгружен в файл "{json_file}".')
        else:
            self.stepChanged.emit('GRAY|    Нет календарей для экспорта.')


    def convert_vlan_interfaces(self):
        """Конвертируем интерфейсы VLAN."""
        self.stepChanged.emit('BLUE|Конвертация интерфейсов VLAN.')

        if 'ifaces' in self.data:
            current_path = os.path.join(self.current_ug_path, 'Network', 'Interfaces')
            err, msg = self.create_dir(current_path)
            if err:
                self.stepChanged.emit(f'RED|    {msg}')
                self.error = 1
                return

            for key, iface in self.data['ifaces'].items():
                iface['description'] = f"Перенесено с Huawei.\n{iface['description']}"
                iface['kind'] = 'vlan'
                iface['enabled'] = False
                iface['zone_id'] = 0
                iface['master'] = False
                iface['netflow_profile'] = 'undefined'
                iface['lldp_profile'] = 'undefined'
                iface['flow_control'] = False
                iface['mode'] = 'static'
                iface['mtu'] = 1500
                iface['tap'] = False
                iface['dhcp_relay'] = {'enabled': False, 'host_ipv4': '', 'servers': []}
                iface['vlan_id'] = int(iface['vlan_id'])
                iface['link'] = ''

            json_file = os.path.join(current_path, 'config_interfaces.json')
            with open(json_file, 'w') as fh:
                json.dump(list(self.data['ifaces'].values()), fh, indent=4, ensure_ascii=False)
            self.stepChanged.emit(f'GREEN|    Интерфейсы VLAN выгружены в файл "{json_file}".')
        else:
            self.stepChanged.emit('GRAY|    Нет интерфейсов VLAN для экспорта.')
    

    def convert_zone(self):
        """Конвертируем зоны"""
        self.stepChanged.emit('BLUE|Конвертация Зон.')

        if 'zones' in self.data:
            current_path = os.path.join(self.current_ug_path, 'Network', 'Zones')
            err, msg = self.create_dir(current_path)
            if err:
                self.stepChanged.emit(f'RED|    {msg}')
                self.error = 1
                return

            for zone in self.data['zones']:
                zone['description'] = f'Перенесено с Huawei.\n{zone["description"]}'
                if zone['interface']:
                    zone['description'] = f'{zone["description"]}\nИнтерфейс {zone["interface"]} на Huawei.'
                zone.pop('interface', None)
                zone['dos_profiles'] = [
                    {
                        'enabled': True,
                        'kind': 'syn',
                        'alert_threshold': 3000,
                        'drop_threshold': 6000,
                        'aggregate': False,
                        'excluded_ips': []
                    },
                    {
                        'enabled': True,
                        'kind': 'udp',
                        'alert_threshold': 3000,
                        'drop_threshold': 6000,
                        'aggregate': False,
                        'excluded_ips': []
                    },
                    {
                        'enabled': True,
                        'kind': 'icmp',
                        'alert_threshold': 100,
                        'drop_threshold': 200,
                        'aggregate': False,
                        'excluded_ips': []
                    }
                ]
                zone['services_access'] = [
                    {
                        'enabled': True,
                        'service_id': 'Ping',
                        'allowed_ips': []
                    },
                    {
                        'enabled': False,
                        'service_id': 'SNMP',
                        'allowed_ips': []
                    },
                    {
                        'enabled': False,
                        'service_id': 'Captive-портал и страница блокировки',
                        'allowed_ips': []
                    },
                    {
                        'enabled': False,
                        'service_id': 'XML-RPC для управления',
                        'allowed_ips': []
                    },
                    {
                        'enabled': False,
                        'service_id': 'Кластер',
                        'allowed_ips': []
                    },
                    {
                        'enabled': False,
                        'service_id': 'VRRP',
                        'allowed_ips': []
                    },
                    {
                        'enabled': False,
                        'service_id': 'Консоль администрирования',
                        'allowed_ips': []
                    },
                    {
                        'enabled': False,
                        'service_id': 'DNS',
                        'allowed_ips': []
                    },
                    {
                        'enabled': False,
                        'service_id': 'HTTP(S)-прокси',
                        'allowed_ips': []
                    },
                    {
                        'enabled': False,
                        'service_id': 'Агент аутентификации',
                        'allowed_ips': []
                    },
                    {
                        'enabled': True,
                        'service_id': 'SMTP(S)-прокси',
                        'allowed_ips': []
                    },
                    {
                        'enabled': True,
                        'service_id': 'POP(S)-прокси',
                        'allowed_ips': []
                    },
                    {
                        'enabled': False,
                        'service_id': 'CLI по SSH',
                        'allowed_ips': []
                    },
                    {
                        'enabled': False,
                        'service_id': 'VPN',
                        'allowed_ips': []
                    },
                    {
                        'enabled': False,
                        'service_id': 'SCADA',
                        'allowed_ips': []
                    },
                    {
                        'enabled': False,
                        'service_id': 'Reverse-прокси',
                        'allowed_ips': []
                    },
                    {
                        'enabled': False,
                        'service_id': 'Веб-портал',
                        'allowed_ips': []
                    },
                    {
                        'enabled': False,
                        'service_id': 'SAML сервер',
                        'allowed_ips': []
                    },
                    {
                        'enabled': False,
                        'service_id': 'Log analyzer',
                        'allowed_ips': []
                    },
                    {
                        'enabled': False,
                        'service_id': 'OSPF',
                        'allowed_ips': []
                    },
                    {
                        'enabled': False,
                        'service_id': 'BGP',
                        'allowed_ips': []
                    },
                    {
                        'enabled': False,
                        'service_id': 'SNMP-прокси',
                        'allowed_ips': []
                    },
                    {
                        'enabled': False,
                        'service_id': 'SSH-прокси',
                        'allowed_ips': []
                    },
                    {
                        'enabled': False,
                        'service_id': 'Multicast',
                        'allowed_ips': []
                    },
                    {
                        'enabled': False,
                        'service_id': 'NTP сервис',
                        'allowed_ips': []
                    },
                    {
                        'enabled': False,
                        'service_id': 'RIP',
                        'allowed_ips': []
                    },
                    {
                        'enabled': False,
                        'service_id': 'UserID syslog collector',
                        'allowed_ips': []
                    },
                    {
                        'enabled': False,
                        'service_id': 'BFD',
                        'allowed_ips': []
                    },
                    {
                        'enabled': False,
                        'service_id': 'Endpoints connect',
                        'allowed_ips': []
                    }
                ]
                zone['readonly'] =  False
                zone['enable_antispoof'] = False
                zone['antispoof_invert'] = False
                zone['networks'] = []
                zone['sessions_limit_enabled'] = False
                zone['sessions_limit_threshold'] = 0
                zone['sessions_limit_exclusions'] = []

            json_file = os.path.join(current_path, 'config_zones.json')
            with open(json_file, 'w') as fh:
                json.dump(self.data['zones'], fh, indent=4, ensure_ascii=False)
            self.stepChanged.emit(f'GREEN|    Настройки зон выгружены в файл "{json_file}".')
        else:
            self.stepChanged.emit('GRAY|    Нет зон для экспорта.')


    def convert_static_routes(self):
        """Конвертируем статические маршруты в VRF по умолчанию"""
        self.stepChanged.emit('BLUE|Конвертация статических маршрутов в VRF по умолчанию.')

        if 'routes' in self.data:
            current_path = os.path.join(self.current_ug_path, 'Network', 'VRF')
            err, msg = self.create_dir(current_path)
            if err:
                self.stepChanged.emit(f'RED|    {msg}')
                self.error = 1
                return

            routes_list = []
            gateways_list = []
            for route in self.data['routes']:
                ip, mask = route['dest'].split('/')
                if not int(mask):
                    gateways_list.append({
                        'name': route['gateway'],
                        'enabled': False,
                        'description': f'Перенесено с Huawei.\n{route["description"]}',
                        'ipv4': route['gateway'],
                        'vrf': 'default',
                        'weight': 1,
                        'multigate': False,
                        'default': False,
                        'iface': 'undefined',
                        'is_automatic': False
                    })
                    continue
                route['enabled'] = False
                route['name'] = f'Route for {route["dest"]}'
                route['description'] = f'Перенесено с Huawei.\n{route["description"]}'
                route['ifname'] = 'undefined'
                route['kind'] = 'unicast'
                route['metric'] = 0
                routes_list.append(route)
            self.vrf['routes'] = routes_list

            if gateways_list:
                gateway_path = os.path.join(self.current_ug_path, 'Network', 'Gateways')
                err, msg = self.create_dir(gateway_path)
                if err:
                    self.stepChanged.emit(f'RED|    {msg}')
                    self.error = 1
                else:
                    json_file = os.path.join(gateway_path, 'config_gateways.json')
                    with open(json_file, 'w') as fh:
                        json.dump(gateways_list, fh, indent=4, ensure_ascii=False)
                    self.stepChanged.emit(f'GREEN|    Список шлюзов выгружен в файл "{json_file}".')
            else:
                self.stepChanged.emit('GRAY|    Нет шлюзов для экспорта.')

            json_file = os.path.join(current_path, 'config_vrf.json')
            with open(json_file, 'w') as fh:
                json.dump([self.vrf], fh, indent=4, ensure_ascii=False)
            self.stepChanged.emit(f'GREEN|    Статические маршруты выгружены в файл "{json_file}".')
        else:
            self.stepChanged.emit('GRAY|    Нет статических маршрутов для экспорта.')


    def convert_shapers_list(self):
        """Конвертируем полосы пропускания"""
        self.stepChanged.emit('BLUE|Конвертация полос пропускания.')

        if 'traffic_shaping' in self.data:
            if self.data['traffic_shaping']['shapers']:
                current_path = os.path.join(self.current_ug_path, 'Libraries', 'BandwidthPools')
                err, msg = self.create_dir(current_path)
                if err:
                    self.stepChanged.emit(f'RED|    {msg}')
                    self.error = 1
                    return

                for shaper in self.data['traffic_shaping']['shapers'].values():
                    _, shaper['name'] = self.get_transformed_name(shaper['name'], descr='Имя полосы пропускания')
                    shaper['description'] = 'Перенесено с Huawei.'

                json_file = os.path.join(current_path, 'config_shaper_list.json')
                with open(json_file, 'w') as fh:
                    json.dump([x for x in self.data['traffic_shaping']['shapers'].values()], fh, indent=4, ensure_ascii=False)
                self.stepChanged.emit(f'GREEN|    Полосы пропускания выгружены в файл "{json_file}".')
            else:
                self.stepChanged.emit('GRAY|    Нет полос пропускания для экспорта.')
        else:
            self.stepChanged.emit('GRAY|    Нет полос пропускания для экспорта.')
        

    def convert_shaper_rules(self):
        """Конвертируем правила пропускной способности"""
        self.stepChanged.emit('BLUE|Конвертация правил пропускной способности.')

        error = 0
        if 'traffic_shaping' in self.data:
            if self.data['traffic_shaping']['rules']:
                current_path = os.path.join(self.current_ug_path, 'NetworkPolicies', 'TrafficShaping')
                err, msg = self.create_dir(current_path)
                if err:
                    self.stepChanged.emit(f'RED|    {msg}')
                    self.error = 1
                    return

                shaping_rules = set()
                names = {}
                for rule in self.data['traffic_shaping']['rules']:
                    if not rule['pool']:
                        self.stepChanged.emit(f'RED|    Error: [Правило пропускной способности "{rule["name"]}"] Не указана полоса пропускания. Данное правило не конвертируется.')
                        error = 1
                        continue
                    _, rule['name'] = self.get_transformed_name(rule['name'], descr='Имя правила пропускной способности')
                    if rule['name'] in names:
                        names[rule['name']] += 1
                        rule['name'] = f'{rule["name"]}-{names[rule["name"]]}'
                    else:
                        names[rule['name']] = 0
                    rule.pop('dscp', None)
                    rule['description'] = f"Перенесено с Huawei.\n{rule['description']}"
                    rule['scenario_rule_id'] = False

                    error, src_ips = self.get_ips(rule['src_ips'], rule['name'], err=error)
                    rule['src_ips'] = src_ips

                    error, dst_ips = self.get_ips(rule['dst_ips'], rule['name'], err=error)
                    rule['dst_ips'] = dst_ips

                    rule['users'] = []
                    rule['apps'] = self.get_apps(rule['apps'], rule['name'])
                    rule['enabled'] = True

                    error, time_sets = self.get_time_restrictions(rule['time_restrictions'], rule['name'], err=error)
                    rule['time_restrictions'] = time_sets

                    rule['pool'] = self.data['traffic_shaping']['shapers'][rule['pool']]['name']
                    rule.update({
                        'limit': True,
                        'limit_value': '3/h',
                        'limit_burst': 5,
                        'log': False,
                        'log_session_start': False,
                        'src_zones_negate': False,
                        'dst_zones_negate': False,
                        'src_ips_negate': False,
                        'dst_ips_negate': False,
                        'services_negate': False,
                        'apps_negate': False,
                    })
                    shaping_rules.add(rule['name'])

                json_file = os.path.join(current_path, 'config_shaper_rules.json')
                with open(json_file, 'w') as fh:
                    json.dump([x for x in self.data['traffic_shaping']['rules'] if x['name'] in shaping_rules], fh, indent=4, ensure_ascii=False)

                if error:
                    self.stepChanged.emit(f'ORANGE|    Конвертация прошла с ошибками. Правила пропускной способности выгружены в файл "{json_file}".')
                    self.error = 1
                else:
                    self.stepChanged.emit(f'GREEN|    Правила пропускной способности выгружены в файл "{json_file}".')
            else:
                self.stepChanged.emit('GRAY|    Нет правил пропускной способности для экспорта.')
        else:
            self.stepChanged.emit('GRAY|    Нет правил пропускной способности для экспорта.')


    def convert_nat_rules(self):
        """Конвертируем правила NAT/DNAT"""
        self.stepChanged.emit('BLUE|Конвертация правил NAT/DNAT.')

        error = 0
        if 'nat_rules' in self.data and self.data['nat_rules']:
            current_path = os.path.join(self.current_ug_path, 'NetworkPolicies', 'NATandRouting')
            err, msg = self.create_dir(current_path)
            if err:
                self.stepChanged.emit(f'RED|    {msg}')
                self.error = 1
                return

            nat_rules = set()
            names = {}
            for rule in self.data['nat_rules']:
                if rule['action'] in {'nat', 'dnat'}:
                    _, rule['name'] = self.get_transformed_name(rule['name'], descr='Имя правила NAT/DNAT')
                    if rule['name'] in names:
                        names[rule['name']] += 1
                        rule['name'] = f'{rule["name"]}-{names[rule["name"]]}'
                    else:
                        names[rule['name']] = 0
                    rule['description'] = f"Перенесено с Huawei.\n{rule['description']}"
                    rule['position'] = 'last'
                    error, source_ips = self.get_ips(rule['source_ip'], rule['name'], err=error)
                    rule['source_ip'] = source_ips
                    error, dest_ips = self.get_ips(rule['dest_ip'], rule['name'], err=error)
                    rule['dest_ip'] = dest_ips
                    error, services = self.get_services(rule['service'], rule['action'], rule['name'], err=error)
                    rule['service'] = services

                    rule.update({
                        'gateway': '',
                        'enabled': False,
                        'log': False,
                        'log_session_start': False,
                        'log_limit': True,
                        'log_limit_value': '3/h',
                        'log_limit_burst': 5,
                        'zone_in_nagate': False,
                        'zone_out_nagate': False,
                        'direction': "input",
                        'users': [],
                        'scenario_rule_id': False
                    })
                    nat_rules.add(rule['name'])
                    self.stepChanged.emit(f'BLACK|    Создано правило {rule["action"]} "{rule["name"]}".')

            json_file = os.path.join(current_path, 'config_nat_rules.json')
            with open(json_file, 'w') as fh:
                json.dump([x for x in self.data['nat_rules'] if x['name'] in nat_rules], fh, indent=4, ensure_ascii=False)

            if error:
                self.error = 1
                self.stepChanged.emit(f'ORANGE|    Конвертация прошла с ошибками. Правила NAT/DNAT выгружены в файл "{json_file}".')
            else:
                self.stepChanged.emit(f'GREEN|    Правила NAT/DNAT выгружены в файл "{json_file}".')
        else:
            self.stepChanged.emit('GRAY|    Нет правил NAT/DNAT для экспорта.')


    def convert_firewall_rules(self):
        """Конвертируем правила МЭ"""
        self.stepChanged.emit('BLUE|Конвертация правил межсетевого экрана.')

        if 'firewall_rules' in self.data and self.data['firewall_rules']:
            current_path = os.path.join(self.current_ug_path, 'NetworkPolicies', 'Firewall')
            err, msg = self.create_dir(current_path)
            if err:
                self.stepChanged.emit(f'RED|    {msg}')
                self.error = 1
                return

            error = 0
            names = {}
            for rule in self.data['firewall_rules']:
                _, rule['name'] = self.get_transformed_name(rule['name'], descr='Имя правила МЭ')
                if rule['name'] in names:
                    names[rule['name']] += 1
                    rule['name'] = f'{rule["name"]}-{names[rule["name"]]}'
                else:
                    names[rule['name']] = 0
                rule['description'] = f"Перенесено с Huawei.\n{rule['description']}"
                rule['position'] = 'last'
                rule['scenario_rule_id'] = False     # При импорте заменяется на UID или "0". 
                error, src_ips = self.get_ips(rule['src_ips'], rule['name'], iplist_name=f'{rule["name"]}_src', err=error)
                rule['src_ips'] = src_ips
                error, dst_ips = self.get_ips(rule['dst_ips'], rule['name'], iplist_name=f'{rule["name"]}_dst', err=error)
                rule['dst_ips'] = dst_ips
                error, services = self.get_services(rule['services'], 'МЭ', rule['name'], err=error)
                rule['services'] = services
                rule['apps'] = self.get_apps(rule['apps'], rule['name'])
                error, time_sets = self.get_time_restrictions(rule['time_restrictions'], rule['name'], err=error)
                rule['time_restrictions'] = time_sets

                rule.update({
                    'users': [],
                    'enabled': False,
                    'limit': True,
                    'limit_value': '3/h',
                    'limit_burst': 5,
                    'log_session_start': True,
                    'src_zones_negate': False,
                    'dst_zones_negate': False,
                    'services_negate': False,
                    'apps_negate': False,
                    'fragmented': 'ignore',
                    'send_host_icmp': '',
                })
                self.stepChanged.emit(f'BLACK|    Создано правило МЭ "{rule["name"]}".')

            json_file = os.path.join(current_path, 'config_firewall_rules.json')
            with open(json_file, 'w') as fh:
                json.dump(self.data['firewall_rules'], fh, indent=4, ensure_ascii=False)

            if error:
                self.stepChanged.emit(f'ORANGE|    Конвертация прошла с ошибками. Правила межсетевого экрана выгружены в файл "{json_file}".')
                self.error = 1
            else:
                self.stepChanged.emit(f'GREEN|    Правила межсетевого экрана выгружены в файл "{json_file}".')
        else:
            self.stepChanged.emit('GRAY|    Нет правил межсетевого экрана для экспорта.')


    def convert_bgp_routes(self):
        """Конвертируем настройки BGP в VRF по умолчанию"""
        if 'config router bgp' not in self.data:
            return

        self.stepChanged.emit('BLUE|Конвертация настроек BGP в VRF по умолчанию.')
        error = 0
        filters = []
        filter_keys = {}
        filter_keys['empty'] = []
        routemaps = []
        routemaps_keys = {}
        routemaps_keys['empty'] = []

        if 'config router prefix-list' in self.data:
            for key, value in self.data['config router prefix-list'].items():
                filter_keys[key] = []
                filter_items_permit = []
                filter_items_deny = []
                for item in value['rule'].values():
                    err, prefix = self.pack_ip_address(*item['prefix'].split())
                    if err:
                        self.stepChanged.emit(f'RED|    Error: router prefix-list "{key} - {item["prefix"]}" не конвертирован. Указан не корректный IP-адрес [prefix].')
                        error = 1
                        continue
                    if 'le' in item:
                        prefix = f'{prefix}:{item.get("ge", "")}:{item["le"]}'
                    if item.get('action', None) == 'deny':
                        filter_items_deny.append(prefix)
                    else:
                        filter_items_permit.append(prefix)
                if filter_items_permit:
                    filter_name = f'{key} (permit)'
                    filters.append({
                        'name': filter_name,
                        'description': '',
                        'action': 'permit',
                        'filter_by': 'ip',
                        'filter_items': filter_items_permit
                    })
                    filter_keys[key].append(filter_name)
                if filter_items_deny:
                    filter_name = f'{key} (deny)'
                    filters.append({
                        'name': filter_name,
                        'description': '',
                        'action': 'deny',
                        'filter_by': 'ip',
                        'filter_items': filter_items_deny
                    })
                    filter_keys[key].append(filter_name)
        if 'config router route-map' in self.data:
            for key, value in self.data['config router route-map'].items():
                routemaps_keys[key] = []
                action = None
                for item in value['rule'].values():
                    action = 'permit' if item.get('match-ip-address', None) == 'allow' else 'deny'
                if action:
                    routemaps.append({
                        'name': key,
                        'description': '',
                        'action': action,
                        'match_by': 'ip',
                        'next_hop': '',
                        'metric': 10,
                        'weight': 10,
                        'preference': 10,
                        'as_prepend': '',
                        'community': '',
                        'additive': False,
                        'match_items': []
                    })
                    routemaps_keys[key].append(key)

        bgp = self.data['config router bgp']
        if 'router-id' in bgp:
            neighbors = []
            try:
                for key, value in bgp['neighbor'].items():
                    neighbors.append({
                        'enabled': True,
                        'description': '',
                        'host': key,
                        'remote_asn': int(value['remote-as']),
                        'weight': 10,
                        'next_hop_self': False,
                        'ebgp_multihop': False,
                        'route_reflector_client': True if value.get('route-reflector-client', None) == 'enable' else False,
                        'multihop_ttl': 10,
                        'soft_reconfiguration': False,
                        'default_originate': False,
                        'send_community': False,
                        'password': False,
                        'filter_in': filter_keys[value.get('prefix-list-in', 'empty')],
                        'filter_out': filter_keys[value.get('prefix-list-out', 'empty')],
                        'routemap_in': routemaps_keys[value.get('route-map-in', 'empty')],
                        'routemap_out': routemaps_keys[value.get('route-map-out', 'empty')],
                        'allowas_in': False,
                        'allowas_in_number': 3,
                        'bfd_profile': -1
                    })
                config_network = []
                
                self.vrf['bgp'] = {
                    'enabled': False,
                    'router_id': bgp['router-id'],
                    'as_number': int(bgp['as']),
                    'multiple_path': False,
                    'redistribute': ['connected'] if bgp['redistribute connected']['status'] == 'enable' else [],
                    'networks': [func.pack_ip_address(*x['prefix'].split()) for x in bgp['network'].values()],
                    'routemaps': routemaps,
                    'filters': filters,
                    'neighbors': neighbors
                }
            except (KeyError, ValueError) as err:
                self.stepChanged.emit(f'bRED|    Произошла ошибка при экспорте настроек BGP: {err}.')
            else:
                current_path = os.path.join(self.current_ug_path, 'Network', 'VRF')
                err, msg = self.create_dir(current_path, delete='no')
                if err:
                    self.stepChanged.emit(f'RED|    {msg}')
                    self.error = 1
                    return

                json_file = os.path.join(current_path, 'config_vrf.json')
                with open(json_file, 'w') as fh:
                    json.dump([self.vrf], fh, indent=4, ensure_ascii=False)

                if error:
                    self.stepChanged.emit(f'ORANGE|    Конвертация BGP прошла с ошибками. Настройки BGP выгружены в файл "{json_file}".')
                else:
                    self.stepChanged.emit(f'GREEN|    Настройки BGP выгружены в файл "{json_file}".')
        else:
            self.stepChanged.emit('GRAY|    Нет настроек BGP для экспорта.')


    def save_application_groups(self):
        """Сохраняем группы приложений в каталог конфигурации"""
        self.stepChanged.emit('BLUE|Сохраняем группы приложений.')
        if self.application_groups:
            current_path = os.path.join(self.current_ug_path, 'Libraries', 'ApplicationGroups')
            err, msg = self.create_dir(current_path)
            if err:
                self.stepChanged.emit(f'RED|    {msg}')
                self.error = 1
                return

            json_file = os.path.join(current_path, 'config_application_groups.json')
            with open(json_file, 'w') as fh:
                json.dump(self.application_groups, fh, indent=4, ensure_ascii=False)
            self.stepChanged.emit(f'GREEN|    Группы приложений выгружены в файл "{json_file}".')
        else:
            self.stepChanged.emit('GRAY|    Нет групп приложений для экспорта.')

    def save_new_services(self):
        """Сохраняем вновь добавленные из правил сервисы в каталог конфигурации"""
        if self.new_services:
            self.stepChanged.emit('BLUE|Сохраняем сервисы, созданные в процессе обработки правил.')
            current_path = os.path.join(self.current_ug_path, 'Libraries', 'Services')
            json_file = os.path.join(current_path, 'config_services_list.json')
            err, data = self.read_json_file(json_file)
            if err == 1:
                return
            elif err in (2, 3):
                err, msg = self.create_dir(current_path)
                if err:
                    self.stepChanged.emit(f'RED|    {msg}.')
                    self.error = 1
                    return
            else:
                self.new_services.extend(data)

            with open(json_file, 'w') as fh:
                json.dump(self.new_services, fh, indent=4, ensure_ascii=False)
            self.stepChanged.emit(f'GREEN|    Дополнительные сервисы сохранены в файле "{json_file}".')

############################################# Служебные функции ###################################################
    def get_time_restrictions(self, time_sets, rule_name, err=0):
        """Проверяем что календари существуют"""
        new_timesets = []
        for item in time_sets:
            try:
                new_timesets.append(self.data['calendars'][item]['name'])
            except KeyError:
                self.stepChanged.emit(f'RED|    Error: [Правило "{rule_name}"] Не найден календарь "{item}".')
                err = 1
        return err, new_timesets


    @staticmethod
    def set_email_group(email):
        """Получить группу почтовых адресов для заданного email"""
        name, domain = email.split('@')
        email_group = {
            'name': f'{name} ({domain})',
            'description': 'Перенесено с Huawei',
            'type': 'emailgroup',
            'url': '',
            'list_type_update': 'static',
            'schedule': 'disabled',
            'attributes': {},
            'content': [{'value': email}]
        }
        return email_group


    def get_ips(self, rule_ips, rule_name, iplist_name=None, err=0):
        """
        Получить имена списков IP-адресов и URL-листов.
        Если списки не найдены, то они создаются или пропускаются, если невозможно создать."""
        new_rule_ips = []
        ip_group = []
        for item in rule_ips:
            error = 0
            if item[0] == 'ip_address':
                if item[1] in self.data['ip_lists']:
                    new_rule_ips.append(['list_id', self.data['ip_lists'][item[1]]['name']])
                else:
                    ip_group.append(item[1])
            elif item[0] == 'list_id':
                if item[1] in self.data['ip_lists']:
                    new_rule_ips.append(['list_id', self.data['ip_lists'][item[1]]['name']])
                elif item[1] in self.data['ip_lists_group']:
                    new_rule_ips.append(['list_id', self.data['ip_lists_group'][item[1]]['name']])
                else:
                    error = 1
            elif item[0] == 'urllist_id':
                if item[1] in self.data['url_list']:
                    new_rule_ips.append(['urllist_id', self.data['url_list'][item[1]]['name']])
                else:
                    error = 1
            else:
                error = 1
            if error:
                self.stepChanged.emit(f'RED|    Error: [Правило "{rule_name}"] Не найден список IP-адресов/URL "{item}".')
                err = 1
        if ip_group:
            ip_list_name = self.create_ip_list(ips=ip_group, name=iplist_name, descr='Портировано с Huawei.')
            if ip_list_name:
                new_rule_ips.append(['list_id', ip_list_name])
        return err, new_rule_ips


    def get_services(self, rule_services, rule_type, rule_name, err=0):
        """Получить список сервисов"""
        new_service_list = []
        num = 1
        for item in rule_services:
            if item[0] == 'new':
                if 'name' in item[1]:
                    group_name = item[1]['name']
                    if 'service_groups' in self.data and group_name in self.data['service_groups']:
                        new_service_list.append(['list_id', self.data['service_groups'][group_name]['name']])
                    else:
                        self.stepChanged.emit(f'RED|    Error: Не найден сервис "{group_name}" для правила "{rule_name}".')
                        err = 1
                    continue

                if item[1]['dst'] == '22' and item[1]['proto'] == 'tcp':
                    new_service_list.append(['service', 'SSH'])
                elif item[1]['dst'] == '80' and item[1]['proto'] == 'tcp':
                    new_service_list.append(['service', 'HTTP'])
                elif item[1]['dst'] == '443' and item[1]['proto'] == 'tcp':
                    new_service_list.append(['service', 'HTTPS'])
                elif item[1]['dst'] == '110' and item[1]['proto'] == 'tcp':
                    new_service_list.append(['service', 'POP3'])
                elif item[1]['dst'] == '995' and item[1]['proto'] == 'tcp':
                    new_service_list.append(['service', 'POP3S'])
                elif item[1]['dst'] == '3389' and item[1]['proto'] == 'tcp':
                    new_service_list.append(['service', 'RDP'])
                elif item[1]['dst'] == '25' and item[1]['proto'] == 'tcp':
                    new_service_list.append(['service', 'SMTP'])
                elif item[1]['dst'] == '465' and item[1]['proto'] == 'tcp':
                    new_service_list.append(['service', 'SMTPS'])
                else:
                    service = {
                        'name': f'For {rule_type} rule {rule_name}-{num}',
                        'description': f'Перенесено с Huawei.\nСоздано для правила {rule_type} "{rule_name}"',
                        'protocols': [{
                            'proto': item[1]['proto'],
                            'port': '' if item[1].get('dst', '') == '0-65535' else item[1].get('dst', ''),
                            'source_port': '' if item[1].get('src', '') == '0-65535' else item[1].get('src', ''),
                            'app_proto': '',
                            'alg': ''
                        }],
                    }
                    num += 1
                    new_service_list.append(['service', service['name']])
                    self.new_services.append(service)
                    self.stepChanged.emit(f'NOTE|    Создан сервис "{service["name"]}" для правила "{rule_name}".')
            else:
                new_service_list.append(item)

        return err, new_service_list


    def get_apps(self, rule_apps, rule_name):
        """Проверяем что приложения существуют на NGFW и создаём группу приложений для списка apps."""
        new_apps = []
        app_list = set()
        for item in rule_apps:
            if item[0] == 'app':
                try:
                    app_list.update(app_compliance[item[1]])
                except KeyError:
                    self.stepChanged.emit(f'RED|    Не найдено приложение "{item[1]}" для правила "{rule_name}". Данное приложение не существует на UG NGFW.')
            elif item[0] == 'ro_group':
                if item[1] in l7_categories:
                    new_apps.append(item)
                else:
                    try:
                        item[1] = l7_categories_compliance[item[1]]
                        new_apps.append(item)
                    except KeyError:
                        self.stepChanged.emit(f'RED|    Не найдена категория приложений "{item[1]}" для правила "{rule_name}". Данная категория не существует на UG NGFW.')
        if app_list:
            group_name = self.create_application_group(app_list, rule_name)
            new_apps.append(['group', group_name])

        return new_apps


    def create_application_group(self, apps_list, rule_name):
        """Создаём группу приложений"""
        app_group = {
            'name': f'For rule {rule_name}',
            'description': 'Перенесено с Huawei',
            'type': 'applicationgroup',
            'url': '',
            'list_type_update': 'static',
            'schedule': 'disabled',
            'attributes': {},
            'content': [{'type': 'app', 'name': x} for x in apps_list]
        }

        self.application_groups.append(app_group)
        return app_group['name']


def main(args):
    return 0

if __name__ == '__main__':
    import sys
    sys.exit(main(sys.argv))

