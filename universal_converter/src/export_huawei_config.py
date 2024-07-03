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
# Версия 1.4
#

import os, sys, json
import copy, re
import common_func as func
from PyQt6.QtCore import QThread, pyqtSignal
from applications import app_compliance, l7_categories, l7_categories_compliance
from services import trans_table, trans_filename, zone_services, ug_services


pattern = re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')

class ConvertHuaweiConfig(QThread):
    """Преобразуем файл конфигурации Huawei в формат UserGate NGFW."""
    stepChanged = pyqtSignal(str)

    def __init__(self, current_vendor_path, current_ug_path):
        super().__init__()
        self.current_vendor_path = current_vendor_path
        self.current_ug_path = current_ug_path
        self.error = 0

        self.huawei_services = set()
        self.service_groups = set()
        self.ip_lists = set()
        self.ip_lists_groups = set()
        self.url_lists = set()
        self.local_users = set()
        self.local_groups = set()
        self.time_restrictions = set()
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
        convert_config_file(self, self.current_vendor_path)
        if self.error:
            self.stepChanged.emit('iRED|Конвертация конфигурации Huawei в формат UserGate NGFW прервана.')
        else:
            json_file = os.path.join(self.current_vendor_path, 'config.json')
            err, data = func.read_json_file(self, json_file)
            if err:
                self.stepChanged.emit('iRED|Конвертация конфигурации Huawei в формат UserGate NGFW прервана.')
            else:
                convert_time_zone(self, self.current_ug_path, data)
                convert_zone(self, self.current_ug_path, data)
                convert_vlan_interfaces(self, self.current_ug_path, data)
                convert_dns_servers(self, self.current_ug_path, data)
                convert_static_routes(self, self.current_ug_path, data)
                convert_notification_profile(self, self.current_ug_path, data)
                convert_services(self, self.current_ug_path, data)
                convert_ip_lists(self, self.current_ug_path, data)
                convert_url_lists(self, self.current_ug_path, data)
                convert_time_sets(self, self.current_ug_path, data)
                convert_shapers_list(self, self.current_ug_path, data)
                convert_shaper_rules(self, self.current_ug_path, data)
                convert_nat_rules(self, self.current_ug_path, data)
                convert_firewall_rules(self, self.current_ug_path, data)

                save_application_groups(self, self.current_ug_path)
                save_new_services(self, self.current_ug_path)

                if self.error:
                    self.stepChanged.emit('iORANGE|Конвертация конфигурации Huawei в формат UserGate NGFW прошла с ошибками.')
                else:
                    self.stepChanged.emit('iGREEN|Конвертация конфигурации Huawei в формат UserGate NGFW прошла успешно.')


def convert_config_file(parent, path):
    """Преобразуем файл конфигурации Huawei в формат json."""
    parent.stepChanged.emit('BLUE|Конвертация файла конфигурации Huawei в формат json.')
    if not os.path.isdir(path):
        parent.stepChanged.emit('RED|    Не найден каталог с конфигурацией Huawei.')
        parent.error = 1
        return
    error = 0
    data = {}
    config_file = 'huawei.cfg'

    config_file = os.path.join(path, config_file)
    try:
        with open(config_file, "r") as fh:
            line = fh.readline().translate(trans_table).strip()
            if not line:
                line = fh.readline().translate(trans_table).strip()
            while line:
                if line == '#':
                    config_block = []
                    line = fh.readline().translate(trans_table).strip()
                    while line != '#':
                        x = line.split(' ')
                        if x[0] == 'return':
                            break
                        config_block.append(x)
                        line = fh.readline().translate(trans_table).strip()
                    else:
                        if config_block:
                            key, value = make_block(parent, config_block)
                            if key:
                                if key in data:
                                    if isinstance(data[key], list):
                                        data[key].extend(value)
                                    elif isinstance(data[key], dict):
                                        data[key].update(value)
                                else:
                                    data[key] = value
                else:
                    line = fh.readline().translate(trans_table).strip()
                    
    except FileNotFoundError:
        parent.stepChanged.emit(f'RED|    Не найден файл "{config_file}" в каталоге "{path}" с конфигурацией Huawei.')
        parent.error = 1
        return

    json_file = os.path.join(path, 'config.json')
    with open(json_file, 'w') as fh:
        json.dump(data, fh, indent=4, ensure_ascii=False)

    if parent.error:
        error = 1
    out_message = f'BLACK|    Конфигурация Huawei в формате json выгружена в файл "{json_file}".'
    parent.stepChanged.emit('ORANGE|    Ошибка экспорта конфигурации Huawei в формат json.' if error else out_message)

def make_block(parent, data):
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
#                'name': name.translate(trans_name),
                'name': func.get_restricted_name(name),
                'description': '',
                'content': []
            }
            parent.ip_lists.add(value['name'])
            for item in data:
                match item:
                    case ['address', _, ip, 'mask', mask]:
                        value['content'].append(func.pack_ip_address(ip, mask))
                    case ['address', _, ip, mask]:
                        value['content'].append(func.pack_ip_address(ip, mask))
                    case ['address', _, 'range', ip1, ip2]:
                        value['content'].append(f'{ip1}-{ip2}')
                    case ['description', *descr]:
                        value['description'] = ' '.join(descr)
            return 'ip_lists', [value]
        case ['ip', 'address-set', name, 'type', 'group']:
            value = {
                'name': func.get_restricted_name(name),
                'description': '',
                'content': []
            }
            parent.ip_lists_groups.add(value['name'])
            for item in data:
                match item:
                    case ['address', _, 'address-set', list_name]:
                        value['content'].append(list_name)
                    case ['description', *descr]:
                        value['description'] = ' '.join(descr)
            return 'ip_lists_group', [value]
        case ['ip', 'service-set', name, 'type', 'object', *_]:
            parent.huawei_services.add(name)
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
                    case ['description', *descr]:
                        value['description'] = ' '.join(descr)
            return 'services_lists', [value]
        case ['time-range', name]:
            value = []
            time_set = None
            for item in data:
                match item:
                    case ['time-range', name]:
                        if time_set: value.append(time_set)
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
            if time_set: value.append(time_set)
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
                        value[name]['ipv4'].append(func.pack_ip_address(ip, mask))
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
                        parent.dnat_ip[dnat_name] = ip1
            return 0, ''
        case ['nat', 'address-group', name, _]:
#            nat_mode = None
            for item in data[1:]:
                match item:
#                    case ['mode', mode]:
#                        nat_mode = mode
                    case ['section', '0', ip1, ip2]:
#                        if nat_mode == 'pat':
                        parent.snat_ip[name] = ip1
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
                    case ['ip', 'route-static', ip, mask, gateway_ip]:
                        try:
                            dest = func.pack_ip_address(ip, mask)
                        except ValueError:
                            pass
                        else:
                            if pattern.match(gateway_ip):
                                gateway = gateway_ip
                            else:
                                continue
                            routes.append({'dest': dest, 'gateway': gateway})
                    case ['ip', 'route-static', ip, mask, port_name, gateway_ip, *other]:
                        try:
                            dest = func.pack_ip_address(ip, mask)
                        except ValueError:
                            pass
                        else:
                            if pattern.match(gateway_ip):
                                gateway = gateway_ip
                            elif pattern.match(port_name):
                                gateway = port_name
                            else:
                                continue
                            routes.append({'dest': dest, 'gateway': gateway})
            return 'routes', routes
        case ['profile', 'type', 'dns-filter', 'name', *name]:
            value = {
#                'name': ' '.join(name).translate(trans_name),
                'name': func.get_restricted_name(' '.join(name)),
                'description': '',
                'content': []
            }
            parent.url_lists.add(value['name'])
            for item in data[1:]:
                match item:
                    case ['add', 'blacklist', url]:
                        value['content'].append(url)
                    case ['description', *descr]:
                        value['description'] = ' '.join(descr)
            return 'url_list', [value]
        case ['domain-set', 'name', *name]:
            value = []
            url_list = None
            for item in data:
                match item:
                    case ['domain-set', 'name', *name]:
                        if url_list: value.append(url_list)
                        url_list = {
                            'name': func.get_restricted_name(' '.join(name)),
                            'description': '',
                            'content': []
                        }
                        parent.url_lists.add(url_list['name'])
                    case ['add', 'domain', url]:
                        url_list['content'].append(url)
                    case ['description', *descr]:
                        url_list['description'] = ' '.join(descr)
            if url_list: value.append(url_list)
            return 'url_list', value
        case ['geo-location', 'user-defined', *name]:
            value = []
            ip_list = None
            for item in data:
                match item:
                    case ['geo-location', 'user-defined', *name]:
                        if ip_list: value.append(ip_list)
                        ip_list = {
                            'name': func.get_restricted_name(' '.join(name)),
                            'description': '',
                            'content': []
                        }
                        parent.ip_lists.add(ip_list['name'])
                    case ['add', 'address', 'range', ip1, ip2]:
                        if ip1 == ip2:
                            ip_list['content'].append(ip1)
                        else:
                            ip_list['content'].append(f'{ip1}-{ip2}')
                    case ['description', *descr]:
                        ip_list['description'] = ' '.join(descr)
            if ip_list: value.append(ip_list)
            return 'ip_lists', value
        case ['geo-location-set', *name]:
            value = []
            ip_list = []
            for item in data:
                match item:
                    case ['geo-location-set', *name]:
                        if ip_list and ip_list['content']:
                            value.append(ip_list)
                            parent.ip_lists.add(ip_list['name'])
                        ip_list = {
                            'name': func.get_restricted_name(' '.join(name)),
                            'description': '',
                            'content': []
                        }
                    case ['add', 'geo-location', *name]:
                        if ' '.join(name) in parent.ip_lists:
                            ip_list['content'].append({'list': ' '.join(name)})
                    case ['description', *descr]:
                        ip_list['description'] = ' '.join(descr)
            if ip_list and ip_list['content']:
                value.append(ip_list)
                parent.ip_lists.add(ip_list['name'])
            return 'ip_lists', value
        case ['security-policy']:
            value = []
            fw_rule = None
            for item in data[1:]:
                match item:
                    case ['rule', 'name', *name]:
                        if fw_rule: value.append(fw_rule)
                        fw_rule = {
                            'name': func.get_restricted_name(' '.join(name)),
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
                        fw_rule['src_ips'].append(['list_id', func.get_restricted_name(ip_list)])
                    case ['source-address-exclude', 'address-set', ip_list]:
                        fw_rule['src_ips'].append(['list_id', func.get_restricted_name(ip_list)])
                        fw_rule['src_ips_negate'] = True
                    case ['source-address-exclude', ip, 'mask', mask]:
                        fw_rule['source_ip'].append(['ip_address', func.pack_ip_address(ip, mask)])
                        fw_rule['src_ips_negate'] = True
                    case ['source-address', 'domain-set', *url_list]:
                        fw_rule['src_ips'].append(['urllist_id', func.get_restricted_name(' '.join(url_list))])
                    case ['source-address', ip, 'mask', mask]:
                        fw_rule['src_ips'].append(['ip_address', func.pack_ip_address(ip, mask)])
                    case ['source-address', 'geo-location-set', geo_ip]:
                        geo_ip = func.get_restricted_name(geo_ip)
                        if geo_ip in parent.ip_lists:
                            fw_rule['src_ips'].append(['list_id', geo_ip])
                        else:
                            fw_rule['src_ips'].append(['geoip_code', geo_ip])
                    case ['destination-address', 'address-set', ip_list]:
                        fw_rule['dst_ips'].append(['list_id', func.get_restricted_name(ip_list)])
                    case ['destination-address-exclude', 'address-set', ip_list]:
                        fw_rule['dst_ips'].append(['list_id', func.get_restricted_name(ip_list)])
                        fw_rule['dst_ips_negate'] = True
                    case ['destination-address', 'domain-set', *url_list]:
                        fw_rule['dst_ips'].append(['urllist_id', func.get_restricted_name(' '.join(url_list))])
                    case ['destination-address', ip, 'mask', mask]:
                        fw_rule['dst_ips'].append(['ip_address', func.pack_ip_address(ip, mask)])
                    case ['destination-address', 'geo-location-set', geo_ip]:
                        fw_rule['dst_ips'].append(['geoip_code', geo_ip])
                    case ['service', service_name]:
                        if service_name in ug_services:
                            fw_rule['services'].append(['service', ug_services[service_name]])
                        elif service_name in parent.huawei_services:
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
            value = {'shapers': [], 'rules': []}
            shaper = None
            rule = None
            for item in data[1:]:
                match item:
                    case ['profile', *name]:
                        if shaper: value['shapers'].append(shaper)
                        shaper = {
                            'name': func.get_restricted_name(' '.join(name)),
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
                                for shpr in value['shapers']:
                                    if shpr['name'] == rule['pool']:
                                        shpr['dscp'] = rule.pop('dscp')
                        rule = {
                            'name': func.get_restricted_name(' '.join(name)),
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
                        rule['src_ips'].append(['list_id', func.get_restricted_name(ip_list)])
                    case ['source-address', ip, 'mask', mask]:
                        rule['src_ips'].append(['ip_address', func.pack_ip_address(ip, mask)])
                    case ['destination-zone', zone_name]:
                        rule['dst_zones'].append(zone_name)
                    case ['destination-address', 'address-set', ip_list]:
                        rule['dst_ips'].append(['list_id', func.get_restricted_name(ip_list)])
                    case ['destination-address', ip, 'mask', mask]:
                        rule['dst_ips'].append(['ip_address', func.pack_ip_address(ip, mask)])
                    case ['application', 'app', app]:
                        rule['apps'].append(['app', app])
                    case ['time-range', schedule_name]:
                        rule['time_restrictions'].append(schedule_name)
                    case ['action', _, _, *profile]:
                        rule['pool'] = func.get_restricted_name(' '.join(profile))
                    case ['service', service_name]:
                        if service_name in ug_services:
                            rule['services'].append(['service', ug_services[service_name]])
                        elif service_name in parent.huawei_services:
                            rule['services'].append(['service', service_name])
                        else:
                            rule['services'].append(['new', {'name': service_name}])
                    case ['dscp', dscp_name]:
                        rule['dscp'] = dscp_table[dscp_name]
                    case ['description', *descr]:
                        rule['description'] = ' '.join(descr)
            if shaper: value['shapers'].append(shaper)
            if rule:
                value['rules'].append(rule)
                if 'dscp' in rule:
                    for shpr in value['shapers']:
                        if shpr['name'] == rule['pool']:
                            shpr['dscp'] = rule.pop('dscp')
            return 'traffic_shaping', value
        case ['nat-policy']:
            value = []
            nat_rule = None
            for item in data[1:]:
                match item:
                    case ['rule', 'name', *name]:
                        if nat_rule: value.append(nat_rule)
                        nat_rule = {
                            'name': func.get_restricted_name(' '.join(name)),
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
                        nat_rule['target_ip'] = parent.dnat_ip[group]
                        nat_rule['action'] = 'dnat'
                    case ['action', 'destination-nat', 'static', 'port-to-address', 'address-group', group, *port]:
                        nat_rule['target_ip'] = parent.dnat_ip[group]
                        nat_rule['action'] = 'dnat'
                    case ['action', 'destination-nat', 'static', 'address-to-address', 'address-group', group, *port]:
                        nat_rule['target_ip'] = parent.dnat_ip[group]
                        nat_rule['action'] = 'dnat'
                    case ['action', 'source-nat', 'easy-ip']:
                        nat_rule['action'] = 'nat'
                    case ['action', 'source-nat', 'address-group', group]:
                        nat_rule['action'] = 'nat'
                        nat_rule['target_snat'] = True
                        nat_rule['snat_target_ip'] = parent.snat_ip[group]
                    case ['source-address', 'address-set', ip_list]:
                        nat_rule['source_ip'].append(['list_id', func.get_restricted_name(ip_list)])
                    case ['source-address-exclude', 'address-set', ip_list]:
                        nat_rule['source_ip'].append(['list_id', func.get_restricted_name(ip_list)])
                        nat_rule['source_ip_negate'] = True
                    case ['source-address-exclude', ip, 'mask', mask]:
                        nat_rule['source_ip'].append(['ip_address', func.pack_ip_address(ip, mask)])
                        nat_rule['source_ip_negate'] = True
                    case ['source-address', 'domain-set', *url_list]:
                        nat_rule['src_ips'].append(['urllist_id', func.get_restricted_name(' '.join(url_list))])
                    case ['source-address', ip, 'mask', mask]:
                        nat_rule['source_ip'].append(['ip_address', func.pack_ip_address(ip, mask)])
                    case ['source-address', 'geo-location-set', geo_ip]:
                        geo_ip = func.get_restricted_name(geo_ip)
                        if geo_ip in parent.ip_lists:
                            nat_rule['source_ip'].append(['list_id', geo_ip])
                    case ['destination-address', 'address-set', ip_list]:
                        nat_rule['dest_ip'].append(['list_id', func.get_restricted_name(ip_list)])
                    case ['destination-address-exclude', 'address-set', ip_list]:
                        nat_rule['dest_ip'].append(['list_id', func.get_restricted_name(ip_list)])
                        nat_rule['dest_ip_negate'] = True
                    case ['destination-address', 'domain-set', *url_list]:
                        nat_rule['dest_ip'].append(['urllist_id', func.get_restricted_name(' '.join(url_list))])
                    case ['destination-address', ip, 'mask', mask]:
                        nat_rule['dest_ip'].append(['ip_address', func.pack_ip_address(ip, mask)])
                    case ['service', service_name]:
                        if service_name in ug_services:
                            nat_rule['service'].append(['service', ug_services[service_name]])
                        elif service_name in parent.huawei_services:
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


def convert_time_zone(parent, path, data):
    """Конвертируем часовой пояс."""
    if 'timezone' not in data:
        return

    parent.stepChanged.emit('BLUE|Конвертация часового пояса.')
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
    if (offset := data['timezone'].get('offset', None)):
        x = offset[:2]
        zone_number = x if x[0] != '0' else x[1]
        time_zone['ui_timezone'] = timezones[zone_number]

    if time_zone:
        section_path = os.path.join(path, 'UserGate')
        current_path = os.path.join(section_path, 'GeneralSettings')
        err, msg = func.create_dir(current_path)
        if err:
            parent.stepChanged.emit(f'RED|    {msg}.')
            parent.error = 1
            return

        json_file = os.path.join(current_path, 'config_settings_ui.json')
        with open(json_file, 'w') as fh:
            json.dump(time_zone, fh, indent=4, ensure_ascii=False)
        parent.stepChanged.emit(f'GREEN|    Настройка часового пояса выгружена в файл "{json_file}".')
    else:
        parent.stepChanged.emit('GRAY|    Нет настроек часового пояса для экспорта.')


def convert_dns_servers(parent, path, data):
    """Заполняем список системных DNS"""
    if 'dns_servers' not in data:
        return
    parent.stepChanged.emit('BLUE|Конвертация настроек DNS.')

    dns_servers = []
    for value in data['dns_servers']:
        dns_servers.append({'dns': value, 'is_bad': False})
        
    if dns_servers:
        section_path = os.path.join(path, 'Network')
        current_path = os.path.join(section_path, 'DNS')
        err, msg = func.create_dir(current_path, delete='no')
        if err:
            parent.stepChanged.emit(f'RED|    {msg}.')
            parent.error = 1
            return

        json_file = os.path.join(current_path, 'config_dns_servers.json')
        with open(json_file, 'w') as fh:
            json.dump(dns_servers, fh, indent=4, ensure_ascii=False)
        parent.stepChanged.emit(f'GREEN|    Настройки серверов DNS выгружены в файл "{json_file}".')
    else:
        parent.stepChanged.emit('GRAY|    Нет серверов DNS для экспорта.')


def convert_notification_profile(parent, path, data):
    """Конвертируем почтовый адрес и профиль оповещения"""
    if 'smtp_settings' not in data:
        return
    parent.stepChanged.emit('BLUE|Конвертация почтовых адресов и профиля оповещения.')
    section_path = os.path.join(path, 'Libraries')

    smtp_settings = data['smtp_settings']

    if 'smtp_server' in smtp_settings:
        current_path = os.path.join(section_path, 'NotificationProfiles')
        err, msg = func.create_dir(current_path)
        if err:
            parent.stepChanged.emit(f'RED|    {msg}.')
            parent.error = 1
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
        parent.stepChanged.emit(f'BLACK|    Профиль оповещения SMTP выгружен в файл "{json_file}".')
    else:
        parent.stepChanged.emit('GRAY|    Нет профиля оповещения для экспорта.')

    email_groups = []
    if 'sender' in smtp_settings:
        email_groups.append(set_email_group(smtp_settings['sender']))
    if 'recipient' in smtp_settings:
        email_groups.append(set_email_group(smtp_settings['recipient']))

    if email_groups:
        current_path = os.path.join(section_path, 'Emails')
        err, msg = func.create_dir(current_path)
        if err:
            parent.stepChanged.emit(f'RED|    {msg}.')
            parent.error = 1
            return

        json_file = os.path.join(current_path, 'config_email_groups.json')
        with open(json_file, 'w') as fh:
            json.dump(email_groups, fh, indent=4, ensure_ascii=False)
        parent.stepChanged.emit(f'BLACK|    Почтовые адреса выгружены в файл "{json_file}".')
    else:
        parent.stepChanged.emit('GRAY|    Нет почтовых адресов для экспорта.')

    parent.stepChanged.emit('GREEN|    Конвертация почтовых адресов и профиля оповещения завершена.')


def convert_services(parent, path, data):
    """Конвертируем сетевые сервисы."""
    parent.stepChanged.emit('BLUE|Конвертация сетевых сервисов.')
    section_path = os.path.join(path, 'Libraries')
    current_path = os.path.join(section_path, 'Services')
    err, msg = func.create_dir(current_path)
    if err:
        parent.stepChanged.emit(f'RED|    {msg}.')
        parent.error = 1
        return

    if 'services_lists' in data:
        services_proto = {'110': 'pop3', '995': 'pop3s', '25': 'smtp', '465': 'smtps'}
        for service in data['services_lists']:
            for protocol in service['protocols']:
                if 'port' not in protocol:
                    protocol['port'] = ''
                protocol['app_proto'] = ''
                protocol['alg'] = ''
                if protocol['proto'] == 'tcp':
                    protocol['proto'] = services_proto.get(protocol['port'], 'tcp')
                    protocol['app_proto'] = services_proto.get(protocol['port'], '')
                if protocol['port'] == '0-65535':
                    protocol['port'] = ''
                if protocol['source_port'] == '0-65535':
                    protocol['source_port'] = ''
    else:
        data['services_lists'] = []
    data['services_lists'].extend(func.create_ug_services())

    json_file = os.path.join(current_path, 'config_services_list.json')
    with open(json_file, 'w') as fh:
        json.dump(data['services_lists'], fh, indent=4, ensure_ascii=False)
    parent.stepChanged.emit(f'BLACK|    Сервисы выгружены в файл "{json_file}".')


def convert_ip_lists(parent, path, data):
    """Конвертируем списки IP-адресов"""
    parent.stepChanged.emit('BLUE|Конвертация списков IP-адресов.')
    section_path = os.path.join(path, 'Libraries')
    current_path = os.path.join(section_path, 'IPAddresses')
    err, msg = func.create_dir(current_path)
    if err:
        parent.stepChanged.emit(f'RED|    {msg}.')
        parent.error = 1
        return

    indicator = [1, 1, 1]
    if 'ip_lists' in data:
        for ip_list in data['ip_lists']:
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

            json_file = os.path.join(current_path, f'{ip_list["name"].strip().translate(trans_filename)}.json')
            with open(json_file, 'w') as fh:
                json.dump(ip_list, fh, indent=4, ensure_ascii=False)
            parent.stepChanged.emit(f'BLACK|       Список IP-адресов "{ip_list["name"]}" выгружен в файл "{json_file}".')
    else:
        indicator.pop()

    if 'ip_lists_group' in data:
        for ip_list in data['ip_lists_group']:
            ip_list['type'] = 'network'
            ip_list['url'] = ''
            ip_list['list_type_update'] = 'static'
            ip_list['schedule'] = 'disabled'
            ip_list['attributes'] = {'threat_level': 3}
            ip_list['content'] = [{'list': value} for value in ip_list['content']]

            json_file = os.path.join(current_path, f'{ip_list["name"].strip().translate(trans_filename)}.json')
            with open(json_file, 'w') as fh:
                json.dump(ip_list, fh, indent=4, ensure_ascii=False)
            parent.stepChanged.emit(f'BLACK|       Список IP-адресов "{ip_list["name"]}" выгружен в файл "{json_file}".')
    else:
        indicator.pop()

    if 'firewall' in data:
        ip_list = {
            'name': '',
            'description': '',
            'type': 'network',
            'url': '',
            'list_type_update': 'static',
            'schedule': 'disabled',
            'attributes': {'threat_level': 3},
        }
        for key1, val1 in data['firewall'].items():
            for key2, val2 in val1.items():
                ip_list['name'] = f'firewall_{key1}_{key2}'
                ip_list['content'] = [{'value': value} for value in val2 if '.' in value]

                json_file = os.path.join(current_path, f'{ip_list["name"].strip().translate(trans_filename)}.json')
                with open(json_file, 'w') as fh:
                    json.dump(ip_list, fh, indent=4, ensure_ascii=False)
                parent.stepChanged.emit(f'BLACK|       Список IP-адресов "{ip_list["name"]}" выгружен в файл "{json_file}".')
    else:
        indicator.pop()

    out_message = 'GRAY|    Нет списков IP-адресов для экспорта.'
    parent.stepChanged.emit(f'GREEN|    Списки IP-адресов выгружены в каталог "{current_path}".' if indicator else out_message)


def convert_url_lists(parent, path, data):
    """Конвертируем списки URL"""
    parent.stepChanged.emit('BLUE|Конвертация списков URL.')

    if 'url_list' in data:
        section_path = os.path.join(path, 'Libraries')
        current_path = os.path.join(section_path, 'URLLists')
        err, msg = func.create_dir(current_path)
        if err:
            parent.stepChanged.emit(f'RED|    {msg}.')
            parent.error = 1
            return

        for url_list in data['url_list']:
            url_list['type'] = 'url'
            url_list['url'] = ''
            url_list['list_type_update'] = 'static'
            url_list['schedule'] = 'disabled'
            url_list['attributes'] = {'list_compile_type': 'case_insensitive'}
            url_list['content'] = [{'value': value} for value in url_list['content']]

            json_file = os.path.join(current_path, f'{url_list["name"].strip().translate(trans_filename)}.json')
            with open(json_file, 'w') as fh:
                json.dump(url_list, fh, indent=4, ensure_ascii=False)
            parent.stepChanged.emit(f'BLACK|       Список URL "{url_list["name"]}" выгружен в файл "{json_file}".')
        parent.stepChanged.emit(f'GREEN|    Списки URL выгружены в каталог "{current_path}".')
    else:
        parent.stepChanged.emit('GRAY|    Нет списков URL для экспорта.')


def convert_time_sets(parent, path, data):
    """Конвертируем time set (календари)"""
    parent.stepChanged.emit('BLUE|Конвертация календарей.')

    if 'calendars' in data:
        section_path = os.path.join(path, 'Libraries')
        current_path = os.path.join(section_path, 'TimeSets')
        err, msg = func.create_dir(current_path)
        if err:
            parent.stepChanged.emit(f'RED|    {msg}.')
            parent.error = 1
            return

        for cal in data['calendars']:
            cal['description'] = ''
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
            parent.time_restrictions.add(cal['name'])

        json_file = os.path.join(current_path, 'config_calendars.json')
        with open(json_file, 'w') as fh:
            json.dump(data['calendars'], fh, indent=4, ensure_ascii=False)
        parent.stepChanged.emit(f'GREEN|    Список календарей выгружен в файл "{json_file}".')
    else:
        parent.stepChanged.emit('GRAY|    Нет календарей для экспорта.')


def convert_vlan_interfaces(parent, path, data):
    """Конвертируем интерфейсы VLAN."""
    parent.stepChanged.emit('BLUE|Конвертация интерфейсов VLAN.')

    if 'ifaces' in data:
        section_path = os.path.join(path, 'Network')
        current_path = os.path.join(section_path, 'Interfaces')
        err, msg = func.create_dir(current_path)
        if err:
            parent.stepChanged.emit(f'RED|    {msg}.')
            parent.error = 1
            return

        for key, iface in data['ifaces'].items():
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
            json.dump(list(data['ifaces'].values()), fh, indent=4, ensure_ascii=False)
        parent.stepChanged.emit(f'BLACK|    Интерфейсы VLAN выгружены в файл "{json_file}".')

    else:
        parent.stepChanged.emit('GRAY|    Нет интерфейсов VLAN для экспорта.')
    

def convert_zone(parent, path, data):
    """Конвертируем зоны"""
    parent.stepChanged.emit('BLUE|Конвертация Зон.')

    if 'zones' in data:
        section_path = os.path.join(path, 'Network')
        current_path = os.path.join(section_path, 'Zones')
        err, msg = func.create_dir(current_path)
        if err:
            parent.stepChanged.emit(f'RED|    {msg}.')
            parent.error = 1
            return

        for zone in data['zones']:
            if zone['interface']:
                zone['description'] = f'{zone["description"]} - Интерфейс {zone["interface"]} на Huawei.'
            zone.pop('interface', None)
            zone["dos_profiles"] = [
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
            json.dump(data['zones'], fh, indent=4, ensure_ascii=False)
        parent.stepChanged.emit(f'BLACK|    Настройки зон выгружены в файл "{json_file}".')

    else:
        parent.stepChanged.emit('GRAY|    Нет зон для экспорта.')


def convert_static_routes(parent, path, data):
    """Конвертируем статические маршруты в VRF по умолчанию"""
    parent.stepChanged.emit('BLUE|Конвертация статических маршрутов в VRF по умолчанию.')

    if 'routes' in data:
        section_path = os.path.join(path, 'Network')
        current_path = os.path.join(section_path, 'VRF')
        err, msg = func.create_dir(current_path)
        if err:
            parent.stepChanged.emit(f'RED|    {msg}.')
            parent.error = 1
            return

        routes_list = []
        gateways_list = []
        for route in data['routes']:
            ip, mask = route['dest'].split('/')
            if not int(mask):
                gateways_list.append({
                    'name': route['gateway'],
                    'enabled': False,
                    'description': 'Перенесено с Huawei.',
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
            route['description'] = ''
            route['ifname'] = 'undefined'
            route['kind'] = 'unicast'
            route['metric'] = 0
            routes_list.append(route)
        parent.vrf['routes'] = routes_list

        if gateways_list:
            gateway_path = os.path.join(section_path, 'Gateways')
            err, msg = func.create_dir(gateway_path)
            if err:
                parent.stepChanged.emit(f'RED|    {msg}.')
                parent.error = 1
            else:
                json_file = os.path.join(gateway_path, 'config_gateways.json')
                with open(json_file, 'w') as fh:
                    json.dump(gateways_list, fh, indent=4, ensure_ascii=False)
                parent.stepChanged.emit(f'GREEN|    Список шлюзов выгружен в файл "{json_file}".')
        else:
            parent.stepChanged.emit('GRAY|    Нет шлюзов для экспорта.')

        json_file = os.path.join(current_path, 'config_vrf.json')
        with open(json_file, 'w') as fh:
            json.dump([parent.vrf], fh, indent=4, ensure_ascii=False)
        parent.stepChanged.emit(f'GREEN|    Статические маршруты выгружены в файл "{json_file}".')
    else:
        parent.stepChanged.emit('GRAY|    Нет статических маршрутов для экспорта.')


def convert_shapers_list(parent, path, data):
    """Конвертируем полосы пропускания"""
    parent.stepChanged.emit('BLUE|Конвертация полос пропускания.')

    if 'traffic_shaping' in data:
        if data['traffic_shaping']['shapers']:
            section_path = os.path.join(path, 'Libraries')
            current_path = os.path.join(section_path, 'BandwidthPools')
            err, msg = func.create_dir(current_path)
            if err:
                parent.stepChanged.emit(f'RED|    {msg}.')
                parent.error = 1
                return

            for shaper in data['traffic_shaping']['shapers']:
                shaper['description'] = ''

            json_file = os.path.join(current_path, 'config_shaper_list.json')
            with open(json_file, 'w') as fh:
                json.dump(data['traffic_shaping']['shapers'], fh, indent=4, ensure_ascii=False)
            parent.stepChanged.emit(f'GREEN|    Полосы пропускания выгружены в файл "{json_file}".')
        else:
            parent.stepChanged.emit('GRAY|    Нет полос пропускания для экспорта.')
    else:
        parent.stepChanged.emit('GRAY|    Нет полос пропускания для экспорта.')
        

def convert_shaper_rules(parent, path, data):
    """Конвертируем правила пропускной способности"""
    parent.stepChanged.emit('BLUE|Конвертация правил пропускной способности.')

    if 'traffic_shaping' in data:
        if data['traffic_shaping']['rules']:
            section_path = os.path.join(path, 'NetworkPolicies')
            current_path = os.path.join(section_path, 'TrafficShaping')
            err, msg = func.create_dir(current_path)
            if err:
                parent.stepChanged.emit(f'RED|    {msg}.')
                parent.error = 1
                return

            shaping_rules = []
            names = {}
            for rule in data['traffic_shaping']['rules']:
                if not rule['pool']:
                    parent.stepChanged.emit(f'bRED|    В правиле пропускной способности "{rule["name"]}" не указана полоса пропускиния. Данное правило не конвертируется.')
                    continue
                if rule['name'] in names:
                    names[rule['name']] += 1
                    rule['name'] = f'{rule["name"]}-{names[rule["name"]]}'
                else:
                    names[rule['name']] = 0
                rule.pop('dscp', None)
                rule['scenario_rule_id'] = False
                rule['src_ips'] = get_ips(parent, path, rule['src_ips'], rule['name'])
                rule['dst_ips'] = get_ips(parent, path, rule['dst_ips'], rule['name'])
                rule['users'] = []
                rule['apps'] = get_apps(parent, rule['apps'], rule['name'])
                rule['enabled'] = True
                rule['time_restrictions'] = func.get_time_restrictions(parent, rule['time_restrictions'], rule['name'])
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
                shaping_rules.append(copy.deepcopy(rule))

            json_file = os.path.join(current_path, 'config_shaper_rules.json')
            with open(json_file, 'w') as fh:
                json.dump(shaping_rules, fh, indent=4, ensure_ascii=False)
            parent.stepChanged.emit(f'GREEN|    Правила пропускной способности выгружены в файл "{json_file}".')
        else:
            parent.stepChanged.emit('GRAY|    Нет правил пропускной способности для экспорта.')
    else:
        parent.stepChanged.emit('GRAY|    Нет правил пропускной способности для экспорта.')

def convert_nat_rules(parent, path, data):
    """Конвертируем правила NAT/DNAT"""
    parent.stepChanged.emit('BLUE|Конвертация правил NAT/DNAT.')

    if 'nat_rules' in data and data['nat_rules']:
        section_path = os.path.join(path, 'NetworkPolicies')
        current_path = os.path.join(section_path, 'NATandRouting')
        err, msg = func.create_dir(current_path)
        if err:
            parent.stepChanged.emit(f'RED|    {msg}.')
            parent.error = 1
            return

        nat_rules = []
        names = {}
        for rule in data['nat_rules']:
            if rule['action'] in {'nat', 'dnat'}:
                if rule['name'] in names:
                    names[rule['name']] += 1
                    rule['name'] = f'{rule["name"]}-{names[rule["name"]]}'
                else:
                    names[rule['name']] = 0
                rule['position'] = 'last'
                rule['source_ip'] = get_ips(parent, path, rule['source_ip'], rule['name'])
                rule['dest_ip'] = get_ips(parent, path, rule['dest_ip'], rule['name'])
                rule['service'] = get_services(parent, rule['service'], rule['action'], rule['name'])

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
                nat_rules.append(copy.deepcopy(rule))
                parent.stepChanged.emit(f'BLACK|    Создано правило {rule["action"]} "{rule["name"]}".')

        json_file = os.path.join(current_path, 'config_nat_rules.json')
        with open(json_file, 'w') as fh:
            json.dump(nat_rules, fh, indent=4, ensure_ascii=False)
        parent.stepChanged.emit(f'GREEN|    Павила NAT/DNAT выгружены в файл "{json_file}".')
    else:
        parent.stepChanged.emit('GRAY|    Нет правил NAT/DNAT для экспорта.')


def convert_firewall_rules(parent, path, data):
    """Конвертируем правила МЭ"""
    parent.stepChanged.emit('BLUE|Конвертация правил межсетевого экрана.')

    if 'firewall_rules' in data and data['firewall_rules']:
        section_path = os.path.join(path, 'NetworkPolicies')
        current_path = os.path.join(section_path, 'Firewall')
        err, msg = func.create_dir(current_path)
        if err:
            parent.stepChanged.emit(f'RED|    {msg}.')
            parent.error = 1
            return

        names = {}
        for rule in data['firewall_rules']:
            if rule['name'] in names:
                names[rule['name']] += 1
                rule['name'] = f'{rule["name"]}-{names[rule["name"]]}'
            else:
                names[rule['name']] = 0
            rule['position'] = 'last'
            rule['scenario_rule_id'] = False     # При импорте заменяется на UID или "0". 
            rule['src_ips'] = get_ips(parent, path, rule['src_ips'], rule['name'], iplist_name=f'{rule["name"]}_src')
            rule['dst_ips'] = get_ips(parent, path, rule['dst_ips'], rule['name'], iplist_name=f'{rule["name"]}_dst')
            rule['services'] = get_services(parent, rule['services'], 'МЭ', rule['name'])
            rule['apps'] = get_apps(parent, rule['apps'], rule['name'])
            rule['time_restrictions'] = func.get_time_restrictions(parent, rule['time_restrictions'], rule['name'])

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
            parent.stepChanged.emit(f'BLACK|    Создано правило МЭ "{rule["name"]}".')

        json_file = os.path.join(current_path, 'config_firewall_rules.json')
        with open(json_file, 'w') as fh:
            json.dump(data['firewall_rules'], fh, indent=4, ensure_ascii=False)
        parent.stepChanged.emit(f'GREEN|    Павила межсетевого экрана выгружены в файл "{json_file}".')
    else:
        parent.stepChanged.emit('GRAY|    Нет правил межсетевого экрана для экспорта.')


#def convert_ntp_settings(parent, path, ntp_info):
#    """Конвертируем настройки NTP"""
#    parent.stepChanged.emit('BLUE|Конвертация настроек NTP.')
#    section_path = os.path.join(path, 'UserGate')
#    current_path = os.path.join(section_path, 'GeneralSettings')
#    err, msg = func.create_dir(current_path, delete='no')
#    if err:
#        parent.stepChanged.emit(f'RED|    {msg}.')
#        parent.error = 1
#        return
#
#    if ntp_info and ntp_info.get('ntpserver', None):
#        ntp_server = {
#            'ntp_servers': [],
#            'ntp_enabled': True,
#            'ntp_synced': True if ntp_info['ntpsync'] == 'enable' else False
#        }
#        for i, value in ntp_info['ntpserver'].items():
#            ntp_server['ntp_servers'].append(value['server'])
#            if int(i) == 2:
#                break
#        if ntp_server['ntp_servers']:
#            json_file = os.path.join(current_path, 'config_ntp.json')
#            with open(json_file, 'w') as fh:
#                json.dump(ntp_server, fh, indent=4, ensure_ascii=False)
#            parent.stepChanged.emit(f'BLACK|    Настройки NTP выгружены в файл "{json_file}".')
#        else:
#            parent.stepChanged.emit('GRAY|    Нет серверов NTP для экспорта.')
#    else:
#        parent.stepChanged.emit('GRAY|    Нет серверов NTP для экспорта.')


def convert_bgp_routes(parent, path, data):
    """Конвертируем настройки BGP в VRF по умолчанию"""
    parent.stepChanged.emit('BLUE|Конвертация настроек BGP в VRF по умолчанию.')
    section_path = os.path.join(path, 'Network')
    current_path = os.path.join(section_path, 'VRF')
    err, msg = func.create_dir(current_path)
    if err:
        parent.stepChanged.emit(f'RED|    {msg}.')
        parent.error = 1
        return

    filters = []
    filter_keys = {}
    filter_keys['empty'] = []
    routemaps = []
    routemaps_keys = {}
    routemaps_keys['empty'] = []
    if 'config router prefix-list' in data:
        for key, value in data['config router prefix-list'].items():
            filter_keys[key] = []
            filter_items_permit = []
            filter_items_deny = []
            for item in value['rule'].values():
                prefix = func.pack_ip_address(*item['prefix'].split())
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
    if 'config router route-map' in data:
        for key, value in data['config router route-map'].items():
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

    bgp = data['config router bgp']
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
            parent.vrf['bgp'] = {
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
            parent.stepChanged.emit(f'bRED|    Произошла ошибка при экспорте настроек BGP: {err}.')
        else:
            json_file = os.path.join(current_path, 'config_vrf.json')
            with open(json_file, 'w') as fh:
                json.dump([parent.vrf], fh, indent=4, ensure_ascii=False)
            parent.stepChanged.emit(f'GREEN|    Настройки BGP выгружены в файл "{json_file}".')
    else:
        parent.stepChanged.emit('GRAY|    Нет настроек BGP для экспорта.')


def save_application_groups(parent, path):
    """Сохраняем группы приложений в каталог конфигурации"""
    parent.stepChanged.emit('BLUE|Сохраняем группы приложений.')
    if parent.application_groups:
        section_path = os.path.join(path, 'Libraries')
        current_path = os.path.join(section_path, 'ApplicationGroups')
        err, msg = func.create_dir(current_path)
        if err:
            parent.stepChanged.emit(f'RED|    {msg}.')
            parent.error = 1
            return

        json_file = os.path.join(current_path, 'config_application_groups.json')
        with open(json_file, 'w') as fh:
            json.dump(parent.application_groups, fh, indent=4, ensure_ascii=False)
        parent.stepChanged.emit(f'GREEN|    Группы приложений выгружены в файл "{json_file}".')
    else:
        parent.stepChanged.emit('GRAY|    Нет групп приложений для экспорта.')

def save_new_services(parent, path):
    """Сохраняем вновь добавленные из правил сервисы в каталог конфигурации"""
    if parent.new_services:
        parent.stepChanged.emit('BLUE|Сохраняем сервисы, созданные в процессе обработки правил.')
        section_path = os.path.join(path, 'Libraries')
        current_path = os.path.join(section_path, 'Services')
        json_file = os.path.join(current_path, 'config_services_list.json')
        err, data = func.read_json_file(parent, json_file)
        if err == 1:
            return
        elif err in (2, 3):
            err, msg = func.create_dir(current_path)
            if err:
                parent.stepChanged.emit(f'RED|    {msg}.')
                parent.error = 1
                return
        else:
            parent.new_services.extend(data)

        with open(json_file, 'w') as fh:
            json.dump(parent.new_services, fh, indent=4, ensure_ascii=False)
        parent.stepChanged.emit(f'GREEN|    Дополнительные сервисы сохранены в файле "{json_file}".')

############################################# Служебные функции ###################################################
def convert_any_service(proto, name):
    """Конвертируем objects не имеющие портов в список сервисов"""
    service = {
        'name': name,
        'description': f'{name} packet',
        'protocols': [
            {
                'proto': proto,
                'port': '',
                'app_proto': '',
                'source_port': '',
                'alg': ''
            }
        ]
    }
    return service

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

def get_ips(parent, path, rule_ips, rule_name, iplist_name=None):
    """
    Получить имена списков IP-адресов и URL-листов.
    Если списки не найдены, то они создаются или пропускаются, если невозможно создать."""
    new_rule_ips = []
    ip_group = []
    for item in rule_ips:
        if item[0] == 'ip_address':
            if item[1] in parent.ip_lists:
                new_rule_ips.append(['list_id', item[1]])
            else:
                ip_group.append(item[1])
        elif item[0] == 'list_id':
            if item[1] in parent.ip_lists or item[1] in parent.ip_lists_groups:
                new_rule_ips.append(item)
        elif item[0] == 'urllist_id':
            if item[1] in parent.url_lists:
                new_rule_ips.append(item)
        else:
            parent.stepChanged.emit(f'bRED|    Error! Не найден список IP-адресов/URL "{item}" для правила "{rule_name}".')
    if ip_group:
        ip_list_name = func.create_ip_list(parent, path, ips=ip_group, name=iplist_name)
        if ip_list_name:
            new_rule_ips.append(['list_id', ip_list_name])

    return new_rule_ips

def get_services(parent, rule_services, rule_type, rule_name):
    """Получить список сервисов"""
    new_service_list = []
    num = 1
    for item in rule_services:
        if item[0] == 'new':
            if 'name' in item[1]:
                parent.stepChanged.emit(f'bRED|    Error! Не найден сервис "{item[1]["name"]}" для правила "{rule_name}".')
                continue
            service = {
                'name': f'For {rule_type} rule {rule_name}-{num}',
                'description': f'Создано для правила {rule_type} "{rule_name}"',
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
            parent.new_services.append(service)
            parent.stepChanged.emit(f'NOTE|    Создан сервис "{service["name"]}" для правила "{rule_name}".')
        else:
            new_service_list.append(item)

    return new_service_list

def get_apps(parent, rule_apps, rule_name):
    """Проверяем что приложения существуют на NGFW и создаём группу приложений для списка apps."""
    new_apps = []
    app_list = set()
    for item in rule_apps:
        if item[0] == 'app':
            try:
                app_list.update(app_compliance[item[1]])
            except KeyError:
                parent.stepChanged.emit(f'bRED|    Не найдено приложение "{item[1]}" для правила "{rule_name}". Данное приложение не существует на UG NGFW.')
        elif item[0] == 'ro_group':
            if item[1] in l7_categories:
                new_apps.append(item)
            else:
                try:
                    item[1] = l7_categories_compliance[item[1]]
                    new_apps.append(item)
                except KeyError:
                    parent.stepChanged.emit(f'bRED|    Не найдена категория приложений "{item[1]}" для правила "{rule_name}". Данная категория не существует на UG NGFW.')
    if app_list:
        group_name = create_application_group(parent, app_list, rule_name)
        new_apps.append(['group', group_name])

    return new_apps

def create_application_group(parent, apps_list, rule_name):
    """Создаём группу приложений"""
    app_group = {
        'name': f'For rule {rule_name}',
        'description': '',
        'type': 'applicationgroup',
        'url': '',
        'list_type_update': 'static',
        'schedule': 'disabled',
        'attributes': {},
        'content': [{'type': 'app', 'name': x} for x in apps_list]
    }

    parent.application_groups.append(app_group)
    return app_group['name']

def get_users_and_groups(parent, users, rule_name):
    """Получить имена групп и пользователей."""
    new_users_list = []
    for item in users.split():
        if item in parent.local_users:
            new_users_list.append(['user', item])
        elif item in parent.local_groups:
            new_users_list.append(['group', item])
        else:
            parent.stepChanged.emit(f'bRED|    Error! Не найден локальный пользователь/группа "{item}" для правила "{rule_name}".')
    return new_users_list


def main(args):
    return 0

if __name__ == '__main__':
    import sys
    sys.exit(main(sys.argv))

