#!/usr/bin/python3
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
#---------------------------------------------------------------------------------------------------------
# Модуль предназначен для выгрузки конфигурации CheckPoint версии gaia 77.30 в формат json NGFW UserGate.
# Версия 1.0  26.05.2025
#

import os, sys, json, shlex
from PyQt6.QtCore import QThread, pyqtSignal
from common_classes import MyConv
from services import ip_proto, network_proto, ug_services, ServicePorts, service_ports


class ConvertOldCheckPointConfig(QThread, MyConv):
    """Преобразуем конфигурацию CheckPoint в формат UserGate NGFW."""
    stepChanged = pyqtSignal(str)
    
    def __init__(self, current_vendor_path, current_ug_path):
        super().__init__()
        self.current_vendor_path = current_vendor_path
        self.current_ug_path = current_ug_path
        self.ip_lists = {}
        self.ngfw_ip_lists = set()
        self.services = {}
        self.ngfw_services = {}
        self.ngfw_services_groups = set()
        self.icmp = set()
        self.icmpv6 = set()
        self.fw_rules = []
        self.nat_rules = []
        self.error = 0

    def run(self):
        self.stepChanged.emit(f'GREEN|{"Конвертация конфигурации CheckPoint (версии 77.30) в формат UserGate NGFW.":>110}')
        self.stepChanged.emit(f'ORANGE|{"="*110}')

        self.convert_config_files(self.current_vendor_path)
        if self.error:
            self.stepChanged.emit('iORANGE|Конфигурация CheckPoint не конвертирована.\n')
        else:
            self.convert_ip_lists()
            self.convert_gateways()
            self.convert_routes()
            self.convert_services()
            self.convert_service_groups()
#            self.convert_time_restrictions()
            self.convert_firewall_rules()

            if self.error:
                self.stepChanged.emit('iORANGE|Конвертация конфигурации CheckPoint в формат UserGate NGFW прошла с ошибками.\n')
            else:
                self.stepChanged.emit('iGREEN|Конвертация конфигурации CheckPoint в формат UserGate NGFW прошла успешно.\n')


    @staticmethod
    def make_iplist_block(string):
        """Преобразование network object в json"""
        netobj = {
            'addr_type_indication': '',
            'comments': '',
            'ipaddr': '',
            'netmask': '',
            'ipaddr_first': '',
            'ipaddr_last': '',
            'host': '',
            'members': [],
            'type': ''
        }

        s = shlex.shlex(string, posix=True, punctuation_chars=False)
        s.whitespace_split=True
        s.whitespace=['(', ')', '\t', '\r', '\n', ' ']
        obj_list = list(s)
        for i, item in enumerate(obj_list):
            if item[1:] in netobj:
                netobj[item[1:]] = obj_list[i+1] if not obj_list[i+1].startswith(':') else ''
            elif item == 'ReferenceObject':
                for x in range(i+1, i+6):
                    if obj_list[x] == ':Name':
                        netobj['members'].append(obj_list[x+1])
                        break
        if netobj['type'] != 'group':
            netobj['members'].clear()
        if netobj['type'] in {'cluster_member', 'gateway_cluster', 'host'}:
            netobj['netmask'] = ''
        return netobj


    @staticmethod
    def make_service_block(string):
        """Преобразование service object в json"""
        netobj = {
            'comments': '',
            'port': '',
            'src_port': '',
            'protocol': '',
            'members': [],
            'exp': '',
            'type': ''
        }
        s = shlex.shlex(string, posix=True, punctuation_chars=False)
        s.whitespace_split=True
        s.whitespace=['(', ')', '\t', '\r', '\n', ' ']
        obj_list = list(s)
        for i, item in enumerate(obj_list):
            if item[1:] in netobj:
                netobj[item[1:]] = obj_list[i+1] if not obj_list[i+1].startswith(':') else ''
            elif item == 'ReferenceObject':
                for x in range(i+1, i+6):
                    if obj_list[x] == ':Name':
                        netobj['members'].append(obj_list[x+1])
                        break
        netobj['type'] = netobj['type'].lower()

        if netobj['type'] != 'group':
            netobj['members'].clear()

        if netobj['type'][:4] in ('tcp_', 'udp_'):
            netobj['type'] = netobj['type'][:3]

        if not netobj['port'] and netobj['type'] == 'other' and netobj['exp'].startswith('dport='):
            port = netobj['exp'].split(',')[0].split('=')[1]
            netobj['port'] = port
        netobj.pop('exp', None)

        if netobj['port'].startswith('>'):
            netobj['port'] = f'{int(netobj["port"][1:])+1}-65535'

        if netobj['protocol']:
            try:
                netobj['protocol'] = ip_proto[netobj['protocol']]
            except KeyError:
                netobj['protocol'] = ''
            if netobj['protocol'] not in network_proto:
                netobj['protocol'] = ''
            if netobj['protocol'] == 'icmp':
                netobj['type'] = 'icmp'
        return netobj


    @staticmethod
    def make_rule_admininfo(string):
        """Определяем ClassName для правила МЭ"""
        s = shlex.shlex(string, posix=True, punctuation_chars=False)
        s.whitespace_split=True
        s.whitespace=['(', ')', '\t', '\r', '\n', ' ']
        obj_list = list(s)
        for i, item in enumerate(obj_list):
            if item == ':ClassName':
                return obj_list[i+1]
        return None


    @staticmethod
    def make_rule_str(string):
        s = shlex.shlex(string, posix=True, punctuation_chars=False)
        s.whitespace_split=True
        s.whitespace=[':', '(', ')', '\t', '\r', '\n', ' ']
        try:
            return list(s)[1]
        except IndexError:
            return ''


    @staticmethod
    def make_rule_obj(string):
        s = shlex.shlex(string, posix=True, punctuation_chars=False)
        s.whitespace_split=True
        s.whitespace=['(', ')', '\t', '\r', '\n', ' ']
        obj_list = list(s)
        members = []
        for i, item in enumerate(obj_list):
            if item == 'ReferenceObject':
                for x in range(i+1, i+6):
                    if obj_list[x] == ':Name':
                        members.append(obj_list[x+1])
                        break
        return members


    def convert_config_files(self, path):
        """Конвертируем файлы конфигурации: 'objects_5.0.C' и 'rulebases_5_0.fws' в json"""
        self.stepChanged.emit('BLUE|Конвертация конфигурации CheckPoint в формат json.')
        if not os.path.isdir(path):
            self.stepChanged.emit('RED|    Не найден каталог с конфигурацией CheckPoint.')
            self.error = 1
            return

        config_path = os.path.join(path, 'objects_5_0.C')
        if not os.path.exists(config_path):
            self.stepChanged.emit(f'RED|    Не найден файл "{config_path}" с конфигурацией CheckPoint.')
            self.error = 1
            return

        with open(config_path, 'r', encoding='latin-1') as fh:
            line = fh.readline().rstrip('\n')
            while line:
                match line:
                    case '\t:network_objects (':
                        while line != '\t)':
                            if line.startswith('\t\t: ('):
                                _, key = line.split('(')
                                line = fh.readline().rstrip('\n')
                                obj_str = ''
                                while line != '\t\t)':
                                    obj_str = f'{obj_str} {line}'
                                    line = fh.readline().rstrip('\n')
                                self.ip_lists[key] = self.make_iplist_block(obj_str)
                            line = fh.readline().rstrip('\n')
                    case '\t:services (':
                        while line != '\t)':
                            if line.startswith('\t\t: ('):
                                _, key = line.split('(')
                                line = fh.readline().rstrip('\n')
                                obj_str = ''
                                while line != '\t\t)':
                                    obj_str = f'{obj_str} {line}'
                                    line = fh.readline().rstrip('\n')
                                self.services[key] = self.make_service_block(obj_str)
                            line = fh.readline().rstrip('\n')
                line = fh.readline().rstrip('\n')

#        json_file = os.path.join(path, 'network_objects.json')
#        with open(json_file, 'w') as fh:
#            json.dump(self.ip_lists, fh, indent=4, ensure_ascii=False)

#        json_file = os.path.join(path, 'service_objects.json')
#        with open(json_file, 'w') as fh:
#            json.dump(self.services, fh, indent=4, ensure_ascii=False)

        config_path = os.path.join(path, 'rulebases_5_0.fws')
        if not os.path.exists(config_path):
            self.stepChanged.emit(f'RED|    Не найден файл "{config_path}" с конфигурацией CheckPoint.')
            self.error = 1
            return

        rule_tag = ''
        with open(config_path, 'r', encoding='latin-1') as fh:
            line = fh.readline().rstrip('\n')
            while line:
                match line:
                    case '\t\t:rule (':
                        rule = {
                            'name': '',
                            'action': '',
                            'enabled': False,
                            'description': 'Портировано с CheckPoint',
                            'src_ips': [],
                            'dst_ips': [],
                            'services': [],
                            'time_restrictions': [],
                            'log': [],
                            'tags': []
                        }
                        while line != '\t\t)':
                            match line:
                                case '\t\t\t:AdminInfo (':
                                    obj_str = ''
                                    while line != '\t\t\t)':
                                        obj_str = f'{obj_str} {line}'
                                        line = fh.readline().rstrip('\n')
                                    if self.make_rule_admininfo(obj_str) == 'security_header_rule':
                                        while line != '\t\t)':
                                            if line.startswith('\t\t\t:header_text'):
                                                rule_tag = self.make_rule_str(line)
                                            line = fh.readline().rstrip('\n')
                                case '\t\t\t:action (':
                                    obj_str = ''
                                    while line != '\t\t\t)':
                                        obj_str = f'{obj_str} {line}'
                                        line = fh.readline().rstrip('\n')
                                    rule['action'] = self.make_rule_str(obj_str)
                                case '\t\t\t:time (':
                                    obj_str = ''
                                    while line != '\t\t\t)':
                                        obj_str = f'{obj_str} {line}'
                                        line = fh.readline().rstrip('\n')
                                    rule['time_restrictions'] = self.make_rule_obj(obj_str)
                                case '\t\t\t:track (':
                                    obj_str = ''
                                    while line != '\t\t\t)':
                                        obj_str = f'{obj_str} {line}'
                                        line = fh.readline().rstrip('\n')
                                    rule['log'] = self.make_rule_obj(obj_str)
                                case '\t\t\t:src (':
                                    obj_str = ''
                                    while line != '\t\t\t)':
                                        obj_str = f'{obj_str} {line}'
                                        line = fh.readline().rstrip('\n')
                                    rule['src_ips'] = self.make_rule_obj(obj_str)
                                case '\t\t\t:dst (':
                                    obj_str = ''
                                    while line != '\t\t\t)':
                                        obj_str = f'{obj_str} {line}'
                                        line = fh.readline().rstrip('\n')
                                    rule['dst_ips'] = self.make_rule_obj(obj_str)
                                case '\t\t\t:services (':
                                    obj_str = ''
                                    while line != '\t\t\t)':
                                        obj_str = f'{obj_str} {line}'
                                        line = fh.readline().rstrip('\n')
                                    rule['services'] = self.make_rule_obj(obj_str)
                            if line.startswith('\t\t\t:comments'):
                                rule['description'] = f'{rule["description"]}\n{self.make_rule_str(line)}'
                            elif line.startswith('\t\t\t:name'):
                                rule['name'] = self.make_rule_str(line)
                            elif line.startswith('\t\t\t:disabled'):
                                rule['enabled'] = True if self.make_rule_str(line) == 'false' else False
                            line = fh.readline().rstrip('\n')
                        rule['tags'].append(rule_tag)
                        self.fw_rules.append(rule)

                    case '\t\t:rule_adtr (':
                        rule = {
                            'name': '',
                            'enabled': False,
                            'description': 'Портировано с CheckPoint',
                            'src_adtr': [],
                            'src_adtr_translated': [],
                            'dst_adtr': [],
                            'dst_adtr_translated': [],
                            'services_adtr': [],
                            'services_adtr_translated': [],
                        }
                        while line != '\t\t)':
                            match line:
                                case '\t\t\t:src_adtr (':
                                    obj_str = ''
                                    while line != '\t\t\t)':
                                        obj_str = f'{obj_str} {line}'
                                        line = fh.readline().rstrip('\n')
                                    rule['src_adtr'] = self.make_rule_obj(obj_str)
                                case '\t\t\t:src_adtr_translated (':
                                    obj_str = ''
                                    while line != '\t\t\t)':
                                        obj_str = f'{obj_str} {line}'
                                        line = fh.readline().rstrip('\n')
                                    rule['src_adtr_translated'] = self.make_rule_obj(obj_str)
                                case '\t\t\t:dst_adtr (':
                                    obj_str = ''
                                    while line != '\t\t\t)':
                                        obj_str = f'{obj_str} {line}'
                                        line = fh.readline().rstrip('\n')
                                    rule['dst_adtr'] = self.make_rule_obj(obj_str)
                                case '\t\t\t:dst_adtr_translated (':
                                    obj_str = ''
                                    while line != '\t\t\t)':
                                        obj_str = f'{obj_str} {line}'
                                        line = fh.readline().rstrip('\n')
                                    rule['dst_adtr_translated'] = self.make_rule_obj(obj_str)
                                case '\t\t\t:services_adtr (':
                                    obj_str = ''
                                    while line != '\t\t\t)':
                                        obj_str = f'{obj_str} {line}'
                                        line = fh.readline().rstrip('\n')
                                    rule['services_adtr'] = self.make_rule_obj(obj_str)
                                case '\t\t\t:services_adtr_translated (':
                                    obj_str = ''
                                    while line != '\t\t\t)':
                                        obj_str = f'{obj_str} {line}'
                                        line = fh.readline().rstrip('\n')
                                    rule['services_adtr_translated'] = self.make_rule_obj(obj_str)
                            if line.startswith('\t\t\t:comments'):
                                rule['description'] = f'{rule["description"]}\n{self.make_rule_str(line)}'
                            elif line.startswith('\t\t\t:name'):
                                rule['name'] = self.make_rule_str(line)
                            elif line.startswith('\t\t\t:disabled'):
                                rule['enabled'] = True if self.make_rule_str(line) == 'false' else False
                            line = fh.readline().rstrip('\n')
                        self.nat_rules.append(rule)

                line = fh.readline().rstrip('\n')

#        json_file = os.path.join(path, 'fw_rules.json')
#        with open(json_file, 'w') as fh:
#            json.dump(self.fw_rules, fh, indent=4, ensure_ascii=False)

#        json_file = os.path.join(path, 'nat_rules.json')
#        with open(json_file, 'w') as fh:
#            json.dump(self.nat_rules, fh, indent=4, ensure_ascii=False)

        self.stepChanged.emit('GREEN|    Конфигурация CheckPoint в формат json конвертирована.')


    def convert_ip_lists(self):
        """Конвертируем списки IP-адесов"""
        self.stepChanged.emit('BLUE|Конвертация списков IP-адесов.')
        current_path = os.path.join(self.current_ug_path, 'Libraries', 'IPAddresses')
        err, msg = self.create_dir(current_path)
        if err:
            self.stepChanged.emit('RED|    {msg}')
            self.error = 1
            return

        error = 0
        ip_list = {
            'name': '',
            'description': '',
            'type': 'network',
            'url': '',
            'list_type_update': 'static',
            'schedule': 'disabled',
            'attributes': {'threat_level': 3},
            'content': []
        }
        valid_type = {'host', 'cluster_member', 'gateway_cluster', 'machines_range', 'network', 'group', 'gateway'}
        n = 0

        for key, value in self.ip_lists.items():
            if value['type'] not in valid_type:
                continue
            if value['type'] != 'group' and value['addr_type_indication'] != 'IPv4':
                continue

            ip_list['name'] = key
            ip_list['description'] = value['comments']

            match value['type']:
                case 'host' | 'cluster_member' | 'gateway_cluster':
                    ip_list['content'] = [{'value': value['ipaddr']}]
                case 'machines_range':
                    ip_list['content'] = [{'value': f'{value["ipaddr_first"]}-{value["ipaddr_last"]}'}]
                case 'network':
                    err, address = self.pack_ip_address(value['ipaddr'], value['netmask'])
                    if err:
                        self.stepChanged.emit(f'RED|    Error: Список IP-адесов "{ip_list["name"]}" не конвертирован. Не валидный IP-адрес "{value["ipaddr"]}/{value["netmask"]}".\n       {err}')
                        error = 1
                        continue
                    ip_list['content'] = [{'value': address}]
                case 'group':
                    ip_list['content'] = [{'list': item} for item in value['members'] if (item in self.ip_lists and self.ip_lists[item]['addr_type_indication'] == 'IPv4')]

            json_file = os.path.join(current_path, f'{key.translate(self.trans_filename)}.json')
            with open(json_file, 'w') as fh:
                json.dump(ip_list, fh, indent=4, ensure_ascii=False)
            n += 1
            self.ngfw_ip_lists.add(ip_list['name'])
            self.stepChanged.emit(f'BLACK|    {n} - Список IP-адесов "{ip_list["name"]}" выгружен в файл "{json_file}".')

        if error:
            self.stepChanged.emit('ORANGE|    Произошла ошибка при конвертации списков IP-адесов.')
            self.error = 1
        else:
            self.stepChanged.emit('GREEN|    Конвертация списков IP-адесов завершена.')


    def convert_routes(self):
        """Конвертируем статические маршруты в VRF по умолчанию"""
        self.stepChanged.emit('BLUE|Конвертация статических маршрутов в VRF по умолчанию.')

        error = 0
        vrf = {
            'name': 'default',
            'description': '',
            'interfaces': [],
            'routes': [],
            'ospf': {},
            'bgp': {},
            'rip': {},
            'pimsm': {}
        }

        for key, value in self.ip_lists.items():
            if value['type'] == 'gateway' and value['netmask']:
                err, network = self.get_network_by_ipaddress(value['ipaddr'], value['netmask'])
                if err:
                    self.stepChanged.emit(f'RED|    Error: Статический маршрут "{key}" не конвертирован. Не корректный IP-адрес "{value["ipaddr"]}/{value["netmask"]}".\n       {err}')
                    error = 1
                    continue

                vrf['routes'].append({
                    'name': key,
                    'enabled': True,
                    'description': value.get('comments', ''),
                    'dest': network,
                    'gateway': value['ipaddr'],
                    'ifname': 'undefined',
                    'kind': 'unicast',
                    'metric': 1
                })


        if vrf['routes']:
            current_path = os.path.join(self.current_ug_path, 'Network', 'VRF')
            err, msg = self.create_dir(current_path)
            if err:
                self.stepChanged.emit('RED|    {msg}')
                self.error = 1
                return

            json_file = os.path.join(current_path, 'config_vrf.json')
            with open(json_file, 'w') as fh:
                json.dump([vrf], fh, indent=4, ensure_ascii=False)

            if error:
                self.stepChanged.emit(f'ORANGE|    Конвертация прошла с ошибками. Статические маршруты выгружены в файл "{json_file}".')
                self.error = 1
            else:
                self.stepChanged.emit(f'GREEN|    Статические маршруты выгружены в файл "{json_file}".')
        else:
            self.stepChanged.emit('GRAY|    Нет статических маршрутов для экспорта.')


    def convert_gateways(self):
        """Конвертируем список шлюзов"""
        self.stepChanged.emit('BLUE|Конвертация списка шлюзов.')

        gateways = []
        valid_types = {'gateway', 'gateway_cluster'}

        for key, value in self.ip_lists.items():
            if value['type'] in valid_types and not value['netmask']:
                gateways.append({
                    'name': key,
                    'enabled': True,
                    'description': value.get('comments', ''),
                    'ipv4': value['ipaddr'],
                    'vrf': 'default',
                    'weight': 1,
                    'multigate': False,
                    'default': False,
                    'iface': 'undefined',
                    'is_automatic': False
                })

        if gateways:
            current_path = os.path.join(self.current_ug_path, 'Network', 'Gateways')
            err, msg = self.create_dir(current_path)
            if err:
                self.stepChanged.emit('RED|    {msg}')
                self.error = 1
                return

            json_file = os.path.join(current_path, 'config_gateways.json')
            with open(json_file, 'w') as fh:
                json.dump(gateways, fh, indent=4, ensure_ascii=False)
            self.stepChanged.emit(f'GREEN|    Список шлюзов выгружен в файл "{json_file}".')
        else:
            self.stepChanged.emit('GRAY|    Нет шлюзов для экспорта.')


    def convert_services(self):
        """Конвертируем список сервисов"""
        self.stepChanged.emit('BLUE|Конвертация сетевых сервисов.')

        services = {}
        valid_types = {'tcp', 'udp'}
        services_proto = {'110': 'pop3', '995': 'pop3s', '25': 'smtp', '465': 'smtps'}
        n = 0

        for key, value in self.services.items():
            if value['type'] == 'icmp':
                self.icmp.add(key)
                continue
            if value['type'] == 'icmpv6':
                self.icmpv6.add(key)
                continue

            service = {
                'name': key,
                'description': f'Портировано с CheckPoint.\n{value.get("comments", "")}',
            }
            if value['type'] in valid_types:
                service['protocols'] = [{
                    'proto': services_proto.get(value['port'], value['type']),
                    'port': value['port'],
                    'app_proto': services_proto.get(value['port'], ''),
                    'source_port': value['src_port'],
                    'alg': ''
                }]
                services[key] = service
            elif value['type'] == 'other':
                if value['port']:
                    service['protocols'] = [{
                        'proto': value['protocol'] if value['protocol'] in valid_types else 'tcp',
                        'port': value['port'],
                        'app_proto': '',
                        'source_port': value['src_port'],
                        'alg': ''
                    }]
                    services[key] = service
                elif value['protocol']:
                    service['protocols'] = [{
                        'proto': value['protocol'],
                        'port': '',
                        'app_proto': value['protocol'],
                        'source_port': '',
                        'alg': ''
                    }]
                    services[key] = service
            elif value['port'] and value['type'].startswith('gtp'):
                service['protocols'] = [{
                    'proto': 'tcp',
                    'port': value['port'],
                    'app_proto': '',
                    'source_port': value['src_port'],
                    'alg': ''
                }]
                services[key] = service

        services['Any IPV6-ICMP'] = {
                'name': 'Any IPV6-ICMP',
                'description': 'Any IPV6-ICMP packet',
                'protocols': [{'proto': 'ipv6-icmp', 'port': '', 'app_proto': 'ipv6-icmp', 'source_port': '', 'alg': ''}]
        }
        services['Any ICMP'] = {
                'name': 'Any ICMP',
                'description': 'Any ICMP packet',
                'protocols': [{'proto': 'icmp', 'port': '', 'app_proto': '', 'source_port': '', 'alg': ''}]
        }

        if services:
            current_path = os.path.join(self.current_ug_path, 'Libraries', 'Services')
            err, msg = self.create_dir(current_path)
            if err:
                self.stepChanged.emit('RED|    {msg}')
                self.error = 1
                return

            json_file = os.path.join(current_path, 'config_services_list.json')
            with open(json_file, 'w') as fh:
                json.dump(list(services.values()), fh, indent=4, ensure_ascii=False)
            self.ngfw_services = services
            self.stepChanged.emit(f'GREEN|    Список сервисов выгружен в файл "{json_file}".')
        else:
            self.stepChanged.emit('GRAY|    Нет сервисов для экспорта.')


    def convert_service_groups(self):
        """Конвертируем группы сервисов"""
        self.stepChanged.emit('BLUE|Конвертация групп сервисов.')
        services_groups = []

        for key, value in self.services.items():
            if value['type'] == 'group':
                members = {}
                for item in value['members']:
                    if item in self.ngfw_services:
                        members[item] = self.ngfw_services[item]
                    elif item in self.icmp:
                        members['Any ICMP'] = self.ngfw_services['Any ICMP']
                    elif item in self.icmpv6:
                        members['Any IPV6-ICMP'] = self.ngfw_services['Any IPV6-ICMP']
                if not members:
                    continue

                services_groups.append({
                    'name': key,
                    'description': f'Портировано с CheckPoint.\n{value.get("comments", "")}',
                    'type': 'servicegroup',
                    'url': '',
                    'list_type_update': 'static',
                    'schedule': 'disabled',
                    'attributes': {},
                    'content': list(members.values())
                })
                self.ngfw_services_groups.add(key)

        if services_groups:
            current_path = os.path.join(self.current_ug_path, 'Libraries', 'ServicesGroups')
            err, msg = self.create_dir(current_path)
            if err:
                self.stepChanged.emit('RED|    {msg}')
                self.error = 1
                return

            json_file = os.path.join(current_path, 'config_services_groups_list.json')
            with open(json_file, 'w') as fh:
                json.dump(services_groups, fh, indent=4, ensure_ascii=False)
            self.stepChanged.emit(f'GREEN|    Группы сервисов выгружен в файл "{json_file}".')
        else:
            self.stepChanged.emit('GRAY|    Нет групп сервисов для экспорта.')


    def convert_firewall_rules(self):
        """Конвертируем правила межсетевого экрана"""
        self.stepChanged.emit('BLUE|Конвертация правил межсетевого экрана.')
        if not self.fw_rules:
            self.stepChanged.emit('GRAY|    Нет правил межсетевого экрана для экспорта.')
            return

        message = (
            '    Перед импортом на NGFW, создайте на NGFW необходимые зоны и присвойте зону каждому интерфейсу.\n'
            '    После импорта правил МЭ на NGFW, необходимо в каждом правиле указать зоны источника и назначения.'
        )
        self.stepChanged.emit(f'LBLUE|{message}')
        error = 0
        n = 0
        
        for rule in self.fw_rules:
            icmp_exist = False
            icmpv6_exist = False
            if rule['action'] == 'reject':
                rule['action'] = 'drop'
                rule['send_host_icmp'] = 'tcp-rst'
            else:
                rule['send_host_icmp'] = ''
            rule['position'] = 'last'
            rule['scenario_rule_id'] = False
            rule['src_zones'] = ''
            rule['dst_zones'] = ''
            rule['src_ips'] = [['list_id', x] for x in rule['src_ips'] if x in self.ngfw_ip_lists]
            rule['dst_ips'] = [['list_id', x] for x in rule['dst_ips'] if x in self.ngfw_ip_lists]
            new_services = []
            for item in rule['services']:
                if item in self.ngfw_services:
                    new_services.append(['service', item])
                elif item in self.ngfw_services_groups:
                    new_services.append(['list_id', item])
                elif item in self.icmp:
                    if not icmp_exist:
                        new_services.append(['service', 'Any ICMP'])
                        icmp_exist = True
                elif item in self.icmpv6:
                    if not icmpv6_exist:
                        new_services.append(['service', 'Any IPV6-ICMP'])
                        icmpv6_exist = True
            rule['services'] = new_services
            rule['apps'] = []
            rule['users'] = []
            rule['limit'] = True
            rule['limit_value'] = '3/h'
            rule['limit_burst'] = 5
            rule['log'] = True if rule['log'][0] == 'Log' else False
            rule['log_session_start'] = True
            rule['src_zones_negate'] = False
            rule['dst_zones_negate'] = False
            rule['src_ips_negate'] = False
            rule['dst_ips_negate'] = False
            rule['service_negate'] = False
            rule['apps_negate'] = False
            rule['fragmented'] = 'ignore'
            rule['time_restrictions'] = []

            n += 1
            self.stepChanged.emit(f'BLACK|    {n} - Правило МЭ "{rule["name"]}" конвертировано.')

        current_path = os.path.join(self.current_ug_path, 'NetworkPolicies', 'Firewall')
        err, msg = self.create_dir(current_path)
        if err:
            self.stepChanged.emit('RED|    {msg}')
            self.error = 1
            return

        json_file = os.path.join(current_path, 'config_firewall_rules.json')
        with open(json_file, 'w') as fh:
            json.dump(self.fw_rules, fh, indent=4, ensure_ascii=False)

        if error:
            self.stepChanged.emit(f'ORANGE|    Конвертация правил прошла с ошибками. Правила межсетевого экрана выгружены в файл "{json_file}".')
            self.error = 1
        else:
            self.stepChanged.emit(f'GREEN|    Правила межсетевого экрана выгружены в файл "{json_file}".')





