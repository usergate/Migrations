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
#--------------------------------------------------------------------------------------------------- 
# Модуль преобразования конфигурации с Kerio в формат UserGate.
# Версия 1.1  27.10.2025
#

import os, sys, copy, json
import xmltodict
from PyQt6.QtCore import QThread, pyqtSignal
from common_classes import MyConv
from services import zone_services, ug_services, ip_proto, GEOIP_CODE


class ConvertKerioConfig(QThread, MyConv):
    """Преобразуем файл конфигурации Kerio в формат UserGate."""
    stepChanged = pyqtSignal(str)

    def __init__(self, current_kerio_path, current_ug_path):
        super().__init__()
        self.current_kerio_path = current_kerio_path
        self.current_ug_path = current_ug_path
        self.services = {}
        self.port_ids = {}
        self.service_groups = set()
        self.ip_lists = {}
        self.url_lists = {}
        self.zones = set()

        self.vendor = 'Kerio'
        self.error = 0

    def run(self):
        self.stepChanged.emit(f'GREEN|{"Конвертация конфигурации Kerio в формат UserGate.":>110}')
        self.stepChanged.emit(f'ORANGE|{"="*110}')
        self.convert_config_file()

        if self.error:
            self.stepChanged.emit('iRED|Конвертация конфигурации Kerio в формат UserGate прервана.')
        else:
            json_file = os.path.join(self.current_kerio_path, 'winroute.json')
            err, data = self.read_json_file(json_file)
            if err:
                self.stepChanged.emit('iRED|Конвертация конфигурации Kerio в формат UserGate прервана.\n')
            else:
                self.convert_zone_settings()
                self.convert_ntp_settings(data['config']['table'])
                self.convert_dns_servers(data['config']['table'])
                for item in data['config']['list']:
                    match item['@name']:
                        case 'Hosts':
                            self.convert_dns_static(item.get('listitem', []))
                        case 'WebKeywords':
                            self.convert_morpology(item.get('listitem', []))
                        case 'IPServices':
                            self.convert_services(item.get('listitem', []))
                            self.convert_service_groups(item.get('listitem', []))
                        case 'IpAccessList':
                            self.convert_ip_lists(item.get('listitem', []))
                            self.convert_url_lists(item.get('listitem', []))
                        case 'StaticRoutes':
                            self.convert_vrfs(item.get('listitem', []))
                        case 'UrlGroups':
                            self.convert_url_groups(item.get('listitem', []))
                        case 'ContentFilterRules':
                            self.convert_content_rules(item.get('listitem', []))
                        case 'TrafficRules_v2':
                            self.convert_dnat_rule(item.get('listitem', []))

            # Выгружаем сетевые сервисы, так как после конвертации правил DNAT былы добавлены новые сервисы.
            current_path = os.path.join(self.current_ug_path, 'Libraries', 'Services')
            err, msg = self.create_dir(current_path)
            if err:
                self.stepChanged.emit(f'RED|    {msg}')
                self.error = 1
                return

            json_file = os.path.join(current_path, 'config_services_list.json')
            with open(json_file, 'w') as fh:
                json.dump(list(self.services.values()), fh, indent=4, ensure_ascii=False)
            self.stepChanged.emit(f'GREEN|    Сервисы выгружены в файл "{json_file}".')

            if self.error:
                self.stepChanged.emit('iORANGE|Конвертация конфигурации Kerio в формат UserGate прошла с ошибками.\n')
            else:
                self.stepChanged.emit('iGREEN|Конвертация конфигурации Kerio в формат UserGate прошла успешно.\n')


    def convert_config_file(self):
        """Преобразуем файлы конфигурации Kerio в формат json."""
        self.stepChanged.emit('BLUE|Конвертация файлов конфигурации Kerio в формат json.')
        if not os.path.isdir(self.current_kerio_path):
            self.stepChanged.emit('RED|    Не найден каталог с конфигурацией Kerio.')
            self.error = 1
            return

        config_file = os.path.join(self.current_kerio_path, 'winroute.cfg')
        try:
            with open(config_file, 'r') as fh:
                data = fh.read()
        except FileNotFoundError:
            self.stepChanged.emit(f'RED|    Не найден файл "{config_file}" с конфигурацией Kerio.')
            self.error = 1
            return

        dict_data = xmltodict.parse(data)

        json_file = os.path.join(self.current_kerio_path, 'winroute.json')
        with open(json_file, 'w') as fh:
            json.dump(dict_data, fh, indent=4, ensure_ascii=False)

        self.stepChanged.emit(f'GREEN|    Конфигурация Kerio в формате json выгружена в файл "{json_file}".')


    #----------------------------------- Конвертация ------------------------------------------------
    def convert_zone_settings(self):
        """Конвертируем зоны"""
        self.stepChanged.emit('BLUE|Конвертация Зон.')

        ifaces_file = os.path.join(self.current_kerio_path, 'interfaces')
        try:
            with open(ifaces_file, 'r') as fh:
                for line in fh:
                    self.zones.update([x.strip() for x in line.split(',')[3:] if x.strip()])
        except FileNotFoundError:
            self.stepChanged.emit(f'RED|    Error: Не найден файл "{ifaces_file}". Зоны не конвертированы.')
            return

        new_zones = []
        for item in self.zones:
            new_zones.append({
                'name': item,
                'description': 'Портировано с Kerio.',
                'dos_profiles': [
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
                ],
                'services_access': [
                    {
                        'enabled': True,
                        'service_id': 'Ping',
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
                    }
                ],
                'readonly': False,
                'enable_antispoof': False,
                'antispoof_invert': False,
                'networks': [],
                'sessions_limit_enabled': False,
                'sessions_limit_threshold': 0,
                'sessions_limit_exclusions': []
            })

        if new_zones:
            current_path = os.path.join(self.current_ug_path, 'Network', 'Zones')
            err, msg = self.create_dir(current_path)
            if err:
                self.stepChanged.emit(f'RED|    {msg}')
                self.error = 1
                return

            json_file = os.path.join(current_path, 'config_zones.json')
            with open(json_file, 'w') as fh:
                json.dump(new_zones, fh, indent=4, ensure_ascii=False)
            self.stepChanged.emit(f'GREEN|    Настройки зон выгружены в файл "{json_file}".')
        else:
            self.stepChanged.emit('GRAY|    Нет зон для экспорта.')


    @staticmethod
    def compress_block(block):
        tmp = {}
        for item in block:
            tmp[item['@name']] = item.get('#text', '')
        return tmp


    def convert_ntp_settings(self, config_array):
        """Конвертируем настройки NTP"""
        self.stepChanged.emit('BLUE|Конвертация настроек NTP.')
        ntp_conf = {
            'ntp_servers': [],
            'ntp_enabled': True,
            'ntp_synced': True
        }
        for item in config_array:
            if item['@name'] == 'TimeSettings':
                for value in item['variable']:
                    if value['@name'] == 'NTPServer':
                        ntp_conf['ntp_servers'] = value['#text'].split(';')

        if ntp_conf['ntp_servers']:
            current_path = os.path.join(self.current_ug_path, 'UserGate', 'GeneralSettings')
            err, msg = self.create_dir(current_path, delete='no')
            if err:
                self.stepChanged.emit(f'RED|    {msg}')
                self.error = 1
                return

            json_file = os.path.join(current_path, 'config_ntp.json')
            with open(json_file, 'w') as fh:
                json.dump(ntp_conf, fh, indent=4, ensure_ascii=False)
            self.stepChanged.emit(f'GREEN|    Настройки NTP выгружены в файл "{json_file}".')
        else:
            self.stepChanged.emit('GRAY|    Нет серверов NTP для экспорта.')


    def convert_dns_servers(self, config_array):
        """Заполняем список системных DNS"""
        self.stepChanged.emit('BLUE|Конвертация настроек DNS.')
        dns_servers = []
        domain = ''
        dns_proxy = {
            'use_cache_enabled': True,
            'enable_dns_filtering': False,
            'recursive_enabled': True,
            'dns_max_ttl': 86400,
            'dns_max_queries_per_user': 100,
            'only_a_for_unknown': False,
            'dns_receive_timeout': 1200,
            'dns_max_attempts': 2
        }

        for item in config_array:
            if item['@name'] == 'DNS':
                for value in item['variable']:
                    match value['@name']:
                        case 'ActiveDirSrv':
                            if '#text' in value:
                                dns_servers.append(value['#text'])
                        case 'Domain':
                            if '#text' in value:
                                domain = value['#text']
                        case 'AnswerTimeout':
                            if '#text' in value:
                                dns_proxy['dns_receive_timeout'] = int(value['#text'])
                        case 'CacheEnabled':
                            if '#text' in value:
                                dns_proxy['use_cache_enabled'] = True if int(value['#text']) else False
                        case 'DnsCacheFileTimeout':
                            if '#text' in value:
                                dns_proxy['dns_max_ttl'] = int(value['#text'])

        if dns_servers:
            current_path = os.path.join(self.current_ug_path, 'Network', 'DNS')
            err, msg = self.create_dir(current_path, delete='no')
            if err:
                self.stepChanged.emit(f'RED|    {msg}')
                self.error = 1
                return

            json_file = os.path.join(current_path, 'config_dns_servers.json')
            with open(json_file, 'w') as fh:
                json.dump([{'dns': x, 'is_bad': False} for x in dns_servers], fh, indent=4, ensure_ascii=False)
        else:
            self.stepChanged.emit('GRAY|    Нет настроек DNS для экспорта.')
            return

        if dns_servers and domain:
            dns_rules = {
                'name': domain,
                'description': '',
                'enabled': True,
                'domains': [f'*.{domain}',],
                'dns_servers': dns_servers
            }
            json_file = os.path.join(current_path, 'config_dns_rules.json')
            with open(json_file, 'w') as fh:
                json.dump([dns_rules], fh, indent=4, ensure_ascii=False)

        json_file = os.path.join(current_path, 'config_dns_proxy.json')
        with open(json_file, 'w') as fh:
            json.dump(dns_proxy, fh, indent=4, ensure_ascii=False)

        self.stepChanged.emit(f'GREEN|    Настройки DNS выгружены в каталог "{current_path}".')


    def convert_dns_static(self, config_array):
        """Конвертация статических записей DNS"""
        self.stepChanged.emit('BLUE|Конвертация статических записей DNS.')
        hosts = []

        for item in config_array:
            host = self.compress_block(item['variable'])
            hosts.append({
                'name': host['HostName'],
                'description': host['Description'],
                'enabled': True if int(host['Enabled']) else False,
                'domain_name': host['HostName'],
                'ip_addresses': [host['IPAddress']]
            })

        if hosts:
            current_path = os.path.join(self.current_ug_path, 'Network', 'DNS')
            err, msg = self.create_dir(current_path, delete='no')
            if err:
                self.stepChanged.emit(f'RED|    {msg}')
                self.error = 1
                return

            json_file = os.path.join(current_path, 'config_dns_static.json')
            with open(json_file, 'w') as fh:
                json.dump(hosts, fh, indent=4, ensure_ascii=False)
            self.stepChanged.emit(f'GREEN|    Статические записи DNS выгружены в файл "{json_file}".')
        else:
            self.stepChanged.emit('GRAY|    Нет статических записей DNS для экспорта.')


    def convert_vrfs(self, config_array):
        """Конвертируем список VRFs"""
        self.stepChanged.emit('BLUE|Конвертация virtual routers.')

        gateways_list = []
        vrf = {
            'name': 'default',
            'descriprion': '',
            'interfaces': [],
            'routes': [],
            'ospf': {},
            'bgp': {},
            'rip': {},
            'pimsm': {}
        }

        for item in config_array:
            # Конвертируем статические маршруты
            route = self.compress_block(item['variable'])
            if (route_name := self.check_ip(f'{route["Net"]}/{route["Mask"]}')):
                vrf['routes'].append({
                    'name': route_name,
                    'description': route.get('Description', 'Портировано с Kerio.'),
                    'enabled': True if int(route['Enabled']) else False,
                    'dest': route_name,
                    'gateway': route['Gateway'],
                    'ifname': 'undefined',
                    'kind': 'unicast',
                    'metric': int(route.get('Metric', 1))
                })
            else:
                self.stepChanged.emit(f'RED|    ERROR: [Статический маршрут "{route["Net"]}"] Не корректный адрес/маска".')

        if vrf['routes']:
            current_path = os.path.join(self.current_ug_path, 'Network', 'VRF')
            err, msg = self.create_dir(current_path)
            if err:
                self.stepChanged.emit(f'RED|    {msg}')
                self.error = 1
                return

            json_file = os.path.join(current_path, 'config_vrf.json')
            with open(json_file, 'w') as fh:
                json.dump([vrf], fh, indent=4, ensure_ascii=False)
            self.stepChanged.emit(f'GREEN|    Virtual Routers выгружены в файл "{json_file}".')
        else:
            self.stepChanged.emit('GRAY|    Нет Virtual Routers для экспорта.')


    def convert_morpology(self, config_array):
        """Конвертируем списки морфологии"""
        self.stepChanged.emit('BLUE|Конвертация списков морфологии.')
        morphology_list = []
        morph = {}

        for item in config_array:
            tmp = {}
            for var in item['variable']:
                if '#text' in var:
                    tmp[var['@name']] = var['#text']
            if tmp['Name'] not in morph:
                morph[tmp['Name']] = []
            morph[tmp['Name']].append({'value': tmp['Keyword'], 'weight': int(tmp['Weight'])})

        if morph:
            for name, content in morph.items():
                error, new_name = self.get_transformed_name(name, descr='Имя списка морфологии')
                morphology_list.append({
                    'name': new_name,
                    'description': 'Портировано с Kerio.',
                    'type': 'morphology',
                    'url': '',
                    'list_type_update': 'static',
                    'schedule': 'disabled',
                    'attributes': {'threat_level': 3, 'threshold': 100},
                    'content': content
                })

            current_path = os.path.join(self.current_ug_path, 'Libraries', 'Morphology')
            err, msg = self.create_dir(current_path)
            if err:
                self.stepChanged.emit(f'RED|    {msg}')
                self.error = 1
                return

            json_file = os.path.join(current_path, 'config_morphology_lists.json')
            with open(json_file, 'w') as fh:
                json.dump(morphology_list, fh, indent=4, ensure_ascii=False)
            self.stepChanged.emit(f'GREEN|    Списки морфологии выгружены в файл "{json_file}".')
        else:
            self.stepChanged.emit('GRAY|    Нет списков морфологии для экспорта.')


    def convert_services(self, config_array):
        """Конвертируем сетевые сервисы."""
        self.stepChanged.emit('BLUE|Конвертация сетевых сервисов.')
        for item in self.create_ug_services():
            self.services[item['name']] = item

        kerio_proto = {
            'LDAP': ['tcp'],
            'NetBIOS-NS': ['udp'],
            'MS-SQL': ['tcp'],
            'WINS': ['tcp', 'udp'],
            'PC Anywhere': ['udp'],
            'Microsoft-DS': ['tcp', 'udp'],
            'Windows Messenger': ['tcp', 'udp'],
            'Kazaa': ['tcp', 'udp'],
            'eDonkey': ['tcp'],
            'SIP TLS': ['tcp', 'udp'],
            'Kerberos': ['tcp', 'udp'],
            'Gnutella': ['tcp', 'udp'],
            'UPnP': ['tcp', 'udp'],
            'Kerio VPN': ['tcp', 'udp'],
            'BGP': ['tcp', 'udp']
        }

        for item in config_array:
            service = self.compress_block(item['variable'])
            if not int(service['Group']):
                if service['Name'] in self.services:
                    self.port_ids[service['Id']] = service['Name']
                    continue
                new_service = {
                    'name': service['Name'],
                    'description': f'{service["Description"]}\nПортировано с Kerio.',
                    'protocols': []
                }
                condition, _, ports = service['Condition'].partition('=')
                if service['Protocol'] in ip_proto:
                    if condition == 'type':
                        new_service['protocols'].append({'proto': ip_proto[service['Protocol']], 'port': '', 'app_proto': '', 'source_port': '', 'alg': ''})
                    else:
                        for port in ports.split(','):
                            if condition == 'dport':
                                new_service['protocols'].append({
                                    'proto': ip_proto[service['Protocol']],
                                    'port': port,
                                    'app_proto': '',
                                    'source_port': '',
                                    'alg': ''
                                })
                            else:
                                print('ERROR: ', service)
                else:
                    if condition == 'dport' and service['Protocol'] == '129':
                        try:
                            for port in ports.split(','):
                                for proto in kerio_proto[service['Name']]:
                                    new_service['protocols'].append({
                                        'proto': proto,
                                        'port': port,
                                        'app_proto': '',
                                        'source_port': '',
                                        'alg': ''
                                    })
                        except KeyError:
                            self.stepChanged.emit(f'ORANGE|    WARNING: Сервис "{service["Name"]}" не конвертирован так как протокол "{service["Protocol"]}" не поддерживается UserGate.')
                            continue
                    elif condition == 'proto' and service['Protocol'] == '128':
                        new_service['protocols'].append({'proto': ip_proto[ports], 'port': '', 'app_proto': '', 'source_port': '', 'alg': ''})
                self.port_ids[service['Id']] = new_service['name']
                self.services[new_service['name']] = new_service

        current_path = os.path.join(self.current_ug_path, 'Libraries', 'Services')
        err, msg = self.create_dir(current_path)
        if err:
            self.stepChanged.emit(f'RED|    {msg}')
            self.error = 1
            return

        json_file = os.path.join(current_path, 'config_services_list.json')
        with open(json_file, 'w') as fh:
            json.dump(list(self.services.values()), fh, indent=4, ensure_ascii=False)
        self.stepChanged.emit(f'GREEN|    Сервисы выгружены в файл "{json_file}".')


    def convert_service_groups(self, config_array):
        """Конвертируем группы сервисов"""
        self.stepChanged.emit('BLUE|Конвертация групп сервисов.')
        services_groups = []


        for item in config_array:
            service = self.compress_block(item['variable'])
            if int(service['Group']):
                srv_group = {
                    'name': service['Name'],
                    'description': f'{service["Description"]}\nПортировано с Kerio.',
                    'type': 'servicegroup',
                    'url': '',
                    'list_type_update': 'static',
                    'schedule': 'disabled',
                    'attributes': {},
                    'content': []
                }
                for x in service['Condition'].split():
                    service_id = x.split('=')[1]
                    try:
                        service_name = self.port_ids[service_id]
                    except KeyError:
                        self.stepChanged.emit(f'RED|    ERROR: [Группа сервисов "{service["Name"]}"] Не найден сервис с ID "{service_id}".')
                        continue
                    srv_group['content'].append(self.services[service_name])

                services_groups.append(srv_group)
                self.service_groups.add(srv_group['name'])

        if services_groups:
            current_path = os.path.join(self.current_ug_path, 'Libraries', 'ServicesGroups')
            err, msg = self.create_dir(current_path)
            if err:
                self.stepChanged.emit('RED|    {msg}')
                self.error = 1
                return

            json_file = os.path.join(current_path, 'config_services_groups_list.json')
            with open(json_file, "w") as fh:
                json.dump(services_groups, fh, indent=4, ensure_ascii=False)
            self.stepChanged.emit(f'GREEN|    Группы сервисов выгружены в файл "{json_file}".')
        else:
            self.stepChanged.emit('GRAY|    Нет групп сервисов для экспорта.')


    def convert_ip_lists(self, config_array):
        """Конвертируем списки IP-адресов"""
        self.stepChanged.emit('BLUE|Конвертация списков IP-адресов.')
        n = 0
        error = 0
        result_ips = {}
        desc_ips = {}

        for item in config_array:
            source = self.compress_block(item['variable'])
            if "'" in source['Value']:
                continue
            if source['Value'].startswith('prefix:'):
                net = source['Value'].split(':')[1]
                if self.check_ip(net):
                    source['Value'] = net
                else:
                    self.stepChanged.emit(f'RED|    ERROR: [Список IP-адресов "{source["Name"]}"]. Не корректный IP: "{net}".')
                    error = 1
                    continue
            elif source['Value'].startswith('='):
                self.stepChanged.emit(f'RED|    ERROR: [Список IP-адресов "{source["Name"]}"] Не корректный адрес: "{source["Value"]}".')
                error = 1
                continue
            if source['Name'] not in result_ips:
                result_ips[source['Name']] = []
            result_ips[source['Name']].append({'value': source['Value']})
            desc_ips[source['Name']] = source['Desc']

        if result_ips:
            current_path = os.path.join(self.current_ug_path, 'Libraries', 'IPAddresses')
            err, msg = self.create_dir(current_path)
            if err:
                self.stepChanged.emit(f'RED|    {msg}')
                self.error = 1
                return

            for name, content in result_ips.items():
                error, iplist_name = self.get_transformed_name(name, err=error, descr='Имя списка IP-адресов')
                ip_list = {
                    'name': iplist_name,
                    'description': 'Портировано с Kerio.',
                    'type': 'network',
                    'url': '',
                    'list_type_update': 'static',
                    'schedule': 'disabled',
                    'attributes': {'threat_level': 3},
                    'content': content
                }
                self.ip_lists[name] = iplist_name

                n += 1
                file_name = ip_list['name'].translate(self.trans_filename)

                json_file = os.path.join(current_path, f'{file_name}.json')
                with open(json_file, 'w') as fh:
                    json.dump(ip_list, fh, indent=4, ensure_ascii=False)
                    self.stepChanged.emit(f'BLACK|    {n} - Список IP-адресов "{ip_list["name"]}" выгружен в файл "{json_file}".')

            if error:
                self.stepChanged.emit(f'ORANGE|    Конвертация списков IP-адресов прошла с ошибками. Списки IP-адресов выгружены в каталог "{current_path}".')
                self.error = 1
            else:
                self.stepChanged.emit(f'GREEN|    Списки IP-адресов выгружены в каталог "{current_path}".')
        else:
            self.stepChanged.emit('GRAY|    Нет списков IP-адресов для экспорта.')


    def convert_url_lists(self, config_array):
        """Конвертируем списки URL"""
        self.stepChanged.emit('BLUE|Конвертация списков URL.')
        n = 0
        error = 0
        urllists = {}

        for item in config_array:
            source = self.compress_block(item['variable'])
            if source['Value'].startswith('='):
                continue
            if "'" in source['Value']:
                if source['Name'] not in urllists:
                    urllists[source['Name']] = []
                urllists[source['Name']].append({'value': source['Value'].replace("'", '')})

        if urllists:
            current_path = os.path.join(self.current_ug_path, 'Libraries', 'URLLists')
            err, msg = self.create_dir(current_path)
            if err:
                self.stepChanged.emit(f'RED|    {msg}')
                self.error = 1
                return

            for name, content in urllists.items():
                error, list_name = self.get_transformed_name(name, err=error, descr='Имя списка URL')
                url_list = {
                    'name': list_name,
                    'description': 'Портировано с Kerio.',
                    'type': 'url',
                    'url': '',
                    'list_type_update': 'static',
                    'schedule': 'disabled',
                    'attributes': {'list_compile_type': 'case_insensitive'},
                    'content': content
                }
                self.url_lists[name] = list_name
                n += 1

                json_file = os.path.join(current_path, f'{url_list["name"].translate(self.trans_filename)}.json')
                with open(json_file, 'w') as fh:
                    json.dump(url_list, fh, indent=4, ensure_ascii=False)
                self.stepChanged.emit(f'BLACK|       {n} - Список URL "{url_list["name"]}" выгружен в файл "{json_file}".')

            if error:
                self.stepChanged.emit(f'ORANGE|    Конвертация списков URL прошла с ошибками. Списки URL выгружены в каталог "{current_path}".')
                self.error = 1
            else:
                self.stepChanged.emit(f'GREEN|    Списки URL выгружены в каталог "{current_path}".')
        else:
            self.stepChanged.emit('GRAY|    Нет списков URL для экспорта.')


    def convert_url_groups(self, config_array):
        """Конвертируем списки URL"""
        self.stepChanged.emit('BLUE|Конвертация UrlGroups в списки URL.')
        n = 0
        error = 0
        urllists = {}
        list_desc = {}

        for item in config_array:
            source = self.compress_block(item['variable'])
            if source['Url'].startswith('*/') or source['Url'].startswith('/'):
                self.stepChanged.emit(f'RED|    ERROR: [Список URL "{source["Name"]}"] Не корректный URL: "{source["Url"]}".')
                error = 1
                continue
            elif '?' in source['Url'] or ' ' in source['Url']:
                self.stepChanged.emit(f'RED|    ERROR: [Список URL "{source["Name"]}"] Не корректный URL: "{source["Url"]}".')
                error = 1
                continue

            if source['Name'] not in urllists:
                urllists[source['Name']] = []
            urllists[source['Name']].append({'value': source['Url']})
            if source['Description'] and source['Name'] not in list_desc:
                list_desc[source['Name']] = source['Description']

        if urllists:
            current_path = os.path.join(self.current_ug_path, 'Libraries', 'URLLists')
            err, msg = self.create_dir(current_path, delete='no')
            if err:
                self.stepChanged.emit(f'RED|    {msg}')
                self.error = 1
                return

            for name, content in urllists.items():
                error, list_name = self.get_transformed_name(name, err=error, descr='Имя списка URL')
                url_list = {
                    'name': list_name,
                    'description': list_desc.get(name, 'Портировано с Kerio.'),
                    'type': 'url',
                    'url': '',
                    'list_type_update': 'static',
                    'schedule': 'disabled',
                    'attributes': {'list_compile_type': 'case_insensitive'},
                    'content': content
                }
                self.url_lists[name] = list_name
                n += 1

                json_file = os.path.join(current_path, f'{url_list["name"].translate(self.trans_filename)}.json')
                with open(json_file, 'w') as fh:
                    json.dump(url_list, fh, indent=4, ensure_ascii=False)
                self.stepChanged.emit(f'BLACK|       {n} - Список URL "{url_list["name"]}" выгружен в файл "{json_file}".')

            if error:
                self.stepChanged.emit(f'ORANGE|    Конвертация списков URL прошла с ошибками. Списки URL выгружены в каталог "{current_path}".')
                self.error = 1
            else:
                self.stepChanged.emit(f'GREEN|    Списки URL выгружены в каталог "{current_path}".')
        else:
            self.stepChanged.emit('GRAY|    Нет списков URL для экспорта.')


    def convert_content_rules(self, config_array):
        """Конвертируем правила фильтрации контента"""
        self.stepChanged.emit('BLUE|Конвертация правил фильтрации контента.')
        n = 0
        error = 0
        rules = []

        for item in config_array:
            rule_urls = []
            rule_src_ips = []
            rule_dst_ips = []
            source = self.compress_block(item['variable'])
            error, rule_name = self.get_transformed_name(source['Name'], err=error, descr='Имя правила КФ')
            for param in item['variable']:
                if param['@name'] == 'Conditions':
                    tag, url = param.get('#text', 'cat:').split(':')
                    if url and tag != 'cat':
                        if tag == 'hostname':
                            if url not in self.url_lists:
                                if not self.create_url_list(url):
                                    self.stepChanged.emit(f'RED|    ERROR: [Правило КФ "{rule_name}"] В адрес назначения не добавлен URL-лист: "{url}".')
                                    error = 1
                                    continue
                            rule_dst_ips.append(['urllist_id', self.url_lists[url]])
                        elif url == '*':
                            continue
                        elif url in self.url_lists:
                            rule_urls.append(self.url_lists[url])
                        elif url in self.ip_lists:
                            rule_dst_ips.append(['list_id', self.ip_lists[url]])
                        elif self.check_ip(url):
                            if not self.create_ip_list(url):
                                self.stepChanged.emit(f'RED|    ERROR: [Правило КФ "{rule_name}"] В адрес назначения не добавлен IP-лист: "{url}".')
                                error = 1
                                continue
                            rule_dst_ips.append(['list_id', self.ip_lists[url]])
                        else:
                            if not self.create_url_list(url):
                                self.stepChanged.emit(f'RED|    ERROR: [Правило КФ "{rule_name}"] В адрес назначения не добавлен URL-лист: "{url}".')
                                error = 1
                                continue
                            rule_urls.append(self.url_lists[url])
                elif param['@name'] == 'Source':
                    tag, src_name = param.get('#text', 'cat:').split(':')
                    if tag == 'ipacl':
                        if src_name in self.ip_lists:
                            rule_src_ips.append(['list_id', self.ip_lists[src_name]])
                        elif src_name in self.url_lists:
                            rule_src_ips.append(['urllist_id', self.url_lists[src_name]])

            actions = tuple(x.strip() for x in source['Action'].split(','))
            rules.append({
                'action': 'accept' if 'Allow' in actions else 'drop',
                'name': rule_name,
                'public_name': '',
                'description': source['Description'],
                'enabled': True if int(source['Enabled']) else False,
                'enable_custom_redirect': True if source['RedirectUrl'] else False,
                'blockpage_template_id': -1,
                'users': [],
                'url_categories': [],
                'src_zones': [],
                'dst_zones': [],
                'src_ips': rule_src_ips,
                'dst_ips': rule_dst_ips,
                'morph_categories': [],
                'urls': rule_urls,
                'referers': [],
                'referer_categories': [],
                'user_agents': [],
                'time_restrictions': [],
                'content_types': [],
                'http_methods': [],
                'users_negate': False,
                'src_zones_negate': False,
                'dst_zones_negate': False,
                'src_ips_negate': False,
                'dst_ips_negate': False,
                'url_categories_negate': False,
                'urls_negate': False,
                'content_types_negate': False,
                'user_agents_negate': False,
                'custom_redirect': source['RedirectUrl'],
                'enable_kav_check': False,
                'enable_md5_check': False,
                'rule_log': True,
                'scenario_rule_id': False,
                'position_layer': 'local',
                'layer': 'Content Rules',
            })
            n += 1
            self.stepChanged.emit(f'BLACK|    {n} - Создано правило КФ "{rule_name}".')

        if rules:
            current_path = os.path.join(self.current_ug_path, 'SecurityPolicies', 'ContentFiltering')
            err, msg = self.create_dir(current_path)
            if err:
                self.stepChanged.emit(f'RED|    {msg}')
                self.error = 1
                return

            json_file = os.path.join(current_path, 'config_content_rules.json')
            with open(json_file, 'w') as fh:
                json.dump(rules, fh, indent=4, ensure_ascii=False)

            if error:
                self.stepChanged.emit(f'ORANGE|    Конвертация прошла с ошибками. Павила фильтрации контента выгружены в файл "{json_file}".')
                self.error = 1
            else:
                self.stepChanged.emit(f'GREEN|    Павила фильтрации контента выгружены в файл "{json_file}".')
        else:
            self.stepChanged.emit('GRAY|    Нет правил фильтрации контента для экспорта.')


    def convert_dnat_rule(self, config_array):
        """Конвертируем правил DNAT"""
        self.stepChanged.emit('BLUE|Конвертация правил DNAT.')
        error = 0
        rules = []
        n = 0

        for item in config_array:
            src_zones = []
            rule_src_ips = []

            source = self.compress_block(item['variable'])
            error, rule_name = self.get_transformed_name(source['Name'], err=error, descr='Имя правила DNAT')
            if source['DNAT']:
                for param in item['variable']:
                    if param['@name'] == 'Src':
                        if param['#text']:
                            if self.check_ip(param['#text']):
                                if param['#text'] not in self.ip_lists:
                                    if not self.create_ip_list(param['#text']):
                                        self.stepChanged.emit(f'RED|    ERROR: [Правило DNAT "{rule_name}"] В адрес источника не добавлен IP-лист: "{param["#text"]}".')
                                        error = 1
                                        continue
                                rule_src_ips.append(['list_id', self.ip_lists[param['#text']]])
                            else:
                                src_val = param['#text'].split(':')
                                if src_val[0] == 'iface':
                                    if src_val[1] in self.zones:
                                        src_zones.append(src_name)
                rule = {
                    'name': rule_name,
                    'description': source['Description'],
                    'action': 'dnat',
                    'position': 'last',
                    'zone_in': src_zones,
                    'zone_out': [],
                    'source_ip': rule_src_ips,
                    'dest_ip': [],
                    'service': [],
                    'target_ip': '',
                    'gateway': '',
                    'enabled': True if int(source['Enabled']) else False,
                    'log': False,
                    'log_session_start': False,
                    'target_snat': True,
                    'snat_target_ip': '',
                    'zone_in_nagate': False,
                    'zone_out_nagate': False,
                    'source_ip_nagate': False,
                    'dest_ip_nagate': False,
                    'port_mappings': [],
                    'direction': "input",
                    'users': [],
                    'scenario_rule_id': False,
                }

                rule['target_ip'], service = source['DNAT'].split()
                if source['Service']:
                    tmp_serv = [x.strip('"') for x in source['Service'].split()]
                    if len(tmp_serv) == 1 and ':' in source['Service']:
                        proto, port = source['Service'].split(':')
                        service_name = self.create_service(port, proto=proto)
                        rule['service'].append(['service', service_name])
                    else:
                        for x in tmp_serv:
                            if x in self.services:
                                rule['service'].append(['service', x])
                            elif x in self.service_groups:
                                rule['service'].append(['list_id', x])
                            else:
                                self.stepChanged.emit(f'RED|    ERROR: [Правило DNAT "{rule_name}"] Не найден сервис: "{x}".')
                                error = 1
                else:
                    tag, port = service.split(':')
                    if tag == 'port':
                        service_name = self.create_service(port, proto='tcp')
                        rule['service'].append(['service', service_name])

                rules.append(rule)
                n += 1
                self.stepChanged.emit(f'BLACK|    {n} - Создано правило DNAT "{rule["name"]}".')

        if rules:
            current_path = os.path.join(self.current_ug_path, 'NetworkPolicies', 'NATandRouting')
            err, msg = self.create_dir(current_path)
            if err:
                self.stepChanged.emit(f'RED|    {msg}')
                self.error = 1
                return

            json_file = os.path.join(current_path, 'config_nat_rules.json')
            with open(json_file, 'w') as fh:
                json.dump(rules, fh, indent=4, ensure_ascii=False)

            if error:
                self.stepChanged.emit(f'ORANGE|    Конвертация прошла с ошибками. Правила DNAT выгружены в файл "{json_file}".')
                self.error = 1
            else:
                self.stepChanged.emit(f'GREEN|    Правила DNAT выгружены в файл "{json_file}".')
        else:
            self.stepChanged.emit('GRAY|    Нет правил DNAT для экспорта.')


############################################# Служебные функции ###################################################
    def create_url_list(self, url):
        """Создать URL-лист для правила"""
        if url.startswith('*/') or url.startswith('/'):
            return False
        elif '?' in url or ' ' in url:
            return False

        error, list_name = self.get_transformed_name(url, descr='Имя списка URL')
        url_list = {
            'name': list_name,
            'description': 'Портировано с Kerio.',
            'type': 'url',
            'url': '',
            'list_type_update': 'static',
            'schedule': 'disabled',
            'attributes': {'list_compile_type': 'case_insensitive'},
            'content': [{'value': url}]
        }
        self.url_lists[url] = list_name

        current_path = os.path.join(self.current_ug_path, 'Libraries', 'URLLists')
        err, msg = self.create_dir(current_path, delete='no')
        if err:
            self.stepChanged.emit(f'RED|    {msg}')
            return False

        json_file = os.path.join(current_path, f'{url_list["name"].translate(self.trans_filename)}.json')
        with open(json_file, 'w') as fh:
            json.dump(url_list, fh, indent=4, ensure_ascii=False)
        self.stepChanged.emit(f'NOTE|    Создан список URL "{url_list["name"]}" и выгружен в файл "{json_file}".')

        return True


    def create_ip_list(self, ip):
        """Создать URL-лист для правила"""
        ip_list = {
            'name': ip,
            'description': 'Портировано с Kerio.',
            'type': 'network',
            'url': '',
            'list_type_update': 'static',
            'schedule': 'disabled',
            'attributes': {'threat_level': 3},
            'content': [{'value': ip}]
        }
        self.ip_lists[ip] = ip

        current_path = os.path.join(self.current_ug_path, 'Libraries', 'IPAddresses')
        err, msg = self.create_dir(current_path, delete='no')
        if err:
            self.stepChanged.emit(f'RED|    {msg}')
            return False

        json_file = os.path.join(current_path, f'{ip_list["name"].translate(self.trans_filename)}.json')
        with open(json_file, 'w') as fh:
            json.dump(ip_list, fh, indent=4, ensure_ascii=False)
        self.stepChanged.emit(f'NOTE|    Создан IP-лист  "{ip_list["name"]}" и выгружен в файл "{json_file}".')

        return True


    def create_service(self, port, proto='tcp'):
        """Создать сервис для правила DNAT"""
        service_name = f'{proto}-{port}'
        if service_name not in self.services:
            new_service = {
                'name': service_name,
                'description': 'Портировано с Kerio для DNAT.',
                'protocols': [
                    {
                        'proto': proto,
                        'port': port,
                        'app_proto': '',
                        'source_port': '',
                        'alg': ''
                    }
                ]
            }
            self.services[service_name] = new_service
        return service_name


def main(args):
    return 0

if __name__ == '__main__':
    import sys
    sys.exit(main(sys.argv))
