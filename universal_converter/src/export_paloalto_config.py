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
# Модуль преобразования конфигурации с PaloAlto в формат UserGate.
# Версия 1.1  27.10.2025
#

import os, sys, copy, json
import xmltodict
from PyQt6.QtCore import QThread, pyqtSignal
from common_classes import MyConv
from services import zone_services, ug_services, ip_proto, GEOIP_CODE


class ConvertPaloaltoConfig(QThread, MyConv):
    """Преобразуем файл конфигурации PaloAlto в формат UserGate."""
    stepChanged = pyqtSignal(str)

    def __init__(self, current_pa_path, current_ug_path):
        super().__init__()
        self.current_pa_path = current_pa_path
        self.current_ug_path = current_ug_path
        self.local_users = {}
        self.local_groups = set()
        self.services = {}
        self.service_groups = set()
        self.ip_lists = {}
        self.url_lists = set()
        self.ip_lists_groups = set()
        self.tags = set()
        self.zones = set()

        self.time_restrictions = set()
        self.vendor = 'PaloAlto'
        self.error = 0

    def run(self):
        self.stepChanged.emit(f'GREEN|{"Конвертация конфигурации PaloAlto в формат UserGate.":>110}')
        self.stepChanged.emit(f'ORANGE|{"="*110}')
        self.convert_config_file()

        if self.error:
            self.stepChanged.emit('iRED|Конвертация конфигурации PaloAlto в формат UserGate прервана.')
        else:
            json_file = os.path.join(self.current_pa_path, 'config.json')
            err, data = self.read_json_file(json_file)
            if err:
                self.stepChanged.emit('iRED|Конвертация конфигурации PaloAlto в формат UserGate прервана.\n')
            else:
                if data['config']['shared'].get('local-user-database', False):  # Проверяем что есть локальные users и groups
                    self.convert_local_users_and_groups(data['config']['shared']['local-user-database'])
                lib = data['config']['devices']['entry']['vsys']['entry']
                if isinstance(lib, list):
                    lib = lib[0]
                self.convert_services(lib['service'])
                if lib['service-group']:
                    self.convert_service_groups(lib['service-group']['entry'])
                if lib['address']:
                    self.convert_ip_lists(lib['address']['entry'])
                    self.convert_url_lists(lib['address']['entry'])
                if lib['address-group']:
                    self.convert_iplist_groups(lib['address-group']['entry'])
                if lib['tag']:
                    self.convert_tags(lib['tag']['entry'])
                if lib['zone']:
                    self.convert_zone_settings(lib['zone']['entry'])
                network = data['config']['devices']['entry']['network']
                self.convert_vlan_interfaces(network)
                if isinstance(network['virtual-router']['entry'], dict):
                    network['virtual-router']['entry'] = [network['virtual-router']['entry']]
                    self.convert_vrfs(network['virtual-router']['entry'])
                systemconfig = data['config']['devices']['entry']['deviceconfig']['system']
                self.convert_settings_ui(systemconfig)
                self.convert_dns_servers(systemconfig)
                self.convert_ntp_settings(systemconfig)
                if lib['rulebase'] and lib['rulebase']['security'] and lib['rulebase']['security']['rules']:
                    self.convert_firewall_policy(lib['rulebase']['security']['rules']['entry'])
                if lib['rulebase'] and lib['rulebase']['nat'] and lib['rulebase']['nat']['rules']:
                    self.convert_nat_rule(lib['rulebase']['nat']['rules']['entry'])

#                self.convert_time_sets(data)
#                self.convert_auth_servers(data)
#                print(json.dumps(self.ip_lists, indent=4, ensure_ascii=False))

                if self.error:
                    self.stepChanged.emit('iORANGE|Конвертация конфигурации PaloAlto в формат UserGate прошла с ошибками.\n')
                else:
                    self.stepChanged.emit('iGREEN|Конвертация конфигурации PaloAlto в формат UserGate прошла успешно.\n')


    def convert_config_file(self):
        """Преобразуем файл конфигурации PaloAlto в формат json."""
        self.stepChanged.emit('BLUE|Конвертация файла конфигурации PaloAlto в формат json.')
        if not os.path.isdir(self.current_pa_path):
            self.stepChanged.emit('RED|    Не найден каталог с конфигурацией PaloAlto.')
            self.error = 1
            return

        config_file = os.path.join(self.current_pa_path, 'config.xml')
        try:
            with open(config_file, 'r') as fh:
                data = fh.read()
        except FileNotFoundError:
            self.stepChanged.emit(f'RED|    Не найден файл "{config_file}" с конфигурацией PaloAlto.')
            self.error = 1
            return

        dict_data = xmltodict.parse(data)

        json_file = os.path.join(self.current_pa_path, 'config.json')
        with open(json_file, 'w') as fh:
            json.dump(dict_data, fh, indent=4, ensure_ascii=False)

        self.stepChanged.emit(f'GREEN|    Конфигурация PaloAlto в формате json выгружена в файл "{json_file}".')


    #----------------------------------- Конвертация ------------------------------------------------
    def convert_local_users_and_groups(self, local_users_database):
        """Конвертируем локальных пользователей и группы"""
        self.stepChanged.emit('BLUE|Конвертация локальных пользователей и групп.')

        if local_users_database['user']:
            for user in local_users_database['user']['entry']:
                auth_login = self.get_transformed_userlogin(user['@name'])
                self.local_users[auth_login] = {
                    'name': auth_login,
                    'enabled': False if user.get('disabled', None) == 'yes' else True,
                    'auth_login': auth_login,
                    'is_ldap': False,
                    'static_ip_addresses': [],
                    'ldap_dn': '',
                    'emails': [],
                    'phones': [],
                    'first_name': '',
                    'last_name': '',
                    'groups': [],
                }

        groups = []
        if local_users_database['user-group']:
            for item in local_users_database['user-group']['entry']:
                group = {
                    'name': item['@name'],
                    'description': 'Портировано с PaloAlto.',
                    'is_ldap': False,
                    'is_transient': False,
                    'users': []
                }
                if item['user']['member']:
                    if isinstance(item['user']['member'], list):
                        group['users'] = item['user']['member']
                    else:
                        group['users'].append(item['user']['member'])

                    for user in group['users']:
                        self.local_users[user]['groups'].append(group['name'])

                    groups.append(group)
                    self.local_groups.add(group['name'])

        if groups:
            current_path = os.path.join(self.current_ug_path, 'UsersAndDevices', 'Groups')
            err, msg = self.create_dir(current_path)
            if err:
                self.stepChanged.emit(f'RED|    {msg}')
                self.error = 1
                return

            json_file = os.path.join(current_path, 'config_groups.json')
            with open(json_file, 'w') as fh:
                json.dump(groups, fh, indent=4, ensure_ascii=False)
            self.stepChanged.emit(f'GREEN|    Список локальных групп пользователей выгружен в файл "{json_file}".')
        else:
            self.stepChanged.emit('GRAY|    Нет локальных групп пользователей для экспорта.')

        if self.local_users:
            current_path = os.path.join(self.current_ug_path, 'UsersAndDevices', 'Users')
            err, msg = self.create_dir(current_path)
            if err:
                self.stepChanged.emit(f'RED|    {msg}.')
                self.error = 1
                return

            json_file = os.path.join(current_path, 'config_users.json')
            with open(json_file, 'w') as fh:
                json.dump([x for x in self.local_users.values()], fh, indent=4, ensure_ascii=False)
            self.stepChanged.emit(f'GREEN|    Список локальных пользователей выгружен в файл "{json_file}".')
        else:
            self.stepChanged.emit('GRAY|    Нет локальных пользователей для экспорта.')


    def convert_services(self, pa_services):
        """Конвертируем сетевые сервисы."""
        self.stepChanged.emit('BLUE|Конвертация сетевых сервисов.')
        services = {}

        if pa_services:
            for item in pa_services['entry']:
                services[item['@name']] = {
                    'name': item['@name'],
                    'description': item.get('description', 'Портировано с PaloAlto.'),
                    'protocols': []
                }
                for key, value in item['protocol'].items():
                    services[item['@name']]['protocols'].append({
                        'proto': key,
                        'port': value['port'],
                        'app_proto': '',
                        'source_port': value.get('source-port', ''),
                        'alg': ''
                    })
            for key, value in {'service-http': '80', 'service-https': '443'}.items():
                services[key] = {
                    'name': key,
                    'description': f'Сервис {key}\nПортировано с PaloAlto.',
                    'protocols': [{
                        'proto': 'tcp',
                        'port': value,
                        'app_proto': '',
                        'source_port': '',
                        'alg': ''
                    }]
                }

            current_path = os.path.join(self.current_ug_path, 'Libraries', 'Services')
            err, msg = self.create_dir(current_path)
            if err:
                self.stepChanged.emit(f'RED|    {msg}')
                self.error = 1
                return

            json_file = os.path.join(current_path, 'config_services_list.json')
            with open(json_file, 'w') as fh:
                json.dump(list(services.values()), fh, indent=4, ensure_ascii=False)
            self.services = services
            self.stepChanged.emit(f'GREEN|    Сервисы выгружены в файл "{json_file}".')
        else:
            self.stepChanged.emit('GRAY|    Нет сетевых сервисов для экспорта.')


    def convert_service_groups(self, pa_servicegroups):
        """Конвертируем группы сервисов"""
        self.stepChanged.emit('BLUE|Конвертация групп сервисов.')
        services_groups = []

        if isinstance(pa_servicegroups, dict):
            pa_servicegroups = [pa_servicegroups]

        for item in pa_servicegroups:
            srv_group = {
                'name': item['@name'],
                'description': item.get('description', 'Портировано с PaloAlto.'),
                'type': 'servicegroup',
                'url': '',
                'list_type_update': 'static',
                'schedule': 'disabled',
                'attributes': {},
                'content': []
            }
            for member in item['members']['member']:
                service = copy.deepcopy(self.services.get(member, None))
                if service:
                    for x in service['protocols']:
                        x['src_port'] = x.pop('source_port', '')
                        x.pop('app_proto', None)
                        x.pop('alg', None)
                    srv_group['content'].append(service)

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


    def convert_ip_lists(self, pa_iplists):
        """Конвертируем списки IP-адресов"""
        self.stepChanged.emit('BLUE|Конвертация списков IP-адресов.')
        current_path = os.path.join(self.current_ug_path, 'Libraries', 'IPAddresses')
        err, msg = self.create_dir(current_path)
        if err:
            self.stepChanged.emit(f'RED|    {msg}')
            self.error = 1
            return

        n = 0
        error = 0
        file_names = set()

        if isinstance(pa_iplists, dict):
            pa_iplists = [pa_iplists]

        for item in pa_iplists:
            content = []
            if 'ip-netmask' in item:
                content.append({'value': item['ip-netmask']})
            elif 'ip-range' in item:
                content.append({'value': item['ip-range']})
            if content:
                number_for_ip_list = 1
                error, iplist_name = self.get_transformed_name(item['@name'], err=error, descr='Имя списка IP-адресов')
                ip_list = {
                    'name': iplist_name,
                    'description': item.get('description', 'Портировано с PaloAlto.'),
                    'type': 'network',
                    'url': '',
                    'list_type_update': 'static',
                    'schedule': 'disabled',
                    'attributes': {'threat_level': 3},
                    'content': content
                }

                n += 1
                self.ip_lists[ip_list['name']] = content[0]['value']
                file_name = ip_list['name'].translate(self.trans_filename)
                while file_name in file_names:
                    file_name = f'{file_name}-{number_for_ip_list}'
                    number_for_ip_list += 1
                file_names.add(file_name)

                json_file = os.path.join(current_path, f'{file_name}.json')
                with open(json_file, 'w') as fh:
                    json.dump(ip_list, fh, indent=4, ensure_ascii=False)
                    self.stepChanged.emit(f'BLACK|       {n} - Список IP-адресов "{ip_list["name"]}" выгружен в файл "{json_file}".')
        if error:
            self.stepChanged.emit(f'ORANGE|    Конвертация списков IP-адресов прошла с ошибками. Списки IP-адресов выгружены в каталог "{current_path}".')
            self.error = 1
        else:
            self.stepChanged.emit(f'GREEN|    Списки IP-адресов выгружены в каталог "{current_path}".')


    def convert_url_lists(self, pa_urllists):
        """Конвертируем списки URL"""
        self.stepChanged.emit('BLUE|Конвертация списков URL.')
        current_path = os.path.join(self.current_ug_path, 'Libraries', 'URLLists')
        err, msg = self.create_dir(current_path)
        if err:
            self.stepChanged.emit(f'RED|    {msg}')
            self.error = 1
            return

        n = 0
        error = 0
        if isinstance(pa_urllists, dict):
            pa_urllists = [pa_urllists]

        for item in pa_urllists:
            if 'fqdn' in item:
                error, list_name = self.get_transformed_name(item['@name'], err=error, descr='Имя списка URL')
                url_list = {
                    'name': list_name,
                    'description': item.get('description', 'Портировано с PaloAlto.'),
                    'type': 'url',
                    'url': '',
                    'list_type_update': 'static',
                    'schedule': 'disabled',
                    'attributes': {'list_compile_type': 'case_insensitive'},
                    'content': [{'value': item['fqdn']}]
                }

                n += 1
                self.url_lists.add(url_list['name'])

                json_file = os.path.join(current_path, f'{url_list["name"].translate(self.trans_filename)}.json')
                with open(json_file, 'w') as fh:
                    json.dump(url_list, fh, indent=4, ensure_ascii=False)
                self.stepChanged.emit(f'BLACK|       {n} - Список URL "{url_list["name"]}" выгружен в файл "{json_file}".')

        if error:
            self.stepChanged.emit(f'ORANGE|    Конвертация списков URL прошла с ошибками. Списки URL выгружены в каталог "{current_path}".')
            self.error = 1
        else:
            self.stepChanged.emit(f'GREEN|    Списки URL выгружены в каталог "{current_path}".')


    def convert_iplist_groups(self, pa_iplist_groups):
        """Конвертируем группы IP-адресов"""
        self.stepChanged.emit('BLUE|Конвертация групп IP-адресов.')
        current_path = os.path.join(self.current_ug_path, 'Libraries', 'IPAddresses')

        n = 0
        error = 0
        if isinstance(pa_iplist_groups, dict):
            pa_iplist_groups = [pa_iplist_groups]

        for item in pa_iplist_groups:
            error, iplist_name = self.get_transformed_name(item['@name'], err=error, descr='Имя списка групп IP-адресов')
            if isinstance(item['static']['member'], str):
                item['static']['member'] = [item['static']['member']]
            ip_list = {
                'name': iplist_name,
                'description': item.get('description', 'Портировано с PaloAlto.'),
                'type': 'network',
                'url': '',
                'list_type_update': 'static',
                'schedule': 'disabled',
                'attributes': {'threat_level': 3},
                'content': [{'list': x} for x in item['static']['member'] if x in self.ip_lists]
            }

            n += 1
            self.ip_lists_groups.add(ip_list['name'])

            json_file = os.path.join(current_path, f'{ip_list["name"].translate(self.trans_filename)}.json')
            with open(json_file, 'w') as fh:
                json.dump(ip_list, fh, indent=4, ensure_ascii=False)
                self.stepChanged.emit(f'BLACK|       {n} - Группа IP-адресов "{ip_list["name"]}" выгружена в файл "{json_file}".')
        if error:
            self.stepChanged.emit(f'ORANGE|    Конвертация группы IP-адресов прошла с ошибками. Группа IP-адресов выгружена в каталог "{current_path}".')
            self.error = 1
        else:
            self.stepChanged.emit(f'GREEN|    Группа IP-адресов выгружена в каталог "{current_path}".')


    def convert_tags(self, pa_tags):
        """Конвертируем тэги."""
        self.stepChanged.emit('BLUE|Конвертация тэгов.')
        current_path = os.path.join(self.current_ug_path, 'Libraries', 'Tags')
        err, msg = self.create_dir(current_path)
        if err:
            self.stepChanged.emit(f'RED|    {msg}')
            self.error = 1
            return

        n = 0
        colors = {
            'color1': 'red',
            'color2': 'orange',
            'color3': 'yellow',
            'color4': 'green',
            'color5': 'aqua',
            'color6': 'blue',
            'color7': 'violet',
            'color8': 'pink',
            'color9': 'purple',
            'color10': 'gray',
        }
        tags = []
        if isinstance(pa_tags, dict):
            pa_tags = [pa_tags]

        for item in pa_tags:
            _, tag_name = self.get_transformed_name(item['@name'], descr='Имя тэга', mode=0)
            color = item.get('color', 'no_color')
            tags.append({
                'name': tag_name,
                'description': item.get('description', 'Портировано с PaloAlto.'),
                'html_color': colors.get(color, 'no_color')
            })
            self.tags.add(tag_name)

        if tags:
            json_file = os.path.join(current_path, 'config_tags.json')
            with open(json_file, 'w') as fh:
                json.dump(tags, fh, indent=4, ensure_ascii=False)
            self.stepChanged.emit(f'GREEN|    Тэги выгружены в файл "{json_file}".')
        else:
            self.stepChanged.emit('GRAY|    Нет тэгов для экспорта.')



    def convert_vlan_interfaces(self, network):
        """Конвертируем интерфейсы VLAN."""
        self.stepChanged.emit('BLUE|Конвертация интерфейсов VLAN.')
        error = 0
        ifaces = []
        if network['interface']['vlan']['units']:
            pass

        if network['interface']['aggregate-ethernet']:
            if isinstance(network['interface']['aggregate-ethernet']['entry'], list):
                for item in network['interface']['aggregate-ethernet']['entry']:
                    self.create_vlans(item['layer3']['units'])
            elif isinstance(network['interface']['aggregate-ethernet']['entry'], dict):
                self.create_vlans(network['interface']['aggregate-ethernet']['entry']['layer3']['units'])


    def create_vlans(self, units):
        vlans = []
        ifaces = []
        if units:
            if isinstance(units['entry'], dict):
                vlans = [units['entry']]
            elif isinstance(units['entry'], list):
                vlans = units['entry']

        for item in vlans:
            if item.get('tag', False):
                iface = {
                    'name': item['@name'],
                    'kind': 'vlan',
                    'enabled': False,
                    'description': 'Портировано с PaloAlto.',
                    'zone_id': 0,
                    'master': False,
                    'netflow_profile': 'undefined',
                    'lldp_profile': 'undefined',
                    'ipv4': [],
                    'ifalias': '',
                    'flow_control': False,
                    'mode': 'manual',
                    'mtu': 1500,
                    'tap': False,
                    'dhcp_relay': {
                        'enabled': False,
                        'host_ipv4': '',
                        'servers': []
                    },
                    'vlan_id': int(item['tag']),
                    'link': ''
                }
                if item['ip']:
                    if isinstance(item['ip']['entry'], dict):
                        item['ip']['entry'] = [item['ip']['entry']]
                    for ip_entry in item['ip']['entry']:
                        if (ip_addr := self.check_ip(ip_entry['@name'])):
                            iface['ipv4'].append(ip_addr)
                            iface['mode'] = 'static'
                        elif ip_entry['@name'] in self.ip_lists:
                            iface['ipv4'].append(self.ip_lists[ip_entry['@name']])
                            iface['mode'] = 'static'
                        else:
                            self.stepChanged.emit(f'RED|    Error: Интерфейс VLAN "[iface["name"]]" - не валидный IP-адрес "{item["ip"]["entry"]["@name"]}".')
                ifaces.append(iface)

        if ifaces:
            current_path = os.path.join(self.current_ug_path, 'Network', 'Interfaces')
            err, msg = self.create_dir(current_path)
            if err:
                self.stepChanged.emit(f'RED|    {msg}')
                self.error = 1
                return

            json_file = os.path.join(current_path, 'config_interfaces.json')
            with open(json_file, 'w') as fh:
                json.dump(ifaces, fh, indent=4, ensure_ascii=False)
            self.stepChanged.emit(f'GREEN|    Интерфейсы VLAN выгружены в файл "{json_file}".')
        else:
            self.stepChanged.emit('GRAY|    Нет интерфейсов VLAN для экспорта.')


    def convert_vrfs(self, pa_vrfs):
        """Конвертируем список VRFs"""
        self.stepChanged.emit('BLUE|Конвертация шлюзов и virtual routers.')

        gateways_list = []
        ngfw_vrfs = []

        for vrf in pa_vrfs:
            new_vrf = {
                'name': vrf['@name'],
                'descriprion': '',
                'interfaces': [],
                'routes': [],
                'ospf': {},
                'bgp': {},
                'rip': {},
                'pimsm': {}
            }
            if vrf['routing-table'] and vrf['routing-table']['ip']['static-route']:
                routes = vrf['routing-table']['ip']['static-route']['entry']

                for item in routes:
                    # Конвертируем шлюзы
                    if item['destination'] == '0.0.0.0/0':
                        gateways_list.append({
                           'name': item['@name'],
                           'enabled': True,
                           'description': item.get('description', 'Портировано с PaloAlto.'),
                           'ipv4': item['nexthop']['ip-address'],
                           'vrf': new_vrf['name'],
                           'weight': int(item.get('metric', 1)),
                           'multigate': False,
                           'default': False,
                           'iface': 'undefined',
                           'is_automatic': False
                        })
                    else:
                        # Конвертируем статические маршруты
                        route = {
                            'name': item['@name'],
                            'description': item.get('description', 'Портировано с PaloAlto.'),
                            'enabled': True,
                            'dest': item['destination'],
                            'gateway': item['nexthop']['ip-address'],
                            'ifname': 'undefined',
                            'kind': 'unicast',
                            'metric': int(item.get('metric', 1))
                        }
                        new_vrf['routes'].append(route)
            ngfw_vrfs.append(new_vrf)

        if gateways_list:
            current_path = os.path.join(self.current_ug_path, 'Network', 'Gateways')
            err, msg = self.create_dir(current_path)
            if err:
                self.stepChanged.emit(f'RED|    {msg}')
                self.error = 1
                return

            json_file = os.path.join(current_path, 'config_gateways.json')
            with open(json_file, 'w') as fh:
                json.dump(gateways_list, fh, indent=4, ensure_ascii=False)
            self.stepChanged.emit(f'GREEN|    Список шлюзов выгружен в файл "{json_file}".')
        else:
            self.stepChanged.emit('GRAY|    Нет списка шлюзов для экспорта.')

        if ngfw_vrfs:
            current_path = os.path.join(self.current_ug_path, 'Network', 'VRF')
            err, msg = self.create_dir(current_path)
            if err:
                self.stepChanged.emit(f'RED|    {msg}')
                self.error = 1
                return

            json_file = os.path.join(current_path, 'config_vrf.json')
            with open(json_file, 'w') as fh:
                json.dump(ngfw_vrfs, fh, indent=4, ensure_ascii=False)
            self.stepChanged.emit(f'GREEN|    Virtual Routers выгружены в файл "{json_file}".')
        else:
            self.stepChanged.emit('GRAY|    Нет Virtual Routers для экспорта.')


    def convert_settings_ui(self, sysconfig):
        """Конвертируем часовой пояс"""
        self.stepChanged.emit('BLUE|Конвертация часового пояса.')

        if sysconfig.get('timezone', None):
            settings = {'ui_timezone': sysconfig['timezone']}

            current_path = os.path.join(self.current_ug_path, 'UserGate', 'GeneralSettings')
            err, msg = self.create_dir(current_path, delete='no')
            if err:
                self.stepChanged.emit(f'RED|    {msg}')
                self.error = 1
                return

            json_file = os.path.join(current_path, 'config_settings_ui.json')
            with open(json_file, 'w') as fh:
                json.dump(settings, fh, indent=4, ensure_ascii=False)
            self.stepChanged.emit(f'GREEN|    Настройка часового пояса выгружена в файл "{json_file}".')
        else:
            self.stepChanged.emit('GRAY|    Нет часового пояса для экспорта.')


    def convert_dns_servers(self, sysconfig):
        """Заполняем список системных DNS"""
        self.stepChanged.emit('BLUE|Конвертация настроек DNS.')
        dns_servers = []

        if sysconfig.get('dns-setting', None):
            if sysconfig['dns-setting'].get('servers', None):
                if sysconfig['dns-setting']['servers'].get('primary', None):
                    dns_servers.append({'dns': sysconfig['dns-setting']['servers']['primary'], 'is_bad': False})
                if sysconfig['dns-setting']['servers'].get('secondary', None):
                    dns_servers.append({'dns': sysconfig['dns-setting']['servers']['secondary'], 'is_bad': False})


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
            self.stepChanged.emit('GRAY|    Нет настроек DNS для экспорта.')


    def convert_ntp_settings(self, sysconfig):
        """Конвертируем настройки NTP"""
        self.stepChanged.emit('BLUE|Конвертация настроек NTP.')
        ntp_conf = {
            'ntp_servers': [],
            'ntp_enabled': True,
            'ntp_synced': True
        }

        if sysconfig.get('ntp-servers', None):
            ntp_conf['ntp_servers'].append(sysconfig['ntp-servers']['primary-ntp-server']['ntp-server-address'])
            if sysconfig['ntp-servers'].get('secondary-ntp-server', None):
                ntp_conf['ntp_servers'].append(sysconfig['ntp-servers']['secondary-ntp-server']['ntp-server-address'])

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


    def convert_firewall_policy(self, firewall_rules):
        """Конвертируем правила МЭ"""
        self.stepChanged.emit('BLUE|Конвертация правил межсетевого экрана.')
        message = (
            '    После импорта правил МЭ, необходимо в каждом правиле указать зону источника и зону назначения.\n'
            '    Создайте необходимое количество зон и присвойте зону каждому интерфейсу.'
        )
        self.stepChanged.emit(f'LBLUE|{message}')

        error = 0
        n = 0
        rules = []
        for item in firewall_rules:
            error, rule_name = self.get_transformed_name(item['@name'], err=error, descr='Имя правила МЭ')
            rule = {
                'name': rule_name,
                'description': item.get('description', 'Портировано с PaloAlto.'),
                'action': 'accept' if item.get('action', None) == 'allow' else 'drop',
                'position': 'last',
                'scenario_rule_id': False,     # При импорте заменяется на UID или "0". 
                'src_zones': self.get_zones(item['from']['member']),
                'dst_zones': self.get_zones(item['to']['member']),
                'src_ips': [],
                'dst_ips': [],
                'services': [],
                'apps': [],
                'users': [],
                'enabled': True,
                'limit': True,
                'limit_value': '3/h',
                'limit_burst': 5,
                'log': True,
                'log_session_start': True,
                'src_zones_negate': False,
                'dst_zones_negate': False,
                'src_ips_negate': False,
                'dst_ips_negate': False,
                'services_negate': False,
                'apps_negate': False,
                'fragmented': 'ignore',
                'time_restrictions': [],
                'send_host_icmp': '',
                'rule_error': 0,
            }
            rule['src_ips'] = self.get_ips('src', item['source']['member'], rule)
            rule['dst_ips'] = self.get_ips('dst', item['destination']['member'], rule)
            rule['services'] = self.get_services(item['service']['member'], rule)
            self.get_users_and_groups(item['source-user']['member'], rule)
#            self.get_time_restrictions(value['schedule'], rule)
            if 'tag' in item:
                self.get_tags(item['tag']['member'], rule)

            if rule['rule_error']:
                rule['name'] = f'ERROR - {rule["name"]}'
                rule['enabled'] = False
                error = 1
            rule.pop('rule_error', None)

            rules.append(rule)
            n += 1
            self.stepChanged.emit(f'BLACK|    {n} - Создано правило МЭ "{rule["name"]}".')

        if rules:
            current_path = os.path.join(self.current_ug_path, 'NetworkPolicies', 'Firewall')
            err, msg = self.create_dir(current_path)
            if err:
                self.stepChanged.emit(f'RED|    {msg}')
                self.error = 1
                return

            json_file = os.path.join(current_path, 'config_firewall_rules.json')
            with open(json_file, 'w') as fh:
                json.dump(rules, fh, indent=4, ensure_ascii=False)

            if error:
                self.stepChanged.emit(f'ORANGE|    Конвертация прошла с ошибками. Павила межсетевого экрана выгружены в файл "{json_file}".')
                self.error = 1
            else:
                self.stepChanged.emit(f'GREEN|    Павила межсетевого экрана выгружены в файл "{json_file}".')
        else:
            self.stepChanged.emit('GRAY|    Нет правил межсетевого экрана для экспорта.')


    def convert_nat_rule(self, nat_rules):
        """Конвертируем правила NAT, DNAT и Port-форвардинга"""
        self.stepChanged.emit('BLUE|Конвертация правил NAT.')
        error = 0
        rules = []

        for item in nat_rules:
            error, rule_name = self.get_transformed_name(item['@name'], err=error, descr='Имя правила NAT')
            rule = {
                'name': rule_name,
                'description': item.get('description', 'Портировано с PaloAlto.'),
                'action': 'nat',
                'position': 'last',
                'zone_in': self.get_zones(item['from']['member']),
                'zone_out': self.get_zones(item['to']['member']),
                'source_ip': [],
                'dest_ip': [],
                'service': [],
                'target_ip': '',
                'gateway': '',
                'enabled': True if item.get('disabled', None) == 'no' else False,
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
                'rule_error': 0,
            }
            rule['service'] = self.get_services(item['service'], rule)
            if 'source' in item:
                rule['source_ip'] = self.get_ips('src', item['source']['member'], rule)
            if 'destination' in item:
                rule['dest_ip'] = self.get_ips('dst', item['destination']['member'], rule)
            if 'tag' in item:
                self.get_tags(item['tag']['member'], rule)

            if 'source-translation' in item:
                if 'dynamic-ip-and-port' in item['source-translation']:
                    rule['snat_target_ip'] = self.ip_lists[item['source-translation']['dynamic-ip-and-port']['interface-address']['ip']].partition('/')[0]
                elif 'static-ip' in item['source-translation']:
                    rule['snat_target_ip'] = self.ip_lists[item['source-translation']['static-ip']['translated-address']].partition('/')[0]

            elif 'destination-translation' in item:
                dnat_ip = item['destination-translation']['translated-address']
                rule['target_ip'] = self.ip_lists.get(dnat_ip, dnat_ip).partition('/')[0]
                trans_port = item['destination-translation']['translated-port']
                try:
                    dport = self.services[item['service']]['protocols'][0]['port']
                    proto = self.services[item['service']]['protocols'][0]['proto']
                except KeyError:
                    error = 1
                else:
                    if trans_port == dport:
                        rule['action'] = 'dnat'
                    else:
                        rule['action'] = 'port_mapping'
                        try:
                            port_mappings = {
                                'proto': proto,
                                'src_port': int(dport),
                                'dst_port': int(trans_port)
                            }
                            rule['port_mappings'].append(port_mappings)
                        except ValueError:
                            pass

            if rule['rule_error']:
                rule['name'] = f'ERROR - {rule["name"]}'
                rule['enabled'] = False
                error = 1
            rule.pop('rule_error', None)

            rules.append(rule)
            self.stepChanged.emit(f'BLACK|    Создано правило {rule["action"]} "{rule["name"]}".')

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
                self.stepChanged.emit(f'ORANGE|    Конвертация прошла с ошибками. Правила NAT выгружены в файл "{json_file}".')
                self.error = 1
            else:
                self.stepChanged.emit(f'GREEN|    Правила NAT выгружены в файл "{json_file}".')
        else:
            self.stepChanged.emit('GRAY|    Нет правил DNAT/Порт-форвардинга для экспорта.')


    def convert_zone_settings(self, zones):
        """Конвертируем зоны"""
        self.stepChanged.emit('BLUE|Конвертация Зон.')
        new_zones = []

        for item in zones:
            new_zones.append({
                'name': item['@name'],
                'description': 'Портировано с PaloAlto.',
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
            self.zones.add(item['@name'])

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


#------------------------------------------------------------------------------------------------------------------
    def convert_time_sets(self, data):
        """Конвертируем time set (календари)"""
        self.stepChanged.emit('BLUE|Конвертация календарей.')
        week = {
            'monday': 1,
            'tuesday': 2,
            'wednesday': 3,
            'thursday': 4,
            'friday': 5,
            'saturday': 6,
            'sunday': 7
        }
        timerestrictiongroup = []
        error = 0

        if 'config firewall schedule onetime' in data:
            for key, value in data['config firewall schedule onetime'].items():
                if value:
                    error, schedule_name = self.get_transformed_name(key, err=error, descr='Имя календаря')
                    time_set = {
                        'name': schedule_name,
                        'description': 'Портировано с PaloAlto',
                        'type': 'timerestrictiongroup',
                        'url': '',
                        'list_type_update': 'static',
                        'schedule': 'disabled',
                        'attributes': {},
                        'content': []
                    }
                    content = {
                        'name': schedule_name,
#                        'type': 'range',
                        'type': 'span',
                    }
                    if 'start' in value and 'end' in value:
                        start = value['start'].split()
                        end = value['end'].split()
                        content['time_to'] = end[0]
                        content['time_from'] = start[0]
                        content['fixed_date_to'] = f'{end[1].replace("/", "-")}T00:00:00'
                        content['fixed_date_from'] = f'{start[1].replace("/", "-")}T00:00:00'
                    elif 'start' not in value:
                        time_to, fixed_date_to = value['end'].split()
#                        content['type'] = 'span'
                        content['time_to'] = time_to
                        content['fixed_date_to'] = f'{fixed_date_to.replace("/", "-")}T00:00:00'
                    elif 'end' not in value:
                        time_from, fixed_date_from = value['start'].split()
#                        content['type'] = 'span'
                        content['time_from'] = time_from
                        content['fixed_date_from'] = f'{fixed_date_from.replace("/", "-")}T00:00:00'
                    time_set['content'].append(content)

                    timerestrictiongroup.append(time_set)
                    self.time_restrictions.add(time_set['name'])

        if 'config firewall schedule recurring' in data:
            for key, value in data['config firewall schedule recurring'].items():
                if value:
                    error, schedule_name = self.get_transformed_name(key, err=error, descr='Имя календаря')
                    schedule = {
                        'name': schedule_name,
                        'description': 'Портировано с PaloAlto',
                        'type': 'timerestrictiongroup',
                        'url': '',
                        'list_type_update': 'static',
                        'schedule': 'disabled',
                        'attributes': {},
                        'content': []
                    }
                    if 'day' in value and value['day'] != 'none':
                        content = {
                            'type': 'weekly',
                            'name': schedule_name,
                            'days': [week[day] for day in value['day'].split()]
                        }
                    else:
                        content = {
                            'type': 'daily',
                            'name': schedule_name,
                        }
                    if 'start' in value:
                        content['time_from'] = value['start']
                        content['time_to'] = value['end']
                    schedule['content'].append(content)

                    timerestrictiongroup.append(schedule)
                    self.time_restrictions.add(schedule['name'])

        if timerestrictiongroup:
            current_path = os.path.join(self.current_ug_path, 'Libraries', 'TimeSets')
            err, msg = self.create_dir(current_path)
            if err:
                self.stepChanged.emit(f'RED|    {msg}')
                self.error = 1
                return

            json_file = os.path.join(current_path, 'config_calendars.json')
            with open(json_file, 'w') as fh:
                json.dump(timerestrictiongroup, fh, indent=4, ensure_ascii=False)

            if error:
                self.stepChanged.emit(f'ORANGE|    Конвертация календарей прошла с ошибками. Список календарей выгружен в файл "{json_file}".')
                self.error = 1
            else:
                self.stepChanged.emit(f'GREEN|    Список календарей выгружен в файл "{json_file}".')
        else:
            self.stepChanged.emit('GRAY|    Нет календарей для экспорта.')


    def convert_auth_servers(self, data):
        """Конвертируем сервера авторизации"""
        self.stepChanged.emit('BLUE|Конвертация серверов аутентификации.')
        ldap_servers = []
        radius_servers = []
        error = 0

        if 'config user ldap' in data:
            for key, value in data['config user ldap'].items():
                if value['dn']:
                    tmp_dn1 = [x.split('=') for x in value['dn'].split(',')]
                    tmp_dn2 = [b for a, b in tmp_dn1 if a in ['dc', 'DC']]
                    dn = '.'.join(tmp_dn2)
                error, rule_name = self.get_transformed_name(f'{key.strip()} - AD Auth server', err=error, descr='Имя календаря')
                ldap_servers.append({
                    'name': rule_name,
                    'description': 'LDAP-коннектор импортирован с PaloAlto.',
                    'enabled': False,
                    'ssl': True if value.get('secure', False) == 'ldaps' else False,
                    'address': value['server'],
                    'bind_dn': value['username'].replace('\\', '', 1),
                    'password': '',
                    'domains': [dn],
                    'roots': [value['dn']] if value['dn'] else [],
                    'keytab_exists': False
                })

        if 'config user radius' in data:
            for key, value in data['config user radius'].items():
                error, rule_name = self.get_transformed_name(f'{key.strip()} - Radius Auth server', err=error, descr='Имя календаря')
                radius_servers.append({
                    'name': rule_name,
                    'description': 'Radius auth server импортирован с PaloAlto.',
                    'enabled': False,
                    'addresses': [
                        {'host': value['server'], 'port': 1812}
                    ]
                })
                auth_login = self.get_transformed_userlogin(key)
                self.local_users[key] = {
                    'name': key,
                    'enabled': True,
                    'auth_login': auth_login,
                    'is_ldap': False,
                    'static_ip_addresses': [],
                    'ldap_dn': '',
                    'emails': [],
                    'phones': [],
                    'first_name': '',
                    'last_name': '',
                    'groups': [],
                }

        if ldap_servers or radius_servers:
            current_path = os.path.join(self.current_ug_path, 'UsersAndDevices', 'AuthServers')
            err, msg = self.create_dir(current_path)
            if err:
                self.stepChanged.emit(f'RED|    {msg}')
                self.error = 1
                return

            if ldap_servers:
                json_file = os.path.join(current_path, 'config_ldap_servers.json')
                with open(json_file, 'w') as fh:
                    json.dump(ldap_servers, fh, indent=4, ensure_ascii=False)
                self.stepChanged.emit(f'BLACK|    Настройки серверов аутентификации LDAP выгружены в файл "{json_file}".')
            if radius_servers:
                json_file = os.path.join(current_path, 'config_radius_servers.json')
                with open(json_file, 'w') as fh:
                    json.dump(radius_servers, fh, indent=4, ensure_ascii=False)
                self.stepChanged.emit(f'BLACK|    Настройки серверов аутентификации RADIUS выгружены в файл "{json_file}".')

            if error:
                self.stepChanged.emit('ORANGE|    Конвертация прошла с ошибками. Настройки серверов аутентификации конвертированы.')
                self.error = 1
            else:
                self.stepChanged.emit('GREEN|    Настройки серверов аутентификации конвертированы.')
        else:
            self.stepChanged.emit('GRAY|    Нет серверов аутентификации для экспорта.')


############################################# Служебные функции ###################################################
    def get_ips(self, mode, ips, rule):
        """
        Получить имена списков IP-адресов и URL-листов.
        Если списки не найдены, то они создаются или пропускаются, если невозможно создать."""
        new_rule_ips = []
        if ips != 'any':
            if isinstance(ips, str):
                ips = [ips]
            for item in ips:
                err, item = self.get_transformed_name(item, descr='Имя списка IP-адресов')
                if err:
                    self.stepChanged.emit(f'RED|       Error: Правило "{rule["name"]}".')
                if item in self.ip_lists or item in self.ip_lists_groups:
                    new_rule_ips.append(['list_id', item])
                elif item in self.url_lists:
                    new_rule_ips.append(['urllist_id', item])
                else:
                    if self.check_ip(item):
                        new_rule_ips.append(['list_id', self.create_ip_list(ips=[item], name=item, descr='Портировано с PaloAlto')])
                    else:
                        self.stepChanged.emit(f'RED|    Error: Не найден список {mode}-адресов "{item}" для правила "{rule["name"]}".')
                        rule['description'] = f'{rule["description"]}\nError: Не найден список {mode}-адресов "{item}".'
                        rule['rule_error'] = 1
        return new_rule_ips


    def get_services(self, rule_services, rule):
        """Получить список сервисов"""
        new_service_list = []
        if rule_services != 'any':
            if isinstance(rule_services, str):
                rule_services = [rule_services]
            for service in rule_services:
                _, service = self.get_transformed_name(service, descr='Имя ceрвиса', mode=0)
                if service in self.services:
                    new_service_list.append(['service', ug_services.get(service, service)])
                elif service in self.service_groups:
                    new_service_list.append(['list_id', service])
                else:
                    self.stepChanged.emit(f'RED|    Error: Не найден сервис "{service}" для правила "{rule["name"]}".')
                    rule['description'] = f'{rule["description"]}\nError: Не найден сервис "{service}".'
                    rule['rule_error'] = 1
        return new_service_list


    def get_zones(self, rule_zones):
        """Получить список зон для правила"""
        new_zones = []
        if rule_zones != 'any':
            if isinstance(rule_zones, str):
                rule_zones = [rule_zones]
            for item in rule_zones:
#                err, item = self.get_transformed_name(item.strip(), descr='Имя зоны')
                if item in self.zones:
                    new_zones.append(item)
        return new_zones


    def get_users_and_groups(self, users, rule):
        """Получить имена групп и пользователей."""
        if users != 'any':
            new_users_list = []
            if isinstance(users, str):
                users = [users]
            for item in users:
                if item in self.local_users:
                    new_users_list.append(['user', item])
                elif item in self.local_groups:
                    new_users_list.append(['group', item])
                else:
                    self.stepChanged.emit(f'RED|    Error: Не найден локальный пользователь/группа "{item}" для правила "{rule["name"]}".')
                    rule['description'] = f'{rule["description"]}\nError: Не найден локальный пользователь/группа "{item}".'
                    rule['rule_error'] = 1
            rule['users'] =  new_users_list


    def get_tags(self, tags, rule):
        """Получить список тэгов"""
        new_tags_list = []
        if isinstance(tags, str):
            tags = [tags]
            for item in tags:
                _, tag_name = self.get_transformed_name(item, descr='Имя тэга', mode=0)
                if tag_name in self.tags:
                    new_tags_list.append(tag_name)
                else:
                    self.stepChanged.emit(f'RED|    Error: Не найден тэг "{item}" для правила "{rule["name"]}".')
                    rule['description'] = f'{rule["description"]}\nError: Не найден тэг "{item}".'
                    rule['rule_error'] = 1
            rule['tags'] = new_tags_list


#    def get_time_restrictions(self, time_restrictions, rule):
#        """Получить значение календаря."""
#        new_schedule = []
#        for item in time_restrictions.split(';'):
#            err, schedule_name = self.get_transformed_name(item, descr='Имя календаря')
#            if err:
#                self.stepChanged.emit(f'RED|    Error: Преобразовано имя календаря "{item}" для правила "{rule["name"]}" uuid: "{rule.get("uuid", "Отсутствует")}".')
#            if schedule_name == 'always':
#                continue
#            if schedule_name in self.time_restrictions:
#                new_schedule.append(schedule_name)
#            else:
#                self.stepChanged.emit(f'RED|    Error: Не найден календарь "{item}" для правила "{rule["name"]}" uuid: "{rule.get("uuid", "Отсутствует")}".')
#                rule['description'] = f'{rule["description"]}\nError! Не найден календарь "{schedule_name}".'
#                rule['rule_error'] = 1
#        rule['time_restrictions'] = new_schedule


def main(args):
    return 0

if __name__ == '__main__':
    import sys
    sys.exit(main(sys.argv))
