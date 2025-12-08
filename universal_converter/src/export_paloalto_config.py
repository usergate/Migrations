#!/usr/bin/env python3
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
# Версия 2.8  08.12.2025
#

import os, sys, copy, json, copy
import xmltodict
from PyQt6.QtCore import QThread, pyqtSignal
from common_classes import MyConv
from services import zone_services, GEOIP_CODE
from applications import pa_url_category


class ConvertPaloAltoConfig(QThread, MyConv):
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
        self.vlans_address = {}
        self.dhcp_relays = {}
        self.dos_profiles = set()

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
                if 'server-profile' in data['config']['shared']:
                    server_profile = data['config']['shared']['server-profile']
                    if 'ldap' in server_profile:
                        self.convert_ldap_servers(server_profile['ldap']['entry'])
                    if 'netflow' in server_profile:
                        self.convert_netflow_profile(server_profile['netflow']['entry'])
                lib = data['config']['devices']['entry']['vsys']['entry']
                if isinstance(lib, list):
                    lib = lib[0]
                self.convert_services(lib['service'])
                if lib.get('service-group', False):
                    self.convert_service_groups(lib['service-group']['entry'])
                if lib.get('address', False):
                    self.convert_ip_lists(lib['address']['entry'])
                    self.convert_url_lists(lib['address']['entry'])
                if lib.get('address-group', False):
                    self.convert_iplist_groups(lib['address-group']['entry'])
                if lib.get('profiles', False):
                    if lib['profiles'].get('custom-url-category', False):
                        self.convert_custom_url_lists(lib['profiles']['custom-url-category']['entry'])
                    if lib['profiles'].get('dos-protection', False):
                        self.convert_dos_profiles(lib['profiles']['dos-protection']['entry'])
                if lib.get('tag', False):
                    self.convert_tags(lib['tag']['entry'])
                if lib.get('zone', False):
                    self.convert_zone_settings(lib['zone']['entry'])
                if lib.get('schedule', False):
                    self.convert_time_sets(lib['schedule']['entry'])
                network = data['config']['devices']['entry']['network']
                if 'dhcp' in network:
                    if isinstance(network['dhcp']['interface'].get('entry', None), dict):
                        network['dhcp']['interface']['entry'] = [network['dhcp']['interface']['entry']]
                    self.convert_dhcp_relays(network['dhcp']['interface']['entry'])
                self.convert_vlan_interfaces(network)
                if 'virtual-router' in network:
                    if isinstance(network['virtual-router'].get('entry', None), dict):
                        network['virtual-router']['entry'] = [network['virtual-router']['entry']]
                    self.convert_vrfs(network['virtual-router']['entry'])
                systemconfig = data['config']['devices']['entry']['deviceconfig']['system']
                self.convert_settings_ui(systemconfig)
                self.convert_dns_servers(systemconfig)
                self.convert_ntp_settings(systemconfig)
                if lib.get('rulebase', False):
                    if lib['rulebase'].get('security', False) and lib['rulebase']['security']['rules']:
                        self.convert_firewall_policy(lib['rulebase']['security']['rules']['entry'])
                        self.convert_content_rule(lib['rulebase']['security']['rules']['entry'])
                    if lib['rulebase'].get('nat', False) and lib['rulebase']['nat']['rules']:
                        self.convert_nat_rule(lib['rulebase']['nat']['rules']['entry'])
                    if lib['rulebase'].get('decryption', False) and lib['rulebase']['decryption']['rules']:
                        self.convert_ssl_inspection(lib['rulebase']['decryption']['rules']['entry'])
                    if lib['rulebase'].get('dos', False) and lib['rulebase']['dos']['rules']:
                        self.convert_dos_rules(lib['rulebase']['dos']['rules']['entry'])

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


    #----------------------------------- Пользователи и устройства ---------------------------------
    def convert_local_users_and_groups(self, local_users_database):
        """Конвертируем локальных пользователей и группы"""
        self.stepChanged.emit('BLUE|Конвертация локальных пользователей и групп.')

        if 'user' in local_users_database:
            users = local_users_database['user']['entry']
            if isinstance(users, dict):
                users = [users]
            for user in users:
                self.local_users[user['@name']] = {
                    'name': user['@name'],
                    'enabled': False if user.get('disabled', None) == 'yes' else True,
                    'auth_login': user['@name'],
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
        if 'user-group' in local_users_database:
            user_group = local_users_database['user-group']['entry']
            if isinstance(user_group, dict):
                user_group = [user_group]
            for item in user_group:
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

                self.local_groups.add(group['name'])
                groups.append(group)

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


    def convert_ldap_servers(self, pa_ldap):
        """Конвертируем сервера авторизации"""
        self.stepChanged.emit('BLUE|Конвертация серверов аутентификации.')
        if isinstance(pa_ldap, dict):
            pa_ldap = [pa_ldap]
        ldap_servers = []

        for item in pa_ldap:
            if item['ldap-type'] == 'active-directory':
                tmp_dn1 = [x.split('=') for x in item['base'].split(',')]
                tmp_dn2 = [b for a, b in tmp_dn1 if a in ('dc', 'DC')]
                dn = '.'.join(tmp_dn2)
                if '=' in item['bind-dn']:
                    tmp_arr = [x.split('=') for x in item['bind-dn'].split(',')]
                    ad_name = tmp_arr[0][1] if tmp_arr[0][0] in ('cn', 'CN') else None
                    ad_name = f'{ad_name}@{dn}'
                else:
                    ad_name = item['bind-dn']
                if isinstance(item['server']['entry'], dict):
                    item['server']['entry'] = [item['server']['entry']]
                for server in item['server']['entry']:
                    ldap_servers.append({
                        'name': server['@name'],
                        'description': 'LDAP-коннектор импортирован с PaloAlto.',
                        'enabled': False,
                        'ssl': False if item.get('ssl', 'no') == 'no' else True,
                        'address': server['address'],
                        'bind_dn': ad_name,
                        'password': '',
                        'domains': [dn],
                        'roots': [dn] if item['base'] else [],
                        'keytab_exists': False
                    })

        if ldap_servers:
            current_path = os.path.join(self.current_ug_path, 'UsersAndDevices', 'AuthServers')
            err, msg = self.create_dir(current_path)
            if err:
                self.stepChanged.emit(f'RED|    {msg}')
                self.error = 1
                return

            json_file = os.path.join(current_path, 'config_ldap_servers.json')
            with open(json_file, 'w') as fh:
                json.dump(ldap_servers, fh, indent=4, ensure_ascii=False)
            self.stepChanged.emit(f'GREEN|    Сервера аутентификации LDAP выгружены в файл "{json_file}".')
        else:
            self.stepChanged.emit('GRAY|    Нет серверов аутентификации LDAP для экспорта.')


    #---------------------------------------- Библиотека ----------------------------------------------------
    def convert_services(self, pa_services):
        """Конвертируем сетевые сервисы."""
        self.stepChanged.emit('BLUE|Конвертация сетевых сервисов.')
        services = {}
        error = 0

        if pa_services:
            for item in pa_services['entry']:
                error, service_name = self.get_transformed_name(item['@name'], err=error, descr='Имя сервиса')
                descr = item.get('description', 'Портировано с PaloAlto.')
                services[service_name] = {
                    'name': service_name,
                    'description': descr['#text'] if isinstance(descr, dict) else descr,
                    'protocols': []
                }
                for key, value in item['protocol'].items():
                    if key in ('tcp', 'udp'):
                        if (source_port := value.get('source-port', '')) and isinstance(source_port, dict):
                            source_port = source_port['#text']
                        ports = value['port'] if isinstance(value['port'], str) else value['port']['#text']
                        for port in ports.split(','):
                            services[item['@name']]['protocols'].append({
                                'proto': key,
                                'port': port,
                                'app_proto': '',
                                'source_port': source_port,
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
            services['netbios-dg'] = {'name': 'netbios-dg', 'description': 'Портировано с PaloAlto', 'protocols': [
                {'proto': 'udp', 'port': '138', 'app_proto': '', 'source_port': '', 'alg': ''}]}
            services['netbios-ns'] = {'name': 'netbios-ns', 'description': 'Портировано с PaloAlto', 'protocols': [
                {'proto': 'tcp', 'port': '137', 'app_proto': '', 'source_port': '', 'alg': ''},
                {'proto': 'udp', 'port': '137', 'app_proto': '', 'source_port': '', 'alg': ''}]}
            services['netbios-ss'] = {'name': 'netbios-ss', 'description': 'Портировано с PaloAlto', 'protocols': [
                {'proto': 'tcp', 'port': '139', 'app_proto': '', 'source_port': '', 'alg': ''}]}
            services['ms-ds-smb'] = {'name': 'ms-ds-smb', 'description': 'Портировано с PaloAlto', 'protocols': [
                {'proto': 'tcp', 'port': '445', 'app_proto': '', 'source_port': '', 'alg': ''},
                {'proto': 'tcp', 'port': '139', 'app_proto': '', 'source_port': '', 'alg': ''},
                {'proto': 'udp', 'port': '445', 'app_proto': '', 'source_port': '', 'alg': ''}]}
            services['rlogin'] = {'name': 'rlogin', 'description': 'Портировано с PaloAlto', 'protocols': [
                {'proto': 'tcp', 'port': '221', 'app_proto': '', 'source_port': '', 'alg': ''},
                {'proto': 'tcp', 'port': '513', 'app_proto': '', 'source_port': '', 'alg': ''},
                {'proto': 'udp', 'port': '221', 'app_proto': '', 'source_port': '', 'alg': ''}]}
            services['web-browsing'] = {'name': 'web-browsing', 'description': 'Портировано с PaloAlto', 'protocols': [
                {'proto': 'tcp', 'port': '80', 'app_proto': '', 'source_port': '', 'alg': ''}]}
            
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
        error = 0

        if isinstance(pa_servicegroups, dict):
            pa_servicegroups = [pa_servicegroups]

        for item in pa_servicegroups:
            error, service_name = self.get_transformed_name(item['@name'], err=error, descr='Имя группы сервисов')
            descr = item.get('description', 'Портировано с PaloAlto.')
            srv_group = {
                'name': service_name,
                'description': descr['#text'] if isinstance(descr, dict) else descr,
                'type': 'servicegroup',
                'url': '',
                'list_type_update': 'static',
                'schedule': 'disabled',
                'attributes': {},
                'content': []
            }
            if isinstance(item['members']['member'], str):
                item['members']['member'] = [item['members']['member']]
            for member in item['members']['member']:
                if isinstance(member, dict):
                    member = member['#text']
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
        file_names = {}

        if isinstance(pa_iplists, dict):
            pa_iplists = [pa_iplists]

        for item in pa_iplists:
            content = []
            if 'ip-netmask' in item:
                content.append({'value': item['ip-netmask'] if isinstance(item['ip-netmask'], str) else item['ip-netmask']['#text']})
            elif 'ip-range' in item:
                content.append({'value': item['ip-range'] if isinstance(item['ip-range'], str) else item['ip-range']['#text']})
            if content:
                error, iplist_name = self.get_transformed_name(item['@name'], err=error, descr='Имя списка IP-адресов')
                descr = item.get('description', 'Портировано с PaloAlto.')
                ip_list = {
                    'name': iplist_name,
                    'description': descr['#text'] if isinstance(descr, dict) else descr,
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

                if file_name in file_names:
                    file_names[file_name] += 1
                    file_name = f'{file_name}-{file_names[file_name]}'
                else:
                    file_names[file_name] = 0

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
        """Конвертируем списки URL (домены)"""
        self.stepChanged.emit('BLUE|Конвертация списков URL (домены).')
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
                descr = item.get('description', 'Портировано с PaloAlto.')
                url_list = {
                    'name': list_name,
                    'description': descr['#text'] if isinstance(descr, dict) else descr,
                    'type': 'url',
                    'url': '',
                    'list_type_update': 'static',
                    'schedule': 'disabled',
                    'attributes': {'list_compile_type': 'case_insensitive'},
                    'content': [{'value': item['fqdn'] if isinstance(item['fqdn'], str) else item['fqdn']['#text']}]
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


    def convert_custom_url_lists(self, custom_urls):
        """Конвертируем списки URL из custom-url-category"""
        self.stepChanged.emit('BLUE|Конвертация списков custom-URL.')
        current_path = os.path.join(self.current_ug_path, 'Libraries', 'URLLists')
        err, msg = self.create_dir(current_path, delete='no')
        if err:
            self.stepChanged.emit(f'RED|    {msg}')
            self.error = 1
            return

        n = 0
        error = 0
        if isinstance(custom_urls, dict):
            custom_urls = [custom_urls]

        for item in custom_urls:
            item_type = item['type'] if isinstance(item['type'], str) else item['type']['#text']
            if item_type == 'URL List':
                error, list_name = self.get_transformed_name(item['@name'], err=error, descr='Имя списка URL')
                descr = item.get('description', 'Портировано с PaloAlto.')
                members = item['list']['member'] if isinstance(item['list']['member'], list) else [item['list']['member']]

                url_list = {
                    'name': list_name,
                    'description': descr['#text'] if isinstance(descr, dict) else descr,
                    'type': 'url',
                    'url': '',
                    'list_type_update': 'static',
                    'schedule': 'disabled',
                    'attributes': {'list_compile_type': 'case_insensitive'},
                    'content': [{'value': url if isinstance(url, str) else url['#text']} for url in members]
                }

                n += 1
                self.url_lists.add(url_list['name'])

                json_file = os.path.join(current_path, f'{url_list["name"].translate(self.trans_filename)}.json')
                with open(json_file, 'w') as fh:
                    json.dump(url_list, fh, indent=4, ensure_ascii=False)
                self.stepChanged.emit(f'BLACK|       {n} - Список URL "{url_list["name"]}" выгружен в файл "{json_file}".')

        if error:
            self.stepChanged.emit(f'ORANGE|    Конвертация списков custom-URL прошла с ошибками. Списки URL выгружены в каталог "{current_path}".')
            self.error = 1
        else:
            self.stepChanged.emit(f'GREEN|    Списки custom-URL выгружены в каталог "{current_path}".')


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
            descr = item.get('description', 'Портировано с PaloAlto.')
            content = []
            urls_list = []
            if 'static' in item:
                if isinstance(item['static']['member'], str):
                    item['static']['member'] = [item['static']['member']]
                for member in item['static']['member']:
                    if isinstance(member, dict):
                        member = member['#text']
                    if member in self.ip_lists:
                        content.append({'list': member})
                    elif member in self.url_lists:
                        urls_list.append({'value': member})
#                        self.stepChanged.emit(f'RED|       Error: [Группа IP-адресов "{iplist_name}"] Пропущен "{member}" т.к. вложенные URL-листы не поддерживаются.')
            ip_list = {
                'name': iplist_name,
                'description': descr['#text'] if isinstance(descr, dict) else descr,
                'type': 'network',
                'url': '',
                'list_type_update': 'static',
                'schedule': 'disabled',
                'attributes': {'threat_level': 3},
                'content': content
            }
            if not ip_list['content']:
                self.stepChanged.emit(f'ORANGE|       Warning: Группа IP-адресов "{iplist_name}" не имеет содержимого.')

            n += 1
            self.ip_lists_groups.add(ip_list['name'])

            json_file = os.path.join(current_path, f'{ip_list["name"].translate(self.trans_filename)}.json')
            with open(json_file, 'w') as fh:
                json.dump(ip_list, fh, indent=4, ensure_ascii=False)
                self.stepChanged.emit(f'BLACK|       {n} - Группа IP-адресов "{ip_list["name"]}" выгружена в файл "{json_file}".')

            if urls_list:
                self.create_url_list(iplist_name, urls_list)

        if error:
            self.stepChanged.emit(f'ORANGE|    Конвертация группы IP-адресов прошла с ошибками. Группа IP-адресов выгружена в каталог "{current_path}".')
            self.error = 1
        else:
            self.stepChanged.emit(f'GREEN|    Группа IP-адресов выгружена в каталог "{current_path}".')


    def convert_netflow_profile(self, pa_netflow):
        """Конвертируем профили netflow."""
        self.stepChanged.emit('BLUE|Конвертация профилей netflow.')
        if isinstance(pa_netflow, dict):
            pa_netflow = [pa_netflow]

        netflow = []
        for item in pa_netflow:
            if isinstance(item['server']['entry'], dict):
                item['server']['entry'] = [item['server']['entry']]
            for flow in item['server']['entry']:
                netflow.append({
                    'name': flow['@name'],
                    'description': 'Портировано с PaloAlto.',
                    'host': flow['host'],
                    'port': flow['port'],
                    'protocol': 9,
                    'active_timeout': int(item['active-timeout']),
                    'inactive_timeout': 15,
                    'refresh_rate': int(item['template-refresh-rate']['packets']),
                    'timeout_rate': int(item['template-refresh-rate']['minutes'])*60,
                    'maxflows': 2000000,
                    'natevents': False,
                })
        if netflow:
            current_path = os.path.join(self.current_ug_path, 'Libraries', 'NetflowProfiles')
            err, msg = self.create_dir(current_path)
            if err:
                self.stepChanged.emit(f'RED|    {msg}')
                self.error = 1
                return
            json_file = os.path.join(current_path, 'config_netflow_profiles.json')
            with open(json_file, 'w') as fh:
                json.dump(netflow, fh, indent=4, ensure_ascii=False)
            self.stepChanged.emit(f'GREEN|    Профили netflow выгружены в файл "{json_file}".')
        else:
            self.stepChanged.emit('GRAY|    Нет профилей netflow для экспорта.')


    def convert_dos_profiles(self, profiles_entry):
        """Конвертируем профили DoS."""
        self.stepChanged.emit('BLUE|Конвертация профилей DoS.')
        if isinstance(profiles_entry, dict):
            profiles_entry = [profiles_entry]

        dos_profiles = []
        try:
            for item in profiles_entry:
                dos_profiles.append({
                    'name': item['@name'],
                    'description': '',
                    'aggregate': True,
                    'sessions': {
                        'enabled': True if item['resource']['sessions']['enabled'] == 'yes' else False,
                        'max_sessions': int(item['resource']['sessions']['max-concurrent-limit'])
                    },
                    'floods': [
                        {
                            'type': 'syn',
                            'enabled': False if item['flood']['tcp-syn']['enable'] == 'no' else True,
                            'alert': int(item['flood']['tcp-syn']['red']['alarm-rate']),
                            'drop': int(item['flood']['tcp-syn']['red']['maximal-rate'])
                        },
                        {
                            'type': 'udp',
                            'enabled': False if item['flood']['udp']['enable'] == 'no' else True,
                            'alert': int(item['flood']['udp']['red']['alarm-rate']),
                            'drop': int(item['flood']['udp']['red']['maximal-rate'])
                        },
                        {
                            'type': 'icmp',
                            'enabled': False if item['flood']['icmp']['enable'] == 'no' else True,
                            'alert': int(item['flood']['icmp']['red']['alarm-rate']),
                            'drop': int(item['flood']['icmp']['red']['maximal-rate'])
                        }
                    ]
                })
                self.dos_profiles.add(item['@name'])
        except Exception:
            print(item)

        if dos_profiles:
            current_path = os.path.join(self.current_ug_path, 'SecurityPolicies', 'DosProfiles')
            err, msg = self.create_dir(current_path)
            if err:
                self.stepChanged.emit(f'RED|    {msg}')
                self.error = 1
                return
            json_file = os.path.join(current_path, 'config_dos_profiles.json')
            with open(json_file, 'w') as fh:
                json.dump(dos_profiles, fh, indent=4, ensure_ascii=False)
            self.stepChanged.emit(f'GREEN|    Профили DoS выгружены в файл "{json_file}".')
        else:
            self.stepChanged.emit('GRAY|    Нет профилей DoS для экспорта.')



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
            descr = item.get('comments', 'Портировано с PaloAlto.')
            color = item.get('color', 'no_color')
            if isinstance(color, dict):
                color = color['#text']
            tags.append({
                'name': tag_name,
                'description': descr['#text'] if isinstance(descr, dict) else descr,
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


    #--------------------------------- Сеть ------------------------------------------------
    def convert_dhcp_relays(self, dhcp_relay_entry):
        """Конвертируем dhcp_relay"""
        for item in dhcp_relay_entry:
            if 'relay' in item:
                if isinstance(item['relay']['ip']['server']['member'], str):
                    item['relay']['ip']['server']['member'] = [item['relay']['ip']['server']['member']]
            self.dhcp_relays[item['@name']] = {
                'enabled': True if item['relay']['ip'].get('enabled', 'no') == 'yes' else False,
                'host_ipv4': '',
                'servers': item['relay']['ip']['server']['member']
            }


    def convert_vlan_interfaces(self, network):
        """Конвертируем интерфейсы VLAN."""
        self.stepChanged.emit('BLUE|Конвертация интерфейсов VLAN.')
        error = 0
        all_vlans = []

        if (tmp_net := network['interface'].get('aggregate-ethernet', False)):
            if isinstance(tmp_net['entry'], list):
                for item in tmp_net['entry']:
                    all_vlans.extend(self.create_vlans(item['@name'], item['layer3']['units']))
            elif isinstance(tmp_net['entry'], dict):
                all_vlans = self.create_vlans(item['@name'], tmp_net['entry']['layer3']['units'])

        if all_vlans:
            current_path = os.path.join(self.current_ug_path, 'Network', 'Interfaces')
            err, msg = self.create_dir(current_path)
            if err:
                self.stepChanged.emit(f'RED|    {msg}')
                self.error = 1
                return

            json_file = os.path.join(current_path, 'config_interfaces.json')
            with open(json_file, 'w') as fh:
                json.dump(all_vlans, fh, indent=4, ensure_ascii=False)
            self.stepChanged.emit(f'GREEN|    Интерфейсы VLAN выгружены в файл "{json_file}".')
        else:
            self.stepChanged.emit('GRAY|    Нет интерфейсов VLAN для экспорта.')


    def create_vlans(self, node_name, units):
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
                    'node_name': node_name,
                    'kind': 'vlan',
                    'enabled': False,
                    'description': item['comment'] if item.get('comment', False) else 'Портировано с PaloAlto.',
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
                    'dhcp_relay': self.dhcp_relays.get(item['@name'], {'enabled': False, 'host_ipv4': '', 'servers': []}),
#                    {
#                        'enabled': False,
#                        'host_ipv4': '',
#                        'servers': []
#                    },
                    'vlan_id': int(item['tag']),
                    'link': ''
                }
                if item.get('ip', False):
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
                            self.stepChanged.emit(f'RED|    Error: Интерфейс VLAN "{iface["name"]}" - не валидный IP-адрес "{ip_entry["@name"]}".')
                else:
                    iface['mode'] = 'manual'
                self.vlans_address[item['@name']] = iface['ipv4']
                ifaces.append(iface)
        return ifaces


    def convert_vrfs(self, pa_vrfs):
        """Конвертируем список VRFs"""
        self.stepChanged.emit('BLUE|Конвертация шлюзов и virtual routers.')
        gateways_list = []
        ngfw_vrfs = []
        error_gw = 0
        error_st = 0

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
            if vrf.get('routing-table', False) and vrf['routing-table']['ip']['static-route']:
                routes = vrf['routing-table']['ip']['static-route']['entry']
                if isinstance(routes, dict):
                    routes = [routes]

                for item in routes:
                    gateway = item['nexthop']['ip-address']
                    # Конвертируем шлюзы
                    if item['destination'] == '0.0.0.0/0':
                        if (route_gateway := self.check_ip(gateway)) or (route_gateway := self.ip_lists.get(gateway, False)):
                            gateways_list.append({
                               'name': item['@name'],
                               'enabled': True,
                               'description': item.get('description', 'Портировано с PaloAlto.'),
                               'ipv4': route_gateway.partition('/')[0],
                               'vrf': new_vrf['name'],
                               'weight': int(item.get('metric', 1)),
                               'multigate': False,
                               'default': False,
                               'iface': 'undefined',
                               'is_automatic': False
                            })
                        else:
                            self.stepChanged.emit(f'RED|    Шлюз "{item["@name"]}" не конвертирован. Ошибка проверки nexthop "{item["nexthop"]["ip-address"]}".')
                            error_gw = 1
                    else:
                        # Конвертируем статические маршруты
                        dest = item['destination']
                        if (route_dest := self.check_ip(dest)) or (route_dest := self.ip_lists.get(dest, False)):
                            if (route_gateway := self.check_ip(gateway)) or (route_gateway := self.ip_lists.get(gateway, False)):
                                new_vrf['routes'].append({
                                    'name': item['@name'],
                                    'description': item.get('description', 'Портировано с PaloAlto.'),
                                    'enabled': True,
                                    'dest': route_dest,
                                    'gateway': route_gateway.partition('/')[0],
                                    'ifname': 'undefined',
                                    'kind': 'unicast',
                                    'metric': int(item.get('metric', 1))
                                })
                            else:
                                self.stepChanged.emit(f'RED|    Статический маршрут "{item["@name"]}" не конвертирован. Ошибка проверки nexthop "{item["nexthop"]["ip-address"]}".')
                                error_st = 1
                        else:
                            self.stepChanged.emit(f'RED|    Статический маршрут "{item["@name"]}" не конвертирован. Ошибка проверки destination "{item["destination"]}".')
                            error_st = 1
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

            if error_gw:
                self.stepChanged.emit(f'ORANGE|    Конвертация прошла с ошибками. Список шлюзов выгружены в файл "{json_file}".')
                self.error = 1
            else:
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

            if error_st:
                self.stepChanged.emit(f'ORANGE|    Конвертация прошла с ошибками. VRF выгружены в файл "{json_file}".')
                self.error = 1
            else:
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
            '    После импорта правил МЭ, в каждом правиле укажите зону источника и зону назначения.\n'
            '    Создайте необходимое количество зон и присвойте зону каждому интерфейсу.'
        )
        self.stepChanged.emit(f'LBLUE|{message}')

        error = 0
        app_error = 0
        n = 0
        rules = []
        for item in firewall_rules:
            # Проверяем что это не правило КФ. Если КФ, пропускаем.
            if 'category' in item:
                category = item['category']['member']
                if isinstance(category, list):
                    continue
                else:
                    if (text := category if isinstance(category, str) else category['#text']) != 'any':
                        continue

            error, rule_name = self.get_transformed_name(item['@name'], err=error, descr='Имя правила МЭ')
            descr = item.get('description', 'Портировано с PaloAlto.')
            if (action := item.get('action', None)):
                action = action['#text'] if isinstance(action, dict) else action
            if (disabled := item.get('disabled', None)):
                disabled = disabled['#text'] if isinstance(disabled, dict) else disabled
            if (negate_src := item.get('negate-source', None)):
                negate_src = negate_src if isinstance(negate_src, str) else negate_src['#text']
            if (negate_dst := item.get('negate-destination', None)):
                negate_dst = negate_dst if isinstance(negate_dst, str) else negate_dst['#text']
            rule = {
                'name': rule_name,
                'description': descr['#text'] if isinstance(descr, dict) else descr,
                'action': 'accept' if action == 'allow' else 'drop',
                'position': 'last',
                'scenario_rule_id': False,
                'src_zones': self.get_zones(item['from']['member']),
                'dst_zones': self.get_zones(item['to']['member']),
                'src_ips': [],
                'dst_ips': [],
                'services': [],
                'apps': [],
                'users': [],
                'enabled': False if disabled == 'yes' else True,
                'limit': True,
                'limit_value': '3/h',
                'limit_burst': 5,
                'log': True,
                'log_session_start': True,
                'src_zones_negate': False,
                'dst_zones_negate': False,
                'src_ips_negate': True if negate_src == 'yes' else False,
                'dst_ips_negate': True if negate_dst == 'yes' else False,
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
            if 'source-user' in item:
                self.get_users_and_groups(item['source-user']['member'], rule)
#            self.get_time_restrictions(value['schedule'], rule)
            if isinstance(item.get('tag', None), dict):
                self.get_tags(item['tag']['member'], rule)

            apps = set()
            if not isinstance(item['application']['member'], list):
                item['application']['member'] = [item['application']['member']]
            for app in item['application']['member']:
                app = app if isinstance(app, str) else app['#text']
                if app != 'any':
                    apps.add(app)
            if apps:
                num_appp = False
                tmp_apps = apps.copy()
                for app in apps:
                    if app.startswith('ms-ds-smb'):
                        tmp_apps.remove(app)
                        if not num_appp:
                            rule['services'].append(['service', 'ms-ds-smb'])
                            num_appp = True
                    elif app in ('rlogin', 'netbios-dg', 'netbios-ns', 'netbios-ss', 'web-browsing', 'ms-ds-smb'):
                        rule['services'].append(['service', app])
                        tmp_apps.remove(app)
                if tmp_apps:
                    self.stepChanged.emit(f'RED|    Error: [Правило "{rule["name"]}"] Не найдено приложение: {", ".join(tmp_apps)}')
                    rule['description'] = f'{rule["description"]}\nНе найдено приложение: {", ".join(tmp_apps)}'
                    rule['rule_error'] = 1
                    app_error = 1

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
                self.stepChanged.emit(f'ORANGE|    Конвертация прошла с ошибками. Правила межсетевого экрана выгружены в файл "{json_file}".')
                self.error = 1
            else:
                self.stepChanged.emit(f'GREEN|    Правила межсетевого экрана выгружены в файл "{json_file}".')
            if app_error:
                self.stepChanged.emit('bRED|    Внимание: После импорта создайте профили отсутствующих приложений и вставте их в соответствующие правила МЭ.')
        else:
            self.stepChanged.emit('GRAY|    Нет правил межсетевого экрана для экспорта.')


    def convert_content_rule(self, firewall_rules):
        """Конвертируем правила фильтрации контента"""
        self.stepChanged.emit('BLUE|Конвертация правил фильтрации контента.')
        message = '    После импорта правил ФК, в каждом правиле укажите зону источника и зону назначения.'

        error = 0
        n = 0
        rules = []
        for item in firewall_rules:
            # Проверяем что это правило КФ. Если не КФ, пропускаем.
            if 'category' not in item:
                continue
            categories = item['category']['member']
            if isinstance(categories, dict) and categories['#text'] == 'any':
                continue
            elif isinstance(categories, str) and categories == 'any':
                continue

            error, rule_name = self.get_transformed_name(item['@name'], err=error, descr='Имя правила МЭ')
            descr = item.get('description', 'Портировано с PaloAlto.')
            if (action := item.get('action', None)):
                action = action['#text'] if isinstance(action, dict) else action
            if (disabled := item.get('disabled', None)):
                disabled = disabled['#text'] if isinstance(disabled, dict) else disabled
            if (negate_src := item.get('negate-source', None)):
                negate_src = negate_src if isinstance(negate_src, str) else negate_src['#text']
            if (negate_dst := item.get('negate-destination', None)):
                negate_dst = negate_dst if isinstance(negate_dst, str) else negate_dst['#text']
            rule = {
                'name': rule_name,
                'public_name': '',
                'description': descr['#text'] if isinstance(descr, dict) else descr,
                'action': 'accept' if action == 'allow' else 'drop',
                'position': 'last',
                'enabled': False if disabled == 'yes' else True,
                'enable_custom_redirect': False,
                'blockpage_template_id': -1,
                'users': [],
                'url_categories': [],
                'src_zones': self.get_zones(item['from']['member']),
                'dst_zones': self.get_zones(item['to']['member']),
                'src_ips': [],
                'dst_ips': [],
                'morph_categories': [],
                'urls': [],
                'referers': [],
                'referer_categories': [],
                'user_agents': [],
                'time_restrictions': [],
                'content_types': [],
                'http_methods': [],
                'custom_redirect': '',
                'enable_kav_check': False,
                'enable_md5_check': False,
                'rule_log': True,
                'scenario_rule_id': False,
                'src_zones_negate': False,
                'dst_zones_negate': False,
                'src_ips_negate': True if negate_src == 'yes' else False,
                'dst_ips_negate': True if negate_dst == 'yes' else False,
                'url_categories_negate': False,
                'urls_negate': False,
                'content_types_negate': False,
                'user_agents_negate': False,
                'user_negate': False,
                'rule_error': 0,
            }
            rule['src_ips'] = self.get_ips('src', item['source']['member'], rule)
            rule['dst_ips'] = self.get_ips('dst', item['destination']['member'], rule)
            self.get_users_and_groups(item['source-user']['member'], rule)
#            self.get_time_restrictions(value['schedule'], rule)
            if isinstance(item.get('tag', None), dict):
                self.get_tags(item['tag']['member'], rule)

            if not isinstance(categories, list):
                categories = [categories]
            cat_set = set()
            err_url_category = set()
            for x in categories:
                category = x if isinstance(x, str) else x['#text']
                if category in self.url_lists:
                    rule['urls'].append(category)
                elif category in pa_url_category:
                    cat_set.update(pa_url_category[category])
                else:
                    err_url_category.add(category)
            # Если есть и URLs и URL_category, то делаем 2 отдельных правила (т.к. у нас логическое 'И').
            if cat_set:
                if rule['urls']:
                    rule2 = copy.deepcopy(rule)
                    rule2['urls'] = []
                    rule2['name'] = f"1_{rule['name']}"
                    rule['name'] = f"2_{rule['name']}"
                    rule2['url_categories'] = [['category_id', y] for y in cat_set]
                    if err_url_category:
                        self.stepChanged.emit(f'RED|    Error: [Правило "{rule2["name"]}"] Не конвертирована URL-категория: {", ".join(err_url_category)}. Возможно такой категории нет на UserGate.')
                        rule2['description'] = f'{rule2["description"]}\nНе найдена URL-категория: {", ".join(err_url_category)}'
                        rule2['rule_error'] = 1
                        err_url_category = set()
                    if rule2['rule_error']:
                        rule2['name'] = f'ERROR-{rule2["name"]}'
                        rule2['enabled'] = False
                        error = 1
                    rule2.pop('rule_error', None)
                    rules.append(rule2)
                    n += 1
                    self.stepChanged.emit(f'BLACK|    {n} - Создано правило ФК "{rule2["name"]}".')
                else:
                    rule['url_categories'] = [['category_id', y] for y in cat_set]

            if err_url_category:
                self.stepChanged.emit(f'RED|    Error: [Правило "{rule["name"]}"] Не конвертирована URL-категория: {", ".join(err_url_category)}. Возможно такой категории нет на UserGate.')
                rule['description'] = f'{rule["description"]}\nНе найдена URL-категория: {", ".join(err_url_category)}'
                rule['rule_error'] = 1

            if rule['rule_error']:
                rule['name'] = f'ERROR-{rule["name"]}'
                rule['enabled'] = False
                error = 1
            rule.pop('rule_error', None)

            rules.append(rule)
            n += 1
            self.stepChanged.emit(f'BLACK|    {n} - Создано правило ФК "{rule["name"]}".')

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
                self.stepChanged.emit(f'ORANGE|    Конвертация прошла с ошибками. Правила фильтрации контента выгружены в файл "{json_file}".')
                self.error = 1
            else:
                self.stepChanged.emit(f'GREEN|    Правила фильтрации контента выгружены в файл "{json_file}".')
            self.stepChanged.emit(f'LBLUE|{message}')
        else:
            self.stepChanged.emit('GRAY|    Нет правил фильтрации контента для экспорта.')


    def convert_nat_rule(self, nat_rules):
        """Конвертируем правила NAT, DNAT и Port-форвардинга"""
        self.stepChanged.emit('BLUE|Конвертация правил NAT.')
        error = 0
        rules = []

        if isinstance(nat_rules, dict):
            nat_rules = [nat_rules]
        for item in nat_rules:
            error, rule_name = self.get_transformed_name(item['@name'], err=error, descr='Имя правила NAT')
            descr = item.get('description', 'Портировано с PaloAlto.')
            if (disabled := item.get('disabled', None)):
                disabled = disabled['#text'] if isinstance(disabled, dict) else disabled
            if (negate_src := item.get('negate-source', None)):
                negate_src = negate_src if isinstance(negate_src, str) else negate_src['#text']
            if (negate_dst := item.get('negate-destination', None)):
                negate_dst = negate_dst if isinstance(negate_dst, str) else negate_dst['#text']
            rule = {
                'name': rule_name,
                'description': descr['#text'] if isinstance(descr, dict) else descr,
                'action': 'nat',
                'position': 'last',
                'zone_in': self.get_zones(item['from']['member']),
                'zone_out': self.get_zones(item['to']['member']),
                'source_ip': [],
                'dest_ip': [],
                'service': [],
                'target_ip': '',
                'gateway': '',
                'enabled': False if disabled == 'yes' else True,
                'log': False,
                'log_session_start': False,
                'target_snat': True,
                'snat_target_ip': '',
                'zone_in_nagate': False,
                'zone_out_nagate': False,
                'source_ip_nagate': True if negate_src == 'yes' else False,
                'dest_ip_nagate': True if negate_dst == 'yes' else False,
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
            if isinstance(item.get('tag', None), dict):
                self.get_tags(item['tag']['member'], rule)

            if 'source-translation' in item:
                if 'dynamic-ip-and-port' in item['source-translation']:
                    if (interface_address := item['source-translation']['dynamic-ip-and-port'].get('interface-address', False)):
                        if (ip := interface_address.get('ip', False)):
                            ip = ip['#text'] if isinstance(ip, dict) else ip
                            rule['snat_target_ip'] = self.ip_lists.get(ip, ip).partition('/')[0]
                        elif (interface := interface_address.get('interface', False)) and self.vlans_address.get(interface, False):
                            rule['snat_target_ip'] = self.vlans_address.get(interface, ['/'])[0].partition('/')[0]
                    elif (translated_address := item['source-translation']['dynamic-ip-and-port'].get('translated-address', False)):
                        self.stepChanged.emit(f'RED|    Error: [Правило "{rule_name}"] Не конвертировано source-translation: "{translated_address}".')
                        rule['rule_error'] = True
                        rule['description'] = f'{rule["description"]}\nНе конвертировано source-translation: "{translated_address}".'
                elif 'static-ip' in item['source-translation']:
                    ip = item['source-translation']['static-ip']['translated-address']
                    ip = ip['#text'] if isinstance(ip, dict) else ip
                    rule['snat_target_ip'] = self.ip_lists.get(ip, ip).partition('/')[0]
                elif 'dynamic-ip' in item['source-translation']:
                    members = item['source-translation']['dynamic-ip']['translated-address']['member']
                    if isinstance(members, str):
                        if self.check_ip(self.ip_lists[members]).partition('/')[2] != "32":
                            pass
#                            rule['source_ip'].extend(self.get_ips('src', members, rule))
#                            if isinstance(item['destination']['member'], str):
#                                if self.check_ip(self.ip_lists[item['destination']['member']]).partition('/')[2] != "32":
#                                    try:
#                                        rule['target_ip'] = self.ip_lists[item['destination']['member']]
#                                        rule['action'] = 'netmap'
#                                    except KeyError:
#                                        self.stepChanged.emit(f'RED|    Error: [Правило "{rule_name}"] Проверьте правило, возможны ошибки конвертации.')
#                                        rule['rule_error'] = True
#                                        rule['description'] = f"{rule['description']}\nПроверьте правило, возможны ошибки конвертации."
                        else:
                            rule['snat_target_ip'] = self.ip_lists.get(members, '/').partition('/')[0]

            elif 'destination-translation' in item:
                dnat_ip = item['destination-translation']['translated-address']
                dnat_ip = dnat_ip['#text'] if isinstance(dnat_ip, dict) else dnat_ip
                rule['target_ip'] = self.ip_lists.get(dnat_ip, dnat_ip).partition('/')[0]
                # Проверяем что есть порт для port-forwarding
                trans_port = item['destination-translation'].get('translated-port', False)
                trans_port = trans_port['#text'] if isinstance(trans_port, dict) else trans_port

                try:
                    dport = self.services[item['service']]['protocols'][0]['port']
                    proto = self.services[item['service']]['protocols'][0]['proto']
                except KeyError:
                    error = 1
                    dport = False

                if not dport and not trans_port:
                    rule['action'] = 'dnat'
                elif dport and not trans_port:
                    rule['action'] = 'dnat'
                elif not dport and trans_port:
                    rule['action'] = 'dnat'
                    rule['service'].append(['service', trans_port])
                elif dport and trans_port:
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

        if isinstance(zones, dict):
            zones = [zones]
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


    def convert_ssl_inspection(self, decript_rules):
        """Конвертируем правила инспектирования SSL"""
        self.stepChanged.emit('BLUE|Конвертация правил инспектирования SSL.')
        error = 0
        n = 0
        rules = []

        if isinstance(decript_rules, dict):
            decript_rules = [decript_rules]
        for item in decript_rules:
            error, rule_name = self.get_transformed_name(item['@name'], err=error, descr='Имя правила инспектирования SSL')
            descr = item.get('description', 'Портировано с PaloAlto.')
            if (disabled := item.get('disabled', None)):
                disabled = disabled['#text'] if isinstance(disabled, dict) else disabled
            if (action := item.get('action', None)):
                action = action['#text'] if isinstance(action, dict) else action
            if (negate_src := item.get('negate-source', None)):
                negate_src = negate_src if isinstance(negate_src, str) else negate_src['#text']
            if (negate_dst := item.get('negate-destination', None)):
                negate_dst = negate_dst if isinstance(negate_dst, str) else negate_dst['#text']
            rule = {
                'name': rule_name,
                'description': descr['#text'] if isinstance(descr, dict) else descr,
                'action': 'pass' if action == 'no-decrypt' else 'decrypt',
                'position': 'last',
                'enabled': False if disabled == 'yes' else True,
                'block_invalid_certs': False,
                'block_revoked_certs': False,
                'block_expired_certs': False,
                'block_selfsigned_certs': False,
                'users': [],
                'url_categories': [],
                'protocols': [],
                'src_zones': self.get_zones(item['from']['member']),
                'src_ips': [],
                'dst_ips': [],
                'urls': [],
                'time_restrictions': [],
                'src_zones_nagate': False,
                'src_ips_nagate': True if negate_src == 'yes' else False,
                'dst_ips_nagate': True if negate_dst == 'yes' else False,
                'url_categories_nagate': False,
                'urls_nagate': False,
                'rule_log': True,
                'ssl_profile_id': 'Default_SSL_profile',
                'ssl_forward_profile_id': -1,
                'position_layer': 'local',
                'rule_error': 0,
            }
            if 'source-user' in item:
                self.get_users_and_groups(item['source-user']['member'], rule)
            rule['src_ips'] = self.get_ips('src', item['source']['member'], rule)
            rule['dst_ips'] = self.get_ips('dst', item['destination']['member'], rule)
            if isinstance(item.get('tag', None), dict):
                self.get_tags(item['tag']['member'], rule)

            if 'category' in item:
                categories = item['category']['member']
                if not isinstance(categories, list):
                    categories = [categories]
                cat_set = set()
                err_url_category = set()
                for x in categories:
                    category = x if isinstance(x, str) else x['#text']
                    if category != 'any':
                        if category in self.url_lists:
                            rule['urls'].append(category)
                        elif category in pa_url_category:
                            cat_set.update(pa_url_category[category])
                        else:
                            err_url_category.add(category)
                if cat_set:
                    rule['url_categories'] = [['category_id', y] for y in cat_set]
                if err_url_category:
                    self.stepChanged.emit(f'RED|    Error: [Правило "{rule["name"]}"] Не конвертирована URL-категория: {", ".join(err_url_category)}. Возможно такой категории нет на UserGate.')
                    rule['description'] = f'{rule["description"]}\nНе найдена URL-категория: {", ".join(err_url_category)}'
                    rule['rule_error'] = 1

            if rule['rule_error']:
                rule['name'] = f'ERROR - {rule["name"]}'
                rule['enabled'] = False
                error = 1
            rule.pop('rule_error', None)

            rules.append(rule)
            n += 1
            self.stepChanged.emit(f'BLACK|    {n} - Создано правило инспектирования SSL "{rule["name"]}".')

        if rules:
            current_path = os.path.join(self.current_ug_path, 'SecurityPolicies', 'SSLInspection')
            err, msg = self.create_dir(current_path)
            if err:
                self.stepChanged.emit(f'RED|    {msg}')
                self.error = 1
                return

            json_file = os.path.join(current_path, 'config_ssldecrypt_rules.json')
            with open(json_file, 'w') as fh:
                json.dump(rules, fh, indent=4, ensure_ascii=False)

            if error:
                self.stepChanged.emit(f'ORANGE|    Конвертация прошла с ошибками. Правила инспектирования SSL выгружены в файл "{json_file}".')
                self.error = 1
            else:
                self.stepChanged.emit(f'GREEN|    Правила инспектирования SSL выгружены в файл "{json_file}".')
        else:
            self.stepChanged.emit('GRAY|    Нет правил инспектирования SSL для экспорта.')


    def convert_dos_rules(self, dos_rules):
        """Конвертируем правила защиты DoS"""
        self.stepChanged.emit('BLUE|Конвертация правил защиты DoS.')
        error = 0
        n = 0
        rules = []

        if isinstance(dos_rules, dict):
            dos_rules = [dos_rules]
        for item in dos_rules:
            error, rule_name = self.get_transformed_name(item['@name'], err=error, descr='Имя правила защиты DoS')
            descr = item.get('description', 'Портировано с PaloAlto.')
            if (disabled := item.get('disabled', None)):
                disabled = disabled['#text'] if isinstance(disabled, dict) else disabled
            if (dos_profile := item['protection']['classified'].get('profile', None)):
                dos_profile = dos_profile if isinstance(dos_profile, str) else dos_profile['#text']
                if dos_profile not in self.dos_profiles:
                    dos_profile = False
            if (action := item.get('action', None)):
                action = action['protect']['#text'] if isinstance(action['protect'], dict) else action['protect']
                if dos_profile and action:
                    action = 'protect'
                elif dos_profile and not action:
                    action = 'accept'
                else:
                    action = 'drop'
            if (negate_src := item.get('negate-source', None)):
                negate_src = negate_src if isinstance(negate_src, str) else negate_src['#text']
            if (negate_dst := item.get('negate-destination', None)):
                negate_dst = negate_dst if isinstance(negate_dst, str) else negate_dst['#text']
            rule = {
                'name': rule_name,
                'description': descr['#text'] if isinstance(descr, dict) else descr,
                'action': action,
                'position': 'last',
                'enabled': False if disabled == 'yes' else True,
                'src_zones': self.get_zones(item['from']['zone']['member']),
                'dst_zones': self.get_zones(item['to']['zone']['member']),
                'src_ips': [],
                'dst_ips': [],
                'services': [],
                'limit': True,
                'limit_value': '3/h',
                'limit_burst': 5,
                'log': True,
                'log_session_start': True,
                'src_zones_nagate': False,
                'dst_zones_nagate': False,
                'src_ips_nagate': True if negate_src == 'yes' else False,
                'dst_ips_nagate': True if negate_dst == 'yes' else False,
                'services_nagate': False,
                'dos_profile': dos_profile,
                'scenario_rule_id': False,
                'users': [],
                'time_restrictions': [],
                'position_layer': 'local',
                'rule_error': 0,
            }
            rule['src_ips'] = self.get_ips('src', item['source']['member'], rule)
            rule['dst_ips'] = self.get_ips('dst', item['destination']['member'], rule)
            rule['services'] = self.get_services(item['service']['member'], rule)
            if 'source-user' in item:
                self.get_users_and_groups(item['source-user']['member'], rule)
#            self.get_time_restrictions(value['schedule'], rule)
            if isinstance(item.get('tag', None), dict):
                self.get_tags(item['tag']['member'], rule)

            if rule['rule_error']:
                rule['name'] = f'ERROR - {rule["name"]}'
                rule['enabled'] = False
                error = 1
            rule.pop('rule_error', None)

            rules.append(rule)
            self.stepChanged.emit(f'BLACK|    Создано правило защиты DoS "{rule["name"]}".')

        if rules:
            current_path = os.path.join(self.current_ug_path, 'SecurityPolicies', 'DoSRules')
            err, msg = self.create_dir(current_path)
            if err:
                self.stepChanged.emit(f'RED|    {msg}')
                self.error = 1
                return

            json_file = os.path.join(current_path, 'config_dos_rules.json')
            with open(json_file, 'w') as fh:
                json.dump(rules, fh, indent=4, ensure_ascii=False)

            if error:
                self.stepChanged.emit(f'ORANGE|    Конвертация прошла с ошибками. Правила защиты DoS выгружены в файл "{json_file}".')
                self.error = 1
            else:
                self.stepChanged.emit(f'GREEN|    Правила защиты DoS выгружены в файл "{json_file}".')
        else:
            self.stepChanged.emit('GRAY|    Нет правил защиты DoS для экспорта.')


    def convert_time_sets(self, data):
        """Конвертируем time set (календари)"""
        self.stepChanged.emit('BLUE|Конвертация календарей.')
#        week = {
#            'monday': 1,
#            'tuesday': 2,
#            'wednesday': 3,
#            'thursday': 4,
#            'friday': 5,
#            'saturday': 6,
#            'sunday': 7
#        }
        timerestrictiongroup = []
        error = 0

        if isinstance(data, dict):
            data = [data]
        for item in data:
            error, item_name = self.get_transformed_name(item['@name'], err=error, descr='Имя календаря')
            time_set = {
                'name': item_name,
                'description': 'Портировано с PaloAlto',
                'type': 'timerestrictiongroup',
                'url': '',
                'list_type_update': 'static',
                'schedule': 'disabled',
                'attributes': {},
                'content': []
            }
            if 'recurring' in item['schedule-type']:
                if (daily := item['schedule-type']['recurring'].get('daily', False)):
                    if isinstance(daily['member'], str):
                        daily['member'] = [daily['member']]
                    for i, member in enumerate(daily['member'], start=1):
                        member = member['#text'] if isinstance(member, dict) else member
                        time_from, _, time_to = member.partition('-')
                        time_set['content'].append({
                            'name': f'{item_name}_{i}',
                            'type': 'daily',
                            'time_from': time_from,
                            'time_to': time_to,
                        })
            if 'non-recurring' in item['schedule-type']:
                if isinstance(member := item['schedule-type']['non-recurring']['member'], str):
                    member = [member]
                for i, member in enumerate(member, start=1):
                    member = member['#text'] if isinstance(member, dict) else member
                    dt_from, _, dt_to = member.partition('-')
                    date_from, _, time_from = dt_from.partition('@')
                    date_to, _, time_to = dt_to.partition('@')
                    time_set['content'].append({
                        'name': f'{item_name}_{i}',
                        'type': 'span',
                        'time_from': time_from,
                        'time_to': time_to,
                        'fixed_date_from': f'{date_from.replace("/", "-")}T00:00:00',
                        'fixed_date_to': f'{date_to.replace("/", "-")}T00:00:00',
                    })

            timerestrictiongroup.append(time_set)
            self.time_restrictions.add(time_set['name'])

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


############################################# Служебные функции ###################################################
    def get_ips(self, mode, ips, rule):
        """
        Получить имена списков IP-адресов и URL-листов.
        Если списки не найдены, то они создаются или пропускаются, если невозможно создать.
        """
        new_rule_ips = []
        if not isinstance(ips, list):
            ips = [ips]
        for item in ips:
            ips_name = item if isinstance(item, str) else item['#text']
            if ips_name != 'any':
                err, ips_name = self.get_transformed_name(ips_name, descr='Имя списка IP-адресов')
                if err:
                    self.stepChanged.emit(f'RED|       Error: Правило "{rule["name"]}".')
                not_found = True
                if ips_name in self.ip_lists or ips_name in self.ip_lists_groups:
                    new_rule_ips.append(['list_id', ips_name])
                    not_found = False
                if ips_name in self.url_lists:
                    new_rule_ips.append(['urllist_id', ips_name])
                    not_found = False
                if not_found:
                    if self.check_ip(ips_name):
                        new_rule_ips.append(['list_id', self.create_ip_list(ips=[ips_name], name=ips_name, descr='Портировано с PaloAlto')])
                    else:
                        self.stepChanged.emit(f'RED|    Error: [Правило "{rule["name"]}"] Не найден список {mode}-адресов "{ips_name}".')
                        rule['description'] = f'{rule["description"]}\nError: Не найден список {mode}-адресов "{ips_name}".'
                        rule['rule_error'] = 1
        return new_rule_ips


    def get_services(self, rule_services, rule):
        """Получить список сервисов"""
        new_service_list = []
        if not isinstance(rule_services, list):
            rule_services = [rule_services]
        for item in rule_services:
            service = item if isinstance(item, str) else item['#text']
            if service != 'any':
                _, service = self.get_transformed_name(service, descr='Имя ceрвиса', mode=0)
                if service in self.services:
                    new_service_list.append(['service', service])
                elif service in self.service_groups:
                    new_service_list.append(['list_id', service])
                else:
                    self.stepChanged.emit(f'RED|    Error: [Правило "{rule["name"]}"] Не найден сервис "{service}".')
                    rule['description'] = f'{rule["description"]}\nError: Не найден сервис "{service}".'
                    rule['rule_error'] = 1
        return new_service_list


    def get_zones(self, rule_zones):
        """Получить список зон для правила"""
        new_zones = []
        if not isinstance(rule_zones, list):
            rule_zones = [rule_zones]
        for item in rule_zones:
            zone = item if isinstance(item, str) else item['#text']
            if zone != 'any' and zone in self.zones:
                new_zones.append(zone)
        return new_zones


    def get_users_and_groups(self, users, rule):
        """Получить имена групп и пользователей."""
        new_users_list = []
        if not isinstance(users, list):
            users = [users]
        for item in users:
            user = item if isinstance(item, str) else item['#text']
            if user != 'any':
                if user == 'unknown':
                    new_users_list.append(['special', 'unknown_user'])
                elif user == 'known-user':
                    new_users_list.append(['special', 'known_user'])
                elif '\\' in user:
                    # Это доменный пользователь.
                    new_users_list.append(['user', user])
                elif '=' in user:
                    # Это доменная группа.
                    tmp_arr1 = [x.split('=') for x in user.split(',')]
                    tmp_arr2 = [y for x, y in tmp_arr1 if x in ('dc', 'DC')]
                    ldap_domain = '.'.join(tmp_arr2)
                    group_name = tmp_arr1[0][1] if tmp_arr1[0][0] in ('cn', 'CN') else None
                    if group_name:
                        new_users_list.append(['group', f'{ldap_domain}\\{group_name}'])
                    else:
                        self.stepChanged.emit(f'bRED|    Warning: [Правило "{rule["name"]}"] Не конвертирован доменный пользователь/группа "{user}".')
                        rule['description'] = f'{rule["description"]}\nWarning: Не конвертирован доменный  пользователь/группа "{user}".'
                        rule['rule_error'] = 1
                elif user in self.local_users:
                    new_users_list.append(['user', user])
                elif user in self.local_groups:
                    new_users_list.append(['group', user])
                else:
                    self.stepChanged.emit(f'RED|    Error: [Правило "{rule["name"]}"] Не найден локальный пользователь/группа "{user}".')
                    rule['description'] = f'{rule["description"]}\nError: Не найден локальный пользователь/группа "{user}".'
                    rule['rule_error'] = 1
        rule['users'] =  new_users_list


    def get_tags(self, tags, rule):
        """Получить список тэгов"""
        new_tags_list = []
        if not isinstance(tags, list):
            tags = [tags]
        for item in tags:
            tag_name = item if isinstance(item, str) else item['#text']
            _, tag_name = self.get_transformed_name(tag_name, descr='Имя тэга', mode=0)
            if tag_name in self.tags:
                new_tags_list.append(tag_name)
            else:
                self.stepChanged.emit(f'RED|    Error: [Правило "{rule["name"]}"] Не найден тэг "{tag_name}".')
                rule['description'] = f'{rule["description"]}\nError: Не найден тэг "{tag_name}".'
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


    def create_url_list(self, list_name, urls_list):
        """Создаём URL-лист"""
        url_list = {
            'name': list_name,
            'description': 'Портировано с PaloAlto.',
            'type': 'url',
            'url': '',
            'list_type_update': 'static',
            'schedule': 'disabled',
            'attributes': {'list_compile_type': 'case_insensitive'},
            'content': urls_list
        }
        self.url_lists.add(url_list['name'])

        current_path = os.path.join(self.current_ug_path, 'Libraries', 'URLLists')
        err, msg = self.create_dir(current_path, delete='no')
        if err:
            self.stepChanged.emit(f'RED|    {msg}')
            self.error = 1
            return False

        json_file = os.path.join(current_path, f'{url_list["name"].translate(self.trans_filename)}.json')
        with open(json_file, 'w') as fh:
            json.dump(url_list, fh, indent=4, ensure_ascii=False)
        self.stepChanged.emit(f'sGREEN|       Список URL "{url_list["name"]}" выгружен в файл "{json_file}".')
        return True


def main(args):
    return 0

if __name__ == '__main__':
    import sys
    sys.exit(main(sys.argv))
