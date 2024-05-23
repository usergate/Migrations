#!/usr/bin/python3
#
# Copyright @ 2021-2023 UserGate Corporation. All rights reserved.
# Author: Aleksei Remnev <aremnev@usergate.com>
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
#-------------------------------------------------------------------------------------------------------- 
# export_checkpoint_config.py
# Класс и его функции для конвертации конфигурации CheckPoint в формат UserGate NGFW.
# Версия 3.0
#

import os, sys, json, uuid, time
import common_func as func
from PyQt6.QtCore import QThread, pyqtSignal
from applications import cp_app_category, app_compliance, appgroup_compliance, l7_category_compliance, new_applicationgroup
from services import ServicePorts, dict_risk, trans_table, trans_filename, trans_name # , character_map_for_url
from checkpoint_embedded_objects import embedded_objects


content_by_uid = {}
#trans_url = str.maketrans(character_map_for_url)
trans_url = ''

class ConvertCheckPointConfig(QThread):
    """Конвертируем всю конфигурацию CheckPoint в формат UserGate NGFW."""
    stepChanged = pyqtSignal(str)
    
    def __init__(self, current_vendor_path, current_ug_path, sg_name):
        super().__init__()
        self.current_vendor_path = current_vendor_path
        self.current_ug_path = current_ug_path
        self.sg_name = sg_name
        self.config_path = None
        self.objects = None
        self.error = 0

        self.services = {}
        self.app_groups = []
        self.zones = {}

    def run(self):
        """Конвертируем всё в пакетном режиме"""
#        convert_config_cp(self)

        self.config_path = os.path.join(self.current_vendor_path, 'data_json')
        err, index_file = func.read_json_file(self, os.path.join(self.config_path, 'index.json'))
        if err:
            return
        for policy_package in index_file['policyPackages']:
            if policy_package['packageName'] == self.sg_name:
                objects_file = policy_package['objects']['htmlObjectsFileName'].replace('html', 'json')
                break
        err, data = func.read_json_file(self, os.path.join(self.config_path, objects_file))
        if err:
            return

        self.objects = {x['uid']: x for x in data}
        json_file = os.path.join(self.config_path, 'objects.json')
        with open(json_file, 'w') as fh:
            json.dump(self.objects, fh, indent=4, ensure_ascii=False)

#        convert_services(self)
        convert_other(self)
#        convert_services_groups(self)
        convert_ip_lists(self)
        convert_ip_lists_groups(self)
        convert_ip_group_with_exclusion(self)
#        convert_url_lists(self)
#        convert_application_site_category(self)
#        convert_application_site(self)
#        convert_application_group(self)
#        convert_access_role(self)
#        convert_access_policy_files(self)
        
#        self.save_app_groups()
#        self.save_zones()

        if self.error:
            self.stepChanged.emit('iORANGE|Преобразование конфигурации CheckPoint в формат UG NGFW прошло с ошибками!')
        else:
            self.stepChanged.emit('iGREEN|Преобразование конфигурации CheckPoint в формат UG NGFW прошло успешно.')

    def create_app_group(self, group_name, app_list, comment=''):
        app_group = {
            "name": group_name,
            "description": comment,
            "type": "applicationgroup",
            "list_type_update": "static",
            "schedule": "disabled",
            "attributes": {},
            "content": [{"value": x} for x in app_list]
        }
        self.app_groups.append(app_group)
    
    def save_app_groups(self):
        """Добавляем группы приложений из applications/new_applicationgroup и записываем все группы приложений в файл."""
        for item in new_applicationgroup:
            self.create_app_group(item['name'], item['app_list'], comment="Группа добавлена для совместимости с CheckPoint.")

        if make_dirs(self, 'data_ug/Libraries/Applications'):
            with open("data_ug/Libraries/Applications/config_applications.json", "w") as fh:
                json.dump(self.app_groups, fh, indent=4, ensure_ascii=False)
        self.stepChanged.emit('5|Группы приложений выгружены в файл "data_ug/Libraries/Applications/config_applications.json".')

    def save_zones(self):
        """Сохраняем зоны, если они есть."""
        if self.zones:
            if make_dirs(self, 'data_ug/Network/Zones'):
                with open('data_ug/Network/Zones/config_zones.json', 'w') as fh:
                    json.dump([x for x in self.zones.values()], fh, indent=4, ensure_ascii=False)
            self.stepChanged.emit('2|Зоны выгружены в файл "data_ug/Network/Zones/config_zones.json".')

def convert_config_cp(parent):
    """Конвертируем данные из файла "config_cp.txt" в формат UG NGFW"""
    system_dns = []
    domain_name = None
    ntp = {
        'ntp_servers': [],
        'ntp_enabled': True,
        'ntp_synced': True
    }
    vlans = {}
    gateways = []
    routes = {}
    default_vrf = {
        'name': 'default',
        'description': '',
        'interfaces': [],
        'routes': [],
        'ospf': {},
        'bgp': {},
        'rip': {},
        'pimsm': {}
    }

    def convert_dns_servers(x):
        """Заполняем список системных DNS"""
        match x[1]:
            case 'suffix':
                domain_name = x[2]
            case 'primary'|'secondary':
                system_dns.append({'dns': x[2], 'is_bad': False})

    def convert_ntp_settings(x):
        """Конвертируем настройки для NTP"""
        match x:
            case ['ntp', 'active', status]:
                ntp['ntp_enabled'] = True if status == 'on' else False
            case ['ntp', 'server', 'primary'|'secondary', ip, *other]:
                if len(ntp['ntp_servers']) < 2:
                    ntp['ntp_servers'].append(ip)

    def convert_settings(x):
        """Конвертируем часовой пояс"""
        section_path = os.path.join(parent.current_ug_path, 'UserGate')
        current_path = os.path.join(section_path, 'GeneralSettings')
        err, msg = func.create_dir(current_path, delete='no')
        if err:
            parent.stepChanged.emit(f'RED|    {msg}')
            parent.error = 1
        else:
            data = {
                "ui_timezone": "".join(x[1:])
            }
            json_file = os.path.join(current_path, 'config_settings_ui.json')
            with open(json_file, 'w') as fh:
                json.dump(data, fh, indent=4, ensure_ascii=False)
            parent.stepChanged.emit(f'BLACK|    Чаcовой пояс {data["ui_timezone"]} выгружен в файл "{json_file}".')

    def convert_interfaces(x):
        """Конвертируем интерфейсы VLAN."""
        if '.' in x[1]:
            name = x[1]
            if name not in vlans:
                vlan = {
                    'name': name,
                    'kind': 'vlan',
                    'enabled': False,
                    'description': '',
                    'zone_id': 0,
                    'master': False,
                    'netflow_profile': 'undefined',
                    'lldp_profile': 'undefined',
                    'ipv4': [],
                    'ifalias': '',
                    'flow_control': False,
                    'mode': 'static',
                    'mtu': 1500,
                    'tap': False,
                    'dhcp_relay': {
                        'enabled': False,
                        'host_ipv4': '',
                        'servers': []
                    },
                    'vlan_id': int(name.partition('.')[2]),
                    'link': ''
                }
                vlans[name] = vlan

            match x[2]:
                case 'comments':
                    vlans[name]['description'] = x[3]
                case 'ipv4-address':
                    vlans[name]['ipv4'].append(f"{x[3]}/{x[5]}")
                case 'mtu':
                    vlans[name]['mtu'] = int(x[3])

    def convert_route(x):
        """Конвертируем шлюзы и статические маршруты в VRF по умолчанию"""
        match x[1:]:
            case ['default', 'nexthop', 'gateway', 'address', ip, *other]:
                weight = 1
                if 'priority' in other:
                    priority_index = other.index('priority')
                    weight = int(other[priority_index+1])
                gateway = {
                    'name': f'Default {ip}',
                    'enabled': True,
                    'description': '',
                    'ipv4': ip,
                    'vrf': 'default',
                    'weight': weight,
                    'multigate': False,
                    'default': False if gateways else True,
                    'iface': 'undefined',
                    'is_automatic': False,
                    'active': True
                }
                gateways.append(gateway)
            case [network, 'comment', *comment]:
                if network in routes:
                    routes[network]['description'] = ' '.join(comment)
                else:
                    routes[network] = {
                        'name': f'Route for {network}',
                        'description': ' '.join(comment),
                        'enabled': False,
                        'dest': network,
                        'gateway': '',
                        'ifname': 'undefined',
                        'kind': 'unicast',
                        'metric': 1
                    }
            case [network, 'nexthop', 'gateway', 'address', ip, *other]:
                if network in routes:
                    routes[network]['gateway'] = ip
                else:
                    routes[network] = {
                        'name': f'Route for {network}',
                        'description': '',
                        'enabled': False,
                        'dest': network,
                        'gateway': ip,
                        'ifname': 'undefined',
                        'kind': 'unicast',
                        'metric': 1
                    }

    config_cp = []
    with open(os.path.join(parent.current_vendor_path, 'config_cp.txt'), 'r') as fh:
        for line in fh:
            x = line.strip('\n').split()
            if x and x[0] in {'set', 'add'}:
                config_cp.append(x[1:])

    for x in config_cp:
        match x[0]:
            case 'dns':
                convert_dns_servers(x)
            case 'domainname':
                domain_name = x[1]
            case 'ntp':
                convert_ntp_settings(x)
            case 'timezone':
                convert_settings(x)
            case 'interface':
                convert_interfaces(x)
            case 'static-route':
                convert_route(x)

    #Выгружаем сервера NTP
    if ntp['ntp_servers']:
        section_path = os.path.join(parent.current_ug_path, 'UserGate')
        current_path = os.path.join(section_path, 'GeneralSettings')
        err, msg = func.create_dir(current_path, delete='no')
        if err:
            parent.stepChanged.emit(f'RED|    {msg}')
            parent.error = 1
        else:
            json_file = os.path.join(current_path, 'config_ntp.json')
            with open(json_file, 'w') as fh:
                json.dump(ntp, fh, indent=4, ensure_ascii=False)
            parent.stepChanged.emit(f'BLACK|    Настройка NTP выгружена в файл "{json_file}".')
    else:
        parent.stepChanged.emit(f'GRAY|    Нет серверов NTP для экспорта.')

    #Выгружаем UserGate->Настройки->Модули
    if domain_name:
        modules = {
            "auth_captive": f"auth.{domain_name}",
            "logout_captive": f"logout.{domain_name}",
            "block_page_domain": f"block.{domain_name}",
            "ftpclient_captive": f"ftpclient.{domain_name}",
        }
        section_path = os.path.join(parent.current_ug_path, 'UserGate')
        current_path = os.path.join(section_path, 'GeneralSettings')
        err, msg = func.create_dir(current_path, delete='no')
        if err:
            parent.stepChanged.emit(f'RED|    {msg}')
            parent.error = 1
        else:
            json_file = os.path.join(current_path, 'config_settings.json')
            with open(json_file, 'w') as fh:
                json.dump(modules, fh, indent=4, ensure_ascii=False)
            parent.stepChanged.emit(f'BLACK|    Настройки домена авторизации выгружены в файл "{json_file}".')
    else:
        parent.stepChanged.emit(f'GRAY|    Нет домена авторизации для экспорта.')

    #Выгружаем сервера DNS
    if system_dns:
        section_path = os.path.join(parent.current_ug_path, 'Network')
        current_path = os.path.join(section_path, 'DNS')
        err, msg = func.create_dir(current_path, delete='no')
        if err:
            parent.stepChanged.emit(f'RED|    {msg}')
            parent.error = 1
        else:
            json_file = os.path.join(current_path, 'config_dns_servers.json')
            with open(json_file, 'w') as fh:
                json.dump(system_dns, fh, indent=4, ensure_ascii=False)
            parent.stepChanged.emit(f'BLACK|    Настройки серверов DNS выгружены в файл "{json_file}".')
    else:
        parent.stepChanged.emit(f'GRAY|    Нет серверов DNS для экспорта.')

    #Выгружаем интерфейсы VLAN
    if vlans:
        section_path = os.path.join(parent.current_ug_path, 'Network')
        current_path = os.path.join(section_path, 'Interfaces')
        err, msg = func.create_dir(current_path)
        if err:
            parent.stepChanged.emit(f'RED|    {msg}')
            parent.error = 1
        else:
            json_file = os.path.join(current_path, 'config_interfaces.json')
            with open(json_file, 'w') as fh:
                json.dump([x for x in vlans.values()], fh, indent=4, ensure_ascii=False)
            parent.stepChanged.emit(f'BLACK|    Интерфейсы VLAN выгружены в файл "{json_file}".')
    else:
        parent.stepChanged.emit(f'GRAY|    Нет Интерфейсов VLAN для экспорта.')

    #Выгружаем шлюзы
    if gateways:
        section_path = os.path.join(parent.current_ug_path, 'Network')
        current_path = os.path.join(section_path, 'Gateways')
        err, msg = func.create_dir(current_path)
        if err:
            parent.stepChanged.emit(f'RED|    {msg}')
            parent.error = 1
        else:
            json_file = os.path.join(current_path, 'config_gateways.json')
            with open(json_file, 'w') as fh:
                json.dump(gateways, fh, indent=4, ensure_ascii=False)
            parent.stepChanged.emit(f'BLACK|    Настройки шлюзов выгружены в файл "{json_file}".')
    else:
        parent.stepChanged.emit(f'GRAY|    Нет шлюзов для экспорта.')

    #Выгружаем статические маршруты в VRF по умолчанию
    if routes:
        default_vrf['routes'].extend([x for x in routes.values()])

        section_path = os.path.join(parent.current_ug_path, 'Network')
        current_path = os.path.join(section_path, 'VRF')
        err, msg = func.create_dir(current_path)
        if err:
            parent.stepChanged.emit(f'RED|    {msg}')
            parent.error = 1
        else:
            json_file = os.path.join(current_path, 'config_vrf.json')
            with open(json_file, 'w') as fh:
                json.dump([default_vrf], fh, indent=4, ensure_ascii=False)
            parent.stepChanged.emit(f'BLACK|    Статические маршруты выгружены в файл "{json_file}".')
    else:
        parent.stepChanged.emit(f'GRAY|    Нет статических маршрутов для экспорта.')

#-------------------------------------------------------------------------------------------------------------------
def convert_services(parent):
    """
    Конвертируем список сервисов. В "objects" UID-ы с сервисами переписываются в вид:
    uid: {'type'; 'service', 'name': 'ИМЯ_СЕРВИСА'} для загрузки сервисов в правила.
    """
    parent.stepChanged.emit('BLUE|Конвертация списков сервисов.')

    for key, value in parent.objects.items():
        if value['type'] == 'service-icmp':
            parent.objects[key] = {'type': 'service', 'name': 'Any ICMP'}
            parent.services['Any ICMP'] = {
                'name': 'Any ICMP',
                'description': 'Any ICMP packet',
                'protocols': [
                    {
                        'proto': 'icmp',
                        'port': '',
                        'app_proto': '',
                        'source_port': '',
                        'alg': ''
                    }
                ]
            }
        elif value['type'] == 'service-icmp6':
            parent.objects[key] = {'type': 'service', 'name': 'Any IPV6-ICMP'}
            parent.services['Any IPV6-ICMP'] = {
                'name': 'Any IPV6-ICMP',
                'description': 'Any IPV6-ICMP packet',
                'protocols': [
                    {
                        'proto': 'ipv6-icmp',
                        'port': '',
                        'app_proto': '',
                        'source_port': '',
                        'alg': ''
                    }
                ]
            }
        elif value['type'] in ('service-tcp', 'service-udp'):
            _, proto = value['type'].split('-')
            parent.objects[key] = ServicePorts.get_dict_by_port(proto, value['port'], value['name'])
            service_name = ServicePorts.get_name_by_port(proto, value['port'], value['name'])
            
            port = value.get('port', "")
            if (">" or "<") in port:
                parent.objects[key]['type'] = 'error'
                parent.objects[key]['description'] = 'Символы "<" и ">" не поддерживаются в определении порта.'
                parent.stepChanged.emit(f'bRED|    Warning: Сервис "{service_name}" содержит символы "<" или ">". Такое значение порта не поддерживается. Сервис не конвертирован.')
            else:
                parent.services[service_name] = {
                    'name': service_name,
                    'description': value['comments'],
                    'protocols': [
                        {
                            'proto': proto,
                            'port': value.get('port', ''),
                            'app_proto': '',
                            'source_port': '',
                            'alg': ''
                        }
                    ]
                }

    if parent.services:
        section_path = os.path.join(parent.current_ug_path, 'Libraries')
        current_path = os.path.join(section_path, 'Services')
        err, msg = func.create_dir(current_path)
        if err:
            parent.stepChanged.emit(f'RED|    {msg}')
            parent.error = 1
            return

        json_file = os.path.join(current_path, 'config_services_list.json')
        with open(json_file, 'w') as fh:
            json.dump(list(parent.services.values()), fh, indent=4, ensure_ascii=False)
        parent.stepChanged.emit(f'GREEN|    Список сервисов выгружен в файл "{json_file}".')
    else:
        parent.stepChanged.emit(f'GRAY|    Нет сервисов для экспорта.')


def convert_services_groups(parent):
    """
    Конвертируем группы сервисов. В "objects" UID-ы с сервис группами переписываются в вид:
    uid: {'type': 'servicegroup', 'name': 'ИМЯ_СЕРВИСА'} для загрузки сервисов в правила.
    """
    parent.stepChanged.emit('BLUE|Конвертация групп сервисов.')
    section_path = os.path.join(parent.current_ug_path, 'Libraries')
    current_path = os.path.join(section_path, 'ServicesGroups')
    err, msg = func.create_dir(current_path)
    if err:
        parent.stepChanged.emit(f'RED|    {msg}')
        parent.error = 1
        return

    # Создаём словарь row_groups. Он используется в основном цикле для добавления сервисов вложенных групп в группу.
    # Отдельный цикл нужен, так как в objects группы идут не в порядке вложения в другие группы.
    row_groups = {}
    for key, value in parent.objects.items():
        if value['type'] == 'service-group':
            row_groups[value['name']] = set()
            for uid in value['members']:
                if uid in parent.objects:
                    service = parent.objects[uid]
                elif uid in embedded_objects:
                    if embedded_objects[uid]['type'] == 'service':
                        service = embedded_objects[uid]
                    else:
                        continue
                else:
                    continue
                if service['type'] != 'error':
                    row_groups[value['name']].add(service['name'])

    # Основной цикл обработки групп сервисов..
    len_1 = len(parent.services)
    servicegroups = {}
    for key, value in parent.objects.items():
        if value['type'] == 'service-group':
            members = set()  # Для members использован сет для удаления одинаковых сервисов.
            for uid in value['members']:
                if uid in parent.objects:
                    service = parent.objects[uid]
                elif uid in embedded_objects:
                    service = embedded_objects[uid]
                    if service['type'] == 'service':
                        parent.services[service['name']] = {
                            'name': service['name'],
                            'description': service['description'],
                            'protocols': [
                                {
                                    'proto': service['proto'],
                                    'port': service['port'],
                                    'app_proto': '',
                                    'source_port': '',
                                    'alg': ''
                                }
                            ]
                        }
                    else:
                        continue
                else:
                    continue
                if service['type'] == 'error':
                    parent.stepChanged.emit(f'bRED|    {service["description"]}. Этот сервис не будет добавлен в группу сервисов "{value["name"]}".')
                else:
                    members.add(service['name'])

            content = []
            for name in members:
                try:
                    content.append(parent.services[name])
                except KeyError as err:
                    if name in row_groups:
                        for item in row_groups[name]:
                            content.append(parent.services[item])
                    else:
                        parent.stepChanged.emit(f'bRED|    Группа сервисов {name} не будет добавлена в группу сервисов "{value["name"]}". Нельзя создать вложенные группы 3-его уровня.')

            for item in content:
                for x in item['protocols']:
                    x.pop('alg', None)
                    x.pop('source_port', None)
                    x.pop('app_proto', None)

            services_group = {
                'name': value['name'],
                'description': value['comments'],
                'type': 'servicegroup',
                'url': '',
                'list_type_update': 'static',
                'schedule': 'disabled',
                'attributes': {},
                'content': content
            }

            parent.objects[key] = {'type': 'servicegroup', 'name': value['name']}
            servicegroups[value['name']] = services_group
            parent.stepChanged.emit(f'BLACK|    Группа сервисов {value["name"]} конвертирована".')

    if servicegroups:
        json_file = os.path.join(current_path, 'config_services_groups_list.json')
        with open(json_file, 'w') as fh:
            json.dump([x for x in servicegroups.values()], fh, indent=4, ensure_ascii=False)
        parent.stepChanged.emit(f'GREEN|    Список групп сервисов выгружен в файл "{json_file}".')

    len_2 = len(parent.services)
    if len_1 != len_2:
        current_path = os.path.join(section_path, 'Services')
        json_file = os.path.join(current_path, 'config_services_list.json')
        with open(json_file, 'w') as fh:
            json.dump(list(parent.services.values()), fh, indent=4, ensure_ascii=False)
        parent.stepChanged.emit(f'GREEN|    Список сервисов обновлён в файле "{json_file}".')


def convert_ip_lists(parent):
    """
    Выгружаем списки IP-адресов.
    В "objects" типы "host", "address-range", "network" переписываются в вид:
    uid: {"type": "network", "name": {"list": "ИМЯ_IP_ЛИСТА"}} для загрузки ip-листов в правила. Или
    uid: {"type": "error", "name": f'Объект value["type"]: "{value["name"]}" содержит IPV6 адрес.'}
    """
    parent.stepChanged.emit('BLUE|Конвертация списков IP-адресов.')
    section_path = os.path.join(parent.current_ug_path, 'Libraries')
    current_path = os.path.join(section_path, 'IPAddresses')
    err, msg = func.create_dir(current_path)
    if err:
        parent.stepChanged.emit(f'RED|    {msg}')
        parent.error = 1
        return

    error = 0
    for key, value in parent.objects.items():
        if value['type'] in ('host', 'address-range', 'network'):
            if value.keys().isdisjoint(('ipv4-address', 'ipv4-address-first', 'subnet4')):
                parent.stepChanged.emit(f"bRED|    Объект value['type']: '{value['name']}' содержит IPV6 адрес или подсеть. Данный тип адреса не поддерживается.")
                parent.objects[key] = {'type': 'error', 'name': f'Объект value["type"]: "{value["name"]}" содержит IPV6 адрес или подсеть.'}
                continue
            parent.objects[key] = {'type': 'network', 'name': {'list': func.get_restricted_name(value['name'])}}
            match value['type']:
                case 'host':
                    content = [{'value': value['ipv4-address']}]
                case 'address-range':
                    content = [{'value': f"{value['ipv4-address-first']}-{value['ipv4-address-last']}"}]
                case 'network':
                    content = [{'value': f"{value['subnet4']}/{value['mask-length4']}"}]

            ip_list = {
                'name': func.get_restricted_name(value['name']),
                'description': value['comments'],
                'type': 'network',
                'url': '',
                'list_type_update': 'static',
                'schedule': 'disabled',
                'attributes': {'threat_level': 3},
                'content': content
            }

            json_file = os.path.join(current_path, f'{value["name"].translate(trans_filename)}.json')
            try:
                with open(json_file, 'w') as fh:
                    json.dump(ip_list, fh, indent=4, ensure_ascii=False)
                parent.stepChanged.emit(f'BLACK|    Список IP-адресов "{ip_list["name"]}" выгружен в файл "{json_file}".')
            except OSError as err:
                error = 1
                parent.error = 1
                parent.objects[key] = {'type': 'error', 'name': value['name'], 'description': f'Список IP-адресов "{value["name"]}" не конвертирован.'}
                parent.stepChanged.emit(f'RED|    Объект "{value["type"]}" - "{value["name"]}" не конвертирован и не будет использован в правилах.')
                parent.stepChanged.emit(f'RED|    {err}')
            time.sleep(0.1)

    if error:
        parent.stepChanged.emit('ORANGE|    Списки IP-адресов выгружены с ошибками.')
    else:
        parent.stepChanged.emit(f'GREEN|    Списки IP-адресов выгружены в каталог "{current_path}".')


def convert_ip_lists_groups(parent):
    """
    Выгружаем списки групп IP-адресов.
    В "objects" тип "group" переписывается в вид:
    uid: {"type": "network", "name": {"list": "ИМЯ_IP_ЛИСТА"}}.
    """
    parent.stepChanged.emit('BLUE|Конвертация списков групп IP-адресов.')
    section_path = os.path.join(parent.current_ug_path, 'Libraries')
    current_path = os.path.join(section_path, 'IPAddresses')
    err, msg = func.create_dir(current_path, delete='no')
    if err:
        parent.stepChanged.emit(f'RED|    {msg}')
        parent.error = 1
        return

    error = 0
    for key, value in parent.objects.items():
        if value['type'] == 'group':
            parent.objects[key] = {'type': 'network', 'name': {'list': func.get_restricted_name(value['name'])}}
            content = []
            for uid in value['members']:
                try:
                    if parent.objects[uid]['type'] == 'simple-gateway':
                        content.append({"value": parent.objects[uid]['ipv4-address']})
                    else:
                        if isinstance(parent.objects[uid]['name'], dict):
                            content.append(parent.objects[uid]['name'])
                        elif isinstance(parent.objects[uid]['name'], str):
                            content.append({"list": parent.objects[uid]['name']})
                        else:
                            error = 1
                            parent.stepChanged.emit(f'RED|    Не определён тип объекта "{parent.objects[uid]["name"]}". Данный список IP-адресов не будет включён в группу {value["name"]}.')
                except KeyError:
                    error = 1
                    parent.error = 1
                    parent.stepChanged.emit(f'RED|    В группе IP-аресов "{value["name"]}" присутствует ссылка на несуществующий объект: {uid}.')
            ip_list = {
                'name': func.get_restricted_name(value['name']),
                'description': value['comments'],
                'type': 'network',
                'url': '',
                'list_type_update': 'static',
                'schedule': 'disabled',
                'attributes': {'threat_level': 3},
                'content': content
            }

            json_file = os.path.join(current_path, f'{value["name"].translate(trans_filename)}.json')
            try:
                with open(json_file, 'w') as fh:
                    json.dump(ip_list, fh, indent=4, ensure_ascii=False)
                parent.stepChanged.emit(f'BLACK|    Список групп IP-адресов "{ip_list["name"]}" выгружен в файл "{json_file}".')
            except OSError as err:
                error = 1
                parent.error = 1
                parent.objects[key] = {'type': 'error', 'name': value['name'], 'description': f'Список групп IP-адресов "{value["name"]}" не конвертирован.'}
                parent.stepChanged.emit(f'RED|    Объект "{value["type"]}" - "{value["name"]}" не конвертирован и не будет использован в правилах.')
                parent.stepChanged.emit(f'RED|    {err}')
            time.sleep(0.1)

    if error:
        parent.stepChanged.emit('ORANGE|    Списки групп IP-адресов выгружены с ошибками.')
    else:
        parent.stepChanged.emit(f'GREEN|    Списки групп IP-адресов выгружены в каталог "{current_path}".')


def convert_ip_group_with_exclusion(parent):
    """
    В objects.json тип "group-with-exclusion" переписывается в вид:
    uid: {
        "type": "group-with-exclusion",
        "groups": [
            {
                "type": "network",
                "name": {"list": "ИМЯ_IP_ЛИСТА"},
                "action": "accept|drop"  - если drop, в правиле ставим признак 'Инвертировать'
            },
            ....
        ]
    }
    """
    parent.stepChanged.emit('BLUE|Конвертация групп IP-адресов с типом group-with-exclusion.')

    error = 0
    for key, value in parent.objects.items():
        if value['type'] == 'group-with-exclusion':
            try:
                groups = []
                if 'except' in value:
                    groups.append({"type": "network", "name": parent.objects[value['except']['uid']]['name'], "action": "drop"})
                if 'include' in value:
                    groups.append({"type": "network", "name": parent.objects[value['include']['uid']]['name'], "action": "accept"})
                parent.objects[key] = {"type": "group-with-exclusion", "groups": groups}
#                print(parent.objects[key], '\n')
            except KeyError as err:
                error = 1
                parent.error = 1
                parent.objects[key] = {'type': 'error', 'name': value['name'], 'description': f'Объект group-with-exclusion "{value["name"]}" не конвертирован.'}
                parent.stepChanged.emit(f'bRED|    Warning! Group-with-exclusion "{value["name"]}" не конвертирована: {err}.')

    if error:
        parent.stepChanged.emit('ORANGE|    Группы IP-адресов с типом group-with-exclusion конвертированы с ошибками.')
    else:
        parent.stepChanged.emit('GREEN|    Группы IP-адресов с типом group-with-exclusion конвертированы.')


def convert_url_lists(parent):
    """
    Выгружаем списки URL в каталог data_ug/Libraries/URLLists для последующей загрузки в NGFW.
    В "objects" тип "application-site" переписывается в вид: uid: {'type': 'url', 'name': 'ИМЯ_URL_ЛИСТА'}.
    """
    parent.stepChanged.emit('0|Конвертация списков URL.')

    if os.path.isdir('data_ug/Libraries/URLLists'):
        for file_name in os.listdir('data_ug/Libraries/URLLists'):
            os.remove(f'data_ug/Libraries/URLLists/{file_name}')
    else:
        os.makedirs('data_ug/Libraries/URLLists')

    error = 0
    for key, value in parent.objects.items():
        if value['type'] == 'application-site' and 'url-list' in value:
            parent.objects[key] = {'type': 'url', 'name': func.get_restricted_name(value['name'])}

            url_list = {
                "name": func.get_restricted_name(value['name']),
                "description": value['comments'],
                "type": "url",
                "url": "",
                "attributes": {
                    "threat_level": dict_risk.get(value['risk'], 5)
                },
                "content": [{'value': url.translate(trans_url)} for url in value['url-list']]
            }

            file_name = value['name'].translate(trans_filename)
            with open(f"data_ug/Libraries/URLLists/{file_name}.json", "w") as fh:
                json.dump(url_list, fh, indent=4, ensure_ascii=False)
            parent.stepChanged.emit(f'2|Список URL "{value["name"]}" выгружен в файл "data_ug/Libraries/URLLists/{file_name}.json"')

    parent.stepChanged.emit('4|Конвертация списков URL прошла с ошибками!' if error else '5|Конвертация списков URL завершена.')

def convert_application_site_category(parent):
    """
    В "objects" тип "application-site-category" переписывается в вид: uid:
    uid: {
       'type': 'app-url-category',
       'l7_category': ['ИМЯ_КАТЕГОРИИ_ПРИЛОЖЕНИЙ', ...],
       'url_category': ['ИМЯ_КАТЕГОРИИ_URL', ...],
       'applicationgroup': ['ИМЯ_ГРУППЫ ПРИЛОЖЕНИЙ', ...]
    }
    """
    parent.stepChanged.emit('0|Конвертация application-site-categoty.')
    
    error = 0
    for key, value in parent.objects.items():
        if value['type'] == 'application-site-category':
            try:
                parent.objects[key] = cp_app_category[value['name']]
            except KeyError:
                error = 1
                parent.error = 1
                parent.objects[key] = {'type': 'error', 'name': value['name'], 'description': f'Для категории "{value["name"]}" нет аналога на UG NGFW.'}
                parent.stepChanged.emit(f'4|Warning! Application-site-category "{value["name"]}" не конвертирована (нет аналога на UG NGFW).')
    parent.stepChanged.emit('4|Конвертации application-site-categoty прошла с ошибками. Некоторые категории не перенесены.' if error else '5|Конвертация application-site-category прошла успешно.')

def convert_application_site(parent):
    """
    В файле objects.json в типе application-site переписывается в вид:
    uid: {'type': 'l7apps', 'name': ['app_name']}.
    """
    parent.stepChanged.emit('0|Конвертация application-site в Приложения и Категории URL.')

    error = 0
    for key, value in parent.objects.items():
        if value['type'] == 'application-site':
            try:
                parent.objects[key] = cp_app_site[value['name']]
            except KeyError:
                error = 1
                parent.error = 1
                parent.objects[key] = {'type': 'error', 'name': value["name"], 'description': f'Для приложения "{value["name"]}" нет аналога на UG NGFW.'}
                parent.stepChanged.emit(f'4|Warning! Приложение "{value["name"]}" не конвертировано (нет аналога на UG NGFW).')
    parent.stepChanged.emit('4|Конвертации application-site прошла с ошибками. Некоторые приложения не перенесены.' if error else '5|Конвертация application-site прошла успешно.')

def convert_application_group(parent):
    """
    Конвертация application-site-group в группы приложений и группы категорий URL.
    В файле objects.json в типе application-site-group переписывается в вид:
    uid: {
        "type": "apps_group",
        "apps": [["ro_group", RO_GROUP_NAME], ..., ["group", GROUP_NAME], ...],
        "url_categories": [["list_id", LIST_NAME], ...],
        "urls": ["ИМЯ_URL_ЛИСТА", ...]
        "error": 0  - Если нет ошибки. Если объект получился пустой (нет приложений и категорий в NGFW), ставим маркер ошибки '1'.
                      В этом случае в названии правила МЭ пишем: "ERROR - ИМЯ_ПРАВИЛА".
        "description": ["Для приложения ... нет аналога на NGFW", ...] - если в этой группе не конвертировались приложения или категории.
                      В описание правила МЭ добавляем этот description с описанием проблем.
    }
    """
    parent.stepChanged.emit('0|Конвертация application-site-group в группы приложений и URL категорий.')

    url_groups = []
    for key in parent.objects:
        try:
            if parent.objects[key]['type'] == 'application-site-group':
                app = set()
                ro_group = set()
                applicationgroups = set()
                url_category = set()
                url_list = set()
                apps_group_tmp = {
                    "name": func.get_restricted_name(parent.objects[key]['name']),
                    "comments": parent.objects[key]['comments'],
                    "type": "apps_group",
                    "apps": [],
                    "url_categories": [],
                    "urls": [],
                    "error": 0,
                    "description": []
                }
                for item in parent.objects[key]['members']:
                    try:
                        match parent.objects[item]['type']:
                            case 'app-url-category':
                                for name in parent.objects[item]['l7_category']:
                                    ro_group.add(name)
                                for name in parent.objects[item]['applicationgroup']:
                                    applicationgroups.add(name)
                                for name in parent.objects[item]['url_category']:
                                    url_category.add(name)
#                                    apps_group_tmp['url_categories'].append(['category_id', name])
                            case 'l7apps':
                                for name in parent.objects[item]['name']:
                                    app.add(name)
                            case 'l7_category':
                                for name in parent.objects[item]['name']:
                                    ro_group.add(name)
                            case 'applicationgroup':
                                for name in parent.objects[item]['name']:
                                    applicationgroups.add(name)
                            case 'url_category':
                                for name in parent.objects[item]['name']:
                                    url_category.add(name)
                            case 'url':
                                url_list.add(parent.objects[item]['name'])
                            case 'error':
                                apps_group_tmp['description'].append(parent.objects[item]['description'])
                    except (TypeError, KeyError) as err:
                        parent.stepChanged.emit(f'4|Warning! {err} - {item}.')

                apps_group_tmp['apps'].extend([['ro_group', x] for x in ro_group]),
                apps_group_tmp['apps'].extend([['group', x] for x in applicationgroups]),
                apps_group_tmp['urls'] = [x for x in url_list]

                if app:
                    apps_group_tmp['apps'].append(['group', apps_group_tmp['name']])
                    parent.create_app_group(apps_group_tmp['name'], app, comment=apps_group_tmp['comments'])
                    
                if url_category:
                    url_groups.append(
                        {
                            "name": apps_group_tmp['name'],
                            "description": apps_group_tmp['comments'],
                            "type": "urlcategorygroup",
                            "url": "",
                            "list_type_update": "static",
                            "schedule": "disabled",
                            "attributes": {},
                            "content": [{"name": x} for x in url_category]
                        }
                    )
                    apps_group_tmp['url_categories'].append(['list_id', apps_group_tmp['name']])
                # Если объект получился пустой (нет приложений и категорий в NGFW), ставим маркер ошибки.
                # В названии правила МЭ пишем: "ERROR - ИМЯ_ПРАВИЛА".
                # В описание правила МЭ добавляем objects[key]['description'] с описанием проблемы.
                if not apps_group_tmp['apps'] and not apps_group_tmp['url_categories'] and not apps_group_tmp['urls']:
                    apps_group_tmp['error'] = 1

                parent.objects[key] = apps_group_tmp
        except (TypeError, KeyError) as err:
            parent.stepChanged.emit(f'4|Warning! {err} - {parent.objects[key]}.')
    parent.stepChanged.emit('5|Конвертация application-site-group завершена.')

    if url_groups:
        if make_dirs(parent, 'data_ug/Libraries/URLCategories'):
            with open("data_ug/Libraries/URLCategories/config_categories_url.json", "w") as fh:
                json.dump(url_groups, fh, indent=4, ensure_ascii=False)
            parent.stepChanged.emit('5|Группы URL категорий выгружены в файл "data_ug/Libraries/URLCategories/config_categories_url.json".')

def convert_access_role(parent):
    """
    Конвертация access-role в objects.json.
    В файле объектов objects.json UID с access-role переписываются в вид:
    uid: {
        "networks": [["list_id", "ИМЯ_IP_ЛИСТА"], ...],
        "users": [
            ["user", "доменое_имя_юзера"],
            ["special", "known_user"],
            ...
            ["group", "name_of_group_users"],
        ]
    }
    """
    parent.stepChanged.emit('0|Конвертация access-role.')

    error = 0
    for key, value in parent.objects.items():
        try:
            if value['type'] == 'access-role':
                tmp_role = {
                    'type': value['type'],
                    'name': value['name'],
                }
                if value['networks'] != 'any':
                    tmp_role['networks'] = [['list_id', x['name']] for x in value['networks']]
                users = []
                if isinstance(value['users'], list):
                    for item in value['users']:
                        tooltip = [x for x in item['tooltiptext'].split('\n')]
                        if '=' in tooltip[1]:
                            tmp1 = tooltip[0].split(' = ')
                            tmp2 = tooltip[1].split(' = ')
                            name = f'{tmp1[1][:-4].lower()}\\{tmp2[1]}'
                        elif ':' in tooltip[1]:
                            tmp1 = tooltip[0].split(': ')
                            tmp2 = tooltip[5].split(': ')
                            name = f'{tmp1[1][:-4].lower()}\\{tmp2[1].split("@")[0]}'
                        else:
                            continue
                        if item['type'] == 'CpmiAdGroup':
                            users.append(['group', name])
                        else:
                            users.append(['user', name])
                elif value['users'] == "all identified":
                    users.append(['special', 'known_user'])
                elif value['users'] == "any":
                    pass
                else:
                    parent.stepChanged.emit(f'4|Warning! access-role "{value["name"]}": users = {value["users"]}.')
                tmp_role['users'] = users
                parent.objects[key] = tmp_role
        except KeyError as err:
            parent.stepChanged.emit(f'4|Warning! {value["name"]} - {err}')
            error = 1
            parent.error = 1

    parent.stepChanged.emit('4|Конвертации access-role прошла с ошибками.' if error else '5|Конвертация access-role прошла успешно.')

def convert_other(parent):
    """
    Конвертация RulebaseAction, CpmiAnyObject и service-other в objects.json.
    В файле объектов objects.json UID с type 'RulebaseAction', 'CpmiAnyObject' и service-other заменяются на:
    uid: {"type": "RulebaseAction", "value": "Accept|Drop|Inform"} если type: 'RulebaseAction',
    uid: {"type": "CpmiAnyObject", "value": "Any"} если type: 'CpmiAnyObject',
    uid: {"type": "error", "name": "ИМЯ_СЕРВИСА", "description": "Сервис ИМЯ_СЕРВИСА не конвертирован."} если type: service-other
    """
    parent.stepChanged.emit('BLUE|Конвертация сопутствующих объектов.')

    for key, value in parent.objects.items():
        try:
            match value['type']:
                case 'RulebaseAction':
                    parent.objects[key] = {"type": "RulebaseAction", "value": "accept" if value['name'] == 'Inform' else value['name'].lower()}
                case 'CpmiAnyObject':
                    parent.objects[key] = {"type": "CpmiAnyObject", "value": "Any"}
                case 'service-other':
                    parent.objects[key] = {'type': 'error', 'name': value["name"], 'description': f'Сервис "{value["name"]}" не конвертирован'}
                    parent.stepChanged.emit(f'bRED|    Warning! Сервисе "{value["name"]}" (тип service-other) не конвертирован и не будет использован в правилах!')
                case 'Internet':
                    parent.objects[key] = {"type": "Zone", "value": "Internet"}
                    create_zone('Internet', parent.zones)
        except KeyError:
            pass
    parent.stepChanged.emit('BLACK|Конвертации сопутствующих объектов завершена.')


def convert_access_policy_files(parent):
    """
    Читаем файл index.json и выбираем файлы конфигурации из раздела 'accessLayers'. Читаем их и вместо uid
    подставляем значения преобразованных объектов из objects. Затем в зависимости от содержимого создаём
    правило МЭ или КФ или правило МЭ и КФ.
    """
    access_rules = []
    checkpoint_hosts = ('CpmiClusterMember', 'simple-cluster', 'checkpoint-host')
    rule_names = set()

    for access_layer in parent.sg_index[parent.sg_name]['accessLayers']:
        access_policy_file = f"{access_layer['name']}-{access_layer['domain']}.json"
        parent.stepChanged.emit(f'0|Конвертируется файл {access_policy_file}.')

        with open(os.path.join(parent.cp_data_json, access_policy_file), "r") as fh:
            data = json.load(fh)

        for item in data:
            if item['type'] == 'access-rule':
                if 'name' not in item or not item['name'] or item['name'].isspace():
                    item['name'] = str(uuid.uuid4()).split('-')[4]
                item['name'] = func.get_restricted_name(item['name'])
                if item['name'] == 'Cleanup rule':
                    continue
                if item['name'] in rule_names:  # Встречаются одинаковые имена.
                    item['name'] += '-1'        # В этом случае добавляем "-1" к имени правила.
                rule_names.add(item['name'])

                item.pop('meta-info', None)
                item.pop('vpn', None)
                item.pop('domain', None)
                item.pop('install-on', None)
                item.pop('track', None)
                item.pop('custom-fields', None)
                item.pop('user-check', None)
                item['description'] = []

                destination = []
                for uid in item['destination']:
                    if parent.objects[uid]['type'] in checkpoint_hosts:
                        item['description'].append(f'Из destination удалена запись {parent.objects[uid]["name"]},')
                    else:
                        destination.append(parent.objects[uid])
                item['destination'] = destination
                source = []
                for uid in item['source']:
                    if parent.objects[uid]['type'] in checkpoint_hosts:
                        item['description'].append(f'Из source удалена запись {parent.objects[uid]["name"]},')
                    else:
                        source.append(parent.objects[uid])
                item['source'] = source
                item['content'] = [parent.objects[uid] for uid in item['content']]
                item['action'] = parent.objects[item['action']]
                item['service'] = [parent.objects[uid] for uid in item['service']]
                item['time'] = [parent.objects[uid] for uid in item['time']]
                
        with open(os.path.join(parent.cp_data_json, access_policy_file.replace('.json', '_convert.json')), "w") as fh:
            json.dump(data, fh, indent=4, ensure_ascii=False)
        access_rules.extend(data)
        parent.stepChanged.emit(f'2|Файл {access_policy_file.replace(".json", "_convert.json")} создан.')

    parent.stepChanged.emit(f'0|Конвертация access-rules.')
    fw_rules = []
    kf_rules = []
    for item in access_rules:
        if item['type'] == 'access-rule':
            if item['name'] == 'Cleanup rule':
                continue
            services = set()
            service_groups = set()
            apps = []
            l7apps = set()
            url_categories = []
            urls = []
            for value in item['service']:
                match value['type']:
                    case 'service':
                        services.add(value['name'])
                    case 'servicegroup':
                        service_groups.add(value['name'])
                    case 'apps_group':
                        if not value['error']:
                            apps.extend(value['apps'])                      # добавляется ['ro_group', 'имя категории приложений'], ['group', 'имя группы прилодений']
                            url_categories.extend(value['url_categories'])  # добавляется ['list_id', 'name_of_categories']
                            urls.extend(value['urls'])
                        item['description'].extend(value['description'])
                    case 'l7apps':
                        l7apps.update(value['name'])
                    case 'app-url-category':
                        apps.extend([['ro_group', x] for x in value['l7_category']])
                        apps.extend([["group", x] for x in  value['applicationgroup']])
                        url_categories.extend([['category_id', x] for x in value['url_category']])
                    case 'l7_category':
                        apps.extend([['ro_group', x] for x in value['name']])
                    case 'url':
                        urls.append(value['name'])
                    case 'error':
                        item['description'].append(value['description'])
            if l7apps:
                appsgroup_name = str(uuid.uuid4()).split('-')[4]
                apps.append(["group", appsgroup_name])
                parent.create_app_group(appsgroup_name, l7apps, comment=f'Создано для правила "{item["name"]}".')

            if item['description']:
                item['name'] = f'ERROR - {item["name"]}'

            item['services'] = [['service', service_name] for service_name in services]
            item['services'].extend([['list_id', servicegroup_name] for servicegroup_name in service_groups])
            item['apps'] = apps
            item['url_categories'] = url_categories
            item['urls'] = urls

            indicator = False
            if services or service_groups or apps:
                create_firewall_rule(parent, item, fw_rules)
                indicator = True
            if url_categories or urls:
                create_content_rule(parent, item, kf_rules)
                indicator = True
            if not indicator:
                create_firewall_rule(parent, item, fw_rules, err=1)

    with open(os.path.join(parent.cp_data_json, "access_rules.json"), "w") as fh:
        json.dump(access_rules, fh, indent=4, ensure_ascii=False)

    if make_dirs(parent, 'data_ug/NetworkPolicies/Firewall'):
        with open("data_ug/NetworkPolicies/Firewall/config_firewall_rules.json", "w") as fh:
            json.dump(fw_rules, fh, indent=4, ensure_ascii=False)
        parent.stepChanged.emit('5|Правила межсетевого экрана выгружены в файл "data_ug/NetworkPolicies/Firewall/config_firewall_rules.json".')

    if make_dirs(parent, 'data_ug/SecurityPolicies/ContentFiltering'):
        with open("data_ug/SecurityPolicies/ContentFiltering/config_content_rules.json", "w") as fh:
            json.dump(kf_rules, fh, indent=4, ensure_ascii=False)
        parent.stepChanged.emit('5|Правила контентной фильтрации выгружены в файл "data_ug/SecurityPolicies/ContentFiltering/config_content_rules.json".')

def create_firewall_rule(parent, item, fw_rules, err=0):
    """
    Создаём правило МЭ из access-rule CheckPoint. Если err=1, правило будет пустое с пояснением ошибок в описание правила.
    """
    parent.stepChanged.emit(f'2|Конвертация access-rule "{item["name"]}" в правило межсетевого экрана.')

    item['description'].append(item['comments'])
    
    rule = {
        "name": item['name'],
        "description": "\n".join(item['description']),
        "action": item['action']['value'] if item['action']['type'] == 'RulebaseAction' else 'drop',
        "position": item['rule-number'],
        "scenario_rule_id": False,
        "src_zones": [x['value'] for x in item['source'] if x['type'] == 'Zone'],
        "src_ips": get_ips_list(item['source']),
        "dst_zones": [x['value'] for x in item['destination'] if x['type'] == 'Zone'],
        "dst_ips": get_ips_list(item['destination']),
        "services": item['services'],
        "apps": item['apps'],
        "users": get_users_list(item['source'], item['destination']),
        "enabled": False,
        "limit": True,
        "lmit_value": "3/h",
        "lmit_burst": 5,
        "log": True,
        "log_session_start": True,
        "src_zones_negate": False,
        "dst_zones_negate": False,
        "src_ips_negate": item['source-negate'],
        "dst_ips_negate": item['destination-negate'],
        "services_negate": item['service-negate'],
        "apps_negate": item['service-negate'],
        "fragmented": "ignore",
        "time_restrictions": [],
        "send_host_icmp": "",
    }

    fw_rules.append(rule)
    parent.stepChanged.emit(f'2|    Создано правило межсетевого экрана "{item["name"]}".')

def create_content_rule(parent, item, kf_rules):
    """
    Создаём правило КФ из access-rule CheckPoint.
    """
    parent.stepChanged.emit(f'2|Конвертация access-rule "{item["name"]}" в правило контентной фильтации.')

    item['description'].append(item['comments'])

    rule = {
        'position': item['rule-number'],
        'action': item['action']['value'] if item['action']['type'] == 'RulebaseAction' else 'drop',
        'name': item['name'],
        'public_name': '',
        'description': "\n".join(item['description']),
        'enabled': False,
        'enable_custom_redirect': False,
        'blockpage_template_id': -1,
        'users': get_users_list(item['source'], item['destination']),
        'url_categories': item['url_categories'],
        'src_zones': [x['value'] for x in item['source'] if x['type'] == 'Zone'],
        'dst_zones': [x['value'] for x in item['destination'] if x['type'] == 'Zone'],
        'src_ips': get_ips_list(item['source']),
        'dst_ips': get_ips_list(item['destination']),
        'morph_categories': [],
        'urls': item['urls'],
        'referers': [],
        'user_agents': [],
        'time_restrictions': [],
        'active': True,
        'content_types': [],
        'http_methods': [],
        'custom_redirect': '',
        'src_zones_negate': False,
        'dst_zones_negate': False,
        'src_ips_negate': item['source-negate'],
        'dst_ips_negate': item['destination-negate'],
        'url_categories_negate': item['service-negate'],
        'urls_negate': item['service-negate'],
        'content_types_negate': item['content-negate'],
        'user_agents_negate': False,
        'enable_kav_check': False,
        'enable_md5_check': False,
        'rule_log': True,
        'scenario_rule_id': False,
    }

    kf_rules.append(rule)
    parent.stepChanged.emit(f'2|    Создано правило контентной фильтрации "{item["name"]}".')

def get_ips_list(array):
    """Получить структуру src_ips/dst_ips для правил МЭ и КФ из объектов access_rule."""
    result = []
    for item in array:
        if item['type'] == 'network':
            result.append(item['name'])
        elif item['type'] == 'access-role' and 'networks' in item:
            result.extend(item['networks'])
    return result

def get_users_list(src_array, dst_array):
    """Получить структуру users для правил МЭ и КФ из объектов access_rule."""
    result = []
    for item in src_array:
        if item['type'] == 'access-role' and 'users' in item:
            result.extend(item['users'])
    for item in dst_array:
        if item['type'] == 'access-role' and 'users' in item:
            result.extend(item['users'])
    return result

def create_zone(zone_name, zones):
    """Создаём зону"""
    zone = {
        'name': zone_name,
        'description': '',
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
        "services_access": [
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
                'service_id': 'NTP севис',
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

######################## Служебнуе функции ####################################################################
def make_dirs(parent, folder):
    if not os.path.isdir(folder):
        try:
            os.makedirs(folder)
        except Exception as err:
            parent.stepChanged.emit(f'4|Error! Ошибка создания каталога: {folder} - {err}')
            return False
        else:
            return True
    else:
        return True
