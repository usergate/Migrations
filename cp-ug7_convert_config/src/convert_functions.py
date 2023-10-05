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
# Класс и его функции для конвертации конфигурации CheckPoint в формат NGFW UserGate версии 7.
# Версия 2.2
#

import os, sys, json, uuid
import ipaddress
from PyQt6.QtCore import QThread, pyqtSignal
from applications import cp_app_category, cp_app_site, new_applicationgroup
from services import ServicePorts, dict_risk, character_map, character_map_file_name, character_map_for_name


content_by_uid = {}
trans_filename = str.maketrans(character_map_file_name)
trans_name = str.maketrans(character_map_for_name)


class ConvertAll(QThread):
    """Конвертируем всю конфигурацию CheckPoint"""
    stepChanged = pyqtSignal(str)
    
    def __init__(self, config_cp, objects, parent):
        super().__init__()
        self.config_cp = config_cp
        self.objects = objects
        self.sg_index = parent.sg_index
        self.sg_name = parent.sg_name
        self.cp_data_json = parent.cp_data_json
        self.error = 0
        self.app_groups = []

    def run(self):
        """Конвертируем всё в пакетном режиме"""
        convert_config_cp(self)
        convert_services(self)
        convert_other(self)
        convert_services_groups(self)
        convert_ip_lists(self)
        convert_ip_lists_groups(self)
        convert_ip_group_with_exclusion(self)
        convert_url_lists(self)
        convert_application_site_category(self)
        convert_application_site(self)
        convert_application_group(self)
        convert_access_role(self)
        convert_access_policy_files(self)
        
        self.save_app_groups()
        self.stepChanged.emit('5|Преобразование конфигурации в формат UG NGFW прошло с ошибками!' if self.error else '5|Преобразование конфигурации в формат UG NGFW прошло успешно.')

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
        self.stepChanged.emit('1|Группы приложений выгружены в файл "data_ug/Libraries/Applications/config_applications.json".')

def convert_config_cp(parent):
    """Конвертируем данные из файла "config_cp.txt" в формат UG NGFW"""
    system_dns = []
    domain_name = None
    vlans = {}
    ntp = {
        "ntp_servers": [],
        "ntp_enabled": True,
        "ntp_synced": True
    }
    gateways = []
    routes = {}
    default_vrf = {
        "name": "default",
        "description": "",
        "interfaces": [],
        "routes": [],
        "ospf": {},
        "bgp": {},
        "rip": {},
        "pimsm": {}
    }
    parent.stepChanged.emit('0|Конвертируем данные из файла config_cp в формат UG NGFW.')

    def convert_dns_servers(x):
        """Заполняем список системных DNS"""
        if x[1] == 'suffix':
            domain_name = x[2]
        else:
            system_dns.append({'dns': x[2], 'is_bad': False})
            parent.stepChanged.emit(f'2|DNS сервер {x[2]} конвертирован в "data_ug/Network/DNS/config_dns_servers.json".')

    def convert_modules(x):
        """Выгружаем UserGate->Настройки->Модули"""
        data = {
            "auth_captive": f"auth.{x[1]}",
            "logout_captive": f"logout.{x[1]}",
            "block_page_domain": f"block.{x[1]}",
            "ftpclient_captive": f"ftpclient.{x[1]}",
        }
        if not os.path.isdir('data_ug/UserGate/GeneralSettings'):
            os.makedirs('data_ug/UserGate/GeneralSettings')
        with open('data_ug/UserGate/GeneralSettings/config_settings.json', 'w') as fh:
            json.dump(data, fh, indent=4, ensure_ascii=False)
        parent.stepChanged.emit('2|Настройки домена авторизации конвертированы в "data_ug/UserGate/GeneralSettings/config_settings.json".')

    def convert_ntp_settings(x):
        """Конвертируем настройки для NTP"""
        match x:
            case ['ntp', 'active', status]:
                ntp['ntp_enabled'] = True if status == 'on' else False
            case ['ntp', 'server', 'primary'|'secondary', ip, *other]:
                if len(ntp['ntp_servers']) < 2:
                    ntp['ntp_servers'].append(ip)
                    parent.stepChanged.emit(f'2|NTP сервер {ip} конвертирован в "data_ug/UserGate/GeneralSettings/config_ntp.json".')

    def convert_settings(x):
        """Конвертируем часовой пояс"""
        data = {
            "ui_timezone": "".join(x[1:])
        }
        
        if not os.path.isdir('data_ug/UserGate/GeneralSettings'):
            os.makedirs('data_ug/UserGate/GeneralSettings')
        with open('data_ug/UserGate/GeneralSettings/config_settings_ui.json', 'w') as fh:
            json.dump(data, fh, indent=4, ensure_ascii=False)
        parent.stepChanged.emit(f'2|Чаcовой пояс {data["ui_timezone"]} конвертирован в "data_ug/UserGate/GeneralSettings/config_settings_ui.json".')


    def convert_interfaces(x):
        """
        Конвертируем интерфейсы VLAN.
        """
        iface = {
            "name": "",
            "kind": "vlan",
            "enabled": False,
            "description": "",
            "zone_id": "",
            "master": False,
            "netflow_profile": "undefined",
            "running": False,
            "ipv4": [],
            "mode": "static",
            "mtu": 1500,
            "tap": False,
            "dhcp_relay": {
                "enabled": False,
                "host_ipv4": "",
                "servers": []
            },
            "vlan_id": 0,
            "link": ""
        }

        if '.' in x[1]:
            ifname = x[1]
            if ifname not in vlans:
                iface['vlan_id'] = int(ifname.partition('.')[2])
                vlans[ifname] = iface
            match x[2]:
                case 'comments':
                    vlans[ifname]['description'] = x[3]
                case 'ipv4-address':
                    vlans[ifname]['ipv4'].append(f"{x[3]}/{x[5]}")
                case 'mtu':
                    vlans[ifname]['mtu'] = int(x[3])

    def convert_route(x):
        """Конвертируем шлюзы и статические маршруты в VRF по умолчанию"""
        match x[1:]:
            case ['default', 'nexthop', 'gateway', 'address', ip, *other]:
                weight = 1
                if 'priority' in other:
                    priority_index = other.index('priority')
                    weight = int(other[priority_index+1])
                gateway = {
                    "name": f"Default {ip}",
                    "enabled": True,
                    "description": "",
                    "ipv4": ip,
                    "vrf": "default",
                    "weight": weight,
                    "multigate": False,
                    "default": False if gateways else True,
                    "iface": "undefined",
                    "is_automatic": False,
                    "active": True
                }
                gateways.append(gateway)
                parent.stepChanged.emit(f'2|Шлюз {ip} конвертирован в "data_ug/Network/Gateways/config_gateways.json".')
            case [network, 'comment', *comment]:
                if network in routes:
                    routes[network]['description'] = ' '.join(comment)
                else:
                    routes[network] = {
                        "name": f"Route for {network}",
                        "description": ' '.join(comment),
                        "enabled": False,
                        "dest": network,
                        "gateway": "",
                        "ifname": "undefined",
                        "kind": "unicast",
                        "metric": 1
                    }
            case [network, 'nexthop', 'gateway', 'address', ip, *other]:
                if network in routes:
                    routes[network]['gateway'] = ip
                else:
                    routes[network] = {
                        "name": f"Route for {network}",
                        "description": "",
                        "enabled": False,
                        "dest": network,
                        "gateway": ip,
                        "ifname": "undefined",
                        "kind": "unicast",
                        "metric": 1
                    }
                parent.stepChanged.emit(f'2|Маршрут для {network} конвертирован в "data_ug/Network/VRF/config_routers.json".')

    for x in parent.config_cp:
        match x[0]:
            case 'dns':
                convert_dns_servers(x)
            case 'domainname':
                convert_modules(x)
            case 'ntp':
                convert_ntp_settings(x)
            case 'timezone':
                convert_settings(x)
            case 'interface':
                convert_interfaces(x)
            case 'static-route':
                convert_route(x)

    if not os.path.isdir('data_ug/UserGate/GeneralSettings'):
        os.makedirs('data_ug/UserGate/GeneralSettings')
    with open('data_ug/UserGate/GeneralSettings/config_ntp.json', 'w') as fh:
        json.dump(ntp, fh, indent=4, ensure_ascii=False)

    if not os.path.isdir('data_ug/Network/DNS'):
        os.makedirs('data_ug/Network/DNS')
    with open('data_ug/Network/DNS/config_dns_servers.json', 'w') as fh:
        json.dump(system_dns, fh, indent=4, ensure_ascii=False)

    if not os.path.isdir('data_ug/Network/DNS'):
        os.makedirs('data_ug/Network/DNS')
    with open('data_ug/Network/DNS/config_dns_servers.json', 'w') as fh:
        json.dump(system_dns, fh, indent=4, ensure_ascii=False)

    if not os.path.isdir('data_ug/Network/Gateways'):
        os.makedirs('data_ug/Network/Gateways')
    with open('data_ug/Network/Gateways/config_gateways.json', 'w') as fh:
        json.dump(gateways, fh, indent=4, ensure_ascii=False)

    if routes:
        default_vrf['routes'].extend([x for x in routes.values()])
        if not os.path.isdir('data_ug/Network/VRF'):
            os.makedirs('data_ug/Network/VRF')
        with open('data_ug/Network/VRF/config_routers.json', 'w') as fh:
            json.dump([default_vrf], fh, indent=4, ensure_ascii=False)

    if not os.path.isdir('data_ug/Network/Interfaces'):
        os.makedirs('data_ug/Network/Interfaces')
    with open("data_ug/Network/Interfaces/config_interfaces.json", "w") as fh:
        json.dump([x for x in vlans.values()], fh, indent=4, ensure_ascii=False)
    parent.stepChanged.emit(f'2|Интерфейсы VLAN выгружены в файл "data_ug/Network/Interfaces/config_interfaces.json".')


def convert_services(parent):
    """
    Выгружаем список сервисов в файл data_ug/Libraries/Services/config_services.json для последующей загрузки в NGFW.
    В "objects" UID-ы с сервисами переписываются в вид: uid: {'type'; 'service', 'name': 'ИМЯ_СЕРВИСА'}
    для загрузки сервисов в правила.
    """
    parent.stepChanged.emit('0|Конвертация списков сервисов.')

    services = {}

    for key, value in parent.objects.items():
        if value['type'] == 'service-icmp':
            parent.objects[key] = {'type': 'service', 'name': 'Any ICMP'}
            services['Any ICMP'] = {
                'name': 'Any ICMP',
                'description': 'Any ICMP packet',
                'protocols': [
                    {
                        'proto': 'icmp',
                        'port': '',
                        'source_port': ''
                    }
                ]
            }
        elif value['type'] == 'service-icmp6':
            parent.objects[key] = {'type': 'service', 'name': 'Any IPV6-ICMP'}
            services['Any IPV6-ICMP'] = {
                'name': 'Any IPV6-ICMP',
                'description': 'Any IPV6-ICMP packet',
                'protocols': [
                    {
                        'proto': 'ipv6-icmp',
                        'port': '',
                        'source_port': ''
                    }
                ]
            }
        elif value['type'] in ('service-tcp', 'service-udp'):
            _, proto = value['type'].split('-')
            parent.objects[key] = ServicePorts.get_dict_by_port(proto, value['port'], value['name'])
            service_name = ServicePorts.get_name_by_port(proto, value['port'], value['name'])

            services[service_name] = {
                'name': service_name,
                'description': value['comments'],
                'protocols': [
                    {
                        'proto': proto,
                        'port': value.get('port', ""),
                        'source_port': ""
                    }
                ]
            }

    if not os.path.isdir('data_ug/Libraries/Services'):
        os.makedirs('data_ug/Libraries/Services')
    with open("data_ug/Libraries/Services/config_services.json", "w") as fh:
        json.dump(list(services.values()), fh, indent=4, ensure_ascii=False)
    parent.stepChanged.emit(f'1|Список сервисов выгружен в файл  "data_ug/Libraries/Services/config_services.json".')

def convert_services_groups(parent):
    """
    Выгружаем группы сервисов в каталог data_ug/Libraries/ServicesGroups для последующей загрузки в NGFW.
    В "objects" UID-ы с сервис группами переписываются в вид: uid: {'type': 'servicegroup', 'name': 'ИМЯ_СЕРВИСА'}
    для загрузки сервисов в правила.
    """
    parent.stepChanged.emit('0|Конвертация групп сервисов.')

    if os.path.isdir('data_ug/Libraries/ServicesGroups'):
        for file_name in os.listdir('data_ug/Libraries/ServicesGroups'):
            os.remove(f'data_ug/Libraries/ServicesGroups/{file_name}')
    else:
        os.makedirs('data_ug/Libraries/ServicesGroups')

    with open("data_ug/Libraries/Services/config_services.json", "r") as fh:
        data = json.load(fh)
    services = {x['name']: x for x in data}

    for key, value in parent.objects.items():
        if value['type'] == 'service-group':
            members = {parent.objects[uid]['name']: parent.objects[uid] for uid in value['members']}  # словарь использован для удаления одинаковых сервисов
            content = [services[x['name']] for x in members.values() if x['type'] != 'error']
            for item in content:
                for x in item['protocols']:
                    x.pop('source_port')

            services_group = {
                "name": value['name'],
                "description": value['comments'],
                "type": 'servicegroup',
                "url": "",
                "list_type_update": "static",
                "schedule": "disabled",
                "attributes": {},
                "content": content
            }

            parent.objects[key] = {'type': 'servicegroup', 'name': value['name']}
            with open(f"data_ug/Libraries/ServicesGroups/{value['name']}.json", "w") as fh:
                json.dump(services_group, fh, indent=4, ensure_ascii=False)
            parent.stepChanged.emit(f'2|Группа сервисов {value["name"]} выгружена в файл  "data_ug/Libraries/ServicesGroups/{value["name"]}.json".')

def convert_ip_lists(parent):
    """
    Выгружаем списки IP-адресов в каталог data_ug/Libraries/IPAddresses для последующей загрузки в NGFW.
    В "objects" типы "host", "address-range", "network" переписываются в вид:
    uid: {"type": "network", "name": ["list_id", "ИМЯ_IP_ЛИСТА"]} для загрузки ip-листов в правила. Или
    uid: {"type": "error", "name": f'Объект host: "{value["name"]}" содержит IPV6 адрес.'}
    """
    parent.stepChanged.emit('0|Конвертация списков IP-адресов.')

    if os.path.isdir('data_ug/Libraries/IPAddresses'):
        for file_name in os.listdir('data_ug/Libraries/IPAddresses'):
            os.remove(f'data_ug/Libraries/IPAddresses/{file_name}')
    else:
        os.makedirs('data_ug/Libraries/IPAddresses')

    error = 0
    for key, value in parent.objects.items():
        if value['type'] in ('host', 'address-range', 'network'):
            if value.keys().isdisjoint(('ipv4-address', 'ipv4-address-first', 'subnet4')):
                error = 1
                parent.error = 1
                parent.stepChanged.emit(f"3|Warning: Объект value['type']: '{value['name']}' содержит IPV6 адрес или подсеть. Данный тип адреса не поддерживается.")
                parent.objects[key] = {'type': 'error', 'name': f'Объект value["type"]: "{value["name"]}" содержит IPV6 адрес или подсеть.'}
                continue
            parent.objects[key] = {'type': 'network', 'name': ['list_id', value['name'].translate(trans_name)]}
            match value['type']:
                case 'host':
                    content = [{'value': value['ipv4-address']}]
                case 'address-range':
                    content = [{'value': f"{value['ipv4-address-first']}-{value['ipv4-address-last']}"}]
                case 'network':
                    content = [{'value': f"{value['subnet4']}/{value['mask-length4']}"}]

            ip_list = {
                "name": value['name'].translate(trans_name),
                "description": value['comments'],
                "type": "network",
                "url": "",
                "list_type_update": "static",
                "schedule": "disabled",
                "attributes": {
                    "threat_level": 3
                },
                "content": content,
            }

            file_name = value['name'].translate(trans_filename)
            try:
                with open(f"data_ug/Libraries/IPAddresses/{file_name}.json", "w") as fh:
                    json.dump(ip_list, fh, indent=4, ensure_ascii=False)
                parent.stepChanged.emit(f'2|Список IP-адресов "{value["name"]}" выгружен в файл "data_ug/Libraries/IPAddresses/{file_name}.json".')
            except OSError as err:
                error = 1
                parent.error = 1
                parent.objects[key] = {'type': 'error', 'name': value['name'], 'description': f'Список IP-адресов "{value["name"]}" не конвертирован.'}
                parent.stepChanged.emit(f'3|Warning! Объект {value["type"]} - "{value["name"]}" не конвертирован и не будет использован в правилах.')
                parent.stepChanged.emit(f'3|Warning! : {err}.')

    parent.stepChanged.emit('1|Списки IP-адресов конвертированы с ошибками!' if error else '1|Списки IP-адресов конвертированы.')

def convert_ip_lists_groups(parent):
    """
    Выгружаем списки групп IP-адресов в каталог data_ug/Libraries/IPAddresses для последующей загрузки в NGFW.
    В "objects" тип "group" переписывается в вид:
    uid: {"type": "network", "name": ["list_id", "ИМЯ_IP_ЛИСТА"]}.
    """
    parent.stepChanged.emit('0|Конвертация списков групп IP-адресов.')

    error = 0
    for key, value in parent.objects.items():
        if value['type'] == 'group':
            parent.objects[key] = {'type': 'network', 'name': ['list_id', value['name'].translate(trans_name)]}
            content = []
            for uid in value['members']:
                try:
                    content.append({"list": parent.objects[uid]['name']})
                except KeyError:
                    error = 1
                    parent.error = 1
                    parent.stepChanged.emit(f'3|Warning! В группе IP-аресов "{value["name"]}" присутствует ссылка на несуществующий объект: {uid}.')
            ip_list = {
                "name": value['name'].translate(trans_name),
                "description": value['comments'],
                "type": "network",
                "url": "",
                "list_type_update": "static",
                "schedule": "disabled",
                "attributes": {
                    "threat_level": 3
                },
                "content": content
            }

            file_name = value['name'].translate(trans_filename)
            try:
                with open(f"data_ug/Libraries/IPAddresses/{file_name}.json", "w") as fh:
                    json.dump(ip_list, fh, indent=4, ensure_ascii=False)
                parent.stepChanged.emit(f'2|Список групп IP-адресов "{value["name"]}" выгружен в файл "data_ug/Libraries/IPAddresses/{file_name}.json".')
            except OSError as err:
                error = 1
                parent.error = 1
                parent.objects[key] = {'type': 'error', 'name': value['name'], 'description': f'Список групп IP-адресов "{value["name"]}" не конвертирован.'}
                parent.stepChanged.emit(f'3|Warning! Объект {value["type"]} - "{value["name"]}" не конвертирован и не будет использован в правилах.')
                parent.stepChanged.emit(f'3|Warning! : {err}.')

    parent.stepChanged.emit('1|Списки групп IP-адресов конвертированы с ошибками!' if error else '1|Списки групп IP-адресов конвертированы.')

def convert_ip_group_with_exclusion(parent):
    """
    В objects.json тип "group-with-exclusion" переписывается в вид:
    uid: {
        "type": "group-with-exclusion",
        "groups": [
            {
                "type": "network",
                "name": ["list_id", "ИМЯ_IP_ЛИСТА"],
                "action": "accept|drop"  - если drop, в правиле ставим признак 'Инвертировать'
            },
            ....
        ]
    }
    """
    parent.stepChanged.emit('0|Конвертация групп IP-адресов с типом group-with-exclusion.')

    error = 0
    for key, value in parent.objects.items():
        if value['type'] == 'group-with-exclusion':
            try:
                groups = []
                if 'except' in value:
                    groups.append({"type": "network", "name": ['list_id', parent.objects[value['except']['uid']]['name']], "action": "drop"})
                if 'include' in value:
                    groups.append({"type": "network", "name": ['list_id', parent.objects[value['include']['uid']]['name']], "action": "accept"})
                parent.objects[key] = {"type": "group-with-exclusion", "groups": groups}
            except KeyError as err:
                error = 1
                parent.error = 1
                parent.objects[key] = {'type': 'error', 'name': value['name'], 'description': f'Объект group-with-exclusion "{value["name"]}" не конвертирован.'}
                parent.stepChanged.emit(f'3|Warning! Group-with-exclusion "{value["name"]}" не конвертирована: {err}.')

    parent.stepChanged.emit('1|Группы IP-адресов с типом group-with-exclusion конвертированы с ошибками!' if error else '1|Группы IP-адресов с типом group-with-exclusion конвертированы.')


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

    for key, value in parent.objects.items():
        if value['type'] == 'application-site' and 'url-list' in value:
            parent.objects[key] = {'type': 'url', 'name': value['name'].translate(trans_name)}

            url_list = {
                "name": value['name'].translate(trans_name),
                "description": value['comments'],
                "type": "url",
                "url": "",
                "attributes": {
                    "threat_level": dict_risk.get(value['risk'], 5)
                },
                "content": [{'value': url} for url in value['url-list']]
            }

            file_name = value['name'].translate(trans_filename)
            with open(f"data_ug/Libraries/URLLists/{file_name}.json", "w") as fh:
                json.dump(url_list, fh, indent=4, ensure_ascii=False)
            parent.stepChanged.emit(f'2|Список URL "{value["name"]}" выгружен в файл "data_ug/Libraries/URLLists/{file_name}.json"')

def convert_application_site_category(parent):
    """
    Выгружаем новые группы приложений в каталог data_ug/Libraries/Applications для последующей загрузки в NGFW.
    В "objects" тип "application-site-category" переписывается в вид: uid:
    Категории приложений: uid:{'type': 'l7_category', 'name': ['ИМЯ_КАТЕГОРИИ_ПРИЛОЖЕНИЙ', ...]},
    Категории URL: uid:{'type': 'url_category', 'name': ['ИМЯ_КАТЕГОРИИ_URL', ...]}.
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
                parent.stepChanged.emit(f'3|Warning! Application-site-category "{value["name"]}" не конвертирована (нет аналога на UG NGFW).')
    parent.stepChanged.emit('1|Конвертации application-site-categoty прошла с ошибками. Некоторые категории не перенесены.' if error else '1|Конвертация application-site-category прошла успешно.')

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
                parent.stepChanged.emit(f'3|Warning! Приложение "{value["name"]}" не конвертировано (нет аналога на UG NGFW).')
    parent.stepChanged.emit('1|Конвертации application-site прошла с ошибками. Некоторые приложения не перенесены.' if error else '1|Конвертация application-site прошла успешно.')

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
                    "name": parent.objects[key]['name'].translate(trans_name),
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
                        parent.stepChanged.emit(f'3|Warning! {err} - {item}.')

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
            parent.stepChanged.emit(f'3|Warning! {err} - {parent.objects[key]}.')

    if url_groups:
        if make_dirs(parent, 'data_ug/Libraries/URLCategories'):
            with open("data_ug/Libraries/URLCategories/config_categories_url.json", "w") as fh:
                json.dump(url_groups, fh, indent=4, ensure_ascii=False)
            parent.stepChanged.emit('1|Группы URL категорий выгружены в файл "data_ug/Libraries/URLCategories/config_categories_url.json".')

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
                        tmp = [y.split(' = ') for y in item['tooltiptext'].split('\n')]
                        name = f'{tmp[0][1][:-4].lower()}\\{tmp[1][1]}'
                        if item['type'] == 'CpmiAdGroup':
                            users.append(['group', name])
                        else:
                            users.append(['user', name])
                elif value['users'] == "all identified":
                    users.append(['special', 'known_user'])
                elif value['users'] == "any":
                    pass
                else:
                    parent.stepChanged.emit(f'3|Warning! access-role "{value["name"]}": users = {value["users"]}. Обратитесь в техподдержку для исправления ситуации.')
                tmp_role['users'] = users
                parent.objects[key] = tmp_role
        except KeyError as err:
            parent.stepChanged.emit(f'3|Warning! {value["name"]} - {err}')
            error = 1
            parent.error = 1

    parent.stepChanged.emit('1|Конвертации access-role прошла с ошибками.' if error else '1|Конвертация access-role прошла успешно.')

def convert_other(parent):
    """
    Конвертация RulebaseAction, CpmiAnyObject и service-other в objects.json.
    В файле объектов objects.json UID с type 'RulebaseAction', 'CpmiAnyObject' и service-other заменяются на:
    uid: {"type": "RulebaseAction", "value": "Accept|Drop|Inform"} если type: 'RulebaseAction',
    uid: {"type": "CpmiAnyObject", "value": "Any"} если type: 'CpmiAnyObject',
    uid: {"type": "error", "name": "ИМЯ_СЕРВИСА", "description": "Сервис ИМЯ_СЕРВИСА не конвертирован."} если type: service-other
    """
    parent.stepChanged.emit('0|Конвертация сопутствующих объектов.')

    for key, value in parent.objects.items():
        try:
            if value['type'] == 'RulebaseAction':
                parent.objects[key] = {"type": "RulebaseAction", "value": value['name'].lower()}
            elif value['type'] == 'CpmiAnyObject':
                parent.objects[key] = {"type": "CpmiAnyObject", "value": "Any"}
            elif value['type'] == 'service-other':
                parent.objects[key] = {'type': 'error', 'name': value["name"], 'description': f'Сервис "{value["name"]}" не конвертирован.'}
                parent.stepChanged.emit(f'3|Warning! Сервисе "{value["name"]}" (тип service-other) не конвертирован и не будет использован в правилах!')
        except KeyError:
            pass
    parent.stepChanged.emit('1|Конвертации сопутствующих объектов завершена.')


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
                if 'name' not in item:
                    item['name'] = str(uuid.uuid4()).split('-')[4]
                item['name'] = item['name'].translate(trans_name)
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
        parent.stepChanged.emit(f'1|Файл {access_policy_file.replace(".json", "_convert.json")} создан.')

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
                    case 'l7_category':
                        url_categories.extend([['category_id', x] for x in value['name']])
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

            if services or service_groups or apps:
                create_firewall_rule(parent, item, fw_rules)
            elif url_categories or urls:
                create_content_rule(parent, item, kf_rules)
            else:
                create_firewall_rule(parent, item, fw_rules, err=1)

    with open(os.path.join(parent.cp_data_json, "access_rules.json"), "w") as fh:
        json.dump(access_rules, fh, indent=4, ensure_ascii=False)

    if make_dirs(parent, 'data_ug/NetworkPolicies/Firewall'):
        with open("data_ug/NetworkPolicies/Firewall/config_firewall_rules.json", "w") as fh:
            json.dump(fw_rules, fh, indent=4, ensure_ascii=False)
        parent.stepChanged.emit('1|Правила межсетевого экрана выгружены в файл "data_ug/NetworkPolicies/Firewall/config_firewall_rules.json".')

    if make_dirs(parent, 'data_ug/SecurityPolicies/ContentFiltering'):
        with open("data_ug/SecurityPolicies/ContentFiltering/config_content_rules.json", "w") as fh:
            json.dump(kf_rules, fh, indent=4, ensure_ascii=False)
        parent.stepChanged.emit('1|Правила контентной фильтрации выгружены в файл "data_ug/SecurityPolicies/ContentFiltering/config_content_rules.json".')

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
        "src_zones": [],
        "src_ips": get_ips_list(item['source']),
        "dst_zones": [],
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
        'src_zones': [],
        'dst_zones': [],
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

################################## Импорт ####################################################################

#def import_content_rules(utm):
#    """Импортировать список правил фильтрации контента"""
#    print('Импорт списка "Фильтрация контента" раздела "Политики безопасности":')
#    try:
#        with open("data_ug/security_policies/config_content_rules.json", "r") as fh:
#            data = json.load(fh)
#    except FileNotFoundError as err:
#        print(f'\t\033[31mСписок "Фильтрация контента" не импортирован!\n\tНе найден файл "data_ug/security_policies/config_content_rules.json" с сохранённой конфигурацией!\033[0;0m')
#        return

#    if not data:
#        print("\tНет правил фильтрации контента для импорта.")
#        return

#    content_rules = utm.get_content_rules()
#    zones = utm.get_zones_list()
#    list_ip = utm.get_nlists_list('network')
#    list_users = utm.get_users_list()
#    list_groups = utm.get_groups_list()
#    list_url = utm.get_nlists_list('url')
#    list_urlcategorygroup = utm.get_nlists_list('urlcategorygroup')
#    url_category = utm.get_url_category()
#    list_mime = utm.get_nlists_list('mime')

#    for item in data:
#        get_guids_users_and_groups(utm, item, list_users, list_groups)
#        set_src_zone_and_ips(item, zones, list_ip)
#        set_dst_zone_and_ips(item, zones, list_ip)
#        set_urls_and_categories(item, list_url, list_urlcategorygroup, url_category)
#        try:
#            item['content_types'] = [list_mime[x] for x in item['content_types']]
#        except KeyError as err:
#            print(f'\t\033[33mНе найден тип контента {err} для правила "{item["name"]}".\n\tЗагрузите список типов контента и повторите попытку.\033[0m')
#            item['content_types'] = []

#        if item['name'] in content_rules:
#            print(f'\tПравило "{item["name"]}" уже существует', end= ' - ')
#            err1, result1 = utm.update_content_rule(content_rules[item['name']], item)
#            if err1 == 2:
#                print("\n", f"\033[31m{result1}\033[0m")
#            else:
#                print("\033[32mUpdated!\033[0;0m")
#        else:
#            err, result = utm.add_content_rule(item)
#            if err == 2:
#                print(f"\033[31m{result}\033[0m")
#            else:
#                content_rules[item['name']] = result
#                print(f'\tПравило "{item["name"]}" добавлено.')

#def set_src_zone_and_ips(item, zones, list_ip={}, list_url={}):
#    if item['src_zones']:
#        try:
#            item['src_zones'] = [zones[x] for x in item['src_zones']]
#        except KeyError as err:
#            print(f'\t\033[33mИсходная зона {err} для правила "{item["name"]}" не найдена.\n\tЗагрузите список зон и повторите попытку.\033[0m')
#            item['src_zones'] = []
#    if item['src_ips']:
#        try:
#            for x in item['src_ips']:
#                if x[0] == 'list_id':
#                    x[1] = list_ip[x[1]]
#                elif x[0] == 'urllist_id':
#                    x[1] = list_url[x[1]]
#        except KeyError as err:
#            print(f'\t\033[33mНе найден адрес источника {err} для правила "{item["name"]}".\n\tЗагрузите списки IP-адресов и URL и повторите попытку.\033[0m')
#            item['src_ips'] = []

#def set_dst_zone_and_ips(item, zones, list_ip={}, list_url={}):
#    if item['dst_zones']:
#        try:
#            item['dst_zones'] = [zones[x] for x in item['dst_zones']]
#        except KeyError as err:
#            print(f'\t\033[33mЗона назначения {err} для правила "{item["name"]}" не найдена.\n\tЗагрузите список зон и повторите попытку.\033[0m')
#            item['dst_zones'] = []
#    if item['dst_ips']:
#        try:
#            for x in item['dst_ips']:
#                if x[0] == 'list_id':
#                    x[1] = list_ip[x[1]]
#                elif x[0] == 'urllist_id':
#                    x[1] = list_url[x[1]]
#        except KeyError as err:
#            print(f'\t\033[33mНе найден адрес назначения {err} для правила "{item["name"]}".\n\tЗагрузите списки IP-адресов и URL и повторите попытку.\033[0m')
#            item['dst_ips'] = []

#def get_guids_users_and_groups(utm, item, list_users, list_groups):
#    """
#    Получить GUID-ы групп и пользователей по их именам.
#    Заменяет имена локальных и доменных пользователей и групп на GUID-ы.
#    """
#    if 'users' in item.keys() and item['users']:
#        users = []
#        for x in item['users']:
#            if x[0] == 'user' and x[1]:
#                i = x[1].partition("\\")
#                if i[2]:
#                    err, result = utm.get_ldap_user_guid(i[0], i[2])
#                    if err != 0:
#                        print(f"\033[31m{result}\033[0m")
#                    elif not result:
#                        print(f'\t\033[31mНет LDAP-коннектора для домена "{i[0]}"!\n\tИмпортируйте и настройте LDAP-коннектор. Затем повторите импорт.\033[0m')
#                    else:
#                        x[1] = result
#                        users.append(x)
#                else:
#                    x[1] = list_users[x[1]]
#                    users.append(x)

#            elif x[0] == 'group' and x[1]:
#                i = x[1].partition("\\")
#                if i[2]:
#                    err, result = utm.get_ldap_group_guid(i[0], i[2])
#                    if err != 0:
#                        print(f"\033[31m{result}\033[0m")
#                    elif not result:
#                        print(f'\t\033[31mНет LDAP-коннектора для домена "{i[0]}"!\n\tИмпортируйте и настройте LDAP-коннектор. Затем повторите импорт групп.\033[0m')
#                    else:
#                        x[1] = result
#                        users.append(x)
#                else:
#                    x[1] = list_groups[x[1]]
#                    users.append(x)
#            elif x[0] == 'special' and x[1]:
#                users.append(x)
#        item['users'] = users
#    else:
#        item['users'] = []

#def set_apps(array_apps, l7_categories, applicationgroup, l7_apps):
#    """Определяем ID приложения по имени при импорте"""
#    for app in array_apps:
#        if app[0] == 'ro_group':
#            if app[1] == 0:
#                app[1] = "All"
#            elif app[1] == "All":
#                app[1] = 0
#            else:
#                try:
#                    app[1] = l7_categories[app[1]]
#                except KeyError as err:
#                    print(f'\t\033[33mНе найдена категория l7 №{err}.\n\tВозможно нет лицензии, и UTM не получил список категорий l7.\n\tУстановите лицензию и повторите попытку.\033[0m')
#        elif app[0] == 'group':
#            try:
#                app[1] = applicationgroup[app[1]]
#            except KeyError as err:
#                print(f'\t\033[33mНе найдена группа приложений №{err}.\n\tЗагрузите приложения и повторите попытку.\033[0m')
#        elif app[0] == 'app':
#            try:
#                app[1] = l7_apps[app[1]]
#            except KeyError as err:
#                print(f'\t\033[33mНе найдено приложение №{err}.\n\tВозможно нет лицензии, и UTM не получил список приложений l7.\n\tЗагрузите приложения или установите лицензию и повторите попытку.\033[0m')

#def set_urls_and_categories(item, list_url, list_urlcategorygroup, url_category):
#    if item['urls']:
#        try:
#            item['urls'] = [list_url[x] for x in item['urls']]
#        except KeyError as err:
#            print(f'\t\033[33mНе найден URL {err} для правила "{item["name"]}".\n\tЗагрузите списки URL и повторите попытку.\033[0m')
#            item['urls'] = []
#    if item['url_categories']:
#        try:
#            for x in item['url_categories']:
#                if x[0] == 'list_id':
#                    x[1] = list_urlcategorygroup[x[1]]
#                elif x[0] == 'category_id':
#                    x[1] = url_category[x[1]]
#        except KeyError as err:
#            print(f'\t\033[33mНе найдена группа URL-категорий {err} для правила "{item["name"]}".\n\tЗагрузите категории URL и повторите попытку.\033[0m')
#            item['url_categories'] = []

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
