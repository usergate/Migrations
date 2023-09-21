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
# Версия 1.0
#

import os, sys, json
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
    
    def __init__(self, config_cp, objects):
        super().__init__()
        self.config_cp = config_cp
        self.objects = objects
        self.error = 0

    def run(self):
        """Конвертируем всё в пакетном режиме"""
        convert_config_cp(self)
        convert_services(self)
        convert_services_groups(self)
        convert_ip_lists(self)
        convert_ip_lists_groups(self)
        convert_url_lists(self)
        convert_application_site_category(self)
        convert_application_site(self)
        convert_application_group(self)
        self.stepChanged.emit('5|Преобразование конфигурации в формат UG NGFW прошло с ошибками!' if self.error else '5|Преобразование конфигурации в формат UG NGFW прошло успешно.')


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
            content = [services[x['name']] for x in members.values()]
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
    uid: {'type': 'network', 'name': 'ИМЯ_IP_ЛИСТА'} для загрузки ip-листов в правила. Или
    uid: {'type': 'error', 'name': f'Объект host: "{value["name"]}" содержит IPV6 адрес.'}
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
            if 'ipv6-address' in value.keys():
                error = 1
                parent.error = 1
                parent.stepChanged.emit(f"3|Warning: Объект host: '{value['name']}' содержит IPV6 адрес. Данный тип адреса не поддерживается.")
                if ('ipv4-address' not in value.keys()) or not value['ipv4-address']:
                    parent.objects[key] = {'type': 'error', 'name': f'Объект host: "{value["name"]}" содержит IPV6 адрес.'}
                    continue
            parent.objects[key] = {'type': 'network', 'name': value['name'].translate(trans_name)}
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
            with open(f"data_ug/Libraries/IPAddresses/{file_name}.json", "w") as fh:
                json.dump(ip_list, fh, indent=4, ensure_ascii=False)
            parent.stepChanged.emit(f'2|Список IP-адресов "{value["name"]}" выгружен в файл "data_ug/Libraries/IPAddresses/{file_name}.json".')
    parent.stepChanged.emit('1|Списки IP-адресов конвертированы с ошибками!' if error else '1|Списки IP-адресов конвертированы.')

def convert_ip_lists_groups(parent):
    """
    Выгружаем списки групп IP-адресов в каталог data_ug/Libraries/IPAddresses для последующей загрузки в NGFW.
    В "objects" тип "group" переписывается в вид: uid: {'type': 'network', 'name': 'ИМЯ_IP_ЛИСТА'} для загрузки ip-листов в правила.
    """
    parent.stepChanged.emit('0|Конвертация списков групп IP-адресов.')

    for key, value in parent.objects.items():
        if value['type'] == 'group':
            parent.objects[key] = {'type': 'network', 'name': value['name'].translate(trans_name)}
            content = []
            for uid in value['members']:
                content.append({"list": parent.objects[uid]['name']})
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
            with open(f"data_ug/Libraries/IPAddresses/{file_name}.json", "w") as fh:
                json.dump(ip_list, fh, indent=4, ensure_ascii=False)
            parent.stepChanged.emit(f'2|Список групп IP-адресов "{value["name"]}" выгружен в файл "data_ug/Libraries/IPAddresses/{file_name}.json".')

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

    app_groups = []
    for item in new_applicationgroup:
        app_group = {
            "name": item['name'],
            "description": "Группа добавлена для совместимости с CheckPoint.",
            "type": "applicationgroup",
            "list_type_update": "static",
            "schedule": "disabled",
            "attributes": {},
            "content": [{"value": x} for x in item['app_list']]
        }
        app_groups.append(app_group)
    
    if not os.path.isdir('data_ug/Libraries/Applications'):
        os.makedirs('data_ug/Libraries/Applications')
    with open("data_ug/Libraries/Applications/config_applications.json", "w") as fh:
        json.dump(app_groups, fh, indent=4, ensure_ascii=False)
    parent.stepChanged.emit('1|Новые группы приложений выгружены в файл  "data_ug/Libraries/Applications/config_applications.json".')

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
        "error": 0  - Если объект получился пустой (нет приложений и категорий в NGFW), ставим маркер ошибки.
                      В этом случае в названии правила МЭ пишем: "ERROR! - ИМЯ_ПРАВИЛА".
        "description": ["Для приложения ... нет аналога на NGFW", ...] - если в этой группе не конвертировались приложения или категории.
                      В описание правила МЭ добавляем этот description с описанием проблем.
    }
    """
    parent.stepChanged.emit('0|Конвертация application-site-group в группы приложений и URL категорий.')

    app_groups = []
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
                        print(f'3|Warning! {err} - {item}.')
                        parent.stepChanged.emit(f'3|Warning! {err} - {item}.')

                apps_group_tmp['apps'].extend([['ro_group', x] for x in ro_group]),
                apps_group_tmp['apps'].extend([['group', x] for x in applicationgroups]),
                apps_group_tmp['urls'] = [x for x in url_list]

                if app:
                    app_groups.append(
                        {
                            "name": apps_group_tmp['name'],
                            "description": apps_group_tmp['comments'],
                            "type": "applicationgroup",
                            "list_type_update": "static",
                            "schedule": "disabled",
                            "attributes": {},
                            "content": [{"value": x} for x in app]
                        }
                    )
                    apps_group_tmp['apps'].append(['group', apps_group_tmp['name']])
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
                # В названии правила МЭ пишем: "ERROR! - ИМЯ_ПРАВИЛА".
                # В описание правила МЭ добавляем objects[key]['description'] с описанием проблемы.
                if not apps_group_tmp['apps'] and not apps_group_tmp['url_categories'] and not apps_group_tmp['urls']:
                    apps_group_tmp['error'] = 1

                parent.objects[key] = apps_group_tmp
        except (TypeError, KeyError) as err:
#            print(f'3|Warning! {err} - {parent.objects[key]}.')
            parent.stepChanged.emit(f'3|Warning! {err} - {parent.objects[key]}.')

    if app_groups:
        if make_dirs(parent, 'data_ug/Libraries/Applications'):
            if os.path.exists('data_ug/Libraries/Applications/config_applications.json'):
                with open("data_ug/Libraries/Applications/config_applications.json", "r") as fh:
                    data = json.load(fh)
                app_groups.extend(data)
            with open("data_ug/Libraries/Applications/config_applications.json", "w") as fh:
                json.dump(app_groups, fh, indent=4, ensure_ascii=False)
    
            parent.stepChanged.emit('1|Группы приложений выгружены в файл "data_ug/Libraries/Applications/config_applications.json".')

    if url_groups:
        if make_dirs(parent, 'data_ug/Libraries/URLCategories'):
            with open("data_ug/Libraries/URLCategories/config_categories_url.json", "w") as fh:
                json.dump(url_groups, fh, indent=4, ensure_ascii=False)
            parent.stepChanged.emit('1|Группы URL категорий выгружены в файл "data_ug/Libraries/URLCategories/config_categories_url.json".')

############################


def convert_access_role(objects):
    """
    В файле объектов objects.json UID с access-role переписываются в вид:
    uid = {
        'networks': [{'ip-list': 'ИМЯ_IP_ЛИСТА'}],
        'users': [
            [ 'user', 'доменое_имя_юзера' ]
        ]
    }
    """
    print('Конвертация access role...', end = ' - ')

    for key, value in objects.items():
        try:
            if value['type'] == 'access-role':
                tmp_role = {
                    'type': value['type'],
                    'name': value['name'],
                }
                if value['networks'] != 'any':
                    tmp_role['networks'] = [{'ip-list': x['name']} for x in value['networks']]
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
                tmp_role['users'] = users
                objects[key] = tmp_role
        except KeyError:
            pass
    print('\033[32mOk!\033[0m')

def convert_other(objects):
    """
    В файле объектов objects.json конвертятся UID с type 'RulebaseAction', 'CpmiAnyObject'
    """
    print('Конвертация сопутствующих объектов...', end = ' - ')

    for key, value in objects.items():
        try:
            if value['type'] == 'RulebaseAction':
                objects[key] = value['name'].lower()
            elif value['type'] == 'CpmiAnyObject':
                objects[key] = 'Any'
            elif value['type'] == 'service-other':
                objects[key] = 'Any'
        except KeyError:
            pass
    print('\033[32mOk!\033[0m')

def convert_access_rule_1(cp, objects):
    """
    Создание правил МЭ из правил Firewall-Management CheckPoint.
    """
    print('Конвертация access rule-1...', end = ' - ')
    file_name = "data_cp/Firewall-Management server_pp.json"
    if cp == 'Main_4600':
        file_name = f"data_cp/{cp} Firewall-Management server_pp.json"

    with open("data_ug/library/ip_list.json", "r") as fh:
        ip_list = {x['name']: ipaddress.ip_interface(x['content'][0]['value'].partition('-')[0]).ip for x in json.load(fh)}
    private_ips = (ipaddress.ip_network('10.0.0.0/8'), ipaddress.ip_network('172.16.0.0/12'), ipaddress.ip_network('192.168.0.0/16'))

    with open(f"{file_name}", "r") as fh:
        data = json.load(fh)

    fw_rules = []
    for item in data:
        if item['type'] == 'access-rule':
            if item['name'] == 'Cleanup rule':
                continue
            item['content'] = [objects[uid] for uid in item['content'] if objects[uid] != 'Any']
            item['source'] = [objects[uid] for uid in item['source'] if objects[uid] != 'Any']
            item['destination'] = [objects[uid] for uid in item['destination'] if objects[uid] != 'Any']
            rule = {
                'name': item['name'],
                'description': item['comments'],
                'action': objects[item['action']],
                'position': item['rule-number'],
                'scenario_rule_id': False,
                'src_zones': [],
                'src_ips': [],
                'dst_zones': [],
                'dst_ips': [],
                'services': list({objects[uid]['services'] for uid in item['service'] if objects[uid] != 'Any'}),
                'apps': item['content'],
                'users': [],
                'enabled': False,
                'limit': True,
                'lmit_value': '3/h',
                'lmit_burst': 5,
                'log': True if True in item['track'].values() else False,
                'log_session_start': True if True in item['track'].values() else False,
                'src_zones_negate': False,
                'dst_zones_negate': False,
                'src_ips_negate': item['source-negate'],
                'dst_ips_negate': item['destination-negate'],
                'services_negate': item['service-negate'],
                'apps_negate': item['content-negate'],
                'fragmented': 'ignore',
                'time_restrictions': [],
                'send_host_icmp': '',
            }
            tmp_ips_set = set()
            tmp_zones_set = set()
            for src in item['source']:
                if 'networks' in src:
                    tmp_ips_set.update(set(x['ip-list'] for x in src['networks']))
                    rule['users'].extend(src['users'])
                elif 'ip-list' in src:
                    tmp_ips_set.add(src['ip-list'])
                else:
                    tmp_zones_set.add('Management')
            rule['src_ips'] = [['list_id', x] for x in tmp_ips_set]
            rule['src_zones'] = [x for x in tmp_zones_set]
            tmp_ips_set.clear()
            tmp_zones_set.clear()
            for dst in item['destination']:
                if 'ip-list' in dst:
                    tmp_ips_set.add(dst['ip-list'])
                else:
                    tmp_zones_set.add('Management')
            rule['dst_ips'] = [['list_id', x] for x in tmp_ips_set]
            rule['dst_zones'] = [x for x in tmp_zones_set]

            if rule['src_ips']:
                ip = ip_list[rule['src_ips'][0][1]]
                if any(ip in network for network in private_ips):
                    rule['src_zones'].append('Trusted')
                else:
                    rule['src_zones'].append('Untrusted')
            if rule['dst_ips']:
                ip = ip_list[rule['dst_ips'][0][1]]
                if any(ip in network for network in private_ips):
                    rule['dst_zones'].append('Trusted')
                else:
                    rule['dst_zones'].append('Untrusted')

            fw_rules.append(rule)

    if not os.path.isdir('data_ug/network_policies'):
        os.makedirs('data_ug/network_policies')
    with open("data_ug/network_policies/config_firewall_rules-1.json", "w") as fh:
        json.dump(fw_rules, fh, indent=4, ensure_ascii=False)
    print('\033[32mOk!\033[0m')
    return len(fw_rules)

def convert_application_rule(cp, objects):
    """
    Разделение Application_and_URL-Management на правила МЭ и КФ.
    """
    print('Конвертация правил Application_and_URL-Management...', end = ' - ')
    file_name = "data_cp/Application_and_URL-Management server_pp.json"
    if cp == 'Main_4600':
        file_name = f"data_cp/{cp} Application_and_URL-Management server_pp.json"

    with open(f"{file_name}", "r") as fh:
        data = json.load(fh)

    for item in data:
        if item['type'] == 'access-rule':
            # удалить потом -------------------
            item.pop('custom-fields', None)
            item.pop('action-settings', None)
            item.pop('install-on', None)
            item.pop('time', None)
            item.pop('domain', None)
            item.pop('vpn', None)
            item.pop('uid', None)
            item.pop('meta-info', None)
            item.pop('user-check', None)
            #-----------------------------------
            item['services'] = []
            item['apps'] = []
            item['url_categories'] = []
            item['urls'] = []
            item['service'] = [objects[uid] for uid in item['service'] if objects[uid] != 'Any']
            apps_set = set()
            l7category_set = set()
            for service in item['service']:
                if 'services' in service:
                    item['services'].append(service['services'])
                elif service['type'] == 'apps_group':
                    item['apps'].extend(service['apps'])
                    item['url_categories'].extend(service['url_categories'])
                    item['urls'].extend(service['urls'])
                elif service['type'] == 'l7_category':
                    l7category_set.add(service['name'])
                elif service['type'] == 'l7apps':
                    tmp_set = set({x for x in service['name']})
                    apps_set.update(tmp_set)
                elif service['type'] == 'url-list':
                    item['urls'].append(service['name'])
                elif service['type'] == 'url_category':
                    item['url_categories'].append(['category_id', service['name']])
            
            item['services'] = list({x for x in item['services']})
            item['apps'].extend([['ro_group', x] for x in l7category_set])
            item['apps'].extend([['app', x] for x in apps_set])
            
    with open("data_cp/Application_rules.json", "w") as fh:
        json.dump(data, fh, indent=4, ensure_ascii=False)
    print('\033[32mOk!\033[0m')

def convert_access_rule_2(rule_count, objects):
    """
    Создание правил МЭ из правил Application_and_URL-Management CheckPoint.
    """
    print('Конвертация access rule-2...', end = ' - ')
    file_name = "data_cp/Application_rules.json"

    with open("data_ug/library/ip_list.json", "r") as fh:
        ip_list = {x['name']: ipaddress.ip_interface(x['content'][0]['value'].partition('-')[0]).ip for x in json.load(fh)}
    private_ips = (ipaddress.ip_network('10.0.0.0/8'), ipaddress.ip_network('172.16.0.0/12'), ipaddress.ip_network('192.168.0.0/16'))

    with open(f"{file_name}", "r") as fh:
        data = json.load(fh)

    fw_rules = []
    for item in data:
        if (item['type'] == 'access-rule') and (item['services'] or item['apps']):
            if item['name'] == 'Cleanup rule':
                continue
            rule_count += 1
            item['content'] = [objects[uid] for uid in item['content'] if objects[uid] != 'Any']
            item['source'] = [objects[uid] for uid in item['source'] if objects[uid] != 'Any']
            item['destination'] = [objects[uid] for uid in item['destination'] if objects[uid] != 'Any']
            rule = {
                'name': item['name'],
                'description': item['comments'],
                'action': objects[item['action']],
                'position': rule_count,
                'scenario_rule_id': False,
                'src_zones': [],
                'src_ips': [],
                'dst_zones': [],
                'dst_ips': [],
                'services': item['services'],
                'apps': item['apps'],
                'users': [],
                'enabled': False,
                'limit': True,
                'lmit_value': '3/h',
                'lmit_burst': 5,
                'log': True if True in item['track'].values() else False,
                'log_session_start': True if True in item['track'].values() else False,
                'src_zones_negate': False,
                'dst_zones_negate': False,
                'src_ips_negate': item['source-negate'],
                'dst_ips_negate': item['destination-negate'],
                'services_negate': item['service-negate'],
                'apps_negate': item['content-negate'],
                'fragmented': 'ignore',
                'time_restrictions': [],
                'send_host_icmp': '',
            }
            tmp_ips_set = set()
            tmp_zones_set = set()
            for src in item['source']:
                if 'networks' in src:
                    tmp_ips_set.update(set(x['ip-list'] for x in src['networks']))
                    rule['users'].extend(src['users'])
                elif 'ip-list' in src:
                    tmp_ips_set.add(src['ip-list'])
                else:
                    tmp_zones_set.add('Management')
            rule['src_ips'] = [['list_id', x] for x in tmp_ips_set]
            rule['src_zones'] = [x for x in tmp_zones_set]
            tmp_ips_set.clear()
            tmp_zones_set.clear()
            for dst in item['destination']:
                if 'ip-list' in dst:
                    tmp_ips_set.add(dst['ip-list'])
                else:
                    tmp_zones_set.add('Management')
            rule['dst_ips'] = [['list_id', x] for x in tmp_ips_set]
            rule['dst_zones'] = [x for x in tmp_zones_set]

            if rule['src_ips']:
                ip = ip_list[rule['src_ips'][0][1]]
                if any(ip in network for network in private_ips):
                    rule['src_zones'].append('Trusted')
                else:
                    rule['src_zones'].append('Untrusted')
            if rule['dst_ips']:
                ip = ip_list[rule['dst_ips'][0][1]]
                if any(ip in network for network in private_ips):
                    rule['dst_zones'].append('Trusted')
                else:
                    rule['dst_zones'].append('Untrusted')

            fw_rules.append(rule)

    if not os.path.isdir('data_ug/network_policies'):
        os.makedirs('data_ug/network_policies')
    with open("data_ug/network_policies/config_firewall_rules-2.json", "w") as fh:
        json.dump(fw_rules, fh, indent=4, ensure_ascii=False)
    print('\033[32mOk!\033[0m')

def convert_content_rule(objects):
    """
    Создание правил КФ из правил Application_and_URL-Management CheckPoint.
    """
    print('Конвертация правил контентной фильтации...', end = ' - ')
    file_name = "data_cp/Application_rules.json"

    with open("data_ug/library/ip_list.json", "r") as fh:
        ip_list = {x['name']: ipaddress.ip_interface(x['content'][0]['value'].partition('-')[0]).ip for x in json.load(fh)}
    private_ips = (ipaddress.ip_network('10.0.0.0/8'), ipaddress.ip_network('172.16.0.0/12'), ipaddress.ip_network('192.168.0.0/16'))

    with open(f"{file_name}", "r") as fh:
        data = json.load(fh)

    kf_rules = []
    rule_number = 0
    for item in data:
        if (item['type'] == 'access-rule') and (item['url_categories'] or item['urls']):
            if item['name'] == 'Cleanup rule':
                continue
            rule_number += 1
            item['content'] = [objects[uid] for uid in item['content'] if objects[uid] != 'Any']
            item['source'] = [objects[uid] for uid in item['source'] if objects[uid] != 'Any']
            item['destination'] = [objects[uid] for uid in item['destination'] if objects[uid] != 'Any']
            rule = {
                'position': rule_number,
                'action': objects[item['action']],
                'name': item['name'],
                'public_name': '',
                'description': item['comments'],
                'enabled': False,
                'enable_custom_redirect': False,
                'blockpage_template_id': -1,
                'users': [],
                'url_categories': item['url_categories'],
                'src_zones': [],
                'dst_zones': [],
                'src_ips': [],
                'dst_ips': [],
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
                'rule_log': True if True in item['track'].values() else False,
                'scenario_rule_id': False,
            }
            tmp_ips_set = set()
            tmp_zones_set = set()
            for src in item['source']:
                if 'networks' in src:
                    tmp_ips_set.update(set(x['ip-list'] for x in src['networks']))
                    rule['users'].extend(src['users'])
                elif 'ip-list' in src:
                    tmp_ips_set.add(src['ip-list'])
                else:
                    tmp_zones_set.add('Management')
            rule['src_ips'] = [['list_id', x] for x in tmp_ips_set]
            rule['src_zones'] = [x for x in tmp_zones_set]
            tmp_ips_set.clear()
            tmp_zones_set.clear()
            for dst in item['destination']:
                if 'ip-list' in dst:
                    tmp_ips_set.add(dst['ip-list'])
                else:
                    tmp_zones_set.add('Management')
            rule['dst_ips'] = [['list_id', x] for x in tmp_ips_set]
            rule['dst_zones'] = [x for x in tmp_zones_set]

            if rule['src_ips']:
                ip = ip_list[rule['src_ips'][0][1]]
                if any(ip in network for network in private_ips):
                    rule['src_zones'].append('Trusted')
                else:
                    rule['src_zones'].append('Untrusted')
            if rule['dst_ips']:
                ip = ip_list[rule['dst_ips'][0][1]]
                if any(ip in network for network in private_ips):
                    rule['dst_zones'].append('Trusted')
                else:
                    rule['dst_zones'].append('Untrusted')

            kf_rules.append(rule)

    if not os.path.isdir('data_ug/security_policies'):
        os.makedirs('data_ug/security_policies')
    with open("data_ug/security_policies/config_content_rules.json", "w") as fh:
        json.dump(kf_rules, fh, indent=4, ensure_ascii=False)
    print('\033[32mOk!\033[0m')

################################## Импорт ####################################################################
#def import_application_groups(utm):
#    """Импортировать список "Приложения" на UTM"""
#    print('Импорт списка "Приложения" раздела "Библиотеки":')
#    try:
#        with open("data_ug/library/application_groups.json", "r") as fh:
#            data = json.load(fh)
#    except FileNotFoundError as err:
#        print('\t\033[31mСписок "Приложения" не импортирован!\n\tНе найден файл "data_ug/library/application_groups.json" с сохранённой конфигурацией!\033[0;0m')
#        return

#    if not data:
#        print("\tНет групп приложений для импорта.")
#        return

#    l7apps = utm.get_l7_apps()

#    for item in data:
#        content = item.pop('content')
#        err, result = utm.add_nlist(item)
#        if err == 1:
#            print(result, "\033[32mOk!\033[0;0m")
#        elif err == 2:
#            print(f"\033[31m{result}\033[0m")
#        else:
#            print(f'\tГруппа приложений "{item["name"]}" добавлена.')
#            if content:
#                try:
#                    content = [{'value': l7apps[x['value']]} for x in content]
#                except KeyError as err:
#                    print(f'\t\t\033[31mНе найдены стандартные приложения.\033[0m')
#                    print(f'\t\t\033[31mВведите лицензионный ключ и дождитесь обновления списков UserGate.\033[0m')
#                    return
#                try:
#                    err2, result2 = utm.add_nlist_items(result, content)
#                    if err2 != 0:
#                        print(f'\033[31m{result2}\033[0m')
#                    else:
#                        print(f'\t\tСодержимое группы приложений: "{item["name"]}" добавлено.')
#                except Exception as err:
#                    print(f'\t\t\033[31mСодержимое группы приложений "{item["name"]}" не добавлено.\n\t\t{err}\033[0m')


#def import_firewall_rules(number, file_rules, utm):
#    """Импортировать список правил межсетевого экрана"""
#    print(f'Импорт списка №{number} "Межсетевой экран" раздела "Политики сети":')
#    try:
#        with open(f"data_ug/network_policies/{file_rules}", "r") as fh:
#            data = json.load(fh)
#    except FileNotFoundError as err:
#        print(f'\t\033[31mСписок №{number} "Межсетевой экран" не импортирован!\n\tНе найден файл "data_ug/network_policies/{file_rules}" с сохранённой конфигурацией!\033[0;0m')
#        return

#    if not data:
#        print("\tНет правил №{number} межсетевого экрана для импорта.")
#        return

#    firewall_rules = utm.get_firewall_rules()
#    services_list = utm.get_services_list()
#    l7_categories = utm.get_l7_categories()
#    applicationgroup = utm.get_nlists_list('applicationgroup')
#    l7_apps = utm.get_l7_apps()
#    zones = utm.get_zones_list()
#    list_ip = utm.get_nlists_list('network')
#    list_users = utm.get_users_list()
#    list_groups = utm.get_groups_list()

#    for item in data:
#        get_guids_users_and_groups(utm, item, list_users, list_groups)
#        set_src_zone_and_ips(item, zones, list_ip)
#        set_dst_zone_and_ips(item, zones, list_ip)
#        try:
#            item['services'] = [services_list[x] for x in item['services']]
#        except KeyError as err:
#            print(f'\t\033[33mНе найден сервис {err} для правила "{item["name"]}".\n\tЗагрузите сервисы и повторите попытку.\033[0m')
#            item['services'] = []
#        try:
#            set_apps(item['apps'], l7_categories, applicationgroup, l7_apps)
#        except KeyError as err:
#            print(f'\t\033[33mНе найдено приложение {err} для правила "{item["name"]}".\n\tЗагрузите сервисы и повторите попытку.\033[0m')
#            item['apps'] = []

#        if item['name'] in firewall_rules:
#            print(f'\tПравило МЭ "{item["name"]}" уже существует', end= ' - ')
#            err1, result1 = utm.update_firewall_rule(firewall_rules[item['name']], item)
#            if err1 != 0:
#                print("\n", f"\033[31m{result1}\033[0m")
#            else:
#                print("\033[32mUpdated!\033[0;0m")
#        else:
#            err, result = utm.add_firewall_rule(item)
#            if err != 0:
#                print(f"\033[31m{result}\033[0m")
#            else:
#                firewall_rules[item["name"]] = result
#                print(f'\tПравило МЭ "{item["name"]}" добавлено.')

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
