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
# Версия 4.6    03.09.2025
#

import os, sys, json, uuid, copy
from PyQt6.QtCore import QThread, pyqtSignal
from common_classes import MyConv
from services import trans_url, GEOIP_CODE
from checkpoint_embedded_objects import embedded_objects
from applications import (app_compliance, appgroup_compliance, l7_category_compliance, url_category_compliance,
                          cp_app_category, url_categories, new_applicationgroup)


class ConvertCheckPointConfig(QThread, MyConv):
    """Конвертируем всю конфигурацию CheckPoint в формат UserGate NGFW."""
    stepChanged = pyqtSignal(str)
    
    def __init__(self, current_vendor_path, current_ug_path, sg_name):
        super().__init__()
        self.current_vendor_path = current_vendor_path
        self.current_ug_path = current_ug_path
        self.sg_name = sg_name
        self.config_path = None
        self.objects = None
        self.access_layers = []
        self.log_tracker = {}
        self.vendor = 'CheckPoint'
        self.error = 0

        self.services = {}
        self.service_groups = {}
        self.app_groups = []
        self.zones = {}
        self.fw_rules = []
        self.kf_rules = []

    def run(self):
        """Конвертируем всё в пакетном режиме"""
        title = f'Конвертация конфигурации CheckPoint (Secure Gateway: {self.sg_name}) в формат UG NGFW'
        self.stepChanged.emit(f'GREEN|{title:>110}')
        self.stepChanged.emit(f'ORANGE|{"="*110}')
        self.convert_config_cp()

        self.config_path = os.path.join(self.current_vendor_path, 'data_json')
        err, index_file = self.read_json_file(os.path.join(self.config_path, 'index.json'))
        if err:
            return
        for policy_package in index_file['policyPackages']:
            if policy_package['packageName'] == self.sg_name:
                objects_file = policy_package['objects']['htmlObjectsFileName'].replace('html', 'json')
                for layer in policy_package['accessLayers']:
                    self.access_layers.append(layer['htmlFileName'].replace('html', 'json'))
                break
        err, data = self.read_json_file(os.path.join(self.config_path, objects_file))
        if err:
            return

        self.objects = {x['uid']: x for x in data}
        json_file = os.path.join(self.config_path, 'objects.json')
        with open(json_file, 'w') as fh:
            json.dump(self.objects, fh, indent=4, ensure_ascii=False)

        self.convert_log_tracker()
        self.convert_other()
        self.convert_timesets()
        self.convert_services()
        self.convert_services_groups()
        self.convert_ip_lists()
        self.convert_simple_cluster()
        self.convert_cluster_members()
        self.convert_checkpoint_host()
        self.convert_ip_lists_groups()
        self.convert_ip_group_with_exclusion()
        self.convert_url_lists()
        self.convert_application_site_category()
        self.convert_application_site()
        self.convert_application_group()
        self.convert_access_role()
        self.convert_access_policy_files()
        self.create_firewall_rule()
        self.create_content_rule()
        
        self.save_app_groups()
        self.save_zones()

        if self.error:
            self.stepChanged.emit('iORANGE|Преобразование конфигурации CheckPoint в формат UG NGFW прошло с ошибками!\n')
        else:
            self.stepChanged.emit('iGREEN|Преобразование конфигурации CheckPoint в формат UG NGFW прошло успешно.\n')

    def create_app_group(self, group_name, app_list, comment=''):
        app_group = {
            'name': group_name,
            'description': f"Портировано с CheckPoint.\n{comment}",
            'type': 'applicationgroup',
            'url': '',
            'list_type_update': 'static',
            'schedule': 'disabled',
            'attributes': {},
            'content': [{'type': 'app', 'name': x} for x in app_list]
        }
        self.app_groups.append(app_group)
    
    def save_app_groups(self):
        """Добавляем группы приложений из applications/new_applicationgroup и записываем все группы приложений в файл."""
        for item in new_applicationgroup:
            self.create_app_group(item['name'], item['app_list'], comment="Группа добавлена для совместимости с CheckPoint.")

        section_path = os.path.join(self.current_ug_path, 'Libraries')
        current_path = os.path.join(section_path, 'ApplicationGroups')
        err, msg = self.create_dir(current_path)
        if err:
            self.stepChanged.emit(f'RED|    {msg}')
            self.error = 1
            return

        json_file = os.path.join(current_path, 'config_application_groups.json')
        with open(json_file, 'w') as fh:
            json.dump(self.app_groups, fh, indent=4, ensure_ascii=False)
        self.stepChanged.emit(f'GREEN|    Группы приложений выгружены в файл "{json_file}".')

    def save_zones(self):
        """Сохраняем зоны, если они есть."""
        if self.zones:
            section_path = os.path.join(self.current_ug_path, 'Network')
            current_path = os.path.join(section_path, 'Zones')
            err, msg = self.create_dir(current_path)
            if err:
                self.stepChanged.emit(f'RED|    {msg}')
                self.error = 1
                return

            json_file = os.path.join(current_path, 'config_zones.json')
            with open(json_file, 'w') as fh:
                json.dump([x for x in self.zones.values()], fh, indent=4, ensure_ascii=False)
            self.stepChanged.emit(f'GREEN|    Зоны выгружены в файл "{json_file}".')


    def convert_config_cp(self):
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
            section_path = os.path.join(self.current_ug_path, 'UserGate')
            current_path = os.path.join(section_path, 'GeneralSettings')
            err, msg = self.create_dir(current_path, delete='no')
            if err:
                self.stepChanged.emit(f'RED|    {msg}')
                self.error = 1
            else:
                data = {
                    "ui_timezone": "".join(x[1:])
                }
                if data['ui_timezone'].startswith('Etc/'):
                    return
                json_file = os.path.join(current_path, 'config_settings_ui.json')
                with open(json_file, 'w') as fh:
                    json.dump(data, fh, indent=4, ensure_ascii=False)
                self.stepChanged.emit(f'BLACK|    Чаcовой пояс {data["ui_timezone"]} выгружен в файл "{json_file}".')

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
        with open(os.path.join(self.current_vendor_path, 'config_cp.txt'), 'r') as fh:
            for line in fh:
                x = line.strip('\n').split()
                if x and x[0] in {'set', 'add'}:
                    config_cp.append(x[1:])

        self.stepChanged.emit('BLUE|Конвертация раздела "UserGate/Настройки".')
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
            section_path = os.path.join(self.current_ug_path, 'UserGate')
            current_path = os.path.join(section_path, 'GeneralSettings')
            err, msg = self.create_dir(current_path, delete='no')
            if err:
                self.stepChanged.emit(f'RED|    {msg}')
                self.error = 1
            else:
                json_file = os.path.join(current_path, 'config_ntp.json')
                with open(json_file, 'w') as fh:
                    json.dump(ntp, fh, indent=4, ensure_ascii=False)
                self.stepChanged.emit(f'BLACK|    Настройка NTP выгружена в файл "{json_file}".')
        else:
            self.stepChanged.emit(f'GRAY|    Нет серверов NTP для экспорта.')

        #Выгружаем UserGate->Настройки->Модули
        if domain_name:
            modules = {
                "auth_captive": f"auth.{domain_name}",
                "logout_captive": f"logout.{domain_name}",
                "block_page_domain": f"block.{domain_name}",
                "ftpclient_captive": f"ftpclient.{domain_name}",
            }
            section_path = os.path.join(self.current_ug_path, 'UserGate')
            current_path = os.path.join(section_path, 'GeneralSettings')
            err, msg = self.create_dir(current_path, delete='no')
            if err:
                self.stepChanged.emit(f'RED|    {msg}')
                self.error = 1
            else:
                json_file = os.path.join(current_path, 'config_settings.json')
                with open(json_file, 'w') as fh:
                    json.dump(modules, fh, indent=4, ensure_ascii=False)
                self.stepChanged.emit(f'BLACK|    Настройки домена авторизации выгружены в файл "{json_file}".')
        else:
            self.stepChanged.emit(f'GRAY|    Нет домена авторизации для экспорта.')

        self.stepChanged.emit('BLUE|Конвертация раздела "Сеть".')
        #Выгружаем сервера DNS
        if system_dns:
            section_path = os.path.join(self.current_ug_path, 'Network')
            current_path = os.path.join(section_path, 'DNS')
            err, msg = self.create_dir(current_path, delete='no')
            if err:
                self.stepChanged.emit(f'RED|    {msg}')
                self.error = 1
            else:
                json_file = os.path.join(current_path, 'config_dns_servers.json')
                with open(json_file, 'w') as fh:
                    json.dump(system_dns, fh, indent=4, ensure_ascii=False)
                self.stepChanged.emit(f'BLACK|    Настройки серверов DNS выгружены в файл "{json_file}".')
        else:
            self.stepChanged.emit(f'GRAY|    Нет серверов DNS для экспорта.')

        #Выгружаем интерфейсы VLAN
        if vlans:
            section_path = os.path.join(self.current_ug_path, 'Network')
            current_path = os.path.join(section_path, 'Interfaces')
            err, msg = self.create_dir(current_path)
            if err:
                self.stepChanged.emit(f'RED|    {msg}')
                self.error = 1
            else:
                json_file = os.path.join(current_path, 'config_interfaces.json')
                with open(json_file, 'w') as fh:
                    json.dump([x for x in vlans.values()], fh, indent=4, ensure_ascii=False)
                self.stepChanged.emit(f'BLACK|    Интерфейсы VLAN выгружены в файл "{json_file}".')
        else:
            self.stepChanged.emit(f'GRAY|    Нет Интерфейсов VLAN для экспорта.')

        #Выгружаем шлюзы
        if gateways:
            section_path = os.path.join(self.current_ug_path, 'Network')
            current_path = os.path.join(section_path, 'Gateways')
            err, msg = self.create_dir(current_path)
            if err:
                self.stepChanged.emit(f'RED|    {msg}')
                self.error = 1
            else:
                json_file = os.path.join(current_path, 'config_gateways.json')
                with open(json_file, 'w') as fh:
                    json.dump(gateways, fh, indent=4, ensure_ascii=False)
                self.stepChanged.emit(f'BLACK|    Настройки шлюзов выгружены в файл "{json_file}".')
        else:
            self.stepChanged.emit(f'GRAY|    Нет шлюзов для экспорта.')

        #Выгружаем статические маршруты в VRF по умолчанию
        if routes:
            default_vrf['routes'].extend([x for x in routes.values()])

            section_path = os.path.join(self.current_ug_path, 'Network')
            current_path = os.path.join(section_path, 'VRF')
            err, msg = self.create_dir(current_path)
            if err:
                self.stepChanged.emit(f'RED|    {msg}')
                self.error = 1
            else:
                json_file = os.path.join(current_path, 'config_vrf.json')
                with open(json_file, 'w') as fh:
                    json.dump([default_vrf], fh, indent=4, ensure_ascii=False)
                self.stepChanged.emit(f'BLACK|    Статические маршруты выгружены в файл "{json_file}".')
        else:
            self.stepChanged.emit(f'GRAY|    Нет статических маршрутов для экспорта.')

    #-------------------------------------------------------------------------------------------------------------------
    def convert_log_tracker(self):
        """Получаем статус логирования правил и устанавливаем атрибут self.log_tracker"""
        for key, value in self.objects.items():
            if value['type'] == 'Track':
                if value['name'] == 'Log':
                    self.log_tracker[key] = True
                else:
                    self.log_tracker[key] = False


    def make_embedded_service(self, service):
        """
        Создаём сервис и заносим его в self.services.
        Для convert_services_groups() и convert_other().
        """
        if service['name'] not in self.services:
            self.services[service['name']] = {
                'name': service['name'],
                'description': f'Портировано с CheckPoint.\n{service.get("description", "")}',
                'protocols': [
                    {
                        'proto': service['proto'],
                        'port': service['port'],
                        'app_proto': self.app_proto.get(service['proto'], ''),
                        'source_port': '',
                        'alg': ''
                    }
                ]
            }


    def convert_other(self):
        """
        Конвертация RulebaseAction, CpmiAnyObject, CpmiGatewayPlain, CpmiHostCkp, CpmiBusinessMailApplication и service-other в objects.json.
        В файле объектов objects.json UID с type 'RulebaseAction', 'CpmiAnyObject', CpmiGatewayPlain, 'updatable-object',
        CpmiHostCkp, CpmiBusinessMailApplication, CpmiConnectraWebApplication и service-other заменяются на:
        uid: {"type": "RulebaseAction", "value": "Accept|Drop|Inform"} если type: 'RulebaseAction',
        uid: {"type": "CpmiAnyObject", "value": "Any"} если type: 'CpmiAnyObject',
        uid: {"type": "geoip", "value": GEOIP_CODE}
        Для type: service-other:
            uid: {"type": "error", "name": "ИМЯ_СЕРВИСА", "description": "Сервис ИМЯ_СЕРВИСА не конвертирован."} если не найден сервис.
        """
        self.stepChanged.emit('BLUE|Конвертация сопутствующих объектов.')

        error = 0
        for key, value in self.objects.items():
            try:
                match value['type']:
                    case 'RulebaseAction':
                        self.objects[key] = {'type': 'RulebaseAction', 'value': 'accept' if value['name'] == 'Inform' else value['name'].lower()}
                    case 'CpmiAnyObject':
                        self.objects[key] = {'type': 'CpmiAnyObject', 'value': 'Any'}
                    case 'service-other':
                        if key in embedded_objects:
                            service = embedded_objects[key]
                            if service['type'] == 'service':
                                self.make_embedded_service(service)
                                self.objects[key] = {'type': 'service', 'name': service['name']}
                                self.stepChanged.emit(f'BLACK|    Конвертирован сервис "{value["name"]}" (тип service-other).')
                            elif service['type'] == 'servicegroup':
                                content = []
                                self.service_groups[service['name']] = {
                                    'name': service['name'],
                                    'description': f'Портировано с CheckPoint.\n{service.get("description", "")}',
                                    'type': 'servicegroup',
                                    'url': '',
                                    'list_type_update': 'static',
                                    'schedule': 'disabled',
                                    'attributes': {},
                                    'content': content
                                }
                                for name, uid in service['content'].items():
                                    try:
                                        content.append(copy.deepcopy(self.services[name]))
                                    except KeyError:
                                        self.make_embedded_service(embedded_objects[uid])
                                        content.append(copy.deepcopy(self.services[name]))

                                for item in content:
                                    for x in item['protocols']:
                                        x.pop('alg', None)
                                        x.pop('source_port', None)
                                        x.pop('app_proto', None)

                                self.objects[key] = {'type': 'servicegroup', 'name': service['name']}
                                self.stepChanged.emit(f'BLACK|    Конвертирована группа сервисов "{value["name"]}" (тип service-other).')
                        else:
                            error = 1
                            self.objects[key] = {'type': 'error', 'name': value['name'], 'description': f'Сервис "{value["name"]}" не конвертирован.'}
                            self.stepChanged.emit(f'bRED|    Warning! Сервис "{value["name"]}" (тип service-other) не конвертирован и не будет использован в правилах.')
                    case 'CpmiBusinessMailApplication':
                        error = 1
                        self.objects[key] = {'type': 'error', 'name': value['name'], 'description': f'Приложение CpmiBusinessMailApplication "{value["name"]}" не конвертировано.'}
                        self.stepChanged.emit(f'bRED|    Warning! Приложение "{value["name"]}" (тип CpmiBusinessMailApplication) не конвертировано и не будет использован в правилах.')
                    case 'CpmiNativeApplication':
                        error = 1
                        self.objects[key] = {'type': 'error', 'name': value['name'], 'description': f'Приложение CpmiNativeApplication "{value["name"]}" не конвертировано.'}
                        self.stepChanged.emit(f'bRED|    Warning! Приложение "{value["name"]}" (тип CpmiNativeApplication) не конвертировано и не будет использован в правилах.')
                    case 'CpmiConnectraWebApplication':
                        error = 1
                        self.objects[key] = {'type': 'error', 'name': value['name'], 'description': f'Приложение CpmiConnectraWebApplication "{value["name"]}" не конвертировано.'}
                        self.stepChanged.emit(f'bRED|    Warning! Приложение "{value["name"]}" (тип CpmiConnectraWebApplication) не конвертировано и не будет использован в правилах.')
                    case 'CpmiGatewayPlain':
                        error = 1
                        self.objects[key] = {'type': 'error', 'name': value['name'], 'description': f'Объект CpmiGatewayPlain "{value["name"]}" не конвертирован'}
                        self.stepChanged.emit(f'bRED|    Warning! Объект "{value["name"]}" (тип CpmiGatewayPlain) не конвертирован и не будет использован в правилах.')
                    case 'CpmiHostCkp':
                        error = 1
                        self.objects[key] = {'type': 'error', 'name': value['name'], 'description': f'Объект CpmiHostCkp "{value["name"]}" не конвертирован'}
                        self.stepChanged.emit(f'bRED|    Warning! Объект "{value["name"]}" (тип CpmiHostCkp) не конвертирован и не будет использован в правилах.')
                    case 'updatable-object':
                        if value['name'] in GEOIP_CODE:
                            self.objects[key] = {'type': 'geoip', 'value': GEOIP_CODE[value['name']]}
                        else:
                            error = 1
                            self.objects[key] = {'type': 'error', 'name': value['name'], 'description': f'GeoIP "{value["name"]}" не конвертировано'}
                            self.stepChanged.emit(f'bRED|    Warning! Объект GeoIP "{value["name"]}" не конвертирован и не будет использован в правилах.')
                    case 'Internet':
                        self.objects[key] = {'type': 'Zone', 'value': 'Internet'}
                        self.create_zone(self.zones, 'Internet')
            except KeyError:
                pass
        if error:
            self.stepChanged.emit('ORANGE|    Конвертации сопутствующих объектов завершена. Но некоторые сервисы не конвертированы и не будет использован в правилах.')
        else:
            self.stepChanged.emit('GREEN|    Конвертации сопутствующих объектов завершена.')


    def convert_timesets(self):
        """Конверируем календари"""
        self.stepChanged.emit('BLUE|Конвертация календарей.')
        error = 0
        timerestrictiongroup = []

        for key, value in self.objects.items():
            if value['type'] == 'time':
                error, time_set_name = self.get_transformed_name(value['name'], err=error, descr='Имя календаря')
                time_set = {
                    'name': time_set_name,
                    'description': f"Портировано с CheckPoint.\n{value.get('comments', '')}",
                    'type': 'timerestrictiongroup',
                    'url': '',
                    'list_type_update': 'static',
                    'schedule': 'disabled',
                    'attributes': {},
                    'content': []
                }
                content = {
                    'name': time_set['name'],
                    'type': 'span',
                    'time_to': value['end']['time'],
                    'time_from': value['start']['time'],
                }
                tmp_date = value['end']['iso-8601'].split('T')
                content['fixed_date_to'] = f'{tmp_date[0]}T00:00:00'
                tmp_date = value['start']['iso-8601'].split('T')
                content['fixed_date_from'] = f'{tmp_date[0]}T00:00:00'
            
                time_set['content'].append(content)
                timerestrictiongroup.append(time_set)
                self.objects[key] = {'type': 'time', 'name': time_set['name']}

        if timerestrictiongroup:
            section_path = os.path.join(self.current_ug_path, 'Libraries')
            current_path = os.path.join(section_path, 'TimeSets')
            err, msg = self.create_dir(current_path)
            if err:
                self.stepChanged.emit(f'RED|    {msg}')
                self.error = 1
                return

            json_file = os.path.join(current_path, 'config_calendars.json')
            with open(json_file, 'w') as fh:
                json.dump(timerestrictiongroup, fh, indent=4, ensure_ascii=False)

            if error:
                self.error = 1
                self.stepChanged.emit(f'ORANGE|    Конвертация календарей прошла с ошибками. Список календарей выгружен в файл "{json_file}".')
            else:
                self.stepChanged.emit(f'GREEN|    Список календарей выгружен в файл "{json_file}".')
        else:
            self.stepChanged.emit(f'GRAY|    Нет календарей для экспорта.')


    def convert_services(self):
        """
        Конвертируем список сервисов. В "objects" UID-ы с сервисами переписываются в вид:
        uid: {'type'; 'service', 'name': 'ИМЯ_СЕРВИСА'} для загрузки сервисов в правила.
        """
        self.stepChanged.emit('BLUE|Конвертация списков сервисов.')
        error = 0

        for key, value in self.objects.items():
            if value['type'] == 'service-icmp':
                self.objects[key] = {'type': 'service', 'name': 'Any ICMP'}
                self.services['Any ICMP'] = {
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
                self.objects[key] = {'type': 'service', 'name': 'Any IPV6-ICMP'}
                self.services['Any IPV6-ICMP'] = {
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
                service_name = value['name']
                self.objects[key] = {'type': 'service', 'name': value['name']}
            
#                if 'Kerberos' in value['name']:
#                    print(value['name'], service_name)

                port = value.get('port', "")
                if (">" or "<") in port:
                    if port[0] == '<':
                        value['port'] = f'0-{port[1:]}'
                    elif port[0] == '>':
                        value['port'] = f'{port[1:]}-65535'
                    else:
                        self.objects[key]['type'] = 'error'
                        self.objects[key]['description'] = f'Сервис "{service_name}" не конвертирован (символы "<" и ">" не поддерживаются в определении порта).'
                        self.stepChanged.emit(f'RED|    Warning: Сервис "{service_name}" не конвертирован (символы "<" и ">" не поддерживаются в определении порта.')
                        error = 1
                        continue
                self.services[service_name] = {
                    'name': service_name,
                    'description': f"Портировано с CheckPoint.\n{value.get('comments', '')}",
                    'protocols': [
                        {
                            'proto': proto,
                            'port': value.get('port', ''),
                            'app_proto': '',
                            'source_port': value.get('source-port', ''),
                            'alg': ''
                        }
                    ]
                }

#               if 'Kerberos' in value['name']:
#                    print(self.services[service_name], '\n')

        if self.services:
            if error:
                self.error = 1
                self.stepChanged.emit(f'ORANGE|    Конвертация сервисов прошла с ошибками.')
            else:
                self.stepChanged.emit(f'GREEN|    Конвертация сервисов прошла успешно.')
        else:
            self.stepChanged.emit('GRAY|    Нет сервисов для экспорта.')


    def convert_services_groups(self):
        """
        Конвертируем группы сервисов. В "objects" UID-ы с сервис группами переписываются в вид:
        uid: {'type': 'servicegroup', 'name': 'ИМЯ_СЕРВИСА'} для загрузки сервисов в правила.
        """
        self.stepChanged.emit('BLUE|Конвертация групп сервисов.')

        # Создаём словарь row_groups. Он используется в основном цикле для добавления сервисов вложенных групп в группу.
        # Отдельный цикл нужен, так как в objects группы идут не в порядке вложения в другие группы.
        row_groups = {}
        for key, value in self.objects.items():
            if value['type'] == 'service-group':
                row_groups[value['name']] = set()
                for uid in value['members']:
                    if uid in self.objects and self.objects[uid]['type'] != 'error':
                        row_groups[value['name']].add(self.objects[uid]['name'])
                    elif uid in embedded_objects:
                        if embedded_objects[uid]['type'] == 'service':
                            row_groups[value['name']].add(embedded_objects[uid]['name'])
                    else:
                        self.stepChanged.emit(f'RED|    Error: [Группа сервисов "{value["name"]}"] Не найден сервис {uid}.')

        # Основной цикл обработки групп сервисов..
        for key, value in self.objects.items():
            if value['type'] == 'service-group':
                members = set()                       # Для members использован сет для удаления одинаковых сервисов.
                for uid in value['members']:
                    if uid in self.objects:
                        if self.objects[uid]['type'] == 'error':
                            self.stepChanged.emit(f'RED|    {self.objects[uid]["description"]} Этот сервис не будет добавлен в группу сервисов "{value["name"]}".')
                        else:
                            members.add(self.objects[uid]['name'])
                    elif uid in embedded_objects:
                        service = embedded_objects[uid]
                        if service['type'] == 'service':
                            self.make_embedded_service(service)
                            members.add(service['name'])

                content = []
                for name in members:
                    try:
                        content.append(copy.deepcopy(self.services[name]))
                    except KeyError as err:
                        if name in row_groups:
                            self.make_row_groups(name, row_groups, content)

                for item in content:
                    for x in item['protocols']:
                        x.pop('alg', None)
                        x.pop('source_port', None)
                        x.pop('app_proto', None)

                self.service_groups[value['name']] = {
                    'name': value['name'],
                    'description': f"Портировано с CheckPoint.\n{value.get('comments', '')}",
                    'type': 'servicegroup',
                    'url': '',
                    'list_type_update': 'static',
                    'schedule': 'disabled',
                    'attributes': {},
                    'content': content
                }

                self.objects[key] = {'type': 'servicegroup', 'name': value['name']}
                self.stepChanged.emit(f'BLACK|    Группа сервисов {value["name"]} конвертирована".')

        section_path = os.path.join(self.current_ug_path, 'Libraries')
        if self.service_groups:
            current_path = os.path.join(section_path, 'ServicesGroups')
            err, msg = self.create_dir(current_path)
            if err:
                self.stepChanged.emit(f'RED|    {msg}')
                self.error = 1
                return

            json_file = os.path.join(current_path, 'config_services_groups_list.json')
            with open(json_file, 'w') as fh:
                json.dump([x for x in self.service_groups.values()], fh, indent=4, ensure_ascii=False)
            self.stepChanged.emit(f'GREEN|    Список групп сервисов выгружен в файл "{json_file}".')
        else:
            self.stepChanged.emit('GRAY|    Нет групп сервисов для экспорта.')

        if self.services:
            current_path = os.path.join(section_path, 'Services')
            err, msg = self.create_dir(current_path)
            if err:
                self.stepChanged.emit(f'RED|    {msg}')
                self.error = 1
                return

            json_file = os.path.join(current_path, 'config_services_list.json')
            with open(json_file, 'w') as fh:
                json.dump(list(self.services.values()), fh, indent=4, ensure_ascii=False)
            self.stepChanged.emit(f'GREEN|    Список сервисов выгружен в файл "{json_file}".')


    def make_row_groups(self, name, row_groups, content):
        """Для convert_services_groups(). Выполняем циклическое преобразование вложенных групп сервисов."""
        for item in row_groups[name]:
            if item in self.services:
                content.append(copy.deepcopy(self.services[item]))
            elif item in row_groups:
                self.make_row_groups(item, row_groups, content)


    def convert_ip_lists(self):
        """
        Выгружаем списки IP-адресов.
        В "objects" типы "host", "address-range", "network" переписываются в вид:
        uid: {"type": "network", "name": {"list": "ИМЯ_IP_ЛИСТА"}} для загрузки ip-листов в правила. Или
        uid: {"type": "error", "name": f'Объект value["type"]: "{value["name"]}" содержит IPV6 адрес.'}
        """
        self.stepChanged.emit('BLUE|Конвертация списков IP-адресов.')
        section_path = os.path.join(self.current_ug_path, 'Libraries')
        current_path = os.path.join(section_path, 'IPAddresses')
        err, msg = self.create_dir(current_path)
        if err:
            self.stepChanged.emit(f'RED|    {msg}')
            self.error = 1
            return

        error = 0
        n = 0
        for key, value in self.objects.items():
            if value['type'] in ('host', 'address-range', 'network'):
                if value.keys().isdisjoint(('ipv4-address', 'ipv4-address-first', 'subnet4')):
                    self.stepChanged.emit(f'bRED|    Warning: [Объект "{value["type"]}"] "{value["name"]}" содержит IPV6 адрес или подсеть. Данный тип адреса не поддерживается.')
                    self.objects[key] = {'type': 'error', 'name': f'Объект {value["type"]}: "{value["name"]}" содержит IPV6 адрес или подсеть.'}
                    continue
                n += 1
                error, ip_list_name = self.get_transformed_name(value['name'], err=error, descr='Имя списка IP-адресов')
                self.objects[key] = {'type': 'network', 'name': {'list': ip_list_name}}
                match value['type']:
                    case 'host':
                        content = [{'value': value['ipv4-address']}]
                    case 'address-range':
                        content = [{'value': f"{value['ipv4-address-first']}-{value['ipv4-address-last']}"}]
                    case 'network':
                        content = [{'value': f"{value['subnet4']}/{value['mask-length4']}"}]

                ip_list = {
                    'name': ip_list_name,
                    'description': f"Портировано с CheckPoint.\n{value.get('comments', '')}",
                    'type': 'network',
                    'url': '',
                    'list_type_update': 'static',
                    'schedule': 'disabled',
                    'attributes': {'threat_level': 3},
                    'content': content
                }

                json_file = os.path.join(current_path, f'{ip_list_name.translate(self.trans_filename)}.json')
                try:
                    with open(json_file, 'w') as fh:
                        json.dump(ip_list, fh, indent=4, ensure_ascii=False)
                    self.stepChanged.emit(f'BLACK|    {n} - Список IP-адресов "{ip_list["name"]}" выгружен в файл "{json_file}".')
                except OSError as err:
                    error = 1
                    self.objects[key] = {'type': 'error', 'name': value['name'], 'description': f'Список IP-адресов "{value["name"]}" не конвертирован.'}
                    self.stepChanged.emit(f'RED|    Error: Объект "{value["type"]}" - "{value["name"]}" не конвертирован и не будет использован в правилах.\n    {err}')
                self.msleep(1)
        if error:
            self.error = 1
            self.stepChanged.emit(f'ORANGE|    Конвертация списков IP-адресов прошла с ошибками. Списки IP-адресов выгружены в каталог "{current_path}".')
        else:
            if n:
                self.stepChanged.emit(f'GREEN|    Списки IP-адресов выгружены в каталог "{current_path}".')
            else:
                self.stepChanged.emit(f'GRAY|    Нет списков IP-адресов для экспорта.')


    def convert_simple_cluster(self):
        """
        Конвертируем объекты type: simple-cluster в списки IP-адресов.
        В "objects" тип "simple-cluster" переписываются в вид:
        uid: {"type": "network", "name": {"list": "ИМЯ_IP_ЛИСТА"}} для загрузки ip-листов в правила. Или
        Если интерфейс ноды содержит IPv6 и не содержит IPv4, то он пропускается.
        """
        self.stepChanged.emit('BLUE|Конвертация объектов с типом "simple-cluster" в списки IP-адресов.')
        section_path = os.path.join(self.current_ug_path, 'Libraries')
        current_path = os.path.join(section_path, 'IPAddresses')
        err, msg = self.create_dir(current_path, delete='no')
        if err:
            self.stepChanged.emit(f'RED|    {msg}')
            self.error = 1
            return

        error = 0
        n = 0
        for key, value in self.objects.items():
            if value['type'] == 'simple-cluster':
                content = []
                if 'cluster-members' in value:
                    for member in value['cluster-members']:
                        for item in member['interfaces']:
                            ipv4 = item.get('ipv4-address', None)
                            if ipv4:
                                content.append({'value': f"{ipv4}/{item['ipv4-mask-length']}"})
                if 'interfaces' in value:
                    if 'objects' in value['interfaces']:
                        for item in value['interfaces']['objects']:
                            ipv4 = item.get('ipv4-address', None)
                            if ipv4:
                                content.append({'value': f"{ipv4}/{item['ipv4-mask-length']}"})
                if content:
                    n += 1
                    error, ip_list_name = self.get_transformed_name(value['name'], err=error, descr='Имя списка IP-адресов')
                    ip_list = {
                        'name': ip_list_name,
                        'description': f"Портировано с CheckPoint.\n{value.get('comments', '')}",
                        'type': 'network',
                        'url': '',
                        'list_type_update': 'static',
                        'schedule': 'disabled',
                        'attributes': {'threat_level': 3},
                        'content': content
                    }

                    json_file = os.path.join(current_path, f'{ip_list_name.translate(self.trans_filename)}.json')
                    try:
                        with open(json_file, 'w') as fh:
                            json.dump(ip_list, fh, indent=4, ensure_ascii=False)
                        self.stepChanged.emit(f'BLACK|    {n} - Список IP-адресов "{ip_list["name"]}" выгружен в файл "{json_file}".')
                    except OSError as err:
                        error = 1
                        self.objects[key] = {'type': 'error', 'name': value['name'], 'description': f'Список IP-адресов "{value["name"]}" не конвертирован.'}
                        self.stepChanged.emit(f'RED|    Error: Объект "{value["type"]}" - "{value["name"]}" не конвертирован и не будет использован в правилах.\n    {err}')

                    self.objects[key] = {'type': 'network', 'name': {'list': ip_list['name']}}
                    self.msleep(2)

        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Списки IP-адресов выгружены с ошибками.')
        else:
            if n:
                self.stepChanged.emit(f'GREEN|    Списки IP-адресов выгружены в каталог "{current_path}".')
            else:
                self.stepChanged.emit('GRAY|    Нет списков IP-адресов для экспорта.')


    def convert_cluster_members(self):
        """
        Конвертируем объекты "type: cluster-member" в списки IP-адресов.
        В "objects" тип "cluster-member" переписываются в вид:
        uid: {"type": "network", "name": {"list": "ИМЯ_IP_ЛИСТА"}} для загрузки ip-листов в правила.
        Если интерфейс ноды содержит IPv6 и не содержит IPv4, то он пропускается.
        """
        self.stepChanged.emit('BLUE|Конвертация объектов с типом "cluster-member" в списки IP-адресов.')
        section_path = os.path.join(self.current_ug_path, 'Libraries')
        current_path = os.path.join(section_path, 'IPAddresses')
        err, msg = self.create_dir(current_path, delete='no')
        if err:
            self.stepChanged.emit(f'RED|    {msg}')
            self.error = 1
            return

        error = 0
        n = 0
        for key, value in self.objects.items():
            if value['type'] == 'cluster-member':
                n += 1
                content = []
                for item in value['interfaces']:
                    ipv4 = item.get('ipv4-address', None)
                    if ipv4:
                        content.append({'value': f"{ipv4}/{item['ipv4-mask-length']}"})

                error, ip_list_name = self.get_transformed_name(value['name'], err=error, descr='Имя списка IP-адресов')
                ip_list = {
                    'name': ip_list_name,
                    'description': f"Портировано с CheckPoint.\n{value.get('comments', '')}",
                    'type': 'network',
                    'url': '',
                    'list_type_update': 'static',
                    'schedule': 'disabled',
                    'attributes': {'threat_level': 3},
                    'content': content
                }

                json_file = os.path.join(current_path, f'{ip_list_name.translate(self.trans_filename)}.json')
                try:
                    with open(json_file, 'w') as fh:
                        json.dump(ip_list, fh, indent=4, ensure_ascii=False)
                    self.stepChanged.emit(f'BLACK|    {n} - Список IP-адресов "{ip_list["name"]}" выгружен в файл "{json_file}".')
                except OSError as err:
                    error = 1
                    self.objects[key] = {'type': 'error', 'name': value['name'], 'description': f'Список IP-адресов "{value["name"]}" не конвертирован.'}
                    self.stepChanged.emit(f'RED|    Error: Объект "{value["type"]}" - "{value["name"]}" не конвертирован и не будет использован в правилах.\n    {err}')

                self.objects[key] = {'type': 'network', 'name': {'list': ip_list['name']}}

        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Списки IP-адресов выгружены с ошибками.')
        else:
            if n:
                self.stepChanged.emit(f'GREEN|    Списки IP-адресов выгружены в каталог "{current_path}".')
            else:
                self.stepChanged.emit('GRAY|    Нет списков IP-адресов для экспорта.')


    def convert_checkpoint_host(self):
        """
        Конвертируем объекты "type: checkpoint_host" в списки IP-адресов.
        В "objects" тип "checkpoint_host" переписываются в вид:
        uid: {"type": "network", "name": {"list": "ИМЯ_IP_ЛИСТА"}} для загрузки ip-листов в правила.
        Если интерфейс ноды содержит IPv6 и не содержит IPv4, то он пропускается.
        """
        self.stepChanged.emit('BLUE|Конвертация объектов с типом "checkpoint_host" в списки IP-адресов.')
        section_path = os.path.join(self.current_ug_path, 'Libraries')
        current_path = os.path.join(section_path, 'IPAddresses')
        err, msg = self.create_dir(current_path, delete='no')
        if err:
            self.stepChanged.emit(f'RED|    {msg}')
            self.error = 1
            return

        error = 0
        n = 0
        for key, value in self.objects.items():
            if value['type'] == 'checkpoint-host':
                n += 1
                content = []
                for item in value['interfaces']:
                    ipv4 = item.get('subnet4', None)
                    if ipv4:
                        content.append({'value': f"{ipv4}/{item['mask-length4']}"})

                error, ip_list_name = self.get_transformed_name(value['name'], err=error, descr='Имя списка IP-адресов')
                ip_list = {
                    'name': ip_list_name,
                    'description': f"Портировано с CheckPoint.\n{value.get('comments', '')}",
                    'type': 'network',
                    'url': '',
                    'list_type_update': 'static',
                    'schedule': 'disabled',
                    'attributes': {'threat_level': 3},
                    'content': content
                }

                json_file = os.path.join(current_path, f'{ip_list_name.translate(self.trans_filename)}.json')
                try:
                    with open(json_file, 'w') as fh:
                        json.dump(ip_list, fh, indent=4, ensure_ascii=False)
                    self.stepChanged.emit(f'BLACK|    {n} - Список IP-адресов "{ip_list["name"]}" выгружен в файл "{json_file}".')
                except OSError as err:
                    error = 1
                    self.objects[key] = {'type': 'error', 'name': value['name'], 'description': f'Список IP-адресов "{value["name"]}" не конвертирован.'}
                    self.stepChanged.emit(f'RED|    Error: Объект "{value["type"]}" - "{value["name"]}" не конвертирован и не будет использован в правилах.\n    {err}')

                self.objects[key] = {'type': 'network', 'name': {'list': ip_list['name']}}
                self.msleep(2)

        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Списки IP-адресов выгружены с ошибками.')
        else:
            if n:
                self.stepChanged.emit(f'GREEN|    Списки IP-адресов выгружены в каталог "{current_path}".')
            else:
                self.stepChanged.emit('GRAY|    Нет списков IP-адресов для экспорта.')


    def convert_ip_lists_groups(self):
        """
        Выгружаем списки групп IP-адресов.
        В "objects" тип "group" переписывается в вид:
        uid: {"type": "network", "name": {"list": "ИМЯ_IP_ЛИСТА"}}.
        """
        self.stepChanged.emit('BLUE|Конвертация списков групп IP-адресов.')
        section_path = os.path.join(self.current_ug_path, 'Libraries')
        current_path = os.path.join(section_path, 'IPAddresses')
        err, msg = self.create_dir(current_path, delete='no')
        if err:
            self.stepChanged.emit(f'RED|    {msg}')
            self.error = 1
            return

        error = 0
        n = 0
        for key, value in self.objects.items():
            if value['type'] == 'group':
                n += 1
                error, ip_list_name = self.get_transformed_name(value['name'], err=error, descr='Имя списка групп IP-адресов')
                self.objects[key] = {'type': 'network', 'name': {'list': ip_list_name}}
                content = []
                for uid in value['members']:
                    try:
                        if self.objects[uid]['type'] == 'simple-gateway':
                            content.append({"value": self.objects[uid]['ipv4-address']})
                        else:
                            if isinstance(self.objects[uid]['name'], dict):
                                content.append(self.objects[uid]['name'])
                            elif isinstance(self.objects[uid]['name'], str):
                                content.append({"list": self.objects[uid]['name']})
                            else:
                                error = 1
                                self.stepChanged.emit(f'RED|    Error: [Группа IP-аресов "{value["name"]}"] Не определён тип объекта "{self.objects[uid]["name"]}". Данный список IP-адресов не будет включён в эту группу.')
                    except KeyError:
                        error = 1
                        self.stepChanged.emit(f'RED|    Error: [Группа IP-аресов "{value["name"]}"] В членах группы присутствует ссылка на несуществующий объект: {uid}.')

                ip_list = {
                    'name': ip_list_name,
                    'description': f"Портировано с CheckPoint.\n{value.get('comments', '')}",
                    'type': 'network',
                    'url': '',
                    'list_type_update': 'static',
                    'schedule': 'disabled',
                    'attributes': {'threat_level': 3},
                    'content': content
                }

                json_file = os.path.join(current_path, f'{ip_list_name.translate(self.trans_filename)}.json')
                try:
                    with open(json_file, 'w') as fh:
                        json.dump(ip_list, fh, indent=4, ensure_ascii=False)
                    self.stepChanged.emit(f'BLACK|    {n} - Список групп IP-адресов "{ip_list["name"]}" выгружен в файл "{json_file}".')
                except OSError as err:
                    error = 1
                    self.objects[key] = {'type': 'error', 'name': value['name'], 'description': f'Список групп IP-адресов "{value["name"]}" не конвертирован.'}
                    self.stepChanged.emit(f'RED|    Error: Объект "{value["type"]}" - "{value["name"]}" не конвертирован и не будет использован в правилах.\n    {err}')
                self.msleep(2)

        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Списки групп IP-адресов выгружены с ошибками.')
        else:
            if n:
                self.stepChanged.emit(f'GREEN|    Списки групп IP-адресов выгружены в каталог "{current_path}".')
            else:
                self.stepChanged.emit(f'GRAY|    Нет списков групп IP-адресов для экспорта.')


    def convert_ip_group_with_exclusion(self):
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
        self.stepChanged.emit('BLUE|Конвертация групп IP-адресов с типом group-with-exclusion.')

        error = 0
        for key, value in self.objects.items():
            if value['type'] == 'group-with-exclusion':
                try:
                    groups = []
                    if 'except' in value:
                        groups.append({"type": "network", "name": self.objects[value['except']['uid']]['name'], "action": "drop"})
                    if 'include' in value:
                        groups.append({"type": "network", "name": self.objects[value['include']['uid']]['name'], "action": "accept"})
                    self.objects[key] = {"type": "group-with-exclusion", "groups": groups}
                except KeyError as err:
                    error = 1
                    self.objects[key] = {'type': 'error', 'name': value['name'], 'description': f'Объект group-with-exclusion "{value["name"]}" не конвертирован.'}
                    self.stepChanged.emit(f'RED|    Error: Group-with-exclusion "{value["name"]}" не конвертирована: {err}.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Группы IP-адресов с типом group-with-exclusion конвертированы с ошибками.')
        else:
            self.stepChanged.emit('GREEN|    Группы IP-адресов с типом group-with-exclusion конвертированы.')


    def convert_url_lists(self):
        """
        Выгружаем списки URL.
        В "objects" тип "application-site" переписывается в вид: uid: {'type': 'url', 'name': 'ИМЯ_URL_ЛИСТА'}.
        """
        self.stepChanged.emit('BLUE|Конвертация списков URL.')
        section_path = os.path.join(self.current_ug_path, 'Libraries')
        current_path = os.path.join(section_path, 'URLLists')
        err, msg = self.create_dir(current_path)
        if err:
            self.stepChanged.emit(f'RED|    {msg}')
            self.error = 1
            return

        error = 0
        n = 0
        for key, value in self.objects.items():
            if value['type'] == 'application-site' and 'url-list' in value:
                n += 1
                error, url_name = self.get_transformed_name(value['name'], err=error, descr='Имя списка URL')
                self.objects[key] = {'type': 'url', 'name': url_name}

                url_list = {
                    'name': url_name,
                    'description': f'Портировано с CheckPoint.\n{value.get("comments", "")}',
                    'type': 'url',
                    'url': '',
                    'list_type_update': 'static',
                    'schedule': 'disabled',
                    'attributes': {
                        'list_compile_type': 'case_insensitive'
                    },
                    'content': [{'value': url.translate(trans_url)} for url in value['url-list']]
                }

                json_file = os.path.join(current_path, f'{url_name.translate(self.trans_filename)}.json')
                try:
                    with open(json_file, 'w') as fh:
                        json.dump(url_list, fh, indent=4, ensure_ascii=False)
                    self.stepChanged.emit(f'BLACK|    {n} - Список URL "{url_list["name"]}" выгружен в файл "{json_file}".')
                except OSError as err:
                    error = 1
                    self.objects[key] = {'type': 'error', 'name': value['name'], 'description': f'Список URL "{value["name"]}" не конвертирован'}
                    self.stepChanged.emit(f'RED|    Объект "{value["type"]}" - "{value["name"]}" не конвертирован и не будет использован в правилах.\n    {err}')
                self.msleep(2)

            elif value['type'] == 'dns-domain':
                n += 1
                error, url_name = self.get_transformed_name(value['name'], err=error, descr='Имя списка URL')
                self.objects[key] = {'type': 'dns-domain', 'value': ['urllist_id', url_name]}
                url_list = {
                    'name': url_name,
                    'description': f'Портировано с CheckPoint.\n{value.get("comments", "")}',
                    'type': 'url',
                    'url': '',
                    'list_type_update': 'static',
                    'schedule': 'disabled',
                    'attributes': {
                        'list_compile_type': 'domain'
                    },
                    'content': [{'value': value['name'].translate(trans_url)}]
                }

                json_file = os.path.join(current_path, f'{url_name.translate(self.trans_filename)}.json')
                try:
                    with open(json_file, 'w') as fh:
                        json.dump(url_list, fh, indent=4, ensure_ascii=False)
                    self.stepChanged.emit(f'BLACK|    {n} - Список URL "{url_list["name"]}" выгружен в файл "{json_file}".')
                except OSError as err:
                    error = 1
                    self.objects[key] = {'type': 'error', 'name': value['name'], 'description': f'Список URL "{value["name"]}" не конвертирован.'}
                    self.stepChanged.emit(f'RED|    Объект "{value["type"]}" - "{value["name"]}" не конвертирован и не будет использован в правилах.\n    {err}')
                self.msleep(2)

        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Списки URL выгружены с ошибками.')
        else:
            if n:
                self.stepChanged.emit(f'GREEN|    Списки URL выгружены в каталог "{current_path}".')
            else:
                self.stepChanged.emit('GRAY|    Нет списков URL для экспорта.')


    def convert_application_site_category(self):
        """
        В "objects" тип "application-site-category" переписывается в вид: uid:
        uid: {
           'type': 'app-url-category',
           'l7_category': ['ИМЯ_КАТЕГОРИИ_ПРИЛОЖЕНИЙ', ...],
           'url_category': ['ИМЯ_КАТЕГОРИИ_URL', ...],
           'applicationgroup': ['ИМЯ_ГРУППЫ ПРИЛОЖЕНИЙ', ...]
        }
        """
        self.stepChanged.emit('BLUE|Конвертация application-site-categoty.')
    
        error = 0
        n = 0
        for key, value in self.objects.items():
            if value['type'] == 'application-site-category':
                n += 1
                try:
                    self.objects[key] = cp_app_category[value['name']]
                except KeyError:
                    error = 1
                    self.objects[key] = {'type': 'error', 'name': value['name'], 'description': f'Для категории "{value["name"]}" нет аналога на UG NGFW.'}
                    self.stepChanged.emit(f'bRED|    Warning! Application-site-category "{value["name"]}" не конвертирована (нет аналога на UG NGFW).')
        if error:
            self.stepChanged.emit('ORANGE|    Конвертации application-site-categoty завершена. Но некоторые категории не перенесены и не будут использованы в правилах.')
        else:
            if n:
                self.stepChanged.emit('GREEN|    Конвертация application-site-category прошла успешно.')
            else:
                self.stepChanged.emit('GRAY|    Нет application-site-category для экспорта.')


    def convert_application_site(self):
        """
        В файле objects.json в типе application-site переписывается в вид:
        uid: {'type': 'l7apps', 'name': ['app_name']}.
        """
        self.stepChanged.emit('BLUE|Конвертация application-site в Приложения и Категории URL.')

        error = 0
        n = 0
        for key, value in self.objects.items():
            if value['type'] == 'application-site':
                n += 1
                if value['name'] in app_compliance:
                    self.objects[key] = {'type': 'l7apps', 'name': app_compliance[value['name']]}
                elif value['name'] in appgroup_compliance:
                    self.objects[key] = {'type': 'applicationgroup', 'name': appgroup_compliance[value['name']]}
                elif value['name'] in l7_category_compliance:
                    self.objects[key] = {'type': 'l7_category', 'name': l7_category_compliance[value['name']]}
                elif value['name'] in url_category_compliance:
                    self.objects[key] = {'type': 'url_category', 'name': url_category_compliance[value['name']]}
                else:
                    error = 1
                    self.objects[key] = {'type': 'error', 'name': value["name"], 'description': f'Для приложения "{value["name"]}" нет аналога на UG NGFW.'}
                    self.stepChanged.emit(f'bRED|    Warning! Приложение "{value["name"]}" не конвертировано (нет аналога на UG NGFW).')
        if error:
            self.stepChanged.emit('ORANGE|    Конвертации application-site завершена. Но некоторые приложения не перенесены и не будут использованы в правилах.')
        else:
            if n:
                self.stepChanged.emit('GREEN|    Конвертация application-site прошла успешно.')
            else:
                self.stepChanged.emit('GRAY|    Нет application-site для экспорта.')


    def convert_application_group(self):
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
        self.stepChanged.emit('BLUE|Конвертация application-site-group в группы приложений и URL категорий.')

        error = 0
        url_groups = []
        for key in self.objects:
            try:
                if self.objects[key]['type'] == 'application-site-group':
                    app = set()
                    ro_group = set()
                    applicationgroups = set()
                    url_category = set()
                    url_list = set()

                    error, apps_group_name = self.get_transformed_name(self.objects[key]['name'], err=error, descr='Имя application-site-group')
                    apps_group_tmp = {
                        'name': apps_group_name,
                        'comments': f"Портировано с CheckPoint.\n{self.objects[key].get('comments', '')}",
                        'type': 'apps_group',
                        'apps': [],
                        'url_categories': [],
                        'urls': [],
                        'error': 0,
                        'description': []
                    }
                    for item in self.objects[key]['members']:
                        try:
                            match self.objects[item]['type']:
                                case 'app-url-category':
                                    for name in self.objects[item]['l7_category']:
                                        ro_group.add(name)
                                    for name in self.objects[item]['applicationgroup']:
                                        applicationgroups.add(name)
                                    for name in self.objects[item]['url_category']:
                                        url_category.add(name)
                                case 'l7apps':
                                    for name in self.objects[item]['name']:
                                        app.add(name)
                                case 'l7_category':
                                    for name in self.objects[item]['name']:
                                        ro_group.add(name)
                                case 'applicationgroup':
                                    for name in self.objects[item]['name']:
                                        applicationgroups.add(name)
                                case 'url_category':
                                    for name in self.objects[item]['name']:
                                        url_category.add(name)
                                case 'url':
                                    url_list.add(self.objects[item]['name'])
                                case 'error':
                                    apps_group_tmp['description'].append(self.objects[item]['description'])
                        except (TypeError, KeyError) as err:
                            self.stepChanged.emit(f'bRED|    Warning! [application-site-group "{self.objects[key]["name"]}"] {err} - {item}.')

                    apps_group_tmp['apps'].extend([['ro_group', x] for x in ro_group]),
                    apps_group_tmp['apps'].extend([['group', x] for x in applicationgroups]),
                    apps_group_tmp['urls'] = [x for x in url_list]

                    if app:
                        apps_group_tmp['apps'].append(['group', apps_group_tmp['name']])
                        self.create_app_group(apps_group_tmp['name'], app, comment=apps_group_tmp['comments'])
                    
                    if url_category:
                        url_groups.append(
                            {
                                'name': apps_group_tmp['name'],
                                'description': apps_group_tmp['comments'],
                                'type': 'urlcategorygroup',
                                'url': '',
                                'list_type_update': 'static',
                                'schedule': 'disabled',
                                'attributes': {},
                                'content': [{'name': x, 'category_id': url_categories[x]} for x in url_category]
                            }
                        )
                        apps_group_tmp['url_categories'].append(['list_id', apps_group_tmp['name']])
                    # Если объект получился пустой (нет приложений, категорий и URL), ставим маркер ошибки.
                    # В названии правила МЭ пишем: "ERROR - ИМЯ_ПРАВИЛА".
                    # В описание правила МЭ добавляем objects[key]['description'] с описанием проблемы.
                    if not apps_group_tmp['apps'] and not apps_group_tmp['url_categories'] and not apps_group_tmp['urls']:
                        apps_group_tmp['error'] = 1

                    self.objects[key] = apps_group_tmp
            except (TypeError, KeyError) as err:
                self.stepChanged.emit(f'dGRAY|    Warning! [application-site-group "{self.objects[key]["name"]}"] {err} - {self.objects[key]}.')
                error = 1
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Конвертация application-site-group завершена с ошибками.')
        else:
            self.stepChanged.emit('GREEN|    Конвертация application-site-group завершена.')

        if url_groups:
            section_path = os.path.join(self.current_ug_path, 'Libraries')
            current_path = os.path.join(section_path, 'URLCategories')
            err, msg = self.create_dir(current_path)
            if err:
                self.stepChanged.emit(f'RED|    {msg}')
                self.error = 1
                return

            json_file = os.path.join(current_path, 'config_url_categories.json')
            with open(json_file, 'w') as fh:
                json.dump(url_groups, fh, indent=4, ensure_ascii=False)
            self.stepChanged.emit(f'GREEN|    Группы категорий URL выгружен в файл "{json_file}".')
        else:
            self.stepChanged.emit('GRAY|    Нет категорий URL для экспорта.')


    def convert_access_role(self):
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
        self.stepChanged.emit('BLUE|Конвертация access-role.')

        error = 0
        n = 0
        for key, value in self.objects.items():
            if value['type'] == 'access-role':
                n += 1
                tmp_role = {
                    'type': value['type'],
                    'name': value['name'],
                    'users': []
                }
                if 'networks' in value and value['networks'] != 'any':
                    tmp_role['networks'] = [['list_id', x['name']] for x in value['networks']]
                if 'users' in value:
                    if isinstance(value['users'], list):
                        for item in value['users']:
                            if item['type'] in {'CpmiAdUser', 'CpmiAdGroup'}:
                                name = None
                                try:
                                    tooltip = [x for x in item['tooltiptext'].split('\n')]
                                except KeyError as err:
                                    self.stepChanged.emit(f'bRED|    Warning! [access-role "{value["name"]}"] - {err}. Access-role не конвертировано и не будет использоваться в правилах.')
                                    error = 1
                                    continue

                                if '=' in tooltip[1]:
                                    tmp1 = tooltip[0].split(' = ')
                                    tmp2 = tooltip[1].split(' = ')
                                    if tmp2[1].isascii():
                                        name = f'{tmp1[1][:-4].lower()}\\{tmp2[1]}'
                                    else:
                                        for x in tooltip:
                                            y = x.split(': ')
                                            if y[0] == 'Email':
                                                tmp2 = y[1].split('@')[0]
                                                name = f'{tmp1[1][:-4].lower()}\\{tmp2}'
                                                break

                                elif ':' in tooltip[1]:
                                    tmp1 = tooltip[0].split(': ')
                                    tmp2 = tooltip[1].split(': ')
                                    if tmp2[1].isascii():
                                        name = f'{tmp1[1][:-4].lower()}\\{tmp2[1]}'
                                    else:
                                        for x in tooltip:
                                            y = x.split(': ')
                                            if y[0] == 'Email':
                                                tmp2 = y[1].split('@')[0]
                                                name = f'{tmp1[1][:-4].lower()}\\{tmp2}'
                                                break
                                else:
                                    continue

                                if name:
                                    if item['type'] == 'CpmiAdGroup':
                                        tmp_role['users'].append(['group', name])
                                    else:
                                        tmp_role['users'].append(['user', name])
                                else:
                                    self.stepChanged.emit(f'bRED|    Warning! [access-role "{value["name"]}"] user: {tmp2[1]}. Данный пользователь не конвертирован и не будет использоваться в правилах.')
                                    error = 1

                    elif value['users'] == "all identified":
                        tmp_role['users'].append(['special', 'known_user'])
                    elif value['users'] == "any":
                        pass
                    else:
                        self.stepChanged.emit(f'rNOTE|    Warning! [access-role "{value["name"]}"] users = {value["users"]}. Данный пользователь не конвертирован и не будет использоваться в правилах.')

                self.objects[key] = tmp_role

        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Конвертации access-role завершена. Но некоторые объекты access-role не перенесены и не будут использованы в правилах.')
        else:
            if n:
                self.stepChanged.emit('GREEN|    Конвертация access-role прошла успешно.')
            else:
                self.stepChanged.emit('GRAY|    Нет access-role для экспорта.')


    def convert_access_policy_files(self):
        """
        Читаем файл index.json и выбираем файлы конфигурации из раздела 'accessLayers'. Читаем их и вместо uid
        подставляем значения преобразованных объектов из objects. Затем в зависимости от содержимого создаём
        правило МЭ или КФ или правило МЭ и КФ.
        """
        access_rules = []
        checkpoint_hosts = ('CpmiClusterMember', 'simple-cluster', 'checkpoint-host')

        for access_policy_file in self.access_layers:
            error = 0
            self.stepChanged.emit(f'BLUE|Конвертируется файл {access_policy_file}.')
            err, data = self.read_json_file(os.path.join(self.config_path, access_policy_file))
            if err:
                self.error = 1
                self.stepChanged.emit(f'ORANGE|    Произошла ошибка при конвертации файла {access_policy_file}.')
                continue

            for item in data:
                if item['type'] == 'access-rule':
                    if 'name' not in item or not item['name'] or item['name'].isspace():
                        item['name'] = str(uuid.uuid4()).split('-')[4]
                    elif item['name'] == 'Cleanup rule':
                        continue
                    else:
                        error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя access-rule')
                    item.pop('meta-info', None)
                    item.pop('vpn', None)
                    item.pop('domain', None)
                    item.pop('install-on', None)
                    item.pop('custom-fields', None)
                    item.pop('user-check', None)
                    item['description'] = []

                    destination = []
                    for uid in item['destination']:
                        if self.objects[uid]['type'] in checkpoint_hosts:
                            item['description'].append(f'Из destination удалена запись {self.objects[uid]["name"]}.')
                        else:
                            destination.append(self.objects[uid])
                    item['destination'] = destination
                    source = []
                    for uid in item['source']:
                        if self.objects[uid]['type'] in checkpoint_hosts:
                            item['description'].append(f'Из source удалена запись {self.objects[uid]["name"]}.')
                        else:
                            source.append(self.objects[uid])
                    item['source'] = source
                    item['content'] = [self.objects[uid] for uid in item['content']]
                    item['action'] = self.objects[item['action']]
                    item['service'] = [self.objects[uid] for uid in item['service']]
                    item['time'] = [self.objects[uid] for uid in item['time']]
                    item['track'] = self.log_tracker.get(item['track']['type'], False)

                    access_rules.append(item)
                    self.stepChanged.emit(f'BLACK|    Конвертировано access-rule "{item["name"]}".')
                
#            access_rules.extend(data)

#            json_file = os.path.join(self.config_path, access_policy_file.replace('.json', '_convert.json'))
#            with open(json_file, 'w') as fh:
#                json.dump(data, fh, indent=4, ensure_ascii=False)
            if error:
                self.stepChanged.emit(f'ORANGE|    Конвертация файла {access_policy_file} прошла с ошибками.')
            else:
                self.stepChanged.emit(f'GREEN|    Файл {access_policy_file} конвертирован.')

        self.stepChanged.emit(f'BLUE|Конвертация access-rules.')
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
                    self.create_app_group(appsgroup_name, l7apps, comment=f'Создано для правила "{item["name"]}".')

                if item['description']:
                    item['name'] = f'ERROR - {item["name"]}'

                item['action'] = item['action']['value'] if item['action']['type'] == 'RulebaseAction' else 'drop'
                item['services'] = [['service', service_name] for service_name in services]
                item['services'].extend([['list_id', servicegroup_name] for servicegroup_name in service_groups])
                item['apps'] = apps
                item['url_categories'] = url_categories
                item['urls'] = urls

                indicator = False
                if services or service_groups or apps:
                    self.fw_rules.append(item)
                    indicator = True
                if url_categories or urls:
                    self.kf_rules.append(item)
                    indicator = True
                if not indicator:
                    item['convert_error'] = 1
                    self.fw_rules.append(item)

#        json_file = os.path.join(self.config_path, 'access_rules.json')
#        with open(json_file, 'w') as fh:
#            json.dump(access_rules, fh, indent=4, ensure_ascii=False)
        self.stepChanged.emit('GREEN|    Конвертации access-rules завершена.')


    def create_firewall_rule(self):
        """
        Создаём правило МЭ из self.fw_rules. Если convert_error=1, правило будет пустое с пояснением ошибок в описание правила.
        """
        self.stepChanged.emit('BLUE|Конвертация access-rules в правила межсетевого экрана.')
        if not self.fw_rules:
            self.stepChanged.emit('GRAY|    Нет access-rules для правил межсетевого экрана.')
            return

        section_path = os.path.join(self.current_ug_path, 'NetworkPolicies')
        current_path = os.path.join(section_path, 'Firewall')
        err, msg = self.create_dir(current_path)
        if err:
            self.stepChanged.emit(f'RED|    {msg}')
            self.error = 1
            return

        rule_names = {}
        rules = []
        n = 0
        for item in self.fw_rules:
            if item['name'] in rule_names:  # Встречаются одинаковые имена.
                rule_names[item['name']] += 1        # В этом случае добавляем "1" к имени правила.
                item['name'] = f'{item["name"]} - {rule_names[item["name"]]}'
            else:
                rule_names[item['name']] = 0

            description = f'Портировано с CheckPoint.\n{"\n".join(item["description"])}'
            if item['comments']:
                description = f'{item["comments"]}\n{description}'
            n += 1
            rule = {
                'name': item['name'],
                'description': description,
                'action': item['action'],
                'position': item['rule-number'],
                'scenario_rule_id': False,
                'src_zones': [x['value'] for x in item['source'] if x['type'] == 'Zone'],
                'dst_zones': [x['value'] for x in item['destination'] if x['type'] == 'Zone'],
                'src_ips': self.get_ips_list(item['source']),
                'dst_ips': self.get_ips_list(item['destination']),
                'services': item['services'],
                'apps': item['apps'],
                'users': self.get_users_list(item['source'], item['destination']),
                'enabled': item['enabled'],
                'limit': True,
                'lmit_value': '3/h',
                'lmit_burst': 5,
                'log': item['track'],
                'log_session_start': True if item['track'] else False,
                'src_zones_negate': False,
                'dst_zones_negate': False,
                'src_ips_negate': item['source-negate'],
                'dst_ips_negate': item['destination-negate'],
                'services_negate': item['service-negate'],
                'apps_negate': item['service-negate'],
                'fragmented': 'ignore',
                'time_restrictions': [x['name'] for x in item['time'] if 'name' in x],
                'send_host_icmp': ''
            }
            rules.append(rule)
            self.stepChanged.emit(f'BLACK|    {n} - Создано правило межсетевого экрана "{rule["name"]}".')

        json_file = os.path.join(current_path, 'config_firewall_rules.json')
        with open(json_file, 'w') as fh:
            json.dump(rules, fh, indent=4, ensure_ascii=False)
        self.stepChanged.emit(f'GREEN|    Правила межсетевого экрана выгружены в файл "{json_file}".')


    def create_content_rule(self):
        """
        Создаём правила КФ из self.kf_rules.
        """
        self.stepChanged.emit('BLUE|Конвертация access-rules в правила контентной фильтации.')
        if not self.kf_rules:
            self.stepChanged.emit('GRAY|    Нет access-rules для правил контентной фильтации.')
            return

        section_path = os.path.join(self.current_ug_path, 'SecurityPolicies')
        current_path = os.path.join(section_path, 'ContentFiltering')
        err, msg = self.create_dir(current_path)
        if err:
            self.stepChanged.emit(f'RED|    {msg}')
            self.error = 1
            return

        rule_names = {}
        rules = []
        n = 0
        for item in self.kf_rules:
            if item['name'] in rule_names:  # Встречаются одинаковые имена.
                rule_names[item['name']] += 1        # В этом случае добавляем "1" к имени правила.
                item['name'] = f'{item["name"]} - {rule_names[item["name"]]}'
            else:
                rule_names[item['name']] = 0

            description = f'Портировано с CheckPoint.\n{"\n".join(item["description"])}'
            if item['comments']:
                description = f'{item["comments"]}\n{description}'

            n += 1
            rule = {
                'position': item['rule-number'],
                'action': item['action'],
                'name': item['name'],
                'public_name': '',
                'description': description,
                'enabled': item['enabled'],
                'enable_custom_redirect': False,
                'blockpage_template_id': -1,
                'users': self.get_users_list(item['source'], item['destination']),
                'url_categories': item['url_categories'],
                'src_zones': [x['value'] for x in item['source'] if x['type'] == 'Zone'],
                'dst_zones': [x['value'] for x in item['destination'] if x['type'] == 'Zone'],
                'src_ips': self.get_ips_list(item['source']),
                'dst_ips': self.get_ips_list(item['destination']),
                'morph_categories': [],
                'urls': item['urls'],
                'referers': [],
                'referer_categories': [],
                'user_agents': [],
                'time_restrictions': [x['name'] for x in item['time'] if 'name' in x],
                'content_types': [],
                'http_methods': [],
                'src_zones_negate': False,
                'dst_zones_negate': False,
                'src_ips_negate': item['source-negate'],
                'dst_ips_negate': item['destination-negate'],
                'url_categories_negate': item['service-negate'],
                'urls_negate': item['service-negate'],
                'content_types_negate': item['content-negate'],
                'user_agents_negate': False,
                'custom_redirect': '',
                'enable_kav_check': False,
                'enable_md5_check': False,
                'rule_log': item['track'],
                'scenario_rule_id': False,
                'layer': 'Content Rules',
                'users_negate': False
            }
            rules.append(rule)
            self.stepChanged.emit(f'BLACK|    {n} - Создано правило контентной фильтации "{rule["name"]}".')

        json_file = os.path.join(current_path, 'config_content_rules.json')
        with open(json_file, 'w') as fh:
            json.dump(rules, fh, indent=4, ensure_ascii=False)
        self.stepChanged.emit(f'GREEN|    Правила правила контентной фильтации выгружены в файл "{json_file}".')


    ######################## Служебнуе функции ####################################################################
    @staticmethod
    def get_ips_list(array):
        """Получить структуру src_ips/dst_ips для правил МЭ и КФ из объектов access_rule."""
        result = []
        for item in array:
            if item['type'] == 'network':
                result.append(['list_id', item['name']['list']])
            elif item['type'] == 'access-role' and 'networks' in item:
                result.extend(item['networks'])
            elif item['type'] == 'geoip':
                result.append(['geoip_code', item['value']])
            elif item['type'] == 'dns-domain':
                result.append(item['value'])
        return result

    @staticmethod
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

    @staticmethod
    def create_zone(zones, zone_name):
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
