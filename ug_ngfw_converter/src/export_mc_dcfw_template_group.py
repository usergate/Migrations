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
# Класс экспорта группы шаблонов DCFW из UserGate Management Center.
# Версия 1.1  11.07.2025
#

import os, sys, json
from datetime import datetime as dt
from xmlrpc.client import DateTime as class_DateTime
from PyQt6.QtCore import QThread, pyqtSignal
from common_classes import MyMixedService
from services import default_urlcategorygroup


class ExportMcDcfwTemplateGroup(QThread, MyMixedService):
    """Экспортируем все шаблоны из данной группы шаблонов DCFW МС"""
    stepChanged = pyqtSignal(str)
    
    def __init__(self, utm, group_name, group_path, templates):
        super().__init__()
        self.utm = utm
        self.group_name = group_name      # Имя экспортируемой группы шаблонов
        self.group_path = group_path      # Путь к каталогу с конфигурацией шаблона
        self.templates = templates        # Шаблоны в группе: структура {template_id: template_name}
        self.error = 0
        self.mc_data = {
            'ldap_servers': {},
            'devices_list': {},
            'services': {},
            'service_groups': {},
            'ip_lists': {
                'id-BOTNET_BLACK_LIST': 'BOTNET_BLACK_LIST',
                'id-BANKS_IP_LIST': 'BANKS_IP_LIST',
                'id-ZAPRET_INFO_BLACK_LIST_IP': 'ZAPRET_INFO_BLACK_LIST_IP',
            },
            'url_lists': {
                'id-ENTENSYS_WHITE_LIST': 'ENTENSYS_WHITE_LIST',
                'id-BAD_SEARCH_BLACK_LIST': 'BAD_SEARCH_BLACK_LIST',
                'id-ENTENSYS_BLACK_LIST': 'ENTENSYS_BLACK_LIST',
                'id-ENTENSYS_KAZ_BLACK_LIST': 'ENTENSYS_KAZ_BLACK_LIST',
                'id-FISHING_BLACK_LIST': 'FISHING_BLACK_LIST',
                'id-ZAPRET_INFO_BLACK_LIST': 'ZAPRET_INFO_BLACK_LIST',
                'id-ZAPRET_INFO_BLACK_LIST_DOMAIN': 'ZAPRET_INFO_BLACK_LIST_DOMAIN'
            },
            'calendars': {},
            'shapers': {},
            'response_pages': {-1: -1},
            'url_categorygroups': {},
            'app_profiles': {},
            'app_groups': {},
            'email_groups': {},
            'phone_groups': {},
            'idps_profiles': {},
            'notification_profiles': {-1: -1, -5: '(?) Показать ключ на странице captive-портала'},
            'netflow_profiles': {'undefined': 'undefined'},
            'lldp_profiles': {'undefined': 'undefined'},
            'ssl_profiles': {-1: -1, 0: 0},
            'ssl_forward_profiles': {-1: -1},
            'bfd_profiles': {-1: -1},
            'userid_filters': {},
            'zones': {},
            'interfaces': {},
            'gateways': {},
            'vrf': {},
            'certs': {-1: -1, 0: 0},
            'user_cert_profiles': {0: 0},
            'local_groups': {},
            'local_users': {},
            'auth_servers': {},
            'auth_profiles': {-1: -1, False: False},
            'captive_profiles': {0: 0},
            'mfa_profiles': {},
            'load_balansing': {},
            'client_vpn_profiles': {},
            'server_vpn_profiles': {},
            'vpn_networks': {},
            'snmp_security_profiles': {},
            'url_categories': {},
            'l7_apps': {},
            'l7_categories': {},
        }
        self.export_funcs = {
            'Services': self.export_services,
            'ServicesGroups': self.export_services_groups,
            'IPAddresses': self.export_IP_lists,
            'URLLists': self.export_url_lists,
            'TimeSets': self.export_time_sets,
            'BandwidthPools': self.export_shapers,
            'ResponcePages': self.export_templates,
            'URLCategories': self.export_url_categories,
            'OverURLCategories': self.export_custom_url_categories,
            'Applications': self.export_applications,
            'ApplicationProfiles': self.export_app_profiles,
            'ApplicationGroups': self.export_application_groups,
            'Emails': self.export_email_groups,
            'Phones': self.export_phone_groups,
            'IDPSSignatures': self.export_custom_idps_signatures,
            'IDPSProfiles': self.export_idps_profiles,
            'NotificationProfiles': self.export_notification_profiles,
            'NetflowProfiles': self.export_netflow_profiles,
            'LLDPProfiles': self.export_lldp_profiles,
            'SSLProfiles': self.export_ssl_profiles,
            'SSLForwardingProfiles': self.export_ssl_forward_profiles,
            'BfdProfiles': self.export_bfd_profiles,
            'UserIdAgentSyslogFilters': self.export_useridagent_syslog_filters,
            'Certificates': self.export_certificates,
            'UserCertificateProfiles': self.export_users_certificate_profiles,
            'Zones': self.export_zones,
            'Interfaces': self.export_interfaces,
            'Gateways': self.export_gateways_list,
            'DHCP': self.export_dhcp_subnets,
            'DNS': self.export_dns_config,
            'VRF': self.export_vrf_list,
            'Groups': self.export_local_groups,
            'Users': self.export_local_users,
            'MFAProfiles': self.export_2fa_profiles,
            'AuthServers': self.export_auth_servers,
            'AuthProfiles': self.export_auth_profiles,
            'CaptiveProfiles': self.export_captive_profiles,
            'CaptivePortal': self.export_captive_portal_rules,
            'UserIDagentProperties': self.export_userid_agent_config,
            'UserIDagentConnectors': self.export_userid_agent_connectors,
            'GeneralSettings':  self.export_general_settings,
            'DeviceManagement': '',
            'Administrators': self.export_template_admins,
            'Firewall': self.export_firewall_rules,
            'NATandRouting': self.export_nat_rules,
            'LoadBalancing': self.export_loadbalancing_rules,
            'TrafficShaping': self.export_shaper_rules,
            'ClientSecurityProfiles': self.export_vpnclient_security_profiles,
            'ServerSecurityProfiles': self.export_vpnserver_security_profiles,
            'VPNNetworks': self.export_vpn_networks,
            'ClientRules': self.export_vpn_client_rules,
            'ServerRules': self.export_vpn_server_rules,
            'AlertRules': self.export_notification_alert_rules,
            'SNMPSecurityProfiles': self.export_snmp_security_profiles,
            'SNMP': self.export_snmp_rules,
            'SNMPParameters': self.export_snmp_settings,
        }

    def run(self):
        """
        Получаем служебные структуры данных. Создаём каталог для каждого шаблона из
        данной группы шаблонов и экспортируем шаблон в этот каталог.
        """
        self.stepChanged.emit(f'BLUE|Заполняем служебные структуры данных.')
        err = self.get_library_data()
        if err:
            self.stepChanged.emit(f'iRED|Произошла ошибка инициализации экспорта! Устраните ошибки и повторите экспорт.')
            self.stepChanged.emit('RED| ')
            return
        else:
            self.stepChanged.emit(f'GREEN|Служебные структуры данных заполнены.\n')

        print('self.group_path - ', self.group_path, '\n')
        self.export_dcfw_devices()

        for item in self.export_funcs:
            if self.export_funcs[item]:
                err = self.export_funcs[item]()
                if err:
                    self.stepChanged.emit(f'RED|Экспорт группы шаблонов "{self.group_name}" прерван! Устраните ошибки и повторите экспорт.\n')
                    return
            else:
                self.stepChanged.emit(f'NOTE|Экспорт раздела "{item}" в настоящее время не реализован.')

        if self.error:
            self.stepChanged.emit(f'iORANGE|Экспорт группы шаблонов "{self.group_name}" прошёл с ошибками!\n')
        else:
            self.stepChanged.emit(f'iGREEN|Экспорт группы шаблонов "{self.group_name}" завершён.\n')


    def export_dcfw_devices(self):
        """Экспортируем устройства DCFW"""
        self.stepChanged.emit('BLUE|Экспорт устройств DCFW из раздела "DCFW/Устройства".')
        error = 0

        err, data = self.utm.get_dcfw_devices_list()
        if err:
            self.stepChanged.emit(f'RED|    {data}')
            self.stepChanged.emit(f'ORANGE|    Error: Произошла ошибка при экспорте устройств DCFW. Устройства не будут добавлены в правила.')
            self.error = 1
            return

        err, result = self.utm.get_dcfw_templates_groups()
        if err:
            self.stepChanged.emit(f'ORANGE|    Error: Произошла ошибка при экспорте устройств DCFW. Устройства не будут добавлены в правила.')
            self.error = 1
            return
        groups = {x['id']: x['name'] for x in result}

        devices_list = []
        for item in data:
            self.mc_data['devices_list'][item['id']] = item['name']
            devices_list.append({
                'name': item['name'],
                'description': item['description'],
                'enabled': item['enabled'],
                'device_templates_group': groups[item['device_templates_group']]
            })

        path = self.group_path[:self.group_path.rindex('/')]    # Убираем имя группы шаблонов из пути.
        json_file = os.path.join(path, 'config_devices_list.json')
        with open(json_file, 'w') as fh:
            json.dump(devices_list, fh, indent=4, ensure_ascii=False)

        if error:
            self.stepChanged.emit(f'ORANGE|    Произошла ошибка при экспорте устройств DCFW. Устройства DCFW выгружены в файл "{json_file}".')
            self.error = 1
        else:
            self.stepChanged.emit(f'GREEN|    Устройства DCFW выгружены в файл "{json_file}".')


    #----------------------------------------------- Библиотека --------------------------------------------------------
    def export_services(self):
        """Экспортируем список сервисов раздела библиотеки"""
        self.stepChanged.emit('BLUE|Экспорт списка сервисов из раздела "Библиотеки/Сервисы".')

        for template_id, template_name in self.templates.items():
            err, data = self.utm.get_dcfw_template_services(template_id)
            if err:
                self.stepChanged.emit(f'RED|    {data}')
                self.stepChanged.emit(f'ORANGE|    Error [Шаблон "{template_name}"]. Произошла ошибка при экспорте списка сервисов.')
                return 1

            if data:
                for item in data:
                    self.mc_data['services'][item['id']] = item['name']
                    item.pop('id')
                    item.pop('template_id')

                path = os.path.join(self.group_path, template_name, 'Libraries/Services')
                err, msg = self.create_dir(path)
                if err:
                    self.stepChanged.emit(f'RED|    {msg}')
                    return 1

                json_file = os.path.join(path, 'config_services_list.json')
                with open(json_file, 'w') as fh:
                    json.dump(data, fh, indent=4, ensure_ascii=False)
                self.stepChanged.emit(f'GREEN|    [Шаблон "{template_name}"] Список сервисов выгружен в файл "{json_file}".')
            else:
                self.stepChanged.emit(f'GRAY|    [Шаблон "{template_name}"] Нет сервисов для экспорта.')
        return 0


    def export_services_groups(self):
        """Экспортируем группы сервисов раздела библиотеки."""
        self.stepChanged.emit('BLUE|Экспорт списка групп сервисов сервисов из раздела "Библиотеки/Группы сервисов".')

        for template_id, template_name in self.templates.items():
            error = 0
            err, data = self.utm.get_dcfw_template_nlists(template_id, 'dcfw_servicegroup')
            if err:
                self.stepChanged.emit(f'RED|    {data}')
                self.stepChanged.emit(f'ORANGE|    Error [Шаблон "{template_name}"]. Произошла ошибка при экспорте групп сервисов.')
                return 1

            if data:
                for item in data:
                    self.mc_data['service_groups'][item['id']] = item['name']
                    item.pop('template_id', None)
                    item.pop('hidden_data', None)
                    item.pop('readonly', None)
                    item.pop('readonly_data', None)
                    item.pop('version', None)
                    item.pop('list_use_in_queries', None)
                    err, result = self.utm.get_dcfw_template_nlist_items(template_id, item['id'])
                    if err:
                        self.stepChanged.emit(f'RED|    {data}')
                        self.stepChanged.emit(f'ORANGE|    Error [Шаблон "{template_name}"]. Не удалось выгрузить содержимое списка "{item["name"]}".')
                        item['content'] = []
                        error = 1
                    else:
                        for content in result:
                            content.pop('id', None)
                            content.pop('value', None)
                            content.pop('template_id', None)
                        item['content'] = result
                    item.pop('id', None)

                path = os.path.join(self.group_path, template_name, 'Libraries/ServicesGroups')
                err, msg = self.create_dir(path)
                if err:
                    self.stepChanged.emit(f'RED|    {msg}')
                    return 1

                json_file = os.path.join(path, 'config_services_groups_list.json')
                with open(json_file, 'w') as fh:
                    json.dump(data, fh, indent=4, ensure_ascii=False)

                if error:
                    self.stepChanged.emit(f'ORANGE|    [Шаблон "{template_name}"] Произошла ошибка при экспорте групп сервисов. Группы сервисов выгружены в файл "{json_file}".')
                    self.error = 1
                else:
                    self.stepChanged.emit(f'GREEN|    [Шаблон "{template_name}"] Группы сервисов выгружены в файл "{json_file}".')
            else:
                self.stepChanged.emit(f'GRAY|    [Шаблон "{template_name}"] Нет групп сервисов для экспорта.')
        return 0


    def export_IP_lists(self):
        """Экспортируем списки IP-адресов и преобразует формат атрибутов списков к версии 7"""
        self.stepChanged.emit('BLUE|Экспорт списка IP-адресов из раздела "Библиотеки/IP-адреса".')

        for template_id, template_name in self.templates.items():
            error = 0
            err, data = self.utm.get_dcfw_template_nlists(template_id, 'network')
            if err:
                self.stepChanged.emit(f'RED|    {data}')
                self.stepChanged.emit(f'ORANGE|    Error [Шаблон "{template_name}"]. Произошла ошибка при экспорте списков IP-адресов.')
                return 1

            self.stepChanged.emit(f'sGREEN|    Экспорт из шаблона "{template_name}".')
            if data:
                path = os.path.join(self.group_path, template_name, 'Libraries/IPAddresses')
                err, msg = self.create_dir(path)
                if err:
                    self.stepChanged.emit(f'RED|    {msg}')
                    return 1
            else:
                self.stepChanged.emit('GRAY|       Нет списков IP-адресов для экспорта.')
                continue

            for item in data:
                self.mc_data['ip_lists'][item['id']] = item['name']
                item.pop('template_id', None)
                item.pop('hidden_data', None)
                item.pop('readonly', None)
                item.pop('readonly_data', None)
                item.pop('version', None)
                item.pop('list_use_in_queries', None)
                err, result = self.utm.get_dcfw_template_nlist_items(template_id, item['id'])
                if err:
                    self.stepChanged.emit(f'RED|       {data}')
                    self.stepChanged.emit(f'ORANGE|       Error: Не удалось выгрузить содержимое списка "{item["name"]}".')
                    item['content'] = []
                    error = 1
                else:
                    for content in result:
                        content.pop('id', None)
                        if 'list' in content:
                            content['list'] = content.pop('value', '')
                            content.pop('description', None)
                            content.pop('template_id', None)
                    item['content'] = result
                item.pop('id', None)

                file_name = item['name'].strip().translate(self.trans_filename)
                json_file = os.path.join(path, f'{file_name}.json')
                with open(json_file, 'w') as fh:
                    json.dump(item, fh, indent=4, ensure_ascii=False)
                self.stepChanged.emit(f'BLACK|       Список IP-адресов "{item["name"]}" выгружен в файл "{json_file}".')
                self.msleep(2)

            if error:
                self.stepChanged.emit(f'ORANGE|    [Шаблон "{template_name}"] Произошла ошибка при экспорте списков IP-адресов. Списки IP-адресов выгружены в каталог "{path}".')
                self.error = 1
            else:
                self.stepChanged.emit(f'GREEN|    [Шаблон "{template_name}"] Списки IP-адресов выгружены в каталог "{path}".')
        return 0


    def export_url_lists(self):
        """Экспортируем списки URL"""
        self.stepChanged.emit('BLUE|Экспорт списков URL из раздела "Библиотеки/Списки URL".')

        for template_id, template_name in self.templates.items():
            error = 0
            err, data = self.utm.get_dcfw_template_nlists(template_id, 'url')
            if err:
                self.stepChanged.emit(f'RED|    {data}')
                self.stepChanged.emit(f'ORANGE|    Error [Шаблон "{template_name}"]. Произошла ошибка при экспорте списков URL.')
                return 1

            self.stepChanged.emit(f'sGREEN|    Экспорт из шаблона "{template_name}".')
            if data:
                path = os.path.join(self.group_path, template_name, 'Libraries/URLLists')
                err, msg = self.create_dir(path)
                if err:
                    self.stepChanged.emit(f'RED|    {msg}')
                    return 1
            else:
                self.stepChanged.emit('GRAY|       Нет списков URL для экспорта.')
                continue

            for item in data:
                self.mc_data['url_lists'][item['id']] = item['name']
                item.pop('template_id', None)
                item.pop('hidden_data', None)
                item.pop('readonly', None)
                item.pop('readonly_data', None)
                item.pop('version', None)
                item.pop('list_use_in_queries', None)
                err, result = self.utm.get_dcfw_template_nlist_items(template_id, item['id'])
                if err:
                    self.stepChanged.emit(f'RED|       {data}')
                    self.stepChanged.emit(f'ORANGE|       Error: Не удалось выгрузить содержимое списка "{item["name"]}".')
                    item['content'] = []
                    error = 1
                else:
                    for content in result:
                        content.pop('id', None)
                    item['content'] = result
                item.pop('id', None)

                file_name = item['name'].strip().translate(self.trans_filename)
                json_file = os.path.join(path, f'{file_name}.json')
                with open(json_file, 'w') as fh:
                    json.dump(item, fh, indent=4, ensure_ascii=False)
                self.stepChanged.emit(f'BLACK|       Список URL "{item["name"]}" выгружен в файл "{json_file}".')
                self.msleep(2)

            if error:
                self.stepChanged.emit(f'ORANGE|    [Шаблон "{template_name}"] Произошла ошибка при экспорте списков URL. Списки URL выгружены в каталог "{path}".')
                self.error = 1
            else:
                self.stepChanged.emit(f'GREEN|    [Шаблон "{template_name}"] Списки URL выгружены в каталог "{path}".')
        return 0


    def export_time_sets(self):
        """Экспортируем содержимое календарей"""
        self.stepChanged.emit('BLUE|Экспорт списка "Календари" из раздела "Библиотеки/Календари".')

        for template_id, template_name in self.templates.items():
            error = 0
            err, data = self.utm.get_dcfw_template_nlists(template_id, 'timerestrictiongroup')
            if err:
                self.stepChanged.emit(f'RED|    {data}')
                self.stepChanged.emit(f'ORANGE|    Error [Шаблон "{template_name}"]. Произошла ошибка при экспорте списка "Календари".')
                return 1

            if data:
                for item in data:
                    self.mc_data['calendars'][item['id']] = item['name']
                    item.pop('template_id', None)
                    item.pop('hidden_data', None)
                    item.pop('readonly', None)
                    item.pop('readonly_data', None)
                    item.pop('version', None)
                    item.pop('list_use_in_queries', None)
                    err, result = self.utm.get_dcfw_template_nlist_items(template_id, item['id'])
                    if err:
                        self.stepChanged.emit(f'RED|    {data}')
                        self.stepChanged.emit(f'ORANGE|    Error [Шаблон "{template_name}"]. Не удалось выгрузить содержимое списка "{item["name"]}".')
                        item['content'] = []
                        error = 1
                    else:
                        for content in result:
                            content.pop('id', None)
                        item['content'] = result
                    item.pop('id', None)

                path = os.path.join(self.group_path, template_name, 'Libraries/TimeSets')
                err, msg = self.create_dir(path)
                if err:
                    self.stepChanged.emit(f'RED|    {msg}')
                    return 1

                json_file = os.path.join(path, 'config_calendars.json')
                with open(json_file, 'w') as fh:
                    json.dump(data, fh, indent=4, ensure_ascii=False)

                if error:
                    self.stepChanged.emit(f'ORANGE|    [Шаблон "{template_name}"] Произошла ошибка при экспорте списка "Календари". Список "Календари" выгружен в файл "{json_file}".')
                    self.error = 1
                else:
                    self.stepChanged.emit(f'GREEN|    [Шаблон "{template_name}"] Список "Календари" выгружен в файл "{json_file}".')
            else:
                self.stepChanged.emit(f'GRAY|    [Шаблон "{template_name}"] Нет типов контента для экспорта.')
        return 0


    def export_shapers(self):
        """Экспортируем список Полосы пропускания"""
        self.stepChanged.emit('BLUE|Экспорт списка "Полосы пропускания" из раздела "Библиотеки/Полосы пропускания".')

        for template_id, template_name in self.templates.items():
            err, data = self.utm.get_dcfw_template_shapers(template_id)
            if err:
                self.stepChanged.emit(f'RED|    {data}')
                self.stepChanged.emit(f'ORANGE|    Error [Шаблон "{template_name}"]. Произошла ошибка при экспорте списка "Полосы пропускания".')
                return 1

            if data:
                for item in data:
                    self.mc_data['shapers'][item['id']] = item['name']
                    item.pop('id', None)
                    item.pop('template_id', None)

                path = os.path.join(self.group_path, template_name, 'Libraries/BandwidthPools')
                err, msg = self.create_dir(path)
                if err:
                    self.stepChanged.emit(f'RED|    {msg}')
                    return 1

                json_file = os.path.join(path, 'config_shaper_list.json')
                with open(json_file, 'w') as fh:
                    json.dump(data, fh, indent=4, ensure_ascii=False)
                self.stepChanged.emit(f'GREEN|    [Шаблон "{template_name}"] Список "Полосы пропускания" выгружен в файл "{json_file}".')
            else:
                self.stepChanged.emit(f'GRAY|    [Шаблон "{template_name}"] Нет полос пропускания для экспорта.')
        return 0


    def export_templates(self):
        """
        Экспортируем список шаблонов страниц.
        Выгружает файл HTML только для изменённых страниц шаблонов.
        """
        self.stepChanged.emit('BLUE|Экспорт шаблонов страниц из раздела "Библиотеки/Шаблоны страниц".')

        for template_id, template_name in self.templates.items():
            err, data = self.utm.get_dcfw_template_responsepages(template_id)
            if err:
                self.stepChanged.emit(f'RED|    {data}')
                self.stepChanged.emit(f'ORANGE|    Error [Шаблон "{template_name}"]. Произошла ошибка при экспорте шаблонов страниц.')
                return 1

            if data:
                path = os.path.join(self.group_path, template_name, 'Libraries/ResponcePages')
                err, msg = self.create_dir(path)
                if err:
                    self.stepChanged.emit(f'RED|    {msg}')
                    return 1

                for item in data:
                    self.mc_data['response_pages'][item['id']] = item['name']

                    err, html_data = self.utm.get_dcfw_template_responsepage_data(template_id, item['id'])
                    if html_data:
                        with open(os.path.join(path, f'{item["name"]}.html'), "w") as fh:
                            fh.write(html_data)
                        self.stepChanged.emit(f'BLACK|    [Шаблон "{template_name}"] Страница HTML для шаблона "{item["name"]}" выгружена в файл "{item["name"]}.html".')

                    item.pop('id', None)
                    item.pop('template_id', None)
                    item.pop('last_update', None)

                json_file = os.path.join(path, 'config_templates_list.json')
                with open(json_file, 'w') as fh:
                    json.dump(data, fh, indent=4, ensure_ascii=False)
                self.stepChanged.emit(f'GREEN|    [Шаблон "{template_name}"] Шаблоны страниц выгружены в файл "{json_file}".')
            else:
                self.stepChanged.emit(f'GRAY|    [Шаблон "{template_name}"] Нет шаблонов страниц для экспорта.')
        return 0


    def export_url_categories(self):
        """Экспортируем категории URL"""
        self.stepChanged.emit('BLUE|Экспорт категорий URL из раздела "Библиотеки/Категории URL".')
        revert_urlcategorygroup = {v: k for k, v in default_urlcategorygroup.items()}

        for template_id, template_name in self.templates.items():
            error = 0
            err, data = self.utm.get_dcfw_template_nlists(template_id, 'urlcategorygroup')
            if err:
                self.stepChanged.emit(f'RED|    {data}')
                self.stepChanged.emit(f'ORANGE|    Error [Шаблон "{template_name}"]. Произошла ошибка при экспорте категорий URL.')
                return 1

            if data:
                for item in data:
                    self.mc_data['url_categorygroups'][item['id']] = item['name']
                    item['name'] = default_urlcategorygroup.get(item['name'], item['name'])
                    item.pop('template_id', None)
                    item.pop('hidden_data', None)
                    item.pop('readonly', None)
                    item.pop('readonly_data', None)
                    item.pop('version', None)
                    item.pop('list_use_in_queries', None)
                    err, result = self.utm.get_dcfw_template_nlist_items(template_id, item['id'])
                    if err:
                        self.stepChanged.emit(f'RED|    {data}')
                        self.stepChanged.emit(f'ORANGE|    Error [Шаблон "{template_name}"]. Не удалось выгрузить содержимое списка "{item["name"]}".')
                        item['content'] = []
                        error = 1
                    else:
                        for content in result:
                            content.pop('id', None)
                        item['content'] = result
                    item.pop('id', None)

                path = os.path.join(self.group_path, template_name, 'Libraries/URLCategories')
                err, msg = self.create_dir(path)
                if err:
                    self.stepChanged.emit(f'RED|    {msg}')
                    return 1

                json_file = os.path.join(path, 'config_url_categories.json')
                with open(json_file, 'w') as fh:
                    json.dump(data, fh, indent=4, ensure_ascii=False)

                if error:
                    self.stepChanged.emit(f'ORANGE|    [Шаблон "{template_name}"] Произошла ошибка при экспорте категорий URL. Категории URL выгружены в файл "{json_file}".')
                    self.error = 1
                else:
                    self.stepChanged.emit(f'GREEN|    [Шаблон "{template_name}"] Категории URL выгружены в файл "{json_file}".')
            else:
                self.stepChanged.emit(f'GRAY|    [Шаблон "{template_name}"] Нет категорий URL для экспорта.')
        return 0


    def export_custom_url_categories(self):
        """Экспортируем изменённые категории URL"""
        self.stepChanged.emit('BLUE|Экспорт изменённых категорий URL из раздела "Библиотеки/Изменённые категории URL".')

        for template_id, template_name in self.templates.items():
            err, data = self.utm.get_dcfw_template_custom_urls(template_id)
            if err:
                self.stepChanged.emit(f'RED|    {data}')
                self.stepChanged.emit(f'ORANGE|    Error [Шаблон "{template_name}"]. Произошла ошибка при экспорте изменённых категорий URL.')
                return 1

            if data:
                for item in data:
                    item.pop('id', None)
                    item.pop('template_id', None)
                    item.pop('default_categories', None)
                    item.pop('user', None)
                    item['change_date'] = item['change_date'].rstrip('Z').replace('T', ' ', 1)
                    for item in data:
                        item['categories'] = [self.mc_data['url_categories'][x] for x in item['categories']]

                path = os.path.join(self.group_path, template_name, 'Libraries/OverURLCategories')
                err, msg = self.create_dir(path)
                if err:
                    self.stepChanged.emit(f'RED|    {msg}')
                    return 1

                json_file = os.path.join(path, 'custom_url_categories.json')
                with open(json_file, 'w') as fh:
                    json.dump(data, fh, indent=4, ensure_ascii=False)
                self.stepChanged.emit(f'GREEN|    [Шаблон "{template_name}"] Изменённые категории URL выгружены в файл "{json_file}".')
            else:
                self.stepChanged.emit(f'GRAY|    [Шаблон "{template_name}"] Нет изменённых категорий URL для экспорта.')
        return 0


    def export_applications(self):
        """Экспортируем список пользовательских приложений"""
        self.stepChanged.emit('BLUE|Экспорт пользовательских приложений из раздела "Библиотеки/Приложения".')

        for template_id, template_name in self.templates.items():
            err, data = self.utm.get_dcfw_template_app_signatures(template_id, query={'query': 'owner = You'})
            if err:
                self.stepChanged.emit(f'iRED|{data}')
                self.stepChanged.emit(f'ORANGE|    Error [Шаблон "{template_name}"]. Произошла ошибка при экспорте пользовательских приложений.')
                return 1

            if data:
                for item in data:
                    self.mc_data['l7_apps'][item['id']] = item['name']
                    item.pop('id', None)
                    item.pop('template_id', None)
                    item.pop('attributes', None)
                    item['l7categories'] = [self.mc_data['l7_categories'][x[1]] for x in item['l7categories']]

                path = os.path.join(self.group_path, template_name, 'Libraries/Applications')
                err, msg = self.create_dir(path)
                if err:
                    self.stepChanged.emit(f'RED|    {msg}')
                    return 1

                json_file = os.path.join(path, 'config_applications.json')
                with open(json_file, 'w') as fh:
                    json.dump(data, fh, indent=4, ensure_ascii=False)
                self.stepChanged.emit(f'GREEN|    [Шаблон "{template_name}"] Пользовательские приложения выгружены в файл "{json_file}".')
            else:
                self.stepChanged.emit(f'GRAY|    [Шаблон "{template_name}"] Нет пользовательских приложений для экспорта.')
        return 0


    def export_app_profiles(self):
        """Экспортируем профили приложений"""
        self.stepChanged.emit('BLUE|Экспорт профилей приложений из раздела "Библиотеки/Профили приложений".')

        for template_id, template_name in self.templates.items():
            err, data = self.utm.get_dcfw_template_l7_profiles(template_id)
            if err:
                self.stepChanged.emit(f'RED|    {data}')
                self.stepChanged.emit(f'ORANGE|    Error [Шаблон "{template_name}"]. Произошла ошибка при экспорте профилей приложений.')
                return 1

            if data:
                for item in data:
                    self.mc_data['app_profiles'][item['id']] = item['name']
                    item.pop('id', None)
                    item.pop('template_id', None)
                    new_overrides = []
                    for app in item['overrides']:
                        try:
                            app['id'] = self.mc_data['l7_apps'][app['id']]
                            new_overrides.append(app)
                        except KeyError:
                            pass            # После обновления сигнатур некоторые могут отсутствовать.
                    item['overrides'] = new_overrides

                path = os.path.join(self.group_path, template_name, 'Libraries/ApplicationProfiles')
                err, msg = self.create_dir(path)
                if err:
                    self.stepChanged.emit(f'RED|    {msg}')
                    return 1

                json_file = os.path.join(path, 'config_app_profiles.json')
                with open(json_file, 'w') as fh:
                    json.dump(data, fh, indent=4, ensure_ascii=False)
                self.stepChanged.emit(f'GREEN|    [Шаблон "{template_name}"] Профили приложений выгружены в файл "{json_file}".')
            else:
                self.stepChanged.emit(f'GRAY|    [Шаблон "{template_name}"] Нет профилей приложений для экспорта.')
        return 0


    def export_application_groups(self):
        """Экспортируем группы приложений."""
        self.stepChanged.emit('BLUE|Экспорт групп приложений из раздела "Библиотеки/Группы приложений".')

        for template_id, template_name in self.templates.items():
            error = 0
            err, data = self.utm.get_dcfw_template_nlists(template_id, 'applicationgroup')
            if err:
                self.stepChanged.emit(f'RED|    {data}')
                self.stepChanged.emit(f'ORANGE|    Error [Шаблон "{template_name}"]. Произошла ошибка при экспорте групп приложений.')
                return 1

            if data:
                for item in data:
                    self.mc_data['app_groups'][item['id']] = item['name']
                    item.pop('template_id', None)
                    item.pop('hidden_data', None)
                    item.pop('readonly', None)
                    item.pop('readonly_data', None)
                    item.pop('version', None)
                    item.pop('list_use_in_queries', None)
                    err, result = self.utm.get_dcfw_template_nlist_items(template_id, item['id'])
                    if err:
                        self.stepChanged.emit(f'RED|    {data}')
                        self.stepChanged.emit(f'ORANGE|    Error [Шаблон "{template_name}"]. Не удалось выгрузить содержимое списка "{item["name"]}".')
                        item['content'] = []
                        error = 1
                    else:
                        for content in result:
                            content.pop('item_id', None)
                            content.pop('attributes', None)
                            content.pop('description', None)
                            try:
                                content['l7categories'] = [self.mc_data['l7_categories'][x[1]] for x in content['l7categories']]
                            except KeyError:
                                pass    # Ошибка бывает если ранее было не корректно добавлено приложение через API в версии 7.1.
                        item['content'] = result
                    item.pop('id', None)

                path = os.path.join(self.group_path, template_name, 'Libraries/ApplicationGroups')
                err, msg = self.create_dir(path)
                if err:
                    self.stepChanged.emit(f'RED|    {msg}')
                    return 1

                json_file = os.path.join(path, 'config_application_groups.json')
                with open(json_file, 'w') as fh:
                    json.dump(data, fh, indent=4, ensure_ascii=False)

                if error:
                    self.stepChanged.emit(f'ORANGE|    [Шаблон "{template_name}"] Произошла ошибка при экспорте групп приложений. Группы приложений выгружены в файл "{json_file}".')
                    self.error = 1
                else:
                    self.stepChanged.emit(f'GREEN|    [Шаблон "{template_name}"] Группы приложений выгружены в файл "{json_file}".')
            else:
                self.stepChanged.emit(f'GRAY|    [Шаблон "{template_name}"] Нет групп приложений для экспорта.')
        return 0


    def export_email_groups(self):
        """Экспортируем группы почтовых адресов."""
        self.stepChanged.emit('BLUE|Экспорт групп почтовых адресов из раздела "Библиотеки/Почтовые адреса".')

        for template_id, template_name in self.templates.items():
            error = 0
            err, data = self.utm.get_dcfw_template_nlists(template_id, 'emailgroup')
            if err:
                self.stepChanged.emit(f'RED|    {data}')
                self.stepChanged.emit(f'ORANGE|    Error [Шаблон "{template_name}"]. Произошла ошибка при экспорте групп почтовых адресов.')
                return 1

            if data:
                for item in data:
                    self.mc_data['email_groups'][item['id']] = item['name']
                    item.pop('template_id', None)
                    item.pop('hidden_data', None)
                    item.pop('readonly', None)
                    item.pop('readonly_data', None)
                    item.pop('version', None)
                    item.pop('list_use_in_queries', None)
                    err, result = self.utm.get_dcfw_template_nlist_items(template_id, item['id'])
                    if err:
                        self.stepChanged.emit(f'RED|    {data}')
                        self.stepChanged.emit(f'ORANGE|    Error [Шаблон "{template_name}"]. Не удалось выгрузить содержимое списка "{item["name"]}".')
                        item['content'] = []
                        error = 1
                    else:
                        for content in result:
                            content.pop('id', None)
                        item['content'] = result
                    item.pop('id', None)

                path = os.path.join(self.group_path, template_name, 'Libraries/Emails')
                err, msg = self.create_dir(path)
                if err:
                    self.stepChanged.emit(f'RED|    {msg}')
                    return 1

                json_file = os.path.join(path, 'config_email_groups.json')
                with open(json_file, 'w') as fh:
                    json.dump(data, fh, indent=4, ensure_ascii=False)

                if error:
                    self.stepChanged.emit(f'ORANGE|    [Шаблон "{template_name}"] Произошла ошибка при экспорте групп почтовых адресов. Группы почтовых адресов выгружены в файл "{json_file}".')
                    self.error = 1
                else:
                    self.stepChanged.emit(f'GREEN|    [Шаблон "{template_name}"] Группы почтовых адресов выгружены в файл "{json_file}".')
            else:
                self.stepChanged.emit(f'GRAY|    [Шаблон "{template_name}"] Нет групп почтовых адресов для экспорта.')
        return 0


    def export_phone_groups(self):
        """Экспортируем группы телефонных номеров."""
        self.stepChanged.emit('BLUE|Экспорт групп телефонных номеров из раздела "Библиотеки/Номера телефонов".')

        for template_id, template_name in self.templates.items():
            error = 0
            err, data = self.utm.get_dcfw_template_nlists(template_id, 'phonegroup')
            if err:
                self.stepChanged.emit(f'RED|    {data}')
                self.stepChanged.emit(f'ORANGE|    Error [Шаблон "{template_name}"]. Произошла ошибка при экспорте групп телефонных номеров.')
                return 1

            if data:
                for item in data:
                    self.mc_data['phone_groups'][item['id']] = item['name']
                    item.pop('template_id', None)
                    item.pop('hidden_data', None)
                    item.pop('readonly', None)
                    item.pop('readonly_data', None)
                    item.pop('version', None)
                    item.pop('list_use_in_queries', None)
                    err, result = self.utm.get_dcfw_template_nlist_items(template_id, item['id'])
                    if err:
                        self.stepChanged.emit(f'RED|    {data}')
                        self.stepChanged.emit(f'ORANGE|    Error [Шаблон "{template_name}"]. Не удалось выгрузить содержимое списка "{item["name"]}".')
                        item['content'] = []
                        error = 1
                    else:
                        for content in result:
                            content.pop('id', None)
                        item['content'] = result
                    item.pop('id', None)

                path = os.path.join(self.group_path, template_name, 'Libraries/Phones')
                err, msg = self.create_dir(path)
                if err:
                    self.stepChanged.emit(f'RED|    {msg}')
                    return 1

                json_file = os.path.join(path, 'config_phone_groups.json')
                with open(json_file, 'w') as fh:
                    json.dump(data, fh, indent=4, ensure_ascii=False)

                if error:
                    self.stepChanged.emit(f'ORANGE|    [Шаблон "{template_name}"] Произошла ошибка при экспорте групп телефонных номеров. Группы телефонных номеров выгружены в файл "{json_file}".')
                    self.error = 1
                else:
                    self.stepChanged.emit(f'GREEN|    [Шаблон "{template_name}"] Группы телефонных номеров выгружены в файл "{json_file}".')
            else:
                self.stepChanged.emit(f'GRAY|    [Шаблон "{template_name}"] Нет групп телефонных номеров для экспорта.')
        return 0


    def export_custom_idps_signatures(self):
        """Экспортируем пользовательские сигнатуры СОВ для версии 7.1 и выше."""
        self.stepChanged.emit('BLUE|Экспорт пользовательских сигнатур СОВ из раздела "Библиотеки/Сигнатуры СОВ".')

        for template_id, template_name in self.templates.items():
            err, data = self.utm.get_dcfw_template_idps_signatures(template_id, query={'query': 'owner = You'})
            if err:
                self.stepChanged.emit(f'RED|    {data}')
                self.stepChanged.emit(f'ORANGE|    Error [Шаблон "{template_name}"]. Произошла ошибка при экспорте пользовательских сигнатур СОВ.')
                return 1

            if data:
                for item in data:
                    item.pop('id', None)
                    item.pop('template_id', None)
                    item.pop('attributes', None)

                path = os.path.join(self.group_path, template_name, 'Libraries/IDPSSignatures')
                err, msg = self.create_dir(path)
                if err:
                    self.stepChanged.emit(f'RED|    {msg}')
                    return 1

                json_file = os.path.join(path, 'custom_idps_signatures.json')
                with open(json_file, 'w') as fh:
                    json.dump(data, fh, indent=4, ensure_ascii=False)
                self.stepChanged.emit(f'GREEN|    [Шаблон "{template_name}"] Пользовательские сигнатуры СОВ выгружены в файл "{json_file}".')
            else:
                self.stepChanged.emit(f'GRAY|    [Шаблон "{template_name}"] Нет пользовательских сигнатур СОВ для экспорта.')
        return 0


    def export_idps_profiles(self):
        """Экспортируем список профилей СОВ"""
        self.stepChanged.emit('BLUE|Экспорт профилей СОВ из раздела "Библиотеки/Профили СОВ".')

        for template_id, template_name in self.templates.items():
            error = 0
            err, data = self.utm.get_dcfw_template_idps_profiles(template_id)
            if err:
                self.stepChanged.emit(f'RED|    {data}')
                self.stepChanged.emit(f'ORANGE|    Error [Шаблон "{template_name}"]. Произошла ошибка при экспорте профилей СОВ.')
                return 1

            if data:
                for item in data:
                    self.mc_data['idps_profiles'][item['id']] = item['name']
                    item.pop('id', None)
                    item.pop('template_id', None)
                    for app in item['overrides']:
                        err, result = self.utm.fetch_dcfw_template_idps_signature(template_id, app['id'])
                        if err:
                            self.stepChanged.emit(f'RED|    {result}')
                            error = 1
                        else:
                            app['signature_id'] = result['signature_id']
                            app['msg'] = result['msg']
                        app.pop('id', None)

                path = os.path.join(self.group_path, template_name, 'Libraries/IDPSProfiles')
                err, msg = self.create_dir(path)
                if err:
                    self.stepChanged.emit(f'RED|    {msg}')
                    return 1

                json_file = os.path.join(path, 'config_idps_profiles.json')
                with open(json_file, 'w') as fh:
                    json.dump(data, fh, indent=4, ensure_ascii=False)

                if error:
                    self.stepChanged.emit(f'ORANGE|    [Шаблон "{template_name}"] Произошла ошибка при экспорте профилей СОВ. Список профилей СОВ выгружен в файл "{json_file}".')
                    self.error = 1
                else:
                    self.stepChanged.emit(f'GREEN|    [Шаблон "{template_name}"] Список профилей СОВ выгружен в файл "{json_file}".')
            else:
                self.stepChanged.emit(f'GRAY|    [Шаблон "{template_name}"] Нет профилей СОВ для экспорта.')
        return 0


    def export_notification_profiles(self):
        """Экспортируем список профилей оповещения"""
        self.stepChanged.emit('BLUE|Экспорт профилей оповещений из раздела "Библиотеки/Профили оповещений".')

        for template_id, template_name in self.templates.items():
            err, data = self.utm.get_dcfw_template_notification_profiles(template_id)
            if err:
                self.stepChanged.emit(f'RED|    {data}')
                self.stepChanged.emit(f'ORANGE|    Error [Шаблон "{template_name}"]. Произошла ошибка при экспорте профилей оповещений.')
                return 1

            if data:
                for item in data:
                    self.mc_data['notification_profiles'][item['id']] = item['name']
                    item.pop('id', None)
                    item.pop('template_id', None)
                    item.pop('cc', None)

                path = os.path.join(self.group_path, template_name, 'Libraries/NotificationProfiles')
                err, msg = self.create_dir(path)
                if err:
                    self.stepChanged.emit(f'RED|    {msg}')
                    return 1

                json_file = os.path.join(path, 'config_notification_profiles.json')
                with open(json_file, 'w') as fh:
                    json.dump(data, fh, indent=4, ensure_ascii=False)
                self.stepChanged.emit(f'GREEN|    [Шаблон "{template_name}"] Профили оповещений выгружены в файл "{json_file}".')
            else:
                self.stepChanged.emit(f'GRAY|    [Шаблон "{template_name}"] Нет профилей оповещений для экспорта.')
        return 0


    def export_netflow_profiles(self):
        """Экспортируем список профилей netflow"""
        self.stepChanged.emit('BLUE|Экспорт профилей netflow из раздела "Библиотеки/Профили netflow".')

        for template_id, template_name in self.templates.items():
            err, data = self.utm.get_dcfw_template_netflow_profiles(template_id)
            if err:
                self.stepChanged.emit(f'RED|    {data}')
                self.stepChanged.emit(f'ORANGE|    Error [Шаблон "{template_name}"]. Произошла ошибка при экспорте профилей netflow.')
                return 1

            if data:
                for item in data:
                    self.mc_data['netflow_profiles'][item['id']] = item['name']
                    item.pop('id', None)
                    item.pop('template_id', None)
                    item.pop('cc', None)

                path = os.path.join(self.group_path, template_name, 'Libraries/NetflowProfiles')
                err, msg = self.create_dir(path)
                if err:
                    self.stepChanged.emit(f'RED|    {msg}')
                    return 1

                json_file = os.path.join(path, 'config_netflow_profiles.json')
                with open(json_file, 'w') as fh:
                    json.dump(data, fh, indent=4, ensure_ascii=False)
                self.stepChanged.emit(f'GREEN|    [Шаблон "{template_name}"] Профили netflow выгружены в файл "{json_file}".')
            else:
                self.stepChanged.emit(f'GRAY|    [Шаблон "{template_name}"] Нет профилей netflow для экспорта.')
        return 0


    def export_lldp_profiles(self):
        """Экспортируем список профилей LLDP"""
        self.stepChanged.emit('BLUE|Экспорт профилей LLDP из раздела "Библиотеки/Профили LLDP".')

        for template_id, template_name in self.templates.items():
            err, data = self.utm.get_dcfw_template_lldp_profiles(template_id)
            if err:
                self.stepChanged.emit(f'RED|    {data}')
                self.stepChanged.emit(f'ORANGE|    Error [Шаблон "{template_name}"]. Произошла ошибка при экспорте профилей LLDP.')
                return 1

            if data:
                for item in data:
                    self.mc_data['lldp_profiles'][item['id']] = item['name']
                    item.pop('id', None)
                    item.pop('template_id', None)
                    item.pop('cc', None)

                path = os.path.join(self.group_path, template_name, 'Libraries/LLDPProfiles')
                err, msg = self.create_dir(path)
                if err:
                    self.stepChanged.emit(f'RED|    {msg}')
                    return 1

                json_file = os.path.join(path, 'config_lldp_profiles.json')
                with open(json_file, 'w') as fh:
                    json.dump(data, fh, indent=4, ensure_ascii=False)
                self.stepChanged.emit(f'GREEN|    [Шаблон "{template_name}"] Профили LLDP выгружены в файл "{json_file}".')
            else:
                self.stepChanged.emit(f'GRAY|    [Шаблон "{template_name}"] Нет профилей LLDP для экспорта.')
        return 0


    def export_ssl_profiles(self):
        """Экспортируем список профилей SSL"""
        self.stepChanged.emit('BLUE|Экспорт профилей SSL из раздела "Библиотеки/Профили SSL".')

        for template_id, template_name in self.templates.items():
            err, data = self.utm.get_dcfw_template_ssl_profiles(template_id)
            if err:
                self.stepChanged.emit(f'RED|    {data}')
                self.stepChanged.emit(f'ORANGE|    Error [Шаблон "{template_name}"]. Произошла ошибка при экспорте профилей SSL.')
                return 1

            if data:
                for item in data:
                    self.mc_data['ssl_profiles'][item['id']] = item['name']
                    item.pop('id', None)
                    item.pop('template_id', None)
                    item.pop('cc', None)

                path = os.path.join(self.group_path, template_name, 'Libraries/SSLProfiles')
                err, msg = self.create_dir(path)
                if err:
                    self.stepChanged.emit(f'RED|    {msg}')
                    return 1

                json_file = os.path.join(path, 'config_ssl_profiles.json')
                with open(json_file, 'w') as fh:
                    json.dump(data, fh, indent=4, ensure_ascii=False)
                self.stepChanged.emit(f'GREEN|    [Шаблон "{template_name}"] Профили SSL выгружены в файл "{json_file}".')
            else:
                self.stepChanged.emit(f'GRAY|    [Шаблон "{template_name}"] Нет профилей SSL для экспорта.')
        return 0


    def export_ssl_forward_profiles(self):
        """Экспортируем профили пересылки SSL"""
        self.stepChanged.emit('BLUE|Экспорт профилей пересылки SSL из раздела "Библиотеки/Профили пересылки SSL".')

        for template_id, template_name in self.templates.items():
            err, data = self.utm.get_dcfw_template_ssl_forward_profiles(template_id)
            if err:
                self.stepChanged.emit(f'RED|    {data}')
                self.stepChanged.emit(f'ORANGE|    Error [Шаблон "{template_name}"]. Произошла ошибка при экспорте профилей пересылки SSL.')
                return 1

            if data:
                for item in data:
                    self.mc_data['ssl_forward_profiles'][item['id']] = item['name']
                    item.pop('id', None)
                    item.pop('template_id', None)
                    item.pop('cc', None)

                path = os.path.join(self.group_path, template_name, 'Libraries/SSLForwardingProfiles')
                err, msg = self.create_dir(path)
                if err:
                    self.stepChanged.emit(f'RED|    {msg}')
                    return 1

                json_file = os.path.join(path, 'config_ssl_forward_profiles.json')
                with open(json_file, 'w') as fh:
                    json.dump(data, fh, indent=4, ensure_ascii=False)
                self.stepChanged.emit(f'GREEN|    [Шаблон "{template_name}"] Профили пересылки SSL выгружены в файл "{json_file}".')
            else:
                self.stepChanged.emit(f'GRAY|    [Шаблон "{template_name}"] Нет профилей пересылки SSL для экспорта.')
        return 0


    def export_bfd_profiles(self):
        """Экспортируем профили BFD"""
        self.stepChanged.emit('BLUE|Экспорт профилей BFD из раздела "Библиотеки/Профили BFD".')

        for template_id, template_name in self.templates.items():
            err, data = self.utm.get_dcfw_template_bfd_profiles(template_id)
            if err:
                self.stepChanged.emit(f'RED|    {data}')
                self.stepChanged.emit(f'ORANGE|    Error [Шаблон "{template_name}"]. Произошла ошибка при экспорте профилей BFD.')
                return 1

            if data:
                for item in data:
                    self.mc_data['bfd_profiles'][item['id']] = item['name']
                    item.pop('id', None)
                    item.pop('template_id', None)

                path = os.path.join(self.group_path, template_name, 'Libraries/BfdProfiles')
                err, msg = self.create_dir(path)
                if err:
                    self.stepChanged.emit(f'RED|    {msg}')
                    return 1

                json_file = os.path.join(path, 'config_bfd_profiles.json')
                with open(json_file, 'w') as fh:
                    json.dump(data, fh, indent=4, ensure_ascii=False)
                self.stepChanged.emit(f'GREEN|    [Шаблон "{template_name}"] Профили BFD выгружены в файл "{json_file}".')
            else:
                self.stepChanged.emit(f'GRAY|    [Шаблон "{template_name}"] Нет профилей BFD для экспорта.')
        return 0


    def export_useridagent_syslog_filters(self):
        """Экспортируем syslog фильтры UserID агента"""
        self.stepChanged.emit('BLUE|Экспорт syslog фильтров UserID агента из раздела "Библиотеки/Syslog фильтры UserID агента".')

        for template_id, template_name in self.templates.items():
            err, data = self.utm.get_dcfw_template_useridagent_filters(template_id)
            if err:
                self.stepChanged.emit(f'RED|    {data}')
                self.stepChanged.emit(f'ORANGE|    Error [Шаблон "{template_name}"]. Произошла ошибка при экспорте syslog фильтров UserID агента.')
                return 1

            if data:
                for item in data:
                    self.mc_data['userid_filters'][item['id']] = item['name']
                    item.pop('id', None)
                    item.pop('template_id', None)

                path = os.path.join(self.group_path, template_name, 'Libraries/UserIdAgentSyslogFilters')
                err, msg = self.create_dir(path)
                if err:
                    self.stepChanged.emit(f'RED|    {msg}')
                    return 1

                json_file = os.path.join(path, 'config_useridagent_syslog_filters.json')
                with open(json_file, 'w') as fh:
                    json.dump(data, fh, indent=4, ensure_ascii=False)
                self.stepChanged.emit(f'GREEN|    [Шаблон "{template_name}"] Syslog фильтры UserID агента выгружены в файл "{json_file}".')
            else:
                self.stepChanged.emit(f'GRAY|    [Шаблон "{template_name}"] Нет профилей syslog фильтров UserID агента для экспорта.')
        return 0


    #-------------------------------------------------- Network -------------------------------------------------------
    def export_zones(self):
        """Экспортируем список зон."""
        self.stepChanged.emit('BLUE|Экспорт настроек раздела "Сеть/Зоны".')
        service_ids = {
            'ffffff03-ffff-ffff-ffff-ffffff000001': 'Ping',
            'ffffff03-ffff-ffff-ffff-ffffff000002': 'SNMP',
            'ffffff03-ffff-ffff-ffff-ffffff000004': 'Captive-портал и страница блокировки',
            'ffffff03-ffff-ffff-ffff-ffffff000005': 'XML-RPC для управления',
            'ffffff03-ffff-ffff-ffff-ffffff000006': 'Кластер',
            'ffffff03-ffff-ffff-ffff-ffffff000007': 'VRRP',
            'ffffff03-ffff-ffff-ffff-ffffff000008': 'Консоль администрирования',
            'ffffff03-ffff-ffff-ffff-ffffff000009': 'DNS',
            'ffffff03-ffff-ffff-ffff-ffffff000010': 'HTTP(S)-прокси',
            'ffffff03-ffff-ffff-ffff-ffffff000011': 'Агент аутентификации',
            'ffffff03-ffff-ffff-ffff-ffffff000012': 'SMTP(S)-прокси',
            'ffffff03-ffff-ffff-ffff-ffffff000013': 'POP(S)-прокси',
            'ffffff03-ffff-ffff-ffff-ffffff000014': 'CLI по SSH',
            'ffffff03-ffff-ffff-ffff-ffffff000015': 'VPN',
            'ffffff03-ffff-ffff-ffff-ffffff000017': 'SCADA',
            'ffffff03-ffff-ffff-ffff-ffffff000018': 'Reverse-прокси',
            'ffffff03-ffff-ffff-ffff-ffffff000019': 'Веб-портал',
            'ffffff03-ffff-ffff-ffff-ffffff000022': 'SAML сервер',
            'ffffff03-ffff-ffff-ffff-ffffff000023': 'Log analyzer',
            'ffffff03-ffff-ffff-ffff-ffffff000024': 'OSPF',
            'ffffff03-ffff-ffff-ffff-ffffff000025': 'BGP',
            'ffffff03-ffff-ffff-ffff-ffffff000030': 'RIP',
            'ffffff03-ffff-ffff-ffff-ffffff000026': 'SNMP-прокси',
            'ffffff03-ffff-ffff-ffff-ffffff000027': 'SSH-прокси',
            'ffffff03-ffff-ffff-ffff-ffffff000028': 'Multicast',
            'ffffff03-ffff-ffff-ffff-ffffff000029': 'NTP сервис',
            'ffffff03-ffff-ffff-ffff-ffffff000031': 'UserID syslog collector',
            'ffffff03-ffff-ffff-ffff-ffffff000032': 'BFD',
            'ffffff03-ffff-ffff-ffff-ffffff000033': 'Endpoints connect'
        }

        for template_id, template_name in self.templates.items():
            error = 0
            err, data = self.utm.get_dcfw_template_zones(template_id)
            if err:
                self.stepChanged.emit(f'RED|    {data}')
                self.stepChanged.emit(f'ORANGE|    Error [Шаблон "{template_name}"]. Произошла ошибка при экспорте зон.')
                return 1

            if data:
                for zone in data:
                    self.mc_data['zones'][zone['id']] = zone['name']
                    zone.pop('id', None)
                    zone.pop('template_id', None)
                    zone.pop('cc', None)

                    new_networks = []
                    for net in zone['networks']:
                        if net[0] == 'list_id':
                            try:
                                net[1] = self.mc_data['ip_lists'][net[1]]
                                new_networks.append(net)
                            except KeyError as err:
                                self.stepChanged.emit(f'RED|    Error [Зона "{zone["name"]}"]. В этой группе шаблонов не найден IP-лист с ID "{err}" в защите от IP-спуфинга.')
                                zone['description'] = f'{zone["description"]}\nError: Не найден IP-лист с ID "{err}" в защите от IP-спуфинга.'
                                error = 1
                        else:
                            new_networks.append(net)

                    new_sessions_limit_exclusions = []
                    for item in zone['sessions_limit_exclusions']:
                        try:
                            item[1] = self.mc_data['ip_lists'][item[1]]
                            new_sessions_limit_exclusions.append(item)
                        except KeyError as err:
                            self.stepChanged.emit(f'RED|    Error [Зона "{zone["name"]}"]. В этой группе шаблонов не найден IP-лист с ID "{err}" в ограничении сессий.')
                            zone['description'] = f'{zone["description"]}\nError: Не найден IP-лист с ID "{err}" в ограничении сессий.'
                            error = 1

                    new_services_access = []
                    for service in zone['services_access']:
                        try:
                            service['service_id'] = service_ids[service['service_id']]
                        except KeyError as err:
                            self.stepChanged.emit(f'RED|    Error [Зона "{zone["name"]}"]. Не экспортирован сервис с ID "{err}" в контроль доступа.')
                            zone['description'] = f'{zone["description"]}\nError: Не экспортирован сервис с ID "{err}" в контроль доступа.'
                            error = 1
                            continue

                        new_allowed_ips = []
                        for item in service['allowed_ips']:
                            if item[0] == 'list_id':
                                try:
                                    item[1] = self.mc_data['ip_lists'][item[1]]
                                    new_allowed_ips.append(item)
                                except KeyError as err:
                                    self.stepChanged.emit(f'RED|    Error [Зона "{zone["name"]}"]. В этой группе шаблонов не найден IP-лист с ID "{err}" в контроле доступа "{service["service_id"]}".')
                                    zone['description'] = f'{zone["description"]}\nError: Не найден IP-лист с ID "{err}" в контроле доступа "{service["service_id"]}".'
                                    error = 1
                            else:
                                new_allowed_ips.append(item)
                        service['allowed_ips'] = new_allowed_ips

                        new_services_access.append(service)
                    zone['services_access'] = new_services_access

                zones_path = os.path.join(self.group_path, template_name, 'Network/Zones')
                err, msg = self.create_dir(zones_path)
                if err:
                    self.stepChanged.emit(f'RED|    {msg}')
                    self.stepChanged.emit(f'ORANGE|    Error [Шаблон "{template_name}"]. Произошла ошибка при экспорте зон.')
                    return 1

                json_file = os.path.join(zones_path, 'config_zones.json')
                with open(json_file, 'w') as fh:
                    json.dump(data, fh, indent=4, ensure_ascii=False)

                if error:
                    self.stepChanged.emit(f'ORANGE|    [Шаблон "{template_name}"] Произошла ошибка при экспорте зон. Настройки зон выгружены в файл "{json_file}".')
                    self.error = 1
                else:
                    self.stepChanged.emit(f'GREEN|    [Шаблон "{template_name}"] Настройки зон выгружены в файл "{json_file}".')
            else:
                self.stepChanged.emit(f'GRAY|    [Шаблон "{template_name}"] Нет зон для экспорта.')
        return 0


    def export_interfaces(self):
        """Экспортируем список интерфейсов"""
        self.stepChanged.emit('BLUE|Экспорт интерфейсов из раздела "Сеть/Интерфейсы".')

        for template_id, template_name in self.templates.items():
            error = 0
            err, data = self.utm.get_dcfw_template_interfaces(template_id)
            if err:
                self.stepChanged.emit(f'RED|    {data}')
                self.stepChanged.emit(f'ORANGE|    Error [Шаблон "{template_name}"]. Произошла ошибка при экспорте интерфейсов.')
                return 1

            if data:
                for item in data:
                    item['id'], _ = item['id'].split(':')
                    item.pop('template_id', None)
                    item.pop('_cc_node_name', None)

                    if item['zone_id']:
                        try:
                            item['zone_id'] = self.mc_data['zones'][item['zone_id']]
                        except KeyError:
                            self.stepChanged.emit(f'RED|    Error [Шаблон "{template_name}"]. В этой группе шаблонов не найдена зона для интерфейса "{item["name"]}".')
                            item['description'] = f'{item["description"]}\nError: Не найдена зона.'
                            error = 1
                    try:
                        item['netflow_profile'] = self.mc_data['netflow_profiles'][item['netflow_profile']]
                    except KeyError:
                        self.stepChanged.emit(f'RED|    Error [Шаблон "{template_name}"]. В этой группе шаблонов не найден netflow profile для интерфейса "{item["name"]}".')
                        item['description'] = f'{item["description"]}\nError: Не найден netflow profile.'
                        item['netflow_profile'] = 'undefined'
                        error = 1
                    try:
                        item['lldp_profile'] = self.mc_data['lldp_profiles'][item['lldp_profile']]
                    except KeyError:
                        self.stepChanged.emit(f'RED|    Error [Шаблон "{template_name}"]. В этой группе шаблонов не найден LLDP profile для интерфейса "{item["name"]}".')
                        item['description'] = f'{item["description"]}\nError: Не найден LLDP profile.'
                        item['lldp_profile'] = 'undefined'
                        error = 1

                    new_ipv4 = []
                    for ips in item['ipv4']:
                        err, result = self.pack_ip_address(ips['ip'], ips['mask'])
                        if err:
                            self.stepChanged.emit(f'RED|    Error [Шаблон "{template_name}"]. Не удалось преобразовать IP: "{ips}" для интерфейса "{item["name"]}".')
                            item['description'] = f'{item["description"]}\nError: Не удалось преобразовать IP: "{ips}".'
                            error = 1
                        else:
                            new_ipv4.append(result)
                    item['ipv4'] = new_ipv4

                data.sort(key=lambda x: x['name'])

                ifaces_path = os.path.join(self.group_path, template_name, 'Network/Interfaces')
                err, msg = self.create_dir(ifaces_path)
                if err:
                    self.stepChanged.emit(f'RED|    {msg}')
                    self.stepChanged.emit(f'ORANGE|    Error: Произошла ошибка при экспорте интерфейсов.')
                    return 1

                json_file = os.path.join(ifaces_path, 'config_interfaces.json')
                with open(json_file, 'w') as fh:
                    json.dump(data, fh, indent=4, ensure_ascii=False)

                if error:
                    self.stepChanged.emit(f'ORANGE|    [Шаблон "{template_name}"] Произошла ошибка при экспорте интерфейсов. Настройки интерфейсов выгружены в файл "{json_file}".')
                    self.error = 1
                else:
                    self.stepChanged.emit(f'GREEN|    [Шаблон "{template_name}"] Настройки интерфейсов выгружены в файл "{json_file}".')
            else:
                self.stepChanged.emit(f'GRAY|    [Шаблон "{template_name}"] Нет интерфейсов для экспорта.')
        return 0


    def export_gateways_list(self):
        """Экспортируем список шлюзов"""
        self.stepChanged.emit('BLUE|Экспорт раздела "Сеть/Шлюзы".')

        for template_id, template_name in self.templates.items():
            gateways_path = os.path.join(self.group_path, template_name, 'Network/Gateways')
            err, msg = self.create_dir(gateways_path)
            if err:
                self.stepChanged.emit(f'RED|    {msg}')
                self.stepChanged.emit(f'ORANGE|    Error [Шаблон "{template_name}"]. Произошла ошибка при экспорте шлюзов.')
                return 1

            err, data = self.utm.get_dcfw_template_gateways(template_id)
            if err:
                self.stepChanged.emit(f'RED|    {data}')
                self.stepChanged.emit(f'ORANGE|    Error [Шаблон "{template_name}"]. Произошла ошибка при экспорте шлюзов.')
                return 1

            if data:
                for item in data:
                    self.mc_data['gateways'][item['id']] = item['name']
                    item.pop('id', None)
                    item.pop('template_id', None)
                    item.pop('_cc_node_name', None)
                    if not item.get('name', False):
                        item['name'] = item['ipv4']
 
                json_file = os.path.join(gateways_path, 'config_gateways.json')
                with open(json_file, 'w') as fh:
                    json.dump(data, fh, indent=4, ensure_ascii=False)
                self.stepChanged.emit(f'BLACK|    [Шаблон "{template_name}"] Настройки шлюзов выгружены в файл "{json_file}".')
            else:
                self.stepChanged.emit(f'GRAY|    [Шаблон "{template_name}"] Нет шлюзов для экспорта.')

            """Экспортируем настройки проверки сети шлюзов"""
            err, data = self.utm.get_dcfw_template_gateway_failover(template_id)
            if err:
                self.stepChanged.emit(f'RED|    {data}')
                self.stepChanged.emit(f'ORANGE|    Error [Шаблон "{template_name}"]. Произошла ошибка при экспорте настроек проверки сети.')
                return 1
            else:
                data.pop('cc_enabled', None)
                json_file = os.path.join(gateways_path, 'config_gateway_failover.json')
                with open(json_file, 'w') as fh:
                    json.dump(data, fh, indent=4, ensure_ascii=False)
                self.stepChanged.emit(f'BLACK|    [Шаблон "{template_name}"] Настройки "Проверка сети" выгружены в файл "{json_file}".')

        self.stepChanged.emit('GREEN|    Экспорт раздела "Сеть/Шлюзы" завершён.')
        return 0


    def export_dhcp_subnets(self):
        """Экспортируем настройки DHCP"""
        self.stepChanged.emit('BLUE|Экспорт настроек DHCP раздела "Сеть/DHCP".')

        for template_id, template_name in self.templates.items():
            err, data = self.utm.get_dcfw_template_dhcp_list(template_id)
            if err:
                self.stepChanged.emit(f'RED|    {data}')
                self.stepChanged.emit(f'ORANGE|    Error [Шаблон "{template_name}"]. Произошла ошибка при экспорте настроек DHCP.')
                return 1

            if data:
                for item in data:
                    item.pop('id', None)
                    item.pop('template_id', None)
                    item.pop('_cc_node_name', None)

                path = os.path.join(self.group_path, template_name, 'Network/DHCP')
                err, msg = self.create_dir(path)
                if err:
                    self.stepChanged.emit(f'RED|    {msg}')
                    self.stepChanged.emit(f'ORANGE|    Error: Произошла ошибка при экспорте настроек DHCP.')
                    return 1

                json_file = os.path.join(path, 'config_dhcp_subnets.json')
                with open(json_file, 'w') as fh:
                    json.dump(data, fh, indent=4, ensure_ascii=False)
                self.stepChanged.emit(f'GREEN|    [Шаблон "{template_name}"] Настройки DHCP выгружены в файл "{json_file}".')
            else:
                self.stepChanged.emit(f'GRAY|    [Шаблон "{template_name}"] Нет настроек DHCP для экспорта.')
        return 0


    def export_dns_config(self):
        """Экспортируем настройки DNS"""
        self.stepChanged.emit('BLUE|Экспорт настройек DNS раздела "Сеть/DNS".')

        for template_id, template_name in self.templates.items():
            dns_path = os.path.join(self.group_path, template_name, 'Network/DNS')
            err, msg = self.create_dir(dns_path)
            if err:
                self.stepChanged.emit(f'RED|    {msg}')
                self.stepChanged.emit(f'ORANGE|    Error [Шаблон "{template_name}"]. Произошла ошибка при экспорте настроек DNS.')
                return 1

            self.stepChanged.emit(f'sGREEN|    Экспорт из шаблона "{template_name}"].')

            # Экспорт настроек DNS-прокси.
            err, result = self.utm.get_dcfw_template_dns_settings(template_id)
            if err:
                self.stepChanged.emit(f'RED|       {result}')
                self.stepChanged.emit(f'ORANGE|       Error: Произошла ошибка при экспорте настроек DNS-прокси.')
                return 1
            else:
                params = {}
                for item in result:
                    params[item['code']] = item['value']

                json_file = os.path.join(dns_path, 'config_dns_proxy.json')
                with open(json_file, 'w') as fh:
                    json.dump(params, fh, indent=4, ensure_ascii=False)
                self.stepChanged.emit(f'BLACK|       Настройки DNS-прокси выгружены в файл "{json_file}".')

            # Экспорт системных DNS-серверов.
            err, result = self.utm.get_dcfw_template_dns_servers(template_id)
            if err:
                self.stepChanged.emit(f'RED|       {result}')
                self.stepChanged.emit(f'ORANGE|       Error: Произошла ошибка при экспорте системных DNS-серверов.')
                return 1
            else:
                json_file = os.path.join(dns_path, 'config_dns_servers.json')
                with open(json_file, 'w') as fh:
                    json.dump(result, fh, indent=4, ensure_ascii=False)
                self.stepChanged.emit(f'BLACK|       Список системных DNS серверов выгружен в файл "{json_file}".')
    
            # Экспорт правил DNS прокси.
            err, result = self.utm.get_dcfw_template_dns_rules(template_id)
            if err:
                self.stepChanged.emit(f'RED|       {result}')
                self.stepChanged.emit(f'ORANGE|       Error: Произошла ошибка при экспорте правил DNS прокси шаблона.')
                return 1
            else:
                for item in result:
                    item.pop('id', None)
                    item.pop('template_id', None)
                    item.pop('grid_position', None)
                json_file = os.path.join(dns_path, 'config_dns_rules.json')
                with open(json_file, 'w') as fh:
                    json.dump(result, fh, indent=4, ensure_ascii=False)
                self.stepChanged.emit(f'BLACK|       Список правил DNS прокси выгружен в файл "{json_file}".')
    
            # Экспорт статических записей DNS.
            err, result = self.utm.get_dcfw_template_dns_static_records(template_id)
            if err:
                self.stepChanged.emit(f'RED|       {result}')
                self.stepChanged.emit(f'ORANGE|       Error: Произошла ошибка при экспорте статических записей DNS шаблона.')
                return 1
            else:
                for item in result:
                    item.pop('id', None)
                    item.pop('template_id', None)
                json_file = os.path.join(dns_path, 'config_dns_static.json')
                with open(json_file, 'w') as fh:
                    json.dump(result, fh, indent=4, ensure_ascii=False)
                self.stepChanged.emit(f'BLACK|       Статические записи DNS прокси выгружены в файл "{json_file}".')

            self.stepChanged.emit(f'GREEN|    [Шаблон "{template_name}"] Настройки DNS экспортированы в каталог "{dns_path}".')
        return 0


    def export_vrf_list(self):
        """Экспортируем настройки VRF"""
        self.stepChanged.emit('BLUE|Экспорт настроек VRF раздела "Сеть/Виртуальные маршрутизаторы".')

        for template_id, template_name in self.templates.items():
            error = 0
            err, data = self.utm.get_dcfw_template_vrfs(template_id)
            if err:
                self.stepChanged.emit(f'RED|    {data}')
                self.stepChanged.emit(f'ORANGE|    Error [Шаблон "{template_name}"]. Произошла ошибка при экспорте настроек VRF.')
                return 1

            if data:
                for item in data:
                    item.pop('id', None)
                    item.pop('template_id', None)
                    item.pop('_cc_node_name', None)

                    for x in item['routes']:
                        x.pop('id', None)
                    route_maps = {}
                    filters = {}
                    item['bgp'].pop('id', None)
                    if item['bgp']['as_number'] == "null":
                        item['bgp']['as_number'] = 0
                    for x in item['bgp']['routemaps']:
                        route_maps[x['id']] = x['name']
                        x.pop('id', None)
                    for x in item['bgp']['filters']:
                        filters[x['id']] = x['name']
                        x.pop('id', None)
                    for x in item['bgp']['neighbors']:
                        x.pop('id', None)
                        x['remote_asn'] = int(x['remote_asn'])
                        for i, rmap in enumerate(x['filter_in']):
                            x['filter_in'][i] = filters[rmap]
                        for i, rmap in enumerate(x['filter_out']):
                            x['filter_out'][i] = filters[rmap]
                        for i, rmap in enumerate(x['routemap_in']):
                            x['routemap_in'][i] = route_maps[rmap]
                        for i, rmap in enumerate(x['routemap_out']):
                            x['routemap_out'][i] = route_maps[rmap]
                        try:
                            x['bfd_profile'] = self.mc_data['bfd_profiles'][x['bfd_profile']]
                        except KeyError:
                            self.stepChanged.emit(f'RED|    [Шаблон "{template_name}"]. Не найден профиль BFD для BGP в VRF "{item["name"]}" в данной группе шаблонов.')
                            x['bfd_profile'] = -1
                            error = 1
                    item['ospf'].pop('id', None)
                    for x in item['ospf']['interfaces']:
                        try:
                            x['bfd_profile'] = self.mc_data['bfd_profiles'][x['bfd_profile']]
                        except KeyError:
                            self.stepChanged.emit(f'RED|    [Шаблон "{template_name}"]. Не найден профиль BFD для OSPF в VRF "{item["name"]}" в данной группе шаблонов.')
                            x['bfd_profile'] = -1
                            error = 1
                    for x in item['ospf']['areas']:
                        x.pop('id', None)
                    item['rip'].pop('id', None)
                    if not isinstance(item['rip']['default_originate'], bool):
                        item['rip']['default_originate'] = True
                    item['pimsm'].pop('id', None)

                path = os.path.join(self.group_path, template_name, 'Network/VRF')
                err, msg = self.create_dir(path)
                if err:
                    self.stepChanged.emit(f'RED|    {msg}')
                    self.stepChanged.emit(f'ORANGE|    Error [Шаблон "{template_name}"]. Произошла ошибка при экспорте настроек VRF.')
                    return 1

                json_file = os.path.join(path, 'config_vrf.json')
                with open(json_file, 'w') as fh:
                    json.dump(data, fh, indent=4, ensure_ascii=False)

                if error:
                    self.stepChanged.emit(f'ORANGE|    [Шаблон "{template_name}"] Произошла ошибка при экспорте настроек VRF.')
                    self.error = 1
                else:
                    self.stepChanged.emit(f'GREEN|    [Шаблон "{template_name}"] Настройки VRF выгружены в файл "{json_file}".')
            else:
                self.stepChanged.emit(f'GRAY|    [Шаблон "{template_name}"] Нет VRF для экспорта.')
        return 0


    #------------------------------------------- Экспорт сертификатов ------------------------------------------------------
    def export_certificates(self):
        """Экспортируем сертификаты."""
        self.stepChanged.emit('BLUE|Экспорт настроек раздела "UserGate/Сертификаты".')

        for template_id, template_name in self.templates.items():
            self.stepChanged.emit(f'sGREEN|    Экспорт из шаблона "{template_name}".')
            certs_path = os.path.join(self.group_path, template_name, 'UserGate/Certificates')
            error = 0

            err, result = self.utm.get_dcfw_template_certificates(template_id)
            if err:
                self.stepChanged.emit(f'RED|       {result}')
                self.stepChanged.emit(f'ORANGE|       Error [Шаблон "{template_name}"]. Произошла ошибка при экспорте сертификатов.')
                return 1

            if result:
                for item in result:
                    self.stepChanged.emit(f'BLACK|       Экспорт сертификата {item["name"]}.')
                    self.mc_data['certs'][item['id']] = item['name']
                    item.pop('cc', None)
                    if isinstance(item['not_before'], class_DateTime):
                        try:
                            item['not_before'] = dt.strptime(item['not_before'].value, "%Y-%m-%dT%H:%M:%SZ").strftime("%Y-%m-%d %H:%M:%S")
                        except Exception:
                            item['not_before'] = ''
                    else:
                        if item['not_before']:
                            item['not_before'] = dt.strptime(item['not_before'], "%Y-%m-%dT%H:%M:%SZ").strftime("%Y-%m-%d %H:%M:%S")
                    if isinstance(item['not_after'], class_DateTime):
                        try:
                            item['not_after'] = dt.strptime(item['not_after'].value, "%Y-%m-%dT%H:%M:%SZ").strftime("%Y-%m-%d %H:%M:%S")
                        except Exception:
                            item['not_after'] = ''
                    else:
                        if item['not_after']:
                            item['not_after'] = dt.strptime(item['not_after'], "%Y-%m-%dT%H:%M:%SZ").strftime("%Y-%m-%d %H:%M:%S")

                    # Для каждого сертификата создаём свой каталог.
                    path_cert = os.path.join(certs_path, item['name'])
                    err, msg = self.create_dir(path_cert)
                    if err:
                        self.stepChanged.emit(f'RED|          {msg}')
                        self.stepChanged.emit(f'ORANGE|          Error: Не удалось создать каталог для сертификата "{item["name"]}".')
                        return 1

                    # Выгружаем сертификат в формат DER.
                    err, base64_cert = self.utm.get_dcfw_template_certificate_data(template_id, item['id'])
                    if err:
                        self.stepChanged.emit(f'RED|          {base64_cert}')
                        self.stepChanged.emit(f'ORANGE|          Error: Не удалось выгрузить сертификат в формате DER.')
                        error = 1
                    else:
                        with open(os.path.join(path_cert, 'cert.der'), 'wb') as fh:
                            fh.write(base64_cert.data)

                    # Выгружаем сертификат с цепочками в формат PEM.
                    err, base64_cert = self.utm.get_dcfw_template_certificate_chain_data(template_id, item['id'])
                    if err:
                        self.stepChanged.emit(f'RED|          {base64_cert}')
                        self.stepChanged.emit(f'ORANGE|          Error: Не удалось выгрузить сертификат в формате PEM.')
                        error = 1
                    else:
                        with open(os.path.join(path_cert, 'cert.pem'), 'wb') as fh:
                            fh.write(base64_cert.data)

                    # Выгружаем детальную информацию сертификата в файл certificate_details.json.
                    err, details_info = self.utm.get_dcfw_template_certificate_details(template_id, item['id'])
                    if err:
                        self.stepChanged.emit(f'RED|          {details_info}')
                        self.stepChanged.emit(f'ORANGE|          Error: [Сертификат "{item["name"]}"] Не удалось выгрузить детальную информацию сертификата.')
                        error = 1
                    else:
                        if isinstance(details_info['notBefore'], class_DateTime):
                            try:
                                details_info['notBefore'] = dt.strptime(details_info['notBefore'].value, "%Y-%m-%dT%H:%M:%SZ").strftime("%Y-%m-%d %H:%M:%S")
                            except Exception:
                                details_info['notBefore'] = ''
                        else:
                            if details_info['notBefore']:
                                details_info['notBefore'] = dt.strptime(details_info['notBefore'], "%Y-%m-%dT%H:%M:%SZ").strftime("%Y-%m-%d %H:%M:%S")
                        if isinstance(details_info['notAfter'], class_DateTime):
                            try:
                                details_info['notAfter'] = dt.strptime(details_info['notAfter'].value, "%Y-%m-%dT%H:%M:%SZ").strftime("%Y-%m-%d %H:%M:%S")
                            except Exception:
                                details_info['notAfter'] = ''
                        else:
                            if details_info['notAfter']:
                                details_info['notAfter'] = dt.strptime(details_info['notAfter'], "%Y-%m-%dT%H:%M:%SZ").strftime("%Y-%m-%d %H:%M:%S")

                        if 'chain' in details_info:
                            for chain_item in details_info['chain']:
                                if isinstance(chain_item['notBefore'], class_DateTime):
                                    try:
                                        chain_item['notBefore'] = dt.strptime(chain_item['notBefore'].value, "%Y-%m-%dT%H:%M:%SZ").strftime("%Y-%m-%d %H:%M:%S")
                                    except Exception:
                                        chain_item['notBefore'] = ''
                                else:
                                    if chain_item['notBefore']:
                                        chain_item['notBefore'] = dt.strptime(chain_item['notBefore'], "%Y-%m-%dT%H:%M:%SZ").strftime("%Y-%m-%d %H:%M:%S")
                                if isinstance(chain_item['notAfter'], class_DateTime):
                                    try:
                                        chain_item['notAfter'] = dt.strptime(chain_item['notAfter'].value, "%Y-%m-%dT%H:%M:%SZ").strftime("%Y-%m-%d %H:%M:%S")
                                    except Exception:
                                        chain_item['notAfter'] = ''
                                else:
                                    if chain_item['notAfter']:
                                        chain_item['notAfter'] = dt.strptime(chain_item['notAfter'], "%Y-%m-%dT%H:%M:%SZ").strftime("%Y-%m-%d %H:%M:%S")

                        json_file = os.path.join(path_cert, 'certificate_details.json')
                        with open(json_file, 'w') as fh:
                            json.dump(details_info, fh, indent=4, ensure_ascii=False)

                    # Выгружаем общую информацию сертификата в файл certificate_list.json.
                    item.pop('id', None)
                    item.pop('template_id', None)
                    json_file = os.path.join(path_cert, 'certificate_list.json')
                    with open(json_file, 'w') as fh:
                        json.dump(item, fh, indent=4, ensure_ascii=False)
                    self.stepChanged.emit(f'BLACK|          Сертификат "{item["name"]}" экспортирован в каталог {path_cert}.')

                if error:
                    self.stepChanged.emit(f'ORANGE|       [Шаблон "{template_name}"] Произошла ошибка при экспорте сертификатов.')
                    self.error = 1
                else:
                    self.stepChanged.emit(f'GREEN|       [Шаблон "{template_name}"] Сертификаты выгружены в каталог "{certs_path}".')
            else:
                self.stepChanged.emit(f'GRAY|       [Шаблон "{template_name}"] Нет сертификатов для экспорта.')
        return 0


    def export_users_certificate_profiles(self):
        """Экспортируем профили пользовательских сертификатов."""
        self.stepChanged.emit('BLUE|Экспорт настроек раздела "UserGate/Профили пользовательских сертификатов".')

        for template_id, template_name in self.templates.items():
            err, data = self.utm.get_dcfw_template_client_certificate_profiles(template_id)
            if err:
                self.stepChanged.emit(f'RED|    {data}')
                self.stepChanged.emit(f'ORANGE|    Error [Шаблон "{template_name}"]. Произошла ошибка при экспорте профилей пользовательских сертификатов.')
                return 1

            if data:
                for item in data:
                    self.mc_data['user_cert_profiles'][item['id']] = item['name']
                    item.pop('id', None)
                    item.pop('template_id', None)
                    try:
                        item['ca_certificates'] = [self.mc_data['certs'][x] for x in item['ca_certificates']]
                    except KeyError:
                        self.stepChanged.emit(f'RED|    Error [Шаблон "{template_name}"]. Не найден сертификат УЦ для профиля "{item["name"]}" в данной группе шаблонов.')
                        return 1

                path = os.path.join(self.group_path, template_name, 'UserGate/UserCertificateProfiles')
                err, msg = self.create_dir(path)
                if err:
                    self.stepChanged.emit(f'RED|    {msg}')
                    self.stepChanged.emit(f'ORANGE|    Error [Шаблон "{template_name}"]. Не удалось создать директорию для экспорта профилей пользовательских сертификатов.')
                    return 1

                json_file = os.path.join(path, 'users_certificate_profiles.json')
                with open(json_file, 'w') as fh:
                    json.dump(data, fh, indent=4, ensure_ascii=False)
                self.stepChanged.emit(f'GREEN|    [Шаблон "{template_name}"] Профили пользовательских сертификатов выгружены в файл "{json_file}".')
            else:
                self.stepChanged.emit(f'GRAY|    [Шаблон "{template_name}"] Нет профилей пользовательских сертификатов для экспорта.')
        return 0


    #------------------------------------------- Пользователи и устройства ------------------------------------------------------
    def export_local_groups(self):
        """Экспортируем список локальных групп пользователей"""
        self.stepChanged.emit('BLUE|Экспорт списка локальных групп из раздела "Пользователи и устройства/Группы".')
        error = 0

        for template_id, template_name in self.templates.items():
            err, data = self.utm.get_dcfw_template_groups(template_id)
            if err:
                self.stepChanged.emit(f'RED|    {data}')
                self.stepChanged.emit(f'ORANGE|    Error [Шаблон "{template_name}"]. Произошла ошибка при экспорте списка локальных групп.')
                return 1

            if data:
                for item in data:
                    self.mc_data['local_groups'][item['id']] = item['name']
                    item['users'] = []
                    err, users = self.utm.get_dcfw_template_group_users(template_id, item['id'])
                    if err:
                        self.stepChanged.emit(f'RED|    {users}')
                        self.stepChanged.emit(f'ORANGE|    [Шаблон "{template_name}"] Произошла ошибка при экспорте членов группы "{item["name"]}".')
                        error = 1
                    else:
                        for x in users:
                            user = x[1].split(f' {chr(8212)} ')[0]  # Убираем длинное тире.
                            if not '\\' in user:
                                user = user.split()[0]  # Убираем логин, оставляем имя.
                            item['users'].append(user)
                    item.pop('id', None)
                    item.pop('template_id', None)
                    item.pop('group_type', None)
                    item.pop('all_users', None)

                path = os.path.join(self.group_path, template_name, 'UsersAndDevices/Groups')
                err, msg = self.create_dir(path)
                if err:
                    self.stepChanged.emit(f'RED|    {msg}')
                    self.stepChanged.emit(f'ORANGE|    Error [Шаблон "{template_name}"]. Не удалось создать директорию для экспорта списка локальных групп.')
                    return 1

                json_file = os.path.join(path, 'config_groups.json')
                with open(json_file, 'w') as fh:
                    json.dump(data, fh, indent=4, ensure_ascii=False)

                if error:
                    self.stepChanged.emit(f'ORANGE|    [Шаблон "{template_name}"] Произошла ошибка при экспорте списка локальных групп.')
                    self.error = 1
                else:
                    self.stepChanged.emit(f'GREEN|    [Шаблон "{template_name}"] Список локальных групп выгружен в файл "{json_file}".')
            else:
                self.stepChanged.emit(f'GRAY|    [Шаблон "{template_name}"] Нет локальных групп для экспорта.')
        return 0


    def export_local_users(self):
        """Экспортируем список локальных пользователей"""
        self.stepChanged.emit('BLUE|Экспорт списка локальных пользователей из раздела "Пользователи и устройства/Пользователи".')

        for template_id, template_name in self.templates.items():
            error = 0
            err, data = self.utm.get_dcfw_template_users(template_id)
            if err:
                self.stepChanged.emit(f'RED|    {data}')
                self.stepChanged.emit(f'ORANGE|    Error [Шаблон "{template_name}"]. Произошла ошибка при экспорте списка локальных пользователей.')
                return 1

            if data:
                for item in data:
                    item.pop('creation_date', None)
                    item.pop('expiration_date', None)
                    item.pop('template_id', None)
                    item.pop('user_type', None)
                    err, groups = self.utm.get_dcfw_template_user_groups(template_id, item['id'])
                    if err:
                        self.stepChanged.emit(f'RED|    {groups}')
                        self.stepChanged.emit(f'ORANGE|    [Шаблон "{template_name}"] Произошла ошибка при экспорте групп пользователя "{item["name"]}".')
                        item['groups'] = []
                        error = 1
                    else:
                        item['groups'] = [x['name'].split(f' {chr(8212)} ')[0] for x in groups]
                    item.pop('id', None)

                path = os.path.join(self.group_path, template_name, 'UsersAndDevices/Users')
                err, msg = self.create_dir(path)
                if err:
                    self.stepChanged.emit(f'RED|    {msg}')
                    self.stepChanged.emit(f'ORANGE|    Error [Шаблон "{template_name}"]. Не удалось создать директорию для экспорта списка локальных пользователей.')
                    return 1

                json_file = os.path.join(path, 'config_users.json')
                with open(json_file, 'w') as fh:
                    json.dump(data, fh, indent=4, ensure_ascii=False)

                if error:
                    self.stepChanged.emit(f'ORANGE|    [Шаблон "{template_name}"] Произошла ошибка при экспорте списка локальных пользователей.')
                    self.error = 1
                else:
                    self.stepChanged.emit(f'GREEN|    [Шаблон "{template_name}"] Список локальных пользователей выгружен в файл "{json_file}".')
            else:
                self.stepChanged.emit(f'GRAY|    [Шаблон "{template_name}"] Нет локальных пользователей для экспорта.')
        return 0


    def export_2fa_profiles(self):
        """Экспортируем список MFA профилей"""
        self.stepChanged.emit('BLUE|Экспорт списка MFA профилей из раздела "Пользователи и устройства/Профили MFA".')

        for template_id, template_name in self.templates.items():
            err, data = self.utm.get_dcfw_template_2fa_profiles(template_id)
            if err:
                self.stepChanged.emit(f'RED|    {data}')
                self.stepChanged.emit(f'ORANGE|    Error [Шаблон "{template_name}"]. Произошла ошибка при экспорте списка MFA профилей.')
                return 1

            if data:
                for item in data:
                    self.mc_data['mfa_profiles'][item['id']] = item['name']
                    item.pop('id', None)
                    item.pop('template_id', None)
                    try:
                        if item['type'] == 'totp':
                            item['init_notification_profile_id'] = self.mc_data['notification_profiles'][item['init_notification_profile_id']]
                            item.pop('auth_notification_profile_id', None)
                        else:
                            item['auth_notification_profile_id'] = self.mc_data['notification_profiles'][item['auth_notification_profile_id']]
                            item.pop('totp_show_qr_code', None)
                            item.pop('init_notification_profile_id', None)
                    except KeyError as err:
                        self.stepChanged.emit(f'RED|    Error [Шаблон "{template_name}"]. Не найден профиль оповещения для MFA профиля "{item["name"]}" в данной группе шаблонов.')
                        return 1

                path = os.path.join(self.group_path, template_name, 'UsersAndDevices/MFAProfiles')
                err, msg = self.create_dir(path)
                if err:
                    self.stepChanged.emit(f'RED|    {msg}')
                    self.stepChanged.emit(f'ORANGE|    Error [Шаблон "{template_name}"]. Не удалось создать директорию для экспорта списка MFA профилей.')
                    return 1

                json_file = os.path.join(path, 'config_2fa_profiles.json')
                with open(json_file, 'w') as fh:
                    json.dump(data, fh, indent=4, ensure_ascii=False)
                self.stepChanged.emit(f'GREEN|    [Шаблон "{template_name}"] Список MFA профилей выгружен в файл "{json_file}".')
            else:
                self.stepChanged.emit(f'GRAY|    [Шаблон "{template_name}"] Нет MFA профилей для экспорта.')
        return 0


    def export_auth_servers(self):
        """Экспортируем список серверов аутентификации"""
        self.stepChanged.emit('BLUE|Экспорт списка серверов аутентификации из раздела "Пользователи и устройства/Серверы аутентификации".')

        for template_id, template_name in self.templates.items():
            error = 0
            self.stepChanged.emit(f'sGREEN|    Экспорт из шаблона "{template_name}".')
            err, result = self.utm.get_dcfw_template_auth_servers(template_id)
            if err:
                self.stepChanged.emit(f'RED|       {result}')
                self.stepChanged.emit(f'ORANGE|       Произошла ошибка при экспорте списка серверов аутентификации.')
                return 1

            if result:
                path = os.path.join(self.group_path, template_name, 'UsersAndDevices/AuthServers')
                err, msg = self.create_dir(path)
                if err:
                    self.stepChanged.emit(f'RED|       {msg}')
                    self.stepChanged.emit(f'ORANGE|       Произошла ошибка при экспорте списка серверов аутентификации.')
                    return 1

                ldap = []
                radius = []
                tacacs = []
                ntlm = []
                saml = []
                for item in result:
                    self.mc_data['auth_servers'][item['id']] = item['name']
                    item.pop('id', None)
                    item.pop('template_id', None)
                    if item['type'] == 'ldap':
                        ldap.append(item)
                    if item['type'] == 'radius':
                        radius.append(item)
                    if item['type'] == 'tacacs_plus':
                        tacacs.append(item)
                    if item['type'] == 'ntlm':
                        ntlm.append(item)
                    if item['type'] == 'saml_idp':
                        saml.append(item)
                    item.pop('type', None)

                if ldap:
                    json_file = os.path.join(path, 'config_ldap_servers.json')
                    with open(json_file, 'w') as fh:
                        json.dump(ldap, fh, indent=4, ensure_ascii=False)
                    self.stepChanged.emit(f'BLACK|       Список серверов LDAP выгружен в файл "{json_file}".')
                if radius:
                    json_file = os.path.join(path, 'config_radius_servers.json')
                    with open(json_file, 'w') as fh:
                        json.dump(radius, fh, indent=4, ensure_ascii=False)
                    self.stepChanged.emit(f'BLACK|       Список серверов RADIUS выгружен в файл "{json_file}".')
                if tacacs:
                    json_file = os.path.join(path, 'config_tacacs_servers.json')
                    with open(json_file, 'w') as fh:
                        json.dump(tacacs, fh, indent=4, ensure_ascii=False)
                    self.stepChanged.emit(f'BLACK|       Список серверов TACACS выгружен в файл "{json_file}".')
                if ntlm:
                    json_file = os.path.join(path, 'config_ntlm_servers.json')
                    with open(json_file, 'w') as fh:
                        json.dump(ntlm, fh, indent=4, ensure_ascii=False)
                    self.stepChanged.emit(f'BLACK|       Список серверов NTLM выгружен в файл "{json_file}".')
                if saml:
                    for item in saml:
                        error, item['certificate_id'] = self.get_certificate_name(item['certificate_id'], item['name'], error, template_name)

                    json_file = os.path.join(path, 'config_saml_servers.json')
                    with open(json_file, 'w') as fh:
                        json.dump(saml, fh, indent=4, ensure_ascii=False)
                    if error:
                        self.stepChanged.emit(f'ORANGE|       Произошла ошибка при экспорте серверов SAML (файл "{json_file}").')
                    else:
                        self.stepChanged.emit(f'BLACK|       Список серверов SAML выгружен в файл "{json_file}".')

                if error:
                    self.stepChanged.emit(f'ORANGE|    [Шаблон "{template_name}"] Произошла ошибка при экспорте серверов аутентификации.')
                else:
                    self.stepChanged.emit(f'GREEN|    [Шаблон "{template_name}"] Список серверов аутентификации экспортирован.')
            else:
                self.stepChanged.emit(f'GRAY|    [Шаблон "{template_name}"] Нет серверов аутентификации для экспорта.')
        return 0


    def export_auth_profiles(self):
        """Экспортируем список профилей аутентификации"""
        self.stepChanged.emit('BLUE|Экспорт списка профилей авторизации из раздела "Пользователи и устройства/Профили аутентификации".')

        for template_id, template_name in self.templates.items():
            error = 0
            err, data = self.utm.get_dcfw_template_auth_profiles(template_id)
            if err:
                self.stepChanged.emit(f'RED|    {data}')
                self.stepChanged.emit(f'ORANGE|    Error [Шаблон "{template_name}"]. Произошла ошибка при экспорте профилей аутентификации.')
                return 1

            if data:
                for item in data:
                    self.mc_data['auth_profiles'][item['id']] = item['name']
                    item.pop('id', None)
                    item.pop('template_id', None)
                    if item['2fa_profile_id']:
                        try:
                            item['2fa_profile_id'] = self.mc_data['mfa_profiles'][item['2fa_profile_id']]
                        except KeyError:
                            self.stepChanged.emit(f'RED|    Error [Шаблон "{template_name}"]. Не найден профиль MFA для профиля аутентификации "{item["name"]}" в данной группе шаблонов.')
                            item['2fa_profile_id'] = False
                            error = 1

                    for auth_method in item['allowed_auth_methods']:
                        if 'saml_idp_server' in auth_method:
                            auth_method['saml_idp_server_id'] = auth_method.pop('saml_idp_server', False)
                        for key, value in auth_method.items():
                            if key in {'ldap_server_id', 'radius_server_id', 'tacacs_plus_server_id', 'ntlm_server_id', 'saml_idp_server_id'}:
                                if auth_method[key]:
                                    try:
                                        auth_method[key] = self.mc_data['auth_servers'][value]
                                    except KeyError:
                                        self.stepChanged.emit(f'RED|    Error [Шаблон "{template_name}"]. Не найден метод аутентификации {auth_method["type"]} для профиля "{item["name"]}". Возможно указан сервер аутентификации из шаблона, не входящего в эту группу шаблонов.')
                                        auth_method[key] = None
                                        error = 1

                path = os.path.join(self.group_path, template_name, 'UsersAndDevices/AuthProfiles')
                err, msg = self.create_dir(path)
                if err:
                    self.stepChanged.emit(f'RED|    {msg}')
                    self.stepChanged.emit(f'ORANGE|    Error [Шаблон "{template_name}"]. Не удалось создать директорию для экспорта профилей аутентификации.')
                    return 1

                json_file = os.path.join(path, 'config_auth_profiles.json')
                with open(json_file, 'w') as fh:
                    json.dump(data, fh, indent=4, ensure_ascii=False)

                if error:
                    self.stepChanged.emit(f'ORANGE|    [Шаблон "{template_name}"] Произошла ошибка при экспорте профилей аутентификации.')
                    self.error = 1
                else:
                    self.stepChanged.emit(f'GREEN|    [Шаблон "{template_name}"] Список профилей аутентификации выгружен в файл "{json_file}".')
            else:
                self.stepChanged.emit(f'GRAY|    [Шаблон "{template_name}"] Нет профилей аутентификации для экспорта.')
        return 0


    def export_captive_profiles(self):
        """Экспортируем список Captive-профилей"""
        self.stepChanged.emit('BLUE|Экспорт списка Captive-профилей из раздела "Пользователи и устройства/Captive-профили".')

        for template_id, template_name in self.templates.items():
            error = 0
            err, data = self.utm.get_dcfw_template_captive_profiles(template_id)
            if err:
                self.stepChanged.emit(f'RED|    {data}')
                self.stepChanged.emit(f'ORANGE|    Error [Шаблон "{template_name}"]. Произошла ошибка при экспорте Captive-профилей.')
                return 1

            if data:
                for item in data:
                    self.mc_data['captive_profiles'][item['id']] = item['name']
                    item.pop('id', None)
                    item.pop('template_id', None)
                    try:
                        item['captive_template_id'] = self.mc_data['response_pages'][item['captive_template_id']]
                    except KeyError:
                        self.stepChanged.emit(f'RED|    Error [Шаблон "{template_name}"]. Не найден шаблон страницы аутентификации для Captive-профиля "{item["name"]}" в данной группе шаблонов.')
                        item['captive_template_id'] = -1
                        error = 1
                    try:
                        item['notification_profile_id'] = self.mc_data['notification_profiles'][item['notification_profile_id']]
                    except KeyError:
                        self.stepChanged.emit(f'RED|    Error [Шаблон "{template_name}"]. Не найден профиль оповещения гостевых пользователей для Captive-профиля "{item["name"]}" в данной группе шаблонов.')
                        item['notification_profile_id'] = -1
                        error = 1
                    try:
                        item['user_auth_profile_id'] = self.mc_data['auth_profiles'][item['user_auth_profile_id']]
                    except KeyError:
                        self.stepChanged.emit(f'RED|    Error [Шаблон "{template_name}"]. Не найден профиль аутентификации для Captive-профиля "{item["name"]}" в данной группе шаблонов. Профиль установлен в дефолтное значение.')
                        item['user_auth_profile_id'] = 'Example user auth profile'
                        error = 1

                    item['ta_groups'] = [self.mc_data['local_groups'][guid] for guid in item['ta_groups']]
                    if item['ta_expiration_date']:
                        item['ta_expiration_date'] = dt.strptime(item['ta_expiration_date'], "%Y-%m-%dT%H:%M:%S").strftime("%Y-%m-%d %H:%M:%S")
                    try:
                        item['client_certificate_profile_id'] = self.mc_data['user_cert_profiles'][item['client_certificate_profile_id']]
                    except KeyError:
                        self.stepChanged.emit(f'RED|    Error [Шаблон "{template_name}"]. Не найден профиль клиентского сертификата для Captive-профиля "{item["name"]}" в данной группе шаблонов.')
                        item['client_certificate_profile_id'] = 0
                        error = 1

                path = os.path.join(self.group_path, template_name, 'UsersAndDevices/CaptiveProfiles')
                err, msg = self.create_dir(path)
                if err:
                    self.stepChanged.emit(f'RED|    {msg}')
                    self.stepChanged.emit(f'ORANGE|    Error [Шаблон "{template_name}"]. Не удалось создать директорию для экспорта Captive-профилей.')
                    return 1

                json_file = os.path.join(path, 'config_captive_profiles.json')
                with open(json_file, 'w') as fh:
                    json.dump(data, fh, indent=4, ensure_ascii=False)

                if error:
                    self.stepChanged.emit(f'ORANGE|    [Шаблон "{template_name}"] Произошла ошибка при экспорте Captive-профилей.')
                    self.error = 1
                else:
                    self.stepChanged.emit(f'GREEN|    [Шаблон "{template_name}"] Список Captive-профилей выгружен в файл "{json_file}".')
            else:
                self.stepChanged.emit(f'GRAY|    [Шаблон "{template_name}"] Нет профилей аутентификации для экспорта.')
        return 0


    def export_captive_portal_rules(self):
        """Экспортируем список правил Captive-портала"""
        self.stepChanged.emit('BLUE|Экспорт списка правил Captive-портала из раздела "Пользователи и устройства/Captive-портал".')

        for template_id, template_name in self.templates.items():
            error = 0
            err, data = self.utm.get_dcfw_template_captive_portal_rules(template_id)
            if err:
                self.stepChanged.emit(f'RED|    {data}')
                self.stepChanged.emit(f'ORANGE|    Error [Шаблон "{template_name}"]. Произошла ошибка при экспорте правил Captive-портала.')
                return 1

            if data:
                for item in data:
                    item.pop('id', None)
                    item.pop('template_id', None)
                    item.pop('grid_position', None)
                    try:
                        item['profile_id'] = self.mc_data['captive_profiles'][item['profile_id']]
                    except KeyError:
                        self.stepChanged.emit(f'RED|    Error [Шаблон "{template_name}"]. Не найден Captive-профиль для Captive-портала "{item["name"]}" в данной группе шаблонов.')
                        item['profile_id'] = 0
                        error = 1
                    error, item['src_zones'] = self.get_zones_name('src', item['src_zones'], item['name'], error, template_name)
                    error, item['dst_zones'] = self.get_zones_name('dst', item['dst_zones'], item['name'], error, template_name)
                    error, item['src_ips'] = self.get_ips_name('src', item['src_ips'], item['name'], error, template_name)
                    error, item['dst_ips'] = self.get_ips_name('dst', item['dst_ips'], item['name'], error, template_name)
                    error, item['urls'] = self.get_urls_name(item['urls'], item['name'], error, template_name)
                    error, item['url_categories'] = self.get_url_categories_name(item['url_categories'], item['name'], error, template_name)
                    error, item['time_restrictions'] = self.get_time_restrictions_name(item['time_restrictions'], item['name'], error, template_name)
                    error, item['cc_network_devices'] = self.get_network_devices(item['cc_network_devices'], item['name'], error, template_name)
                    item['time_created'] = item['time_created'].replace('T', ' ').replace('Z', '')
                    item['time_updated'] = item.get('time_updated', '').replace('T', ' ').replace('Z', '')

                path = os.path.join(self.group_path, template_name, 'UsersAndDevices/CaptivePortal')
                err, msg = self.create_dir(path)
                if err:
                    self.stepChanged.emit(f'RED|    {msg}')
                    self.stepChanged.emit(f'ORANGE|    Error [Шаблон "{template_name}"]. Не удалось создать директорию для экспорта правил Captive-портала.')
                    return 1

                json_file = os.path.join(path, 'config_captive_portal_rules.json')
                with open(json_file, 'w') as fh:
                    json.dump(data, fh, indent=4, ensure_ascii=False)

                if error:
                    self.stepChanged.emit(f'ORANGE|    Error [Шаблон "{template_name}"]. Произошла ошибка при экспорте правил Captive-портала.')
                    self.error = 1
                else:
                    self.stepChanged.emit(f'GREEN|    [Шаблон "{template_name}"] Список правил Captive-портала выгружен в файл "{json_file}".')
            else:
                self.stepChanged.emit(f'GRAY|    [Шаблон "{template_name}"] Нет правил Captive-портала для экспорта.')
        return 0


    def export_userid_agent_config(self):
        """Экспортируем свойства агента UserID"""
        self.stepChanged.emit('BLUE|Экспорт свойств агента UserID из раздела "Пользователи и устройства/Свойства агента UserID".')
        if self.utm.float_version < 7.2:
            self.stepChanged.emit('LBLUE|    Для версии МС меньше чем 7.2 свойства и коннекторы агентов UserID не экспортируются.')
            return 0

        for template_id, template_name in self.templates.items():
            error = 0
            err, data = self.utm.get_dcfw_template_useridagent_config(template_id)
            if err:
                self.stepChanged.emit(f'RED|    {data}')
                self.stepChanged.emit(f'ORANGE|    Error [Шаблон "{template_name}"]. Произошла ошибка при экспорте свойств агента UserID.')
                return 1

            if data:
                for item in data:
                    item.pop('id', None)
                    item.pop('template_id', None)
                    if item['tcp_ca_certificate_id']:
                        try:
                            item['tcp_ca_certificate_id'] = self.mc_data['certs'][item['tcp_ca_certificate_id']]
                        except KeyError:
                            self.stepChanged.emit(f'RED|    Error [Шаблон "{template_name}"]. Не найден сертификат УЦ для свойства "{item["name"]}" в данной группе шаблонов.')
                            item['tcp_ca_certificate_id'] = ''
                            error = 1
                    if item['tcp_server_certificate_id']:
                        try:
                            item['tcp_server_certificate_id'] = self.mc_data['certs'][item['tcp_server_certificate_id']]
                        except KeyError:
                            self.stepChanged.emit(f'RED|    Error [Шаблон "{template_name}"]. Не найден сертификат для свойства "{item["name"]}" в данной группе шаблонов.')
                            item['tcp_server_certificate_id'] = ''
                            error = 1
                    try:
                        item['ignore_networks'] = [['list_id', self.mc_data['ip_lists'][x[1]]] for x in item['ignore_networks']]
                    except KeyError:
                        self.stepChanged.emit(f'RED|    Error [Шаблон "{template_name}"]. Не найден IP-лист в списке Ignore server для свойства "{item["name"]}" в данной группе шаблонов.')
                        item['ignore_networks'] = []
                        error = 1

                path = os.path.join(self.group_path, template_name, 'UsersAndDevices/UserIDagent')
                err, msg = self.create_dir(path)
                if err:
                    self.stepChanged.emit(f'RED|    {msg}')
                    self.stepChanged.emit(f'ORANGE|    Error [Шаблон "{template_name}"]. Не удалось создать директорию для экспорта свойств агента UserID.')
                    return 1

                json_file = os.path.join(path, 'userid_agent_config.json')
                with open(json_file, 'w') as fh:
                    json.dump(data, fh, indent=4, ensure_ascii=False)

                if error:
                    self.stepChanged.emit(f'ORANGE|    Error [Шаблон "{template_name}"]. Произошла ошибка при экспорте свойств агента UserID.')
                    self.error = 1
                else:
                    self.stepChanged.emit(f'GREEN|    [Шаблон "{template_name}"] Свойства агента UserID выгружены в файл "{json_file}".')
            else:
                self.stepChanged.emit(f'GRAY|    [Шаблон "{template_name}"] Нет свойств агента UserID для экспорта.')
        return 0



    def export_userid_agent_connectors(self):
        """Экспортируем UserID коннекторы"""
        self.stepChanged.emit('BLUE|Экспорт UserID агент коннекторов из раздела "Пользователи и устройства/UserID агент коннекторы".')
        if self.utm.float_version < 7.2:
            self.stepChanged.emit('LBLUE|    Для версии МС меньше чем 7.2 свойства и коннекторы агентов UserID не экспортируются.')
            return 0

        for template_id, template_name in self.templates.items():
            error = 0
            err, data = self.utm.get_dcfw_template_useridagent_servers(template_id)
            if err:
                self.stepChanged.emit(f'RED|    {data}')
                self.stepChanged.emit(f'ORANGE|    Error [Шаблон "{template_name}"]. Произошла ошибка при экспорте агентов UserID.')
                return 1

            if data:
                for item in data:
                    item.pop('id', None)
                    item.pop('template_id', None)
                    try:
                        item['auth_profile_id'] = self.mc_data['auth_profiles'][item['auth_profile_id']]
                    except KeyError:
                        self.stepChanged.emit(f'RED|    Error [Шаблон "{template_name}"]. Не найден профиль аутентификации для коннектора "{item["name"]}" в данной группе шаблонов. Установлено значение по умолчанию.')
                        item['auth_profile_id'] = 'Example user auth profile'
                        error = 1
                    if 'filters' in item:
                        try:
                            item['filters'] = [self.mc_data['userid_filters'][x] for x in item['filters']]
                        except KeyError:
                            self.stepChanged.emit(f'RED|    Error [Шаблон "{template_name}"]. Не найден фильтр для коннектора "{item["name"]}".')
                            item['filters'] = []
                            error = 1

                path = os.path.join(self.group_path, template_name, 'UsersAndDevices/UserIDagent')
                err, msg = self.create_dir(path, delete='no')
                if err:
                    self.stepChanged.emit(f'RED|    {msg}')
                    self.stepChanged.emit(f'ORANGE|    Error [Шаблон "{template_name}"]. Не удалось создать директорию для экспорта UserID агент коннекторов.')
                    return 1

                json_file = os.path.join(path, 'userid_agent_servers.json')
                with open(json_file, 'w') as fh:
                    json.dump(data, fh, indent=4, ensure_ascii=False)

                if error:
                    self.stepChanged.emit(f'ORANGE|    Error [Шаблон "{template_name}"]. Произошла ошибка при экспорте коннекторов агента UserID.')
                    self.error = 1
                else:
                    self.stepChanged.emit(f'GREEN|    [Шаблон "{template_name}"] UserID агент коннекторы выгружены в файл "{json_file}".')
            else:
                self.stepChanged.emit(f'GRAY|    [Шаблон "{template_name}"] Нет UserID агент коннекторов для экспорта.')
        return 0


#-------------------------------------------------- General Settings -------------------------------------------------------
    def export_general_settings(self):
        """Экспортируем раздел 'UserGate/Настройки'."""
        self.stepChanged.emit('BLUE|Экспорт раздела "UserGate/Настройки.')

        for template_id, template_name in self.templates.items():
            error = 0
            err, data = self.utm.get_dcfw_template_general_settings(template_id)
            if err:
                self.stepChanged.emit(f'RED|    {data}')
                self.stepChanged.emit(f'RED|    Error [Шаблон "{template_name}"]. Произошла ошибка экспорта раздела "UserGate/Настройки".')
                return 1

            self.stepChanged.emit(f'sGREEN|    Экспорт из шаблона {template_name}.')
            path = os.path.join(self.group_path, template_name, 'UserGate/GeneralSettings')
            err, msg = self.create_dir(path)
            if err:
                self.stepChanged.emit(f'RED|    {msg}')
                self.stepChanged.emit(f'RED|    Error [Шаблон "{template_name}"]. Не удалось создать директорию для экспорта настроек.')
                return 1

            error = self.export_ui(path, data)
            error = self.export_ntp_settings(path, data)
            error = self.export_modules(path, data)
            error = self.export_upstream_proxy_settings(path, data)

            if error:
                self.stepChanged.emit(f'ORANGE|    Error [Шаблон "{template_name}"]. Произошла ошибка при экспорте настроек.')
                self.error = 1
            else:
                self.stepChanged.emit(f'GREEN|    [Шаблон "{template_name}"] Настройки выгружены в каталог "{path}".')
        return 0


    def export_ui(self, path, data):
        """Экспортируем раздел 'UserGate/Настройки/Настройки интерфейса'"""
        self.stepChanged.emit('BLUE|       Экспорт раздела "UserGate/Настройки/Настройки интерфейса".')

        error = 0
        params = {}

        params['ui_timezone'] = data['ui_timezone']
        params['ui_timezone'].pop('template_id', None)

        params['ui_language'] = data['ui_language']
        params['ui_language'].pop('template_id', None)

        try:
            data['web_console_ssl_profile_id']['value'] = self.mc_data['ssl_profiles'][data['web_console_ssl_profile_id']['value']]
        except KeyError:
            self.stepChanged.emit('RED|          Error: Не найден профиль SSL для веб-консоли в данной группе шаблонов. Данный параметр не экспортирован.')
            data['web_console_ssl_profile_id']['value'] = 0
            data['web_console_ssl_profile_id']['enabled'] = False
            error = 1
        params['web_console_ssl_profile_id'] = data['web_console_ssl_profile_id']
        params['web_console_ssl_profile_id'].pop('template_id', None)

        try:
            data['response_pages_ssl_profile_id']['value'] = self.mc_data['ssl_profiles'][data['response_pages_ssl_profile_id']['value']]
        except KeyError:
            self.stepChanged.emit('RED|          Error: Не найден профиль SSL для страниц блокировки/аутентификации в данной группе шаблонов. Данный параметр не экспортирован.')
            data['response_pages_ssl_profile_id']['value'] = 0
            data['response_pages_ssl_profile_id']['enabled'] = False
            error = 1
        params['response_pages_ssl_profile_id'] =  data['response_pages_ssl_profile_id']
        params['response_pages_ssl_profile_id'].pop('template_id', None)

        try:
            data['endpoint_ssl_profile_id']['value'] = self.mc_data['ssl_profiles'][data['endpoint_ssl_profile_id']['value']]
        except KeyError:
            self.stepChanged.emit('RED|          Error: Не найден профиль SSL конечного устройства в данной группе шаблонов. Данный параметр не экспортирован.')
            data['endpoint_ssl_profile_id']['value'] = 0
            data['endpoint_ssl_profile_id']['enabled'] = False
            error = 1
        params['endpoint_ssl_profile_id'] = data['endpoint_ssl_profile_id']
        params['endpoint_ssl_profile_id'].pop('template_id', None)

        try:
            data['endpoint_certificate_id']['value'] = self.mc_data['certs'][data['endpoint_certificate_id']['value']]
        except KeyError:
            self.stepChanged.emit('RED|          Error: Не найден сертификат конечного устройства в данной группе шаблонов. Данный параметр не экспортирован.')
            data['endpoint_certificate_id']['value'] = 0
            data['endpoint_certificate_id']['enabled'] = False
            error = 1
        params['endpoint_certificate_id'] = data['endpoint_certificate_id']
        params['endpoint_certificate_id'].pop('template_id', None)

        params['webui_auth_mode'] = data['webui_auth_mode']
        params['webui_auth_mode'].pop('template_id', None)

        json_file = os.path.join(path, 'config_settings_ui.json')
        with open(json_file, 'w') as fh:
            json.dump(params, fh, indent=4, ensure_ascii=False)

        if error:
            self.stepChanged.emit('ORANGE|          Произошла ошибка при экспорте настроек интерфейса.')
        else:
            self.stepChanged.emit(f'BLACK|          Настройки интерфейса выгружены в файл "{json_file}".')
        return error


    def export_ntp_settings(self, path, data):
        """Экспортируем настройки NTP"""
        self.stepChanged.emit('BLUE|       Экспорт настроек NTP раздела "UserGate/Настройки/Настройка времени сервера".')

        ntp_settings = {
            'ntp_servers': [],
            'ntp_enabled': data['ntp_enabled']['value'],
            'ntp_synced': data['ntp_enabled']['enabled']
        }
        if data['ntp_server1']['value']:
            ntp_settings['ntp_servers'].append({'value': data['ntp_server1']['value'], 'enabled': data['ntp_server1']['enabled']})
        if data['ntp_server2']['value']:
            ntp_settings['ntp_servers'].append({'value': data['ntp_server2']['value'], 'enabled': data['ntp_server2']['enabled']})

        if ntp_settings['ntp_servers']:
            json_file = os.path.join(path, 'config_ntp.json')
            with open(json_file, 'w') as fh:
                json.dump(ntp_settings, fh, indent=4, ensure_ascii=False)
            self.stepChanged.emit(f'BLACK|          Настройки NTP выгружены в файл "{json_file}".')
        else:
            self.stepChanged.emit('GRAY|          Нет настроек NTP для экспорта.')
        return 0


    def export_modules(self, path, data):
        """Экспортируем раздел 'UserGate/Настройки/Модули'"""
        self.stepChanged.emit('BLUE|       Экспорт раздела "UserGate/Настройки/Модули".')
        error = 0

        data['proxy_server_port'].pop('template_id', None)
        json_file = os.path.join(path, 'config_proxy_port.json')
        with open(json_file, 'w') as fh:
            json.dump(data['proxy_server_port'], fh, indent=4, ensure_ascii=False)
        self.stepChanged.emit(f'BLACK|          HTTP(S)-прокси порт выгружен в файл "{json_file}".')

        data['saml_server_port'].pop('template_id', None)
        json_file = os.path.join(path, 'config_saml_port.json')
        with open(json_file, 'w') as fh:
            json.dump(data['saml_server_port'], fh, indent=4, ensure_ascii=False)
        self.stepChanged.emit(f'BLACK|          Порт SAML-сервера выгружен в файл "{json_file}".')

        data['auth_captive'].pop('template_id', None)
        data['logout_captive'].pop('template_id', None)
        data['cert_captive'].pop('template_id', None)
        data['block_page_domain'].pop('template_id', None)
        data['ftpclient_captive'].pop('template_id', None)
        data['ftp_proxy_enabled'].pop('template_id', None)
        data['lldp_config'].pop('template_id', None)
        params = {
            'auth_captive': data['auth_captive'],
            'logout_captive': data['logout_captive'],
            'cert_captive': data.get('cert_captive', {}),
            'block_page_domain': data['block_page_domain'],
            'ftpclient_captive': data['ftpclient_captive'],
            'ftp_proxy_enabled': data['ftp_proxy_enabled'],
            'lldp_config': data['lldp_config']
        }
        data['tunnel_inspection_zone_config'].pop('template_id', None)
        target_zone = data['tunnel_inspection_zone_config']['value']['target_zone']
        if target_zone:
            try:
                data['tunnel_inspection_zone_config']['value']['target_zone'] = self.mc_data['zones'][target_zone]
            except KeyError:
                self.stepChanged.emit('RED|          Error: Не найдена зона в данной группе шаблонов. Параметр "Зона для инспектируемых туннелей" не экспортирован.')
                data['tunnel_inspection_zone_config']['value']['target_zone'] = ''
                error = 1
        params['tunnel_inspection_zone_config'] = data['tunnel_inspection_zone_config']
    
        json_file = os.path.join(path, 'config_settings_modules.json')
        with open(json_file, 'w') as fh:
            json.dump(params, fh, indent=4, ensure_ascii=False)

        if error:
            self.stepChanged.emit('ORANGE|          Произошла ошибка при экспорта настроек модулей.')
        else:
            self.stepChanged.emit(f'BLACK|          Настройки модулей выгружены в файл "{json_file}".')
        return error


    def export_upstream_proxy_settings(self, path, data):
        """Экспортируем настройки вышестоящего прокси"""
        self.stepChanged.emit('BLUE|       Экспорт настроек прокси раздела "UserGate/Настройки/Вышестоящий прокси".')

        values = data['upstream_proxy']
        values.pop('template_id', None)
        json_file = os.path.join(path, 'upstream_proxy_settings.json')
        with open(json_file, 'w') as fh:
            json.dump(values, fh, indent=4, ensure_ascii=False)
        self.stepChanged.emit(f'BLACK|          Настройки вышестоящего прокси выгружены в файл "{json_file}".')

        values = data['upstream_update_proxy']
        values.pop('template_id', None)
        json_file = os.path.join(path, 'upstream_proxy_check_update.json')
        with open(json_file, 'w') as fh:
            json.dump(values, fh, indent=4, ensure_ascii=False)
        self.stepChanged.emit(f'BLACK|          Настройки вышестоящего прокси для проверки лицензии и обновлений выгружены в файл "{json_file}".')

        return 0


    def export_template_admins(self):
        """Экспортируем раздел 'UserGate/Администраторы'."""
        self.stepChanged.emit('BLUE|Экспорт раздела "UserGate/Администраторы".')
        admin_profiles = {}

        for template_id, template_name in self.templates.items():
            error = 0
            self.stepChanged.emit(f'sGREEN|    Экспорт из шаблона {template_name}.')

            err, data = self.utm.get_dcfw_template_admins_profiles(template_id)
            if err:
                self.stepChanged.emit(f'RED|       {data}')
                self.stepChanged.emit(f'RED|       Error [Шаблон "{template_name}"]. Произошла ошибка экспорта раздела "UserGate/Администраторы".')
                return 1

            if data:
                for item in data:
                    admin_profiles[item['id']] = item['name']
                    item.pop('id', None)
                    item.pop('template_id', None)

                path = os.path.join(self.group_path, template_name, 'UserGate/Administrators')
                err, msg = self.create_dir(path)
                if err:
                    self.stepChanged.emit(f'RED|       {msg}')
                    self.stepChanged.emit(f'RED|       Error [Шаблон "{template_name}"]. Не удалось создать директорию для экспорта настроек Администраторов.')
                    return 1

                json_file = os.path.join(path, 'administrator_profiles.json')
                with open(json_file, 'w') as fh:
                    json.dump(data, fh, indent=4, ensure_ascii=False)
                self.stepChanged.emit(f'BLACK|       Профили администраторов выгружены в файл "{json_file}".')

                err, data = self.utm.get_dcfw_template_admins(template_id)
                if err:
                    self.stepChanged.emit(f'RED|       {data}')
                    self.stepChanged.emit(f'RED|       Error [Шаблон "{template_name}"]. Произошла ошибка при экспорте списка администраторов".')
                    return 1

                if data:
                    for item in data:
                        item.pop('id', None)
                        item.pop('template_id', None)
                        item['profile_id'] = admin_profiles[item['profile_id']]
                        if 'user_auth_profile_id' in item:
                            try:
                                item['user_auth_profile_id'] = self.mc_data['auth_profiles'][item['user_auth_profile_id']]
                            except KeyError:
                                self.stepChanged.emit(f'RED|       Error: Не найден профиль аутентификации для администратора "{item["name"]}" в данной группе шаблонов. Профиль установлен в дефолтное значение.')
                                item['user_auth_profile_id'] = 'Example user auth profile'
                                error = 1

                    json_file = os.path.join(path, 'administrators_list.json')
                    with open(json_file, 'w') as fh:
                        json.dump(data, fh, indent=4, ensure_ascii=False)
                    self.stepChanged.emit(f'BLACK|       Список администраторов выгружен в файл "{json_file}".')

                if error:
                    self.stepChanged.emit(f'ORANGE|       [Шаблон "{template_name}"]. Произошла ошибка при экспорте раздела "UserGate/Администраторы".')
                    self.error = 1
                else:
                    self.stepChanged.emit(f'GREEN|       [Шаблон "{template_name}"] Раздел "UserGate/Администраторы" выгружен в каталог "{path}".')
            else:
                self.stepChanged.emit(f'GRAY|       [Шаблон "{template_name}"] Нет администраторов для экспорта.')
        return error


    #-------------------------------------- Политики сети -----------------------------------------------------
    def export_firewall_rules(self):
        """Экспортируем список правил межсетевого экрана"""
        self.stepChanged.emit('BLUE|Экспорт правил межсетевого экрана из раздела "Политики сети/Межсетевой экран".')

        for template_id, template_name in self.templates.items():
            error = 0
            err, data = self.utm.get_dcfw_template_firewall_rules(template_id)
            if err:
                self.stepChanged.emit(f'RED|    {data}')
                self.stepChanged.emit(f'RED|    Error [Шаблон "{template_name}"]. Произошла ошибка при экспорте правил межсетевого экрана.')
                return 1

            if data:
                for item in data:
                    item.pop('id', None)
                    item.pop('template_id', None)
                    item.pop('grid_position', None)
                    item.pop('active', None)

                    error, item['src_zones'] = self.get_zones_name('src', item['src_zones'], item['name'], error, template_name)
                    error, item['dst_zones'] = self.get_zones_name('dst', item['dst_zones'], item['name'], error, template_name)
                    error, item['src_ips'] = self.get_ips_name('src', item['src_ips'], item['name'], error, template_name)
                    error, item['dst_ips'] = self.get_ips_name('dst', item['dst_ips'], item['name'], error, template_name)
                    error, item['services'] = self.get_services(item['services'], item['name'], error)
                    error, item['users'] = self.get_names_users_and_groups(item['users'], item['name'], error, template_name)
                    error, item['time_restrictions'] = self.get_time_restrictions_name(item['time_restrictions'], item['name'], error, template_name)
                    error, item['cc_network_devices'] = self.get_network_devices(item['cc_network_devices'], item['name'], error, template_name)
                    if item['profiles']['idps']:
                        try:
                            item['profiles']['idps'] = self.mc_data['idps_profiles'][item['profiles']['idps']]
                        except KeyError:
                            self.stepChanged.emit(f'RED|    Error [Шаблон "{template_name}"]. Не найден профиль СОВ для правила "{item["name"]}" в данной группе шаблонов.')
                            item['profiles']['ipds'] = False
                            error = 1
                    if item['profiles']['l7']:
                        try:
                            item['profiles']['l7'] = self.mc_data['app_profiles'][item['profiles']['l7']]
                        except KeyError:
                            self.stepChanged.emit(f'RED|    Error [Шаблон "{template_name}"]. Не найден профиль приложений для правила "{item["name"]}" в данной группе шаблонов.')
                            item['profiles']['l7'] = False
                            error = 1
                    item['time_created'] = item['time_created'].replace('T', ' ').replace('Z', '')
                    item['time_updated'] = item.get('time_updated', '').replace('T', ' ').replace('Z', '')

                path = os.path.join(self.group_path, template_name, 'NetworkPolicies/Firewall')
                err, msg = self.create_dir(path)
                if err:
                    self.stepChanged.emit(f'RED|    {msg}')
                    self.stepChanged.emit(f'ORANGE|    Error [Шаблон "{template_name}"]. Не удалось создать директорию для экспорта правил МЭ.')
                    return 1

                json_file = os.path.join(path, 'config_firewall_rules.json')
                with open(json_file, 'w') as fh:
                    json.dump(data, fh, indent=4, ensure_ascii=False)

                if error:
                    self.stepChanged.emit(f'ORANGE|    [Шаблон "{template_name}"] Произошла ошибка при экспорте правил МЭ.')
                    self.error = 1
                else:
                    self.stepChanged.emit(f'GREEN|    [Шаблон "{template_name}"] Правила межсетевого экрана выгружены в файл "{json_file}".')
            else:
                self.stepChanged.emit(f'GRAY|    [Шаблон "{template_name}"] Нет правил межсетевого экрана для экспорта.')
        return 0


    def export_nat_rules(self):
        """Экспортируем список правил NAT"""
        self.stepChanged.emit('BLUE|Экспорт правил NAT из раздела "Политики сети/NAT и маршрутизация".')

        for template_id, template_name in self.templates.items():
            error = 0
            err, data = self.utm.get_dcfw_template_traffic_rules(template_id)
            if err:
                self.stepChanged.emit(f'RED|    {data}')
                self.stepChanged.emit(f'RED|    Error [Шаблон "{template_name}"]. Произошла ошибка при экспорте правил NAT.')
                return 1

            if data:
                for item in data:
                    item.pop('id', None)
                    item.pop('template_id', None)
                    item.pop('class', None)
                    error, item['zone_in'] = self.get_zones_name('src', item['zone_in'], item['name'], error, template_name)
                    error, item['zone_out'] = self.get_zones_name('dst', item['zone_out'], item['name'], error, template_name)
                    error, item['source_ip'] = self.get_ips_name('src', item['source_ip'], item['name'], error, template_name)
                    error, item['dest_ip'] = self.get_ips_name('dst', item['dest_ip'], item['name'], error, template_name)
                    error, item['service'] = self.get_services(item['service'], item['name'], error)
                    error, item['users'] = self.get_names_users_and_groups(item['users'], item['name'], error, template_name)
                    if item['gateway']:
                        try:
                            item['gateway'] = self.mc_data['gateways'][item['gateway']]
                        except KeyError:
                            self.stepChanged.emit(f'RED|    Error [Шаблон "{template_name}"].  Не найден шлюз для правила NAT "{item["name"]}" в этой группе шаблонов.')
                            error = 1
                    if 'cc_network_devices' in item:    # Если устройство не указано, то это поле не выводится.
                        error, item['cc_network_devices'] = self.get_network_devices(item['cc_network_devices'], item['name'], error, template_name)

                    item['time_created'] = item['time_created'].replace('T', ' ').replace('Z', '')
                    item['time_updated'] = item.get('time_updated', '').replace('T', ' ').replace('Z', '')

                path = os.path.join(self.group_path, template_name, 'NetworkPolicies/NATandRouting')
                err, msg = self.create_dir(path)
                if err:
                    self.stepChanged.emit(f'RED|    {msg}')
                    self.stepChanged.emit(f'ORANGE|    Error [Шаблон "{template_name}"]. Не удалось создать директорию для экспорта правил NAT.')
                    return 1

                json_file = os.path.join(path, 'config_nat_rules.json')
                with open(json_file, 'w') as fh:
                    json.dump(data, fh, indent=4, ensure_ascii=False)

                if error:
                    self.stepChanged.emit(f'ORANGE|    [Шаблон "{template_name}"] Произошла ошибка при экспорте правил NAT.')
                    self.error = 1
                else:
                    self.stepChanged.emit(f'GREEN|    [Шаблон "{template_name}"] Правила NAT выгружены в файл "{json_file}".')
            else:
                self.stepChanged.emit(f'GRAY|    [Шаблон "{template_name}"] Нет правил NAT для экспорта.')
        return 0


    def export_loadbalancing_rules(self):
        """Экспортируем список правил балансировки нагрузки"""
        self.stepChanged.emit('BLUE|Экспорт правил балансировки нагрузки из раздела "Политики сети/Балансировка нагрузки".')

        for template_id, template_name in self.templates.items():
            error = 0
            err, data = self.utm.get_dcfw_template_loadbalancing_rules(template_id)
            if err:
                self.stepChanged.emit(f'RED|    {data}')
                self.stepChanged.emit(f'RED|    Error [Шаблон "{template_name}"]. Произошла ошибка при экспорте правил балансировки нагрузки.')
                return 1

            if data:
                for item in data:
                    item.pop('id', None)
                    item.pop('guid', None)
                    item.pop('template_id', None)
                    error, item['src_zones'] = self.get_zones_name('src', item['src_zones'], item['name'], err, template_name)
                    error, item['src_ips'] = self.get_ips_name('src', item['src_ips'], item['name'], err, template_name)
                    error, item['cc_network_devices'] = self.get_network_devices(item['cc_network_devices'], item['name'], err, template_name)

                path = os.path.join(self.group_path, template_name, 'NetworkPolicies/LoadBalancing')
                err, msg = self.create_dir(path)
                if err:
                    self.stepChanged.emit(f'RED|    {msg}')
                    self.stepChanged.emit(f'ORANGE|    Error [Шаблон "{template_name}"]. Не удалось создать директорию для экспорта правил балансировки нагрузки.')
                    return 1

                json_file = os.path.join(path, 'config_loadbalancing_tcpudp.json')
                with open(json_file, 'w') as fh:
                    json.dump(data, fh, indent=4, ensure_ascii=False)

                if error:
                    self.stepChanged.emit(f'ORANGE|    [Шаблон "{template_name}"] Список балансировщиков TCP/UDP выгружен в файл "{json_file}" с ошибками.')
                    self.error = 1
                else:
                    self.stepChanged.emit(f'GREEN|    [Шаблон "{template_name}"] Список балансировщиков TCP/UDP выгружен в файл "{json_file}".')
            else:
                self.stepChanged.emit(f'GRAY|    [Шаблон "{template_name}"] Нет балансировщиков TCP/UDP для экспорта.')


    def export_shaper_rules(self):
        """Экспортируем список правил пропускной способности"""
        self.stepChanged.emit('BLUE|Экспорт правил пропускной способности из раздела "Политики сети/Пропускная способность".')

        for template_id, template_name in self.templates.items():
            error = 0
            err, data = self.utm.get_dcfw_template_shaper_rules(template_id)
            if err:
                self.stepChanged.emit(f'RED|    {data}')
                self.stepChanged.emit(f'RED|    Error [Шаблон "{template_name}"]. Произошла ошибка при экспорте правил пропускной способности.')
                return 1

            if data:
                for item in data:
                    item.pop('id', None)
                    item.pop('template_id', None)
                    item.pop('grid_position', None)
                    item.pop('active', None)
                    error, item['src_zones'] = self.get_zones_name('src', item['src_zones'], item['name'], error, template_name)
                    error, item['dst_zones'] = self.get_zones_name('dst', item['dst_zones'], item['name'], error, template_name)
                    error, item['src_ips'] = self.get_ips_name('src', item['src_ips'], item['name'], error, template_name)
                    error, item['dst_ips'] = self.get_ips_name('dst', item['dst_ips'], item['name'], error, template_name)
                    error, item['services'] = self.get_services(item['services'], item['name'], error)
                    error, item['users'] = self.get_names_users_and_groups(item['users'], item['name'], error, template_name)
                    error, item['time_restrictions'] = self.get_time_restrictions_name(item['time_restrictions'], item['name'], error, template_name)
                    error, item['apps'] = self.get_apps(item['apps'], item['name'], error, template_name)
                    error, item['cc_network_devices'] = self.get_network_devices(item['cc_network_devices'], item['name'], error, template_name)
                    try:
                        item['pool'] = self.mc_data['shapers'][item['pool']]
                    except KeyError:
                        self.stepChanged.emit(f'RED|    Error [Шаблон "{template_name}"]. Не найдена полоса пропускания для правила "{item["name"]}" в данной группе шаблонов.')
                        item['pool'] = False
                        error = 1

                path = os.path.join(self.group_path, template_name, 'NetworkPolicies/TrafficShaping')
                err, msg = self.create_dir(path)
                if err:
                    self.stepChanged.emit(f'RED|    {msg}')
                    self.stepChanged.emit(f'ORANGE|    Error [Шаблон "{template_name}"]. Не удалось создать директорию для экспорта правил пропускной способности.')
                    return 1

                json_file = os.path.join(path, 'config_shaper_rules.json')
                with open(json_file, 'w') as fh:
                    json.dump(data, fh, indent=4, ensure_ascii=False)

                if error:
                    self.stepChanged.emit(f'ORANGE|    [Шаблон "{template_name}"] Произошла ошибка при экспорте правил пропускной способности.')
                    self.error = 1
                else:
                    self.stepChanged.emit(f'GREEN|    [Шаблон "{template_name}"] Правила пропускной способности выгружены в файл "{json_file}".')
            else:
                self.stepChanged.emit(f'GRAY|    [Шаблон "{template_name}"] Нет правил пропускной способности для экспорта.')
        return 0


    #------------------------------------------------------- VPN ------------------------------------------------------------
    def export_vpnclient_security_profiles(self):
        """Экспортируем клиентские профили безопасности VPN."""
        self.stepChanged.emit('BLUE|Экспорт клиентских профилей безопасности VPN из раздела "VPN/Клиентские профили безопасности".')

        for template_id, template_name in self.templates.items():
            error = 0
            err, data = self.utm.get_dcfw_template_vpn_client_security_profiles(template_id)
            if err:
                self.stepChanged.emit(f'RED|    {data}')
                self.stepChanged.emit(f'RED|       Error [Шаблон "{template_name}"]. Произошла ошибка при экспорте клиентских профилей безопасности VPN.')
                return 1

            if data:
                for item in data:
                    self.mc_data['client_vpn_profiles'][item['id']] = item['name']
                    item.pop('id', None)
                    item.pop('template_id', None)
                    if item['certificate_id']:
                        error, item['certificate_id'] = self.get_certificate_name(item['certificate_id'], item['name'], error, template_name)

                path = os.path.join(self.group_path, template_name, 'VPN/ClientSecurityProfiles')
                err, msg = self.create_dir(path)
                if err:
                    self.stepChanged.emit(f'RED|    {msg}')
                    self.stepChanged.emit(f'ORANGE|       Error [Шаблон "{template_name}"]. Не удалось создать директорию для экспорта клиентских профилей безопасности VPN.')
                    return 1

                json_file = os.path.join(path, 'config_vpnclient_security_profiles.json')
                with open(json_file, 'w') as fh:
                    json.dump(data, fh, indent=4, ensure_ascii=False)

                if error:
                    self.stepChanged.emit(f'ORANGE|    [Шаблон "{template_name}"] Произошла ошибка при экспорте клиентских профилей безопасности VPN.')
                    self.error = 1
                else:
                    self.stepChanged.emit(f'GREEN|    [Шаблон "{template_name}"] Клиентские профили безопасности VPN выгружены в файл "{json_file}".')
            else:
                self.stepChanged.emit(f'GRAY|    [Шаблон "{template_name}"] Нет клиентских профилей безопасности VPN для экспорта.')
        return 0


    def export_vpnserver_security_profiles(self):
        """Экспортируем серверные профили безопасности VPN. Для версии 7.1 и выше"""
        self.stepChanged.emit('BLUE|Экспорт серверных профилей безопасности VPN из раздела "VPN/Серверные профили безопасности".')

        for template_id, template_name in self.templates.items():
            error = 0
            err, data = self.utm.get_dcfw_template_vpn_server_security_profiles(template_id)
            if err:
                self.stepChanged.emit(f'RED|    {data}')
                self.stepChanged.emit(f'RED|       Error [Шаблон "{template_name}"]. Произошла ошибка при экспорте серверных профилей безопасности VPN.')
                return 1

            if data:
                for item in data:
                    self.mc_data['server_vpn_profiles'][item['id']] = item['name']
                    item.pop('id', None)
                    item.pop('template_id', None)
                    if item['certificate_id']:
                        error, item['certificate_id'] = self.get_certificate_name(item['certificate_id'], item['name'], error, template_name)
                    try:
                        item['client_certificate_profile_id'] = self.mc_data['user_cert_profiles'][item['client_certificate_profile_id']]
                    except KeyError:
                        self.stepChanged.emit(f'RED|    Error [Правило "{item["name"]}"]. Не найден профиль клиентского сертификата для правила "{item["name"]}" в данной группе шаблонов.')
                        item['client_certificate_profile_id'] = 0
                        error = 1

                path = os.path.join(self.group_path, template_name, 'VPN/ServerSecurityProfiles')
                err, msg = self.create_dir(path)
                if err:
                    self.stepChanged.emit(f'RED|    {msg}')
                    self.stepChanged.emit(f'ORANGE|       Error [Шаблон "{template_name}"]. Не удалось создать директорию для экспорта серверных профилей безопасности VPN.')
                    return 1

                json_file = os.path.join(path, 'config_vpnserver_security_profiles.json')
                with open(json_file, 'w') as fh:
                    json.dump(data, fh, indent=4, ensure_ascii=False)

                if error:
                    self.stepChanged.emit(f'ORANGE|    [Шаблон "{template_name}"] Произошла ошибка при экспорте серверных профилей безопасности VPN.')
                    self.error = 1
                else:
                    self.stepChanged.emit(f'GREEN|    [Шаблон "{template_name}"] Серверные профили безопасности VPN выгружены в файл "{json_file}".')
            else:
                self.stepChanged.emit(f'GRAY|    [Шаблон "{template_name}"] Нет серверных профилей безопасности VPN для экспорта.')
        return 0


    def export_vpn_networks(self):
        """Экспортируем список сетей VPN"""
        self.stepChanged.emit('BLUE|Экспорт списка сетей VPN из раздела "VPN/Сети VPN".')

        for template_id, template_name in self.templates.items():
            error = 0
            err, data = self.utm.get_dcfw_template_vpn_networks(template_id)
            if err:
                self.stepChanged.emit(f'RED|    {data}')
                self.stepChanged.emit(f'RED|       Error [Шаблон "{template_name}"]. Произошла ошибка при экспорте сетей VPN.')
                return 1

            if data:
                for item in data:
                    self.mc_data['vpn_networks'][item['id']] = item['name']
                    item.pop('id', None)
                    item.pop('template_id', None)
                    for x in item['networks']:
                        if x[0] == 'list_id':
                            try:
                                x[1] = self.mc_data['ip_lists'][x[1]]
                            except KeyError:
                                self.stepChanged.emit(f'RED|    Error [Правило "{item["name"]}"]. Не найден маршрут VPN для сети VPN "{item["name"]}" в данной группе шаблонов.')
                                error = 1
                    for x in item['ep_routes_include']:
                        if x[0] == 'list_id':
                            try:
                                x[1] = self.mc_data['ip_lists'][x[1]]
                            except KeyError:
                                self.stepChanged.emit(f'RED|    Error [Правило "{item["name"]}"]. Не найден маршрут для UserGate Client в сети VPN "{item["name"]}" в данной группе шаблонов.')
                                error = 1
                    for x in item['ep_routes_exclude']:
                        if x[0] == 'list_id':
                            try:
                                x[1] = self.mc_data['ip_lists'][x[1]]
                            except KeyError:
                                self.stepChanged.emit(f'RED|    Error [Правило "{item["name"]}"]. Не найден маршрут для UserGate Client в сети VPN "{item["name"]}" в данной группе шаблонов.')
                                error = 1

                path = os.path.join(self.group_path, template_name, 'VPN/VPNNetworks')
                err, msg = self.create_dir(path)
                if err:
                    self.stepChanged.emit(f'RED|    {msg}')
                    self.stepChanged.emit(f'ORANGE|       Error [Шаблон "{template_name}"]. Не удалось создать директорию для экспорта сетей VPN.')
                    return 1

                json_file = os.path.join(path, 'config_vpn_networks.json')
                with open(json_file, 'w') as fh:
                    json.dump(data, fh, indent=4, ensure_ascii=False)

                if error:
                    self.stepChanged.emit(f'ORANGE|    [Шаблон "{template_name}"] Произошла ошибка при экспорте списка сетей VPN.')
                    self.error = 1
                else:
                    self.stepChanged.emit(f'GREEN|    [Шаблон "{template_name}"] Список сетей VPN выгружен в файл "{json_file}".')
            else:
                self.stepChanged.emit(f'GRAY|    [Шаблон "{template_name}"] Нет сетей VPN для экспорта.')
        return 0


    def export_vpn_client_rules(self):
        """Экспортируем список клиентских правил VPN"""
        self.stepChanged.emit('BLUE|Экспорт клиентских правил VPN из раздела "VPN/Клиентские правила".')

        for template_id, template_name in self.templates.items():
            error = 0
            err, data = self.utm.get_dcfw_template_vpn_client_rules(template_id)
            if err:
                self.stepChanged.emit(f'RED|    {data}')
                self.stepChanged.emit(f'RED|       Error [Шаблон "{template_name}"]. Произошла ошибка при экспорте клиентских правил VPN.')
                return 1

            if data:
                for item in data:
                    item.pop('id', None)
                    item.pop('template_id', None)
                    item.pop('last_error', None)
                    item.pop('status', None)
                    error, item['cc_network_devices'] = self.get_network_devices(item['cc_network_devices'], item['name'], error, template_name)
                    try:
                        item['security_profile_id'] = self.mc_data['client_vpn_profiles'][item['security_profile_id']]
                    except KeyError:
                        self.stepChanged.emit(f'RED|    Error [Правило "{item["name"]}"]. Не найден клиентский профиль безопасности VPN для правила "{item["name"]}" в данной группе шаблонов.')
                        item['security_profile_id'] = 0
                        error = 1

                path = os.path.join(self.group_path, template_name, 'VPN/ClientRules')
                err, msg = self.create_dir(path)
                if err:
                    self.stepChanged.emit(f'RED|    {msg}')
                    self.stepChanged.emit(f'ORANGE|       Error [Шаблон "{template_name}"]. Не удалось создать директорию для экспорта клиентских правил VPN.')
                    return 1

                json_file = os.path.join(path, 'config_vpn_client_rules.json')
                with open(json_file, 'w') as fh:
                    json.dump(data, fh, indent=4, ensure_ascii=False)

                if error:
                    self.stepChanged.emit(f'ORANGE|    [Шаблон "{template_name}"] Произошла ошибка при экспорте клиентских правил VPN.')
                    self.error = 1
                else:
                    self.stepChanged.emit(f'GREEN|    [Шаблон "{template_name}"] Клиентские правила VPN выгружены в файл "{json_file}".')
            else:
                self.stepChanged.emit(f'GRAY|    [Шаблон "{template_name}"] Нет клиентских правил VPN для экспорта.')
        return 0


    def export_vpn_server_rules(self):
        """Экспортируем список серверных правил VPN"""
        self.stepChanged.emit('BLUE|Экспорт серверных правил VPN из раздела "VPN/Серверные правила".')

        for template_id, template_name in self.templates.items():
            error = 0
            err, data = self.utm.get_dcfw_template_vpn_server_rules(template_id)
            if err:
                self.stepChanged.emit(f'RED|    {data}')
                self.stepChanged.emit(f'RED|       Error [Шаблон "{template_name}"]. Произошла ошибка при экспорте серверных правил VPN.')
                return 1

            if data:
                for item in data:
                    item.pop('id', None)
                    item.pop('template_id', None)
                    item.pop('grid_position', None)
                    error, item['src_zones'] = self.get_zones_name('src', item['src_zones'], item['name'], error, template_name)
                    error, item['source_ips'] = self.get_ips_name('src', item['source_ips'], item['name'], error, template_name)
                    error, item['dst_ips'] = self.get_ips_name('dst', item['dst_ips'], item['name'], error, template_name)
                    error, item['users'] = self.get_names_users_and_groups(item['users'], item['name'], error, template_name)
                    error, item['cc_network_devices'] = self.get_network_devices(item['cc_network_devices'], item['name'], error, template_name)
                    try:
                        item['security_profile_id'] = self.mc_data['server_vpn_profiles'][item['security_profile_id']]
                    except KeyError:
                        self.stepChanged.emit(f'RED|    Error [Правило "{item["name"]}"]. Не найден серверный профиль безопасности VPN для правила "{item["name"]}" в данной группе шаблонов.')
                        item['security_profile_id'] = 0
                        error = 1
                    if item['tunnel_id']:
                        try:
                            item['tunnel_id'] = self.mc_data['vpn_networks'][item['tunnel_id']]
                        except KeyError:
                            self.stepChanged.emit(f'RED|    Error [Правило "{item["name"]}"]. Не найдена сеть VPN для правила "{item["name"]}" в данной группе шаблонов.')
                            item['tunnel_id'] = False
                            error = 1
                    if item['auth_profile_id']:
                        try:
                            item['auth_profile_id'] = self.mc_data['auth_profiles'][item['auth_profile_id']]
                        except KeyError:
                            self.stepChanged.emit(f'RED|    Error [Правило "{item["name"]}"]. Не найден профиль аутентификации для правила "{item["name"]}" в данной группе шаблонов.')
                            item['auth_profile_id'] = False
                            error = 1

                path = os.path.join(self.group_path, template_name, 'VPN/ServerRules')
                err, msg = self.create_dir(path)
                if err:
                    self.stepChanged.emit(f'RED|    {msg}')
                    self.stepChanged.emit(f'ORANGE|       Error [Шаблон "{template_name}"]. Не удалось создать директорию для экспорта серверных правил VPN.')
                    return 1

                json_file = os.path.join(path, 'config_vpn_server_rules.json')
                with open(json_file, 'w') as fh:
                    json.dump(data, fh, indent=4, ensure_ascii=False)

                if error:
                    self.stepChanged.emit(f'ORANGE|    [Шаблон "{template_name}"] Произошла ошибка при экспорте серверных правил VPN.')
                    self.error = 1
                else:
                    self.stepChanged.emit(f'GREEN|    [Шаблон "{template_name}"] Серверные правила VPN выгружены в файл "{json_file}".')
            else:
                self.stepChanged.emit(f'GRAY|    [Шаблон "{template_name}"] Нет серверных правил VPN для экспорта.')
        return 0


    #------------------------------------- Диагностка и мониторинг -----------------------------------------------------------
    def export_notification_alert_rules(self):
        """Экспортируем список правил оповещений"""
        self.stepChanged.emit('BLUE|Экспорт правил оповещений из раздела "Диагностика и мониторинг/Правила оповещений".')

        for template_id, template_name in self.templates.items():
            error = 0
            err, data = self.utm.get_dcfw_template_notification_alert_rules(template_id)
            if err:
                self.stepChanged.emit(f'RED|    {data}')
                self.stepChanged.emit(f'ORANGE|       Error [Шаблон "{template_name}"]. Произошла ошибка при экспорте правил оповещений.')
                return 1

            if data:
                for item in data:
                    item.pop('id', None)
                    item.pop('template_id', None)
                    item.pop('cc', None)
                    try:
                        item['notification_profile_id'] = self.mc_data['notification_profiles'][item['notification_profile_id']]
                    except KeyError:
                        self.stepChanged.emit(f'RED|    Error [Правило "{item["name"]}"]. Не найден профиль оповещения для правила "{item["name"]}" в данной группе шаблонов.')
                        item['notification_profile_id'] = -1
                        error = 1
                    if item['emails']:
                        error, item['emails'] = self.get_email_groups(item['emails'], item['name'], error, template_name)
                    if item['phones']:
                        error, item['phones'] = self.get_phone_groups(item['phones'], item['name'], error, template_name)

                path = os.path.join(self.group_path, template_name, 'Notifications/AlertRules')
                err, msg = self.create_dir(path)
                if err:
                    self.stepChanged.emit(f'RED|    {msg}')
                    self.stepChanged.emit(f'ORANGE|       Error [Шаблон "{template_name}"]. Не удалось создать директорию для экспорта правил оповещений.')
                    return 1

                json_file = os.path.join(path, 'config_alert_rules.json')
                with open(json_file, 'w') as fh:
                    json.dump(data, fh, indent=4, ensure_ascii=False)

                if error:
                    self.stepChanged.emit(f'ORANGE|    [Шаблон "{template_name}"] Произошла ошибка при экспорте правил оповещений.')
                    self.error = 1
                else:
                    self.stepChanged.emit(f'GREEN|    [Шаблон "{template_name}"] Правила оповещений выгружены в файл "{json_file}".')
            else:
                self.stepChanged.emit(f'GRAY|    [Шаблон "{template_name}"] Нет правил оповещений для экспорта.')
        return 0


    def export_snmp_security_profiles(self):
        """Экспортируем профили безопасности SNMP."""
        self.stepChanged.emit('BLUE|Экспорт профилей безопасности SNMP из раздела "Диагностика и мониторинг/Профили безопасности SNMP".')

        for template_id, template_name in self.templates.items():
            err, data = self.utm.get_dcfw_template_snmp_security_profiles(template_id)
            if err:
                self.stepChanged.emit(f'RED|    {data}')
                self.stepChanged.emit(f'ORANGE|       Error [Шаблон "{template_name}"]. Произошла ошибка при экспорте профилей безопасности SNMP.')
                return 1

            if data:
                for item in data:
                    self.mc_data['snmp_security_profiles'][item['id']] = item['name']
                    item.pop('id', None)
                    item.pop('template_id', None)
                    item.pop('cc', None)
                    item.pop('readonly', None)

                path = os.path.join(self.group_path, template_name, 'Notifications/SNMPSecurityProfiles')
                err, msg = self.create_dir(path)
                if err:
                    self.stepChanged.emit(f'RED|    {msg}')
                    self.stepChanged.emit(f'ORANGE|       Error [Шаблон "{template_name}"]. Не удалось создать директорию для экспорта профилей безопасности SNMP.')
                    return 1

                json_file = os.path.join(path, 'config_snmp_profiles.json')
                with open(json_file, 'w') as fh:
                    json.dump(data, fh, indent=4, ensure_ascii=False)
                self.stepChanged.emit(f'GREEN|    [Шаблон "{template_name}"] Профили безопасности SNMP выгружены в файл "{json_file}".')
            else:
                self.stepChanged.emit(f'GRAY|    [Шаблон "{template_name}"] Нет профилей безопасности SNMP для экспорта.')


    def export_snmp_rules(self):
        """Экспортируем список правил SNMP"""
        self.stepChanged.emit('BLUE|Экспорт списка правил SNMP из раздела "Диагностика и мониторинг/SNMP".')

        for template_id, template_name in self.templates.items():
            error = 0
            err, data = self.utm.get_dcfw_template_snmp_rules(template_id)
            if err:
                self.stepChanged.emit(f'RED|    {data}')
                self.stepChanged.emit(f'ORANGE|       Error [Шаблон "{template_name}"]. Произошла ошибка при экспорте правил SNMP.')
                return 1

            if data:
                for item in data:
                    item.pop('id', None)
                    item.pop('template_id', None)
                    item.pop('cc', None)
                    if item['snmp_security_profile']:
                        try:
                            item['snmp_security_profile'] = self.mc_data['snmp_security_profiles'][item['snmp_security_profile']]
                        except KeyError:
                            self.stepChanged.emit(f'RED|    Error [Правило "{item["name"]}"]. Не найден профиль безопасности SNMP для правила "{item["name"]}" в данной группе шаблонов.')
                            item['snmp_security_profile'] = 0
                            error = 1

                path = os.path.join(self.group_path, template_name, 'Notifications/SNMP')
                err, msg = self.create_dir(path)
                if err:
                    self.stepChanged.emit(f'RED|    {msg}')
                    self.stepChanged.emit(f'ORANGE|       Error [Шаблон "{template_name}"]. Не удалось создать директорию для экспорта правил SNMP.')
                    return 1

                json_file = os.path.join(path, 'config_snmp_rules.json')
                with open(json_file, 'w') as fh:
                    json.dump(data, fh, indent=4, ensure_ascii=False)

                if error:
                    self.stepChanged.emit(f'ORANGE|    [Шаблон "{template_name}"] Произошла ошибка при экспорте правил SNMP.')
                    self.error = 1
                else:
                    self.stepChanged.emit(f'GREEN|    [Шаблон "{template_name}"] Список правил SNMP выгружен в файл "{json_file}".')
            else:
                self.stepChanged.emit(f'GRAY|    [Шаблон "{template_name}"] Нет правил SNMP для экспорта.')


    def export_snmp_settings(self):
        """Экспортируем параметры SNMP"""
        self.stepChanged.emit('BLUE|Экспорт параметров SNMP из раздела "Диагностика и мониторинг/Параметры SNMP".')

        for template_id, template_name in self.templates.items():
            err, data = self.utm.get_dcfw_template_snmp_parameters(template_id)
            if err:
                self.stepChanged.emit(f'RED|    {data}')
                self.stepChanged.emit(f'ORANGE|       Error [Шаблон "{template_name}"]. Произошла ошибка при экспорте параметров SNMP.')
                return 1

            if data:
                for item in data:
                    item.pop('id', None)
                    item.pop('template_id', None)
            
                path = os.path.join(self.group_path, template_name, 'Notifications/SNMPParameters')
                err, msg = self.create_dir(path)
                if err:
                    self.stepChanged.emit(f'RED|    {msg}')
                    self.stepChanged.emit(f'ORANGE|       Error [Шаблон "{template_name}"]. Не удалось создать директорию для экспорта параметров SNMP.')
                    return 1

                json_file = os.path.join(path, 'config_snmp_params.json')
                with open(json_file, 'w') as fh:
                    json.dump(data, fh, indent=4, ensure_ascii=False)
                self.stepChanged.emit(f'GREEN|    [Шаблон "{template_name}"] Параметры SNMP выгружены в файл "{json_file}".')
            else:
                self.stepChanged.emit(f'GRAY|    [Шаблон "{template_name}"] Нет параметров SNMP для экспорта.')


    #--------------------------------------------- Служебные функции -------------------------------------------------------
    def get_ips_name(self, mode, rule_ips, rule_name, error, template_name):
        """Получаем имена списков IP-адресов, URL-листов и GeoIP. Если списки не существует на MC, то они пропускаются."""
        new_rule_ips = []
        for ips in rule_ips:
            if ips[0] == 'geoip_code':
                new_rule_ips.append(ips)
            try:
                if ips[0] == 'list_id':
                    new_rule_ips.append(['list_id', self.mc_data['ip_lists'][ips[1]]])
                elif ips[0] == 'urllist_id':
                    new_rule_ips.append(['urllist_id', self.mc_data['url_lists'][ips[1]]])
            except KeyError as err:
                self.stepChanged.emit(f'RED|    Error [Шаблон "{template_name}"]. Не найден список {mode}-адресов c {ips[0].upper()}: {ips[1]} для правила "{rule_name}".')
                self.stepChanged.emit(f'bRED|       Возможно данный список находится в шаблоне не входящим в эту группу шаблонов.')
                error = 1
        return error, new_rule_ips


    def get_zones_name(self, mode, zones, rule_name, error, template_name):
        """Получаем имена зон. Если зона не существует на MC, то она пропускается."""
        new_zones = []
        for zone_id in zones:
            try:
                new_zones.append(self.mc_data['zones'][zone_id])
            except KeyError as err:
                self.stepChanged.emit(f'RED|    Error [Шаблон "{template_name}"]. Не найдена {mode}-зона c ID: {zone_id} для правила "{rule_name}" в данной группе шаблонов.')
                error = 1
        return error, new_zones


    def get_urls_name(self, urls, rule_name, error, template_name):
        """Получаем имена списков URL. Если список не существует на MC, то он пропускается."""
        new_urls = []
        for url_id in urls:
            try:
                new_urls.append(self.mc_data['url_lists'][url_id])
            except KeyError as err:
                self.stepChanged.emit(f'RED|    Error [Шаблон "{template_name}"]. Не найден список URL c ID: {url_id} для правила "{rule_name}".')
                self.stepChanged.emit(f'bRED|       Возможно данный список находится в шаблоне не входящим в эту группу шаблонов.')
                error = 1
        return error, new_urls


    def get_url_categories_name(self, url_categories, rule_name, error, template_name):
        """Получаем имена категорий URL и групп категорий URL. Если список не существует на MC, то он пропускается."""
        new_urls = []
        for arr in url_categories:
            try:
                if arr[0] == 'list_id':
                    new_urls.append(['list_id', self.mc_data['url_categorygroups'][arr[1]]])
                elif arr[0] == 'category_id':
                    new_urls.append(['category_id', self.mc_data['url_categories'][arr[1]]])
            except KeyError as err:
                self.stepChanged.emit(f'RED|    Error [Шаблон "{template_name}"]. Не найдена категория URL {err} для правила "{rule_name}" в данной группе шаблонов.')
                error = 1
        return error, new_urls


    def get_time_restrictions_name(self, times, rule_name, error, template_name):
        """Получаем имена календарей. Если не существуют на MC, то пропускаются."""
        new_times = []
        for cal_id in times:
            try:
                new_times.append(self.mc_data['calendars'][cal_id])
            except KeyError as err:
                self.stepChanged.emit(f'RED|    Error [Шаблон "{template_name}"]. Не найден календарь c ID: {cal_id} для правила "{rule_name}" в данной группе шаблонов.')
                error = 1
        return error, new_times


    def get_useragent_names(self, user_agents, rule_name, error, template_name):
        """Получаем имена User Agents. Если не существуют на MC, то пропускаются."""
        new_user_agents = []
        for item in user_agents:
            try:
                item[1] = self.mc_data['useragents'][item[1]]
                new_user_agents.append(item)
            except KeyError:
                self.stepChanged.emit(f'RED|    Error [Шаблон "{template_name}"]. Не найден Useragent для правила "{rule_name}" в данной группе шаблонов.')
                error = 1
        return error, new_user_agents


    def get_names_users_and_groups(self, users, rule_name, error, template_name):
        """Получаем имена групп и пользователей по их GUID."""
        new_users = []
        guids = {'user': [], 'group': []}
        for item in users:
            match item[0]:
                case 'special':
                    new_users.append(item)
                case 'user':
                    guids['user'].append(item[1])
                case 'group':
                    guids['group'].append(item[1])
        err, result = self.utm.get_dcfw_object_names(query=guids)
        if err:
            self.stepChanged.emit(f'RED|    {result}')
            self.stepChanged.emit(f'RED|    Error [Шаблон "{template_name}"]. Не удалось получить список пользователей для правила "{rule_name}".')
            error = 1
        else:
            for item in result['user']:
                item[0] = 'user'
                new_users.append(item)
            for item in result['group']:
                item[0] = 'group'
                new_users.append(item)

        return error, new_users


    def get_services(self, service_list, rule_name, error):
        """Получаем имена сервисов по их ID. Если сервис не найден, то он пропускается."""
        new_service_list = []
        for item in service_list:
            try:
                new_service_list.append(['service', self.mc_data['services'][item[1]]] if item[0] == 'service' else ['list_id', self.mc_data['service_groups'][item[1]]])
            except KeyError as err:
                self.stepChanged.emit(f'RED|    Error [Rule: "{rule_name}"]. Не найден сервис или группа сервисов "{item}" в данной группе шаблонов.')
                error = 1
        return error, new_service_list


    def get_email_groups(self, email_groups, rule_name, error, template_name):
        """Получаем имена групп почтовых адресов по их ID. Если группа не найдена, то она пропускается."""
        new_email_groups = []
        for x in email_groups:
            try:
                new_email_groups.append(['list_id', self.mc_data['email_groups'][x[1]]])
            except KeyError:
                self.stepChanged.emit(f'RED|    Error [Шаблон "{template_name}"]. Не найдена группа почтовых адресов для правила "{rule_name}" в данной группе шаблонов.')
                error = 1
        return error, new_email_groups


    def get_phone_groups(self, phone_groups, rule_name, error, template_name):
        """Получаем имена групп телефонных номеров по их ID. Если группа не найдена, то она пропускается."""
        new_phone_groups = []
        for x in phone_groups:
            try:
                new_phone_groups.append(['list_id', self.mc_data['phone_groups'][x[1]]])
            except KeyError:
                self.stepChanged.emit(f'RED|    Error [Правило "{item["name"]}"]. Не найдена группа номеров телефонов для правила "{rule_name}" в данной группе шаблонов.')
                error = 1
        return error, new_phone_groups


    def get_network_devices(self, devices, rule_name, error, template_name):
        """Получаем имена устройств по их ID. Если устройство не найдено, то оно пропускается."""
        devices_list = []
        for item in devices:
            try:
                devices_list.append(self.mc_data['devices_list'][item])
            except KeyError:
                self.stepChanged.emit(f'RED|    Error [Шаблон "{template_name}"]. Не найдено устройство для правила "{rule_name}".')
                error = 1
        return error, devices_list


    def get_apps(self, array_apps, rule_name, error, template_name):
        """Определяем имя приложения или группы приложений по ID."""
        new_app_list = []
        for app in array_apps:
            if app[0] == 'ro_group':
                if app[1] == 0:
                    new_app_list.append(['ro_group', 'All'])
                else:
                    try:
                        new_app_list.append(['ro_group', self.mc_data['l7_categories'][app[1]]])
                    except KeyError as err:
                        self.stepChanged.emit(f'RED|    Error [Шаблон "{template_name}"]. Не найдена категория l7 "{app}" для правила "{rule_name}".')
                        self.stepChanged.emit(f'ORANGE|       Возможно нет лицензии и UTM не получил список категорий l7. Установите лицензию и повторите попытку.')
                        error = 1
            elif app[0] == 'group':
                try:
                    new_app_list.append(['group', self.mc_data['app_groups'][app[1]]])
                except KeyError as err:
                    self.stepChanged.emit(f'RED|    Error [Шаблон "{template_name}"]. Не найдена группа приложений l7 id: {err} для правила "{rule_name}".')
                    error = 1
            elif app[0] == 'app':
                try:
                    new_app_list.append(['app', self.mc_data['l7_apps'][app[1]]])
                except KeyError as err:
                    self.stepChanged.emit(f'RED|    Error [Шаблон "{template_name}"]. Не найдено приложение id: {err} для правила "{rule_name}".')
                    self.stepChanged.emit(f'ORANGE|       Возможно нет лицензии и UTM не получил список приложений l7. Установите лицензию и повторите попытку.')
                    error = 1
        return error, new_app_list


    def get_ssl_profile_name(self, ssl_profile_id, error_value, rule_name, error, template_name):
        """
        Получаем имя профиля SSL по его ID. Если профиль не найден,
        возвращается error_value, так как в разные правила надо возвращать разные значения (0, -1, '').
        """
        try:
            ssl_profile_name = self.mc_data['ssl_profiles'][ssl_profile_id]
        except KeyError:
            self.stepChanged.emit(f'RED|    Error [Шаблон "{template_name}"]. Не найден профиль SSL для правила "{rule_name}" в данной группе шаблонов.')
            return 1, error_value
        return error, ssl_profile_name


    def get_certificate_name(self, certificate_id, rule_name, error, template_name):
        """Получаем имя сертификата по его ID. Если сертификат не найден, возвращается 0."""
        try:
            certificate_name = self.mc_data['certs'][certificate_id]
        except KeyError:
            self.stepChanged.emit(f'RED|    Error [Шаблон "{template_name}"]. Не найден сертификат для правила "{rule_name}" в данной группе шаблонов.')
            return 1, 0
        return error, certificate_name


    def get_library_data(self):
        """Получаем часто используемые данные из библиотек группы шаблонов DCFW."""

        # Получаем список всех активных LDAP-серверов области
        self.stepChanged.emit(f'BLACK|    Получаем список активных LDAP-серверов в каталогах пользователей области.')
        err, result = self.utm.get_usercatalog_ldap_servers()
        if err:
            self.stepChanged.emit(f'RED|    {result}')
            return 1
        elif result:
            err, result2 = self.utm.get_usercatalog_servers_status()
            if err:
                self.stepChanged.emit(f'RED|       {result2}')
            else:
                servers_status = {x['id']: x['status'] for x in result2}
                for srv in result:
                    if servers_status[srv['id']] == 'connected':
                        for domain in srv['domains']:
                            self.mc_data['ldap_servers'][domain.lower()] = srv['id']
                        self.stepChanged.emit(f'GREEN|       LDAP-коннектор "{srv["name"]}" - статус: "connected".')
                    else:
                        self.stepChanged.emit(f'GRAY|       LDAP-коннектор "{srv["name"]}" имеет не корректный статус: "{servers_status[srv["id"]]}".')
        if not self.mc_data['ldap_servers']:
            self.stepChanged.emit('NOTE|       Нет доступных LDAP-серверов в каталогах пользователей области. Доменные пользователи не будут импортированы.')

        # Получаем список предопределёных категорий URL
        self.stepChanged.emit(f'BLACK|    Получаем список категорий URL.')
        err, result = self.utm.get_url_categories()
        if err:
            self.stepChanged.emit(f'RED|    {result}')
            return 1
        else:
            self.mc_data['url_categories'] = {x['id']: x['name'] for x in result}

        # Получаем список приложений l7 из первого шаблона в группе
        self.stepChanged.emit(f'BLACK|    Получаем список приложений l7.')
        for uid, name in self.templates.items():
            err, result = self.utm.get_dcfw_template_app_signatures(uid)
            if err:
                self.stepChanged.emit(f'RED|    {result}')
                return 1
            if result:
                for x in result:
                    self.mc_data['l7_apps'][x['id']] = x['name']
                break

        # Получаем список предопределённых категорий приложений l7
        self.stepChanged.emit(f'BLACK|    Получаем список категорий приложений l7.')
        err, result = self.utm.get_dcfw_l7_categories()
        if err:
            self.stepChanged.emit(f'RED|    {result}')
            return 1
        else:
            self.mc_data['l7_categories'] = {x['id']: x['name'] for x in result}

