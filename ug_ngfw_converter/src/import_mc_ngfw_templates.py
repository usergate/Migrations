#!/usr/bin/env python3
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
# Импорт ранее экспортированной группы шаблонов на UserGate Management Center версии 7 и выше.
# Версия 1.8   24.11.2025
#

import os, sys, json
import copy
from PyQt6.QtCore import QThread, pyqtSignal
from common_classes import MyMixedService, UsercatalogLdapServers, BaseObject, BaseAppObject
from services import certs_role


class ImportMcNgfwTemplates(QThread, MyMixedService, UsercatalogLdapServers):
    """Импортируем разделы конфигурации в шаблон МС"""
    stepChanged = pyqtSignal(str)

    def __init__(self, utm, device_type=None, base_path=None, device_groups=None, selected_group=None, selected_templates=None):
        super().__init__()
        self.utm = utm
        self.realm = self.utm._login.split('/')[1]
        self.base_path = base_path
        self.device_groups = device_groups
        self.selected_group = selected_group
        self.selected_templates = selected_templates
        self.realm_templates = {}
        self.groups = {}
        self.group_templates = {}
        self.template_config_section_paths = {}
        self.error = 0

        self.mc_data = {
            'ip_lists': {
                'BOTNET_BLACK_LIST': BaseObject(id='id-BOTNET_BLACK_LIST', template_id='', template_name=''),
                'BANKS_IP_LIST': BaseObject(id='id-BANKS_IP_LIST', template_id='', template_name=''),
                'ZAPRET_INFO_BLACK_LIST_IP': BaseObject(id='id-ZAPRET_INFO_BLACK_LIST_IP', template_id='', template_name=''),
            },
            'mime': {
                'MIME_CAT_APPLICATIONS': BaseObject(id='id-MIME_CAT_APPLICATIONS', template_id='', template_name=''),
                'MIME_CAT_DOCUMENTS': BaseObject(id='id-MIME_CAT_DOCUMENTS', template_id='', template_name=''),
                'MIME_CAT_IMAGES': BaseObject(id='id-MIME_CAT_IMAGES', template_id='', template_name=''),
                'MIME_CAT_JAVASCRIPT': BaseObject(id='id-MIME_CAT_JAVASCRIPT', template_id='', template_name=''),
                'MIME_CAT_SOUNDS': BaseObject(id='id-MIME_CAT_SOUNDS', template_id='', template_name=''),
                'MIME_CAT_VIDEO': BaseObject(id='id-MIME_CAT_VIDEO', template_id='', template_name=''),
            },
            'url_lists': {
                'ENTENSYS_WHITE_LIST': BaseObject(id='id-ENTENSYS_WHITE_LIST', template_id='', template_name=''),
                'BAD_SEARCH_BLACK_LIST': BaseObject(id='id-BAD_SEARCH_BLACK_LIST', template_id='', template_name=''),
                'ENTENSYS_BLACK_LIST': BaseObject(id='id-ENTENSYS_BLACK_LIST', template_id='', template_name=''),
                'ENTENSYS_KAZ_BLACK_LIST': BaseObject(id='id-ENTENSYS_KAZ_BLACK_LIST', template_id='', template_name=''),
                'FISHING_BLACK_LIST': BaseObject(id='id-FISHING_BLACK_LIST', template_id='', template_name=''),
                'ZAPRET_INFO_BLACK_LIST': BaseObject(id='id-ZAPRET_INFO_BLACK_LIST', template_id='', template_name=''),
                'ZAPRET_INFO_BLACK_LIST_DOMAIN': BaseObject(id='id-ZAPRET_INFO_BLACK_LIST_DOMAIN', template_id='', template_name=''),
            },
            'ug_morphology': ('MORPH_CAT_BADWORDS', 'MORPH_CAT_DLP_ACCOUNTING',
                'MORPH_CAT_DLP_FINANCE', 'MORPH_CAT_DLP_LEGAL', 'MORPH_CAT_DLP_MARKETING', 'MORPH_CAT_DLP_PERSONAL',
                'MORPH_CAT_DRUGSWORDS', 'MORPH_CAT_FZ_436', 'MORPH_CAT_GAMBLING', 'MORPH_CAT_KAZAKHSTAN',
                'MORPH_CAT_MINJUSTWORDS', 'MORPH_CAT_PORNOWORDS', 'MORPH_CAT_SUICIDEWORDS', 'MORPH_CAT_TERRORWORDS'),
            'ug_useragents': (
                'USERAGENT_ANDROID',
                'USERAGENT_APPLE',
                'USERAGENT_BLACKBERRY',
                'USERAGENT_CHROMEGENERIC',
                'USERAGENT_CHROMEOS',
                'USERAGENT_CHROMIUM',
                'USERAGENT_EDGE',
                'USERAGENT_FFGENERIC',
                'USERAGENT_IE',
                'USERAGENT_IOS',
                'USERAGENT_LINUX',
                'USERAGENT_MACOS',
                'USERAGENT_MOBILESAFARI',
                'USERAGENT_OPERA',
                'USERAGENT_SAFARIGENERIC',
                'USERAGENT_SPIDER',
                'USERAGENT_UCBROWSER',
                'USERAGENT_WIN',
                'USERAGENT_WINPHONE',
                'USERAGENT_YABROWSER'
            )
        }
        self.convert_mc_url_categorygroups = {
            'mc parental control': 'MC Parental control',
            'mc productivity': 'MC Productivity',
            'mc recommended for morphology checking': 'MC Recommended for morphology checking',
            'mc recommended for virus check': 'MC Recommended for virus check',
            'mc safe categories': 'MC Safe categories',
            'mc threats': 'MC Threats'
        }
        self.import_library_funcs = {
            'Morphology': self.import_morphology_lists,
            'Services': self.import_services_list,
            'ServicesGroups': self.import_services_groups,
            'IPAddresses': self.import_ip_lists,
            'Useragents': self.import_useragent_lists,
            'ContentTypes': self.import_mime_lists,
            'URLLists': self.import_url_lists,
            'TimeSets': self.import_time_restricted_lists,
            'BandwidthPools': self.import_shaper_list,
            'ResponcePages': self.import_templates_list,
            'URLCategories': self.import_url_categories,
            'OverURLCategories': self.import_custom_url_category,
            'Applications': self.import_application_signature,
            'ApplicationProfiles': self.import_app_profiles,
            'ApplicationGroups': self.import_application_groups,
            'Emails': self.import_email_groups,
            'Phones': self.import_phone_groups,
            'IDPSSignatures': self.import_custom_idps_signature,
            'IDPSProfiles': self.import_idps_profiles,
            'NotificationProfiles': self.import_notification_profiles,
            'NetflowProfiles': self.import_netflow_profiles,
            'LLDPProfiles': self.import_lldp_profiles,
            'SSLProfiles': self.import_ssl_profiles,
            'SSLForwardingProfiles': self.import_ssl_forward_profiles,
            'HIPObjects': self.import_hip_objects,
            'HIPProfiles': self.import_hip_profiles,
            'BfdProfiles': self.import_bfd_profiles,
            'UserIdAgentSyslogFilters': self.import_useridagent_syslog_filters,
            'Scenarios': self.import_scenarios,
            'Certificates': self.import_certificates,
            'Groups': self.import_local_groups,
            'SNMPSecurityProfiles': self.import_snmp_security_profiles,

        }
        self.import_shared_1 = {
            'MFAProfiles': self.import_2fa_profiles,
            'Zones': self.import_zones,
            'Interfaces': self.import_interfaces,
            'Gateways': self.import_gateways,
            'UserCertificateProfiles': self.import_client_certificate_profiles,
            'Users': self.import_local_users,
            'AuthServers': self.import_auth_servers,
            'ICAPServers': self.import_icap_servers,
            'ReverseProxyServers': self.import_reverseproxy_servers,
        }
        self.import_shared_2 = {
            'AuthProfiles': self.import_auth_profiles,
        }
        self.import_shared_3 = {
            'CaptiveProfiles': self.import_captive_profiles,
            'ServerSecurityProfiles': self.import_vpnserver_security_profiles,
            'ClientSecurityProfiles': self.import_vpnclient_security_profiles,
            'VPNNetworks': self.import_vpn_networks,
            'LoadBalancing': self.import_loadbalancing_rules,
        }
        self.import_funcs = {
            'DNS': self.import_dns_config,
            'DHCP': self.import_dhcp_subnets,
            'VRF': self.import_vrf,
            'WCCP': self.import_wccp_rules,
            'GeneralSettings': self.import_general_settings,
            'DeviceManagement': self.pass_function,
            'Administrators': self.import_administrators,
            'CaptivePortal': self.import_captive_portal_rules,
            'TerminalServers': self.import_terminal_servers,
            'UserIDagent': self.import_userid_agent,
            'Firewall': self.import_firewall_rules,
            'NATandRouting': self.import_nat_rules,
            'TrafficShaping': self.import_shaper_rules,
            'ContentFiltering': self.import_content_rules,
            'SafeBrowsing': self.import_safebrowsing_rules,
            'TunnelInspection': self.import_tunnel_inspection_rules,
            'SSLInspection': self.import_ssldecrypt_rules,
            'SSHInspection': self.import_sshdecrypt_rules,
            'MailSecurity': self.import_mailsecurity,
            'ICAPRules': self.import_icap_rules,
            'DoSProfiles': self.import_dos_profiles,
            'DoSRules': self.import_dos_rules,
            'WebPortal': self.import_proxyportal_rules,
            'ReverseProxyRules': self.import_reverseproxy_rules,
            'UpstreamProxiesServers': self.import_upstream_proxies_servers,
            'UpstreamProxiesProfiles': self.import_upstream_proxies_profiles,
            'UpstreamProxiesRules': self.import_upstream_proxies_rules,
            'ServerRules': self.import_vpn_server_rules,
            'ClientRules': self.import_vpn_client_rules,
            'AlertRules': self.import_notification_alert_rules,
            'SNMPParameters': self.import_snmp_settings,
            'SNMP': self.import_snmp_rules,
        }


    def run(self):
        """Импортируем разделы конфигурации"""
        if self.device_groups:
            """Импортируем все групы с шаблонами данного раздела"""
            path_dict = {}
            return
#            for item in self.all_points:
#                top_level_path = os.path.join(self.config_path, item['path'])
#                for point in item['points']:
#                    path_dict[point] = os.path.join(top_level_path, point)
#            for key, value in self.import_funcs.items():
#                if key in path_dict:
#                    value(path_dict[key])
        else:
            """
            Импортируем шаблоны определённой группы:
            1. Проверяем существует ли данная группа шаблонов. Если не существует, то создаём её.
            2. Идём по списку шаблонов. Проверяем что такого шаблона нет в группе. Если нет, создаём, иначе пропускаем.
            3. Импортируем шаблон.
            """
            self.stepChanged.emit(f'BLUE|Импорт группы шаблонов "{self.selected_group}" в раздел "NGFW".')
            self.get_groups_templates()     # Получаем группы шаблонов области и шаблоны каждой группы (self.groups, self.group_templates).
            if self.error:
                self.stepChanged.emit('ORANGE|Импорт конфигурации прерван.')
                return
            if self.selected_group in self.groups:
                self.stepChanged.emit(f'GRAY|    Группа шаблонов "{self.selected_group}" уже существует.')
            else:
                err, result = self.utm.add_device_templates_group({'name': self.selected_group})
                if err:
                    self.stepChanged.emit(f'RED|    {result}.')
                    self.stepChanged.emit('ORANGE|    Импорт конфигурации прерван.')
                    return
                self.groups[self.selected_group] = result
                self.group_templates[self.selected_group] = {}
                self.stepChanged.emit(f'GREEN|    Создана группа шаблонов "{self.selected_group}".')

            if self.selected_templates:
                for template in self.selected_templates:
                    self.stepChanged.emit(f'LBLUE|Проверяем отсутствие шаблона "{template}" в группе шаблонов "{self.selected_group}" и области "{self.realm}".')
                    if template in self.group_templates[self.selected_group]:
                        self.stepChanged.emit(f'ORANGE|    Warning: Шаблон "{template}" уже существует в группе шаблонов "{self.selected_group}".')
                        self.error = 2
                    elif template in list(self.realm_templates.values()):
                        self.stepChanged.emit(f'ORANGE|    Warning: Шаблон "{template}" уже существует в области "{self.realm}".')
                        self.error = 2

                if not self.error:
                    for template in self.selected_templates:
                        err, result = self.utm.add_device_template({'name': template})
                        if err:
                            self.stepChanged.emit(f'RED|    {result}.')
                            self.stepChanged.emit('ORANGE|    Импорт конфигурации прерван.')
                            return
                        template_id = result    # Запоминаем ID текущего шаблона
                        self.group_templates[self.selected_group][template] = template_id
                        self.stepChanged.emit(f'BLUE|Создан шаблон "{template}" в области "{self.realm}".')

                        group_info = {
                            'name': self.selected_group,
                            'device_templates': [[template_id, True] for template_id in self.group_templates[self.selected_group].values()]
                        }
                        err, result = self.utm.update_device_templates_group(self.groups[self.selected_group], group_info)
                        if err:
                            self.stepChanged.emit(f'RED|    {result}.')
                            self.stepChanged.emit('ORANGE|    Импорт конфигурации прерван.')
                            return
                        self.stepChanged.emit(f'BLACK|    Шаблон "{template}" добавлен в группу шаблонов "{self.selected_group}".')

                        path_dict = {}
                        template_path = os.path.join(self.base_path, self.selected_group, template)
                        for dir1 in os.listdir(template_path):
                            dir1_path = os.path.join(template_path, dir1)
                            if os.path.isdir(dir1_path):
                                for dir2 in os.listdir(dir1_path):
                                    current_path = os.path.join(dir1_path, dir2)
                                    if os.path.isdir(current_path):
                                        path_dict[dir2] = current_path
                        if path_dict:
                            self.template_config_section_paths[template] = path_dict
                        else:
                            self.stepChanged.emit(f'GRAY|    Каталог "{template_path}" пуст.')

#                        print('\n', 'self.groups: ', self.groups)
#                        print('\n', 'self.group_templates: ', self.group_templates, '\n')

                    self.get_ldap_servers()  # Получаем список всех активных LDAP-серверов области.
                    self.get_library_data()  # Получаем часто используемые данные из библиотек всех шаблонов группы шаблонов
                    self.import_ngfw_devices()  # Импортируем устройства NGFW

                    for section in (self.import_library_funcs, self.import_shared_1, self.import_shared_2, self.import_shared_3, self.import_funcs):
                        for template in self.selected_templates:
                            self.stepChanged.emit(f'TEST|\nИмпортируем разделы конфигурации в шаблон "{template}".')
                            if (path_dict := self.template_config_section_paths.get(template, False)):
                                template_id = self.group_templates[self.selected_group][template]
                                for key, value in section.items():
                                    if key in path_dict:
                                        value(path_dict[key], template_id, template)
            else:
                self.stepChanged.emit(f'GRAY|    В группе шаблонов "{self.selected_group}" нет шаблонов для импорта.')
                
        if self.error == 1:
            self.stepChanged.emit('iORANGE|\nИмпорт конфигурации прошёл с ошибками!\n')
        elif self.error == 2:
            self.stepChanged.emit('iORANGE|\nИмпорт конфигурации прерван. Удалите эти шаблоны или переименуйте имортируемые и повторите импорт.\n')
        else:
            self.stepChanged.emit('iGREEN|\nИмпорт конфигурации завершён.\n')


    def get_groups_templates(self):
        """Получаем группы шаблонов области и шаблоны каждой группы"""
        err, result = self.utm.get_device_templates()
        if err:
            self.stepChanged.emit('iRED|Не удалось получить список шаблонов области.')
            self.stepChanged.emit(f'RED|{result}')
            self.error = 1
        else:
            for item in result:
                self.realm_templates[item['id']] = item['name']
                if item['name'] == 'UserGate Libraries template':
                    self.usergate_lib_template = (item['name'], item['id'])
            
            err, result = self.utm.get_ngfw_templates_groups()
            if err:
                self.stepChanged.emit('iRED|Не удалось получить список групп шаблонов области.')
                self.stepChanged.emit(f'RED|{result}')
                self.error = 1
            else:
                for item in result:
                    self.groups[item['name']] = item['id']
                    self.group_templates[item['name']] = {self.realm_templates[template_id]: template_id for template_id in item['templates']}


    def import_ngfw_devices(self):
        """Импортируем устройства NGFW"""
        self.stepChanged.emit('BLUE|Импорт устройств NGFW в раздел "NGFW/Устройства".')
        json_file = os.path.join(self.base_path, 'config_devices_list.json')
        err, data = self.read_json_file(json_file, mode=1)
        if err:
            self.stepChanged.emit('ORANGE|    Устройств NGFW не импортированы и не будут использованы в правилах.')
            return

        error = 0
        n = 0
        for item in data:
            if item['name'] in self.mc_data['devices_list']:
                if self.selected_group == item['device_templates_group']:
                    n = 1
                    self.stepChanged.emit(f'uGRAY|    Устройство NGFW "{item["name"]}" для группы шаблонов "{self.selected_group}" уже существует.')
            else:
                if self.selected_group == item['device_templates_group']:   # Проверяем что устройство принадлежит импортируемой группе шаблонов.
                    n = 1
                    try:
                        item['device_templates_group'] = self.groups[item['device_templates_group']]
                    except KeyError:
                        self.stepChanged.emit(f'RED|    Не найдена группа шаблонов "{item["device_templates_group"]}" для устройства NGFW "{item["name"]}" [Устройство NGFW "{item["name"]}" не импортировано].')
                        error = 1
                        continue

                    err, result = self.utm.add_ngfw_device(item)
                    if err:
                        self.stepChanged.emit(f'RED|    {result}  [Устройство NGFW "{item["name"]}" не импортировано]')
                        error = 1
                        continue
                    else:
                        self.mc_data['devices_list'][item['name']] = result
                        self.stepChanged.emit(f'BLACK|    Устройство NGFW "{item["name"]}" импортировано.')
        if not n:
            self.stepChanged.emit(f'uGRAY|    Нет устройств NGFW для группы шаблонов "{self.selected_group}".')

        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте устройств NGFW.')
        else:
            self.stepChanged.emit('GREEN|    Импорт устройств NGFW завершён.')


    #--------------------------------------- Библиотека -------------------------------------------------
    def import_morphology_lists(self, path, template_id, template_name):
        """Импортируем списки морфологии"""
        json_file = os.path.join(path, 'config_morphology_lists.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт списков морфологии в раздел "Библиотеки/Морфология".')
        error = 0

        if not self.mc_data.get('morphology', False):
            if self.get_morphology_list():        # Заполняем self.mc_data['morphology']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте списков морфологии.')
                return
        morphology = self.mc_data['morphology']

        for item in data:
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя списка')
            content = item.pop('content')
            item.pop('last_update', None)

            if item['name'] in morphology:
                if template_id == morphology[item['name']].template_id:
                    self.stepChanged.emit(f'uGRAY|    Список морфологии "{item["name"]}" уже существует в текущем шаблоне.')
                else:
                    self.stepChanged.emit(f'sGREEN|    Список морфологии "{item["name"]}" уже существует в шаблоне "{morphology[item["name"]].template_name}".')
                    continue
            else:
                err, result = self.utm.add_template_nlist(template_id, item)
                if err:
                    self.stepChanged.emit(f'RED|    {result}  [Список морфологии "{item["name"]}" не импортирован]')
                    error = 1
                    continue
                else:
                    morphology[item['name']] = BaseObject(id=result, template_id=template_id, template_name=template_name)
                    self.stepChanged.emit(f'BLACK|    Список морфологии "{item["name"]}" импортирован.')

            if item['list_type_update'] == 'static':
                if content:
                    for value in content:
                        err2, result2 = self.utm.add_template_nlist_item(template_id, morphology[item['name']].id, value)
                        if err2 == 3:
                            self.stepChanged.emit(f'GRAY|       {result2}')
                        elif err2 == 1:
                            self.stepChanged.emit(f'RED|       {result2}  [Список морфологии "{item["name"]}"]')
                            error = 1
                        elif err2 == 7:
                            message = f'       Error: Список морфологии "{item["name"]}" не найден в шаблоне "{morphology[item["name"]].template_name}".'
                            self.stepChanged.emit(f'RED|{message}\n          Импорт прерван. Перелогиньтесь в МС и повторите попытку.')
                            self.error = 1
                            return
                        else:
                            self.stepChanged.emit(f'BLACK|       Добавлено "{value["value"]}".')
                else:
                    self.stepChanged.emit(f'GRAY|       Содержимое списка морфологии "{item["name"]}" не обновлено так как он пуст.')
            else:
                self.stepChanged.emit(f'GRAY|       Содержимое списка морфологии "{item["name"]}" не обновлено так как он обновляется удалённо.')

        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте списков морфологии.')
        else:
            self.stepChanged.emit('GREEN|    Импорт списков морфологии завершён.')


    def import_services_list(self, path, template_id, template_name):
        """Импортируем список сервисов раздела библиотеки"""
        json_file = os.path.join(path, 'config_services_list.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт списка сервисов в раздел "Библиотеки/Сервисы"')
        error = 0

        services = self.mc_data['services']

        for item in data:
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя сервиса')
            if item['name'] in services:
                if template_id == services[item['name']].template_id:
                    self.stepChanged.emit(f'uGRAY|    Сервис "{item["name"]}" уже существует в текущем шаблоне.')
                else:
                    self.stepChanged.emit(f'sGREEN|    Сервис "{item["name"]}" уже существует в шаблоне "{services[item["name"]].template_name}".')
            else:
                err, result = self.utm.add_template_service(template_id, item)
                if err == 3:
                    self.stepChanged.emit(f'GRAY|    {result}')
                elif err == 1:
                    self.stepChanged.emit(f'RED|    {result} [Сервис "{item["name"]}" не импортирован]')
                    error = 1
                else:
                    services[item['name']] = BaseObject(id=result, template_id=template_id, template_name=template_name)
                    self.stepChanged.emit(f'BLACK|    Сервис "{item["name"]}" импортирован.')
            self.msleep(3)
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при добавлении сервисов.')
        else:
            self.stepChanged.emit('GREEN|    Импорт списка сервисов завершён')


    def import_services_groups(self, path, template_id, template_name):
        """Импортируем группы сервисов в раздел Библиотеки/Группы сервисов"""
        json_file = os.path.join(path, 'config_services_groups_list.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт групп сервисов раздела "Библиотеки/Группы сервисов".')
        out_message = 'GREEN|    Группы сервисов импортированы в раздел "Библиотеки/Группы сервисов".'
        error = 0

        servicegroups = self.mc_data['service_groups']
    
        for item in data:
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя группы')
            content = item.pop('content')
            item.pop('last_update', None)

            if item['name'] in servicegroups:
                if template_id == servicegroups[item['name']].template_id:
                    self.stepChanged.emit(f'uGRAY|    Группа сервисов "{item["name"]}" уже существует в текущем шаблоне.')
                else:
                    self.stepChanged.emit(f'sGREEN|    Группа сервисов "{item["name"]}" уже существует в шаблоне "{servicegroups[item["name"]].template_name}".')
                    continue
            else:
                err, result = self.utm.add_template_nlist(template_id, item)
                if err == 1:
                    self.stepChanged.emit(f'RED|    {result}  [Группа сервисов "{item["name"]}" не импортирована]')
                    error = 1
                    continue
                elif err == 3:
                    self.stepChanged.emit(f'GRAY|    {result}.')
                else:
                    servicegroups[item['name']] = BaseObject(id=result, template_id=template_id, template_name=template_name)
                    self.stepChanged.emit(f'BLACK|    Группа сервисов "{item["name"]}" импортирована.')

            if item['list_type_update'] == 'static':
                if content:
                    for service in content:
                        try:
                            tmp = self.mc_data['services'][service['name']]
                        except KeyError as err:
                            self.stepChanged.emit(f'RED|       Error: [Группа сервисов "{item["name"]}"] Не найден сервис {err}. Загрузите сервисы в шаблон и повторите попытку.')
                            error = 1
                            continue
                        if tmp.template_id == template_id:
                            service['value'] = tmp.id
                        else:
                            self.stepChanged.emit(f'RED|       Error: [Группа сервисов "{item["name"]}"] Сервис "{service["name"]}" не добавлен так как находиться в другом шаблоне ("{tmp.template_name}"). Можно добавлять сервисы только из текущего шаблона.')
                            error = 1
                            continue
                        err2, result2 = self.utm.add_template_nlist_item(template_id, servicegroups[item['name']].id, service)
                        if err2 == 3:
                            self.stepChanged.emit(f'GRAY|       Сервис "{service["name"]}" уже существует в этой группе сервисов.')
                        elif err2 == 1:
                            self.stepChanged.emit(f'RED|       {result2}  [Группа сервисов "{item["name"]}"]')
                            error = 1
                        elif err2 == 7:
                            message = f'       Error: Группа сервисов "{item["name"]}" не найдена в шаблоне "{servicegroups[item["name"]].template_name}".'
                            self.stepChanged.emit(f'RED|{message}\n          Импорт прерван. Перелогиньтесь в МС и повторите попытку.')
                            self.error = 1
                            return
                        else:
                            self.stepChanged.emit(f'BLACK|       Добавлен сервис "{service["name"]}".')
                else:
                    self.stepChanged.emit(f'GRAY|       Нет содержимого в группе сервисов "{item["name"]}".')
            else:
                self.stepChanged.emit(f'GRAY|       Содержимое группы сервисов "{item["name"]}" не обновлено так как она обновляется удалённо.')
            self.msleep(1)

        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте групп сервисов.')
        else:
            self.stepChanged.emit('GREEN|    Импорт групп сервисов завершён.')


    def import_ip_lists(self, path, template_id, template_name):
        """Импортируем списки IP адресов"""
        self.stepChanged.emit('BLUE|Импорт списков IP-адресов раздела "Библиотеки/IP-адреса".')

        if not os.path.isdir(path):
            self.stepChanged.emit('GRAY|    Нет списков IP-адресов для импорта.')
            return
        files_list = os.listdir(path)
        if not files_list:
            self.stepChanged.emit('GRAY|    Нет списков IP-адресов для импорта.')
            return

        error = 0
        ip_lists = self.mc_data['ip_lists']

        # Импортируем все списки IP-адресов без содержимого (пустые).
        self.stepChanged.emit('LBLUE|    Импортируем списки IP-адресов без содержимого.')
        for file_name in files_list:
            json_file = os.path.join(path, file_name)
            err, data = self.read_json_file(json_file, mode=2)
            if err:
                continue

            error, data['name'] = self.get_transformed_name(data['name'], err=error, descr='Имя списка')
            content = data.pop('content')
            data.pop('last_update', None)

            if data['name'] in ip_lists:
                if template_id == ip_lists[data['name']].template_id:
                    self.stepChanged.emit(f'uGRAY|    Список IP-адресов "{data["name"]}" уже существует в текущем шаблоне.')
                else:
                    self.stepChanged.emit(f'sGREEN|    Список IP-адресов "{data["name"]}" уже существует в шаблоне "{ip_lists[data["name"]].template_name}".')
                    continue
            else:
                err, result = self.utm.add_template_nlist(template_id, data)
                if err == 1:
                    self.stepChanged.emit(f'RED|    {result}  [Список IP-адресов "{data["name"]}" не импортирован]')
                    error = 1
                elif err == 3:
                    self.stepChanged.emit(f'GRAY|    {result}.')
                else:
                    ip_lists[data['name']] = BaseObject(id=result, template_id=template_id, template_name=template_name)
                    self.stepChanged.emit(f'BLACK|    Список IP-адресов "{data["name"]}" импортирован.')

        # Импортируем содержимое в уже добавленные списки IP-адресов.
        self.stepChanged.emit('LBLUE|    Импортируем содержимое списков IP-адресов.')
        for file_name in files_list:
            json_file = os.path.join(path, file_name)
            err, data = self.read_json_file(json_file)
            if err:
                continue

            _, data['name'] = self.get_transformed_name(data['name'], descr='Имя списка', mode=0)
            self.stepChanged.emit(f'BLACK|    Импортируем содержимое списка IP-адресов "{data["name"]}".')

            if data['name'] not in ip_lists:
                self.stepChanged.emit(f'RED|       Не найден список IP-адресов "{data["name"]}". Содержимое не импортировано.')
                error = 1
                continue

            if template_id == ip_lists[data['name']].template_id:
                if data['list_type_update'] == 'static':
                    if data['content']:
                        new_content = []
                        for item in data['content']:
                            if 'list' in item:
                                item_list = self.get_transformed_name(item['list'], descr='Имя списка', mode=0)[1]
                                item_value = f'IP-лист "{item_list}"'
                                try:
                                    item['list'] = ip_lists[item_list].id
                                    new_content.append(item)
                                except KeyError:
                                    self.stepChanged.emit(f'RED|       Error: [Список IP-адресов "{data["name"]}"] {item_value} не добавлен в список так как не найден в данной группе шаблонов. ')
                                    error = 1
                            else:
                                new_content.append(item)
                        if not new_content:
                            self.stepChanged.emit(f'uGRAY|       Список "{data["name"]}" не имеет содержимого.')
                            continue
                        err, result = self.utm.add_template_nlist_items(template_id, ip_lists[data['name']].id, new_content)
                        if err == 1:
                            self.stepChanged.emit(f'RED|       {result} [Список IP-адресов "{data["name"]}" содержимое не импортировано]')
                            error = 1
                        else:
                            self.stepChanged.emit(f'BLACK|       Содержимое списка IP-адресов "{data["name"]}" обновлено.')
                    else:
                        self.stepChanged.emit(f'GRAY|       Список "{data["name"]}" пуст.')
                else:
                    self.stepChanged.emit(f'GRAY|       Содержимое списка IP-адресов "{data["name"]}" не обновлено так как он обновляется удалённо.')
            else:
                self.stepChanged.emit(f'sGREEN|       Содержимое списка IP-адресов "{data["name"]}" не обновлено так как он находится в другом шаблоне.')
            self.msleep(2)

        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте списков IP-адресов.')
        else:
            self.stepChanged.emit('GREEN|    Импорт списков IP-адресов завершён.')


    def import_useragent_lists(self, path, template_id, template_name):
        """Импортируем списки Useragent браузеров"""
        json_file = os.path.join(path, 'config_useragents_list.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт списка "Useragent браузеров" в раздел "Библиотеки/Useragent браузеров".')
        error = 0

        if not self.mc_data.get('useragents', False):
            if self.get_useragents_list():        # Заполняем self.mc_data['useragents']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте списков Useragent браузеров.')
                return
        useragents = self.mc_data['useragents']

        for item in data:
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя списка')
            content = item.pop('content')
            item.pop('last_update', None)

            if item['name'] in useragents:
                if template_id == useragents[item['name']].template_id:
                    self.stepChanged.emit(f'uGRAY|    Список Useragent "{item["name"]}" уже существует в текущем шаблоне.')
                else:
                    self.stepChanged.emit(f'sGREEN|    Список Useragent "{item["name"]}" уже существует в шаблоне "{useragents[item["name"]].template_name}".')
                    continue
            else:
                err, result = self.utm.add_template_nlist(template_id, item)
                if err:
                    self.stepChanged.emit(f'RED|    {result}  [Список Useragent "{item["name"]}" не импортирован]')
                    error = 1
                    continue
                else:
                    useragents[item['name']] = BaseObject(id=result, template_id=template_id, template_name=template_name)
                    self.stepChanged.emit(f'BLACK|    Список Useragent "{item["name"]}" импортирован.')

            if item['list_type_update'] == 'static':
                if content:
                    err2, result2 = self.utm.add_template_nlist_items(template_id, useragents[item['name']].id, content)
                    if err2 == 3:
                        self.stepChanged.emit(f'GRAY|       {result2}')
                    elif err2 == 1:
                        self.stepChanged.emit(f'RED|       {result2}  [Список Useragent: "{item["name"]}"]')
                        error = 1
                    else:
                        self.stepChanged.emit(f'BLACK|       Содержимое списка Useragent "{item["name"]}" импортировано.')
                else:
                    self.stepChanged.emit(f'GRAY|       Список Useragent "{item["name"]}" пуст.')
            else:
                self.stepChanged.emit(f'GRAY|       Содержимое списка Useragent "{item["name"]}" не импортировано так как он обновляется удалённо.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте списков Useragent браузеров.')
        else:
            self.stepChanged.emit('GREEN|    Импорт списка "Useragent браузеров" завершён.')


    def import_mime_lists(self, path, template_id, template_name):
        """Импортируем списки Типов контента"""
        json_file = os.path.join(path, 'config_mime_types.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт списка "Типы контента" в раздел "Библиотеки/Типы контента".')
        error = 0

        mimes = self.mc_data['mime']

        for item in data:
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя списка')
            content = item.pop('content')
            item.pop('last_update', None)

            if item['name'] in mimes:
                if template_id == mimes[item['name']].template_id:
                    self.stepChanged.emit(f'uGRAY|    Список Типов контента "{item["name"]}" уже существует в текущем шаблоне.')
                else:
                    self.stepChanged.emit(f'sGREEN|    Список Типов контента "{item["name"]}" уже существует в шаблоне "{mimes[item["name"]].template_name}".')
                    continue
            else:
                err, result = self.utm.add_template_nlist(template_id, item)
                if err:
                    self.stepChanged.emit(f'RED|    {result}  [Список Типов контента "{item["name"]}" не импортирован]')
                    error = 1
                    continue
                else:
                    mimes[item['name']] = BaseObject(id=result, template_id=template_id, template_name=template_name)
                    self.stepChanged.emit(f'BLACK|    Список Типов контента "{item["name"]}" импортирован.')

            if item['list_type_update'] == 'static':
                if content:
                    err2, result2 = self.utm.add_template_nlist_items(template_id, mimes[item['name']].id, content)
                    if err2 == 3:
                        self.stepChanged.emit(f'GRAY|       {result2}')
                    elif err2 == 1:
                        self.stepChanged.emit(f'RED|       {result2}  [Список Типов контента "{item["name"]}"]')
                        error = 1
                    else:
                        self.stepChanged.emit(f'BLACK|       Содержимое списка Типов контента "{item["name"]}" импортировано.')
                else:
                    self.stepChanged.emit(f'GRAY|       Список Типов контента "{item["name"]}" пуст.')
            else:
                self.stepChanged.emit(f'GRAY|       Содержимое списка Типов контента "{item["name"]}" не импортировано так как он обновляется удалённо.')

        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте списков "Типы контента".')
        else:
            self.stepChanged.emit('GREEN|    Импорт списка "Типы контента" завершён.')


    def import_url_lists(self, path, template_id, template_name):
        """Импортировать списки URL в шаблон МС"""
        self.stepChanged.emit('BLUE|Импорт списков URL раздела "Библиотеки/Списки URL".')
        
        if not os.path.isdir(path):
            self.stepChanged.emit('GRAY|    Нет списков URL для импорта.')
            return
        files_list = os.listdir(path)
        if not files_list:
            self.stepChanged.emit('GRAY|    Нет списков URL для импорта.')
            return

        error = 0
        url_lists = self.mc_data['url_lists']

        # Импортируем все списки URL без содержимого (пустые).
        self.stepChanged.emit('LBLUE|    Импортируем списки URL без содержимого.')
        for file_name in files_list:
            json_file = os.path.join(path, file_name)
            err, data = self.read_json_file(json_file, mode=2)
            if err:
                continue

            error, data['name'] = self.get_transformed_name(data['name'], err=error, descr='Имя списка')
            content = data.pop('content')
            data.pop('last_update', None)
            if not data['attributes'] or 'threat_level' in data['attributes']:
                data['attributes'] = {'list_compile_type': 'case_sensitive'}

            if data['name'] in url_lists:
                if template_id == url_lists[data['name']].template_id:
                    self.stepChanged.emit(f'uGRAY|    Список URL "{data["name"]}" уже существует в текущем шаблоне.')
                else:
                    self.stepChanged.emit(f'sGREEN|    Список URL "{data["name"]}" уже существует в шаблоне "{url_lists[data["name"]].template_name}".')
                    continue
            else:
                err, result = self.utm.add_template_nlist(template_id, data)
                if err == 1:
                    self.stepChanged.emit(f'RED|    {result}  [Список URL "{data["name"]}" не импортирован]')
                    error = 1
                elif err == 3:
                    self.stepChanged.emit(f'GRAY|    {result}')
                else:
                    url_lists[data['name']] = BaseObject(id=result, template_id=template_id, template_name=template_name)
                    self.stepChanged.emit(f'BLACK|    Список URL "{data["name"]}" импортирован.')

        # Импортируем содержимое в уже добавленные списки URL.
        self.stepChanged.emit('LBLUE|    Импортируем содержимое списков URL.')
        for file_name in files_list:
            json_file = os.path.join(path, file_name)
            err, data = self.read_json_file(json_file)
            if err:
                continue

            _, data['name'] = self.get_transformed_name(data['name'], descr='Имя списка URL', mode=0)
            self.stepChanged.emit(f'BLACK|    Импортируем содержимое списка URL "{data["name"]}".')

            if data['name'] not in url_lists:
                self.stepChanged.emit(f'RED|       Не найден список URL "{data["name"]}". Содержимое не импортировано.')

            if template_id == url_lists[data['name']].template_id:
                if data['list_type_update'] == 'static':
                    if data['content']:
                        err, result = self.utm.add_template_nlist_items(template_id, url_lists[data['name']].id, data['content'])
                        if err == 1:
                            self.stepChanged.emit(f'RED|       {result} [Список URL "{data["name"]}" - содержимое не импортировано]')
                            error = 1
                        else:
                            self.stepChanged.emit(f'BLACK|       Содержимое списка URL "{data["name"]}" обновлено.')
                    else:
                        self.stepChanged.emit(f'GRAY|      Список URL "{data["name"]}" пуст.')
                else:
                    self.stepChanged.emit(f'GRAY|       Содержимое списка URL "{data["name"]}" не импортировано так как он обновляется удалённо.')
            else:
                self.stepChanged.emit(f'sGREEN|       Содержимое списка URL "{data["name"]}" не обновлено так как он находится в другом шаблоне.')
            self.msleep(1)

        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте списков URL.')
        else:
            self.stepChanged.emit('GREEN|    Импорт списков URL завершён.')


    def import_time_restricted_lists(self, path, template_id, template_name):
        """Импортируем содержимое календарей"""
        json_file = os.path.join(path, 'config_calendars.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт списка "Календари" в раздел "Библиотеки/Календари".')
        error = 0

        calendars = self.mc_data['calendars']

        for item in data:
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя календаря')
            content = item.pop('content')
            item.pop('last_update', None)

            if item['name'] in calendars:
                if template_id == calendars[item['name']].template_id:
                    self.stepChanged.emit(f'uGRAY|    Календарь "{item["name"]}" уже существует в текущем шаблоне.')
                else:
                    self.stepChanged.emit(f'sGREEN|    Календарь "{item["name"]}" уже существует в шаблоне "{calendars[item["name"]].template_name}".')
                    continue
            else:
                err, result = self.utm.add_template_nlist(template_id, item)
                if err == 1:
                    self.stepChanged.emit(f'RED|    {result}  [Календарь "{item["name"]}" не импортирован]')
                    error = 1
                    continue
                elif err == 3:
                    self.stepChanged.emit(f'uGRAY|    {result}')
                else:
                    calendars[item['name']] = BaseObject(id=result, template_id=template_id, template_name=template_name)
                    self.stepChanged.emit(f'BLACK|    Календарь "{item["name"]}" импортирован.')

            if item['list_type_update'] == 'static':
                if content:
                    for value in content:
                        err2, result2 = self.utm.add_template_nlist_item(template_id, calendars[item['name']].id, value)
                        if err2 == 1:
                            error = 1
                            self.stepChanged.emit(f'RED|       {result2}  [TimeSet "{value["name"]}"] не импортирован')
                        elif err2 == 3:
                            self.stepChanged.emit(f'GRAY|       TimeSet "{value["name"]}" уже существует.')
                        elif err2 == 7:
                            message = f'       Error: Календарь "{item["name"]}" не найден в шаблоне "{calendars[item["name"]].template_name}".'
                            self.stepChanged.emit(f'RED|{message}\n          Импорт прерван. Перелогиньтесь в МС и повторите попытку.')
                            self.error = 1
                            return
                        else:
                            self.stepChanged.emit(f'BLACK|       TimeSet "{value["name"]}" импортирован.')
                else:
                    self.stepChanged.emit(f'GRAY|       Календарь "{item["name"]}" пуст.')
            else:
                self.stepChanged.emit(f'GRAY|       Содержимое календаря "{item["name"]}" не импортировано так как он обновляется удалённо.')

        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте списка "Календари".')
        else:
            self.stepChanged.emit('GREEN|    Импорт списка "Календари" завершён.')


    def import_shaper_list(self, path, template_id, template_name):
        """Импортируем список Полос пропускания раздела библиотеки"""
        json_file = os.path.join(path, 'config_shaper_list.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт списка "Полосы пропускания" в раздел "Библиотеки/Полосы пропускания".')
        error = 0

        shapers = self.mc_data['shapers']

        for item in data:
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя Полосы пропускания')
            if item['name'] in shapers:
                if template_id == shapers[item['name']].template_id:
                    self.stepChanged.emit(f'uGRAY|    Полоса пропускания "{item["name"]}" уже существует в текущем шаблоне.')
                else:
                    self.stepChanged.emit(f'sGREEN|    Полоса пропускания "{item["name"]}" уже существует в шаблоне "{shapers[item["name"]].template_name}".')
            else:
                err, result = self.utm.add_template_shaper(template_id, item)
                if err:
                    self.stepChanged.emit(f'RED|    {result}  [Полоса пропускания "{item["name"]}" не импортирована]')
                    error = 1
                elif err == 3:
                    self.stepChanged.emit(f'GRAY|    {result}')
                else:
                    shapers[item['name']] = BaseObject(id=result, template_id=template_id, template_name=template_name)
                    self.stepChanged.emit(f'BLACK|    Полоса пропускания "{item["name"]}" импортирована.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте списка "Полосы пропускания".')
        else:
            self.stepChanged.emit('GREEN|    Импорт списка "Полосы пропускания" завершён.')


    def import_templates_list(self, path, template_id, template_name):
        """
        Импортируем список шаблонов страниц.
        После создания шаблона, он инициализируется страницей HTML по умолчанию для данного типа шаблона.
        """
        json_file = os.path.join(path, 'config_templates_list.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт списка шаблонов страниц в раздел "Библиотеки/Шаблоны страниц".')
#        self.stepChanged.emit('LBLUE|    Импортируются только шаблоны страниц у которых есть HTML-файл страницы.')
        error = 0
        html_files = os.listdir(path)

        response_pages = self.mc_data['response_pages']

#        n = 0
        for item in data:
#            if f"{item['name']}.html" in html_files:
#                n += 1
            if item['name'] in response_pages:
                if template_id == response_pages[item['name']].template_id:
                    self.stepChanged.emit(f'uGRAY|    Шаблон страницы "{item["name"]}" уже существует в текущем шаблоне.')
                else:
                    self.stepChanged.emit(f'sGREEN|    Шаблон страницы "{item["name"]}" уже существует в шаблоне "{response_pages[item["name"]].template_name}".')
                    continue
            else:
                err, result = self.utm.add_template_responsepage(template_id, item)
                if err:
                    self.stepChanged.emit(f'RED|    {result}  [Шаблон страницы "{item["name"]}" не импортирован]')
                    error = 1
                    continue
                else:
                    response_pages[item['name']] = BaseObject(id=result, template_id=template_id, template_name=template_name)
                    self.stepChanged.emit(f'BLACK|    Шаблон страницы "{item["name"]}" импортирован.')

            if f"{item['name']}.html" in html_files:
                upload_file = os.path.join(path, f"{item['name']}.html")
                err, result = self.utm.get_realm_upload_session(upload_file)
                if err:
                    self.stepChanged.emit(f'RED|       {result}')
                    error = 1
                elif result['success']:
                    err2, result2 = self.utm.set_template_responsepage_data(template_id, response_pages[item['name']].id, result['storage_file_uid'])
                    if err2:
                        self.stepChanged.emit(f'RED|       {result2} [Страница "{item["name"]}.html" не импортирована]')
                        error = 1
                    else:
                        self.stepChanged.emit(f'BLACK|       Страница "{item["name"]}.html" импортирована.')
                else:
                    error = 1
                    self.stepChanged.emit(f'ORANGE|       Error: Не удалось импортировать страницу "{item["name"]}.html".')
#        if not n:
#            self.stepChanged.emit('GRAY|    Нет шаблонов страниц у которых есть HTML-файл страницы.')

        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте шаблонов страниц.')
        else:
            self.stepChanged.emit('GREEN|    Импорт шаблонов страниц завершён.')


    def import_url_categories(self, path, template_id, template_name):
        """Импортировать группы URL категорий с содержимым"""
        json_file = os.path.join(path, 'config_url_categories.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт групп URL категорий раздела "Библиотеки/Категории URL".')
        error = 0

        url_category_groups = self.mc_data['url_categorygroups']

        for item in data:
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя группы')
            content = item.pop('content')
            item.pop('last_update', None)
            item.pop('guid', None)

            if item['name'] in url_category_groups:
                if template_id == url_category_groups[item['name']].template_id:
                    self.stepChanged.emit(f'uGRAY|    Группа URL категорий "{item["name"]}" уже существует в текущем шаблоне.')
                else:
                    self.stepChanged.emit(f'sGREEN|    Группа URL категорий "{item["name"]}" уже существует в шаблоне "{url_category_groups[item["name"]].template_name}".')
                    continue
            else:
                err, result = self.utm.add_template_nlist(template_id, item)
                if err == 1:
                    self.stepChanged.emit(f'RED|    {result}  [Группа URL категорий "{item["name"]}" не импортирована]')
                    error = 1
                    continue
                elif err == 3:
                    self.stepChanged.emit(f'uGRAY|    {result}')
                else:
                    url_category_groups[item['name']] = BaseObject(id=result, template_id=template_id, template_name=template_name)
                    self.stepChanged.emit(f'BLACK|    Группа URL категорий "{item["name"]}" импортирована.')

            if item['list_type_update'] == 'static':
                if content:
                    for category in content:
                        err2, result2 = self.utm.add_template_nlist_item(template_id, url_category_groups[item['name']].id, category)
                        if err2 == 3:
                            self.stepChanged.emit(f'GRAY|       Категория "{category["name"]}" уже существует.')
                        elif err2 == 1:
                            self.stepChanged.emit(f'RED|       {result2}  [Категория "{category["name"]}"]')
                            error = 1
                        elif err2 == 7:
                            message = f'       Error: Группа URL категорий "{item["name"]}" не найдена в шаблоне "{url_category_groups[item["name"]].template_name}".'
                            self.stepChanged.emit(f'RED|{message}\n          Импорт прерван. Перелогиньтесь в МС и повторите попытку.')
                            self.error = 1
                            return
                        else:
                            self.stepChanged.emit(f'BLACK|       Добавлена категория "{category["name"]}".')
                else:
                    self.stepChanged.emit(f'GRAY|       Группа URL категорий "{item["name"]}" не содержит категорий.')
            else:
                self.stepChanged.emit(f'GRAY|       Содержимое группы URL категорий "{item["name"]}" не импортировано так как она обновляется удалённо.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте групп URL категорий.')
        else:
            self.stepChanged.emit('GREEN|    Импорт групп URL категорий завершён.')


    def import_custom_url_category(self, path, template_id, template_name):
        """Импортируем изменённые категории URL"""
        json_file = os.path.join(path, 'custom_url_categories.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт категорий URL раздела "Библиотеки/Изменённые категории URL".')
        error = 0

        custom_url = {}
        for name, uid in self.group_templates[self.selected_group].items():
            err, result = self.utm.get_template_custom_url_list(uid)
            if err:
                self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте изменённых категорий URL.')
                self.error = 1
                return
            for x in result:
                if x['name'] in custom_url:
                    self.stepChanged.emit('ORANGE|    Warning: Категория для URL "{x["name"]}" изменена в нескольких шаблонах группы. Запись из шаблона "{name}" не будет испольована.')
                else:
                    custom_url[x['name']] = BaseObject(id=x['id'], template_id=uid, template_name=name)

        for item in data:
            try:
                item['categories'] = [self.mc_data['url_categories'][x] for x in item['categories']]
            except KeyError as err:
                self.stepChanged.emit(f'RED|    Error: В правиле "{item["name"]}" обнаружена несуществующая категория {err}. Правило  не добавлено.')
                error = 1
                continue

            if item['name'] in custom_url:
                if template_id == custom_url[item['name']].template_id:
                    self.stepChanged.emit(f'uGRAY|    Изменение категории URL "{item["name"]}" уже существует в текущем шаблоне.')
                else:
                    self.stepChanged.emit(f'sGREEN|    Изменение категории URL "{item["name"]}" уже существует в шаблоне "{custom_url[item["name"]].template_name}".')
            else:
                err, result = self.utm.add_template_custom_url(template_id, item)
                if err:
                    self.stepChanged.emit(f'RED|    {result}  [Изменение категорий для URL "{item["name"]}" не импортировано]')
                    error = 1
                else:
                    custom_url[item['name']] = BaseObject(id=result, template_id=template_id, template_name=template_name)
                    self.stepChanged.emit(f'BLACK|    Изменение категории для URL "{item["name"]}" импортировано.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте изменённых категорий URL.')
        else:
            self.stepChanged.emit('GREEN|    Импорт изменённых категорий URL завершён.')


    def import_application_signature(self, path, template_id, template_name):
        """Импортируем список Приложения"""
        json_file = os.path.join(path, 'config_applications.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт пользовательских приложений в раздел "Библиотеки/Приложения".')
        error = 0

        users_apps = {}
        err, result = self.utm.get_realm_l7_signatures(query={'query': 'owner = You'})
        if err:
            self.stepChanged.emit(f'RED|    {result}')
            self.error = 1
            return
        for x in result:
            users_apps[x['name']] = BaseObject(id=x['id'], template_id=x['template_id'], template_name=self.realm_templates[x['template_id']])

        for item in data:
            item.pop('signature_id', None)

            new_l7categories = []
            for category in item['l7categories']:
                try:
                    new_l7categories.append(self.mc_data['l7_categories'][category])
                except KeyError as err:
                    self.stepChanged.emit(f'RED|    Error: [Правило "{item["name"]}"] Категория {err} не существует. Категория не добавлена.')
                    error = 1
            item['l7categories'] = new_l7categories

            if item['name'] in users_apps:
                if template_id == users_apps[item['name']].template_id:
                    self.stepChanged.emit(f'uGRAY|    Пользовательское приложение "{item["name"]}" уже существует в текущем шаблоне.')
                else:
                    message = f'Пользовательское приложение "{item["name"]}" уже существует в шаблоне "{users_apps[item["name"]].template_name}".'
                    if users_apps[item['name']].template_name not in self.selected_templates:
                        message = f'{message}\n       Пользовательское приложение "{item["name"]}" существует в шаблоне, отсутствующем в данной группе шаблонов.'
                    self.stepChanged.emit(f'sGREEN|    {message}')
            else:
                err, result = self.utm.add_template_app_signature(template_id, item)
                if err:
                    self.stepChanged.emit(f'RED|    {result}  [Пользовательское приложение "{item["name"]}" не импортировано]')
                    error = 1
                else:
                    users_apps[item['name']] = BaseObject(id=result, template_id=template_id, template_name=template_name)
                    self.stepChanged.emit(f'BLACK|    Приложение "{item["name"]}" импортировано.')
            self.msleep(1)
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте пользовательских приложений.')
        else:
            self.stepChanged.emit('GREEN|    Импорт пользовательских приложений завершён.')


    def import_app_profiles(self, path, template_id, template_name):
        """Импортируем профили приложений"""
        json_file = os.path.join(path, 'config_app_profiles.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт профилей приложений раздела "Библиотеки/Профили приложений".')
        error = 0

        if not self.mc_data.get('l7_apps', False):
            if self.get_app_signatures():        # Заполняем self.mc_data['l7_apps']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей приложений.')
                return
        l7_apps = self.mc_data['l7_apps']

        if not self.mc_data.get('l7_profiles', False):
            if self.get_l7_profiles():        # Заполняем self.mc_data['l7_profiles']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей приложений.')
                return
        l7_profiles = self.mc_data['l7_profiles']

        for item in data:
            new_overrides = []
            for app in item['overrides']:
                try:
                    app['id'] = l7_apps[app['id']].id
                    new_overrides.append(app)
                except KeyError as err:
                    self.stepChanged.emit(f'RED|    Error: [Правило "{item["name"]}"] Не найдено приложение {err}. Приложение не добавлено.')
                    error = 1
            item['overrides'] = new_overrides

            if item['name'] in l7_profiles:
                if template_id == l7_profiles[item['name']].template_id:
                    self.stepChanged.emit(f'uGRAY|    Профиль приложений "{item["name"]}" уже существует в текущем шаблоне.')
                else:
                    self.stepChanged.emit(f'sGREEN|    Профиль приложений "{item["name"]}" уже существует в шаблоне "{l7_profiles[item["name"]].template_name}".')
            else:
                err, result = self.utm.add_template_l7_profile(template_id, item)
                if err:
                    self.stepChanged.emit(f'RED|    {result}  [Профиль приложений "{item["name"]}" не импортирован]')
                    error = 1
                else:
                    l7_profiles[item['name']] = BaseObject(id=result, template_id=template_id, template_name=template_name)
                    self.stepChanged.emit(f'BLACK|    Профиль приложений "{item["name"]}" импортирован.')
            self.msleep(1)
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей приложений.')
        else:
            self.stepChanged.emit('GREEN|    Импорт профилей приложений завершён.')


    def import_application_groups(self, path, template_id, template_name):
        """Импортировать группы приложений на UTM"""
        json_file = os.path.join(path, 'config_application_groups.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт групп приложений в раздел "Библиотеки/Группы приложений".')

        if not self.mc_data.get('l7_apps', False):
            if self.get_app_signatures():        # Заполняем self.mc_data['l7_apps']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте групп приложений.')
                return
        l7_apps = self.mc_data['l7_apps']
        apps_groups = self.mc_data['apps_groups']

        error = 0
        for item in data:
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя группы')
            content = item.pop('content')
            item.pop('last_update', None)

            if item['name'] in apps_groups:
                if template_id == apps_groups[item['name']].template_id:
                    self.stepChanged.emit(f'uGRAY|    Группа приложений "{item["name"]}" уже существует в текущем шаблоне.')
                else:
                    self.stepChanged.emit(f'sGREEN|    Группа приложений "{item["name"]}" уже существует в шаблоне "{apps_groups[item["name"]].template_name}".')
                    continue
            else:
                err, result = self.utm.add_template_nlist(template_id, item)
                if err == 1:
                    self.stepChanged.emit(f'RED|    {result}  [Группа приложений "{item["name"]}" не импортирована]')
                    error = 1
                    continue
                elif err == 3:
                    self.stepChanged.emit(f'uGRAY|    {result}')
                else:
                    apps_groups[item['name']] = BaseObject(id=result, template_id=template_id, template_name=template_name)
                    self.stepChanged.emit(f'BLACK|    Группа приложений "{item["name"]}" импортирована.')

            if item['list_type_update'] == 'static':
                if content:
                    for app in content:
                        if 'name' not in app:   # Так бывает при некорректном добавлении приложения через API
                            self.stepChanged.emit(f'RED|       Error: [Группа приложений "{item["name"]}"] Приложение "{app}" не добавлено, так как не содержит имя.')
                            error = 1
                            continue
                        try:
                            app['value'] = l7_apps[app['name']].signature_id
                        except KeyError as err:
                            self.stepChanged.emit(f'RED|       Error: [Группа приложений "{item["name"]}"] Приложение "{app["name"]}" не импортировано. Такого приложения нет на UG MC.')
                            error = 1
                            continue

                        err2, result2 = self.utm.add_template_nlist_item(template_id, apps_groups[item['name']].id, app) 
                        if err2 == 1:
                            self.stepChanged.emit(f'RED|       {result2}  [Группа приложений "{item["name"]}"]')
                            error = 1
                        elif err2 == 7:
                            message = f'       Error: Группа приложений "{item["name"]}" не найдена в шаблоне "{template_name}".'
                            self.stepChanged.emit(f'RED|{message}\n          Импорт прерван. Перелогиньтесь в МС и повторите попытку.')
                            self.error = 1
                            return
                        elif err2 == 3:
                            self.stepChanged.emit(f'GRAY|       Приложение "{app["name"]}" уже существует в группе приложений "{item["name"]}".')
                        else:
                            self.stepChanged.emit(f'BLACK|       Приложение "{app["name"]}" импортировано.')
                else:
                    self.stepChanged.emit(f'GRAY|       Группа приложений "{item["name"]}" не имеет содержимого.')
            else:
                self.stepChanged.emit(f'GRAY|       Содержимое группы приложений "{item["name"]}" не импортировано так как она обновляется удалённо.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте групп приложений.')
        else:
            self.stepChanged.emit('GREEN|    Импорт групп приложений завершён.')


    def import_email_groups(self, path, template_id, template_name):
        """Импортируем группы почтовых адресов."""
        json_file = os.path.join(path, 'config_email_groups.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт групп почтовых адресов раздела "Библиотеки/Почтовые адреса".')
        error = 0

        if not self.mc_data.get('email_groups', False):
            if self.get_email_groups():        # Заполняем self.mc_data['email_groups']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте групп почтовых адресов.')
                return
        email_groups = self.mc_data['email_groups']

        for item in data:
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя группы')
            content = item.pop('content')
            item.pop('last_update', None)

            if item['name'] in email_groups:
                if template_id == email_groups[item['name']].template_id:
                    self.stepChanged.emit(f'uGRAY|    Группа почтовых адресов "{item["name"]}" уже существует в текущем шаблоне.')
                else:
                    self.stepChanged.emit(f'sGREEN|    Группа почтовых адресов "{item["name"]}" уже существует в шаблоне "{email_groups[item["name"]].template_name}".')
                    continue
            else:
                err, result = self.utm.add_template_nlist(template_id, item)
                if err == 1:
                    self.stepChanged.emit(f'RED|    {result}  [Группа почтовых адресов "{item["name"]}" не импортирована]')
                    error = 1
                    continue
                elif err == 3:
                    self.stepChanged.emit(f'uGRAY|    {result}')
                else:
                    email_groups[item['name']] = BaseObject(id=result, template_id=template_id, template_name=template_name)
                    self.stepChanged.emit(f'BLACK|    Группа почтовых адресов "{item["name"]}" импортирована.')

            if item['list_type_update'] == 'static':
                if content:
                    for email in content:
                        err2, result2 = self.utm.add_template_nlist_item(template_id, email_groups[item['name']].id, email)
                        if err2 == 1:
                            self.stepChanged.emit(f'RED|       {result2} [Группа почтовых адресов "{item["name"]}"]')
                            error = 1
                        elif err2 == 3:
                            self.stepChanged.emit(f'GRAY|       Адрес "{email["value"]}" уже существует.')
                        elif err2 == 7:
                            message = f'       Error: Группа почтовых адресов "{item["name"]}" не найдена в шаблоне "{template_name}".'
                            self.stepChanged.emit(f'RED|{message}\n          Импорт прерван. Перелогиньтесь в МС и повторите попытку.')
                            self.error = 1
                            return
                        else:
                            self.stepChanged.emit(f'BLACK|       Адрес "{email["value"]}" импортирован.')
                else:
                    self.stepChanged.emit(f'GRAY|       Группа почтовых адресов "{item["name"]}" не имеет содержимого.')
            else:
                self.stepChanged.emit(f'GRAY|       Содержимое группы почтовых адресов "{item["name"]}" не импортировано так как она обновляется удалённо.')

        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте групп почтовых адресов.')
        else:
            self.stepChanged.emit('GREEN|    Импорт групп почтовых адресов завершён.')


    def import_phone_groups(self, path, template_id, template_name):
        """Импортируем группы телефонных номеров."""
        json_file = os.path.join(path, 'config_phone_groups.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт групп телефонных номеров раздела "Библиотеки/Номера телефонов".')
        error = 0

        if not self.mc_data.get('phone_groups', False):
            if self.get_phone_groups():        # Заполняем self.mc_data['phone_groups']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте групп телефонных номеров.')
                return
        phone_groups = self.mc_data['phone_groups']

        for item in data:
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя группы')
            content = item.pop('content')
            item.pop('last_update', None)

            if item['name'] in phone_groups:
                if template_id == phone_groups[item['name']].template_id:
                    self.stepChanged.emit(f'uGRAY|    Группа телефонных номеров "{item["name"]}" уже существует в текущем шаблоне.')
                else:
                    self.stepChanged.emit(f'sGREEN|    Группа телефонных номеров "{item["name"]}" уже существует в шаблоне "{phone_groups[item["name"]].template_name}".')
                    continue
            else:
                err, result = self.utm.add_template_nlist(template_id, item)
                if err == 1:
                    self.stepChanged.emit(f'RED|    {result}  [Группа телефонных номеров "{item["name"]}" не импортирована]')
                    error = 1
                    continue
                elif err == 3:
                    self.stepChanged.emit(f'uGRAY|    {result}')
                else:
                    phone_groups[item['name']] = BaseObject(id=result, template_id=template_id, template_name=template_name)
                    self.stepChanged.emit(f'BLACK|    Группа телефонных номеров "{item["name"]}" импортирована.')

            if item['list_type_update'] == 'static':
                if content:
                    for number in content:
                        err2, result2 = self.utm.add_template_nlist_item(template_id, phone_groups[item['name']].id, number)
                        if err2 == 1:
                            self.stepChanged.emit(f'RED|       {result2} [Группа телефонных номеров "{item["name"]}"]')
                            error = 1
                        elif err2 == 3:
                            self.stepChanged.emit(f'GRAY|       Номер "{number["value"]}" уже существует.')
                        elif err2 == 7:
                            message = f'       Error: Группа телефонных номеров "{item["name"]}" не найдена в шаблоне "{template_name}".'
                            self.stepChanged.emit(f'RED|{message}\n          Импорт прерван. Перелогиньтесь в МС и повторите попытку.')
                            self.error = 1
                            return
                        else:
                            self.stepChanged.emit(f'BLACK|       Номер "{number["value"]}" импортирован.')
                else:
                    self.stepChanged.emit(f'GRAY|       Нет содержимого в группе телефонных номеров "{item["name"]}".')
            else:
                self.stepChanged.emit(f'GRAY|       Содержимое группы телефонных номеров "{item["name"]}" не импортировано так как она обновляется удалённо.')

        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте групп телефонных номеров.')
        else:
            self.stepChanged.emit('GREEN|    Импорт групп телефонных номеров завершён.')


    def import_custom_idps_signature(self, path, template_id, template_name):
        """Импортируем пользовательские сигнатуры СОВ."""
        json_file = os.path.join(path, 'custom_idps_signatures.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт пользовательских сигнатур СОВ в раздел "Библиотеки/Сигнатуры СОВ".')
        error = 0

        if not self.mc_data.get('realm_users_signatures', False):
            if self.get_idps_realm_users_signatures():        # Заполняем атрибут self.mc_data['realm_users_signatures']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте импорте пользовательских сигнатур СОВ.')
                return
        users_signatures = self.mc_data['realm_users_signatures']

        for item in data:
            if item['msg'] in users_signatures:
                if template_id == users_signatures[item['msg']].template_id:
                    self.stepChanged.emit(f'uGRAY|    Сигнатура СОВ "{item["msg"]}" уже существует в текущем шаблоне.')
                else:
                    message = f'Сигнатура СОВ "{item["msg"]}" уже существует в шаблоне "{users_signatures[item["msg"]].template_name}".'
                    if users_signatures[item['msg']].template_name not in self.selected_templates:
                        message = f'{message}\n       Сигнатура СОВ "{item["msg"]}" существует в шаблоне, отсутствующем в данной группе шаблонов.'
                    self.stepChanged.emit(f'sGREEN|    {message}')
            else:
                err, result = self.utm.add_template_idps_signature(template_id, item)
                if err:
                    self.stepChanged.emit(f'RED|    {result}  [Сигнатура СОВ "{item["msg"]}" не импортирована]')
                    error = 1
                else:
                    users_signatures[item['msg']] = BaseObject(id=result, template_id=template_id, template_name=template_name)
                    self.stepChanged.emit(f'BLACK|    Сигнатура СОВ "{item["msg"]}" импортирована.')
            self.msleep(1)
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте пользовательских сигнатур СОВ.')
        else:
            self.stepChanged.emit('GREEN|    Импорт пользовательских сигнатур СОВ завершён.')


    def import_idps_profiles(self, path, template_id, template_name):
        """Импортируем профили СОВ"""
        json_file = os.path.join(path, 'config_idps_profiles.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт профилей СОВ в раздел "Библиотеки/Профили СОВ".')
        error = 0

        # Получаем пользовательские сигнатуры СОВ.
        if not self.mc_data.get('realm_users_signatures', False):
            if self.get_idps_realm_users_signatures():        # Заполняем атрибут self.mc_data['realm_users_signatures']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей СОВ.')
                return

        self.stepChanged.emit(f'NOTE|    Получаем список сигнатур СОВ с МС, это может быть долго...')
        err, result = self.utm.get_template_idps_signatures_list(template_id)
        if err:
            self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте профилей СОВ.')
            self.error = 1
            return
        idps_signatures = {x['msg']: BaseObject(id=x['id'], template_id=template_id, template_name=template_name) for x in result}
        idps_signatures.update(self.mc_data['realm_users_signatures'])

        if not self.mc_data.get('idps_profiles', False):
            if self.get_idps_profiles():        # Заполняем self.mc_data['idps_profiles']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей СОВ.')
                return
        idps_profiles = self.mc_data['idps_profiles']

        for item in data:
            if 'filters' not in item:
                self.stepChanged.emit('RED|    Импорт профилей СОВ старых версий не поддерживается для версий 7.1 и выше.')
                error = 1
                break

            # Исключаем отсутствующие сигнатуры. И получаем ID сигнатур по имени так как ID может не совпадать.
            new_overrides = []
            for signature in item['overrides']:
                if 'msg' not in signature:
                    self.stepChanged.emit(f'RED|    Error: [Профиль СОВ "{item["name"]}"] Обнаружена пустая сигнатура СОВ в переопределённых сигнатурах.')
                    error = 1
                    continue
                try:
                    signature['id'] = idps_signatures[signature['msg']].id
                    new_overrides.append(signature)
                except KeyError as err:
                    self.stepChanged.emit(f'RED|    Error: [Профиль СОВ "{item["name"]}"] Не найдена сигнатура СОВ: {err} в переопределённых сигнатурах.')
                    error = 1
            item['overrides'] = new_overrides

            if item['name'] in idps_profiles:
                if template_id == idps_profiles[item['name']].template_id:
                    self.stepChanged.emit(f'uGRAY|    Профиль СОВ "{item["name"]}" уже существует в текущем шаблоне.')
                else:
                    self.stepChanged.emit(f'sGREEN|    Профиль СОВ "{item["name"]}" уже существует в шаблоне "{idps_profiles[item["name"]].template_name}".')
            else:
                err, result = self.utm.add_template_idps_profile(template_id, item)
                if err:
                    error = 1
                    self.stepChanged.emit(f'RED|    {result}  [Профиль СОВ "{item["name"]}" не импортирован]')
                else:
                    idps_profiles[item['name']] = BaseObject(id=result, template_id=template_id, template_name=template_name)
                    self.stepChanged.emit(f'BLACK|    Профиль СОВ "{item["name"]}" импортирован.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей СОВ.')
        else:
            self.stepChanged.emit('GREEN|    Импорт профилей СОВ завершён.')


    def import_notification_profiles(self, path, template_id, template_name):
        """Импортируем список профилей оповещения"""
        json_file = os.path.join(path, 'config_notification_profiles.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт профилей оповещений в раздел "Библиотеки/Профили оповещений".')
        error = 0

        if not self.mc_data.get('notification_profiles', False):
            if self.get_notification_profiles():        # Заполняем self.mc_data['notification_profiles']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей оповещений.')
                return
        notification_profiles = self.mc_data['notification_profiles']

        for item in data:
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя профиля')
            if item['name'] in notification_profiles:
                if template_id == notification_profiles[item['name']].template_id:
                    self.stepChanged.emit(f'uGRAY|    Профиль оповещения "{item["name"]}" уже существует в текущем шаблоне.')
                else:
                    self.stepChanged.emit(f'sGREEN|    Профиль оповещения "{item["name"]}" уже существует в шаблоне "{notification_profiles[item["name"]].template_name}".')
            else:
                err, result = self.utm.add_template_notification_profile(template_id, item)
                if err:
                    self.stepChanged.emit(f'RED|    {result}  [Профиль оповещения "{item["name"]}" не импортирован]')
                    error = 1
                elif err == 3:
                    self.stepChanged.emit(f'GRAY|    {result}')
                else:
                    notification_profiles[item['name']] = BaseObject(id=result, template_id=template_id, template_name=template_name)
                    self.stepChanged.emit(f'BLACK|    Профиль оповещения "{item["name"]}" импортирован.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей оповещений.')
        else:
            self.stepChanged.emit('GREEN|    Импорт профилей оповещений завершён.')


    def import_netflow_profiles(self, path, template_id, template_name):
        """Импортируем список профилей netflow"""
        json_file = os.path.join(path, 'config_netflow_profiles.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт профилей netflow в раздел "Библиотеки/Профили netflow".')
        error = 0

        if not self.mc_data.get('netflow_profiles', False):
            if self.get_netflow_profiles():        # Заполняем self.mc_data['netflow_profiles']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей netflow.')
                return
        netflow_profiles = self.mc_data['netflow_profiles']

        for item in data:
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя профиля')
            if item['name'] in netflow_profiles:
                if template_id == netflow_profiles[item['name']].template_id:
                    self.stepChanged.emit(f'uGRAY|    Профиль netflow "{item["name"]}" уже существует в текущем шаблоне.')
                else:
                    self.stepChanged.emit(f'sGREEN|    Профиль netflow "{item["name"]}" уже существует в шаблоне "{netflow_profiles[item["name"]].template_name}".')
            else:
                err, result = self.utm.add_template_netflow_profile(template_id, item)
                if err:
                    self.stepChanged.emit(f'RED|    {result}  [Профиль netflow "{item["name"]}" не импортирован]')
                    error = 1
                else:
                    netflow_profiles[item['name']] = BaseObject(id=result, template_id=template_id, template_name=template_name)
                    self.stepChanged.emit(f'BLACK|    Профиль netflow "{item["name"]}" импортирован.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей netflow.')
        else:
            self.stepChanged.emit('GREEN|    Импорт профилей netflow завершён.')


    def import_lldp_profiles(self, path, template_id, template_name):
        """Импортируем список профилей LLDP"""
        json_file = os.path.join(path, 'config_lldp_profiles.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт профилей LLDP в раздел "Библиотеки/Профили LLDP".')
        error = 0

        if not self.mc_data.get('lldp_profiles', False):
            if self.get_lldp_profiles():        # Заполняем self.mc_data['lldp_profiles']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей LLDP.')
                return
        lldp_profiles = self.mc_data['lldp_profiles']

        for item in data:
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя профиля')
            if item['name'] in lldp_profiles:
                if template_id == lldp_profiles[item['name']].template_id:
                    self.stepChanged.emit(f'uGRAY|    Профиль LLDP "{item["name"]}" уже существует в текущем шаблоне.')
                else:
                    self.stepChanged.emit(f'sGREEN|    Профиль LLDP "{item["name"]}" уже существует в шаблоне "{lldp_profiles[item["name"]].template_name}".')
            else:
                err, result = self.utm.add_template_lldp_profile(template_id, item)
                if err:
                    self.stepChanged.emit(f'RED|    {result}  [Профиль LLDP "{item["name"]}" не импортирован]')
                    error = 1
                else:
                    lldp_profiles[item['name']] = BaseObject(id=result, template_id=template_id, template_name=template_name)
                    self.stepChanged.emit(f'BLACK|    Профиль LLDP "{item["name"]}" импортирован.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей LLDP.')
        else:
            self.stepChanged.emit('GREEN|    Импорт профилей LLDP завершён.')


    def import_ssl_profiles(self, path, template_id, template_name):
        """Импортируем список профилей SSL"""
        json_file = os.path.join(path, 'config_ssl_profiles.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт профилей SSL в раздел "Библиотеки/Профили SSL".')
        error = 0
        ssl_profiles = self.mc_data['ssl_profiles']

        for item in data:
            if 'supported_groups' not in item:
                item['supported_groups'] = []
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя профиля')

            if item['name'] in ssl_profiles:
                if template_id == ssl_profiles[item['name']].template_id:
                    self.stepChanged.emit(f'uGRAY|    Профиль SSL "{item["name"]}" уже существует в текущем шаблоне.')
                else:
                    self.stepChanged.emit(f'sGREEN|    Профиль SSL "{item["name"]}" уже существует в шаблоне "{ssl_profiles[item["name"]].template_name}".')
            else:
                err, result = self.utm.add_template_ssl_profile(template_id, item)
                if err:
                    self.stepChanged.emit(f'RED|    {result}  [Профиль SSL "{item["name"]}" не импортирован]')
                    error = 1
                else:
                    ssl_profiles[item['name']] = BaseObject(id=result, template_id=template_id, template_name=template_name)
                    self.stepChanged.emit(f'BLACK|    Профиль SSL "{item["name"]}" импортирован.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей SSL.')
        else:
            self.stepChanged.emit('GREEN|    Импорт профилей SSL завершён.')


    def import_ssl_forward_profiles(self, path, template_id, template_name):
        """Импортируем профили пересылки SSL"""
        json_file = os.path.join(path, 'config_ssl_forward_profiles.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт профилей пересылки SSL в раздел "Библиотеки/Профили пересылки SSL".')
        error = 0

        if not self.mc_data.get('ssl_forward_profiles', False):
            if self.get_ssl_forward_profiles():        # Заполняем self.mc_data['ssl_forward_profiles']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей пересылки SSL.')
                return
        ssl_forward_profiles = self.mc_data['ssl_forward_profiles']

        for item in data:
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя профиля')
            if item['name'] in ssl_forward_profiles:
                if template_id == ssl_forward_profiles[item['name']].template_id:
                    self.stepChanged.emit(f'uGRAY|    Профиль пересылки SSL "{item["name"]}" уже существует в текущем шаблоне.')
                else:
                    self.stepChanged.emit(f'sGREEN|    Профиль пересылки SSL "{item["name"]}" уже существует в шаблоне "{ssl_forward_profiles[item["name"]].template_name}".')
            else:
                err, result = self.utm.add_template_ssl_forward_profile(template_id, item)
                if err:
                    error = 1
                    self.stepChanged.emit(f'RED|    {result}  [Профиль пересылки SSL "{item["name"]}" не импортирован]')
                else:
                    ssl_forward_profiles[item['name']] = BaseObject(id=result, template_id=template_id, template_name=template_name)
                    self.stepChanged.emit(f'BLACK|    Профиль пересылки SSL "{item["name"]}" импортирован.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей пересылки SSL.')
        else:
            self.stepChanged.emit('GREEN|    Импорт профилей пересылки SSL завершён.')


    def import_hip_objects(self, path, template_id, template_name):
        """Импортируем HIP объекты"""
        json_file = os.path.join(path, 'config_hip_objects.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт HIP объектов в раздел "Библиотеки/HIP объекты".')
        error = 0

        if not self.mc_data.get('hip_objects', False):
            if self.get_hip_objects():        # Заполняем self.mc_data['hip_objects']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте HIP объектов.')
                return
        hip_objects = self.mc_data['hip_objects']

        for item in data:
            if item['name'] in hip_objects:
                if template_id == hip_objects[item['name']].template_id:
                    self.stepChanged.emit(f'uGRAY|    HIP объект "{item["name"]}" уже существует в текущем шаблоне.')
                else:
                    self.stepChanged.emit(f'sGREEN|    HIP объект "{item["name"]}" уже существует в шаблоне "{hip_objects[item["name"]].template_name}".')
            else:
                err, result = self.utm.add_template_hip_object(template_id, item)
                if err:
                    self.stepChanged.emit(f'RED|    {result}  [HIP объект "{item["name"]}" не импортирован]')
                    error = 1
                else:
                    hip_objects[item['name']] = BaseObject(id=result, template_id=template_id, template_name=template_name)
                    self.stepChanged.emit(f'BLACK|    HIP объект "{item["name"]}" импортирован.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте HIP объектов.')
        else:
            self.stepChanged.emit('GREEN|    Импорт HIP объектов завершён.')


    def import_hip_profiles(self, path, template_id, template_name):
        """Импортируем HIP профили"""
        json_file = os.path.join(path, 'config_hip_profiles.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт HIP профилей в раздел "Библиотеки/HIP профили".')
        error = 0

        if not self.mc_data.get('hip_objects', False):
            if self.get_hip_objects():        # Заполняем self.mc_data['hip_objects']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте HIP профилей.')
                return
        hip_objects = self.mc_data['hip_objects']

        if not self.mc_data.get('hip_profiles', False):
            if self.get_hip_profiles():        # Заполняем self.mc_data['hip_profiles']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте HIP профилей.')
                return
        hip_profiles = self.mc_data['hip_profiles']

        for item in data:
            for obj in item['hip_objects']:
                obj['id'] = hip_objects[obj['id']].id
            if item['name'] in hip_profiles:
                if template_id == hip_profiles[item['name']].template_id:
                    self.stepChanged.emit(f'uGRAY|    HIP профиль "{item["name"]}" уже существует в текущем шаблоне.')
                else:
                    self.stepChanged.emit(f'sGREEN|    HIP профиль "{item["name"]}" уже существует в шаблоне "{hip_profiles[item["name"]].template_name}".')
            else:
                err, result = self.utm.add_template_hip_profile(template_id, item)
                if err:
                    self.stepChanged.emit(f'RED|    {result}  [HIP профиль "{item["name"]}" не импортирован]')
                    error = 1
                else:
                    hip_profiles[item['name']] = BaseObject(id=result, template_id=template_id, template_name=template_name)
                    self.stepChanged.emit(f'BLACK|    HIP профиль "{item["name"]}" импортирован.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте HIP профилей.')
        else:
            self.stepChanged.emit('GREEN|    Импорт HIP профилей завершён.')


    def import_bfd_profiles(self, path, template_id, template_name):
        """Импортируем профили BFD"""
        json_file = os.path.join(path, 'config_bfd_profiles.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт профилей BFD в раздел "Библиотеки/Профили BFD".')
        error = 0

        if not self.mc_data.get('bfd_profiles', False):
            if self.get_bfd_profiles():        # Заполняем self.mc_data['bfd_profiles']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте BFD профилей.')
                return
        bfd_profiles = self.mc_data['bfd_profiles']

        for item in data:
            if item['name'] in bfd_profiles:
                if template_id == bfd_profiles[item['name']].template_id:
                    self.stepChanged.emit(f'uGRAY|    Профиль BFD "{item["name"]}" уже существует в текущем шаблоне.')
                else:
                    self.stepChanged.emit(f'sGREEN|    Профиль BFD "{item["name"]}" уже существует в шаблоне "{bfd_profiles[item["name"]].template_name}".')
            else:
                err, result = self.utm.add_template_bfd_profile(template_id, item)
                if err:
                    self.stepChanged.emit(f'RED|    {result}  [Профиль BFD: "{item["name"]}" не импортирован]')
                    error = 1
                else:
                    bfd_profiles[item['name']] = BaseObject(id=result, template_id=template_id, template_name=template_name)
                    self.stepChanged.emit(f'BLACK|    Профиль BFD "{item["name"]}" импортирован.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей BFD.')
        else:
            self.stepChanged.emit('GREEN|    Импорт профилей BFD завершён.')


    def import_useridagent_syslog_filters(self, path, template_id, template_name):
        """Импортируем syslog фильтры UserID агента"""
        json_file = os.path.join(path, 'config_useridagent_syslog_filters.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт syslog фильтров UserID агента в раздел "Библиотеки/Syslog фильтры UserID агента".')
        error = 0

        if not self.mc_data.get('userid_filters', False):
            if self.get_useridagent_filters():        # Заполняем self.mc_data['userid_filters']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте syslog фильтров UserID агента.')
                return
        userid_filters = self.mc_data['userid_filters']

        for item in data:
            if item['name'] in userid_filters:
                if template_id == userid_filters[item['name']].template_id:
                    self.stepChanged.emit(f'uGRAY|    Фильтр агента UserID "{item["name"]}" уже существует в текущем шаблоне.')
                else:
                    self.stepChanged.emit(f'sGREEN|    Фильтр агента UserID "{item["name"]}" уже существует в шаблоне "{userid_filters[item["name"]].template_name}".')
            else:
                err, result = self.utm.add_template_useridagent_filter(template_id, item)
                if err:
                    self.stepChanged.emit(f'RED|    {result}  [Фильтр "{item["name"]}" не импортирован]')
                    error = 1
                else:
                    userid_filters[item['name']] = BaseObject(id=result, template_id=template_id, template_name=template_name)
                    self.stepChanged.emit(f'BLACK|    Фильтр "{item["name"]}" импортирован.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте syslog фильтров UserID агента.')
        else:
            self.stepChanged.emit('GREEN|    Импорт Syslog фильтров UserID агента завершён.')


    def import_scenarios(self, path, template_id, template_name):
        """Импортируем список сценариев"""
        json_file = os.path.join(path, 'config_scenarios.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт списка сценариев в раздел "Библиотеки/Сценарии".')
        error = 0
        scenarios = self.mc_data['scenarios']

        for item in data:
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя сценария')
            for condition in item['conditions']:
                if condition['kind'] == 'application':
                    for x in condition['apps']:
                        try:
                            if x[0] == 'ro_group':
                                x[1] = 0 if x[1] == 'All' else self.mc_data['l7_categories'][x[1]]
                            elif x[0] == 'group':
                                x[1] = self.mc_data['apps_groups'][x[1]].id
                        except KeyError as err:
                            self.stepChanged.emit(f'RED|    Error: [Сценарий "{item["name"]}"] Не найдена группа приложений {err}. Загрузите группы приложений и повторите попытку.')
                            item['description'] = f'{item["description"]}\nError: Не найдена группа приложений {err}.'
                            condition['apps'] = []
                            error = 1
                            break
                elif condition['kind'] == 'mime_types':
                    try:
                        condition['content_types'] = [self.mc_data['mime'][x].id for x in condition['content_types']]
                    except KeyError as err:
                        self.stepChanged.emit(f'RED|    Error: [Сценарий "{item["name"]}"] Не найден тип контента {err}. Загрузите типы контента и повторите попытку.')
                        item['description'] = f'{item["description"]}\nError: Не найден тип контента {err}.'
                        condition['content_types'] = []
                        error = 1
                elif condition['kind'] == 'url_category':
                    for x in condition['url_categories']:
                        try:
                            if x[0] == 'list_id':
                                x[1] = self.mc_data['url_categorygroups'][x[1]].id
                            elif x[0] == 'category_id':
                                x[1] = self.mc_data['url_categories'][x[1]]
                        except KeyError as err:
                            self.stepChanged.emit(f'RED|    Error: [Сценарий "{item["name"]}"] Не найдена группа URL категорий {err}. Загрузите категории URL и повторите попытку.')
                            item['description'] = f'{item["description"]}\nError: Не найдена группа URL категорий {err}.'
                            condition['url_categories'] = []
                            error = 1
                            break

            if item['name'] in scenarios:
                if template_id == scenarios[item['name']].template_id:
                    self.stepChanged.emit(f'uGRAY|    Сценарий "{item["name"]}" уже существует в текущем шаблоне.')
                else:
                    self.stepChanged.emit(f'sGREEN|    Сценарий "{item["name"]}" уже существует в шаблоне "{scenarios[item["name"]].template_name}".')
            else:
                err, result = self.utm.add_template_scenarios_rule(template_id, item)
                if err:
                    self.stepChanged.emit(f'RED|    {result}  [Сценарий "{item["name"]}" не импортирован]')
                    error = 1
                else:
                    scenarios[item['name']] = BaseObject(id=result, template_id=template_id, template_name=template_name)
                    self.stepChanged.emit(f'BLACK|    Сценарий "{item["name"]}" импортирован.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте списка сценариев.')
        else:
            self.stepChanged.emit('GREEN|    Импорт списка сценариев завершён.')


    #----------------------------------------- Сеть ------------------------------------------------
    def import_zones(self, path, template_id, template_name):
        """Импортируем зоны на NGFW, если они есть."""
        json_file = os.path.join(path, 'config_zones.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт зон в раздел "Сеть/Зоны".')
        mc_zones = self.mc_data['zones']
        error = 0

        for zone in data:
            error, zone['name'] = self.get_transformed_name(zone['name'], err=error, descr='Имя зоны')
            if zone['name'] in mc_zones:
                if template_id == mc_zones[zone['name']].template_id:
                    self.stepChanged.emit(f'uGRAY|    Зона "{zone["name"]}" уже существует в текущем шаблоне.')
                else:
                    self.stepChanged.emit(f'sGREEN|    Зона "{zone["name"]}" уже существует в шаблоне "{mc_zones[zone["name"]].template_name}".')
                continue

            current_zone = Zone(self, zone)
            zone['services_access'] = current_zone.services_access
            zone['enable_antispoof'] = current_zone.enable_antispoof
            zone['antispoof_invert'] = current_zone.antispoof_invert
            zone['networks'] = current_zone.networks
            zone['sessions_limit_enabled'] = current_zone.sessions_limit_enabled
            zone['sessions_limit_exclusions'] = current_zone.sessions_limit_exclusions
            zone['description'] = current_zone.description
            error = current_zone.error

            err, result = self.utm.add_template_zone(template_id, zone)
            if err == 3:
                self.stepChanged.emit(f'uGRAY|    {result}')
            elif err == 1:
                self.stepChanged.emit(f'RED|    {result} [Зона "{zone["name"]}" не импортирована]')
                error = 1
            else:
                mc_zones[zone['name']] = BaseObject(id=result, template_id=template_id, template_name=template_name)
                self.stepChanged.emit(f'BLACK|    Зона "{zone["name"]}" импортирована.')

        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте зон.')
        else:
            self.stepChanged.emit('GREEN|    Импорт Зон завершён.')


    def import_interfaces(self, path, template_id, template_name):
        """Импортируем интерфейсы."""
        json_file = os.path.join(path, 'config_interfaces.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit(f'BLUE|Импорт интерфейсов.')
        if not self.mc_data.get('interfaces', False):
            if self.get_interfaces_list():        # Получаем все интерфейсы группы шаблонов и заполняем: self.mc_data['interfaces']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте интерфейсов.')
                return

        if not self.mc_data.get('netflow_profiles', False):
            if self.get_netflow_profiles():        # Заполняем self.mc_data['netflow_profiles']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте интерфейсов.')
                return

        if not self.mc_data.get('lldp_profiles', False):
            if self.get_lldp_profiles():        # Заполняем self.mc_data['lldp_profiles']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте интерфейсов.')
                return

        kinds = set()
        for item in data:
            kinds.add(item['kind'])

        if 'adapter' in kinds:
            self.import_adapter_interfaces(path, data, template_id, template_name)
        if kinds.intersection({'bond', 'bridge'}):
            self.import_bond_interfaces(path, data, template_id, template_name)
        if 'tunnel' in kinds:
            self.import_ipip_interfaces(path, data, template_id, template_name)
        if 'vpn' in kinds:
            self.import_vpn_interfaces(path, data, template_id, template_name)
        if 'vlan' in kinds:
            self.import_vlan_interfaces(path, data, template_id, template_name)


    def import_adapter_interfaces(self, path, data, template_id, template_name):
        """Импортируем интерфесы типа ADAPTER."""
        self.stepChanged.emit('BLUE|    Импорт сетевых адаптеров в раздел "Сеть/Интерфейсы"')
        error = 0

        mc_ifaces = self.mc_data['interfaces']
        netflow_profiles = self.mc_data['netflow_profiles']
        lldp_profiles = self.mc_data['lldp_profiles']

        for item in data:
            if 'kind' in item and item['kind'] == 'adapter':
                iface_name = f'{item["name"]}:{item["node_name"]}'
                if iface_name in mc_ifaces:
                    if template_id == mc_ifaces[iface_name].template_id:
                        self.stepChanged.emit(f'uGRAY|       Интерфейс "{item["name"]}" уже существует в текущем шаблоне на узле кластера "{item["node_name"]}".')
                    else:
                        self.stepChanged.emit(f'sGREEN|       Интерфейс "{item["name"]}" уже существует в шаблоне "{mc_ifaces[iface_name].template_name}" на узле кластера "{item["node_name"]}".')
                    continue
                if item['name'] == 'port0':
                    self.stepChanged.emit(f'LBLUE|       Интерфейс "{item["name"]}" не может быть импортирован в шаблон МС.')
                    continue

                item.pop('running', None)
                item.pop('master', None)
                item.pop('mac', None)
                item.pop('id', None)

                if 'config_on_device' not in item:
                    item['config_on_device'] = False

                if item['zone_id']:
                    try:
                        item['zone_id'] = self.mc_data['zones'][item['zone_id']].id
                    except KeyError as err:
                        self.stepChanged.emit(f'RED|       Error: [Интерфейс "{item["name"]}"] Не найдена зона {err}. Импортируйте зоны и повторите попытку.')
                        item['zone_id'] = 0
                        error = 1

                new_ipv4 = []
                for ip in item['ipv4']:
                    err, result = self.unpack_ip_address(ip)
                    if err:
                        self.stepChanged.emit(f'RED|       Error: [Интерфейс "{item["name"]}"] Не удалось преобразовать IP: "{ip}". IP-адрес использован не будет. {result}')
                        error = 1
                    else:
                        new_ipv4.append(result)
                if not new_ipv4 and item['mode'] != 'keep':
                    item['mode'] = 'manual'
                item['ipv4'] = new_ipv4

                try:
                    item['lldp_profile'] = lldp_profiles[item['lldp_profile']].id
                except KeyError:
                    self.stepChanged.emit(f'RED|       Error: [Интерфейс "{item["name"]}"] Не найден lldp profile "{item["lldp_profile"]}". Импортируйте профили LLDP и повторите попытку.')
                    item['lldp_profile'] = 'undefined'
                    error = 1
                try:
                    item['netflow_profile'] = netflow_profiles[item['netflow_profile']].id
                except KeyError:
                    self.stepChanged.emit(f'RED|       Error: [Интерфейс "{item["name"]}"] Не найден netflow profile "{item["netflow_profile"]}". Импортируйте профили netflow и повторите попытку.')
                    item['netflow_profile'] = 'undefined'
                    error = 1

                err, result = self.utm.add_template_interface(template_id, item)
                if err:
                    self.stepChanged.emit(f'RED|       {result} [Интерфейс {item["name"]} не импортирован]')
                    error = 1
                else:
                    mc_ifaces[iface_name] = BaseObject(id=result, template_id=template_id, template_name=template_name)
                    self.stepChanged.emit(f'BLACK|       Сетевой адаптер "{item["name"]}" импортирован на узел кластера "{item["node_name"]}".')

        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|       Произошла ошибка при создании сетевых адаптеров.')
        else:
            self.stepChanged.emit('GREEN|       Импорт сетевых адаптеров завершён.')


    def import_bond_interfaces(self, path, data, template_id, template_name):
        """Импортируем Бонд-интерфесы."""
        self.stepChanged.emit('BLUE|    Импорт агрегированных интерфейсов в раздел "Сеть/Интерфейсы"')
        error = 0

        mc_ifaces = self.mc_data['interfaces']
        netflow_profiles = self.mc_data['netflow_profiles']
        lldp_profiles = self.mc_data['lldp_profiles']

        for item in data:
            if 'kind' in item and item['kind'] in ('bond', 'bridge'):
                iface_name = f'{item["name"]}:{item["node_name"]}'
                if iface_name in mc_ifaces:
                    if template_id == mc_ifaces[iface_name].template_id:
                        self.stepChanged.emit(f'uGRAY|       Интерфейс "{item["name"]}" уже существует в текущем шаблоне на узле кластера "{item["node_name"]}".')
                    else:
                        self.stepChanged.emit(f'sGREEN|       Интерфейс "{item["name"]}" уже существует в шаблоне "{mc_ifaces[iface_name].template_name}" на узле кластера "{item["node_name"]}".')
                    continue
                if item['kind'] == 'bond':
                    if 'port0' in item['bonding']['slaves']:
                        self.stepChanged.emit(f'RED|       Error: Интерфейс "{item["name"]}" не импортирован в шаблон МС так как содержит "port0".')
                        error = 1
                        continue
                elif item['kind'] == 'bridge':
                    if 'port0' in item['bridging']['ports']:
                        self.stepChanged.emit(f'RED|       Error: Интерфейс "{item["name"]}" не импортирован в шаблон МС так как содержит "port0".')
                        error = 1
                        continue

                item.pop('running', None)
                item.pop('mac', None)
                item.pop('id', None)

                if 'config_on_device' not in item:
                    item['config_on_device'] = False

                if item['zone_id']:
                    try:
                        item['zone_id'] = self.mc_data['zones'][item['zone_id']].id
                    except KeyError as err:
                        self.stepChanged.emit(f'RED|       Error: [Интерфейс "{item["name"]}"] Не найдена зона {err}. Импортируйте зоны и повторите попытку.')
                        item['zone_id'] = 0
                        error = 1

                new_ipv4 = []
                for ip in item['ipv4']:
                    err, result = self.unpack_ip_address(ip)
                    if err:
                        self.stepChanged.emit(f'RED|       Error: [Интерфейс "{item["name"]}"] Не удалось преобразовать IP: "{ip}". IP-адрес использован не будет. {result}')
                        error = 1
                    else:
                        new_ipv4.append(result)
                if not new_ipv4 and item['mode'] != 'keep':
                    item['mode'] = 'manual'
                item['ipv4'] = new_ipv4

                try:
                    item['lldp_profile'] = lldp_profiles[item['lldp_profile']].id
                except KeyError:
                    self.stepChanged.emit(f'RED|       Error: [Интерфейс "{item["name"]}"] Не найден lldp profile "{item["lldp_profile"]}". Импортируйте профили LLDP и повторите попытку.')
                    item['lldp_profile'] = 'undefined'
                    error = 1
                try:
                    item['netflow_profile'] = netflow_profiles[item['netflow_profile']].id
                except KeyError:
                    self.stepChanged.emit(f'RED|       Error: [Интерфейс "{item["name"]}"] Не найден netflow profile "{item["netflow_profile"]}". Импортируйте профили netflow и повторите попытку.')
                    item['netflow_profile'] = 'undefined'
                    error = 1

                err, result = self.utm.add_template_interface(template_id, item)
                if err:
                    self.stepChanged.emit(f'RED|       {result} [Интерфейс {item["name"]} не импортирован]')
                    error = 1
                else:
                    mc_ifaces[iface_name] = BaseObject(id=result, template_id=template_id, template_name=template_name)
                    self.stepChanged.emit(f'BLACK|       Интерфейс "{item["name"]}" импортирован на узел кластера "{item["node_name"]}".')

        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|       Произошла ошибка при создании агрегированных интерфейсов.')
        else:
            self.stepChanged.emit('GREEN|       Импорт агрегированных интерфейсов завершён.')


    def import_ipip_interfaces(self, path, data, template_id, template_name):
        """Импортируем интерфесы IP-IP."""
        self.stepChanged.emit('BLUE|    Импорт интерфейсов GRE/IPIP/VXLAN в раздел "Сеть/Интерфейсы".')
        mc_ifaces = self.mc_data['interfaces']
        error = 0

        for item in data:
            if 'kind' in item and item['kind'] == 'tunnel' and item['name'].startswith('gre'):
                item.pop('id', None)          # удаляем readonly поле
                item.pop('master', None)      # удаляем readonly поле
                item.pop('mac', None)

                iface_name = f'{item["name"]}:{item["node_name"]}'
                if iface_name in mc_ifaces:
                    if template_id == mc_ifaces[iface_name].template_id:
                        self.stepChanged.emit(f'uGRAY|       Интерфейс "{item["name"]}" уже существует в текущем шаблоне на узле кластера "{item["node_name"]}".')
                    else:
                        self.stepChanged.emit(f'sGREEN|       Интерфейс "{item["name"]}" уже существует в шаблоне "{mc_ifaces[iface_name].template_name}" на узле кластера "{item["node_name"]}".')
                    continue

                if item['zone_id']:
                    try:
                        item['zone_id'] = self.mc_data['zones'][item['zone_id']].id
                    except KeyError as err:
                        self.stepChanged.emit(f'RED|       Error: [Интерфейс "{item["name"]}"] Не найдена зона {err}. Импортируйте зоны и повторите попытку.')
                        item['zone_id'] = 0
                        error = 1

                new_ipv4 = []
                for ip in item['ipv4']:
                    err, result = self.unpack_ip_address(ip)
                    if err:
                        self.stepChanged.emit(f'RED|       Error: [Интерфейс "{item["name"]}"] Не удалось преобразовать IP: "{ip}". IP-адрес использован не будет. {result}')
                        error = 1
                    else:
                        new_ipv4.append(result)
                if not new_ipv4 and item['mode'] != 'keep':
                    item['mode'] = 'manual'
                    item['config_on_device'] = True
                item['ipv4'] = new_ipv4

                err, result = self.utm.add_template_interface(template_id, item)
                if err:
                    self.stepChanged.emit(f'RED|       {result} [Интерфейс "{item["tunnel"]["mode"]} - {item["name"]}" не импортирован]')
                    error = 1
                else:
                    mc_ifaces[iface_name] = BaseObject(id=result, template_id=template_id, template_name=template_name)
                    self.stepChanged.emit(f'BLACK|       Интерфейс {item["tunnel"]["mode"]} - {item["name"]} импортирован на узел кластера "{item["node_name"]}".')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|       Произошла ошибка при создании интерфейсов GRE/IPIP/VXLAN.')
        else:
            self.stepChanged.emit('GREEN|       Импорт интерфейсов GRE/IPIP/VXLAN завершён.')


    def import_vpn_interfaces(self, path, data, template_id, template_name):
        """Импортируем интерфесы VPN."""
        self.stepChanged.emit('BLUE|    Импорт интерфейсов VPN в раздел "Сеть/Интерфейсы"')
        error = 0

        mc_ifaces = self.mc_data['interfaces']
        netflow_profiles = self.mc_data['netflow_profiles']
        lldp_profiles = self.mc_data['lldp_profiles']

        for item in data:
            if 'kind' in item and item['kind'] == 'vpn':
                item['node_name'] = 'cluster'
                item.pop('running', None)
                item.pop('master', None)
                item.pop('mac', None)
                item.pop('id', None)

                iface_name = f'{item["name"]}:cluster'
                if iface_name in mc_ifaces:
                    if template_id == mc_ifaces[iface_name].template_id:
                        self.stepChanged.emit(f'uGRAY|       Интерфейс "{item["name"]}" уже существует в текущем шаблоне на узле кластера "{item["node_name"]}".')
                    else:
                        self.stepChanged.emit(f'sGREEN|       Интерфейс "{item["name"]}" уже существует в шаблоне "{mc_ifaces[iface_name].template_name}" на узле кластера "{item["node_name"]}".')
                    continue

                if item['zone_id']:
                    try:
                        item['zone_id'] = self.mc_data['zones'][item['zone_id']].id
                    except KeyError as err:
                        self.stepChanged.emit(f'RED|       Error: [Интерфейс "{item["name"]}"] Не найдена зона {err}. Импортируйте зоны и повторите попытку.')
                        item['zone_id'] = 0
                        error = 1

                new_ipv4 = []
                for ip in item['ipv4']:
                    err, result = self.unpack_ip_address(ip)
                    if err:
                        self.stepChanged.emit(f'RED|       Error: [Интерфейс "{item["name"]}"] Не удалось преобразовать IP: "{ip}". IP-адрес использован не будет. {result}')
                        error = 1
                    else:
                        new_ipv4.append(result)
                if not new_ipv4 and item['mode'] != 'keep':
                    item['mode'] = 'manual'
                item['ipv4'] = new_ipv4

                try:
                    item['lldp_profile'] = lldp_profiles[item['lldp_profile']].id
                except KeyError:
                    self.stepChanged.emit(f'RED|       Error: [Интерфейс "{item["name"]}"] Не найден lldp profile "{item["lldp_profile"]}". Импортируйте профили LLDP и повторите попытку.')
                    item['lldp_profile'] = 'undefined'
                    error = 1
                try:
                    item['netflow_profile'] = netflow_profiles[item['netflow_profile']].id
                except KeyError:
                    self.stepChanged.emit(f'RED|       Error: [Интерфейс "{item["name"]}"] Не найден netflow profile "{item["netflow_profile"]}". Импортируйте профили netflow и повторите попытку.')
                    item['netflow_profile'] = 'undefined'
                    error = 1

                err, result = self.utm.add_template_interface(template_id, item)
                if err:
                    self.stepChanged.emit(f'RED|       {result} [Интерфейс {item["name"]} не импортирован]')
                    error = 1
                else:
                    mc_ifaces[iface_name] = BaseObject(id=result, template_id=template_id, template_name=template_name)
                    self.stepChanged.emit(f'BLACK|       Интерфейс VPN "{item["name"]}" импортирован на узел кластера "cluster".')

        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|       Произошла ошибка при создании интерфейсов VPN.')
        else:
            self.stepChanged.emit('GREEN|       Импорт интерфейсов VPN завершён.')


    def import_vlan_interfaces(self, path, data, template_id, template_name):
        """Импортируем интерфесы VLAN."""
        self.stepChanged.emit('BLUE|    Импорт интерфейсов VLAN в раздел "Сеть/Интерфейсы"')
        error = 0

        mc_ifaces = self.mc_data['interfaces']
        netflow_profiles = self.mc_data['netflow_profiles']
        lldp_profiles = self.mc_data['lldp_profiles']

        for item in data:
            if 'kind' in item and item['kind'] == 'vlan':
                iface_name = f'{item["name"]}:{item["node_name"]}'
                if iface_name in mc_ifaces:
                    if template_id == mc_ifaces[iface_name].template_id:
                        self.stepChanged.emit(f'uGRAY|       Интерфейс "{item["name"]}" уже существует в текущем шаблоне на узле кластера "{item["node_name"]}".')
                    else:
                        self.stepChanged.emit(f'sGREEN|       Интерфейс "{item["name"]}" уже существует в шаблоне "{mc_ifaces[iface_name].template_name}" на узле кластера "{item["node_name"]}".')
                    continue
                if item['link'] == 'port0':
                    self.stepChanged.emit(f'LBLUE|       Интерфейс "{item["name"]}" не может быть импортирован в шаблон МС так как привязан к port0.')
                    continue

                item.pop('running', None)
                item.pop('master', None)
                item.pop('mac', None)
                item.pop('id', None)

                if 'config_on_device' not in item:
                    item['config_on_device'] = False

                if item['zone_id']:
                    try:
                        item['zone_id'] = self.mc_data['zones'][item['zone_id']].id
                    except KeyError as err:
                        self.stepChanged.emit(f'RED|       Error: [Интерфейс "{item["name"]}"] Не найдена зона {err}. Импортируйте зоны и повторите попытку.')
                        item['zone_id'] = 0
                        error = 1

                new_ipv4 = []
                for ip in item['ipv4']:
                    err, result = self.unpack_ip_address(ip)
                    if err:
                        self.stepChanged.emit(f'RED|       Error: [Интерфейс "{item["name"]}"] Не удалось преобразовать IP: "{ip}". IP-адрес использован не будет. {result}')
                        error = 1
                    else:
                        new_ipv4.append(result)
                if not new_ipv4 and item['mode'] != 'keep':
                    item['mode'] = 'manual'
                item['ipv4'] = new_ipv4

                try:
                    item['lldp_profile'] = lldp_profiles[item['lldp_profile']].id
                except KeyError:
                    self.stepChanged.emit(f'RED|       Error: [Интерфейс "{item["name"]}"] Не найден lldp profile "{item["lldp_profile"]}". Импортируйте профили LLDP и повторите попытку.')
                    item['lldp_profile'] = 'undefined'
                    error = 1
                try:
                    item['netflow_profile'] = netflow_profiles[item['netflow_profile']].id
                except KeyError:
                    self.stepChanged.emit(f'RED|       Error: [Интерфейс "{item["name"]}"] Не найден netflow profile "{item["netflow_profile"]}". Импортируйте профили netflow и повторите попытку.')
                    item['netflow_profile'] = 'undefined'
                    error = 1

                err, result = self.utm.add_template_interface(template_id, item)
                if err:
                    self.stepChanged.emit(f'RED|       {result} [Интерфейс "{item["name"]}" не импортирован]')
                    error = 1
                else:
                    mc_ifaces[iface_name] = BaseObject(id=result, template_id=template_id, template_name=template_name)
                    self.stepChanged.emit(f'BLACK|       Интерфейс VLAN "{item["name"]}" импортирован на узел кластера "{item["node_name"]}".')

        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|       Произошла ошибка при создании интерфейсов VLAN.')
        else:
            self.stepChanged.emit('GREEN|       Импорт интерфейсов VLAN завершён.')


    def import_gateways(self, path, template_id, template_name):
        self.import_gateways_list(path, template_id, template_name)
        self.import_gateway_failover(path, template_id, template_name)


    def import_gateways_list(self, path, template_id, template_name):
        """Импортируем список шлюзов"""
        json_file = os.path.join(path, 'config_gateways.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт шлюзов в раздел "Сеть/Шлюзы".')
        error = 0

        if not self.mc_data.get('interfaces', False):
            if self.get_interfaces_list():        # Получаем все интерфейсы группы шаблонов и заполняем: self.mc_data['interfaces']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте шлюзов.')
                return
        mc_ifaces = self.mc_data['interfaces'].keys()

        if self.get_gateways_list():           # Получаем все шлюзы группы шаблонов и заполняем: self.mc_data['gateways']
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте шлюзов.')
            return
        gateways = self.mc_data['gateways']

        if self.get_vrf_list():                # Получаем все VRF группы шаблонов и заполняем: self.mc_data['vrf']
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте шлюзов.')
            return
        mc_vrf = self.mc_data['vrf']

        gateways_vrf = {item['vrf']: [] for item in data}
        for item in data:
            if f'{item["iface"]}:{item["node_name"]}' in mc_ifaces:
                gateways_vrf[item['vrf']].append(item['iface'])

        for item in data:
            item['is_automatic'] = False

            # Создаём новый VRF если такого ещё нет для этого узла кластера с интерфейсами, которые используются в шлюзах.
            vrf_name = f'{item["vrf"]}:{item["node_name"]}'
            if vrf_name not in mc_vrf:
                err, result = self.add_empty_vrf(item['vrf'], gateways_vrf[item['vrf']], item['node_name'], template_id)
                if err:
                    self.stepChanged.emit(f'RED|    {result}\n    Error: Для шлюза "{item["name"]}" не удалось добавить VRF "{item["vrf"]}". Установлен VRF по умолчанию.')
                    item['vrf'] = 'default'
                    item['default'] = False
                    error = 1
                else:
                    self.stepChanged.emit(f'NOTE|    Для шлюза "{item["name"]}" создан VRF "{item["vrf"]}" на узле кластера "{item["node_name"]}".')
                    mc_vrf[vrf_name] = BaseObject(id=result, template_id=template_id, template_name=template_name)

            if item['iface'] not in gateways_vrf[item['vrf']]:
                item['iface'] = 'undefined'

            gateway_name = f'{item["name"]}:{item["node_name"]}'
            if gateway_name in gateways:
                if template_id == gateways[gateway_name].template_id:
                    self.stepChanged.emit(f'uGRAY|    Шлюз "{item["name"]}" уже существует в текущем шаблоне на узле кластера "{item["node_name"]}".')
                else:
                    self.stepChanged.emit(f'sGREEN|    Шлюз "{item["name"]}" уже существует в шаблоне "{gateways[gateway_name].template_name}" на узле кластера "{item["node_name"]}".')
            else:
                err, result = self.utm.add_template_gateway(template_id, item)
                if err:
                    self.stepChanged.emit(f'RED|    {result}  [Шлюз "{item["name"]}" не импортирован]')
                    error = 1
                else:
                    gateways[gateway_name] = BaseObject(id=result, template_id=template_id, template_name=template_name)
                    self.stepChanged.emit(f'BLACK|    Шлюз "{item["name"]}" импортирован на узел кластера "{item["node_name"]}".')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте шлюзов.')
        else:
            self.stepChanged.emit('GREEN|    Импорт шлюзов завершён.')


    def import_gateway_failover(self, path, template_id, template_name):
        """Импортируем настройки проверки сети"""
        json_file = os.path.join(path, 'config_gateway_failover.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт настроек проверки сети раздела "Сеть/Шлюзы/Проверка сети".')

        err, result = self.utm.update_template_gateway_failover(template_id, data)
        if err:
            self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при обновлении настроек проверки сети.')
            self.error = 1
        else:
            self.stepChanged.emit('GREEN|    Настройки проверки сети обновлены.')


    def import_dhcp_subnets(self, path, template_id, template_name):
        """Импортируем настойки DHCP"""
        json_file = os.path.join(path, 'config_dhcp_subnets.json')
        err, self.dhcp_settings = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт настроек DHCP раздела "Сеть/DHCP".')
        if not self.mc_data.get('interfaces', False):
            if self.get_interfaces_list():        # Получаем все интерфейсы группы шаблонов и заполняем: self.mc_data['interfaces']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте настроек DHCP.')
                return
        mc_ifaces = self.mc_data['interfaces']

        mc_dhcp_subnets = {}
        for name, uid in self.group_templates[self.selected_group].items():
            err, result = self.utm.get_template_dhcp_list(uid)
            if err:
                self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте настроек DHCP.')
                self.error = 1
                return
            mc_dhcp_subnets.update({f'{x["name"]}:{x["node_name"]}': name for x in result})
        error = 0

        for item in self.dhcp_settings:
            if item['iface_id'] == 'Undefined':
                self.stepChanged.emit(f'GRAY|    DHCP subnet "{item["name"]}" не добавлен так как для него не указан порт.')
                continue

            iface_name = f'{item["iface_id"]}:{item["node_name"]}'
            if iface_name not in mc_ifaces:
                self.stepChanged.emit(f'rNOTE|    DHCP subnet "{item["name"]}" не добавлен так как порт "{item["iface_id"]}" не существует для узла "{item["node_name"]}" в группе шаблонов.')
                continue

            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя DHCP subnet')
            full_name = f'{item["name"]}:{item["node_name"]}'
            if full_name in mc_dhcp_subnets:
                self.stepChanged.emit(f'sGREEN|    DHCP subnet "{item["name"]}" уже существует в шаблоне "{mc_dhcp_subnets[full_name]}" на узле кластера "{item["node_name"]}".')
                continue

            err, result = self.utm.add_template_dhcp_subnet(template_id, item)
            if err == 1:
                self.stepChanged.emit(f'RED|    {result}  [subnet "{item["name"]}" не импортирован]')
                error = 1
            elif err == 3:
                self.stepChanged.emit(f'GRAY|    {result}.')
            else:
                self.stepChanged.emit(f'BLACK|    DHCP subnet "{item["name"]}" импортирован на узел кластера "{item["node_name"]}".')

        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте настроек DHCP.')
        else:
            self.stepChanged.emit('GREEN|    Импорт настроек DHCP завершён.')


    def import_dns_config(self, path, template_id, template_name):
        """Импортируем раздел 'UserGate/DNS'."""
        self.import_dns_servers(path, template_id)
        self.import_dns_proxy(path, template_id)
        self.import_dns_rules(path, template_id)
        self.import_dns_static(path, template_id)


    def import_dns_servers(self, path, template_id):
        """Импортируем список системных DNS серверов"""
        json_file = os.path.join(path, 'config_dns_servers.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт системных DNS серверов в раздел "Сеть/DNS/Системные DNS-серверы".')
        error = 0

        for item in data:
            item.pop('is_bad', None)
            err, result = self.utm.add_template_dns_server(template_id, item)
            if err == 3:
                self.stepChanged.emit(f'GRAY|    {result}')
            elif err == 1:
                self.stepChanged.emit(f'RED|    {result} [DNS сервер "{item["dns"]}" не импортирован]')
                error = 1
            else:
                self.stepChanged.emit(f'BLACK|    DNS сервер "{item["dns"]}" импортирован.')

        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте DNS-серверов.')
        else:
            self.stepChanged.emit('GREEN|    Импорт системных DNS-серверов завершён.')


    def import_dns_proxy(self, path, template_id):
        """Импортируем настройки DNS прокси"""
        json_file = os.path.join(path, 'config_dns_proxy.json')
        err, result = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт настроек DNS-прокси раздела "Сеть/DNS/Настройки DNS-прокси".')
        error = 0

        for key, value in result.items():
            value = {'enabled': True, 'code': key, 'value': value}
            err, result = self.utm.update_template_dns_setting(template_id, key, value)
            if err:
                self.stepChanged.emit(f'RED|    {result}')
                error = 1
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте настроек DNS-прокси!')
        else:
            self.stepChanged.emit('GREEN|    Настройки DNS-прокси импортированы.')


    def import_dns_rules(self, path, template_id):
        """Импортируем правила DNS-прокси"""
        json_file = os.path.join(path, 'config_dns_rules.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт правил DNS-прокси в раздел "Сеть/DNS/DNS-прокси/Правила DNS".')
        error = 0

        for item in data:
            err, result = self.utm.add_template_dns_rule(template_id, item)
            if err == 3:
                self.stepChanged.emit(f'GRAY|    {result}')
            elif err == 1:
                self.stepChanged.emit(f'RED|    {result} [Правило DNS-прокси "{item["name"]}" не импортировано]')
                error = 1
            else:
                self.stepChanged.emit(f'BLACK|    Правило DNS-прокси "{item["name"]}" импортировано.')

        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил DNS-прокси.')
        else:
            self.stepChanged.emit('GREEN|    Импорт правил DNS-прокси завершён.')


    def import_dns_static(self, path, template_id):
        """Импортируем статические записи DNS"""
        json_file = os.path.join(path, 'config_dns_static.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт статических записей DNS в раздел "Сеть/DNS/DNS-прокси/Статические записи".')
        error = 0

        for item in data:
            err, result = self.utm.add_template_dns_static_record(template_id, item)
            if err == 3:
                self.stepChanged.emit(f'GRAY|    {result}')
            elif err == 1:
                self.stepChanged.emit(f'RED|    {result} [Статическая запись DNS "{item["name"]}" не импортирована]')
                error = 1
            else:
                self.stepChanged.emit(f'BLACK|    Статическая запись DNS "{item["name"]}" импортирована.')

        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте статических записей DNS.')
        else:
            self.stepChanged.emit('GREEN|    Импорт статических записей DNS завершён.')


    def import_vrf(self, path, template_id, template_name):
        """Импортируем виртуальный маршрутизатор по умолчанию"""
        json_file = os.path.join(path, 'config_vrf.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт виртуальных маршрутизаторов в раздел "Сеть/Виртуальные маршрутизаторы".')
        self.stepChanged.emit('LBLUE|    Если вы используете BGP, после импорта включите нужные фильтры in/out для BGP-соседей и Routemaps в свойствах соседей.')
        error = 0
    
        if self.get_vrf_list():                # Получаем все VRF группы шаблонов и заполняем: self.mc_data['vrf']
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте виртуальных маршрутизаторов.')
            return
        mc_vrf = self.mc_data['vrf']

        if not self.mc_data.get('interfaces', False):
            if self.get_interfaces_list():     # Получаем все интерфейсы группы шаблонов и заполняем: self.mc_data['interfaces']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте шлюзов.')
                return
        mc_ifaces = self.mc_data['interfaces'].keys()

        if not self.mc_data.get('bfd_profiles', False):
            if self.get_bfd_profiles():        # Получаем все профили BFD группы шаблонов и заполняем: self.mc_data['bfd_profiles']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте виртуальных маршрутизаторов.')
                return
        bfd_profiles = self.mc_data['bfd_profiles']
        bfd_profiles[-1] = BaseObject(id=-1, template_id='', template_name='')

        vrfnames = []
        for item in data:
            if item['name'] in vrfnames:
                self.stepChanged.emit(f'rNOTE|    VRF "{item["name"]}" не импортирован так как VRF с таким именем уже был импортирован выше.')
                continue
            else:
                vrfnames.append(item['name'])

            vrf_name = f'{item["name"]}:{item["node_name"]}'
            if vrf_name in mc_vrf:
                if template_id != mc_vrf[vrf_name].template_id:
                    self.stepChanged.emit(f'sGREEN|    VRF "{item["name"]}" уже существует в шаблоне "{mc_vrf[vrf_name].template_name}" на узле кластера "{item["node_name"]}".')
                    continue

            new_interfaces = []
            for x in item['interfaces']:
                if f'{x}:{item["node_name"]}' in mc_ifaces:
                    new_interfaces.append(x)
                else:
                    self.stepChanged.emit(f'RED|    Error: [VRF "{item["name"]}"] Из VRF удалён интерфейс "{x}" так как отсутствует на узле кластера "{item["node_name"]}".')
                    error = 1
            item['interfaces'] = new_interfaces

            for x in item['routes']:
                x['name'] = self.get_transformed_name(x['name'], descr='Имя route')[1]
                if x['ifname'] != 'undefined':
                    if f'{x["ifname"]}:{item["node_name"]}' not in mc_ifaces:
                        if f'{x["ifname"]}:cluster' not in mc_ifaces:
                            self.stepChanged.emit(f'RED|    Error: [VRF "{item["name"]}"] Интерфейс "{x["ifname"]}" удалён из статического маршрута "{x["name"]}" так как отсутствует на узле кластера "{item["node_name"]}".')
                            x['ifname'] = 'undefined'
                            error = 1

            if item['ospf']:
                ids = set()
                new_interfaces = []
                for iface in item['ospf']['interfaces']:
                    iface['network_type'] = iface.get('network_type', '')   # Добавляем поле, отсутствующее с старых версиях
                    iface['is_passive'] = iface.get('is_passive', False)    # Добавляем поле, отсутствующее с старых версиях
                    if item['name'] != 'default' and iface['iface_id'] not in item['interfaces']:
                        self.stepChanged.emit(f'RED|    Error: [VRF "{item["name"]}"] Интерфейс OSPF "{iface["iface_id"]}" удалён из настроек OSPF так как отсутствует в этом VRF.')
                        ids.add(iface['id'])
                        error = 1
                    else:
                        try:
                            iface['bfd_profile'] = bfd_profiles[iface['bfd_profile']].id
                        except KeyError as err:
                            self.stepChanged.emit(f'RED|    Error: [VRF "{item["name"]}"] Для OSPF не найден профиль BFD {err}. Установлено значение по умолчанию.')
                            iface['bfd_profile'] = -1
                            error = 1
                        new_interfaces.append(iface)
                item['ospf']['interfaces'] = new_interfaces

                new_areas = []
                for area in item['ospf']['areas']:
                    err, result = self.unpack_ip_address(area['area_id'])
                    if err:
                        try:
                            area['area_id'] = int(area['area_id'])
                        except ValueError:
                            self.stepChanged.emit(f'RED|    Error: [VRF "{item["name"]}"] Область OSPF "{area["name"]}" удалёна из настроек OSPF так как у неё не валидный идентификатор области.')
                            error = 1
                            continue
                    tmp = set(area['interfaces'])
                    if not (tmp - ids):
                        self.stepChanged.emit(f'RED|    Error: [VRF "{item["name"]}"] Область OSPF "{area["name"]}" удалёна из настроек OSPF так как у неё отсутствуют интерфейсы.')
                        error = 1
                    else:
                        new_areas.append(area)
                item['ospf']['areas'] = new_areas

            if item['bgp']:
                for x in item['bgp']['neighbors']:
                    x['filter_in'] = []
                    x['filter_out'] = []
                    x['routemap_in'] = []
                    x['routemap_out'] = []
                    try:
                        x['bfd_profile'] = bfd_profiles[x['bfd_profile']].id
                    except KeyError as err:
                        self.stepChanged.emit(f'RED|    Error: [VRF "{item["name"]}"] Для BGP не найден профиль BFD {err}. Установлено значение по умолчанию.')
                        x['bfd_profile'] = -1
                        error = 1
            if item['rip']:
                # Проверяем сети RIP
                new_networks = []
                for net in item['rip']['networks']:
                    if 'ifname' in net and net['ifname'] not in item['interfaces']:
                        self.stepChanged.emit(f'RED|    Error: [VRF "{item["name"]}"] Сеть RIP "{net["ifname"]}" удалёна из настроек RIP так как этот интерфейс отсутствует в этом VRF.')
                        error = 1
                    else:
                        new_networks.append(net)
                item['rip']['networks'] = new_networks
                # Проверяем интерфейсы RIP
                new_interfaces = []
                for iface in item['rip']['interfaces']:
                    if iface['name'] not in item['interfaces']:
                        self.stepChanged.emit(f'RED|    Error: [VRF "{item["name"]}"] Интерфейс RIP "{iface["name"]}" удалён из настроек RIP так как он отсутствует в этом VRF.')
                        error = 1
                    else:
                        new_interfaces.append(iface)
                item['rip']['interfaces'] = new_interfaces

            try:
                if vrf_name in mc_vrf:
                    self.stepChanged.emit(f'uGRAY|    VRF "{item["name"]}" уже существует в текущем шаблоне на узле кластера "{item["node_name"]}".')
                    err, result = self.utm.update_template_vrf(template_id, mc_vrf[vrf_name].id, item)
                    if err:
                        self.stepChanged.emit(f'RED|       {result} [VRF "{item["name"]}"]')
                        error = 1
                    else:
                        self.stepChanged.emit(f'uGRAY|       VRF "{item["name"]}" обновлён.')
                else:
                    err, result = self.utm.add_template_vrf(template_id, item)
                    if err:
                        self.stepChanged.emit(f'RED|    {result} [VRF "{item["name"]}" не импортирован]')
                        error = 1
                    else:
                        mc_vrf[vrf_name] = BaseObject(id=result, template_id=template_id, template_name=template_name)
                        self.stepChanged.emit(f'BLACK|    Создан виртуальный маршрутизатор "{item["name"]}" для узла кластера "{item["node_name"]}".')
            except OverflowError as err:
                self.stepChanged.emit(f'RED|    Произошла ошибка при импорте виртуального маршрутизатора "{item["name"]}" [{err}].')
                error = 1
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте виртуальных маршрутизаторов.')
        else:
            self.stepChanged.emit('GREEN|    Импорт виртуальных маршрутизаторов завершён.')


    def import_wccp_rules(self, path, template_id, template_name):
        """Импортируем список правил WCCP"""
        json_file = os.path.join(path, 'config_wccp.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт правил WCCP в раздел "Сеть/WCCP".')
        error = 0

        wccp_rules = {}
        for name, uid in self.group_templates[self.selected_group].items():
            err, result = self.utm.get_template_wccp_rules(uid)
            if err:
                self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте правил WCCP.')
                self.error = 1
                return
            for x in result:
                if x['name'] in wccp_rules:
                    self.stepChanged.emit(f'ORANGE|    Warning: Правило WCCP "{x["name"]}" обнаружено в нескольких шаблонах группы шаблонов. Правило из шаблона "{name}" не будет использовано.')
                else:
                    wccp_rules[x['name']] = BaseObject(id=x['id'], template_id=uid, template_name=name)

        for item in data:
            item['cc_network_devices'] = self.get_network_devices(item)
            if item.pop('error', False):
                item['enabled'] = False
                error = 1

            if item['routers']:
                routers = []
                for x in item['routers']:
                    if x[0] == 'list_id':
                        try:
                            x[1] = self.mc_data['ip_lists'][x[1]].id
                        except KeyError as err:
                            self.stepChanged.emit(f'RED|    Error: [Правило "{item["name"]}"] Не найден список {err} в группе шаблонов. Возможно он отсутствует в этой группе шаблонов.')
                            error = 1
                            continue
                    routers.append(x)
                item['routers'] = routers

            if item['name'] in wccp_rules:
                if template_id == wccp_rules[item['name']].template_id:
                    self.stepChanged.emit(f'uGRAY|    Правило WCCP "{item["name"]}" уже существует в текущем шаблоне.')
                else:
                    self.stepChanged.emit(f'sGREEN|    Правило WCCP "{item["name"]}" уже существует в шаблоне "{wccp_rules[item["name"]].template_name}".')
            else:
                err, result = self.utm.add_template_wccp_rule(template_id, item)
                if err:
                    self.stepChanged.emit(f'RED|    {result} [Правило WCCP "{item["name"]}" не импортировано]')
                    error = 1
                else:
                    self.stepChanged.emit(f'BLACK|    Правило WCCP "{item["name"]}" импортировано.')
                    wccp_rules[item['name']] = BaseObject(id=result, template_id=template_id, template_name=template_name)
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил WCCP.')
        else:
            self.stepChanged.emit('GREEN|    Импорт правил WCCP завершён.')


    #------------------------------------------ UserGate --------------------------------------------------
    def import_certificates(self, path, template_id, template_name):
        """
        Импортируем сертификаты. Правила импорта приведены в разделе  документации 'Импорт сертификатов'.
        """
        self.stepChanged.emit('BLUE|Импорт сертификатов в раздел "UserGate/Сертификаты".')

        if not os.path.isdir(path):
            return
        certificates = {entry.name: entry.path for entry in os.scandir(path) if entry.is_dir()}
        if not certificates:
            self.stepChanged.emit('GRAY|    Нет сертификатов для импорта.')
            return
        error = 0
        mc_certs = self.mc_data['certs']
        new_cert_exists = False

        for cert_name, cert_path in certificates.items():
            files = [entry.name for entry in os.scandir(cert_path) if entry.is_file()]

            json_file = os.path.join(cert_path, 'certificate_list.json')
            err, data = self.read_json_file(json_file)
            if err:
                continue

            cert_data =  None
            if 'cert.pem' in files:
                with open(os.path.join(cert_path, 'cert.pem'), mode='rb') as fh:
                    cert_data = fh.read()
            elif 'cert.der' in files:
                with open(os.path.join(cert_path, 'cert.der'), mode='rb') as fh:
                    cert_data = fh.read()

            key_data = None
            if 'key.der' in files:
                with open(os.path.join(cert_path, 'key.der'), mode='rb') as fh:
                    key_data = fh.read()
            elif 'key.pem' in files:
                with open(os.path.join(cert_path, 'key.pem'), mode='rb') as fh:
                    key_data = fh.read()

            if data['name'] in mc_certs:
                if template_id == mc_certs[data['name']].template_id:
                    self.stepChanged.emit(f'uGRAY|    Сертификат "{cert_name}" уже существует в текущем шаблоне.')
                else:
                    self.stepChanged.emit(f'sGREEN|    Cертификат "{cert_name}" уже существует в шаблоне "{mc_certs[data["name"]].template_name}".')
            else:
                if not cert_data:
                    self.stepChanged.emit(f'BLACK|    Cертификат "{cert_name}": Не найден файл "cert.pem" или "cert.der" для импорта. Будет сгенерирован новый сертификат.')
                    data.pop('user_guid', None)
                    data.pop('subject', None)
                    data.pop('has_private_key', None)
                    data.pop('has_cert', None)
                    data.pop('has_csr', None)
                    data.pop('has_cert_chain', None)
                    data.pop('not_before', None)
                    data.pop('not_after', None)
                    data.pop('ca', None)
                    data.pop('keyUsage', None)
                    data.update(data.pop('issuer', None))

                    err, result = self.utm.new_template_certificate(template_id, data)
                    if err == 1:
                        self.stepChanged.emit(f'RED|       {result}')
                        error = 1
                    elif err == 3:
                        self.stepChanged.emit(f'GRAY|       {result}')
                    else:
                        mc_certs[cert_name] = BaseObject(id=result, template_id=template_id, template_name=template_name)
                        self.stepChanged.emit(f'BLACK|    Создан новый сертификат "{cert_name}".')

                    if data['role'] in self.mc_data['cert_roles']:
                        self.stepChanged.emit(f'NOTE|       Сертификат "{cert_name}": Роль не назначена. Роль "{certs_role.get(data["role"], data["role"])}" уже используется в другом сертификате.')
                    else:
                        err, result = self.utm.update_template_certificate(template_id, mc_certs[data['name']].id, {'role': data['role']})
                        if err:
                            self.stepChanged.emit(f'RED|       {result} [Сертификат "{cert_name}"]')
                            error = 1
                        else:
                            self.stepChanged.emit(f'uGRAY|       Для Cертификата "{cert_name}" установлена роль "{certs_role.get(data["role"], data["role"])}".')
                            self.mc_data['cert_roles'].add(data['role'])
                            new_cert_exists = True
                elif key_data or data['role'] in ('proxy_ca_chain', 'proxy_ca_chain_root'):
                    if data['role'] in self.mc_data['cert_roles']:
                        self.stepChanged.emit(f'NOTE|    Сертификат "{cert_name}": Роль не будет назначена. Роль "{certs_role.get(data["role"], data["role"])}" уже используется в другом сертификате.')
                        data['role'] = 'none'
                    err, result = self.utm.add_template_certificate(template_id, data, cert_data, private_key=key_data)
                    if err:
                        self.stepChanged.emit(f'RED|    {result} [Сертификат "{cert_name}" не импортирован]')
                        error = 1
                    else:
                        mc_certs[cert_name] = BaseObject(id=result, template_id=template_id, template_name=template_name)
                        self.mc_data['cert_roles'].add(data['role'])
                        self.stepChanged.emit(f'BLACK|    Сертификат "{cert_name}" импортирован. Установлена роль "{certs_role.get(data["role"], data["role"])}".')
                else:
                    self.stepChanged.emit(f'bRED|    Warning: Сертификат "{cert_name}" не импортирован так как не имеет приватного ключа.')
            self.msleep(1)
        if new_cert_exists:
            self.stepChanged.emit('NOTE|    ВНИМАНИЕ: Были созданы новые сертификаты. После синхронизации с NGFW необходимо заново импортировать их на клиентские устройства.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте сертификатов.')
        else:
            self.stepChanged.emit('GREEN|    Импорт сертификатов завершён.')


    def import_client_certificate_profiles(self, path, template_id, template_name):
        """Импортируем профили пользовательских сертификатов в шаблон"""
        json_file = os.path.join(path, 'users_certificate_profiles.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт раздела "UserGate/Профили клиентских сертификатов".')

        if not self.mc_data.get('client_certs_profiles', False):
            if self.get_client_certificate_profiles(): # Заполняем self.mc_data['client_certs_profiles']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей клиентских сертификатов.')
                return

        client_certs_profiles = self.mc_data['client_certs_profiles']
        error = 0

        for item in data:
            if item['name'] in client_certs_profiles:
                if template_id == client_certs_profiles[item['name']].template_id:
                    self.stepChanged.emit(f'uGRAY|    Профиль клиентского сертификата "{item["name"]}" уже существует в текущем шаблоне.')
                else:
                    self.stepChanged.emit(f'sGREEN|    Профиль клиентского сертификата "{item["name"]}" уже существует в шаблоне "{client_certs_profiles[item["name"]].template_name}".')
            else:
                item['ca_certificates'] = [self.mc_data['certs'][x].id for x in item['ca_certificates']]

                err, result = self.utm.add_template_client_certificate_profile(template_id, item)
                if err == 1:
                    self.stepChanged.emit(f'RED|    {result} [Профиль клиентского сертификата "{item["name"]}" не импортирован]')
                    error = 1
                elif err == 3:
                    self.stepChanged.emit(f'GRAY|    {result}')
                else:
                    client_certs_profiles[item['name']] = BaseObject(id=result, template_id=template_id, template_name=template_name)
                    self.stepChanged.emit(f'BLACK|    Профиль клиентского сертификата "{item["name"]}" импортирован.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей клиентских сертификатов.')
        else:
            self.stepChanged.emit('GREEN|    Импорт профилей клиентских сертификатов завершён.')


    def import_general_settings(self, path, template_id, template_name):
        """Импортируем раздел 'UserGate/Настройки'."""
        self.import_ui(path, template_id)
        self.import_ntp_settings(path, template_id)
        self.import_proxy_port(path, template_id)
        self.import_saml_server_port(path, template_id)
        self.import_modules(path, template_id)
        self.import_cache_settings(path, template_id)
        self.import_proxy_exceptions(path, template_id)
        self.import_web_portal_settings(path, template_id)
        self.import_upstream_proxy_settings(path, template_id)
        self.import_upstream_update_proxy_settings(path, template_id)


    def import_ui(self, path, template_id):
        """Импортируем раздел UserGate/Настройки/Настройки интерфейса"""
        json_file = os.path.join(path, 'config_settings_ui.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт раздела "UserGate/Настройки/Настройки интерфейса".')

        if not self.mc_data.get('client_certs_profiles', False):
            if self.get_client_certificate_profiles(): # Заполняем self.mc_data['client_certs_profiles']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте настроек интерфейса.')
                return

        params = {
            'ui_timezone': 'Часовой пояс',
            'ui_language': 'Язык интерфейса по умолчанию',
            'web_console_ssl_profile_id': 'Профиль SSL для веб-консоли',
            'response_pages_ssl_profile_id': 'Профиль SSL для страниц блокировки/аутентификации',
            'endpoint_ssl_profile_id': 'Профиль SSL конечного устройства',
            'endpoint_certificate_id': 'Сертификат конечного устройства',
            'webui_auth_mode': 'Режим аутентификации веб-консоли'
        }
        error = 0

        for key, value in data.items():
            if key in params:
                setting = {}
                if key == 'webui_auth_mode':
                    if isinstance(value['value'], dict):
                        if value['value']['type'] == 'pki':
                            try:
                                value['value']['client_certificate_profile_id'] = self.mc_data['client_certs_profiles'][value['value']['client_certificate_profile_id']].id
                            except KeyError as err:
                                self.stepChanged.emit(f'RED|    Error: Не найден профиль клиентского сертификата {err} для "{params[key]}". Загрузите профили клиентских сертификатов и повторите попытку.')
                                error = 1
                                continue
                elif key == 'web_console_ssl_profile_id' and value['value']:
                    try:
                        value['value'] = self.mc_data['ssl_profiles'][value['value']].id
                    except KeyError as err:
                        self.stepChanged.emit(f'RED|    Error: Не найден профиль SSL {err} для "{params[key]}". Загрузите профили SSL и повторите попытку.')
                        error = 1
                        continue
                elif key == 'response_pages_ssl_profile_id':
                    if not value['value']:
                        continue
                    try:
                        value['value'] = self.mc_data['ssl_profiles'][value['value']].id
                    except KeyError as err:
                        self.stepChanged.emit(f'RED|    Error: Не найден профиль SSL {err} для "{params[key]}". Загрузите профили SSL и повторите попытку.')
                        error = 1
                        continue
                elif key == 'endpoint_ssl_profile_id':
                    if not value['value']:
                        continue
                    try:
                        value['value'] = self.mc_data['ssl_profiles'][value['value']].id
                    except KeyError as err:
                        self.stepChanged.emit(f'RED|    Error: Не найден профиль SSL {err} для "{params[key]}". Загрузите профили SSL и повторите попытку.')
                        error = 1
                        continue
                elif key == 'endpoint_certificate_id':
                    if not value['value']:
                        continue
                    try:
                        value['value'] = self.mc_data['certs'][value['value']].id
                    except KeyError as err:
                        self.stepChanged.emit(f'RED|    Error: Не найден сертификат {err} для "{params[key]}". Загрузите сертификаты и повторите попытку.')
                        error = 1
                        continue
                setting[key] = value
                err, result = self.utm.set_template_settings(template_id, setting)
                if err:
                    self.stepChanged.emit(f'RED|    {result} [Параметр "{params[key]}" не импортирован]')
                    error = 1
                else:
                    self.stepChanged.emit(f'BLACK|    "{params[key]}" установлен в значение "{data[key]}".')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте настроек интерфейса.')
        else:
            self.stepChanged.emit('GREEN|    Импорт настроек интерфейса завершён.')


    def import_ntp_settings(self, path, template_id):
        """Импортируем настройки NTP в шаблон"""
        json_file = os.path.join(path, 'config_ntp.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт настроек NTP раздела "UserGate/Настройки/Настройки времени сервера".')
        error = 0

        for i, ntp_server in enumerate(data['ntp_servers']):
            settings = {f'ntp_server{i+1}': ntp_server}
            err, result = self.utm.set_template_settings(template_id, settings)
            if err:
                self.stepChanged.emit(f'RED|    {result} [NTP-сервер "{ntp_server["value"]}" не импортирован]')
                error = 1
            else:
                self.stepChanged.emit(f'BLACK|    NTP-сервер "{ntp_server["value"]}" добавлен.')
            if i >= 1:
                break

        settings = {
            'ntp_enabled': {
                'value': data['ntp_enabled'],
                'enabled': True if data['ntp_synced'] else False
            }
        }
        err, result = self.utm.set_template_settings(template_id, settings)
        if err:
            self.stepChanged.emit(f'RED|    {result} [Параметр "Использовать NTP" не установлен]')
            error = 1
        else:
            self.stepChanged.emit(f'BLACK|    Использование NTP {"включено" if data["ntp_enabled"] else "отключено"}.')

        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произоша ошибка при импорте настроек NTP.')
        else:
            self.stepChanged.emit('GREEN|    Импорт серверов NTP завершён.')


    def import_proxy_port(self, path, template_id):
        """Импортируем HTTP(S)-прокси порт в шаблон"""
        json_file = os.path.join(path, 'config_proxy_port.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт раздела "UserGate/Настройки/Модули/HTTP(S)-прокси порт".')

        err, result = self.utm.set_template_settings(template_id, {'proxy_server_port': data})
        if err:
            self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте HTTP(S)-прокси порта.')
            self.error = 1
        else:
            self.stepChanged.emit(f'BLACK|    HTTP(S)-прокси порт установлен в значение "{data["value"]}"')


    def import_saml_server_port(self, path, template_id):
        """Импортируем порт SAML-сервера в шаблон"""
        json_file = os.path.join(path, 'config_saml_port.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт раздела "UserGate/Настройки/Модули/Порт SAML-сервера".')

        err, result = self.utm.set_template_settings(template_id, {'saml_server_port': data})
        if err:
            self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте порта SAML-сервера.')
            self.error = 1
        else:
            self.stepChanged.emit(f'BLACK|    Порт SAML-сервера установлен в значение "{data["value"]}"')


    def import_modules(self, path, template_id):
        """Импортируем модули"""
        json_file = os.path.join(path, 'config_settings_modules.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт раздела "UserGate/Настройки/Модули".')
        params = {
            'auth_captive': 'Домен Auth captive-портала',
            'logout_captive': 'Домен Logout captive-портала',
            'cert_captive': 'Домен Cert captive-портала',
            'block_page_domain': 'Домен страницы блокировки',
            'ftpclient_captive': 'FTP поверх HTTP домен',
            'ftp_proxy_enabled': 'FTP поверх HTTP',
            'tunnel_inspection_zone_config': 'Зона для инспектируемых туннелей',
            'lldp_config': 'Настройка LLDP',
        }
        error = 0
    
        for key, value in data.items():
            if key in params:
                if key == 'tunnel_inspection_zone_config':
                    if not value['value']['target_zone']:
                        continue
                    try:
                        value['value']['target_zone'] = self.mc_data['zones'][value['value']['target_zone']].id
                    except KeyError:
                        self.stepChanged.emit(f'RED|    Error: Не найдена зона {value["value"]["target_zone"]} для "{params[key]}". Вероятно зона отсутствует в этой группе шаблонов.')
                        value['value']['target_zone'] = ''
                        error = 1
                elif key == 'cert_captive' and not value:
                    continue
                setting = {}
                setting[key] = value
                err, result = self.utm.set_template_settings(template_id, setting)
                if err:
                    self.stepChanged.emit(f'RED|    {result} [Параметр "{params[key]}" не установлен]')
                    error = 1
                else:
                    self.stepChanged.emit(f'BLACK|    Параметр "{params[key]}" установлен в значение "{value["value"]}".')

        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Импорт модулей прошёл с ошибками.')
        else:
            self.stepChanged.emit('GREEN|    Импорт модулей завершён.')


    def import_cache_settings(self, path, template_id):
        """Импортируем раздел 'UserGate/Настройки/Настройки кэширования HTTP'"""
        json_file = os.path.join(path, 'config_proxy_settings.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт разделов "Расширенные настройки" и "Настройки кэширования HTTP" из "UserGate/Настройки".')
        error = 0
        settings = {
            'advanced': 'Расширенные настройки',
            'http_cache': 'Настройки кэширования HTTP',
        }
        for key in data:
            err, result = self.utm.set_template_settings(template_id, data[key])
            if err:
                self.stepChanged.emit(f'RED|    {result} [{settings[key]} не импортированы]')
                error = 1
            else:
                self.stepChanged.emit(f'BLACK|    {settings[key]} импортированы.')

        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте настроек.')
        else:
            self.stepChanged.emit('GREEN|    Импортированы "Расширенные настройки" и "Настройки кэширования HTTP".')


    def import_proxy_exceptions(self, path, template_id):
        """Импортируем раздел UserGate/Настройки/Настройки кэширования HTTP/Исключения кэширования"""
        json_file = os.path.join(path, 'config_proxy_exceptions.json')
        err, exceptions = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт раздела "UserGate/Настройки/Настройки кэширования HTTP/Исключения кэширования".')
        error = 0

        err, result = self.utm.get_template_nlists_list(template_id, 'httpcwl')
        if err:
            self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте исключений кэширования HTTP.')
            self.error = 1
            return
        if result:
            list_id = result[0]['id']
        else:
            httpcwl_list = {'name': 'HTTP Cache Exceptions', 'type': 'httpcwl'}
            err, list_id = self.utm.add_template_nlist(template_id, httpcwl_list)
            if err:
                self.stepChanged.emit(f'RED|    {list_id}\n    Произошла ошибка при импорте исключений кэширования HTTP.')
                self.error = 1
                return
    
        for item in exceptions:
            err, result = self.utm.add_template_nlist_item(template_id, list_id, item)
            if err == 1:
                self.stepChanged.emit(f'RED|    {result} [URL "{item["value"]}" не импортирован]')
                error = 1
            elif err == 3:
                self.stepChanged.emit(f'GRAY|    URL "{item["value"]}" уже существует в исключениях кэширования.')
            else:
                self.stepChanged.emit(f'BLACK|    В исключения кэширования добавлен URL "{item["value"]}".')

        if exceptions:
            err, result = self.utm.set_template_settings(template_id, {'http_cache_exceptions': {'enabled': True}})
            if err:
                self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при установке статуса исключения кэширования.')
                error = 1
            else:
                self.stepChanged.emit(f'BLACK|    Исключения кэширования включено.')

        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте исключений кэширования HTTP.')
        else:
            self.stepChanged.emit('GREEN|    Исключения кэширования HTTP импортированы".')


    def import_web_portal_settings(self, path, template_id):
        """Импортируем раздел 'UserGate/Настройки/Веб-портал'"""
        json_file = os.path.join(path, 'config_web_portal.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт раздела "UserGate/Настройки/Веб-портал".')
        error = 0

        response_pages = self.mc_data['response_pages']

        if not self.mc_data.get('client_certs_profiles', False):
            if self.get_client_certificate_profiles(): # Устанавливаем self.mc_data['client_certs_profiles']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте настроек Веб-портала.')
                return
        client_certs_profiles = self.mc_data['client_certs_profiles']

        value = data['value']
        try:
            value['user_auth_profile_id'] = self.mc_data['auth_profiles'][value['user_auth_profile_id']].id
        except KeyError:
            message = f'    Error: Не найден профиль аутентификации "{value["user_auth_profile_id"]}". Возможно он отсутствует в этой группе шаблонов.'
            self.stepChanged.emit(f'RED|{message}\n    Произошла ошибка при импорте настроек Веб-портала.')
            self.error = 1
            return

        try:
            value['ssl_profile_id'] = self.mc_data['ssl_profiles'][value['ssl_profile_id']].id
        except KeyError:
            message = f'    Error: Не найден профиль SSL "{value["ssl_profile_id"]}". Возможно он отсутствует в этой группе шаблонов.'
            self.stepChanged.emit('RED|{massage}\n    Произошла ошибка при импорте настроек Веб-портала.')
            self.error = 1
            return

        if value['client_certificate_profile_id']:
            try:
                value['client_certificate_profile_id'] = client_certs_profiles[value['client_certificate_profile_id']].id
            except KeyError:
                self.stepChanged.emit(f'RED|    Error: Не найден профиль клиентского сертификата "{value["client_certificate_profile_id"]}". Возможно он отсутствует в этой группе шаблонов.')
                value['client_certificate_profile_id'] = 0
                value['cert_auth_enabled'] = False
                error = 1

        if value['certificate_id']:
            try:
                value['certificate_id'] = self.mc_data['certs'][value['certificate_id']].id
            except KeyError:
                self.stepChanged.emit(f'RED|    Error: Не найден сертификат "{value["certificate_id"]}". Возможно он отсутствует в этой группе шаблонов.')
                value['certificate_id'] = -1
                error = 1
        else:
            data['certificate_id'] = -1

        if value['proxy_portal_template_id'] != -1:
            try:
                value['proxy_portal_template_id'] = response_pages[value['proxy_portal_template_id']].id
            except KeyError:
                value['proxy_portal_template_id'] = -1
                self.stepChanged.emit(f'RED|    Error: Не найден шаблон портала "{value["proxy_portal_template_id"]}". Возможно он отсутствует в этой группе шаблонов.')
                error = 1

        if value['proxy_portal_login_template_id'] != -1:
            try:
                value['proxy_portal_login_template_id'] = response_pages[value['proxy_portal_login_template_id']].id
            except KeyError as err:
                value['proxy_portal_login_template_id'] = -1
                self.stepChanged.emit(f'RED|    Error: Не найден шаблон страницы аутентификации {err}. Возможно он отсутствует в этой группе шаблонов.')
                error = 1

        settings = {
            'proxy_portal': {
                'value': value,
                'enabled': data['enabled']
            }
        }
    
        err, result = self.utm.set_template_settings(template_id, settings)
        if err:
            self.stepChanged.emit(f'RED|    {result} [Настройки не импортированы]\n    Произошла ошибка при импорте настроек Веб-портала.')
            self.error = 1
        else:
            self.stepChanged.emit('GREEN|    Импортирован раздел "UserGate/Настройки/Веб-портал".')


    def import_upstream_proxy_settings(self, path, template_id):
        """Импортируем настройки вышестоящего прокси. Только для версий меньше 7.4"""
        if self.utm.float_version >= 7.4:
            return

        json_file = os.path.join(path, 'upstream_proxy_settings.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт настроек раздела "UserGate/Настройки/Вышестоящий прокси".')

        settings = {
            'upstream_proxy': {
                'value': data['value'],
                'enabled': data['enabled']
            }
        }
    
        err, result = self.utm.set_template_settings(template_id, settings)
        if err:
            self.stepChanged.emit(f'RED|    {result} [Настройки не импортированы]\n    Произошла ошибка при импорте настроек вышестоящего прокси.')
            self.error = 1
        else:
            self.stepChanged.emit('GREEN|    Настройки вышестоящего прокси импортировны.')


    def import_upstream_update_proxy_settings(self, path, template_id):
        """Импортируем настройки вышестоящего прокси для проверки лицензий и обновлений"""
        json_file = os.path.join(path, 'upstream_proxy_check_update.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт настроек раздела "UserGate/Настройки/Вышестоящий прокси для проверки лицензий и обновлений".')

        settings = {
            'upstream_update_proxy': {
                'value': data['value'],
                'enabled': data['enabled']
            }
        }
    
        err, result = self.utm.set_template_settings(template_id, settings)
        if err:
            message = 'Произошла ошибка при импорте настроек вышестоящего прокси для проверки лицензий и обновлений.'
            self.stepChanged.emit(f'RED|    {result} [Настройки не импортированы]\n    {message}')
            self.error = 1
        else:
            self.stepChanged.emit('GREEN|    Импортированы настройки вышестоящего прокси для проверки лицензий и обновлений".')


    def import_administrators(self, path, template_id, template_name):
        self.import_administrators_profiles(path, template_id, template_name)
        self.import_template_admins(path, template_id, template_name)
        
        json_file = os.path.join(path, 'auth_settings.json')
        err, auth_config = self.read_json_file(json_file, mode=2)
        if err:
            return
        err, result = self.utm.set_template_admin_config(template_id, auth_config)
        if err:
            self.stepChanged.emit(f'RED|    {result}  [Настройки аутентификации не импортированы]')
            self.error = 1
        else:
            self.stepChanged.emit('GREEN|    Импортированы настройки аутентификации.')


    def import_administrators_profiles(self, path, template_id, template_name):
        """Импортируем список профилей администраторов"""
        json_file = os.path.join(path, 'administrator_profiles.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт профилей администраторов в раздел "UserGate/Администраторы".')
        error = 0

        self.mc_data['admin_profiles'] = {}
        for name, uid in self.group_templates[self.selected_group].items():
            err, result = self.utm.get_template_admins_profiles(uid)
            if err:
                self.stepChanged.emit('RED|    {result}')
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей администраторов.')
                return
            for x in result:
                if x['name'] in self.mc_data['admin_profiles']:
                    self.stepChanged.emit(f'ORANGE|    Профиль администратора "{x["name"]}" обнаружен в нескольких шаблонах группы шаблонов. Профиль из шаблона "{name}" не будет использован.')
                else:
                    self.mc_data['admin_profiles'][x['name']] = BaseObject(id=x['id'], template_id=uid, template_name=name)

        for item in data:
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя профиля')

            if item['name'] in self.mc_data['admin_profiles']:
                if template_id == self.mc_data['admin_profiles'][item['name']].template_id:
                    self.stepChanged.emit(f'uGRAY|    Профиль администратора "{item["name"]}" уже существует в текущем шаблоне.')
                else:
                    self.stepChanged.emit(f'sGREEN|    Профиль администратора "{item["name"]}" уже существует в шаблоне "{self.mc_data["admin_profiles"][item["name"]].template_name}".')
            else:
                err, result = self.utm.add_template_admins_profile(template_id, item)
                if err:
                    self.stepChanged.emit(f'RED|    {result} [Профиль администратора "{item["name"]}" не импортирован]')
                    error = 1
                else:
                    self.mc_data['admin_profiles'][item['name']] = BaseObject(id=result, template_id=template_id, template_name=template_name)
                    self.stepChanged.emit(f'BLACK|    Профиль администратора "{item["name"]}" импортирован.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей администраторов.')
        else:
            self.stepChanged.emit('GREEN|    Импорт профилей администраторов завершён.')


    def import_template_admins(self, path, template_id, template_name):
        """Импортируем администраторов в шаблоны"""
        json_file = os.path.join(path, 'administrators_list.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit(f'BLUE|[Шаблон "{template_name}"] Импорт администраторов в раздел "Консоль администратора/Администраторы".')
        error = 0

        err, result = self.utm.get_template_admins(template_id)
        if err:
            self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте администраторов.')
            self.error = 1
            return
        admins = {x['display_name']: x['id'] for x in result}
        admins_exists = False

        for item in data:
            if item['type'] == 'local':
                error, item['display_name'] = self.get_transformed_name(item['display_name'], err=error, descr='Имя администратора')
                item['password'] = 'Q12345678@'
                item['enabled'] = False
            if item['type'] in ['ldap_user', 'ldap_group']:
                login = item['display_name'].split('(')[1].replace(')', '')
                ldap_domain, _, login_name = login.partition("\\")

                try:
                    ldap_id = self.mc_data['ldap_servers'][ldap_domain.lower()]
                except KeyError:
                    self.stepChanged.emit(f'RED|    Error: [Администратор "{item["display_name"]}" не импортирован.] Нет LDAP-коннектора для домена "{ldap_domain}".')
                    error = 1
                    continue
                else:
                    if item['type'] == 'ldap_user':
                        err, result = self.utm.get_usercatalog_ldap_user_guid(ldap_id, login_name)
                    if item['type'] == 'ldap_group':
                        err, result = self.utm.get_usercatalog_ldap_group_guid(ldap_id, login_name)
                    if err:
                        self.stepChanged.emit(f'RED|    {result}\n       Администратор "{item["display_name"]}" не импортирован.')
                        error = 1
                        continue
                    elif not result:
                        self.stepChanged.emit(f'RED|    Error: [Администратор "{item["display_name"]}" не импортирован.] Нет такого пользователя в домене "{ldap_domain}".')
                        error = 1
                        continue
                    else:
                        item['guid'] = result

            item['profile_id'] = self.mc_data['admin_profiles'][item['profile_id']].id
            if item['type'] == 'auth_profile':
                try:
                    item['user_auth_profile_id'] = self.mc_data['auth_profiles'][item['user_auth_profile_id']].id
                except KeyError:
                    self.stepChanged.emit(f'RED|    Error: [Администратор "{item["display_name"]}" не импортирован.] Не найден профиль аутентификации "{item["user_auth_profile_id"]}".')
                    error = 1
                    continue

            if item['display_name'] in admins:
                self.stepChanged.emit(f'uGRAY|    Администратор "{item["display_name"]}" уже существует в текущем шаблоне.')
            else:
                err, result = self.utm.add_template_admin(template_id, item)
                if err:
                    self.stepChanged.emit(f'RED|    {result} [Администратор "{item["display_name"]}" не импортирован]')
                    error = 1
                else:
                    admins[item['display_name']] = result
                    self.stepChanged.emit(f'BLACK|    Администратор "{item["display_name"]}" импортирован.')
                    admins_exists = True
        if admins_exists:
            self.stepChanged.emit('NOTE|    Импортированным локальным администраторам установлен статус "disabled". Активируйте их и установите пароль.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте администраторов.')
        else:
            self.stepChanged.emit('GREEN|    Импорт администраторов завершён.')


    #------------------------------------ Пользователи и устройства -------------------------------------------------
    def import_local_groups(self, path, template_id, template_name):
        """Импортируем список локальных групп пользователей"""
        json_file = os.path.join(path, 'config_groups.json')
        err, groups = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт локальных групп пользователей в раздел "Пользователи и устройства/Группы".')
        self.stepChanged.emit(f'LBLUE|    Если используются доменные пользователи, необходимы настроенные LDAP-коннекторы в "Управление областью/Каталоги пользователей"')
        error = 0

        local_groups = self.mc_data['local_groups']

        for item in groups:
            users = item.pop('users')
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя группы')
            if item['name'] in local_groups:
                if template_id == local_groups[item['name']].template_id:
                    self.stepChanged.emit(f'uGRAY|    Группа пользователей "{item["name"]}" уже существует в текущем шаблоне.')
                else:
                    self.stepChanged.emit(f'sGREEN|    Группа пользователей "{item["name"]}" уже существует в шаблоне "{local_groups[item["name"]].template_name}".')
                    continue
            else:
                err, result = self.utm.add_template_group(template_id, item)
                if err == 1:
                    self.stepChanged.emit(f'RED|    {result} [Группа пользователей "{item["name"]}" не импортирована]')
                    error = 1
                    continue
                elif err == 3:
                    self.stepChanged.emit(f'GRAY|    {result}') # В версиях 6 и выше проверяется что группа уже существует.
                else:
                    local_groups[item['name']] = BaseObject(id=result, template_id=template_id, template_name=template_name)
                    self.stepChanged.emit(f'BLACK|    Группа пользователей "{item["name"]}" импортирована.')

            # Добавляем доменных пользователей в группу.
            self.stepChanged.emit(f'NOTE|       Добавляем доменных пользователей в группу "{item["name"]}".')
            n = 0
            for user in users:
                if '\\' in user:
                    n += 1
                    if ' ' in user: # В версиях до 7.3 имя было 'domain\\user_name', сейчас 'User1 (domain\\user1)'
                        user = user.split()[1].replace('(', '').replace(')', '')    # Убираем логин, оставляем имя и убираем скобки
                    domain, name = user.split('\\')
                    try:
                        ldap_id = self.mc_data['ldap_servers'][domain.lower()]
                    except KeyError:
                        self.stepChanged.emit(f'bRED|       Warning: Доменный пользователь "{user}" не импортирован в группу "{item["name"]}". Нет LDAP-коннектора для домена "{domain}".')
                    else:
                        err1, result1 = self.utm.get_usercatalog_ldap_user_guid(ldap_id, name)
                        if err1:
                            self.stepChanged.emit(f'RED|       {result1}')
                            error = 1
                            continue
                        elif not result1:
                            self.stepChanged.emit(f'bRED|       Warning: Нет пользователя "{user}" в домене "{domain}". Доменный пользователь не импортирован в группу "{item["name"]}".')
                            continue
                        err2, result2 = self.utm.add_user_in_template_group(template_id, local_groups[item['name']].id, result1)
                        if err2:
                            self.stepChanged.emit(f'RED|       {result2}  [{user}]')
                            error = 1
                        else:
                            self.stepChanged.emit(f'BLACK|       Пользователь "{user}" добавлен в группу "{item["name"]}".')
            if not n:
                self.stepChanged.emit(f'GRAY|       Нет доменных пользователей в группе "{item["name"]}".')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте локальных групп пользователей.')
        else:
            self.stepChanged.emit('GREEN|    Импорт групп пользователей завершён.')


    def import_local_users(self, path, template_id, template_name):
        """Импортируем локальных пользователей и добавляем их в группы"""
        json_file = os.path.join(path, 'config_users.json')
        err, users = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт локальных пользователей в раздел "Пользователи и устройства/Пользователи".')
        error = 0
        local_users = self.mc_data['local_users']

        for item in users:
            user_groups = item.pop('groups', None)
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя пользователя')
            item['auth_login'] = self.get_transformed_userlogin(item['auth_login'])

            if item['name'] in local_users:
                if template_id == local_users[item['name']].template_id:
                    self.stepChanged.emit(f'uGRAY|    Пользователь "{item["name"]}" уже существует в текущем шаблоне.')
                else:
                    self.stepChanged.emit(f'sGREEN|    Пользователь "{item["name"]}" уже существует в шаблоне "{local_users[item["name"]].template_name}".')
                    continue
            else:
                err, result = self.utm.add_template_user(template_id, item)
                if err == 1:
                    self.stepChanged.emit(f'RED|    {result} [Пользователь "{item["name"]}" не импортирован]')
                    error = 1
                    continue
                elif err == 3:
                    self.stepChanged.emit(f'GRAY|    {result}.') # В версиях 6 и выше проверяется что пользователь уже существует.
                else:
                    local_users[item['name']] = BaseObject(id=result, template_id=template_id, template_name=template_name)
                    self.stepChanged.emit(f'BLACK|    Локальный пользователь "{item["name"]}" импортирован.')

            # Добавляем пользователя в группу.
            for group in user_groups:
                try:
                    group_guid = self.mc_data['local_groups'][group].id
                except KeyError as err:
                    self.stepChanged.emit(f'bRED|       Warning: Не найдена группа {err} для пользователя {item["name"]}. Возможно она отсутствует в этой группе шаблонов.')
                else:
                    err2, result2 = self.utm.add_user_in_template_group(template_id, group_guid, local_users[item['name']].id)
                    if err2:
                        self.stepChanged.emit(f'RED|       {result2}  [User "{item["name"]}" не добавлен в группу "{group}"]')
                        error = 1
                    else:
                        self.stepChanged.emit(f'BLACK|       Пользователь "{item["name"]}" добавлен в группу "{group}".')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте локальных пользователей.')
        else:
            self.stepChanged.emit('GREEN|    Импорт локальных пользователей завершён.')


    def import_auth_servers(self, path, template_id, template_name):
        """Импортируем список серверов аутентификации"""
        self.stepChanged.emit('BLUE|Импорт раздела "Пользователи и устройства/Серверы аутентификации".')

        if not self.mc_data.get('auth_servers', False):
            if self.get_auth_servers():    # Устанавливаем self.mc_data['auth_servers']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте серверов аутентификации.')
                return
        auth_servers = self.mc_data['auth_servers']

        self.import_ldap_servers(path, auth_servers['ldap'], template_id, template_name)
        self.import_ntlm_server(path, auth_servers['ntlm'], template_id, template_name)
        self.import_radius_server(path, auth_servers['radius'], template_id, template_name)
        self.import_tacacs_server(path, auth_servers['tacacs_plus'], template_id, template_name)
        self.import_saml_server(path, auth_servers['saml_idp'], template_id, template_name)
    

    def import_ldap_servers(self, path, ldap_servers, template_id, template_name):
        """Импортируем список серверов LDAP"""
        json_file = os.path.join(path, 'config_ldap_servers.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|    Импорт серверов LDAP в раздел "Пользователи и устройства/Серверы аутентификации".')
        self.stepChanged.emit(f'LBLUE|       После импорта Необходимо ввести пароль и импортировать keytab файл в LDAP-коннекторы.')
        error = 0

        for item in data:
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя сервера')
            if item['name'] in ldap_servers:
                if template_id == ldap_servers[item['name']].template_id:
                    self.stepChanged.emit(f'uGRAY|       LDAP-сервер "{item["name"]}" уже существует в текущем шаблоне.')
                else:
                    self.stepChanged.emit(f'sGREEN|       LDAP-сервер "{item["name"]}" уже существует в шаблоне "{ldap_servers[item["name"]].template_name}".')
            else:
                item['keytab_exists'] = False
                item['type'] = 'ldap'
                item.pop("cc", None)
                err, result = self.utm.add_template_auth_server(template_id, item)
                if err:
                    self.stepChanged.emit(f'RED|       {result} [LDAP-сервер "{item["name"]}" не импортирован]')
                    error = 1
                else:
                    ldap_servers[item['name']] = BaseObject(id=result, template_id=template_id, template_name=template_name)
                    self.stepChanged.emit(f'BLACK|       Сервер аутентификации LDAP "{item["name"]}" импортирован.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте серверов LDAP.')
        else:
            self.stepChanged.emit('GREEN|    Импорт серверов LDAP завершён.')


    def import_ntlm_server(self, path, ntlm_servers, template_id, template_name):
        """Импортируем список серверов NTLM"""
        json_file = os.path.join(path, 'config_ntlm_servers.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|    Импорт серверов NTLM в раздел "Пользователи и устройства/Серверы аутентификации".')
        error = 0

        for item in data:
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя сервера')
            if item['name'] in ntlm_servers:
                if template_id == ntlm_servers[item['name']].template_id:
                    self.stepChanged.emit(f'uGRAY|       NTLM-сервер "{item["name"]}" уже существует в текущем шаблоне.')
                else:
                    self.stepChanged.emit(f'sGREEN|       NTLM-сервер "{item["name"]}" уже существует в шаблоне "{ntlm_servers[item["name"]].template_name}".')
            else:
                item['type'] = 'ntlm'
                item.pop("cc", None)
                err, result = self.utm.add_template_auth_server(template_id, item)
                if err:
                    self.stepChanged.emit(f'RED|       {result} [NTLM-сервер "{item["name"]}" не импортирован]')
                    error = 1
                else:
                    ntlm_servers[item['name']] = BaseObject(id=result, template_id=template_id, template_name=template_name)
                    self.stepChanged.emit(f'BLACK|       Сервер аутентификации NTLM "{item["name"]}" импортирован.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте серверов NTLM.')
        else:
            self.stepChanged.emit('GREEN|    Импорт серверов NTLM завершён.')


    def import_radius_server(self, path, radius_servers, template_id, template_name):
        """Импортируем список серверов RADIUS"""
        json_file = os.path.join(path, 'config_radius_servers.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|    Импорт серверов RADIUS в раздел "Пользователи и устройства/Серверы аутентификации".')
        self.stepChanged.emit(f'LBLUE|       После импорта необходимо ввести пароль на серверах RADIUS.')
        error = 0

        for item in data:
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя сервера')
            if item['name'] in radius_servers:
                if template_id == radius_servers[item['name']].template_id:
                    self.stepChanged.emit(f'uGRAY|       RADIUS-сервер "{item["name"]}" уже существует в текущем шаблоне.')
                else:
                    self.stepChanged.emit(f'sGREEN|       RADIUS-сервер "{item["name"]}" уже существует в шаблоне "{radius_servers[item["name"]].template_name}".')
            else:
                item['type'] = 'radius'
                item.pop("cc", None)
                err, result = self.utm.add_template_auth_server(template_id, item)
                if err:
                    self.stepChanged.emit(f'RED|       {result} [RADIUS-сервер "{item["name"]}" не импортирован]')
                    error = 1
                else:
                    radius_servers[item['name']] = BaseObject(id=result, template_id=template_id, template_name=template_name)
                    self.stepChanged.emit(f'BLACK|       Сервер аутентификации RADIUS "{item["name"]}" импортирован.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте серверов RADIUS.')
        else:
            self.stepChanged.emit('GREEN|    Импорт серверов RADIUS завершён.')


    def import_tacacs_server(self, path, tacacs_servers, template_id, template_name):
        """Импортируем список серверов TACACS+"""
        json_file = os.path.join(path, 'config_tacacs_servers.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|    Импорт серверов TACACS+ в раздел "Пользователи и устройства/Серверы аутентификации".')
        self.stepChanged.emit(f'LBLUE|       После импорта необходимо ввести секретный ключ на серверах TACACS+ .')
        error = 0

        for item in data:
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя сервера')
            if item['name'] in tacacs_servers:
                if template_id == tacacs_servers[item['name']].template_id:
                    self.stepChanged.emit(f'uGRAY|       TACACS-сервер "{item["name"]}" уже существует в текущем шаблоне.')
                else:
                    self.stepChanged.emit(f'sGREEN|       TACACS-сервер "{item["name"]}" уже существует в шаблоне "{tacacs_servers[item["name"]].template_name}".')
            else:
                item['type'] = 'tacacs_plus'
                item.pop("cc", None)
                err, result = self.utm.add_template_auth_server(template_id, item)
                if err:
                    self.stepChanged.emit(f'RED|       {result} [Сервер TACACS+ "{item["name"]}" не импортирован]')
                    error = 1
                else:
                    tacacs_servers[item['name']] = BaseObject(id=result, template_id=template_id, template_name=template_name)
                    self.stepChanged.emit(f'BLACK|       Сервер аутентификации TACACS+ "{item["name"]}" импортирован.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте серверов TACACS+.')
        else:
            self.stepChanged.emit('GREEN|    Импорт серверов TACACS+ завершён.')


    def import_saml_server(self, path, saml_servers, template_id, template_name):
        """Импортируем список серверов SAML"""
        json_file = os.path.join(path, 'config_saml_servers.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|    Импорт серверов SAML в раздел "Пользователи и устройства/Серверы аутентификации".')
        self.stepChanged.emit(f'LBLUE|       После импорта необходимо  загрузить SAML metadata на каждый сервер SAML.')
        error = 0

        for item in data:
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя сервера')
            if item['name'] in saml_servers:
                if template_id == saml_servers[item['name']].template_id:
                    self.stepChanged.emit(f'uGRAY|       SAML-сервер "{item["name"]}" уже существует в текущем шаблоне.')
                else:
                    self.stepChanged.emit(f'sGREEN|       SAML-сервер "{item["name"]}" уже существует в шаблоне "{saml_servers[item["name"]].template_name}".')
            else:
                item['type'] = 'saml_idp'
                item.pop("cc", None)
                if item['certificate_id']:
                    try:
                        item['certificate_id'] = self.mc_data['certs'][item['certificate_id']].id
                    except KeyError:
                        self.stepChanged.emit(f'RED|       Error: [Сервер SAML "{item["name"]}"] Не найден сертификат "{item["certificate_id"]}". Возможно он отсутствует в этой группе шаблонов.')
                        item['certificate_id'] = 0
                        error = 1
                err, result = self.utm.add_template_auth_server(template_id, item)
                if err:
                    self.stepChanged.emit(f'RED|       {result} [Сервер SAML "{item["name"]}" не импортирован]')
                    error = 1
                else:
                    saml_servers[item['name']] = BaseObject(id=result, template_id=template_id, template_name=template_name)
                    self.stepChanged.emit(f'BLACK|       Сервер аутентификации SAML "{item["name"]}" импортирован.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте серверов SAML.')
        else:
            self.stepChanged.emit('GREEN|    Импорт серверов SAML завершён.')


    def import_2fa_profiles(self, path, template_id, template_name):
        """Импортируем список 2FA профилей"""
        json_file = os.path.join(path, 'config_2fa_profiles.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт профилей MFA в раздел "Пользователи и устройства/Профили MFA".')
        error = 0

        if not self.mc_data.get('notification_profiles', False):
            if self.get_notification_profiles():      # Устанавливаем self.mc_data['notification_profiles']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей MFA.')
                return
        notification_profiles = self.mc_data['notification_profiles']

        if not self.mc_data.get('profiles_2fa', False):
            if self.get_profiles_2fa():      # Устанавливаем self.mc_data['profiles_2fa']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей MFA.')
                return
        profiles_2fa = self.mc_data['profiles_2fa']

        for item in data:
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя профиля')
            if item['name'] in profiles_2fa:
                if template_id == profiles_2fa[item['name']].template_id:
                    self.stepChanged.emit(f'uGRAY|    Профиль MFA "{item["name"]}" уже существует в текущем шаблоне.')
                else:
                    self.stepChanged.emit(f'sGREEN|    Профиль MFA "{item["name"]}" уже существует в шаблоне "{profiles_2fa[item["name"]].template_name}".')
            else:
                if item['type'] == 'totp':
                    if item['init_notification_profile_id'] not in notification_profiles:
                        self.stepChanged.emit(f'RED|    Error: Профиль MFA "{item["name"]}" не добавлен. Не найден профиль оповещения "{item["init_notification_profile_id"]}". Возможно он отсутствует в этой группе шаблонов.')
                        error = 1
                        continue
                    item['init_notification_profile_id'] = notification_profiles[item['init_notification_profile_id']].id
                else:
                    if item['auth_notification_profile_id'] not in notification_profiles:
                        self.stepChanged.emit(f'RED|    Error: Профиль MFA "{item["name"]}" не добавлен. Не найден профиль оповещения "{item["auth_notification_profile_id"]}". Возможно он отсутствует в этой группе шаблонов.')
                        error = 1
                        continue
                    item['auth_notification_profile_id'] = notification_profiles[item['auth_notification_profile_id']].id

                err, result = self.utm.add_template_2fa_profile(template_id, item)
                if err:
                    self.stepChanged.emit(f'RED|    {result}  [Профиль MFA "{item["name"]}" не импортирован]')
                    error = 1
                else:
                    profiles_2fa[item['name']] = BaseObject(id=result, template_id=template_id, template_name=template_name)
                    self.stepChanged.emit(f'BLACK|    Профиль MFA "{item["name"]}" импортирован.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей MFA.')
        else:
            self.stepChanged.emit('GREEN|    Импорт профилей MFA завершён.')


    def import_auth_profiles(self, path, template_id, template_name):
        """Импортируем список профилей аутентификации"""
        json_file = os.path.join(path, 'config_auth_profiles.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт профилей аутентификации в раздел "Пользователи и устройства/Профили аутентификации".')
        error = 0

        if not self.mc_data.get('auth_servers', False):
            if self.get_auth_servers():    # Устанавливаем self.mc_data['auth_servers']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей аутентификации.')
                return
        auth_servers = self.mc_data['auth_servers']

        if not self.mc_data.get('profiles_2fa', False):
            if self.get_profiles_2fa():      # Устанавливаем self.mc_data['profiles_2fa']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей аутентификации.')
                return
        profiles_2fa = self.mc_data['profiles_2fa']

        auth_profiles = self.mc_data['auth_profiles']
        auth_type = {
            'ldap': 'ldap_server_id',
            'radius': 'radius_server_id',
            'tacacs_plus': 'tacacs_plus_server_id',
            'ntlm': 'ntlm_server_id',
            'saml_idp': 'saml_idp_server_id'
        }

        for item in data:
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя профиля')
            if item['2fa_profile_id']:
                try:
                    item['2fa_profile_id'] = profiles_2fa[item['2fa_profile_id']].id
                except KeyError:
                    self.stepChanged.emit(f'RED|    Error: [Профиль аутентификации "{item["name"]}"] Не найден профиль MFA "{item["2fa_profile_id"]}". Возможно он отсутствует в этой группе шаблонов.')
                    item['2fa_profile_id'] = False
                    error = 1

            for auth_method in item['allowed_auth_methods']:
                if len(auth_method) == 2:
                    method_type = auth_method['type']
                    method_server_id = auth_type[method_type]
                    try:
                        auth_method[method_server_id] = auth_servers[method_type][auth_method[method_server_id]].id
                    except KeyError:
                        self.stepChanged.emit(f'RED|    Error: [Профиль аутентификации "{item["name"]}"] Не найден сервер аутентификации "{auth_method[method_server_id]}". Возможно он отсутствует в этой группе шаблонов.')
                        auth_method.clear()
                        error = 1
            item['allowed_auth_methods'] = [x for x in item['allowed_auth_methods'] if x]

            if item['name'] in auth_profiles:
                if template_id == auth_profiles[item['name']].template_id:
                    self.stepChanged.emit(f'uGRAY|    Профиль аутентификации "{item["name"]}" уже существует в текущем шаблоне.')
                else:
                    self.stepChanged.emit(f'sGREEN|    Профиль аутентификации "{item["name"]}" уже существует в шаблоне "{auth_profiles[item["name"]].template_name}".')
            else:
                err, result = self.utm.add_template_auth_profile(template_id, item)
                if err:
                    self.stepChanged.emit(f'RED|    {result} [Профиль аутентификации "{item["name"]}" не импортирован]')
                    error = 1
                else:
                    auth_profiles[item['name']] = BaseObject(id=result, template_id=template_id, template_name=template_name)
                    self.stepChanged.emit(f'BLACK|    Профиль аутентификации "{item["name"]}" импортирован.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей аутентификации.')
        else:
            self.stepChanged.emit('GREEN|    Импорт профилей аутентификации завершён.')


    def import_captive_profiles(self, path, template_id, template_name):
        """Импортируем список Captive-профилей"""
        json_file = os.path.join(path, 'config_captive_profiles.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт Captive-профилей в раздел "Пользователи и устройства/Captive-профили".')
        error = 0

        response_pages = self.mc_data['response_pages']

        if not self.mc_data.get('notification_profiles', False):
            if self.get_notification_profiles():       # Устанавливаем self.mc_data['notification_profiles']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте Captive-профилей.')
                return
        notification_profiles = self.mc_data['notification_profiles']

        if not self.mc_data.get('client_certs_profiles', False):
            if self.get_client_certificate_profiles(): # Устанавливаем self.mc_data['client_certs_profiles']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте Captive-профилей.')
                return
        client_certs_profiles = self.mc_data['client_certs_profiles']

        if not self.mc_data.get('captive_profiles', False):
            if self.get_captive_profiles():            # Устанавливаем self.mc_data['captive_profiles']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте Captive-профилей.')
                return
        captive_profiles = self.mc_data['captive_profiles']

        for item in data:
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя профиля')
            try:
                item['captive_template_id'] = response_pages[item['captive_template_id']].id
            except KeyError:
                self.stepChanged.emit(f'RED|    Error: [Captive-profile "{item["name"]}"] Не найден шаблон страницы аутентификации "{item["captive_template_id"]}". Возможно он отсутствует в этой группе шаблонов.')
                item['description'] = f'{item["description"]}\nError: Не найден профиль аутентификации "{item["captive_template_id"]}".'
                item['captive_template_id'] = -1
                error = 1
            try:
                item['user_auth_profile_id'] = self.mc_data['auth_profiles'][item['user_auth_profile_id']].id
            except KeyError:
                self.stepChanged.emit(f'RED|    Error: [Captive-profile "{item["name"]}"] Не найден профиль аутентификации "{item["user_auth_profile_id"]}". Возможно он отсутствует в этой группе шаблонов.')
                item['description'] = f'{item["description"]}\nError: Не найден профиль аутентификации "{item["user_auth_profile_id"]}".'
                item['user_auth_profile_id'] = 1
                error = 1

            if item['notification_profile_id'] != -1:
                try:
                    item['notification_profile_id'] = notification_profiles[item['notification_profile_id']].id
                except KeyError:
                    self.stepChanged.emit(f'RED|    Error: [Captive-profile "{item["name"]}"] Не найден профиль оповещения "{item["notification_profile_id"]}". Возможно он отсутствует в этой группе шаблонов.')
                    item['description'] = f'{item["description"]}\nError: Не найден профиль оповещения "{item["notification_profile_id"]}".'
                    item['notification_profile_id'] = -1
                    error = 1
            try:
                item['ta_groups'] = [self.mc_data['local_groups'][name].id for name in item['ta_groups']]
            except KeyError as err:
                self.stepChanged.emit(f'RED|    Error: [Captive-profile "{item["name"]}"] Группа гостевых пользователей {err} не найдена в группе шаблонов. Возможно она отсутствует в этой группе шаблонов.')
                item['description'] = f'{item["description"]}\nError: Не найдена группа гостевых пользователей {err}.'
                item['ta_groups'] = []
                error = 1

            if item['ta_expiration_date']:
                item['ta_expiration_date'] = item['ta_expiration_date'].replace(' ', 'T')
            else:
                item.pop('ta_expiration_date', None)

            item.pop('use_https_auth', None)
            if item['captive_auth_mode'] != 'aaa':
                try:
                    item['client_certificate_profile_id'] = client_certs_profiles[item['client_certificate_profile_id']].id
                except KeyError as err:
                    self.stepChanged.emit(f'RED|    Error: [Captive-profile "{item["name"]}"] Не найден профиль сертификата пользователя {err}. Возможно он отсутствует в этой группе шаблонов.')
                    item['description'] = f'{item["description"]}\nError: Не найден профиль сертификата пользователя "{item["client_certificate_profile_id"]}".'
                    item['captive_auth_mode'] = 'aaa'
                    item['client_certificate_profile_id'] = 0
                    error = 1

            if item['name'] in captive_profiles:
                if template_id == captive_profiles[item['name']].template_id:
                    self.stepChanged.emit(f'uGRAY|    Captive-профиль "{item["name"]}" уже существует в текущем шаблоне.')
                else:
                    self.stepChanged.emit(f'sGREEN|    Captive-профиль "{item["name"]}" уже существует в шаблоне "{captive_profiles[item["name"]].template_name}".')
            else:
                err, result = self.utm.add_template_captive_profile(template_id, item)
                if err:
                    self.stepChanged.emit(f'RED|    {result}  [Captive-profile "{item["name"]}" не импортирован]')
                    error = 1
                else:
                    captive_profiles[item['name']] = BaseObject(id=result, template_id=template_id, template_name=template_name)
                    self.stepChanged.emit(f'BLACK|    Captive-профиль "{item["name"]}" импортирован.')

        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте Captive-профилей.')
        else:
            self.stepChanged.emit('GREEN|    Импорт Captive-профилей завершён.')


    def import_captive_portal_rules(self, path, template_id, template_name):
        """Импортируем список правил Captive-портала"""
        json_file = os.path.join(path, 'config_captive_portal_rules.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт правил Captive-портала в раздел "Пользователи и устройства/Captive-портал".')
        error = 0

        if not self.mc_data.get('captive_profiles', False):
            if self.get_captive_profiles():            # Устанавливаем self.mc_data['captive_profiles']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил Captive-портала.')
                return
        captive_profiles = self.mc_data['captive_profiles']

        captive_portal_rules = {}
        for name, uid in self.group_templates[self.selected_group].items():
            err, result = self.utm.get_template_captive_portal_rules(uid)
            if err:
                self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте правил Captive-портала.')
                self.error = 1
                return
            for x in result:
                captive_portal_rules[x['name']] = BaseObject(id=x['id'], template_id=uid, template_name=name)

        for item in data:
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя правила')
            item.pop('time_created', None)
            item.pop('time_updated', None)
            if item['profile_id']:
                try:
                    item['profile_id'] = captive_profiles[item['profile_id']].id
                except KeyError:
                    self.stepChanged.emit(f'RED|    Error: [Captive-portal "{item["name"]}"] Captive-профиль "{item["profile_id"]}" не найден. Возможно он отсутствует в этой группе шаблонов.')
                    item['description'] = f'{item["description"]}\nError: Не найден Captive-профиль "{item["profile_id"]}".'
                    item['profile_id'] = 0
                    error = 1
            item['src_zones'] = self.get_zones_id('src', item['src_zones'], item)
            item['dst_zones'] = self.get_zones_id('dst', item['dst_zones'], item)
            item['src_ips'] = self.get_ips_id('src', item['src_ips'], item)
            item['dst_ips'] = self.get_ips_id('dst', item['dst_ips'], item)
            item['urls'] = self.get_urls_id(item['urls'], item)
            item['url_categories'] = self.get_url_categories_id(item)
            item['time_restrictions'] = self.get_time_restrictions(item)
            item['cc_network_devices'] = self.get_network_devices(item)

            if item.pop('error', False):
                item['enabled'] = False
                error = 1

            if item['name'] in captive_portal_rules:
                if template_id == captive_portal_rules[item['name']].template_id:
                    self.stepChanged.emit(f'uGRAY|    Правило Captive-портала "{item["name"]}" уже существует в текущем шаблоне.')
                else:
                    self.stepChanged.emit(f'sGREEN|    Правило Captive-портала "{item["name"]}" уже существует в шаблоне "{captive_portal_rules[item["name"]].template_name}".')
            else:
                err, result = self.utm.add_template_captive_portal_rule(template_id, item)
                if err:
                    self.stepChanged.emit(f'RED|    {result}  [Captive-portal "{item["name"]}" не импортирован]')
                    error = 1
                else:
                    captive_portal_rules[item['name']] = result
                    self.stepChanged.emit(f'BLACK|    Правило Captive-портала "{item["name"]}" импортировано.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил Captive-портала.')
        else:
            self.stepChanged.emit('GREEN|    Импорт правил Captive-портала завершён.')


    def import_terminal_servers(self, path, template_id, template_name):
        """Импортируем список терминальных серверов"""
        json_file = os.path.join(path, 'config_terminal_servers.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт списка терминальных серверов в раздел "Пользователи и устройства/Терминальные серверы".')
        error = 0
        terminal_servers = {}
        for name, uid in self.group_templates[self.selected_group].items():
            err, result = self.utm.get_template_terminal_servers(uid)
            if err:
                self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте списка терминальных серверов.')
                self.error = 1
                return
            for x in result:
                if x['name'] in terminal_servers:
                    self.stepChanged.emit('ORANGE|    Терминальный сервер обнаружен в нескольких шаблонах группы. Сервер из шаблона "{name}" не будет использован.')
                else:
                    terminal_servers[x['name']] = BaseObject(id=x['id'], template_id=uid, template_name=name)

        for item in data:
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя сервера')
            if item['name'] in terminal_servers:
                if template_id == terminal_servers[item['name']].template_id:
                    self.stepChanged.emit(f'uGRAY|    Терминальный сервер "{item["name"]}" уже существует в текущем шаблоне.')
                else:
                    self.stepChanged.emit(f'sGREEN|    Терминальный сервер "{item["name"]}" уже существует в шаблоне "{terminal_servers[item["name"]].template_name}".')
            else:
                err, result = self.utm.add_template_terminal_server(template_id, item)
                if err:
                    self.stepChanged.emit(f'RED|    {result}  [Terminal Server "{item["name"]}" не импортирован]')
                    error = 1
                else:
                    terminal_servers[item['name']] = BaseObject(id=result, template_id=template_id, template_name=template_name)
                    self.stepChanged.emit(f'BLACK|    Терминальный сервер "{item["name"]}" импортирован.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте терминальных серверов.')
        else:
            self.stepChanged.emit('GREEN|    Импорт терминальных серверов завершён.')


    def import_userid_agent(self, path, template_id, template_name):
        """Импортируем настройки UserID агент"""
        self.import_agent_config(path, template_id, template_name)
        self.import_agent_servers(path, template_id, template_name)


    def import_agent_config(self, path, template_id, template_name):
        """Импортируем настройки UserID агент"""
        json_file = os.path.join(path, 'userid_agent_config.json')
        err, config_data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт свойств агента UserID в раздел "Пользователи и устройства/Свойства агента UserID')
        error = 0
        
        useridagent_config = {}
        for name, uid in self.group_templates[self.selected_group].items():
            err, result = self.utm.get_template_useridagent_config(uid)
            if err:
                self.stepChanged.emit('RED|    {result}\n       Произошла ошибка при импорте свойств агента UserID.')
                self.error = 1
                return
            for x in result:
                if x['name'] in useridagent_config:
                    self.stepChanged.emit('ORANGE|    Свойство агента UserID для узла кластера "{x["name"]}" обнаружено в нескольких шаблонах группы шаблонов. Свойство из шаблона "{name}" не будет использовано.')
                else:
                    useridagent_config[x['name']] = BaseObject(id=x['id'], template_id=uid, template_name=name)

        for item in config_data:
            if item['name'] in useridagent_config:
                if template_id == useridagent_config[item['name']].template_id:
                    self.stepChanged.emit(f'uGRAY|    Свойства агента UserID для узла "{item["name"]}" уже существуют в текущем шаблоне.')
                else:
                    self.stepChanged.emit(f'sGREEN|    Свойства агента UserID для узла "{item["name"]}" уже существует в шаблоне "{useridagent_config[item["name"]].template_name}".')
            else:
                if item['tcp_ca_certificate_id']:
                    try:
                        item['tcp_ca_certificate_id'] = self.mc_data['certs'][item['tcp_ca_certificate_id']].id
                    except KeyError as err:
                        self.stepChanged.emit(f'RED|    Error: Не найден сертификат {err}. Возможно он отсутствует в этой группе шаблонов.')
                        item.pop('tcp_ca_certificate_id', None)
                        error = 1
                else:
                    item.pop('tcp_ca_certificate_id', None)

                if item['tcp_server_certificate_id']:
                    try:
                        item['tcp_server_certificate_id'] = self.mc_data['certs'][item['tcp_server_certificate_id']].id
                    except KeyError as err:
                        self.stepChanged.emit(f'RED|    Error: Не найден сертификат УЦ "{err}". Возможно он отсутствует в этой группе шаблонов.')
                        item.pop('tcp_server_certificate_id', None)
                        error = 1
                else:
                    item.pop('tcp_server_certificate_id', None)

                new_networks = []
                for x in item['ignore_networks']:
                    try:
                        new_networks.append(['list_id', self.mc_data['ip_lists'][x[1]].id])
                    except KeyError as err:
                        self.stepChanged.emit(f'RED|    Error: Не найден список IP-адресов {err} для Ignore Networks. Возможно он отсутствует в этой группе шаблонов.')
                        error = 1
                item['ignore_networks'] = new_networks

                err, result = self.utm.set_template_useridagent_config(template_id, item)
                if err:
                    self.stepChanged.emit(f'RED|    {result} [Свойства агента UserID не установлены]')
                    error = 1
                else:
                    useridagent_config[item['name']] = BaseObject(id=result, template_id=template_id, template_name=template_name)
                    self.stepChanged.emit(f'BLACK|    Свойства агента UserID для узла "{item["name"]}" импортированы')

        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте свойств агента UserID.')
        else:
            self.stepChanged.emit('GREEN|    Импорт свойств агента UserID завершён.')


    def import_agent_servers(self, path, template_id, template_name):
        """Импортируем коннекторы UserID агент"""
        json_file = os.path.join(path, 'userid_agent_servers.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт Агент UserID в раздел "Пользователи и устройства/UserID агент коннекторы".')
        self.stepChanged.emit(f'LBLUE|    Фильтры для коннеторов Syslog Агентов UserID в этой версии МС не переносятся. Необходимо добавить их руками.')
        error = 0

        if not self.mc_data.get('userid_filters', False):
            if self.get_useridagent_filters():        # Заполняем self.mc_data['userid_filters']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте syslog фильтров UserID агента.')
                return
        userid_filters = self.mc_data['userid_filters']

        useridagent_servers = {}
        for name, uid in self.group_templates[self.selected_group].items():
            err, result = self.utm.get_template_useridagent_servers(uid)
            if err:
                self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте агентов UserID.')
                self.error = 1
                return
            for x in result:
                srv_name = f'{x["name"]}:{x["node_name"]}'
                if srv_name in useridagent_servers:
                    self.stepChanged.emit(f'ORANGE|    Коннектор UserID агента "{x["name"]}" для узла "{x["node_name"]}" обнаружен в нескольких шаблонах группы шаблонов. Коннектор из шаблона "{name}" не будет использован.')
                else:
                    useridagent_servers[srv_name] = BaseObject(id=x['id'], template_id=uid, template_name=name)

        for item in data:
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя')
            srv_name = f'{item["name"]}:{item["node_name"]}'
            if srv_name in useridagent_servers:
                if template_id == useridagent_servers[srv_name].template_id:
                    self.stepChanged.emit(f'uGRAY|    Коннектор UserID агент "{item["name"]}" для узла "{item["node_name"]}" уже существует в текущем шаблоне.')
                else:
                    self.stepChanged.emit(f'sGREEN|    Коннектор UserID агент "{item["name"]}" для узла "{item["node_name"]}" уже существует в шаблоне "{useridagent_servers[srv_name].template_name}".')
            else:
                try:
                    item['auth_profile_id'] = self.mc_data['auth_profiles'][item['auth_profile_id']].id
                except KeyError:
                    self.stepChanged.emit(f'RED|    Error: [UserID агент "{item["name"]}"] Не найден профиль аутентификации "{item["auth_profile_id"]}". Возможно он отсутствует в этой группе шаблонов.')
                    item['description'] = f'{item["description"]}\nError: Не найден профиль аутентификации "{item["auth_profile_id"]}".'
                    item['auth_profile_id'] = 1
                    error = 1
                if 'filters' in item:
                    new_filters = []
                    for filter_name in item['filters']:
                        try:
                            new_filters.append(userid_filters[filter_name].id)
                        except KeyError:
                            self.stepChanged.emit(f'RED|    Error: [UserID агент "{item["name"]}"] Не найден Syslog фильтр "{filter_name}". Загрузите фильтры UserID агента и повторите попытку.')
                            item['description'] = f'{item["description"]}\nError: Не найден Syslog фильтр UserID агента "{filter_name}".'
                            error = 1
                    item['filters'] = new_filters

                if item['type'] == 'radius' and 'server_secret' not in item:
                    item['server_secret'] = '123'

                err, result = self.utm.add_template_useridagent_server(template_id, item)
                if err:
                    self.stepChanged.emit(f'RED|    {result}  [Коннектор UserID агент "{item["name"]}" для узла "{item["node_name"]}" не импортирован]')
                    error = 1
                else:
                    useridagent_servers[srv_name] = BaseObject(id=result, template_id=template_id, template_name=template_name)
                    self.stepChanged.emit(f'BLACK|    Коннектор UserID агент "{item["name"]}" для узла "{item["node_name"]}" импортирован.')
            if item['type'] == 'ad':
                self.stepChanged.emit(f'LBLUE|       Необходимо указать пароль для этого коннектора Microsoft AD.')
            elif item['type'] == 'radius':
                self.stepChanged.emit(f'LBLUE|       Необходимо указать секретный код для этого коннектора RADIUS.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте агентов UserID.')
        else:
            self.stepChanged.emit('GREEN|    Импорт раздела "UserID агент коннекторы" завершён.')


#-------------------------------------- Политики сети ---------------------------------------------------------
    def import_firewall_rules(self, path, template_id, template_name):
        """Импортируем правила межсетевого экрана"""
        json_file = os.path.join(path, 'config_firewall_rules.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт правил межсетевого экрана в раздел "Политики сети/Межсетевой экран".')

        if not self.mc_data.get('idps_profiles', False):
            if self.get_idps_profiles():            # Устанавливаем self.mc_data['idps_profiles']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил межсетевого экрана.')
                return
        idps_profiles = self.mc_data['idps_profiles']

        if not self.mc_data.get('l7_profiles', False):
            if self.get_l7_profiles():            # Устанавливаем self.mc_data['l7_profiles']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил межсетевого экрана.')
                return
        l7_profiles = self.mc_data['l7_profiles']

        if not self.mc_data.get('hip_profiles', False):
            if self.get_hip_profiles():            # Устанавливаем self.mc_data['hip_profiles']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил межсетевого экрана.')
                return
        hip_profiles = self.mc_data['hip_profiles']

        err, result = self.utm.get_template_firewall_rules(template_id)
        if err:
            self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте правил межсетевого экрана.')
            self.error = 1
            return
        firewall_rules = {x['name']: x['id'] for x in result}

        error = 0
        for item in data:
            item.pop('time_created', None)
            item.pop('time_updated', None)
            item.pop('apps', None)
            item.pop('apps_negate', None)

            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя правила')
            if item['scenario_rule_id']:
                try:
                    item['scenario_rule_id'] = self.mc_data['scenarios'][item['scenario_rule_id']].id
                except KeyError as err:
                    self.stepChanged.emit(f'RED|    Error: [Правило "{item["name"]}"] Не найден сценарий {err}. Возможно он отсутствует в этой группе шаблонов.')
                    item['description'] = f'{item["description"]}\nError: Не найден сценарий {err}.'
                    item['scenario_rule_id'] = False
                    item['error'] = True
            if 'ips_profile' in item and item['ips_profile']:
                try:
                    item['ips_profile'] = idps_profiles[item['ips_profile']].id
                except KeyError as err:
                    self.stepChanged.emit(f'RED|    Error: [Правило "{item["name"]}"] Не найден профиль СОВ {err}. Возможно он отсутствует в этой группе шаблонов.')
                    item['description'] = f'{item["description"]}\nError: Не найден профиль СОВ {err}.'
                    item['ips_profile'] = False
                    item['error'] = True
            else:
                item['ips_profile'] = False
            if 'l7_profile' in item and item['l7_profile']:
                try:
                    item['l7_profile'] = l7_profiles[item['l7_profile']].id
                except KeyError as err:
                    self.stepChanged.emit(f'RED|    Error: [Правило "{item["name"]}"] Не найден профиль приложений {err}. Возможно он отсутствует в этой группе шаблонов.')
                    item['description'] = f'{item["description"]}\nError: Не найден профиль приложений {err}.'
                    item['l7_profile'] = False
                    item['error'] = True
            else:
                item['l7_profile'] = False
            if 'hip_profiles' in item:
                new_hip_profiles = []
                for hip in item['hip_profiles']:
                    try:
                        new_hip_profiles.append(hip_profiles[hip].id)
                    except KeyError as err:
                        self.stepChanged.emit(f'RED|    Error: [Правило "{item["name"]}"] Не найден профиль HIP {err}. Возможно он отсутствует в этой группе шаблонов.')
                        item['description'] = f'{item["description"]}\nError: Не найден профиль HIP {err}.'
                        item['error'] = True
                item['hip_profiles'] = new_hip_profiles
            else:
                item['hip_profiles'] = []

            item['src_zones'] = self.get_zones_id('src', item['src_zones'], item)
            item['dst_zones'] = self.get_zones_id('dst', item['dst_zones'], item)
            item['src_ips'] = self.get_ips_id('src', item['src_ips'], item)
            item['dst_ips'] = self.get_ips_id('dst', item['dst_ips'], item)
            item['users'] = self.get_guids_users_and_groups(item) if self.mc_data['ldap_servers'] else []
            item['services'] = self.get_services(item['services'], item)
            item['time_restrictions'] = self.get_time_restrictions(item)
            item['cc_network_devices'] = self.get_network_devices(item)

            if item.pop('error', False):
                item['enabled'] = False
                error = 1

            if item['name'] in firewall_rules:
                self.stepChanged.emit(f'uGRAY|    Правило МЭ "{item["name"]}" уже существует в текущем шаблоне.')
            else:
#                item['position'] = 'last'
                err, result = self.utm.add_template_firewall_rule(template_id, item)
                if err:
                    error = 1
                    self.stepChanged.emit(f'RED|    {result}  [Правило МЭ "{item["name"]}" не импортировано]')
                else:
                    firewall_rules[item['name']] = result
                    self.stepChanged.emit(f'BLACK|   Правило МЭ "{item["name"]}" импортировано.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил межсетевого экрана.')
        else:
            self.stepChanged.emit('GREEN|    Импорт правил межсетевого экрана завершён.')


    def import_nat_rules(self, path, template_id, template_name):
        """Импортируем список правил NAT"""
        json_file = os.path.join(path, 'config_nat_rules.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт правил NAT в раздел "Политики сети/NAT и маршрутизация".')
        error = 0

        if not self.mc_data.get('gateways', False):
            if self.get_gateways_list():            # Устанавливаем self.mc_data['gateways']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил NAT.')
                return
        mc_gateways = self.mc_data['gateways']

        err, result = self.utm.get_template_traffic_rules(template_id)
        if err:
            self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте правил NAT.')
            self.error = 1
            return
        nat_rules = {x['name']: x['id'] for x in result}

        for item in data:
            item.pop('time_created', None)
            item.pop('time_updated', None)
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя правила')
            item['zone_in'] = self.get_zones_id('src', item['zone_in'], item)
            item['zone_out'] = self.get_zones_id('dst', item['zone_out'], item)
            item['source_ip'] = self.get_ips_id('src', item['source_ip'], item)
            item['dest_ip'] = self.get_ips_id('dst', item['dest_ip'], item)
            item['service'] = self.get_services(item['service'], item)
            item['users'] = self.get_guids_users_and_groups(item) if self.mc_data['ldap_servers'] else []
            item['cc_network_devices'] = self.get_network_devices(item)

            gateway_exist = False
            if item['action'] == 'route':
                for key in mc_gateways:
                    gateway_name, node_name = key.split(':')
                    if gateway_name == item['gateway']:
                        item['gateway'] = mc_gateways[key].id
                        self.stepChanged.emit(f'rNOTE|    Для правила ПБР "{item["name"]}" установлен шлюз "{gateway_name}" для узла "{node_name}". Если нужен шлюз для другого узла, установите его вручную.')
                        gateway_exist = True
                        break
                if not gateway_exist:
                    self.stepChanged.emit(f'RED|    Error: [Правило "{item["name"]}"] Не найден шлюз "{item["gateway"]}" для правила ПБР в группе шаблонов.')
                    item['description'] = f'{item["description"]}\nError: Не найден шлюз "{item["gateway"]}" для правила ПБР в группе шаблонов.'
                    item['gateway'] = ''
                    item['error'] = True

            if item['scenario_rule_id']:
                try:
                    item['scenario_rule_id'] = self.mc_data['scenarios'][item['scenario_rule_id']].id
                except KeyError as err:
                    self.stepChanged.emit(f'RED|    Error: [Правило "{item["name"]}"] Не найден сценарий {err}. Возможно он отсутствует в этой группе шаблонов.')
                    item['description'] = f'{item["description"]}\nError: Не найден сценарий {err}.'
                    item['scenario_rule_id'] = False
                    item['error'] = True
            
            if item.pop('error', False):
                item['enabled'] = False
                error = 1

            if item['name'] in nat_rules:
                self.stepChanged.emit(f'uGRAY|    Правило "{item["name"]}" уже существует.')
            else:
#                item['position'] = 'last'
                err, result = self.utm.add_template_traffic_rule(template_id, item)
                if err:
                    error = 1
                    self.stepChanged.emit(f'RED|    {result}  [Правило "{item["name"]}" не импортировано]')
                else:
                    nat_rules[item['name']] = result
                    self.stepChanged.emit(f'BLACK|    Правило "{item["name"]}" импортировано.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил NAT.')
        else:
            self.stepChanged.emit('GREEN|    Импорт правил NAT завершён.')


    def import_loadbalancing_rules(self, path, template_id, template_name):
        """Импортируем правила балансировки нагрузки"""
        self.stepChanged.emit('BLUE|Импорт правил балансировки нагрузки в раздел "Политики сети/Балансировка нагрузки".')
        err, result = self.utm.get_template_loadbalancing_rules(template_id)
        if err:
            self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте правил балансировки нагрузки.')
            self.error = 1
            return

        self.import_loadbalancing_tcpudp(path, result, template_id)
        self.import_loadbalancing_icap(path, result, template_id)
        self.import_loadbalancing_reverse(path, result, template_id)


    def import_loadbalancing_tcpudp(self, path, balansing_servers, template_id):
        """Импортируем балансировщики TCP/UDP"""
        self.stepChanged.emit('BLUE|    Импорт балансировщиков TCP/UDP.')
        json_file = os.path.join(path, 'config_loadbalancing_tcpudp.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err in (2, 3):
            self.stepChanged.emit(f'GRAY|       Нет балансировщиков TCP/UDP для импорта.')
            return
        elif err == 1:
            return

        tcpudp_rules = {x['name']: x['id'] for x in balansing_servers if x['type'] == 'ipvs'}
        error = 0

        for item in data:
            item['src_zones'] = self.get_zones_id('src', item['src_zones'], item)
            item['src_ips'] = self.get_ips_id('src', item['src_ips'], item)
            item['cc_network_devices'] = self.get_network_devices(item)
            item['type'] = 'ipvs'

            if item.pop('error', False):
                item['enabled'] = False
                error = 1

            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя правила')
            if item['name'] in tcpudp_rules:
                self.stepChanged.emit(f'uGRAY|       Правило балансировки TCP/UDP "{item["name"]}" уже существует.')
            else:
                err, result = self.utm.add_template_loadbalancing_rule(template_id, item)
                if err:
                    self.stepChanged.emit(f'RED|       {result}  [Правило "{item["name"]}" не импортировано]')
                    error = 1
                else:
                    tcpudp_rules[item['name']] = result
                    self.stepChanged.emit(f'BLACK|       Правило балансировки TCP/UDP "{item["name"]}" импортировано.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил балансировки TCP/UDP.')
        else:
            self.stepChanged.emit('GREEN|    Импорт правил балансировки TCP/UDP завершён.')


    def import_loadbalancing_icap(self, path, balansing_servers, template_id):
        """Импортируем балансировщики ICAP"""
        self.stepChanged.emit('BLUE|    Импорт балансировщиков ICAP.')
        json_file = os.path.join(path, 'config_loadbalancing_icap.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err in (2, 3):
            self.stepChanged.emit(f'GRAY|       Нет балансировщиков ICAP для импорта.')
            return
        elif err == 1:
            return

        error = 0

        if not self.mc_data.get('icap_servers', False):
            if self.get_icap_servers():            # Устанавливаем self.mc_data['icap_servers']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил балансировки ICAP.')
                return
        icap_servers = self.mc_data['icap_servers']

        icap_loadbalancing = {x['name']: x['id'] for x in balansing_servers if x['type'] == 'icap'}

        for item in data:
            item['type'] = 'icap'
            item['cc_network_devices'] = self.get_network_devices(item)
            new_profiles = []
            for profile in item['profiles']:
                try:
                    new_profiles.append(icap_servers[profile].id)
                except KeyError as err:
                    self.stepChanged.emit(f'RED|       Error: [Правило "{item["name"]}"] Не найден сервер ICAP "{profile}" в группе шаблонов. Возможно он отсутствует в этой группе шаблонов.')
                    item['description'] = f'{item["description"]}\nError: Не найден сервер ICAP "{profile}".'
                    item['enabled'] = False
                    error = 1
            item['profiles'] = new_profiles

            if item.pop('error', False):
                item['enabled'] = False
                error = 1

            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя правила')
            if item['name'] in icap_loadbalancing:
                self.stepChanged.emit(f'uGRAY|       Правило балансировки ICAP "{item["name"]}" уже существует.')
            else:
                err, result = self.utm.add_template_loadbalancing_rule(template_id, item)
                if err:
                    self.stepChanged.emit(f'RED|       {result}  [Правило "{item["name"]}" не импортировано]')
                    error = 1
                else:
                    icap_loadbalancing[item['name']] = result
                    self.stepChanged.emit(f'BLACK|       Правило балансировки ICAP "{item["name"]}" импортировано.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил балансировки ICAP.')
        else:
            self.stepChanged.emit('GREEN|    Импорт правил балансировки ICAP завершён.')


    def import_loadbalancing_reverse(self, path, balansing_servers, template_id):
        """Импортируем балансировщики reverse-proxy"""
        self.stepChanged.emit('BLUE|    Импорт балансировщиков Reverse-proxy.')
        json_file = os.path.join(path, 'config_loadbalancing_reverse.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err in (2, 3):
            self.stepChanged.emit(f'GRAY|       Нет балансировщиков Reverse-proxy для импорта.')
            return
        elif err == 1:
            return

        error = 0

        if not self.mc_data.get('reverseproxy_servers', False):
            if self.get_reverseproxy_servers():            # Устанавливаем self.mc_data['reverseproxy_servers']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил балансировки Reverse-proxy.')
                return
        reverseproxy_servers = self.mc_data['reverseproxy_servers']

        reverse_rules = {x['name']: x['id'] for x in balansing_servers if x['type'] == 'rp'}

        for item in data:
            item['cc_network_devices'] = self.get_network_devices(item)
            item['type'] = 'rp'
            new_profiles = []
            for profile in item['profiles']:
                try:
                    new_profiles.append(reverseproxy_servers[profile].id)
                except KeyError as err:
                    self.stepChanged.emit(f'RED|       Error: [Правило "{item["name"]}"] Не найден сервер reverse-proxy {err} в группе шаблонов. Возможно он отсутствует в этой группе шаблонов.')
                    item['description'] = f'{item["description"]}\nError: Не найден сервер reverse-proxy {err}.'
                    item['enabled'] = False
                    error = 1
            item['profiles'] = new_profiles

            if item.pop('error', False):
                item['enabled'] = False
                error = 1

            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя правила')
            if item['name'] in reverse_rules:
                self.stepChanged.emit(f'uGRAY|       Правило балансировки reverse-proxy "{item["name"]}" уже существует.')
            else:
                err, result = self.utm.add_template_loadbalancing_rule(template_id, item)
                if err:
                    self.stepChanged.emit(f'RED|       {result}  [Правило "{item["name"]}" не импортировано]')
                    error = 1
                else:
                    reverse_rules[item['name']] = result
                    self.stepChanged.emit(f'BLACK|       Правило балансировки reverse-proxy "{item["name"]}" импортировано.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил балансировки Reverse-proxy.')
        else:
            self.stepChanged.emit('GREEN|    Импорт правил балансировки Reverse-proxy завершён.')


    def import_shaper_rules(self, path, template_id, template_name):
        """Импортируем список правил пропускной способности"""
        json_file = os.path.join(path, 'config_shaper_rules.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт правил пропускной способности в раздел "Политики сети/Пропускная способность".')
        error = 0

        err, result = self.utm.get_template_shaper_rules(template_id)
        if err:
            self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте правил пропускной способности.')
            self.error = 1
            return
        shaper_rules = {x['name']: x['id'] for x in result}

        for item in data:
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя правила')
            if item['scenario_rule_id']:
                try:
                    item['scenario_rule_id'] = self.mc_data['scenarios'][item['scenario_rule_id']].id
                except KeyError as err:
                    self.stepChanged.emit(f'RED|    Error: [Правило "{item["name"]}"] Не найден сценарий {err}. Возможно он отсутствует в этой группе шаблонов.')
                    item['description'] = f'{item["description"]}\nError: Не найден сценарий {err}.'
                    item['scenario_rule_id'] = False
                    item['error'] = True

            item['src_zones'] = self.get_zones_id('src', item['src_zones'], item)
            item['dst_zones'] = self.get_zones_id('dst', item['dst_zones'], item)
            item['src_ips'] = self.get_ips_id('src', item['src_ips'], item)
            item['dst_ips'] = self.get_ips_id('dst', item['dst_ips'], item)
            item['services'] = self.get_services(item['services'], item)
            item['users'] = self.get_guids_users_and_groups(item) if self.mc_data['ldap_servers'] else []
            item['apps'] = self.get_apps(item)
            item['time_restrictions'] = self.get_time_restrictions(item)
            item['cc_network_devices'] = self.get_network_devices(item)
            try:
                item['pool'] = self.mc_data['shapers'][item['pool']].id
            except KeyError as err:
                self.stepChanged.emit(f'RED|    Error: [Правило "{item["name"]}"] Не найдена полоса пропускания "{item["pool"]}". Возможно она отсутствует в этой группе шаблонов.')
                item['description'] = f'{item["description"]}\nError: Не найдена полоса пропускания "{item["pool"]}".'
                item['pool'] = 1
                item['error'] = True

            if item.pop('error', False):
                item['enabled'] = False
                error = 1

            if item['name'] in shaper_rules:
                self.stepChanged.emit(f'uGRAY|    Правило пропускной способности "{item["name"]}" уже существует.')
            else:
                err, result = self.utm.add_template_shaper_rule(template_id, item)
                if err:
                    error = 1
                    self.stepChanged.emit(f'RED|    {result}  [Правило "{item["name"]}" не импортировано]')
                else:
                    shaper_rules[item['name']] = result
                    self.stepChanged.emit(f'BLACK|    Правило пропускной способности "{item["name"]}" импортировано.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил пропускной способности.')
        else:
            self.stepChanged.emit('GREEN|    Импорт правил пропускной способности завершён.')


    #------------------------------------- Политики безопасности ------------------------------------------
    def import_content_rules(self, path, template_id, template_name):
        """Импортировать список правил фильтрации контента"""
        json_file = os.path.join(path, 'config_content_rules.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт правил фильтрации контента в раздел "Политики безопасности/Фильтрация контента".')
        error = 0

        if not self.mc_data.get('morphology', False):
            if self.get_morphology_list():    # Устанавливаем self.mc_data['morphology']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил контентной фильтрации.')
                return
        morphology_list = self.mc_data['morphology']

        if not self.mc_data.get('useragents', False):
            if self.get_useragent_list():    # Устанавливаем self.mc_data['useragents']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил контентной фильтрации.')
                return
        useragent_list = self.mc_data['useragents']

        err, result = self.utm.get_template_content_rules(template_id)
        if err:
            self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте правил контентной фильтрации.')
            self.error = 1
            return
        content_rules = {x['name']: x['id'] for x in result}

        for item in data:
            item.pop('time_created', None)
            item.pop('time_updated', None)
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя правила')
            try:
                item['blockpage_template_id'] = self.mc_data['response_pages'][item['blockpage_template_id']].id
            except KeyError as err:
                self.stepChanged.emit(f'RED|    Error: [Правило "{item["name"]}"] Не найден шаблон страницы блокировки {err}. Возможно он отсутствует в этой группе шаблонов.')
                item['description'] = f'{item["description"]}\nError: Не найден шаблон страницы блокировки {err}.'
                item['blockpage_template_id'] = -1
                item['error'] = True

            item['src_zones'] = self.get_zones_id('src', item['src_zones'], item)
            item['dst_zones'] = self.get_zones_id('dst', item['dst_zones'], item)
            item['src_ips'] = self.get_ips_id('src', item['src_ips'], item)
            item['dst_ips'] = self.get_ips_id('dst', item['dst_ips'], item)
            item['users'] = self.get_guids_users_and_groups(item) if self.mc_data['ldap_servers'] else []
            item['url_categories'] = self.get_url_categories_id(item)
            item['urls'] = self.get_urls_id(item['urls'], item)
            item['referers'] = self.get_urls_id(item['referers'], item)
            item['referer_categories'] = self.get_url_categories_id(item, referer=1)
            item['time_restrictions'] = self.get_time_restrictions(item)
            item['cc_network_devices'] = self.get_network_devices(item)

            if item['scenario_rule_id']:
                try:
                    item['scenario_rule_id'] = self.mc_data['scenarios'][item['scenario_rule_id']].id
                except KeyError as err:
                    self.stepChanged.emit(f'RED|    Error: [Правило "{item["name"]}"] Не найден сценарий {err}. Возможно он отсутствует в этой группе шаблонов.')
                    item['description'] = f'{item["description"]}\nError: Не найден сценарий {err}.'
                    item['scenario_rule_id'] = False
                    item['error'] = True

            new_morph_categories = []
            for x in item['morph_categories']:
                if x in self.mc_data['ug_morphology']:
                    new_morph_categories.append(f'id-{x}')
                else:
                    try:
                        new_morph_categories.append(morphology_list[x].id)
                    except KeyError as err:
                        self.stepChanged.emit(f'RED|    Error: [Правило "{item["name"]}"] Не найден список морфологии {err}. Возможно он отсутствует в этой группе шаблонов.')
                        item['description'] = f'{item["description"]}\nError: Не найден список морфологии {err}.'
                        item['error'] = True
            item['morph_categories'] = new_morph_categories

            new_user_agents = []
            for x in item['user_agents']:
                if x[1] in self.mc_data['ug_useragents']:
                    new_user_agents.append(['list_id', f'id-{x[1]}'])
                else:
                    try:
                        new_user_agents.append(['list_id', useragent_list[x[1]].id])
                    except KeyError as err:
                        self.stepChanged.emit(f'RED|    Error: [Правило "{item["name"]}"] Не найден список UserAgent {err}. Возможно он отсутствует в этой группе шаблонов.')
                        item['description'] = f'{item["description"]}\nError: Не найден список UserAgent {err}.'
                        item['error'] = True
            item['user_agents'] = new_user_agents

            new_content_types = []
            for x in item['content_types']:
                try:
                    new_content_types.append(self.mc_data['mime'][x].id)
                except KeyError as err:
                    self.stepChanged.emit(f'RED|    Error: [Правило "{item["name"]}"] Не найден список типов контента {err}. Возможно он отсутствует в этой группе шаблонов.')
                    item['description'] = f'{item["description"]}\nError: Не найден список типов контента {err}.'
                    item['error'] = True
            item['content_types'] = new_content_types

            if item.pop('error', False):
                item['enabled'] = False
                error = 1

            if item['name'] in content_rules:
                self.stepChanged.emit(f'uGRAY|    Правило контентной фильтрации "{item["name"]}" уже существует.')
            else:
#                item['position'] = 'last'
                err, result = self.utm.add_template_content_rule(template_id, item)
                if err:
                    error = 1
                    self.stepChanged.emit(f'RED|    {result}  [Правило "{item["name"]}" не импортировано]')
                else:
                    content_rules[item['name']] = result
                    self.stepChanged.emit(f'BLACK|    Правило контентной фильтрации "{item["name"]}" импортировано.')

        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил контентной фильтрации.')
        else:
            self.stepChanged.emit('GREEN|    Импорт правил контентной фильтрации завершён.')


    def import_safebrowsing_rules(self, path, template_id, template_name):
        """Импортируем список правил веб-безопасности"""
        json_file = os.path.join(path, 'config_safebrowsing_rules.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт правил веб-безопасности в раздел "Политики безопасности/Веб-безопасность".')
        error = 0

        err, result = self.utm.get_template_safebrowsing_rules(template_id)
        if err:
            self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте правил веб-безопасности.')
            self.error = 1
            return
        safebrowsing_rules = {x['name']: x['id'] for x in result}

        for item in data:
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя правила')
            item.pop('time_created', None)
            item.pop('time_updated', None)
            item['src_zones'] = self.get_zones_id('src', item['src_zones'], item)
            item['src_ips'] = self.get_ips_id('src', item['src_ips'], item)
            item['users'] = self.get_guids_users_and_groups(item) if self.mc_data['ldap_servers'] else []
            item['time_restrictions'] = self.get_time_restrictions(item)
            item['url_list_exclusions'] = self.get_urls_id(item['url_list_exclusions'], item)
            item['cc_network_devices'] = self.get_network_devices(item)

            if item.pop('error', False):
                item['enabled'] = False
                error = 1

            if item['name'] in safebrowsing_rules:
                self.stepChanged.emit(f'uGRAY|    Правило веб-безопасности "{item["name"]}" уже существует.')
            else:
#                item['position'] = 'last'
                err, result = self.utm.add_template_safebrowsing_rule(template_id, item)
                if err:
                    error = 1
                    self.stepChanged.emit(f'RED|    {result}  [Правило веб-безопасности "{item["name"]}" не импортировано]')
                else:
                    safebrowsing_rules[item['name']] = result
                    self.stepChanged.emit(f'BLACK|    Правило веб-безопасности "{item["name"]}" импортировано.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил веб-безопасности.')
        else:
            self.stepChanged.emit('GREEN|    Импорт правил веб-безопасности завершён.')


    def import_tunnel_inspection_rules(self, path, template_id, template_name):
        """Импортируем список правил инспектирования туннелей"""
        json_file = os.path.join(path, 'config_tunnelinspection_rules.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт правил инспектирования туннелей в раздел "Политики безопасности/Инспектирование туннелей".')
        error = 0

        err, rules = self.utm.get_template_tunnel_inspection_rules(template_id)
        if err:
            self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте правил инспектирования туннелей.')
            self.error = 1
            return
        tunnel_inspect_rules = {x['name']: x['id'] for x in rules}

        for item in data:
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя правила')
            item['src_zones'] = self.get_zones_id('src', item['src_zones'], item)
            item['dst_zones'] = self.get_zones_id('dst', item['dst_zones'], item)
            item['src_ips'] = self.get_ips_id('src', item['src_ips'], item)
            item['dst_ips'] = self.get_ips_id('dst', item['dst_ips'], item)
            item['cc_network_devices'] = self.get_network_devices(item)

            if item.pop('error', False):
                item['enabled'] = False
                error = 1

            if item['name'] in tunnel_inspect_rules:
                self.stepChanged.emit(f'uGRAY|    Правило инспектирования туннелей "{item["name"]}" уже существует.')
            else:
#                item['position'] = 'last'
                err, result = self.utm.add_template_tunnel_inspection_rule(template_id, item)
                if err:
                    error = 1
                    self.stepChanged.emit(f'RED|    {result}  [Правило инспектирования туннелей "{item["name"]}" не импортировано]')
                else:
                    tunnel_inspect_rules[item['name']] = result
                    self.stepChanged.emit(f'BLACK|    Правило инспектирования туннелей "{item["name"]}" импортировано.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил инспектирования туннелей.')
        else:
            self.stepChanged.emit('GREEN|    Импорт правил инспектирования туннелей завершён.')


    def import_ssldecrypt_rules(self, path, template_id, template_name):
        """Импортируем список правил инспектирования SSL"""
        json_file = os.path.join(path, 'config_ssldecrypt_rules.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт правил инспектирования SSL в раздел "Политики безопасности/Инспектирование SSL".')
        error = 0

        if not self.mc_data.get('ssl_forward_profiles', False):
            if self.get_ssl_forward_profiles():    # Устанавливаем self.mc_data['ssl_forward_profiles']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил инспектирования SSL.')
                return
        ssl_forward_profiles = self.mc_data['ssl_forward_profiles']

        err, rules = self.utm.get_template_ssldecrypt_rules(template_id)
        if err:
            self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте правил инспектирования SSL.')
            self.error = 1
            return
        ssldecrypt_rules = {x['name']: x['id'] for x in rules}

        for item in data:
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя правила')
            item.pop('time_created', None)
            item.pop('time_updated', None)
            item['users'] = self.get_guids_users_and_groups(item) if self.mc_data['ldap_servers'] else []
            item['src_zones'] = self.get_zones_id('src', item['src_zones'], item)
            item['src_ips'] = self.get_ips_id('src', item['src_ips'], item)
            item['dst_ips'] = self.get_ips_id('dst', item['dst_ips'], item)
            item['url_categories'] = self.get_url_categories_id(item)
            item['urls'] = self.get_urls_id(item['urls'], item)
            item['time_restrictions'] = self.get_time_restrictions(item)
            item['cc_network_devices'] = self.get_network_devices(item)
            try:
                item['ssl_profile_id'] = self.mc_data['ssl_profiles'][item['ssl_profile_id']].id
            except KeyError as err:
                self.stepChanged.emit(f'RED|    Error: [Правило "{item["name"]}"] Не найден профиль SSL {err}. Возможно он отсутствует в этой группе шаблонов.')
                item['description'] = f'{item["description"]}\nError: Не найден профиль SSL {err}. Установлен Default SSL profile.'
                item['ssl_profile_id'] = self.mc_data['ssl_profiles']['Default SSL profile'].id
                item['error'] = True
            try:
                item['ssl_forward_profile_id'] = ssl_forward_profiles[item['ssl_forward_profile_id']].id
            except KeyError as err:
                self.stepChanged.emit(f'RED|    Error: [Правило "{item["name"]}"] Не найден профиль пересылки SSL {err}. Возможно он отсутствует в этой группе шаблонов.')
                item['description'] = f'{item["description"]}\nError: Не найден профиль пересылки SSL {err}.'
                item['ssl_forward_profile_id'] = -1
                item['error'] = True

            if item.pop('error', False):
                item['enabled'] = False
                error = 1

            if item['name'] in ssldecrypt_rules:
                self.stepChanged.emit(f'uGRAY|    Правило инспектирования SSL "{item["name"]}" уже существует.')
            else:
#                item['position'] = 'last'
                err, result = self.utm.add_template_ssldecrypt_rule(template_id, item)
                if err:
                    error = 1
                    self.stepChanged.emit(f'RED|    {result}  [Правило инспектирования SSL "{item["name"]}" не импортировано]')
                else:
                    ssldecrypt_rules[item['name']] = result
                    self.stepChanged.emit(f'BLACK|    Правило инспектирования SSL "{item["name"]}" импортировано.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил инспектирования SSL.')
        else:
            self.stepChanged.emit('GREEN|    Импорт правил инспектирования SSL завершён.')


    def import_sshdecrypt_rules(self, path, template_id, template_name):
        """Импортируем список правил инспектирования SSH"""
        json_file = os.path.join(path, 'config_sshdecrypt_rules.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт правил инспектирования SSH в раздел "Политики безопасности/Инспектирование SSH".')
        error = 0

        err, rules = self.utm.get_template_sshdecrypt_rules(template_id)
        if err:
            self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте правил инспектирования SSH.')
            self.error = 1
            return
        sshdecrypt_rules = {x['name']: x['id'] for x in rules}

        for item in data:
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя правила')
            item.pop('time_created', None)
            item.pop('time_updated', None)
            item['users'] = self.get_guids_users_and_groups(item) if self.mc_data['ldap_servers'] else []
            item['src_zones'] = self.get_zones_id('src', item['src_zones'], item)
            item['src_ips'] = self.get_ips_id('src', item['src_ips'], item)
            item['dst_ips'] = self.get_ips_id('dst', item['dst_ips'], item)
            item['time_restrictions'] = self.get_time_restrictions(item)
            item['protocols'] = self.get_services(item['protocols'], item)
            item['cc_network_devices'] = self.get_network_devices(item)

            if item.pop('error', False):
                item['enabled'] = False
                error = 1

            if item['name'] in sshdecrypt_rules:
                self.stepChanged.emit(f'uGRAY|    Правило инспектирования SSH "{item["name"]}" уже существует.')
            else:
                item['position'] = 'last'
                err, result = self.utm.add_template_sshdecrypt_rule(template_id, item)
                if err:
                    error = 1
                    self.stepChanged.emit(f'RED|    {result}  [Правило инспектирования SSH "{item["name"]}" не импортировано]')
                else:
                    sshdecrypt_rules[item['name']] = result
                    self.stepChanged.emit(f'BLACK|    Правило инспектирования SSH "{item["name"]}" импортировано.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил инспектирования SSH.')
        else:
            self.stepChanged.emit('GREEN|    Импорт правил инспектирования SSH завершён.')


    def import_mailsecurity(self, path, template_id, template_name):
        self.import_mailsecurity_rules(path, template_id)
        self.import_mailsecurity_antispam(path, template_id)


    def import_mailsecurity_rules(self, path, template_id):
        """Импортируем список правил защиты почтового трафика"""
        json_file = os.path.join(path, 'config_mailsecurity_rules.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт правил защиты почтового трафика в раздел "Политики безопасности/Защита почтового трафика".')
        error = 0

        if not self.mc_data.get('email_groups', False):
            if self.get_email_groups():    # Устанавливаем self.mc_data['email_groups']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил защиты почтового трафика.')
                return
        email = self.mc_data['email_groups']

        err, result = self.utm.get_template_mailsecurity_rules(template_id)
        if err:
            self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте правил защиты почтового трафика.')
            self.error = 1
            return
        mailsecurity_rules = {x['name']: x['id'] for x in result}

        for item in data:
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя правила')
            item['src_zones'] = self.get_zones_id('src', item['src_zones'], item)
            item['dst_zones'] = self.get_zones_id('dst', item['dst_zones'], item)
            item['src_ips'] = self.get_ips_id('src', item['src_ips'], item)
            item['dst_ips'] = self.get_ips_id('dst', item['dst_ips'], item)
            item['users'] = self.get_guids_users_and_groups(item) if self.mc_data['ldap_servers'] else []
            item['cc_network_devices'] = self.get_network_devices(item)

            if not item['services']:
                item['services'] = [['service', 'SMTP'], ['service', 'POP3'], ['service', 'SMTPS'], ['service', 'POP3S']]
            item['services'] = self.get_services(item['services'], item)

            try:
                item['envelope_from'] = [[x[0], email[x[1]].id] for x in item['envelope_from']]
            except KeyError as err:
                self.stepChanged.emit(f'RED|    Error: [Правило "{item["name"]}"] Не найден список почтовых адресов {err}. Возможно он отсутствует в этой группе шаблонов.')
                item['description'] = f'{item["description"]}\nError: Не найден список почтовых адресов {err}.'
                item['envelope_from'] = []
                item['error'] = True

            try:
                item['envelope_to'] = [[x[0], email[x[1]].id] for x in item['envelope_to']]
            except KeyError as err:
                self.stepChanged.emit(f'RED|    Error: [Правило "{item["name"]}"] Не найден список почтовых адресов {err}. Возможно он отсутствует в этой группе шаблонов.')
                item['description'] = f'{item["description"]}\nError: Не найден список почтовых адресов {err}.'
                item['envelope_to'] = []
                item['error'] = True

            if item.pop('error', False):
                item['enabled'] = False
                error = 1

            if item['name'] in mailsecurity_rules:
                self.stepChanged.emit(f'uGRAY|    Правило "{item["name"]}" уже существует.')
            else:
                err, result = self.utm.add_template_mailsecurity_rule(template_id, item)
                if err:
                    error = 1
                    self.stepChanged.emit(f'RED|    {result}  [Правило "{item["name"]}" не импортировано]')
                else:
                    mailsecurity_rules[item['name']] = result
                    self.stepChanged.emit(f'BLACK|    Правило "{item["name"]}" импортировано.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил защиты почтового трафика.')
        else:
            self.stepChanged.emit('GREEN|    Импорт правил защиты почтового трафика завершён.')


    def import_mailsecurity_antispam(self, path, template_id):
        """Импортируем dnsbl и batv защиты почтового трафика"""
        json_file = os.path.join(path, 'config_mailsecurity_dnsbl.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт настроек антиспама защиты почтового трафика в раздел "Политики безопасности/Защита почтового трафика".')

        data['white_list'] = self.get_ips_id('white_list', data['white_list'], {'name': 'antispam DNSBL'})
        data['black_list'] = self.get_ips_id('black_list', data['black_list'], {'name': 'antispam DNSBL'})

        err, result = self.utm.set_template_mailsecurity_antispam(template_id, data)
        if err:
            self.error = 1
            self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте настроек антиспама.')
        else:
            self.stepChanged.emit(f'GREEN|    Настройки антиспама импортированы.')


    def import_icap_servers(self, path, template_id, template_name):
        """Импортируем список серверов ICAP"""
        json_file = os.path.join(path, 'config_icap_servers.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт серверов ICAP в раздел "Политики безопасности/ICAP-серверы".')
        error = 0

        if not self.mc_data.get('icap_servers', False):
            if self.get_icap_servers():      # Устанавливаем self.mc_data['icap_servers']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте серверов ICAP.')
                return
        icap_servers = self.mc_data['icap_servers']

        for item in data:
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя сервера')
            if item['name'] in icap_servers:
                if template_id == icap_servers[item['name']].template_id:
                    self.stepChanged.emit(f'uGRAY|    ICAP-сервер "{item["name"]}" уже существует в текущем шаблоне.')
                else:
                    self.stepChanged.emit(f'sGREEN|    ICAP-сервер "{item["name"]}" уже существует в шаблоне "{icap_servers[item["name"]].template_name}".')
            else:
                item['position'] = 'last'
                err, result = self.utm.add_template_icap_server(template_id, item)
                if err:
                    self.stepChanged.emit(f'RED|    {result}  [ICAP-сервер "{item["name"]}" не импортирован]')
                    error = 1
                else:
                    icap_servers[item['name']] = BaseObject(id=result, template_id=template_id, template_name=template_name)
                    self.stepChanged.emit(f'BLACK|    ICAP-сервер "{item["name"]}" импортирован.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте серверов ICAP.')
        else:
            self.stepChanged.emit('GREEN|    Импорт серверов ICAP завершён.')


    def import_icap_rules(self, path, template_id, template_name):
        """Импортируем список правил ICAP"""
        json_file = os.path.join(path, 'config_icap_rules.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт правил ICAP в раздел "Политики безопасности/ICAP-правила".')
        error = 0

        if not self.mc_data.get('icap_servers', False):
            if self.get_icap_servers():      # Устанавливаем self.mc_data['icap_servers']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил ICAP.')
                return
        icap_servers = self.mc_data['icap_servers']

        err, result = self.utm.get_template_loadbalancing_rules(template_id, query={'query': 'type = icap'})
        if err:
            self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте правил ICAP.')
            self.error = 1
            return
        icap_loadbalancing = {x['name']: x['id'] for x in result}

        err, result = self.utm.get_template_icap_rules(template_id)
        if err:
            self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте правил ICAP.')
            self.error = 1
            return
        icap_rules = {x['name']: x['id'] for x in result}

        for item in data:
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя правила')
            item.pop('time_created', None)
            item.pop('time_updated', None)

            new_servers = []
            for server in item['servers']:
                if server[0] == 'lbrule':
                    try:
                        new_servers.append(['lbrule', icap_loadbalancing[server[1]]])
                    except KeyError as err:
                        self.stepChanged.emit(f'RED|    Error: [Правило "{item["name"]}"] Не найден балансировщик серверов ICAP {err}. Возможно он отсутствует в этой группе шаблонов.')
                        item['description'] = f'{item["description"]}\nError: Не найден балансировщик серверов ICAP {err}.'
                        item['error'] = True
                elif server[0] == 'profile':
                    try:
                        new_servers.append(['profile', icap_servers[server[1]].id])
                    except KeyError as err:
                        self.stepChanged.emit(f'RED|    Error: [Правило "{item["name"]}"] Не найден сервер ICAP {err}. Возможно он отсутствует в этой группе шаблонов.')
                        item['description'] = f'{item["description"]}\nError: Не найден сервер ICAP {err}.'
                        item['error'] = True
            item['servers'] = new_servers

            item['users'] = self.get_guids_users_and_groups(item) if self.mc_data['ldap_servers'] else []
            item['src_zones'] = self.get_zones_id('src', item['src_zones'], item)
            item['src_ips'] = self.get_ips_id('src', item['src_ips'], item)
            item['dst_ips'] = self.get_ips_id('dst', item['dst_ips'], item)
            item['url_categories'] = self.get_url_categories_id(item)
            item['urls'] = self.get_urls_id(item['urls'], item)
            item['cc_network_devices'] = self.get_network_devices(item)

            new_content_types = []
            for x in item['content_types']:
                try:
                    new_content_types.append(self.mc_data['mime'][x].id)
                except KeyError as err:
                    self.stepChanged.emit(f'RED|    Error: [Правило "{item["name"]}"] Не найден список типов контента {err}. Возможно он отсутствует в этой группе шаблонов.')
                    item['description'] = f'{item["description"]}\nError: Не найден список типов контента {err}.'
                    item['error'] = True
            item['content_types'] = new_content_types

            if item.pop('error', False):
                item['enabled'] = False
                error = 1

            if item['name'] in icap_rules:
                self.stepChanged.emit(f'uGRAY|    ICAP-правило "{item["name"]}" уже существует.')
            else:
                err, result = self.utm.add_template_icap_rule(template_id, item)
                if err:
                    self.stepChanged.emit(f'RED|    {result}  [ICAP-правило "{item["name"]}" не импортировано]')
                    error = 1
                else:
                    icap_rules[item['name']] = result
                    self.stepChanged.emit(f'BLACK|    ICAP-правило "{item["name"]}" импортировано.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил ICAP.')
        else:
            self.stepChanged.emit('GREEN|    Импорт правил ICAP завершён.')


    def import_dos_profiles(self, path, template_id, template_name):
        """Импортируем список профилей DoS"""
        json_file = os.path.join(path, 'config_dos_profiles.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт профилей DoS в раздел "Политики безопасности/Профили DoS".')
        error = 0

        if not self.mc_data.get('dos_profiles', False):
            if self.get_dos_profiles():      # Устанавливаем self.mc_data['dos_profiles']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей DoS.')
                return
        dos_profiles = self.mc_data['dos_profiles']

        for item in data:
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя профиля')
            if item['name'] in dos_profiles:
                if template_id == dos_profiles[item['name']].template_id:
                    self.stepChanged.emit(f'uGRAY|    Профиль DoS "{item["name"]}" уже существует в текущем шаблоне.')
                else:
                    self.stepChanged.emit(f'sGREEN|    Профиль DoS "{item["name"]}" уже существует в шаблоне "{dos_profiles[item["name"]].template_name}".')
            else:
                err, result = self.utm.add_template_dos_profile(template_id, item)
                if err:
                    error = 1
                    self.stepChanged.emit(f'RED|    {result}  [Профиль DoS "{item["name"]}" не импортирован]')
                else:
                    dos_profiles[item['name']] = BaseObject(id=result, template_id=template_id, template_name=template_name)
                    self.stepChanged.emit(f'BLACK|    Профиль DoS "{item["name"]}" импортирован.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей DoS.')
        else:
            self.stepChanged.emit('GREEN|    Импорт профилей DoS завершён.')


    def import_dos_rules(self, path, template_id, template_name):
        """Импортируем список правил защиты DoS"""
        json_file = os.path.join(path, 'config_dos_rules.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт правил защиты DoS в раздел "Политики безопасности/Правила защиты DoS".')
        error = 0

        if not self.mc_data.get('dos_profiles', False):
            if self.get_dos_profiles():      # Устанавливаем self.mc_data['dos_profiles']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей DoS.')
                return
        dos_profiles = self.mc_data['dos_profiles']

        err, result = self.utm.get_template_dos_rules(template_id)
        if err:
            self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте правил защиты DoS.')
            self.error = 1
            return
        dos_rules = {x['name']: x['id'] for x in result}

        for item in data:
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя правила')
            item['src_zones'] = self.get_zones_id('src', item['src_zones'], item)
            item['dst_zones'] = self.get_zones_id('dst', item['dst_zones'], item)
            item['src_ips'] = self.get_ips_id('src', item['src_ips'], item)
            item['dst_ips'] = self.get_ips_id('dst', item['dst_ips'], item)
            item['users'] = self.get_guids_users_and_groups(item) if self.mc_data['ldap_servers'] else []
            item['services'] = self.get_services(item['services'], item)
            item['time_restrictions'] = self.get_time_restrictions(item)
            item['cc_network_devices'] = self.get_network_devices(item)

            if item['dos_profile']:
                try:
                    item['dos_profile'] = dos_profiles[item['dos_profile']].id
                except KeyError as err:
                    self.stepChanged.emit(f'RED|    Error: [Правило "{item["name"]}"] Не найден профиль DoS {err}. Возможно он отсутствует в этой группе шаблонов.')
                    item['description'] = f'{item["description"]}\nError: Не найден профиль DoS {err}.'
                    item['dos_profile'] = False
                    item['error'] = True
            if item['scenario_rule_id']:
                try:
                    item['scenario_rule_id'] = self.mc_data['scenarios'][item['scenario_rule_id']].id
                except KeyError as err:
                    self.stepChanged.emit(f'RED|    Error: [Правило "{item["name"]}"] Не найден сценарий {err}. Возможно он отсутствует в этой группе шаблонов.')
                    item['description'] = f'{item["description"]}\nError: Не найден сценарий {err}.'
                    item['scenario_rule_id'] = False
                    item['error'] = True

            if item.pop('error', False):
                item['enabled'] = False
                error = 1

            if item['name'] in dos_rules:
                self.stepChanged.emit(f'uGRAY|    Правило защиты DoS "{item["name"]}" уже существует.')
            else:
                err, result = self.utm.add_template_dos_rule(template_id, item)
                if err:
                    error = 1
                    self.stepChanged.emit(f'RED|    {result}  [Правило защиты DoS "{item["name"]}" не импортировано]')
                else:
                    dos_rules[item['name']] = result
                    self.stepChanged.emit(f'BLACK|    Правило защиты DoS "{item["name"]}" импортировано.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил защиты DoS.')
        else:
            self.stepChanged.emit('GREEN|    Импорт правил защиты DoS завершён.')


    #---------------------------------------- Глобальный портал ----------------------------------------
    def import_proxyportal_rules(self, path, template_id, template_name):
        """Импортируем список URL-ресурсов веб-портала"""
        json_file = os.path.join(path, 'config_web_portal.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт списка ресурсов веб-портала в раздел "Глобальный портал/Веб-портал".')
        error = 0

        err, result = self.utm.get_template_proxyportal_rules(template_id)
        if err:
            self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте ресурсов веб-портала.')
            self.error = 1
            return
        list_proxyportal = {x['name']: x['id'] for x in result}

        for item in data:
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя ресурса')
            item['users'] = self.get_guids_users_and_groups(item) if self.mc_data['ldap_servers'] else []
            item['cc_network_devices'] = self.get_network_devices(item)

            try:
                if item['mapping_url_ssl_profile_id']:
                    item['mapping_url_ssl_profile_id'] = self.mc_data['ssl_profiles'][item['mapping_url_ssl_profile_id']].id
            except KeyError as err:
                self.stepChanged.emit(f'RED|    Error: [Правило "{item["name"]}"] Не найден профиль SSL {err}. Возможно он отсутствует в этой группе шаблонов.')
                item['description'] = f'{item["description"]}\nError: Не найден профиль SSL {err}.'
                item['mapping_url_ssl_profile_id'] = 0
                item['error'] = True

            try:
                if item['mapping_url_certificate_id']:
                    item['mapping_url_certificate_id'] = self.mc_data['certs'][item['mapping_url_certificate_id']].id
            except KeyError as err:
                self.stepChanged.emit(f'RED|    Error: [Правило "{item["name"]}"] Не найден сертификат {err}. Возможно он отсутствует в этой группе шаблонов.')
                item['description'] = f'{item["description"]}\nError: Не найден сертификат {err}.'
                item['mapping_url_certificate_id'] = 0
                item['error'] = True

            if item.pop('error', False):
                item['enabled'] = False
                error = 1

            if item['name'] in list_proxyportal:
                self.stepChanged.emit(f'uGRAY|    Ресурс веб-портала "{item["name"]}" уже существует.')
            else:
                err, result = self.utm.add_template_proxyportal_rule(template_id, item)
                if err:
                    self.stepChanged.emit(f'RED|    {result}  [Ресурс веб-портала "{item["name"]}" не импортирован]')
                    error = 1
                else:
                    list_proxyportal[item['name']] = result
                    self.stepChanged.emit(f'BLACK|    Ресурс веб-портала "{item["name"]}" импортирован.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте ресурсов веб-портала.')
        else:
            self.stepChanged.emit('GREEN|    Импорт списка ресурсов веб-портала завершён.')


    def import_reverseproxy_servers(self, path, template_id, template_name):
        """Импортируем список серверов reverse-прокси"""
        json_file = os.path.join(path, 'config_reverseproxy_servers.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт серверов reverse-прокси в раздел "Глобальный портал/Серверы reverse-прокси".')
        error = 0

        if not self.mc_data.get('reverseproxy_servers', False):
            if self.get_reverseproxy_servers():      # Устанавливаем self.mc_data['reverseproxy_servers']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте серверов reverse-прокси.')
                return
        reverseproxy_servers = self.mc_data['reverseproxy_servers']

        for item in data:
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя сервера')
            if item['name'] in reverseproxy_servers:
                if template_id == reverseproxy_servers[item['name']].template_id:
                    self.stepChanged.emit(f'uGRAY|    Сервер reverse-прокси "{item["name"]}" уже существует в текущем шаблоне.')
                else:
                    self.stepChanged.emit(f'sGREEN|    Сервер reverse-прокси "{item["name"]}" уже существует в шаблоне "{icap_servers[item["name"]].template_name}".')
            else:
                err, result = self.utm.add_template_reverseproxy_server(template_id, item)
                if err:
                    self.stepChanged.emit(f'RED|    {result}  [Сервер reverse-прокси "{item["name"]}" не импортирован]')
                    error = 1
                else:
                    reverseproxy_servers[item['name']] = BaseObject(id=result, template_id=template_id, template_name=template_name)
                    self.stepChanged.emit(f'BLACK|    Сервер reverse-прокси "{item["name"]}" импортирован.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте серверов reverse-прокси.')
        else:
            self.stepChanged.emit('GREEN|    Импорт серверов reverse-прокси завершён.')


    def import_reverseproxy_rules(self, path, template_id, template_name):
        """Импортируем список правил reverse-прокси"""
        json_file = os.path.join(path, 'config_reverseproxy_rules.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт правил reverse-прокси в раздел "Глобальный портал/Правила reverse-прокси".')
        error = 0

        err, result = self.utm.get_template_loadbalancing_rules(template_id, query={'query': 'type = reverse'})
        if err:
            self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте правил reverse-прокси.')
            self.error = 1
            return
        reverse_loadbalancing = {x['name']: x['id'] for x in result}

        if not self.mc_data.get('reverseproxy_servers', False):
            if self.get_reverseproxy_servers():      # Устанавливаем self.mc_data['reverseproxy_servers']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил reverse-прокси.')
                return
        reverseproxy_servers = self.mc_data['reverseproxy_servers']

        if not self.mc_data.get('useragents', False):
            if self.get_useragent_list():      # Устанавливаем self.mc_data['useragents']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил reverse-прокси.')
                return
        useragent_list = self.mc_data['useragents']

        if not self.mc_data.get('client_certs_profiles', False):
            if self.get_client_certificate_profiles(): # Устанавливаем self.mc_data['client_certs_profiles']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил reverse-прокси.')
                return
        client_certs_profiles = self.mc_data['client_certs_profiles']

        err, result = self.utm.get_template_reverseproxy_rules(template_id)
        if err:
            self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте правил reverse-прокси.')
            self.error = 1
            return
        reverseproxy_rules = {x['name']: x['id'] for x in result}

        for item in data:
            item.pop('waf_profile_id', None)    # Если конфигурация была выгрудена с версии < 7.3
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя правила')
            item['src_zones'] = self.get_zones_id('src', item['src_zones'], item)
            item['src_ips'] = self.get_ips_id('src', item['src_ips'], item)
            item['dst_ips'] = self.get_ips_id('dst', item['dst_ips'], item)
            item['users'] = self.get_guids_users_and_groups(item) if self.mc_data['ldap_servers'] else []
            item['cc_network_devices'] = self.get_network_devices(item)

            if not item['src_zones']:
                self.stepChanged.emit(f'RED|    Error: Правило "{item["name"]}" не импортировано. Не указана src-зона.')
                error = 1
                continue

            try:
                for x in item['servers']:
                    x[1] = reverseproxy_servers[x[1]].id if x[0] == 'profile' else reverse_loadbalancing[x[1]]
            except KeyError as err:
                self.stepChanged.emit(f'RED|    Error: Правило "{item["name"]}" не импортировано. Не найден сервер reverse-прокси или балансировщик {err}. Возможно он отсутствует в этой группе шаблонов..')
                error = 1
                continue

            if item['ssl_profile_id']:
                try:
                    item['ssl_profile_id'] = self.mc_data['ssl_profiles'][item['ssl_profile_id']].id
                except KeyError as err:
                    self.stepChanged.emit(f'RED|    Error: [Правило "{item["name"]}"] Не найден профиль SSL {err}. Возможно он отсутствует в этой группе шаблонов.')
                    item['description'] = f'{item["description"]}\nError: Не найден профиль SSL {err}.'
                    item['ssl_profile_id'] = 0
                    item['is_https'] = False
                    item['error'] = True
            else:
                item['is_https'] = False

            if item['certificate_id']:
                try:
                    item['certificate_id'] = self.mc_data['certs'][item['certificate_id']].id
                except KeyError as err:
                    self.stepChanged.emit(f'RED|    Error: [Правило "{item["name"]}"] Не найден сертификат {err}. Возможно он отсутствует в этой группе шаблонов.')
                    item['description'] = f'{item["description"]}\nError: Не найден сертификат {err}.'
                    item['certificate_id'] = -1
                    item['is_https'] = False
                    item['error'] = True
            else:
                item['certificate_id'] = -1
                item['is_https'] = False

            new_user_agents = []
            for x in item['user_agents']:
                if x[1] in self.mc_data['ug_useragents']:
                    new_user_agents.append(['list_id', f'id-{x[1]}'])
                else:
                    try:
                        new_user_agents.append(['list_id', useragent_list[x[1]].id])
                    except KeyError as err:
                        self.stepChanged.emit(f'RED|    Error: [Правило "{item["name"]}"] Не найден список Useragent {err}. Возможно он отсутствует в этой группе шаблонов.')
                        item['description'] = f'{item["description"]}\nError: Не найден Useragent {err}.'
                        item['error'] = True
            item['user_agents'] = new_user_agents

            if item['client_certificate_profile_id']:
                try:
                    item['client_certificate_profile_id'] = client_certs_profiles[item['client_certificate_profile_id']].id
                except KeyError as err:
                    self.stepChanged.emit(f'RED|    Error: [Правило "{item["name"]}"] Не найден профиль сертификата пользователя "{item["client_certificate_profile_id"]}". Возможно он отсутствует в этой группе шаблонов.')
                    item['description'] = f'{item["description"]}\nError: Не найден профиль сертификата пользователя "{item["client_certificate_profile_id"]}".'
                    item['client_certificate_profile_id'] = 0
                    item['error'] = True

            if item.pop('error', False):
                item['enabled'] = False
                error = 1

            if item['name'] in reverseproxy_rules:
                self.stepChanged.emit(f'uGRAY|    Правило reverse-прокси "{item["name"]}" уже существует.')
            else:
                err, result = self.utm.add_template_reverseproxy_rule(template_id, item)
                if err:
                    self.stepChanged.emit(f'RED|    {result}  [Правило reverse-прокси "{item["name"]}" не импортировано]')
                    error = 1
                else:
                    reverseproxy_rules[item['name']] = result
                    self.stepChanged.emit(f'BLACK|    Правило reverse-прокси "{item["name"]}" импортировано.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил reverse-прокси.')
        else:
            self.stepChanged.emit('GREEN|    Импорт правил reverse-прокси завершён.')
        self.stepChanged.emit('LBLUE|    Проверьте флаг "Использовать HTTPS" во всех импортированных правилах! Если не установлен профиль SSL, выберите нужный.')


    #------------------------------- Вышестоящий прокси -----------------------------------------
    def import_upstream_proxies_servers(self, path, template_id, template_name):
        """Импортируем список серверов вышестоящих прокси"""
        if self.utm.float_version < 7.4:
            return

        json_file = os.path.join(path, 'config_upstreamproxies_servers.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт серверов вышестоящих прокси в раздел "Вышестоящие прокси/Серверы".')
        error = 0

        if not self.mc_data.get('upstreamproxies_servers', False):
            if self.get_upstream_proxies_servers(): # Устанавливаем self.mc_data['upstreamproxies_servers']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте серверов вышестоящих прокси.')
                return
        proxies_servers = self.mc_data['upstreamproxies_servers']

        for item in data:
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя сервера')
            if item['name'] in proxies_servers:
                if template_id == proxies_servers[item['name']].template_id:
                    self.stepChanged.emit(f'uGRAY|    Cервер вышестоящих прокси "{item["name"]}" уже существует в текущем шаблоне.')
                else:
                    self.stepChanged.emit(f'sGREEN|    Cервер вышестоящих прокси "{item["name"]}" уже существует в шаблоне "{proxies_servers[item["name"]].template_name}".')
            else:
                err, result = self.utm.add_template_cascade_proxy_server(template_id, item)
                if err:
                    self.stepChanged.emit(f'RED|    {result}  [Cервер вышестоящих прокси "{item["name"]}" не импортирован]')
                    error = 1
                else:
                    proxies_servers[item['name']] = BaseObject(id=result, template_id=template_id, template_name=template_name)
                    self.stepChanged.emit(f'BLACK|    Cервер вышестоящих прокси "{item["name"]}" импортирован.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте серверов вышестоящих прокси.')
        else:
            self.stepChanged.emit('GREEN|    Импорт серверов вышестоящих прокси завершён.')


    def import_upstream_proxies_profiles(self, path, template_id, template_name):
        """Импортируем список профилей вышестоящих прокси"""
        if self.utm.float_version < 7.4:
            return

        json_file = os.path.join(path, 'config_upstreamproxies_profiles.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт профилей вышестоящих прокси в раздел "Вышестоящие прокси/Профили".')
        error = 0

        if not self.mc_data.get('upstreamproxies_servers', False):
            if self.get_upstream_proxies_servers(): # Устанавливаем self.mc_data['upstreamproxies_servers']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей вышестоящих прокси.')
                return
        proxies_servers = self.mc_data['upstreamproxies_servers']

        if not self.mc_data.get('upstreamproxies_profiles', False):
            if self.get_upstream_proxies_profiles(): # Устанавливаем self.mc_data['upstreamproxies_profiles']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей вышестоящих прокси.')
                return
        proxies_profiles = self.mc_data['upstreamproxies_profiles']

        for item in data:
            new_servers = []
            for x in item['servers']:
                error, x = self.get_transformed_name(x, err=error, descr='Имя сервера')
                try:
                    new_servers.append(proxies_servers[x].id)
                except KeyError:
                    self.stepChanged.emit(f'RED|    Error: [Профиль "{item["name"]}"] Не найден сервер "{x}".')
                    item['description'] = f'{item["description"]}\nError: Не найден сервер "{x}".'
                    error = 1
            item['servers'] = new_servers

            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя сервера')
            if item['name'] in proxies_profiles:
                if template_id == proxies_profiles[item['name']].template_id:
                    self.stepChanged.emit(f'uGRAY|    Профиль вышестоящих прокси "{item["name"]}" уже существует в текущем шаблоне.')
                else:
                    self.stepChanged.emit(f'sGREEN|    Профиль вышестоящих прокси "{item["name"]}" уже существует в шаблоне "{proxies_profiles[item["name"]].template_name}".')
            else:
                err, result = self.utm.add_template_cascade_proxy_profile(template_id, item)
                if err:
                    self.stepChanged.emit(f'RED|    {result}  [Профиль вышестоящих прокси "{item["name"]}" не импортирован]')
                    error = 1
                else:
                    proxies_profiles[item['name']] = BaseObject(id=result, template_id=template_id, template_name=template_name)
                    self.stepChanged.emit(f'BLACK|    Профиль вышестоящих прокси "{item["name"]}" импортирован.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей вышестоящих прокси.')
        else:
            self.stepChanged.emit('GREEN|    Импорт профилей вышестоящих прокси завершён.')


    def import_upstream_proxies_rules(self, path, template_id, template_name):
        """Импортируем список правил вышестоящих прокси"""
        if self.utm.float_version < 7.4:
            return

        json_file = os.path.join(path, 'config_upstreamproxies_rules.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт правил вышестоящих прокси в раздел "Вышестоящие прокси/Правила".')
        error = 0

        if not self.mc_data.get('upstreamproxies_profiles', False):
            if self.get_upstream_proxies_profiles(): # Устанавливаем self.mc_data['upstreamproxies_profiles']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил вышестоящих прокси.')
                return
        proxies_profiles = self.mc_data['upstreamproxies_profiles']

        err, result = self.utm.get_template_cascade_proxy_rules(template_id)
        if err:
            self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте правил вышестоящих прокси.')
            self.error = 1
            return
        proxies_rules = {x['name']: x['id'] for x in result}

        for item in data:
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя правила')
            item.pop('time_created', None)
            item.pop('time_updated', None)

            if item['proxy_profile']:
                try:
                    item['proxy_profile'] = proxies_profiles[item['proxy_profile']].id
                except KeyError as err:
                    self.stepChanged.emit(f'RED|    Error: [Правило "{item["name"]}"] Не найден профиль прокси {err}. Установлен режим работы: "Мимо прокси".')
                    item['description'] = f'{item["description"]}\nError: Не найден профиль прокси {err}. Установлен режим работы: "Мимо прокси".'
                    item['proxy_profile'] = ''
                    item['action'] = 'direct'
                    item['fallback_action'] = 'direct'
                    item.pop('fallback_block_page', None)
                    error = 1
            if 'fallback_block_page' in item:
                try:
                    item['fallback_block_page'] = self.mc_data['response_pages'][item['fallback_block_page']].id
                except KeyError as err:
                    self.stepChanged.emit(f'RED|    Error: [Правило "{item["name"]}"] Не найден шаблон страницы блокировки {err}. Импортируйте шаблоны страниц и повторите попытку.')
                    item['description'] = f'{item["description"]}\nError: Не найден шаблон страницы блокировки "{item["fallback_block_page"]}".'
                    item['fallback_block_page'] = -1
                    error = 1

            item['users'] = self.get_guids_users_and_groups(item) if self.mc_data['ldap_servers'] else []
            item['time_restrictions'] = self.get_time_restrictions(item)
            item['url_categories'] = self.get_url_categories_id(item)
            item['urls'] = self.get_urls_id(item['urls'], item)
            item['src_zones'] = self.get_zones_id('src', item['src_zones'], item)
            item['src_ips'] = self.get_ips_id('src', item['src_ips'], item)

            if item.pop('error', False):
                item['enabled'] = False
                error = 1

            if item['name'] in proxies_rules:
                self.stepChanged.emit(f'uGRAY|    Правило вышестоящих прокси "{item["name"]}" уже существует в текущем шаблоне.')
            else:
                err, result = self.utm.add_template_cascade_proxy_rule(template_id, item)
                if err:
                    self.stepChanged.emit(f'RED|    {result}  [Правило вышестоящих прокси "{item["name"]}" не импортировано]')
                    error = 1
                else:
                    proxies_rules[item['name']] = result
                    self.stepChanged.emit(f'BLACK|    Правило вышестоящих прокси "{item["name"]}" импортировано.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил вышестоящих прокси.')
        else:
            self.stepChanged.emit('GREEN|    Импорт правил вышестоящих прокси завершён.')


    #-------------------------------------- VPN -------------------------------------------------
    def import_vpnclient_security_profiles(self, path, template_id, template_name):
        """Импортируем клиентские профилей безопасности VPN"""
        json_file = os.path.join(path, 'config_vpnclient_security_profiles.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт клиентских профилей безопасности VPN в раздел "VPN/Клиентские профили безопасности".')
        error = 0

        if not self.mc_data.get('vpn_client_security_profiles', False):
            if self.get_vpn_client_security_profiles(): # Устанавливаем self.mc_data['vpn_client_security_profiles']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте клиентских профилей безопасности VPN.')
                return
        security_profiles = self.mc_data['vpn_client_security_profiles']

        for item in data:
            if item['certificate_id']:
                try:
                    item['certificate_id'] = self.mc_data['certs'][item['certificate_id']].id
                except KeyError as err:
                    self.stepChanged.emit(f'RED|    Error: [Правило "{item["name"]}"] Не найден сертификат {err}. Возможно он отсутствует в этой группе шаблонов.')
                    item['description'] = f'{item["description"]}\nError: Не найден сертификат {err}.'
                    item['certificate_id'] = 0
                    error = 1

            if item['name'] in security_profiles:
                if template_id == security_profiles[item['name']].template_id:
                    self.stepChanged.emit(f'uGRAY|    Профиль безопасности VPN "{item["name"]}" уже существует в текущем шаблоне.')
                else:
                    self.stepChanged.emit(f'sGREEN|    Профиль безопасности VPN "{item["name"]}" уже существует в шаблоне "{security_profiles[item["name"]].template_name}".')
            else:
                err, result = self.utm.add_template_vpn_client_security_profile(template_id, item)
                if err:
                    self.stepChanged.emit(f'RED|    {result}  [Профиль безопасности VPN "{item["name"]}" не импортирован]')
                    error = 1
                else:
                    security_profiles[item['name']] = BaseObject(id=result, template_id=template_id, template_name=template_name)
                    self.stepChanged.emit(f'BLACK|    Профиль безопасности VPN "{item["name"]}" импортирован.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте клиентских профилей безопасности VPN.')
        else:
            self.stepChanged.emit('GREEN|    Импорт клиентских профилей безопасности завершён.')


    def import_vpnserver_security_profiles(self, path, template_id, template_name):
        """Импортируем серверные профилей безопасности VPN"""
        json_file = os.path.join(path, 'config_vpnserver_security_profiles.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт серверных профилей безопасности VPN в раздел "VPN/Серверные профили безопасности".')
        error = 0

        if not self.mc_data.get('client_certs_profiles', False):
            if self.get_client_certificate_profiles(): # Устанавливаем self.mc_data['client_certs_profiles']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте серверных профилей безопасности VPN.')
                return
        client_certs_profiles = self.mc_data['client_certs_profiles']

        if not self.mc_data.get('vpn_server_security_profiles', False):
            if self.get_vpn_server_security_profiles(): # Устанавливаем self.mc_data['vpn_server_security_profiles']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте серверных профилей безопасности VPN.')
                return
        security_profiles = self.mc_data['vpn_server_security_profiles']

        for item in data:
            if item['certificate_id']:
                try:
                    item['certificate_id'] = self.mc_data['certs'][item['certificate_id']].id
                except KeyError as err:
                    self.stepChanged.emit(f'RED|    Error: [Профиль "{item["name"]}"] Не найден сертификат {err}. Возможно он отсутствует в этой группе шаблонов.')
                    item['description'] = f'{item["description"]}\nError: Не найден сертификат {err}.'
                    item['certificate_id'] = 0
                    error = 1
            if item['client_certificate_profile_id']:
                try:
                    item['client_certificate_profile_id'] = client_certs_profiles[item['client_certificate_profile_id']].id
                except KeyError as err:
                    self.stepChanged.emit(f'RED|    Error: [Профиль "{item["name"]}"] Не найден профиль сертификата пользователя {err}. Возможно он отсутствует в этой группе шаблонов.')
                    item['description'] = f'{item["description"]}\nError: Не найден профиль сертификата пользователя {err}.'
                    item['client_certificate_profile_id'] = 0
                    error = 1

            if item['name'] in security_profiles:
                if template_id == security_profiles[item['name']].template_id:
                    self.stepChanged.emit(f'uGRAY|    Профиль безопасности VPN "{item["name"]}" уже существует в текущем шаблоне.')
                else:
                    self.stepChanged.emit(f'sGREEN|    Профиль безопасности VPN "{item["name"]}" уже существует в шаблоне "{security_profiles[item["name"]].template_name}".')
            else:
                err, result = self.utm.add_template_vpn_server_security_profile(template_id, item)
                if err:
                    self.stepChanged.emit(f'RED|    {result}  [Профиль безопасности VPN "{item["name"]}" не импортирован]')
                    error = 1
                else:
                    security_profiles[item['name']] = BaseObject(id=result, template_id=template_id, template_name=template_name)
                    self.stepChanged.emit(f'BLACK|    Профиль безопасности VPN "{item["name"]}" импортирован.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте серверных профилей безопасности VPN.')
        else:
            self.stepChanged.emit('GREEN|    Импорт серверных профилей безопасности завершён.')


    def get_networks(self, networks, rule):
        new_networks = []
        for x in networks:
            try:
                new_networks.append(['list_id', self.mc_data['ip_lists'][x[1]].id]  if x[0] == 'list_id' else x)
            except KeyError as err:
                self.stepChanged.emit(f'RED|    Error: [Правило "{rule["name"]}"] Не найден список IP-адресов {err}. Возможно он отсутствует в этой группе шаблонов.')
                rule['description'] = f'{rule["description"]}\nError: Не найден список IP-адресов {err}.'
                rule['error'] = True
        return new_networks


    def import_vpn_networks(self, path, template_id, template_name):
        """Импортируем список сетей VPN"""
        json_file = os.path.join(path, 'config_vpn_networks.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт списка сетей VPN в раздел "VPN/Сети VPN".')
        error = 0

        if not self.mc_data.get('vpn_networks', False):
            if self.get_vpn_networks():        # Устанавливаем self.mc_data['vpn_networks']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте списка сетей VPN.')
                return
        vpn_networks = self.mc_data['vpn_networks']

        for item in data:
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя сети VPN')
            item['networks'] = self.get_networks(item['networks'], item)
            item['ep_routes_include'] = self.get_networks(item['ep_routes_include'], item)
            item['ep_routes_exclude'] = self.get_networks(item['ep_routes_exclude'], item)
            if item.pop('error', False):
                error = 1

            if item['name'] in vpn_networks:
                if template_id == vpn_networks[item['name']].template_id:
                    self.stepChanged.emit(f'uGRAY|    Сеть VPN "{item["name"]}" уже существует в текущем шаблоне.')
                else:
                    self.stepChanged.emit(f'sGREEN|    Сеть VPN "{item["name"]}" уже существует в шаблоне "{vpn_networks[item["name"]].template_name}".')
            else:
                err, result = self.utm.add_template_vpn_network(template_id, item)
                if err:
                    self.stepChanged.emit(f'RED|    {result}  [Сеть VPN "{item["name"]}" не импортирована]')
                    error = 1
                else:
                    vpn_networks[item['name']] = BaseObject(id=result, template_id=template_id, template_name=template_name)
                    self.stepChanged.emit(f'BLACK|    Сеть VPN "{item["name"]}" импортирована.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте списка сетей VPN.')
        else:
            self.stepChanged.emit('GREEN|    Импорт списка сетей VPN завершён.')


    def import_vpn_client_rules(self, path, template_id, template_name):
        """Импортируем список клиентских правил VPN"""
        json_file = os.path.join(path, 'config_vpn_client_rules.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт клиентских правил VPN в раздел "VPN/Клиентские правила".')
        error = 0

        if not self.mc_data.get('interfaces', False):
            if self.get_interfaces_list(): # Устанавливаем self.mc_data['interfaces']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте клиентских правил VPN.')
                return

        if not self.mc_data.get('vpn_client_security_profiles', False):
            if self.get_vpn_client_security_profiles(): # Устанавливаем self.mc_data['vpn_client_security_profiles']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте клиентских правил VPN.')
                return
        security_profiles = self.mc_data['vpn_client_security_profiles']

        err, result = self.utm.get_template_vpn_client_rules(template_id)
        if err:
            self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте клиентских правил VPN.')
            self.error = 1
            return
        vpn_client_rules = {x['name']: x['id'] for x in result}

        for item in data:
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя правила')
            item['cc_network_devices'] = self.get_network_devices(item)
            item.pop('xauth_login', None)
            item.pop('xauth_password', None)
            item.pop('protocol', None)
            item.pop('subnet1', None)
            item.pop('subnet2', None)

            if f'{item["iface_id"]}:cluster' not in self.mc_data['interfaces']:
                self.stepChanged.emit(f'RED|    Error: [Правило "{item["name"]}"] Не найден интерфейс VPN "{item["iface_id"]}" в группе шаблонов.\n       Правило не импортировано.')
                error = 1
                continue
            try:
                item['security_profile_id'] = security_profiles[item['security_profile_id']].id
            except KeyError as err:
                self.stepChanged.emit(f'RED|    Error: [Правило "{item["name"]}"] Не найден профиль безопасности VPN {err}. Возможно он отсутствует в этой группе шаблонов.\n       Правило не импортировано.')
                error = 1
                continue

            if item.pop('error', False):
                item['enabled'] = False
                error = 1

            if item['name'] in vpn_client_rules:
                self.stepChanged.emit(f'uGRAY|    Клиентское правило VPN "{item["name"]}" уже существует в текущем шаблоне.')
            else:
                err, result = self.utm.add_template_vpn_client_rule(template_id, item)
                if err:
                    self.stepChanged.emit(f'RED|    {result}  [Клиентское правило VPN "{item["name"]}" не импортировано]')
                    error = 1
                else:
                    vpn_client_rules[item['name']] = result
                    self.stepChanged.emit(f'BLACK|    Клиентское правило VPN "{item["name"]}" импортировано.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте клиентских правил VPN.')
        else:
            self.stepChanged.emit('GREEN|    Импорт клиентских правил VPN завершён.')


    def import_vpn_server_rules(self, path, template_id, template_name):
        """Импортируем список серверных правил VPN"""
        json_file = os.path.join(path, 'config_vpn_server_rules.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт серверных правил VPN в раздел "VPN/Серверные правила".')
        error = 0

        if not self.mc_data.get('interfaces', False):
            if self.get_interfaces_list(): # Устанавливаем self.mc_data['interfaces']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте клиентских правил VPN.')
                return

        if not self.mc_data.get('vpn_server_security_profiles', False):
            if self.get_vpn_server_security_profiles(): # Устанавливаем self.mc_data['vpn_server_security_profiles']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте серверных правил VPN.')
                return
        security_profiles = self.mc_data['vpn_server_security_profiles']

        if not self.mc_data.get('vpn_networks', False):
            if self.get_vpn_networks():        # Устанавливаем self.mc_data['vpn_networks']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте серверных правил VPN.')
                return
        vpn_networks = self.mc_data['vpn_networks']

        err, result = self.utm.get_template_vpn_server_rules(template_id)
        if err:
            self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте серверных правил VPN.')
            self.error = 1
            return
        vpn_server_rules = {x['name']: x['id'] for x in result}

        for item in data:
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя правила')
            item['src_zones'] = self.get_zones_id('src', item['src_zones'], item)
            item['source_ips'] = self.get_ips_id('src', item['source_ips'], item)
            item['dst_ips'] = self.get_ips_id('dst', item['dst_ips'], item)
            item['users'] = self.get_guids_users_and_groups(item) if self.mc_data['ldap_servers'] else []
            item['cc_network_devices'] = self.get_network_devices(item)

            message = '       Правило "{item["name"]}" не импортировано.'
            if f'{item["iface_id"]}:cluster' not in self.mc_data['interfaces']:
                self.stepChanged.emit(f'RED|    Error: [Правило "{item["name"]}"] Не найден интерфейс VPN "{item["iface_id"]}". Возможно он отсутствует в этой группе шаблонов.\n{message}')
                error = 1
                continue
            try:
                item['security_profile_id'] = security_profiles[item['security_profile_id']].id
            except KeyError as err:
                self.stepChanged.emit(f'RED|    Error: [Правило "{item["name"]}"] Не найден профиль безопасности VPN {err}. Возможно он отсутствует в этой группе шаблонов.\n{message}')
                error = 1
                continue
            try:
                item['tunnel_id'] = vpn_networks[item['tunnel_id']].id
            except KeyError as err:
                self.stepChanged.emit(f'RED|    Error: [Правило "{item["name"]}"] Не найдена сеть VPN "{err}". Возможно она отсутствует в этой группе шаблонов.\n{message}')
                error = 1
                continue
            try:
                item['auth_profile_id'] = self.mc_data['auth_profiles'][item['auth_profile_id']].id
            except KeyError as err:
                self.stepChanged.emit(f'RED|    Error: [Правило "{item["name"]}"] Не найден профиль авторизации {err}. Возможно он отсутствует в этой группе шаблонов.\n{message}')
                error = 1
                continue

            if item.pop('error', False):
                item['enabled'] = False
                error = 1

            if item['name'] in vpn_server_rules:
                self.stepChanged.emit(f'uGRAY|    Серверное правило VPN "{item["name"]}" уже существует в текщем шаблоне.')
            else:
                err, result = self.utm.add_template_vpn_server_rule(template_id, item)
                if err:
                    self.stepChanged.emit(f'RED|    {result}  [Серверное правило VPN "{item["name"]}" не импортировано]')
                    error = 1
                else:
                    vpn_server_rules[item['name']] = result
                    self.stepChanged.emit(f'BLACK|    Серверное правило VPN "{item["name"]}" импортировано.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте серверных правил VPN.')
        else:
            self.stepChanged.emit('GREEN|    Импорт серверных правил VPN завершён.')


    #------------------------------------------- Оповещения ----------------------------------------------
    def import_notification_alert_rules(self, path, template_id, template_name):
        """Импортируем список правил оповещений"""
        json_file = os.path.join(path, 'config_alert_rules.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт правил оповещений в раздел "Диагностика и мониторинг/Правила оповещений".')
        error = 0

        if not self.mc_data.get('notification_profiles', False):
            if self.get_notification_profiles():      # Устанавливаем self.mc_data['notification_profiles']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил оповещений.')
                return

        if not self.mc_data.get('email_groups', False):
            if self.get_email_groups():      # Устанавливаем self.mc_data['email_groups']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил оповещений.')
                return

        if not self.mc_data.get('phone_groups', False):
            if self.get_phone_groups():      # Устанавливаем self.mc_data['phone_groups']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил оповещений.')
                return

        err, result = self.utm.get_template_notification_alert_rules(template_id)
        if err:
            self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте правил оповещений.')
            self.error = 1
            return
        alert_rules = {x['name']: x['id'] for x in result}

        for item in data:
            try:
                item['notification_profile_id'] = self.mc_data['notification_profiles'][item['notification_profile_id']].id
            except KeyError as err:
                message = f'Error: [Правило "{item["name"]}"] Не найден профиль оповещений {err}. Возможно он отсутствует в этой группе шаблонов.'
                self.stepChanged.emit(f'RED|    {message}\n       Правило "{item["name"]}" не импортировано.')
                error = 1
                continue

            new_emails = []
            for x in item['emails']:
                try:
                    new_emails.append(['list_id', self.mc_data['email_groups'][x[1]].id])
                except KeyError as err:
                    self.stepChanged.emit(f'RED|    Error: [Правило "{item["name"]}"] Не найдена группа почтовых адресов {err}. Возможно она отсутствует в этой группе шаблонов.')
                    item['description'] = f'{item["description"]}\nError: Не найдена группа почтовых адресов {err}.'
                    item['enabled'] = False
                    error = 1
            item['emails'] = new_emails

            new_phones = []
            for x in item['phones']:
                try:
                    new_phones.append(['list_id', self.mc_data['phone_groups'][x[1]].id])
                except KeyError as err:
                    self.stepChanged.emit(f'RED|    Error: [Правило "{item["name"]}"] Не найдена группа телефонных номеров {err}. Возможно она отсутствует в этой группе шаблонов.')
                    item['description'] = f'{item["description"]}\nError: Не найдена группа телефонных номеров {err}.'
                    item['enabled'] = False
                    error = 1
            item['phones'] = new_phones

            if item['name'] in alert_rules:
                self.stepChanged.emit(f'uGRAY|    Правило оповещения "{item["name"]}" уже существует в текущем шаблоне.')
            else:
                err, result = self.utm.add_template_notification_alert_rule(template_id, item)
                if err:
                    self.stepChanged.emit(f'RED|    {result}  [Правило оповещения "{item["name"]}" не импортировано]')
                    error = 1
                else:
                    alert_rules[item['name']] = result
                    self.stepChanged.emit(f'BLACK|    Правило оповещения "{item["name"]}" импортировано.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил оповещений.')
        else:
            self.stepChanged.emit('GREEN|    Импорт правил оповещений завершён.')


    def import_snmp_security_profiles(self, path, template_id, template_name):
        """Импортируем профили безопасности SNMP"""
        json_file = os.path.join(path, 'config_snmp_profiles.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт профилей безопасности SNMP в раздел "Диагностика и мониторинг/Профили безопасности SNMP".')
        error = 0

        if not self.mc_data.get('snmp_security_profiles', False):
            if self.get_snmp_security_profiles():      # Устанавливаем self.mc_data['snmp_security_profiles']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей безопасности SNMP.')
                return
        snmp_security_profiles = self.mc_data['snmp_security_profiles']

        for item in data:
            if not isinstance(item['auth_password'], str):
                item['auth_password'] = ''
            if not isinstance(item['private_password'], str):
                item['private_password'] = ''

            if item['name'] in snmp_security_profiles:
                if template_id == snmp_security_profiles[item['name']].template_id:
                    self.stepChanged.emit(f'uGRAY|    Профиль безопасности SNMP "{item["name"]}" уже существует в текущем шаблоне.')
                else:
                    self.stepChanged.emit(f'sGREEN|    Профиль безопасности SNMP "{item["name"]}" уже существует в шаблоне "{snmp_security_profiles[item["name"]].template_name}".')
            else:
                err, result = self.utm.add_template_snmp_security_profile(template_id, item)
                if err:
                    self.stepChanged.emit(f'RED|    {result}  [Профиль безопасности SNMP: "{item["name"]}" не импортирован]')
                    error = 1
                else:
                    snmp_security_profiles[item['name']] = BaseObject(id=result, template_id=template_id, template_name=template_name)
                    self.stepChanged.emit(f'BLACK|    Профиль безопасности SNMP "{item["name"]}" импортирован.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей безопасности SNMP.')
        else:
            self.stepChanged.emit('GREEN|    Импорт профилей безопасности SNMP завершён.')


    def import_snmp_settings(self, path, template_id, template_name):
        """Импортируем параметры SNMP"""
        json_file = os.path.join(path, 'config_snmp_params.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт параметров SNMP в раздел "Диагностика и мониторинг/Параметры SNMP".')
        error = 0
        for item in data:
            err, result = self.utm.add_template_snmp_parameters(template_id, item)
            if err == 1:
                self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте параметров SNMP.')
                error = 1
            elif err == 3:
                self.stepChanged.emit(f'GRAY|    {result}')
            else:
                self.stepChanged.emit('GREEN|    Параметры SNMP для "{item["name"]}" импортированы.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте параметров SNMP.')
        else:
            self.stepChanged.emit('GREEN|    Импорт параметров SNMP завершён.')


    def import_snmp_rules(self, path, template_id, template_name):
        """Импортируем список правил SNMP"""
        json_file = os.path.join(path, 'config_snmp_rules.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт списка правил SNMP в раздел "Диагностика и мониторинг/SNMP".')
        error = 0

        if not self.mc_data.get('snmp_security_profiles', False):
            if self.get_snmp_security_profiles():      # Устанавливаем self.mc_data['snmp_security_profiles']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил SNMP.')
                return
        snmp_security_profiles = self.mc_data['snmp_security_profiles']

        err, result = self.utm.get_template_snmp_rules(template_id)
        if err:
            self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте правил SNMP.')
            self.error = 1
            return
        snmp_rules = {x['name']: x['id'] for x in result}

        for item in data:
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя правила')
            if 'snmp_security_profile' in item:
                if item['snmp_security_profile']:
                    try:
                        item['snmp_security_profile'] = snmp_security_profiles[item['snmp_security_profile']].id
                    except KeyError as err:
                        self.stepChanged.emit(f'RED|    Error: [Правило "{item["name"]}"] Не найден профиль безопасности SNMP {err}. Возможно она отсутствует в этой группе шаблонов.')
                        item['description'] = f'{item["description"]}\nError: Не найден профиль безопасности SNMP {err}.'
                        item['snmp_security_profile'] = 0
                        item['enabled'] = False
                        error = 1
            else:
                item['snmp_security_profile'] = 0
#                item.pop('username', None)
#                item.pop('auth_type', None)
#                item.pop('auth_alg', None)
#                item.pop('auth_password', None)
#                item.pop('private_alg', None)
#                item.pop('private_password', None)

            if item['name'] in snmp_rules:
                self.stepChanged.emit(f'uGRAY|    Правило SNMP "{item["name"]}" уже существует в текущем шаблоне.')
            else:
                err, result = self.utm.add_template_snmp_rule(template_id, item)
                if err:
                    self.stepChanged.emit(f'RED|    {result}  [Правило SNMP "{item["name"]}" не импортировано]')
                    error = 1
                else:
                    snmp_rules[item['name']] = result
                    self.stepChanged.emit(f'BLACK|    Правило SNMP "{item["name"]}" импортировано.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил SNMP.')
        else:
            self.stepChanged.emit('GREEN|    Импорт правил SNMP завершён.')


    def pass_function(self, path, template_id, template_name):
        """Функция заглушка"""
        self.stepChanged.emit(f'GRAY|Импорт раздела "{path.rpartition("/")[2]}" в настоящее время не реализован.')

    ###################################### Служебные функции ############################################
    def get_ips_id(self, mode, rule_ips, rule):
        """
        Получить UID-ы списков IP-адресов. Если список IP-адресов не существует на MC, то он пропускается.
        mode - принимает значения: src | dst (для формирования сообщений)
        """
        new_rule_ips = []
        for ips in rule_ips:
            if ips[0] == 'geoip_code':
                new_rule_ips.append(ips)
            try:
                if ips[0] == 'list_id':
                    new_rule_ips.append(['list_id', self.mc_data['ip_lists'][ips[1]].id])
                elif ips[0] == 'urllist_id':
                    new_rule_ips.append(['urllist_id', self.mc_data['url_lists'][ips[1]].id])
            except KeyError as err:
                self.stepChanged.emit(f'RED|    Error: [Правило "{rule["name"]}"] Не найден список {mode}-адресов "{ips[1]}". Возможно он отсутствует в этой группе шаблонов.')
                rule['description'] = f'{rule["description"]}\nError: Не найден список {mode}-адресов "{ips[1]}".'
                rule['error'] = True
        return new_rule_ips


    def get_zones_id(self, mode, zones, rule):
        """
        Получить UID-ы зон. Если зона не существует на MC, то она пропускается.
        mode - принимает значения: src | dst (для формирования сообщений)
        """
        new_zones = []
        for zone in zones:
            try:
                new_zones.append(self.mc_data['zones'][zone].id)
            except KeyError as err:
                self.stepChanged.emit(f'RED|    Error: [Правило "{rule["name"]}"] Не найдена {mode}-зона "{zone}" в группе шаблонов. Возможно она отсутствует в этой группе шаблонов.')
                rule['description'] = f'{rule["description"]}\nError: Не найдена {mode}-зона "{zone}".'
                rule['error'] = True
        return new_zones


    def get_guids_users_and_groups(self, rule):
        """
        Получить GUID-ы групп и пользователей по их именам.
        Заменяет имена локальных и доменных пользователей и групп на GUID-ы.
        """
        new_users = []
        for item in rule['users']:
            item[1] = item[1].split(f' {chr(8212)} ')[0]    # Убираем длинное тире
            match item[0]:
                case 'special':
                    new_users.append(item)
                case 'user':
                    if not '\\' in item[1]:
                        user = item[1].split()[0]   # Убираем логин, оставляем имя.
                        try:
                            new_users.append(['user', self.mc_data['local_users'][user].id])
                        except KeyError as err:
                            self.stepChanged.emit(f'RED|    Error: [Правило "{rule["name"]}"] Не найден локальный пользователь {err}. Импортируйте локальных пользователей.')
                            rule['description'] = f'{rule["description"]}\nError: Не найден локальный пользователь {err}.'
                            rule['error'] = True
                    else:
                        user_name = None
                        user = item[1].split()[1].replace('(', '').replace(')', '')   # Убираем логин, оставляем имя и убираем скобки.
                        try:
                            ldap_domain, _, user_name = user.partition("\\")
                        except IndexError:
                            self.stepChanged.emit(f'ORANGE|    Warning: [Правило "{rule["name"]}"] Не указано имя пользователя в {item}.')
                        if user_name:
                            try:
                                ldap_id = self.mc_data['ldap_servers'][ldap_domain.lower()]
                            except KeyError:
                                self.stepChanged.emit(f'RED|    Error: [Правило "{rule["name"]}"] Нет LDAP-коннектора для домена "{ldap_domain}".')
                                rule['description'] = f'{rule["description"]}\nError: Нет LDAP-коннектора для домена "{ldap_domain}".'
                                rule['error'] = True
                            else:
                                err, result = self.utm.get_usercatalog_ldap_user_guid(ldap_id, user_name)
                                if err:
                                    self.stepChanged.emit(f'RED|    {result}  [Правило "{rule["name"]}"]')
                                    rule['description'] = f'{rule["description"]}\nError: Не удалось получить ID пользователя "{user_name}" - {result}.'
                                    rule['error'] = True
                                elif not result:
                                    self.stepChanged.emit(f'RED|    Error: [Правило "{rule["name"]}"] Нет пользователя "{user_name}" в домене "{ldap_domain}".')
                                    rule['description'] = f'{rule["description"]}\nError: Нет пользователя "{user_name}" в домене "{ldap_domain}".'
                                    rule['error'] = True
                                else:
                                    new_users.append(['user', result])
                case 'group':
                    if '=' not in item[1]:
                        try:
                            new_users.append(['group', self.mc_data['local_groups'][item[1]].id])
                        except KeyError as err:
                            self.stepChanged.emit(f'RED|    Error: [Правило "{rule["name"]}"] Не найдена группа пользователей {err}. Импортируйте группы пользователей.')
                            rule['description'] = f'{rule["description"]}\nError: Не найдена группа пользователей {err}.'
                            rule['error'] = True

                    else:
                        tmp_arr1 = [x.split('=') for x in item[1].split(',')]
                        tmp_arr2 = [b for a, b in tmp_arr1 if a in ('dc', 'DC')]
                        ldap_domain = '.'.join(tmp_arr2)
                        group_name = tmp_arr1[0][1] if tmp_arr1[0][0] == 'CN' else None
                        if group_name:
                            try:
                                ldap_id = self.mc_data['ldap_servers'][ldap_domain.lower()]
                            except KeyError:
                                self.stepChanged.emit(f'RED|    Error: [Правило "{rule["name"]}"] Нет LDAP-коннектора для домена "{ldap_domain}"')
                                rule['description'] = f'{rule["description"]}\nError: Нет LDAP-коннектора для домена "{ldap_domain}".'
                                rule['error'] = True
                            else:
                                err, result = self.utm.get_usercatalog_ldap_group_guid(ldap_id, group_name)
                                if err:
                                    self.stepChanged.emit(f'RED|    {result}  [Правило "{rule["name"]}"]')
                                    rule['description'] = f'{rule["description"]}\nError: Не удалось получить ID группы "{group_name}" - {result}.'
                                    rule['error'] = True
                                elif not result:
                                    self.stepChanged.emit(f'RED|    Error: [Правило "{rule["name"]}"] Нет группы "{group_name}" в домене "{ldap_domain}"!')
                                    rule['description'] = f'{rule["description"]}\nError: Нет группы "{group_name}" в домене "{ldap_domain}".'
                                    rule['error'] = True
                                else:
                                    new_users.append(['group', result])
        return new_users


    def get_services(self, service_list, rule):
        """Получаем ID сервисов по из именам. Если сервис не найден, то он пропускается."""
        new_service_list = []
        for item in service_list:
            try:
                if item[0] == 'service':
                    new_service_list.append(['service', self.mc_data['services'][item[1]].id])
                elif item[0] == 'list_id':
                    new_service_list.append(['list_id', self.mc_data['service_groups'][item[1]].id])
            except KeyError as err:
                self.stepChanged.emit(f'RED|    Error: [Правило "{rule["name"]}"] Не найден сервис или группа сервисов "{item[1]}" в группе шаблонов. Возможно он отсутствует в этой группе шаблонов.')
                rule['description'] = f'{rule["description"]}\nError: Не найден сервис "{item[1]}".'
                rule['error'] = True
        return new_service_list


    def get_url_categories_id(self, rule, referer=0):
        """Получаем ID категорий URL и групп категорий URL. Если список не существует на MC, то он пропускается."""
        new_categories = []
        rule_data = rule['referer_categories'] if referer else rule['url_categories']
        for item in rule_data:
            try:
                if item[0] == 'list_id':
                    if item[1] in self.convert_mc_url_categorygroups and self.utm.float_version >= 7.4:   # для совместимости с версией 7.4
                        item[1] = self.convert_mc_url_categorygroups[item[1]]
                    new_categories.append(['list_id', self.mc_data['url_categorygroups'][item[1]].id])
                elif item[0] == 'category_id':
                    new_categories.append(['category_id', self.mc_data['url_categories'][item[1]]])
            except KeyError as err:
                self.stepChanged.emit(f'RED|    Error: [Правило "{rule["name"]}"] Не найдена категория URL "{item[1]}" в группе шаблонов. Возможно она отсутствует в этой группе шаблонов.')
                rule['description'] = f'{rule["description"]}\nError: Не найдена категория URL "{item[1]}".'
                rule['error'] = True
        return new_categories


    def get_urls_id(self, urls, rule):
        """Получаем ID списков URL. Если список не существует на MC, то он пропускается."""
        new_urls = []
        for item in urls:
            try:
                new_urls.append(self.mc_data['url_lists'][item].id)
            except KeyError as err:
                self.stepChanged.emit(f'RED|    Error: [Правило "{rule["name"]}"] Не найден список URL "{item}" в группе шаблонов. Возможно он отсутствует в этой группе шаблонов.')
                rule['description'] = f'{rule["description"]}\nError: Не найден список URL "{item}".'
                rule['error'] = True
        return new_urls


    def get_apps(self, rule):
        """Определяем ID приложения или группы приложений по именам."""
        new_app_list = []
        for app in rule['apps']:
            if app[0] == 'ro_group':
                if app[1] == 'All':
                    new_app_list.append(['ro_group', 0])
                else:
                    try:
                        new_app_list.append(['ro_group', self.mc_data['l7_categories'][app[1]]])
                    except KeyError as err:
                        message = 'Возможно нет лицензии и MC не получил список категорий l7. Установите лицензию и повторите попытку.'
                        self.stepChanged.emit(f'RED|    Error: [Правило "{rule["name"]}"] Не найдена категория l7 "{app[1]}".\n    {message}')
                        rule['description'] = f'{rule["description"]}\nError: Не найдена категория l7 "{app[1]}".'
                        rule['error'] = True
            elif app[0] == 'group':
                try:
                    new_app_list.append(['group', self.mc_data['apps_groups'][app[1]].id])
                except KeyError as err:
                    self.stepChanged.emit(f'RED|    Error: [Правило "{rule["name"]}"] Не найдена группа приложений l7 "{app[1]}".')
                    rule['description'] = f'{rule["description"]}\nError: Не найдена группа приложений l7 "{app[1]}".'
                    rule['error'] = True
        return new_app_list


    def get_time_restrictions(self, rule):
        """Получаем ID календарей шаблона по их именам. Если календарь не найден в шаблоне, то он пропускается."""
        new_schedules = []
        for name in rule['time_restrictions']:
            try:
                new_schedules.append(self.mc_data['calendars'][name].id)
            except KeyError:
                self.stepChanged.emit(f'RED|    Error: [Правило "{rule["name"]}"] Не найден календарь "{name}" в группе шаблонов.')
                rule['description'] = f'{rule["description"]}\nError: Не найден календарь "{name}".'
                rule['error'] = True
        return new_schedules

    def get_network_devices(self, rule):
        """Получаем ID устройств NGFW по их именам. Если устройство не найдено в области, то оно пропускается."""
        devices_list = []
        if 'cc_network_devices' in rule:
            for name in rule['cc_network_devices']:
                try:
                    devices_list.append(self.mc_data['devices_list'][name])
                except KeyError:
                    self.stepChanged.emit(f'RED|    Error: [Правило "{rule["name"]}"] Не найдено устройство "{name}" в области.')
                    rule['description'] = f'{rule["description"]}\nError: Не найдено устройство "{name}".'
                    rule['error'] = True
        return devices_list

    #-------------------------- Заполнение self.mc_data ------------------------------------------------------
    def get_morphology_list(self):
        """Получаем список морфологии группы шаблонов и устанавливаем значение self.mc_data['morphology']"""
        self.mc_data['morphology'] = {}
        for name, uid in self.group_templates[self.selected_group].items():
            err, result = self.utm.get_template_nlists_list(uid, 'morphology')
            if err:
                self.stepChanged.emit(f'RED|    {result}')
                self.error = 1
                return 1
            for x in result:
                if x['name'] in self.mc_data['morphology']:
                    self.stepChanged.emit(f'ORANGE|    Список морфологии "{x["name"]}" обнаружен в нескольких шаблонах группы. Список из шаблона "{name}" не будет использован.')
                else:
                    self.mc_data['morphology'][x['name']] = BaseObject(id=x['id'], template_id=uid, template_name=name)
        return 0


    def get_useragents_list(self):
        """Получаем список UserAgents группы шаблонов и устанавливаем значение self.mc_data['useragents']"""
        self.mc_data['useragents'] = {}
        for name, uid in self.group_templates[self.selected_group].items():
            err, result = self.utm.get_template_nlists_list(uid, 'useragent')
            if err:
                self.stepChanged.emit(f'RED|    {result}')
                self.error = 1
                return 1
            for x in result:
                if x['name'] in self.mc_data['useragents']:
                    self.stepChanged.emit(f'ORANGE|    Список UserAgents "{x["name"]}" обнаружен в нескольких шаблонах группы. Список из шаблона "{name}" не будет использован.')
                else:
                    self.mc_data['useragents'][x['name']] = BaseObject(id=x['id'], template_id=uid, template_name=name)
        return 0


    def get_app_signatures(self):
        """Получаем список предустановленных приложений l7 и устанавливаем значение self.mc_data['l7_apps']"""
        self.mc_data['l7_apps'] = {}
        err, result = self.utm.get_realm_l7_signatures()
        if err:
            self.stepChanged.emit(f'RED|    {result}')
            self.error = 1
            return 1
        for x in result:
            self.mc_data['l7_apps'][x['name']] = BaseAppObject(id=x['id'], owner=x['attributes']['owner'], signature_id=x['signature_id'])
        return 0


    def get_l7_profiles(self):
        """Получаем список профилей приложений группы шаблонов и устанавливаем значение self.mc_data['l7_profiles']"""
        self.mc_data['l7_profiles'] = {}
        for name, uid in self.group_templates[self.selected_group].items():
            err, result = self.utm.get_template_l7_profiles_list(uid)
            if err:
                self.stepChanged.emit(f'RED|    {result}')
                self.error = 1
                return 1
            for x in result:
                if x['name'] in self.mc_data['l7_profiles']:
                    self.stepChanged.emit(f'ORANGE|    Профиль приложений "{x["name"]}" обнаружен в нескольких шаблонах группы. Профиль из шаблона "{name}" не будет использован.')
                else:
                    self.mc_data['l7_profiles'][x['name']] = BaseObject(id=x['id'], template_id=uid, template_name=name)
        return 0


    def get_email_groups(self):
        """Получаем список групп почтовых адресов группы шаблонов и устанавливаем значение self.mc_data['email_groups']"""
        self.mc_data['email_groups'] = {}
        for name, uid in self.group_templates[self.selected_group].items():
            err, result = self.utm.get_template_nlists_list(uid, 'emailgroup')
            if err:
                self.stepChanged.emit(f'RED|    {result}')
                self.error = 1
                return 1
            for x in result:
                if x['name'] in self.mc_data['email_groups']:
                    self.stepChanged.emit(f'ORANGE|    Группа почтовых адресов "{x["name"]}" обнаружена в нескольких шаблонах группы. Группа из шаблона "{name}" не будет использована.')
                else:
                    self.mc_data['email_groups'][x['name']] = BaseObject(id=x['id'], template_id=uid, template_name=name)
        return 0


    def get_phone_groups(self):
        """Получаем список групп телефонных номеров группы шаблонов и устанавливаем значение self.mc_data['phone_groups']"""
        self.mc_data['phone_groups'] = {}
        for name, uid in self.group_templates[self.selected_group].items():
            err, result = self.utm.get_template_nlists_list(uid, 'phonegroup')
            if err:
                self.stepChanged.emit(f'RED|    {result}')
                self.error = 1
                return 1
            for x in result:
                if x['name'] in self.mc_data['phone_groups']:
                    self.stepChanged.emit(f'ORANGE|    Группа телефонных номеров "{x["name"]}" обнаружена в нескольких шаблонах группы. Группа из шаблона "{name}" не будет использована.')
                else:
                    self.mc_data['phone_groups'][x['name']] = BaseObject(id=x['id'], template_id=uid, template_name=name)
        return 0


    def get_idps_realm_users_signatures(self):
        """Получаем список пользовательских сигнатур СОВ всех шаблонов и устанавливаем значение self.mc_data['users_signatures']"""
        self.mc_data['realm_users_signatures'] = {}
        err, result = self.utm.get_realm_idps_signatures(query={'query': 'owner = You'})
        if err:
            self.stepChanged.emit(f'RED|    {result}')
            self.error = 1
            return 1
        for x in result:
            self.mc_data['realm_users_signatures'][x['msg']] = BaseObject(id=x['id'], template_id=x['template_id'], template_name=self.realm_templates[x['template_id']])
        return 0


    def get_idps_profiles(self):
        """Получаем список профилей СОВ группы шаблонов и устанавливаем значение self.mc_data['idps_profiles']"""
        self.mc_data['idps_profiles'] = {}
        for name, uid in self.group_templates[self.selected_group].items():
            err, result = self.utm.get_template_idps_profiles_list(uid)
            if err:
                self.stepChanged.emit(f'RED|    {result}')
                self.error = 1
                return 1
            for x in result:
                if x['name'] in self.mc_data['idps_profiles']:
                    self.stepChanged.emit(f'ORANGE|    Профиль СОВ "{x["name"]}" обнаружен в нескольких шаблонах группы. Профиль из шаблона "{name}" не будет использован.')
                else:
                    self.mc_data['idps_profiles'][x['name']] = BaseObject(id=x['id'], template_id=uid, template_name=name)
        return 0


    def get_notification_profiles(self):
        """Получаем список профилей оповещения группы шаблонов и устанавливаем значение атрибута self.mc_data['notification_profiles']"""
        self.mc_data['notification_profiles'] = {-5: BaseObject(id=-5, template_id='', template_name='')}
        for name, uid in self.group_templates[self.selected_group].items():
            err, result = self.utm.get_template_notification_profiles(uid)
            if err:
                self.stepChanged.emit(f'RED|    {result}')
                self.error = 1
                return 1
            for x in result:
                if x['name'] in self.mc_data['notification_profiles']:
                    self.stepChanged.emit(f'ORANGE|    Профиль оповещения "{x["name"]}" обнаружен в нескольких шаблонах группы. Профиль из шаблона "{name}" не будет использован.')
                else:
                    self.mc_data['notification_profiles'][x['name']] = BaseObject(id=x['id'], template_id=uid, template_name=name)
        return 0


    def get_netflow_profiles(self):
        """Получаем список профилей netflow группы шаблонов и устанавливаем значение self.mc_data['netflow_profiles']"""
        self.mc_data['netflow_profiles'] = {'undefined': BaseObject(id='undefined', template_id='', template_name='')}
        for name, uid in self.group_templates[self.selected_group].items():
            err, result = self.utm.get_template_netflow_profiles(uid)
            if err:
                self.stepChanged.emit(f'RED|    {result}')
                self.error = 1
                return 1
            for x in result:
                if x['name'] in self.mc_data['netflow_profiles']:
                    self.stepChanged.emit(f'ORANGE|    Профиль netflow "{x["name"]}" обнаружен в нескольких шаблонах группы. Профиль из шаблона "{name}" не будет использован.')
                else:
                    self.mc_data['netflow_profiles'][x['name']] = BaseObject(id=x['id'], template_id=uid, template_name=name)
        return 0


    def get_lldp_profiles(self):
        """Получаем список профилей lldp группы шаблонов и устанавливаем значение self.mc_data['lldp_profiles']"""
        self.mc_data['lldp_profiles'] = {'undefined': BaseObject(id='undefined', template_id='', template_name='')}
        for name, uid in self.group_templates[self.selected_group].items():
            err, result = self.utm.get_template_lldp_profiles(uid)
            if err:
                self.stepChanged.emit(f'RED|    {result}')
                self.error = 1
                return 1
            for x in result:
                if x['name'] in self.mc_data['lldp_profiles']:
                    self.stepChanged.emit(f'ORANGE|    Профиль lldp "{x["name"]}" обнаружен в нескольких шаблонах группы. Профиль из шаблона "{name}" не будет использован.')
                else:
                    self.mc_data['lldp_profiles'][x['name']] = BaseObject(id=x['id'], template_id=uid, template_name=name)
        return 0


    def get_ssl_forward_profiles(self):
        """Получаем список профилей пересылки SSL группы шаблонов и устанавливаем значение self.mc_data['ssl_forward_profiles']"""
        self.mc_data['ssl_forward_profiles'] = {-1: BaseObject(id=-1, template_id='', template_name='')}
        for name, uid in self.group_templates[self.selected_group].items():
            err, result = self.utm.get_template_ssl_forward_profiles(uid)
            if err:
                self.stepChanged.emit(f'RED|    {result}')
                self.error = 1
                return 1
            for x in result:
                if x['name'] in self.mc_data['ssl_forward_profiles']:
                    self.stepChanged.emit(f'ORANGE|    Профиль пересылки SSL "{x["name"]}" обнаружен в нескольких шаблонах группы. Профиль из шаблона "{name}" не будет использован.')
                else:
                    self.mc_data['ssl_forward_profiles'][x['name']] = BaseObject(id=x['id'], template_id=uid, template_name=name)
        return 0


    def get_hip_objects(self):
        """Получаем список HIP объектов группы шаблонов и устанавливаем значение self.mc_data['hip_objects']"""
        self.mc_data['hip_objects'] = {}
        for name, uid in self.group_templates[self.selected_group].items():
            err, result = self.utm.get_template_hip_objects(uid)
            if err:
                self.stepChanged.emit(f'RED|    {result}')
                self.error = 1
                return 1
            for x in result:
                if x['name'] in self.mc_data['hip_objects']:
                    self.stepChanged.emit(f'ORANGE|    HIP объект "{x["name"]}" обнаружен в нескольких шаблонах группы. HIP объект из шаблона "{name}" не будет использован.')
                else:
                    self.mc_data['hip_objects'][x['name']] = BaseObject(id=x['id'], template_id=uid, template_name=name)
        return 0


    def get_hip_profiles(self):
        """Получаем список HIP профилей группы шаблонов и устанавливаем значение self.mc_data['hip_profiles']"""
        self.mc_data['hip_profiles'] = {}
        for name, uid in self.group_templates[self.selected_group].items():
            err, result = self.utm.get_template_hip_profiles(uid)
            if err:
                self.stepChanged.emit(f'RED|    {result}')
                self.error = 1
                return 1
            for x in result:
                if x['name'] in self.mc_data['hip_profiles']:
                    self.stepChanged.emit(f'ORANGE|    HIP профиль "{x["name"]}" обнаружен в нескольких шаблонах группы. HIP профиль из шаблона "{name}" не будет использован.')
                else:
                    self.mc_data['hip_profiles'][x['name']] = BaseObject(id=x['id'], template_id=uid, template_name=name)
        return 0


    def get_bfd_profiles(self):
        """Получаем список BFD профилей группы шаблонов и устанавливаем значение self.mc_data['bfd_profiles']"""
        self.mc_data['bfd_profiles'] = {}
        for name, uid in self.group_templates[self.selected_group].items():
            err, result = self.utm.get_template_bfd_profiles(uid)
            if err:
                self.stepChanged.emit(f'RED|    {result}')
                self.error = 1
                return 1
            for x in result:
                if x['name'] in self.mc_data['bfd_profiles']:
                    self.stepChanged.emit(f'ORANGE|    BFD профиль "{x["name"]}" обнаружен в нескольких шаблонах группы. BFD профиль из шаблона "{name}" не будет использован.')
                else:
                    self.mc_data['bfd_profiles'][x['name']] = BaseObject(id=x['id'], template_id=uid, template_name=name)
        return 0


    def get_useridagent_filters(self):
        """Получаем Syslog фильтры агента UserID группы шаблонов и устанавливаем значение self.mc_data['userid_filters']"""
        self.mc_data['userid_filters'] = {}
        for name, uid in self.group_templates[self.selected_group].items():
            err, result = self.utm.get_template_useridagent_filters(uid)
            if err:
                self.stepChanged.emit(f'RED|    {result}')
                self.error = 1
                return 1
            for x in result:
                if x['name'] in self.mc_data['userid_filters']:
                    self.stepChanged.emit(f'ORANGE|    Syslog фильтр агента UserID "{x["name"]}" обнаружен в нескольких шаблонах группы. Фильтр из шаблона "{name}" не будет использован.')
                else:
                    self.mc_data['userid_filters'][x['name']] = BaseObject(id=x['id'], template_id=uid, template_name=name)
        return 0


    def get_interfaces_list(self):
        """Получаем список всех интерфейсов в группе шаблонов и устанавливаем значение self.mc_data['interfaces']"""
        self.mc_data['interfaces'] = {}
        for name, uid in self.group_templates[self.selected_group].items():
            err, result = self.utm.get_template_interfaces_list(uid)
            if err:
                self.stepChanged.emit(f'RED|    {result}')
                self.error = 1
                return 1
            for x in result:
                if x['kind'] not in ('bridge', 'bond', 'adapter', 'vlan', 'tunnel', 'vpn') or x['master']:
                    continue
                iface_name = f'{x["name"]}:{x["node_name"]}'
                if iface_name in self.mc_data['interfaces'] and x['kind'] in ('vlan', 'tunnel'):
                    self.stepChanged.emit(f'ORANGE|    Интерфейс "{x["name"]}" для узла кластера "{x["node_name"]}" обнаружен в нескольких шаблонах группы. Интерфейс из шаблона "{name}" не будет использован.')
                else:
                    self.mc_data['interfaces'][iface_name] = BaseObject(id=x['id'], template_id=uid, template_name=name)
        return 0


    def get_gateways_list(self):
        """Получаем список всех шлюзов в группе шаблонов и устанавливаем значение self.mc_data['gateways']"""
        self.mc_data['gateways'] = {}
        for name, uid in self.group_templates[self.selected_group].items():
            err, result = self.utm.get_template_gateways(uid)
            if err:
                self.stepChanged.emit(f'RED|    {result}')
                self.error = 1
                return 1
            for x in result:
                xname = x.get("name", x["ipv4"])
                gateway_name = f'{xname}:{x["node_name"]}'
                if gateway_name in self.mc_data['gateways']:
                    self.stepChanged.emit(f'ORANGE|    Шлюз "{xname}" для узла кластера "{x["node_name"]}" обнаружен в нескольких шаблонах группы. Шлюз из шаблона "{name}" не будет использован.')
                else:
                    self.mc_data['gateways'][gateway_name] = BaseObject(id=x['id'], template_id=uid, template_name=name)
        return 0


    def get_vrf_list(self):
        """Получаем список всех VRF в группе шаблонов и устанавливаем значение self.mc_data['vrf']"""
        self.mc_data['vrf'] = {}
        for name, uid in self.group_templates[self.selected_group].items():
            err, result = self.utm.get_template_vrf_list(uid)
            if err:
                self.stepChanged.emit(f'RED|    {result}')
                self.error = 1
                return 1
            for x in result:
                vrf_name = f'{x["name"]}:{x["node_name"]}'
                if vrf_name in self.mc_data['vrf']:
                    self.stepChanged.emit(f'ORANGE|    VRF "{x["name"]}" для узла кластера "{x["node_name"]}" обнаружен в нескольких шаблонах группы. VRF из шаблона "{name}" не будет использован.')
                else:
                    self.mc_data['vrf'][vrf_name] = BaseObject(id=x['id'], template_id=uid, template_name=name)
        return 0


    def get_client_certificate_profiles(self):
        """
        Получаем список профилей клиентских сертификатов в группе шаблонов и устанавливаем значение self.mc_data['client_cert_profiles']"""
        self.mc_data['client_certs_profiles'] = {}
        for name, uid in self.group_templates[self.selected_group].items():
            err, result = self.utm.get_template_client_certificate_profiles(uid)
            if err:
                self.stepChanged.emit(f'RED|    {result}')
                self.error = 1
                return 1
            for x in result:
                if x['name'] in self.mc_data['client_certs_profiles']:
                    self.stepChanged.emit(f'ORANGE|    Профиль клиентского сертификата "{x["name"]}" обнаружен в нескольких шаблонах группы. Профиль из шаблона "{name}" не будет использован.')
                else:
                    self.mc_data['client_certs_profiles'][x['name']] = BaseObject(id=x['id'], template_id=uid, template_name=name)
        return 0


    def get_auth_servers(self):
        """Получаем список всех серверов аутентификации в группе шаблонов и устанавливаем значение self.mc_data['auth_servers']"""
        auth_servers = {'ldap': {}, 'ntlm': {}, 'radius': {}, 'tacacs_plus': {}, 'saml_idp': {}}
        for name, uid in self.group_templates[self.selected_group].items():
            err, result = self.utm.get_template_auth_servers(uid)
            if err == 1:
                self.stepChanged.emit(f'RED|    {result}')
                self.error = 1
                return 1
            for x in result:
                if x['name'] in auth_servers[x['type']]:
                    self.stepChanged.emit(f'ORANGE|    Сервер аутентификации "{x["name"]}" обнаружен в нескольких шаблонах группы шаблонов. Сервер из шаблона "{name}" не будет использован.')
                else:
                    auth_servers[x['type']][x['name']] = BaseObject(id=x['id'], template_id=uid, template_name=name)
        self.mc_data['auth_servers'] = auth_servers
        return 0


    def get_profiles_2fa(self):
        """Получаем список профилей MFA в группе шаблонов и устанавливаем значение self.mc_data['profiles_2fa']"""
        self.mc_data['profiles_2fa'] = {}
        for name, uid in self.group_templates[self.selected_group].items():
            err, result = self.utm.get_template_2fa_profiles(uid)
            if err:
                self.stepChanged.emit(f'RED|    {result}')
                self.error = 1
                return 1
            for x in result:
                if x['name'] in self.mc_data['profiles_2fa']:
                    self.stepChanged.emit(f'ORANGE|    Профиль MFA "{x["name"]}" обнаружен в нескольких шаблонах группы шаблонов. Профиль из шаблона "{name}" не будет использован.')
                else:
                    self.mc_data['profiles_2fa'][x['name']] = BaseObject(id=x['id'], template_id=uid, template_name=name)
        return 0


    def get_captive_profiles(self):
        """Получаем список Captive-профилей в группе шаблонов и устанавливаем значение self.mc_data['captive_profiles']"""
        self.mc_data['captive_profiles'] = {}
        for name, uid in self.group_templates[self.selected_group].items():
            err, result = self.utm.get_template_captive_profiles(uid)
            if err:
                self.stepChanged.emit(f'RED|    {result}')
                self.error = 1
                return 1
            for x in result:
                if x['name'] in self.mc_data['captive_profiles']:
                    self.stepChanged.emit(f'ORANGE|    Captive-профиль "{x["name"]}" обнаружен в нескольких шаблонах группы шаблонов. Профиль из шаблона "{name}" не будет использован.')
                else:
                    self.mc_data['captive_profiles'][x['name']] = BaseObject(id=x['id'], template_id=uid, template_name=name)
        return 0


    def get_icap_servers(self):
        """Получаем список серверов ICAP в группе шаблонов и устанавливаем значение self.mc_data['icap_servers']"""
        self.mc_data['icap_servers'] = {}
        for name, uid in self.group_templates[self.selected_group].items():
            err, result = self.utm.get_template_icap_servers(uid)
            if err:
                self.stepChanged.emit(f'RED|    {result}')
                self.error = 1
                return 1
            for x in result:
                if x['name'] in self.mc_data['icap_servers']:
                    self.stepChanged.emit(f'ORANGE|    Сервер ICAP "{x["name"]}" обнаружен в нескольких шаблонах группы. Сервер из шаблона "{name}" не будет использован.')
                else:
                    self.mc_data['icap_servers'][x['name']] = BaseObject(id=x['id'], template_id=uid, template_name=name)
        return 0


    def get_reverseproxy_servers(self):
        """Получаем список серверов reverse-proxy в группе шаблонов и устанавливаем значение self.mc_data['reverseproxy_servers']"""
        self.mc_data['reverseproxy_servers'] = {}
        for name, uid in self.group_templates[self.selected_group].items():
            err, result = self.utm.get_template_reverseproxy_servers(uid)
            if err:
                self.stepChanged.emit(f'RED|    {result}')
                self.error = 1
                return 1
            for x in result:
                if x['name'] in self.mc_data['reverseproxy_servers']:
                    self.stepChanged.emit(f'ORANGE|    Сервер Reverse-прокси "{x["name"]}" обнаружен в нескольких шаблонах группы. Сервер из шаблона "{name}" не будет использован.')
                else:
                    self.mc_data['reverseproxy_servers'][x['name']] = BaseObject(id=x['id'], template_id=uid, template_name=name)
        return 0


    def get_dos_profiles(self):
        """Получаем список профилей DoS в группе шаблонов и устанавливаем значение self.mc_data['dos_profiles']"""
        self.mc_data['dos_profiles'] = {}
        for name, uid in self.group_templates[self.selected_group].items():
            err, result = self.utm.get_template_dos_profiles(uid)
            if err:
                self.stepChanged.emit(f'RED|    {result}')
                self.error = 1
                return 1
            for x in result:
                if x['name'] in self.mc_data['dos_profiles']:
                    self.stepChanged.emit(f'ORANGE|    Профиль DoS "{x["name"]}" обнаружен в нескольких шаблонах группы шаблонов. Профиль DoS из шаблона "{name}" не будет использован.')
                else:
                    self.mc_data['dos_profiles'][x['name']] = BaseObject(id=x['id'], template_id=uid, template_name=name)
        return 0


    def get_upstream_proxies_servers(self):
        """Получаем сервера вышестоящих прокси в группе шаблонов и устанавливаем значение self.mc_data['upstreamproxies_servers']"""
        self.mc_data['upstreamproxies_servers'] = {}
        if self.utm.float_version < 7.4:
            return 0

        for name, uid in self.group_templates[self.selected_group].items():
            err, result = self.utm.get_template_cascade_proxy_servers(uid)
            if err:
                self.stepChanged.emit(f'RED|    {result}')
                self.error = 1
                return 1
            for x in result:
                if x['name'] in self.mc_data['upstreamproxies_servers']:
                    self.stepChanged.emit(f'ORANGE|    Сервер вышестоящих прокси "{x["name"]}" обнаружен в нескольких шаблонах группы шаблонов. Сервер из шаблона "{name}" не будет использован.')
                else:
                    self.mc_data['upstreamproxies_servers'][x['name']] = BaseObject(id=x['id'], template_id=uid, template_name=name)
        return 0


    def get_upstream_proxies_profiles(self):
        """Получаем профили вышестоящих прокси в группе шаблонов и устанавливаем значение self.mc_data['upstreamproxies_profiles']"""
        self.mc_data['upstreamproxies_profiles'] = {}
        if self.utm.float_version < 7.4:
            return 0

        for name, uid in self.group_templates[self.selected_group].items():
            err, result = self.utm.get_template_cascade_proxy_profiles(uid)
            if err:
                self.stepChanged.emit(f'RED|    {result}')
                self.error = 1
                return 1
            for x in result:
                if x['name'] in self.mc_data['upstreamproxies_profiles']:
                    self.stepChanged.emit(f'ORANGE|    Профиль вышестоящих прокси "{x["name"]}" обнаружен в нескольких шаблонах группы шаблонов. Профиль из шаблона "{name}" не будет использован.')
                else:
                    self.mc_data['upstreamproxies_profiles'][x['name']] = BaseObject(id=x['id'], template_id=uid, template_name=name)
        return 0


    def get_vpn_client_security_profiles(self):
        """Получаем клиентские профили безопасности VPN в группе шаблонов и устанавливаем значение self.mc_data['vpn_client_security_profiles']"""
        self.mc_data['vpn_client_security_profiles'] = {}
        for name, uid in self.group_templates[self.selected_group].items():
            err, result = self.utm.get_template_vpn_client_security_profiles(uid)
            if err:
                self.stepChanged.emit(f'RED|    {result}')
                self.error = 1
                return 1
            for x in result:
                if x['name'] in self.mc_data['vpn_client_security_profiles']:
                    self.stepChanged.emit(f'ORANGE|    Клиентский профиль безопасности VPN "{x["name"]}" обнаружен в нескольких шаблонах группы шаблонов. Профиль из шаблона "{name}" не будет использован.')
                else:
                    self.mc_data['vpn_client_security_profiles'][x['name']] = BaseObject(id=x['id'], template_id=uid, template_name=name)
        return 0


    def get_vpn_server_security_profiles(self):
        """Получаем серверные профили безопасности VPN в группе шаблонов и устанавливаем значение self.mc_data['vpn_server_security_profiles']"""
        self.mc_data['vpn_server_security_profiles'] = {}
        for name, uid in self.group_templates[self.selected_group].items():
            err, result = self.utm.get_template_vpn_server_security_profiles(uid)
            if err:
                self.stepChanged.emit(f'RED|    {result}')
                self.error = 1
                return 1
            for x in result:
                if x['name'] in self.mc_data['vpn_server_security_profiles']:
                    self.stepChanged.emit(f'ORANGE|    Серверный профиль безопасности VPN "{x["name"]}" обнаружен в нескольких шаблонах группы шаблонов. Профиль из шаблона "{name}" не будет использован.')
                else:
                    self.mc_data['vpn_server_security_profiles'][x['name']] = BaseObject(id=x['id'], template_id=uid, template_name=name)
        return 0


    def get_vpn_networks(self):
        """Получаем сети VPN в группе шаблонов и устанавливаем значение self.mc_data['vpn_networks']"""
        self.mc_data['vpn_networks'] = {False: BaseObject(id=False, template_id='', template_name='')}
        for name, uid in self.group_templates[self.selected_group].items():
            err, result = self.utm.get_template_vpn_networks(uid)
            if err:
                self.stepChanged.emit(f'RED|    {result}')
                self.error = 1
                return 1
            for x in result:
                if x['name'] in self.mc_data['vpn_networks']:
                    self.stepChanged.emit(f'ORANGE|    Сеть VPN "{x["name"]}" обнаружена в нескольких шаблонах группы шаблонов. Сеть VPN из шаблона "{name}" не будет использована.')
                else:
                    self.mc_data['vpn_networks'][x['name']] = BaseObject(id=x['id'], template_id=uid, template_name=name)
        return 0


    def get_snmp_security_profiles(self):
        """Получаем профили безопасности SNMP в группе шаблонов и устанавливаем значение self.mc_data['snmp_security_profiles']"""
        self.mc_data['snmp_security_profiles'] = {}
        for name, uid in self.group_templates[self.selected_group].items():
            err, result = self.utm.get_template_snmp_security_profiles(uid)
            if err:
                self.stepChanged.emit(f'RED|    {result}')
                self.error = 1
                return 1
            for x in result:
                if x['name'] in self.mc_data['snmp_security_profiles']:
                    self.stepChanged.emit(f'ORANGE|    Профиль безопасности SNMP "{x["name"]}" обнаружен в нескольких шаблонах группы шаблонов. Профиль из шаблона "{name}" не будет использован.')
                else:
                    self.mc_data['snmp_security_profiles'][x['name']] = BaseObject(id=x['id'], template_id=uid, template_name=name)
        return 0

#----------------------------------------------------------------------------------------------------------------------------------
    def add_empty_vrf(self, vrf_name, ports, node_name, template_id):
        """Добавляем пустой VRF"""
        vrf = {
            'name': vrf_name,
            'description': '',
            'node_name': node_name,
            'interfaces': ports if vrf_name != 'default' else [],
            'routes': [],
            'ospf': {},
            'bgp': {},
            'rip': {},
            'pimsm': {}
        }
        err, result = self.utm.add_template_vrf(template_id, vrf)
        if err:
            return err, result
        return 0, result    # Возвращаем ID добавленного VRF


    def add_new_nlist(self, name, nlist_type, content):
        """Добавляем в библиотеку новый nlist с содержимым"""
        nlist = {
            'name': name,
            'description': '',
            'type': nlist_type,
            'list_type_update': 'static',
            'schedule': 'disabled',
            'attributes': {'threat_level': 3},
        }
        err, list_id = self.utm.add_template_nlist(self.template_id, nlist)
        if err:
            return err, list_id
        err, result = self.utm.add_template_nlist_items(self.template_id, list_id, content)
        if err:
            return err, result
        return 0, list_id


    def get_library_data(self):
        """Получаем часто используемые данные из библиотек всех шаблонов группы шаблонов"""
        # Добавляем в список шаблонов предустановленный шаблон 'UserGate Libraries template'.
        templates = list(self.group_templates[self.selected_group].items())
        templates.append(self.usergate_lib_template)
        error = 0

        self.stepChanged.emit('BLUE|Заполняем служебные структуры данных.')

        # Получаем список зон группы шаблонов и устанавливаем значение self.mc_data['zones']
        self.mc_data['zones'] = {}
        for name, uid in templates:
            err, result = self.utm.get_template_zones_list(uid)
            if err:
                self.stepChanged.emit(f'RED|    {result}')
                error = 1
                break
            for x in result:
                if x['name'] in self.mc_data['zones']:
                    self.stepChanged.emit(f'ORANGE|    Зона "{x["name"]}" обнаружен в нескольких шаблонах группы. Зона из шаблона "{name}" не будет использована.')
                else:
                    self.mc_data['zones'][x['name']] = BaseObject(id=x['id'], template_id=uid, template_name=name)

        # Получаем список сервисов группы шаблонов и устанавливаем значение self.mc_data['services']
        self.mc_data['services'] = {}
        for name, uid in templates:
            err, result = self.utm.get_template_services_list(uid)
            if err:
                self.stepChanged.emit(f'RED|    {result}')
                error = 1
                break
            for x in result:
                if x['name'] in self.mc_data['services']:
                    self.stepChanged.emit(f'ORANGE|    Сервис "{x["name"]}" обнаружен в нескольких шаблонах группы. Сервис из шаблона "{name}" не будет использован.')
                else:
                    self.mc_data['services'][x['name']] = BaseObject(id=x['id'], template_id=uid, template_name=name)

        # Получаем список календарей группы шаблонов и устанавливаем значение self.mc_data['calendars']
        self.mc_data['calendars'] = {}
        for name, uid in templates:
            err, result = self.utm.get_template_nlists_list(uid, 'timerestrictiongroup')
            if err:
                self.stepChanged.emit(f'RED|    {result}')
                error = 1
                break
            for x in result:
                if x['name'] in self.mc_data['calendars']:
                    self.stepChanged.emit(f'ORANGE|    Календарь "{x["name"]}" обнаружен в нескольких шаблонах группы. Календарь из шаблона "{name}" не будет использован.')
                else:
                    self.mc_data['calendars'][x['name']] = BaseObject(id=x['id'], template_id=uid, template_name=name)

        # Получаем список групп категорий URL группы шаблонов и устанавливаем значение self.mc_data['url_categorygroups']
        self.mc_data['url_categorygroups'] = {}
        for name, uid in templates:
            err, result = self.utm.get_template_nlists_list(uid, 'urlcategorygroup')
            if err:
                self.stepChanged.emit(f'RED|    {result}')
                error = 1
                break
            for x in result:
                if x['name'] in self.mc_data['url_categorygroups']:
                    self.stepChanged.emit(f'ORANGE|    Категория URL "{x["name"]}" обнаружена в нескольких шаблонах группы. Категория из шаблона "{name}" не будет использована.')
                else:
                    self.mc_data['url_categorygroups'][x['name']] = BaseObject(id=x['id'], template_id=uid, template_name=name)

        # Получаем список профилей SSL группы шаблонов и устанавливаем значение self.mc_data['ssl_profiles']
        self.mc_data['ssl_profiles'] = {-1: BaseObject(id=-1, template_id='', template_name='')}
        for name, uid in templates:
            err, result = self.utm.get_template_ssl_profiles(uid)
            if err:
                self.stepChanged.emit(f'RED|    {result}')
                error = 1
                break
            for x in result:
                if x['name'] in self.mc_data['ssl_profiles']:
                    self.stepChanged.emit(f'ORANGE|    Профиль SSL "{x["name"]}" обнаружен в нескольких шаблонах группы. Профиль из шаблона "{name}" не будет использован.')
                else:
                    self.mc_data['ssl_profiles'][x['name']] = BaseObject(id=x['id'], template_id=uid, template_name=name)

        # Получаем список шаблонов страниц группы шаблонов и устанавливаем значение self.mc_data['response_pages']
        self.mc_data['response_pages'] = {-1: BaseObject(id=-1, template_id='', template_name='')}
        for name, uid in templates:
            err, result = self.utm.get_template_responsepages_list(uid)
            if err:
                self.stepChanged.emit(f'RED|    {result}')
                error = 1
                break
            for x in result:
                if x['name'] in self.mc_data['response_pages']:
                    self.stepChanged.emit(f'ORANGE|    Шаблон страницы "{x["name"]}" обнаружен в нескольких шаблонах группы. Шаблон из шаблона "{name}" не будет использован.')
                else:
                    self.mc_data['response_pages'][x['name']] = BaseObject(id=x['id'], template_id=uid, template_name=name)

        # Получаем полосы пропускания группы шаблонов и устанавливаем значение self.mc_data['shapers']
        self.mc_data['shapers'] = {}
        for name, uid in templates:
            err, result = self.utm.get_template_shapers_list(uid)
            if err:
                self.stepChanged.emit(f'RED|    {result}')
                error = 1
                break
            for x in result:
                if x['name'] in self.mc_data['shapers']:
                    self.stepChanged.emit(f'ORANGE|    Полоса пропускания "{x["name"]}" обнаружена в нескольких шаблонах группы. Полоса из шаблона "{name}" не будет использована.')
                else:
                    self.mc_data['shapers'][x['name']] = BaseObject(id=x['id'], template_id=uid, template_name=name)

        # Получаем список групп сервисов группы шаблонов и устанавливаем значение self.mc_data['service_groups']
        self.mc_data['service_groups'] = {}
        for name, uid in self.group_templates[self.selected_group].items():
            err, result = self.utm.get_template_nlists_list(uid, 'servicegroup')
            if err:
                self.stepChanged.emit(f'RED|    {result}')
                error = 1
                break
            for x in result:
                if x['name'] in self.mc_data['service_groups']:
                    self.stepChanged.emit(f'ORANGE|    Группа сервисов "{x["name"]}" обнаружена в нескольких шаблонах группы. Группа сервисов из шаблона "{name}" не будет использована.')
                else:
                    self.mc_data['service_groups'][x['name']] = BaseObject(id=x['id'], template_id=uid, template_name=name)

        # Получаем список IP-листов группы шаблонов и устанавливаем значение self.mc_data['ip_lists']
        for name, uid in self.group_templates[self.selected_group].items():
            err, result = self.utm.get_template_nlists_list(uid, 'network')
            if err:
                self.stepChanged.emit(f'RED|    {result}')
                error = 1
                break
            for x in result:
                if x['name'] in self.mc_data['ip_lists']:
                    self.stepChanged.emit(f'ORANGE|    IP-лист "{x["name"]}" обнаружен в нескольких шаблонах группы. IP-лист из шаблона "{name}" не будет использован.')
                else:
                    self.mc_data['ip_lists'][x['name']] = BaseObject(id=x['id'], template_id=uid, template_name=name)

        # Получаем список типов контента группы шаблонов и устанавливаем значение self.mc_data['mime']
        for name, uid in self.group_templates[self.selected_group].items():
            err, result = self.utm.get_template_nlists_list(uid, 'mime')
            if err:
                self.stepChanged.emit(f'RED|    {result}')
                error = 1
                break
            for x in result:
                if x['name'] in self.mc_data['mime']:
                    self.stepChanged.emit(f'ORANGE|    Список типов контента "{x["name"]}" обнаружен в нескольких шаблонах группы. Список из шаблона "{name}" не будет использован.')
                else:
                    self.mc_data['mime'][x['name']] = BaseObject(id=x['id'], template_id=uid, template_name=name)

        # Получаем список URL-листов группы шаблонов и устанавливаем значение self.mc_data['url_lists']
        for name, uid in self.group_templates[self.selected_group].items():
            err, result = self.utm.get_template_nlists_list(uid, 'url')
            if err:
                self.stepChanged.emit(f'RED|    {result}')
                error = 1
                break
            for x in result:
                if x['name'] in self.mc_data['url_lists']:
                    self.stepChanged.emit(f'ORANGE|    Список URL "{x["name"]}" обнаружен в нескольких шаблонах группы. Список из шаблона "{name}" не будет использован.')
                else:
                    self.mc_data['url_lists'][x['name']] = BaseObject(id=x['id'], template_id=uid, template_name=name)

        # Получаем список групп приложений группы шаблонов и устанавливаем значение self.mc_data['apps_groups']
        self.mc_data['apps_groups'] = {}
        for name, uid in self.group_templates[self.selected_group].items():
            err, result = self.utm.get_template_nlists_list(uid, 'applicationgroup')
            if err:
                self.stepChanged.emit(f'RED|    {result}')
                error = 1
                break
            for x in result:
                if x['name'] in self.mc_data['apps_groups']:
                    self.stepChanged.emit(f'ORANGE|    Группа приложений "{x["name"]}" обнаружена в нескольких шаблонах группы. Группа из шаблона "{name}" не будет использована.')
                else:
                    self.mc_data['apps_groups'][x['name']] = BaseObject(id=x['id'], template_id=uid, template_name=name)

        # Получаем список сценариев группы шаблонов и устанавливаем значение self.mc_data['scenarios']
        self.mc_data['scenarios'] = {}
        for name, uid in self.group_templates[self.selected_group].items():
            err, result = self.utm.get_template_scenarios_rules(uid)
            if err:
                self.stepChanged.emit(f'RED|    {result}')
                error = 1
                break
            for x in result:
                if x['name'] in self.mc_data['scenarios']:
                    self.stepChanged.emit(f'ORANGE|    Сценарий "{x["name"]}" обнаружен в нескольких шаблонах группы. Сценарий из шаблона "{name}" не будет использован.')
                else:
                    self.mc_data['scenarios'][x['name']] = BaseObject(id=x['id'], template_id=uid, template_name=name)

        # Получаем список сертификатов группы шаблонов NGFW и устанавливаем значение self.mc_data['certs']
        self.mc_data['certs'] = {-1: BaseObject(id=-1, template_id='', template_name='')}
        self.mc_data['cert_roles'] = set()
        for name, uid in self.group_templates[self.selected_group].items():
            err, result = self.utm.get_template_certificates_list(uid)
            if err:
                self.stepChanged.emit(f'RED|    {result}')
                error = 1
                break
            for x in result:
                if x['name'] in self.mc_data['certs']:
                    self.stepChanged.emit(f'ORANGE|    Сертификат "{x["name"]}" обнаружен в нескольких шаблонах группы. Сертификат из шаблона "{name}" не будет использован.')
                else:
                    self.mc_data['certs'][x['name']] = BaseObject(id=x['id'], template_id=uid, template_name=name)
                    self.mc_data['cert_roles'].add(x['role'])

        # Получаем список профилей аутентификации группы шаблонов и устанавливаем значение self.mc_data['auth_profiles']
        self.mc_data['auth_profiles'] = {
            -1: BaseObject(id=-1, template_id='', template_name=''),
            False: BaseObject(id=False, template_id='', template_name=''),
        }
        for name, uid in self.group_templates[self.selected_group].items():
            err, result = self.utm.get_template_auth_profiles(uid)
            if err:
                self.stepChanged.emit(f'RED|    {result}')
                error = 1
                break
            for x in result:
                if x['name'] in self.mc_data['auth_profiles']:
                    self.stepChanged.emit(f'ORANGE|    Профиль аутентификации "{x["name"]}" обнаружен в нескольких шаблонах группы. Профиль из шаблона "{name}" не будет использован.')
                else:
                    self.mc_data['auth_profiles'][x['name']] = BaseObject(id=x['id'], template_id=uid, template_name=name)

        # Получаем список локальных групп пользователей группы шаблонов и устанавливаем значение self.mc_data['local_groups']
        self.mc_data['local_groups'] = {}
        for name, uid in self.group_templates[self.selected_group].items():
            err, result = self.utm.get_template_groups_list(uid)
            if err:
                self.stepChanged.emit(f'RED|    {result}')
                error = 1
                break
            for x in result:
                if x['name'] in self.mc_data['local_groups']:
                    self.stepChanged.emit(f'ORANGE|    Группа пользователей "{x["name"]}" обнаружена в нескольких шаблонах группы. Группа из шаблона "{name}" не будет использована.')
                else:
                    self.mc_data['local_groups'][x['name']] = BaseObject(id=x['id'], template_id=uid, template_name=name)

        # Получаем список локальных пользователей группы шаблонов и устанавливаем значение self.mc_data['local_users']
        self.mc_data['local_users'] = {}
        for name, uid in self.group_templates[self.selected_group].items():
            err, result = self.utm.get_template_users_list(uid)
            if err:
                self.stepChanged.emit(f'RED|    {result}')
                error = 1
                break
            for x in result:
                if x['name'] in self.mc_data['local_users']:
                    self.stepChanged.emit(f'ORANGE|    Пользователь "{x["name"]}" обнаружен в нескольких шаблонах группы. Пользователь из шаблона "{name}" не будет использован.')
                else:
                    self.mc_data['local_users'][x['name']] = BaseObject(id=x['id'], template_id=uid, template_name=name)

        # Получаем список предопределённых категорий URL и устанавливаем значение self.mc_data['url_categories']
        self.mc_data['url_categories'] = {}
        err, result = self.utm.get_url_categories()
        if err:
            self.stepChanged.emit(f'RED|    {result}')
            error = 1
        self.mc_data['url_categories'] = {x['name']: x['id'] for x in result}

        # Получаем список предопределённых категорий приложений l7 и устанавливаем значение self.mc_data['l7_categories']
        self.mc_data['l7_categories'] = {}
        err, result = self.utm.get_l7_categories()
        if err:
            self.stepChanged.emit(f'RED|    {result}')
            error = 1
        self.mc_data['l7_categories'] = {x['name']: x['id'] for x in result}

        # Получаем список устройств NGFW области и устанавливаем значение self.mc_data['devices_list']
        self.mc_data['devices_list'] = {}
        err, result = self.utm.get_devices_list()
        if err:
            self.stepChanged.emit(f'RED|    {result}')
            error = 1
        self.mc_data['devices_list'] = {x['name']: x['id'] for x in result}

        if error:
            self.stepChanged.emit('iRED|Произошла ошибка инициализации импорта. Устраните ошибки и повторите импорт.')
        else:
            self.stepChanged.emit('GREEN|    Служебные структуры данных заполнены.')


class Zone:
    def __init__(self, parent, zone):
        self.parent = parent
        self.name = zone['name']
        self.description = zone['description']
        self.services_access = zone['services_access']
        self.enable_antispoof = zone['enable_antispoof']
        self.antispoof_invert = zone['antispoof_invert']
        self.networks = zone['networks']
        self.sessions_limit_enabled = zone['sessions_limit_enabled']
        self.sessions_limit_exclusions = zone['sessions_limit_exclusions']
        self.service_ids = {
            'Ping': 'ffffff03-ffff-ffff-ffff-ffffff000001',
            'SNMP': 'ffffff03-ffff-ffff-ffff-ffffff000002',
            'Captive-портал и страница блокировки': 'ffffff03-ffff-ffff-ffff-ffffff000004',
            'XML-RPC для управления': 'ffffff03-ffff-ffff-ffff-ffffff000005',
            'Кластер': 'ffffff03-ffff-ffff-ffff-ffffff000006',
            'VRRP': 'ffffff03-ffff-ffff-ffff-ffffff000007',
            'Консоль администрирования': 'ffffff03-ffff-ffff-ffff-ffffff000008',
            'DNS': 'ffffff03-ffff-ffff-ffff-ffffff000009',
            'HTTP(S)-прокси': 'ffffff03-ffff-ffff-ffff-ffffff000010',
            'Агент аутентификации': 'ffffff03-ffff-ffff-ffff-ffffff000011',
            'SMTP(S)-прокси': 'ffffff03-ffff-ffff-ffff-ffffff000012',
            'POP(S)-прокси': 'ffffff03-ffff-ffff-ffff-ffffff000013',
            'CLI по SSH': 'ffffff03-ffff-ffff-ffff-ffffff000014',
            'VPN': 'ffffff03-ffff-ffff-ffff-ffffff000015',
#           'SCADA': 'ffffff03-ffff-ffff-ffff-ffffff000017',
            'Reverse-прокси': 'ffffff03-ffff-ffff-ffff-ffffff000018',
            'Веб-портал': 'ffffff03-ffff-ffff-ffff-ffffff000019',
            'SAML сервер': 'ffffff03-ffff-ffff-ffff-ffffff000022',
            'Log analyzer': 'ffffff03-ffff-ffff-ffff-ffffff000023',
            'Log analyzer/SIEM': 'ffffff03-ffff-ffff-ffff-ffffff000023',
            'OSPF': 'ffffff03-ffff-ffff-ffff-ffffff000024',
            'BGP': 'ffffff03-ffff-ffff-ffff-ffffff000025',
            'RIP': 'ffffff03-ffff-ffff-ffff-ffffff000030',
            'SNMP-прокси': 'ffffff03-ffff-ffff-ffff-ffffff000026',
            'SSH-прокси': 'ffffff03-ffff-ffff-ffff-ffffff000027',
            'Multicast': 'ffffff03-ffff-ffff-ffff-ffffff000028',
            'NTP сервис': 'ffffff03-ffff-ffff-ffff-ffffff000029',
            'UserID syslog collector': 'ffffff03-ffff-ffff-ffff-ffffff000031',
            'BFD': 'ffffff03-ffff-ffff-ffff-ffffff000032',
            'Endpoints connect': 'ffffff03-ffff-ffff-ffff-ffffff000033',
            'API XML RPC поверх HTTPS': 'ffffff03-ffff-ffff-ffff-ffffff000034'
        }
        self.error = 0
        self.check_services_access()
        self.check_networks()
        self.check_sessions_limit()


    def check_services_access(self):
        """Обрабатываем сервисы из контроля доступа"""
        new_services_access = []
        for service in self.services_access:
            if service['enabled']:
                # Проверяем что такой сервис существует в этой версии МС и получаем его ID.
                service_name = service['service_id']
                if service_name == 'API XML RPC поверх HTTPS' and self.parent.utm.float_version < 7.4:
                    continue
                try:
                    service['service_id'] = self.service_ids[service_name]
                except KeyError as err:
                    self.parent.stepChanged.emit(f'RED|    Error [Зона "{self.name}"]. Не корректный сервис "{service_name}" в контроле доступа. Сервис не импортирован.')
                    self.description = f'{self.description}\nError: Не импортирован сервис "{service_name}" в контроль доступа.'
                    self.error = 1
                    continue
                # Приводим список разрешённых адресов сервиса к спискам IP-листов.
                if service['allowed_ips']:
                    if isinstance(service['allowed_ips'][0], list):
                        allowed_ips = []
                        for item in service['allowed_ips']:
                            if item[0] == 'list_id':
                                try:
                                    item[1] = self.parent.mc_data['ip_lists'][item[1]].id
                                except KeyError as err:
                                    self.parent.stepChanged.emit(f'RED|    Error [Зона "{self.name}"]. В контроле доступа "{service_name}" не найден список IP-адресов {err}.')
                                    self.description = f'{self.description}\nError: В контроле доступа "{service_name}" не найден список IP-адресов {err}.'
                                    self.error = 1
                                    continue
                            allowed_ips.append(item)
                        service['allowed_ips'] = allowed_ips
                    else:
                        nlist_name = f'Zone {self.name} (service access: {service_name})'
                        if nlist_name in self.parent.mc_data['ip_lists']:
                            service['allowed_ips'] = [['list_id', self.parent.mc_data['ip_lists'][nlist_name].id]]
                        else:
                            content = [{'value': ip} for ip in service['allowed_ips']]
                            err, list_id = add_new_nlist(self.parent, nlist_name, 'network', content)
                            if err == 1:
                                self.parent.stepChanged.emit(f'RED|    {list_id}')
                                self.parent.stepChanged.emit(f'RED|       Error [Зона "{self.name}"]. Не создан список IP-адресов в контроле доступа "{service_name}".')
                                self.description = f'{self.description}\nError: В контроле доступа "{service_name}" не создан список IP-адресов.'
                                self.error = 1
                                continue
                            elif err == 3:
                                self.parent.stepChanged.emit(f'ORANGE|    Warning: Список IP-адресов "{nlist_name}" контроля доступа сервиса "{service_name}" зоны "{self.name}" уже существует.')
                                self.parent.stepChanged.emit('bRED|       Перезапустите конвертер и повторите попытку.')
                                continue
                            else:
                                self.parent.stepChanged.emit(f'BLACK|       Создан список IP-адресов "{nlist_name}" контроля доступа сервиса "{service_name}" для зоны "{self.name}".')
                                service['allowed_ips'] = [['list_id', list_id]]
                                self.parent.mc_data['ip_lists'][nlist_name] = BaseObject(id=list_id, template_id=self.parent.template_id, template_name=self.parent.templates[self.parent.template_id])

                new_services_access.append(service)
        self.services_access = new_services_access


    def check_networks(self):
        """Обрабатываем защиту от IP-спуфинга"""
        if self.networks:
            if isinstance(self.networks[0], list):
                new_networks = []
                for item in self.networks:
                    if item[0] == 'list_id':
                        try:
                            item[1] = self.parent.mc_data['ip_lists'][item[1]].id
                        except KeyError as err:
                            self.parent.stepChanged.emit(f'RED|    Error [Зона "{self.name}"]. В разделе "Защита от IP-спуфинга" не найден список IP-адресов {err}.')
                            self.description = f'{self.description}\nError: В разделе "Защита от IP-спуфинга" не найден список IP-адресов {err}.'
                            self.error = 1
                            continue
                    new_networks.append(item)
                self.networks = new_networks
            else:
                nlist_name = f'Zone {self.name} (IP-spufing)'
                if nlist_name in self.parent.mc_data['ip_lists']:
                    self.networks = [['list_id', self.parent.mc_data['ip_lists'][nlist_name].id]]
                else:
                    content = [{'value': ip} for ip in self.networks]
                    err, list_id = add_new_nlist(self.parent, nlist_name, 'network', content)
                    if err == 1:
                        self.parent.stepChanged.emit(f'RED|    {list_id}')
                        self.parent.stepChanged.emit(f'RED|       Error [Зона "{self.name}"]. Не создан список IP-адресов в защите от IP-спуфинга.')
                        self.description = f'{self.description}\nError: В разделе "Защита от IP-спуфинга" не создан список IP-адресов.'
                        self.networks = []
                        self.error = 1
                    elif err == 3:
                        self.parent.stepChanged.emit(f'ORANGE|    Warning: Список IP-адресов "{nlist_name}" в защите от IP-спуфинга зоны "{self.name}" уже существует.')
                        self.parent.stepChanged.emit('bRED|       Перезапустите конвертер и повторите попытку.')
                    else:
                        self.parent.stepChanged.emit(f'BLACK|       Создан список IP-адресов "{nlist_name}" в защите от IP-спуфинга для зоны "{self.name}".')
                        self.networks = [['list_id', list_id]]
                        self.parent.mc_data['ip_lists'][nlist_name] = BaseObject(id=list_id, template_id=self.parent.template_id, template_name=self.parent.templates[self.parent.template_id])
        if not self.networks:
            self.enable_antispoof = False
            self.antispoof_invert = False


    def check_sessions_limit(self):
        """Обрабатываем ограничение сессий"""
        new_sessions_limit_exclusions = []
        for item in self.sessions_limit_exclusions:
            try:
                item[1] = self.parent.mc_data['ip_lists'][item[1]].id
                new_sessions_limit_exclusions.append(item)
            except KeyError as err:
                self.parent.stepChanged.emit(f'RED|    Error [Зона "{self.name}"]. В разделе "Ограничение сессий" не найден список IP-адресов {err}.')
                self.description = f'{self.description}\nError: В разделе "Ограничение сессий" не найден список IP-адресов {err}.'
                self.error = 1
        self.sessions_limit_exclusions = new_sessions_limit_exclusions
        if not self.sessions_limit_exclusions:
            self.sessions_limit_enabled = False


