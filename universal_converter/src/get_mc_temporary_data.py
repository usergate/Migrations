#!/usr/bin/python3
#
# Copyright @ 2020-2022 UserGate Corporation. All rights reserved.
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
# get_mc_temporary_data.py
# Version 1.3  10.12.2024
#--------------------------------------------------------------------------------------------------- 
#
import os, sys, json
from dataclasses import dataclass
from PyQt6.QtCore import QThread, pyqtSignal
from services import default_urlcategorygroup
from common_func import write_bin_file


@dataclass(kw_only=True, slots=True, frozen=True)
class BaseObject:
    id: str|int
    template_id: str
    template_name: str


#@dataclass(kw_only=True, slots=True, frozen=True)
#class BaseAppObject:
#    id: str
#    owner: str
#    signature_id: str


class GetExportTemporaryData(QThread):
    """Получаем конфигурационные данные с MC для заполнения служебных структур данных для экспорта."""
    stepChanged = pyqtSignal(str)
    def __init__(self, utm, template_id):
        super().__init__()
        self.utm = utm
        self.template_id = template_id
        self.mc_data = {
            'ldap_servers': {},
            'ug_morphology': (
                'MORPH_CAT_BADWORDS', 'MORPH_CAT_DLP_ACCOUNTING',
                'MORPH_CAT_DLP_FINANCE', 'MORPH_CAT_DLP_LEGAL', 'MORPH_CAT_DLP_MARKETING', 'MORPH_CAT_DLP_PERSONAL',
                'MORPH_CAT_DRUGSWORDS', 'MORPH_CAT_FZ_436', 'MORPH_CAT_GAMBLING', 'MORPH_CAT_KAZAKHSTAN',
                'MORPH_CAT_MINJUSTWORDS', 'MORPH_CAT_PORNOWORDS', 'MORPH_CAT_SUICIDEWORDS', 'MORPH_CAT_TERRORWORDS'
            ),
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
        self.ug_iplists = ('BOTNET_BLACK_LIST', 'BANKS_IP_LIST', 'ZAPRET_INFO_BLACK_LIST_IP')
        self.ug_url_lists = ('ENTENSYS_WHITE_LIST', 'BAD_SEARCH_BLACK_LIST', 'ENTENSYS_BLACK_LIST',
            'ENTENSYS_KAZ_BLACK_LIST', 'FISHING_BLACK_LIST', 'ZAPRET_INFO_BLACK_LIST', 'ZAPRET_INFO_BLACK_LIST_DOMAIN')
        self.ug_mime = ('MIME_CAT_APPLICATIONS', 'MIME_CAT_DOCUMENTS', 'MIME_CAT_IMAGES',
            'MIME_CAT_JAVASCRIPT', 'MIME_CAT_SOUNDS', 'MIME_CAT_VIDEO')
        self.error = 0

    def run(self):
        """Заполняем служебные структуры данных"""
        self.stepChanged.emit(f'BLUE|Заполняем служебные структуры данных.')

        # Получаем список всех активных LDAP-серверов области
        self.stepChanged.emit(f'BLACK|    Получаем список активных LDAP-серверов в каталогах пользователей области.')
        self.mc_data['ldap_servers'] = {}
        err, result = self.utm.get_usercatalog_ldap_servers()
        if err:
            self.stepChanged.emit(f'RED|       {result}')
            self.stepChanged.emit(f'iRED|Произошла ошибка инициализации экспорта! Устраните ошибки и повторите экспорт.')
            return
        elif result:
            err, result2 = self.utm.get_usercatalog_servers_status()
            if err:
                self.stepChanged.emit(f'RED|       {result2}')
                self.error = 1
            else:
                servers_status = {x['id']: x['status'] for x in result2}
                for srv in result:
                    if servers_status[srv['id']] == 'connected':
                        for domain in srv['domains']:
                            self.mc_data['ldap_servers'][srv['id']] = domain.lower()
                        self.stepChanged.emit(f'GREEN|       LDAP-коннектор "{srv["name"]}" - статус: "connected".')
                    else:
                        self.stepChanged.emit(f'GRAY|       LDAP-коннектор "{srv["name"]}" имеет не корректный статус: "{servers_status[srv["id"]]}".')
        if not self.mc_data['ldap_servers']:
            self.stepChanged.emit('NOTE|       Нет доступных LDAP-серверов в каталогах пользователей области. Доменные пользователи не будут импортированы.')

        # Получаем список зон
        self.stepChanged.emit(f'BLACK|    Получаем список зон.')
        err, result = self.utm.get_realm_zones_list()
        if err:
            self.stepChanged.emit(f'RED|    {result}')
            self.error = 1
        self.mc_data['zones'] = {x['id']: x['name'] for x in result}

        # Получаем список сервисов
        self.stepChanged.emit(f'BLACK|    Получаем список сервисов.')
        err, result = self.utm.get_realm_services_list()
        if err:
            self.stepChanged.emit(f'RED|    {result}')
            self.error = 1
        self.mc_data['services'] = {x['id']: x['name'] for x in result}

        # Получаем список групп сервисов
        self.stepChanged.emit(f'BLACK|    Получаем список групп сервисов.')
        err, result = self.utm.get_realm_nlists_list('servicegroup')
        if err:
            self.stepChanged.emit(f'RED|    {result}')
            self.error = 1
        self.mc_data['service_groups'] = {x['id']: x['name'] for x in result}

        # Получаем список типов контента
        self.stepChanged.emit(f'BLACK|    Получаем список типов контента.')
        err, result = self.utm.get_realm_nlists_list('mime')
        if err:
            self.stepChanged.emit(f'RED|    {result}')
            self.error = 1
        self.mc_data['mime'] = {x['id']: x['name'].strip() for x in result}
        for item in self.ug_mime:
            self.mc_data['mime'][f'id-{item}'] = item

        # Получаем список IP-листов
        self.stepChanged.emit(f'BLACK|    Получаем список IP-листов.')
        err, result = self.utm.get_realm_nlists_list('network')
        if err:
            self.stepChanged.emit(f'RED|    {result}')
            self.error = 1
        self.mc_data['ip_lists'] = {x['id']: x['name'] for x in result}
        for item in self.ug_iplists:
            self.mc_data['ip_lists'][f'id-{item}'] = item

        # Получаем список URL-листов
        self.stepChanged.emit(f'BLACK|    Получаем список URL-листов.')
        err, result = self.utm.get_realm_nlists_list('url')
        if err:
            self.stepChanged.emit(f'RED|    {result}')
            self.error = 1
        self.mc_data['url_lists'] = {x['id']: x['name'] for x in result}
        for item in self.ug_url_lists:
            self.mc_data['url_lists'][f'id-{item}'] = item

        # Получаем список календарей
        self.stepChanged.emit(f'BLACK|    Получаем список календарей.')
        err, result = self.utm.get_realm_nlists_list('timerestrictiongroup')
        if err:
            self.stepChanged.emit(f'iRED|{result}')
            self.error = 1
        self.mc_data['calendars'] = {x['id']: x['name'] for x in result}

        # Получаем список групп категорий URL
        self.stepChanged.emit(f'BLACK|    Получаем список групп категорий URL.')
        err, result = self.utm.get_realm_nlists_list('urlcategorygroup')
        if err:
            self.stepChanged.emit(f'RED|    {result}')
            self.error = 1
        self.mc_data['url_categorygroups'] = {x['id']: default_urlcategorygroup.get(x['name'], x['name']) for x in result}

        # Получаем список категорий URL
        self.stepChanged.emit(f'BLACK|    Получаем список категорий URL.')
        err, result = self.utm.get_url_categories()
        if err:
            self.stepChanged.emit(f'RED|    {result}')
            self.error = 1
        self.mc_data['url_categories'] = {x['id']: x['name'] for x in result}

        # Получаем список профилей SSL области
        self.stepChanged.emit(f'BLACK|    Получаем список профилей SSL области.')
        err, result = self.utm.get_realm_ssl_profiles_list()
        if err:
            self.stepChanged.emit(f'RED|    {result}')
            self.error = 1
        self.mc_data['ssl_profiles'] = {x['id']: x['name'] for x in result}

        # Получаем список сценариев шаблона
        self.stepChanged.emit(f'BLACK|    Получаем список сценариев.')
        err, result = self.utm.get_template_scenarios_rules(self.template_id)
        if err:
            self.stepChanged.emit(f'RED|    {result}')
            self.error = 1
        self.mc_data['scenarios'] = {x['id']: x['name'] for x in result}

        # Получаем список сертификатов
        self.stepChanged.emit(f'BLACK|    Получаем список сертификатов области')
        err, result = self.utm.get_realm_certificates_list()
        if err:
            self.stepChanged.emit(f'iRED|{result}')
            return
        self.mc_data['certs'] = {x['id']: x['name'] for x in result}

        # Получаем список профилей аутентификации
        self.stepChanged.emit(f'BLACK|    Получаем список профилей аутентификации')
        err, result = self.utm.get_realm_auth_profiles()
        if err:
            self.stepChanged.emit(f'iRED|{result}')
            return
        self.mc_data['auth_profiles'] = {x['id']: x['name'] for x in result}

        # Получаем список локальных групп
        self.stepChanged.emit(f'BLACK|    Получаем список локальных групп')
        err, result = self.utm.get_template_groups_list(self.template_id)
        if err:
            self.stepChanged.emit(f'iRED|{result}')
            return
        self.mc_data['local_groups'] = {x['id']: x['name'] for x in result}

        # Получаем список локальных пользователей
        self.stepChanged.emit(f'BLACK|    Получаем список локальных пользователей')
        err, result = self.utm.get_template_users_list(self.template_id)
        if err:
            self.stepChanged.emit(f'iRED|{result}')
            return
        self.mc_data['local_users'] = {x['id']: x['name'] for x in result}

        # Получаем список групп приложений
        self.stepChanged.emit(f'BLACK|    Получаем список групп приложений.')
        err, result = self.utm.get_template_nlists_list(self.template_id, 'applicationgroup')
        if err:
            self.stepChanged.emit(f'RED|    {result}')
            self.error = 1
        self.mc_data['application_groups'] = {x['id']: x['name'] for x in result}

        # Получаем список категорий приложений l7
        self.stepChanged.emit(f'BLACK|    Получаем список категорий приложений.')
        err, result = self.utm.get_l7_categories()
        if err:
            self.stepChanged.emit(f'RED|    {result}')
            self.error = 1
        self.mc_data['l7_categories'] = {x['id']: x['name'] for x in result}


        if self.error:
            self.stepChanged.emit(f'iRED|Произошла ошибка инициализации экспорта! Устраните ошибки и повторите экспорт.')
        else:
            if write_bin_file(self, self.mc_data):
                self.stepChanged.emit(f'iRED|Произошла ошибка инициализации экспорта! Не удалось сохранить служебные структуры данных.')
            else:
                self.stepChanged.emit(f'GREEN|Служебные структуры данных заполнены.')

class GetImportTemporaryData(QThread):
    """Получаем конфигурационные данные с MC для заполнения служебных структур данных."""
    stepChanged = pyqtSignal(str)
    def __init__(self, utm, template_id, templates):
        super().__init__()
        self.utm = utm
        self.template_id = template_id
        self.templates = templates    # структура {template_id: template_name}
        self.mc_data = {
            'ldap_servers': {},     # LDAP-сервера в каталогах пользователей области
            'morphology': {},
            'services': {},
            'service_groups': {},
            'ip_lists': {
                'BOTNET_BLACK_LIST': BaseObject(id='id-BOTNET_BLACK_LIST', template_id='', template_name=''),
                'BANKS_IP_LIST': BaseObject(id='id-BANKS_IP_LIST', template_id='', template_name=''),
                'ZAPRET_INFO_BLACK_LIST_IP': BaseObject(id='id-ZAPRET_INFO_BLACK_LIST_IP', template_id='', template_name=''),
            },
            'useragents': {},
            'mime': {},
            'url_lists': {},
            'calendars': {},
            'shapers': {},
            'response_pages': {},
            'url_categorygroups': {},
            'l7_apps': {},
            'l7_profiles': {},
            'apps_groups': {},
            'email_groups': {},
            'phone_groups': {},
            'idps_profiles': {},
            'notification_profiles': {},
            'netflow_profiles': {},
            'lldp_profiles': {},
            'ssl_profiles': {},
            'ssl_forward_profiles': {},
            'hip_objects': {},
            'hip_profiles': {},
            'bfd_profiles': {},
            'userid_filters': {},
            'scenarios': {},
            'zones': {},
            'gateways': {},
            'interfaces': {},
            'vrf': {},
            'certs': {},
            'client_certs_profiles': {},
            'auth_profiles': {},
            'local_groups': {},
            'local_users': {},
            'auth_servers': {},
            'profiles_2fa': {},
            'captive_profiles': {},
            'icap_servers': {},
            'reverseproxy_servers': {},
            'dos_profiles': {},
            'waf_profiles': {},
            'vpn_client_security_profiles': {},
            'vpn_server_security_profiles': {},
            'vpn_networks': {},
            'snmp_security_profiles': {},
            'url_categories': {},
            'l7_categories': {},
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
        self.ug_url_lists = ('ENTENSYS_WHITE_LIST', 'BAD_SEARCH_BLACK_LIST', 'ENTENSYS_BLACK_LIST',
            'ENTENSYS_KAZ_BLACK_LIST', 'FISHING_BLACK_LIST', 'ZAPRET_INFO_BLACK_LIST', 'ZAPRET_INFO_BLACK_LIST_DOMAIN')
        self.ug_mime = ('MIME_CAT_APPLICATIONS', 'MIME_CAT_DOCUMENTS', 'MIME_CAT_IMAGES',
            'MIME_CAT_JAVASCRIPT', 'MIME_CAT_SOUNDS', 'MIME_CAT_VIDEO')
        self.error = 0

    def run(self):
        """Заполняем служебные структуры данных"""
        self.stepChanged.emit(f'BLUE|Заполняем служебные структуры данных.')

        # Получаем список всех активных LDAP-серверов области
        self.stepChanged.emit(f'BLACK|    Получаем список активных LDAP-серверов в каталогах пользователей области.')
        self.mc_data['ldap_servers'] = {}
        err, result = self.utm.get_usercatalog_ldap_servers()
        if err:
            self.stepChanged.emit(f'RED|       {result}')
            self.stepChanged.emit(f'iRED|Произошла ошибка инициализации импорта! Устраните ошибки и повторите импорт.')
            return
        elif result:
            err, result2 = self.utm.get_usercatalog_servers_status()
            if err:
                self.stepChanged.emit(f'RED|       {result2}')
                self.error = 1
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

        # Получаем список зон
        self.stepChanged.emit(f'BLACK|    Получаем список зон группы шаблонов.')
        for uid, name in self.templates.items():
            err, result = self.utm.get_template_zones_list(uid)
            if err:
                self.stepChanged.emit(f'RED|    {result}')
                self.error = 1
                break
            for x in result:
                if x['name'] in self.mc_data['zones']:
                    self.stepChanged.emit(f'ORANGE|       Зона "{x["name"]}" обнаружена в нескольких шаблонах группы. Зона из шаблона "{name}" не будет использована.')
                else:
                    self.mc_data['zones'][x['name']] = BaseObject(id=x['id'], template_id=uid, template_name=name)

        # Получаем список сервисов
        self.stepChanged.emit(f'BLACK|    Получаем список сервисов группы шаблонов.')
        for uid, name in self.templates.items():
            err, result = self.utm.get_template_services_list(uid)
            if err:
                self.stepChanged.emit(f'RED|    {result}')
                self.error = 1
                break
            for x in result:
                if x['name'] in self.mc_data['services']:
                    self.stepChanged.emit(f'ORANGE|       Сервис "{x["name"]}" обнаружен в нескольких шаблонах группы. Сервис из шаблона "{name}" не будет использован.')
                else:
                    self.mc_data['services'][x['name']] = BaseObject(id=x['id'], template_id=uid, template_name=name)

        # Получаем список групп сервисов
        self.stepChanged.emit(f'BLACK|    Получаем список групп сервисов группы шаблонов.')
        for uid, name in self.templates.items():
            err, result = self.utm.get_template_nlists_list(uid, 'servicegroup')
            if err:
                self.stepChanged.emit(f'RED|    {result}')
                self.error = 1
                break
            for x in result:
                if x['name'] in self.mc_data['service_groups']:
                    self.stepChanged.emit(f'ORANGE|       Группа сервисов "{x["name"]}" обнаружена в нескольких шаблонах группы. Группа сервисов из шаблона "{name}" не будет использована.')
                else:
                    self.mc_data['service_groups'][x['name']] = BaseObject(id=x['id'], template_id=uid, template_name=name)

        # Получаем список IP-листов
        self.stepChanged.emit(f'BLACK|    Получаем список IP-листов группы шаблонов.')
        for uid, name in self.templates.items():
            err, result = self.utm.get_template_nlists_list(uid, 'network')
            if err:
                self.stepChanged.emit(f'RED|    {result}')
                self.error = 1
                break
            for x in result:
                if x['name'] in self.mc_data['ip_lists']:
                    self.stepChanged.emit(f'ORANGE|       IP-лист "{x["name"]}" обнаружен в нескольких шаблонах группы. IP-лист из шаблона "{name}" не будет использован.')
                else:
                    self.mc_data['ip_lists'][x['name']] = BaseObject(id=x['id'], template_id=uid, template_name=name)

        # Получаем список типов контента
        self.stepChanged.emit(f'BLACK|    Получаем список типов контента.')
        for uid, name in self.templates.items():
            err, result = self.utm.get_template_nlists_list(uid, 'mime')
            if err:
                self.stepChanged.emit(f'RED|    {result}')
                self.error = 1
                break
            for x in result:
                if x['name'] in self.mc_data['mime']:
                    self.stepChanged.emit(f'ORANGE|       Список типов контента "{x["name"]}" обнаружен в нескольких шаблонах группы. Список из шаблона "{name}" не будет использован.')
                else:
                    self.mc_data['mime'][x['name']] = BaseObject(id=x['id'], template_id=uid, template_name=name)
        for item in self.ug_mime:
            self.mc_data['mime'][item] = BaseObject(id=f'id-{item}', template_id='', template_name='')

        # Получаем список URL-листов
        self.stepChanged.emit(f'BLACK|    Получаем список URL-листов.')
        for uid, name in self.templates.items():
            err, result = self.utm.get_template_nlists_list(uid, 'url')
            if err:
                self.stepChanged.emit(f'RED|    {result}')
                self.error = 1
                break
            for x in result:
                if x['name'] in self.mc_data['url_lists']:
                    self.stepChanged.emit(f'ORANGE|       Список URL "{x["name"]}" обнаружен в нескольких шаблонах группы. Список из шаблона "{name}" не будет использован.')
                else:
                    self.mc_data['url_lists'][x['name']] = BaseObject(id=x['id'], template_id=uid, template_name=name)
        for item in self.ug_url_lists:
            self.mc_data['url_lists'][item] = BaseObject(id=f'id-{item}', template_id='', template_name='')

        # Получаем список календарей
        self.stepChanged.emit(f'BLACK|    Получаем список календарей.')
        for uid, name in self.templates.items():
            err, result = self.utm.get_template_nlists_list(uid, 'timerestrictiongroup')
            if err:
                self.stepChanged.emit(f'iRED|{result}')
                self.error = 1
                break
            for x in result:
                if x['name'] in self.mc_data['calendars']:
                    self.stepChanged.emit(f'ORANGE|       Календарь "{x["name"]}" обнаружен в нескольких шаблонах группы. Календарь из шаблона "{name}" не будет использован.')
                else:
                    self.mc_data['calendars'][x['name']] = BaseObject(id=x['id'], template_id=uid, template_name=name)

        # Получаем список групп категорий URL
        self.stepChanged.emit(f'BLACK|    Получаем список групп категорий URL.')
        for uid, name in self.templates.items():
            err, result = self.utm.get_template_nlists_list(uid, 'urlcategorygroup')
            if err:
                self.stepChanged.emit(f'RED|    {result}')
                self.error = 1
                break
            for x in result:
                if x['name'] in self.mc_data['url_categorygroups']:
                    self.stepChanged.emit(f'ORANGE|       Календарь "{x["name"]}" обнаружен в нескольких шаблонах группы. Календарь из шаблона "{name}" не будет использован.')
                else:
                    category_name = default_urlcategorygroup.get(x['name'], x['name'])
                    self.mc_data['url_categorygroups'][category_name] = BaseObject(id=x['id'], template_id=uid, template_name=name)

        # Получаем список групп приложений
        self.stepChanged.emit(f'BLACK|    Получаем список групп приложений.')
        for uid, name in self.templates.items():
            err, result = self.utm.get_template_nlists_list(uid, 'applicationgroup')
            if err:
                self.stepChanged.emit(f'RED|    {result}')
                self.error = 1
                break
            for x in result:
                if x['name'] in self.mc_data['apps_groups']:
                    self.stepChanged.emit(f'ORANGE|       Группа приложений "{x["name"]}" обнаружена в нескольких шаблонах группы шаблонов. Группа из шаблона "{name}" не будет использована.')
                else:
                    self.mc_data['apps_groups'][x['name']] = BaseObject(id=x['id'], template_id=uid, template_name=name)

        # Получаем список профилей SSL
        self.stepChanged.emit(f'BLACK|    Получаем список профилей SSL.')
        for uid, name in self.templates.items():
            err, result = self.utm.get_template_ssl_profiles(uid)
            if err:
                self.stepChanged.emit(f'RED|    {result}')
                self.error = 1
                break
            for x in result:
                if x['name'] in self.mc_data['ssl_profiles']:
                    self.stepChanged.emit(f'ORANGE|       Профиль SSL "{x["name"]}" обнаружен в нескольких шаблонах группы шаблонов. Профиль из шаблона "{name}" не будет использован.')
                else:
                    self.mc_data['ssl_profiles'][x['name']] = BaseObject(id=x['id'], template_id=uid, template_name=name)
        self.mc_data['ssl_profiles'][-1] = BaseObject(id=-1, template_id='', template_name='')

        # Получаем список сценариев шаблона
        self.stepChanged.emit(f'BLACK|    Получаем список сценариев.')
        for uid, name in self.templates.items():
            err, result = self.utm.get_template_scenarios_rules(uid)
            if err:
                self.stepChanged.emit(f'RED|    {result}')
                self.error = 1
                break
            for x in result:
                if x['name'] in self.mc_data['scenarios']:
                    self.stepChanged.emit(f'ORANGE|       Сценарий "{x["name"]}" обнаружен в нескольких шаблонах группы шаблонов. Сценарий из шаблона "{name}" не будет использован.')
                else:
                    self.mc_data['scenarios'][x['name']] = BaseObject(id=x['id'], template_id=uid, template_name=name)

        # Получаем список сертификатов
        self.stepChanged.emit(f'BLACK|    Получаем список сертификатов группы шаблонов')
        for uid, name in self.templates.items():
            err, result = self.utm.get_template_certificates_list(uid)
            if err:
                self.stepChanged.emit(f'iRED|{result}')
                self.error = 1
                break
            for x in result:
                if x['name'] in self.mc_data['certs']:
                    self.stepChanged.emit(f'ORANGE|       Сертификат "{x["name"]}" обнаружен в нескольких шаблонах группы шаблонов. Сертификат из шаблона "{name}" не будет использован.')
                else:
                    self.mc_data['certs'][x['name']] = BaseObject(id=x['id'], template_id=uid, template_name=name)
        self.mc_data['certs'][-1] = BaseObject(id=-1, template_id='', template_name='')

        # Получаем список профилей аутентификации
        self.stepChanged.emit(f'BLACK|    Получаем список профилей аутентификации группы шаблонов')
        for uid, name in self.templates.items():
            err, result = self.utm.get_template_auth_profiles(uid)
            if err:
                self.stepChanged.emit(f'iRED|{result}')
                self.error = 1
                break
            for x in result:
                if x['name'] in self.mc_data['auth_profiles']:
                    self.stepChanged.emit(f'ORANGE|       Ппрофиль аутентификации "{x["name"]}" обнаружен в нескольких шаблонах группы шаблонов. Профиль из шаблона "{name}" не будет использован.')
                else:
                    self.mc_data['auth_profiles'][x['name']] = BaseObject(id=x['id'], template_id=uid, template_name=name)
        self.mc_data['auth_profiles'][-1] = BaseObject(id=-1, template_id='', template_name='')

        # Получаем список локальных групп
        self.stepChanged.emit(f'BLACK|    Получаем список групп пользователей группы шаблонов')
        for uid, name in self.templates.items():
            err, result = self.utm.get_template_groups_list(uid)
            if err:
                self.stepChanged.emit(f'iRED|{result}')
                self.error = 1
                break
            for x in result:
                if x['name'] in self.mc_data['local_groups']:
                    self.stepChanged.emit(f'ORANGE|       Группа пользователей "{x["name"]}" обнаружена в нескольких шаблонах группы шаблонов. Группа из шаблона "{name}" не будет использована.')
                else:
                    self.mc_data['local_groups'][x['name']] = BaseObject(id=x['id'], template_id=uid, template_name=name)

        # Получаем список локальных пользователей
        self.stepChanged.emit(f'BLACK|    Получаем список локальных пользователей группы шаблонов')
        for uid, name in self.templates.items():
            err, result = self.utm.get_template_users_list(uid)
            if err:
                self.stepChanged.emit(f'iRED|{result}')
                self.error = 1
                break
            for x in result:
                if x['name'] in self.mc_data['local_users']:
                    self.stepChanged.emit(f'ORANGE|       Пользователь "{x["name"]}" обнаружен в нескольких шаблонах группы шаблонов. Пользователь из шаблона "{name}" не будет использован.')
                else:
                    self.mc_data['local_users'][x['name']] = BaseObject(id=x['id'], template_id=uid, template_name=name)

        # Получаем список приложений l7 в МС
#        self.stepChanged.emit(f'BLACK|    Получаем список приложений.')
#        err, result = self.utm.get_template_app_signatures(self.template_id)
#        if err:
#            self.stepChanged.emit(f'RED|    {result}')
#            self.error = 1
#            return
#        for x in result:
#            self.mc_data['l7_apps'][x['name']] = BaseAppObject(id=x['id'], owner=x['attributes']['owner'], signature_id=x['signature_id'])

        # Получаем список предопределённых категорий URL
        self.stepChanged.emit(f'BLACK|    Получаем список категорий URL.')
        err, result = self.utm.get_url_categories()
        if err:
            self.stepChanged.emit(f'RED|    {result}')
            self.error = 1
            return
        self.mc_data['url_categories'] = {x['name']: x['id'] for x in result}

        # Получаем список предопределённых категорий приложений l7
        self.stepChanged.emit(f'BLACK|    Получаем список категорий приложений.')
        err, result = self.utm.get_l7_categories()
        if err:
            self.stepChanged.emit(f'RED|    {result}')
            self.error = 1
            return
        self.mc_data['l7_categories'] = {x['name']: x['id'] for x in result}


        if self.error:
            self.stepChanged.emit(f'iRED|Произошла ошибка инициализации импорта! Устраните ошибки и повторите импорт.')
        else:
            if write_bin_file(self, self.mc_data):
                self.stepChanged.emit(f'iRED|Произошла ошибка инициализации импорта! Не удалось сохранить служебные структуры данных.')
            else:
                self.stepChanged.emit(f'GREEN|Служебные структуры данных заполнены.\n')
