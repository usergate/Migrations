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
#--------------------------------------------------------------------------------------------------- 
# get_mc_temporary_data.py
# Класс GetMcDcfwTemporaryData - для получения часто используемых данных.
# Version 1.1  03.07.2025    (идентично для ug_ngfw_converter и universal_converter)
#

import os, sys
from PyQt6.QtCore import QThread, pyqtSignal
from services import default_urlcategorygroup
from common_classes import WriteBinFile, UsercatalogLdapServers, BaseObject


class GetMcDcfwTemporaryData(QThread, WriteBinFile, UsercatalogLdapServers):
    """Получаем конфигурационные данные с MC для заполнения служебных структур данных DCFW."""
    stepChanged = pyqtSignal(str)
    def __init__(self, utm, templates):
        super().__init__()
        self.utm = utm
        self.templates = templates    # структура {template_id: template_name}
        self.mc_data = {
            'services': {},
            'service_groups': {},
            'ip_lists': {
                'BOTNET_BLACK_LIST': BaseObject(id='id-BOTNET_BLACK_LIST', template_id='', template_name=''),
                'BANKS_IP_LIST': BaseObject(id='id-BANKS_IP_LIST', template_id='', template_name=''),
                'ZAPRET_INFO_BLACK_LIST_IP': BaseObject(id='id-ZAPRET_INFO_BLACK_LIST_IP', template_id='', template_name=''),
            },
            'url_lists': {
                'ENTENSYS_WHITE_LIST': BaseObject(id='id-ENTENSYS_WHITE_LIST', template_id='', template_name=''),
                'ENTENSYS_BLACK_LIST': BaseObject(id='id-ENTENSYS_BLACK_LIST', template_id='', template_name=''),
                'BAD_SEARCH_BLACK_LIST': BaseObject(id='id-BAD_SEARCH_BLACK_LIST', template_id='', template_name=''),
                'ENTENSYS_KAZ_BLACK_LIST': BaseObject(id='id-ENTENSYS_KAZ_BLACK_LIST', template_id='', template_name=''),
                'FISHING_BLACK_LIST': BaseObject(id='id-FISHING_BLACK_LIST', template_id='', template_name=''),
                'ZAPRET_INFO_BLACK_LIST': BaseObject(id='id-ZAPRET_INFO_BLACK_LIST', template_id='', template_name=''),
                'ZAPRET_INFO_BLACK_LIST_DOMAIN': BaseObject(id='id-ZAPRET_INFO_BLACK_LIST_DOMAIN', template_id='', template_name=''),
            },
            'calendars': {},
            'shapers': {},
            'response_pages': {-1: BaseObject(id=-1, template_id='', template_name='')},
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
            'ssl_profiles': {-1: BaseObject(id=-1, template_id='', template_name='')},
            'ssl_forward_profiles': {},
            'bfd_profiles': {},
            'userid_filters': {},
            'zones': {},
            'interfaces': {},
            'gateways': {},
            'vrf': {},
            'certs': {-1: BaseObject(id=-1, template_id='', template_name='')},
            'client_certs_profiles': {},
            'local_groups': {},
            'local_users': {},
            'auth_servers': {},
            'auth_profiles': {
                -1: BaseObject(id=-1, template_id='', template_name=''),
                False: BaseObject(id=False, template_id='', template_name=''),
            },
            'captive_profiles': {},
            'profiles_2fa': {},
            'vpn_client_security_profiles': {},
            'vpn_server_security_profiles': {},
            'vpn_networks': {},
            'snmp_security_profiles': {},
            'url_categories': {},
            'l7_categories': {},
            'realm_users_signatures': {},
        }
        self.error = 0

    def run(self):
        """Заполняем служебные структуры данных"""
        self.stepChanged.emit(f'BLUE|Заполняем служебные структуры данных.')

        # Получаем список всех активных LDAP-серверов области
        self.get_ldap_servers()

        # Получаем список групп сервисов
        self.stepChanged.emit(f'BLACK|    Получаем список групп сервисов группы шаблонов.')
        for uid, name in self.templates.items():
            err, result = self.utm.get_dcfw_template_nlists(uid, 'dcfw_servicegroup')
            if err:
                self.stepChanged.emit(f'RED|    {result} ["dcfw_servicegroup"]')
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
            err, result = self.utm.get_dcfw_template_nlists(uid, 'network')
            if err:
                self.stepChanged.emit(f'RED|    {result} ["network"]')
                self.error = 1
                break
            for x in result:
                if x['name'] in self.mc_data['ip_lists']:
                    self.stepChanged.emit(f'ORANGE|       IP-лист "{x["name"]}" обнаружен в нескольких шаблонах группы. IP-лист из шаблона "{name}" не будет использован.')
                else:
                    self.mc_data['ip_lists'][x['name']] = BaseObject(id=x['id'], template_id=uid, template_name=name)

        # Получаем список URL-листов
        self.stepChanged.emit(f'BLACK|    Получаем список URL-листов.')
        for uid, name in self.templates.items():
            err, result = self.utm.get_dcfw_template_nlists(uid, 'url')
            if err:
                self.stepChanged.emit(f'RED|    {result} ["url"]')
                self.error = 1
                break
            for x in result:
                if x['name'] in self.mc_data['url_lists']:
                    self.stepChanged.emit(f'ORANGE|       Список URL "{x["name"]}" обнаружен в нескольких шаблонах группы. Список из шаблона "{name}" не будет использован.')
                else:
                    self.mc_data['url_lists'][x['name']] = BaseObject(id=x['id'], template_id=uid, template_name=name)

        # Получаем список групп приложений
        self.stepChanged.emit(f'BLACK|    Получаем список групп приложений.')
        for uid, name in self.templates.items():
            err, result = self.utm.get_dcfw_template_nlists(uid, 'applicationgroup')
            if err:
                self.stepChanged.emit(f'RED|    {result} ["applicationgroup"]')
                self.error = 1
                break
            for x in result:
                if x['name'] in self.mc_data['apps_groups']:
                    self.stepChanged.emit(f'ORANGE|       Группа приложений "{x["name"]}" обнаружена в нескольких шаблонах группы шаблонов. Группа из шаблона "{name}" не будет использована.')
                else:
                    self.mc_data['apps_groups'][x['name']] = BaseObject(id=x['id'], template_id=uid, template_name=name)

        # Получаем список сертификатов
        self.stepChanged.emit(f'BLACK|    Получаем список сертификатов группы шаблонов')
        for uid, name in self.templates.items():
            err, result = self.utm.get_dcfw_template_certificates(uid)
            if err:
                self.stepChanged.emit(f'iRED|{result}')
                self.error = 1
                break
            for x in result:
                if x['name'] in self.mc_data['certs']:
                    self.stepChanged.emit(f'ORANGE|       Сертификат "{x["name"]}" обнаружен в нескольких шаблонах группы шаблонов. Сертификат из шаблона "{name}" не будет использован.')
                else:
                    self.mc_data['certs'][x['name']] = BaseObject(id=x['id'], template_id=uid, template_name=name)

        # Получаем список профилей аутентификации
        self.stepChanged.emit(f'BLACK|    Получаем список профилей аутентификации группы шаблонов')
        for uid, name in self.templates.items():
            err, result = self.utm.get_dcfw_template_auth_profiles(uid)
            if err:
                self.stepChanged.emit(f'iRED|{result}')
                self.error = 1
                break
            for x in result:
                if x['name'] in self.mc_data['auth_profiles']:
                    self.stepChanged.emit(f'ORANGE|       Ппрофиль аутентификации "{x["name"]}" обнаружен в нескольких шаблонах группы шаблонов. Профиль из шаблона "{name}" не будет использован.')
                else:
                    self.mc_data['auth_profiles'][x['name']] = BaseObject(id=x['id'], template_id=uid, template_name=name)

        # Получаем список локальных групп
        self.stepChanged.emit(f'BLACK|    Получаем список групп пользователей группы шаблонов')
        for uid, name in self.templates.items():
            err, result = self.utm.get_dcfw_template_groups(uid)
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
            err, result = self.utm.get_dcfw_template_users(uid)
            if err:
                self.stepChanged.emit(f'iRED|{result}')
                self.error = 1
                break
            for x in result:
                if x['name'] in self.mc_data['local_users']:
                    self.stepChanged.emit(f'ORANGE|       Пользователь "{x["name"]}" обнаружен в нескольких шаблонах группы шаблонов. Пользователь из шаблона "{name}" не будет использован.')
                else:
                    self.mc_data['local_users'][x['name']] = BaseObject(id=x['id'], template_id=uid, template_name=name)

        # Получаем список предопределённых категорий URL
        self.stepChanged.emit(f'BLACK|    Получаем список категорий URL.')
        err, result = self.utm.get_url_categories()
        if err:
            self.stepChanged.emit(f'RED|    {result}')
            self.error = 1
        self.mc_data['url_categories'] = {x['name']: x['id'] for x in result}

        # Получаем список предопределённых категорий приложений l7
        self.stepChanged.emit(f'BLACK|    Получаем список категорий приложений.')
        err, result = self.utm.get_dcfw_l7_categories()
        if err:
            self.stepChanged.emit(f'RED|    {result}')
            self.error = 1
        self.mc_data['l7_categories'] = {x['name']: x['id'] for x in result}


        # Получаем ID шаблона "UserGate Libraries template" и добавляем его в список шаблонов.
        # Далее получаем данные с учётом этого шаблона.
#        err, result = self.utm.get_dcfw_device_templates()
#        if err:
#            self.stepChanged.emit(f'RED|    {result}')
#            self.error = 1
#        else:
#            for item in result:
#                if item['name'] == 'UserGate Libraries template':
#                    self.templates[item['id']] = item['name']
#                    break

        # Получаем список зон
        self.stepChanged.emit(f'BLACK|    Получаем список зон группы шаблонов.')
        for uid, name in self.templates.items():
            err, result = self.utm.get_dcfw_template_zones(uid)
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
            err, result = self.utm.get_dcfw_template_services(uid)
            if err:
                self.stepChanged.emit(f'RED|    {result}')
                self.error = 1
                break
            for x in result:
                if x['name'] in self.mc_data['services']:
                    self.stepChanged.emit(f'ORANGE|       Сервис "{x["name"]}" обнаружен в нескольких шаблонах группы. Сервис из шаблона "{name}" не будет использован.')
                else:
                    self.mc_data['services'][x['name']] = BaseObject(id=x['id'], template_id=uid, template_name=name)

        # Получаем список календарей
        self.stepChanged.emit(f'BLACK|    Получаем список календарей.')
        for uid, name in self.templates.items():
            err, result = self.utm.get_dcfw_template_nlists(uid, 'timerestrictiongroup')
            if err:
                self.stepChanged.emit(f'RED|    {result} ["timerestrictiongroup"]')
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
            err, result = self.utm.get_dcfw_template_nlists(uid, 'urlcategorygroup')
            if err:
                self.stepChanged.emit(f'RED|    {result} ["urlcategorygroup"]')
                self.error = 1
                break
            for x in result:
                if x['name'] in self.mc_data['url_categorygroups']:
                    self.stepChanged.emit(f'ORANGE|       Категория URL "{x["name"]}" обнаружена в нескольких шаблонах группы. Категория из шаблона "{name}" не будет использована.')
                else:
                    category_name = default_urlcategorygroup.get(x['name'], x['name'])
                    self.mc_data['url_categorygroups'][category_name] = BaseObject(id=x['id'], template_id=uid, template_name=name)

        # Получаем список профилей SSL
        self.stepChanged.emit(f'BLACK|    Получаем список профилей SSL.')
        for uid, name in self.templates.items():
            err, result = self.utm.get_dcfw_template_ssl_profiles(uid)
            if err:
                self.stepChanged.emit(f'RED|    {result}')
                self.error = 1
                break
            for x in result:
                if x['name'] in self.mc_data['ssl_profiles']:
                    self.stepChanged.emit(f'ORANGE|       Профиль SSL "{x["name"]}" обнаружен в нескольких шаблонах группы шаблонов. Профиль из шаблона "{name}" не будет использован.')
                else:
                    self.mc_data['ssl_profiles'][x['name']] = BaseObject(id=x['id'], template_id=uid, template_name=name)

        # Получаем список шаблонов страниц
        self.stepChanged.emit(f'BLACK|    Получаем список шаблонов страниц.')
        for uid, name in self.templates.items():
            err, result = self.utm.get_dcfw_template_responsepages(uid)
            if err:
                self.stepChanged.emit(f'RED|    {result}')
                self.error = 1
                break
            for x in result:
                if x['name'] in self.mc_data['response_pages']:
                    self.stepChanged.emit(f'ORANGE|       Шаблон страницы "{x["name"]}" обнаружен в нескольких шаблонах группы шаблонов. Страница из шаблона "{name}" не будет использована.')
                else:
                    self.mc_data['response_pages'][x['name']] = BaseObject(id=x['id'], template_id=uid, template_name=name)

        # Получаем полосы пропускания
        self.stepChanged.emit(f'BLACK|    Получаем полосы пропускания.')
        for uid, name in self.templates.items():
            err, result = self.utm.get_dcfw_template_shapers(uid)
            if err:
                self.stepChanged.emit(f'RED|    {result}')
                self.error = 1
                break
            for x in result:
                if x['name'] in self.mc_data['shapers']:
                    self.stepChanged.emit(f'ORANGE|       Полоса пропускания "{x["name"]}" обнаружен в нескольких шаблонах группы шаблонов. Полоса из шаблона "{name}" не будет использована.')
                else:
                    self.mc_data['shapers'][x['name']] = BaseObject(id=x['id'], template_id=uid, template_name=name)

                    
        if self.error:
            self.stepChanged.emit(f'iRED|Произошла ошибка инициализации импорта! Устраните ошибки и повторите импорт.')
        else:
            if self.write_bin_file(self.mc_data):
                self.stepChanged.emit(f'iRED|Произошла ошибка инициализации импорта! Не удалось сохранить служебные структуры данных.')
            else:
                self.stepChanged.emit(f'GREEN|Служебные структуры данных заполнены.\n')
