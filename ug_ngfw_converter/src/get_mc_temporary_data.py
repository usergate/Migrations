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
# init_temporary_data.py
# Version 1.2
#--------------------------------------------------------------------------------------------------- 
#
import os, sys, json
from PyQt6.QtCore import QThread, pyqtSignal
from services import default_urlcategorygroup
from common_func import write_bin_file


class GetTemporaryData(QThread):
    """Получаем конфигурационные данные с MC для заполнения служебных структур данных."""
    stepChanged = pyqtSignal(str)
    def __init__(self, utm, template_id):
        super().__init__()
        self.utm = utm
        self.template_id = template_id
        self.mc_data = {}
        self.ug_iplists = ('BOTNET_BLACK_LIST', 'BANKS_IP_LIST', 'ZAPRET_INFO_BLACK_LIST_IP')
        self.ug_url_lists = ('ENTENSYS_WHITE_LIST', 'BAD_SEARCH_BLACK_LIST', 'ENTENSYS_BLACK_LIST',
            'ENTENSYS_KAZ_BLACK_LIST', 'FISHING_BLACK_LIST', 'ZAPRET_INFO_BLACK_LIST', 'ZAPRET_INFO_BLACK_LIST_DOMAIN')
        self.ug_mime = ('MIME_CAT_APPLICATIONS', 'MIME_CAT_DOCUMENTS', 'MIME_CAT_IMAGES',
            'MIME_CAT_JAVASCRIPT', 'MIME_CAT_SOUNDS', 'MIME_CAT_VIDEO')
        self.mc_data['ug_morphology'] = ('MORPH_CAT_BADWORDS', 'MORPH_CAT_DLP_ACCOUNTING',
            'MORPH_CAT_DLP_FINANCE', 'MORPH_CAT_DLP_LEGAL', 'MORPH_CAT_DLP_MARKETING', 'MORPH_CAT_DLP_PERSONAL',
            'MORPH_CAT_DRUGSWORDS', 'MORPH_CAT_FZ_436', 'MORPH_CAT_GAMBLING', 'MORPH_CAT_KAZAKHSTAN',
            'MORPH_CAT_MINJUSTWORDS', 'MORPH_CAT_PORNOWORDS', 'MORPH_CAT_SUICIDEWORDS', 'MORPH_CAT_TERRORWORDS')
        self.mc_data['ug_useragents'] = (
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
            self.error = 1
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
        self.stepChanged.emit(f'BLACK|    Получаем список зон.')
        err, result = self.utm.get_template_zones_list(self.template_id)
        if err:
            self.stepChanged.emit(f'RED|    {result}')
            self.error = 1
        self.mc_data['zones'] = {x['name']: x['id'] for x in result}

        # Получаем список сервисов
        self.stepChanged.emit(f'BLACK|    Получаем список сервисов.')
        err, result = self.utm.get_template_services_list(self.template_id)
        if err:
            self.stepChanged.emit(f'RED|    {result}')
            self.error = 1
        self.mc_data['services'] = {x['name']: x['id'] for x in result}

        # Получаем список групп сервисов
        self.stepChanged.emit(f'BLACK|    Получаем список групп сервисов.')
        err, result = self.utm.get_template_nlists_list(self.template_id, 'servicegroup')
        if err:
            self.stepChanged.emit(f'RED|    {result}')
            self.error = 1
        self.mc_data['service_groups'] = {x['name']: x['id'] for x in result}

        # Получаем список типов контента
        self.stepChanged.emit(f'BLACK|    Получаем список типов контента.')
        err, result = self.utm.get_template_nlists_list(self.template_id, 'mime')
        if err:
            self.stepChanged.emit(f'RED|    {result}')
            self.error = 1
        self.mc_data['mime'] = {x['name'].strip(): x['id'] for x in result}
        for item in self.ug_mime:
            self.mc_data['mime'][item] = f'id-{item}'

        # Получаем список IP-листов
        self.stepChanged.emit(f'BLACK|    Получаем список IP-листов.')
        err, result = self.utm.get_template_nlists_list(self.template_id, 'network')
        if err:
            self.stepChanged.emit(f'RED|    {result}')
            self.error = 1
        self.mc_data['ip_lists'] = {x['name']: x['id'] for x in result}
        for item in self.ug_iplists:
            self.mc_data['ip_lists'][item] = f'id-{item}'

        # Получаем список URL-листов
        self.stepChanged.emit(f'BLACK|    Получаем список URL-листов.')
        err, result = self.utm.get_template_nlists_list(self.template_id, 'url')
        if err:
            self.stepChanged.emit(f'RED|    {result}')
            self.error = 1
        self.mc_data['url_lists'] = {x['name']: x['id'] for x in result}
        for item in self.ug_url_lists:
            self.mc_data['url_lists'][item] = f'id-{item}'

        # Получаем список календарей
        self.stepChanged.emit(f'BLACK|    Получаем список календарей.')
        err, result = self.utm.get_template_nlists_list(self.template_id, 'timerestrictiongroup')
        if err:
            self.stepChanged.emit(f'iRED|{result}')
            self.error = 1
        self.mc_data['calendars'] = {x['name']: x['id'] for x in result}

        # Получаем список групп категорий URL
        self.stepChanged.emit(f'BLACK|    Получаем список групп категорий URL.')
        err, result = self.utm.get_template_nlists_list(self.template_id, 'urlcategorygroup')
        if err:
            self.stepChanged.emit(f'RED|    {result}')
            self.error = 1
        self.mc_data['url_categorygroups'] = {default_urlcategorygroup.get(x['name'], x['name']): x['id'] for x in result}

        # Получаем список категорий URL
        self.stepChanged.emit(f'BLACK|    Получаем список категорий URL.')
        err, result = self.utm.get_url_categories()
        if err:
            self.stepChanged.emit(f'RED|    {result}')
            self.error = 1
        self.mc_data['url_categories'] = {x['name']: x['id'] for x in result}

        # Получаем список профилей SSL
        self.stepChanged.emit(f'BLACK|    Получаем список профилей SSL.')
        err, result = self.utm.get_template_ssl_profiles_list(self.template_id)
        if err:
            self.stepChanged.emit(f'RED|    {result}')
            self.error = 1
        self.mc_data['ssl_profiles'] = {x['name']: x['id'] for x in result}

        # Получаем список сценариев шаблона
        self.stepChanged.emit(f'BLACK|    Получаем список сценаиев.')
        err, result = self.utm.get_template_scenarios_rules(self.template_id)
        if err:
            self.stepChanged.emit(f'RED|    {result}')
            self.error = 1
        self.mc_data['scenarios'] = {x['name']: x['id'] for x in result}

        # Получаем список сертификатов
        self.stepChanged.emit(f'BLACK|    Получаем список сертификатов')
        err, result = self.utm.get_template_certificates_list(self.template_id)
        if err:
            self.stepChanged.emit(f'iRED|{result}')
            return
        self.mc_data['certs'] = {x['name']: x['id'] for x in result}
        self.mc_data['certs'][-1] = 0

        # Получаем список профилей аутентификации
        self.stepChanged.emit(f'BLACK|    Получаем список профилей аутентификации')
        err, result = self.utm.get_template_auth_profiles(self.template_id)
        if err:
            self.stepChanged.emit(f'iRED|{result}')
            return
        self.mc_data['auth_profiles'] = {x['name']: x['id'] for x in result}

        # Получаем список локальных групп
        self.stepChanged.emit(f'BLACK|    Получаем список локальных групп')
        err, result = self.utm.get_template_groups_list(self.template_id)
        if err:
            self.stepChanged.emit(f'iRED|{result}')
            return
        self.mc_data['local_groups'] = {x['name']: x['id'] for x in result}

        # Получаем список локальных пользователей
        self.stepChanged.emit(f'BLACK|    Получаем список локальных пользователей')
        err, result = self.utm.get_template_users_list(self.template_id)
        if err:
            self.stepChanged.emit(f'iRED|{result}')
            return
        self.mc_data['local_users'] = {x['name']: x['id'] for x in result}

        # Получаем список групп приложений
        self.stepChanged.emit(f'BLACK|    Получаем список групп приложений.')
        err, result = self.utm.get_template_nlists_list(self.template_id, 'applicationgroup')
        if err:
            self.stepChanged.emit(f'RED|    {result}')
            self.error = 1
        self.mc_data['application_groups'] = {x['name']: x['id'] for x in result}

        # Получаем список категорий приложений l7
        self.stepChanged.emit(f'BLACK|    Получаем список категорий приложений.')
        err, result = self.utm.get_l7_categories()
        if err:
            self.stepChanged.emit(f'RED|    {result}')
            self.error = 1
        self.mc_data['l7_categories'] = {x['name']: x['id'] for x in result}


        if self.error:
            self.stepChanged.emit(f'iRED|Произошла ошибка инициализации импорта! Устраните ошибки и повторите импорт.')
        else:
            if write_bin_file(self, self.mc_data):
                self.stepChanged.emit(f'iRED|Произошла ошибка инициализации импорта! Не удалось сохранить служебные структуры данных.')
            else:
                self.stepChanged.emit(f'GREEN|Служебные структуры данных заполнены.')
