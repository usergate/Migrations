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
# Классы импорта разделов конфигурации CheckPoint на NGFW UserGate версии 7.
# Версия 0.4
#

import os, sys, json
from datetime import datetime as dt
from PyQt6.QtCore import QThread, pyqtSignal
from services import zone_services, character_map_file_name, character_map_for_name


trans_filename = str.maketrans(character_map_file_name)
trans_name = str.maketrans(character_map_for_name)


class ExportAll(QThread):
    """Экспортируем всю конфигурацию с NGFW"""
    stepChanged = pyqtSignal(str)
    
    def __init__(self, utm, base_path, all_points):
        super().__init__()
        self.utm = utm
        self.base_path = base_path
        self.all_points = all_points
        self.ssl_profiles = {}
        self.servicegroups_list = {}
        self.l7_categories = {}             # Устанавливаются через функцию set_appps_values()
        self.l7_apps = {}                   # -- // --
        self.list_applicationgroup = {}     # -- // --
        self.scenarios_rules = {}           # Устанавливаются через функцию set_scenarios_rules()
        self.version = float(f'{self.utm.version_hight}.{self.utm.version_midle}')
        self.error = 0
        self.default_urlcategorygroup = {
            'Parental Control': 'URL_CATEGORY_GROUP_PARENTAL_CONTROL',
            'Productivity': 'URL_CATEGORY_GROUP_PRODUCTIVITY',
            'Safe categories': 'URL_CATEGORY_GROUP_SAFE',
            'Threats': 'URL_CATEGORY_GROUP_THREATS',
            'Recommended for morphology checking': 'URL_CATEGORY_MORPHO_RECOMMENDED',
            'Recommended for virus check': 'URL_CATEGORY_VIRUSCHECK_RECOMMENDED'
        }
        self.init_struct()

    def init_struct(self):
        """Звполняем служебные структуры данных"""
        err, result = self.utm.get_zones_list()
        if err:
            self.stepChanged.emit(f'iRED|{result}')
            return
        self.zones = {x['id']: x['name'].strip().translate(trans_name) for x in result}
        # Получаем список сертификатов
        err, result = self.utm.get_certificates_list()
        if err:
            parent.stepChanged.emit(f'iRED|{result}')
            return
        self.ngfw_certs = {x['id']: x['name'].strip().translate(trans_name) for x in result}
        # Получаем список профилей аутентификации
        err, result = self.utm.get_auth_profiles()
        if err:
            self.stepChanged.emit(f'iRED|{result}')
            return
        self.auth_profiles = {x['id']: x['name'].strip().translate(trans_name) for x in result}
        # Получаем список локальных групп
        err, result = self.utm.get_groups_list()
        if err:
            self.stepChanged.emit(f'iRED|{result}')
            return
        self.list_groups = {x['id']: x['name'].strip().translate(trans_name) for x in result}
        # Получаем список локальных пользователей
        err, result = self.utm.get_users_list()
        if err:
            self.stepChanged.emit(f'iRED|{result}')
            return
        self.list_users = {x['id']: x['name'].strip().translate(trans_name) for x in result}
        # Получаем список профилей SSL
        if self.version > 5:
            err, result = self.utm.get_ssl_profiles_list()
            if err:
                self.stepChanged.emit(f'iRED|{result}')
                return
            self.ssl_profiles = {x['id']: x['name'].strip().translate(trans_name) for x in result}
        # Получаем список IP-листов
        err, result = self.utm.get_nlists_list('network')
        if err:
            self.stepChanged.emit(f'iRED|{result}')
            return
        self.ip_lists = {x['id']: x['name'].strip().translate(trans_name) for x in result}
        # Получаем список URL-листов
        err, result = self.utm.get_nlists_list('url')
        if err:
            self.stepChanged.emit(f'iRED|{result}')
            return
        self.url_lists = {x['id']: x['name'].strip().translate(trans_name) for x in result}
        # Получаем список групп категорий URL
        err, result = self.utm.get_nlists_list('urlcategorygroup')
        if err:
            self.stepChanged.emit(f'iRED|{result}')
            return
        self.list_urlcategorygroup = {x['id']: self.default_urlcategorygroup.get(x['name'], x['name'].strip().translate(trans_name)) for x in result}
        # Получаем список категорий URL
        err, result = self.utm.get_url_categories()
        if err:
            self.stepChanged.emit(f'iRED|{result}')
            return
        self.url_categories = {x['id']: x['name'].strip().translate(trans_name) for x in result}
        # Получаем список календарей
        err, result = self.utm.get_nlists_list('timerestrictiongroup')
        if err:
            self.stepChanged.emit(f'iRED|{result}')
            return
        self.list_calendar = {x['id']: x['name'].strip().translate(trans_name) for x in result}
        # Получаем список сервисов
        err, result = self.utm.get_services_list()
        if err:
            self.stepChanged.emit(f'iRED|{result}')
            return
        self.services_list = {x['id']: x['name'].strip().translate(trans_name) for x in result}
        # Получаем список групп сервисов
        if self.version >= 7:
            err, result = self.utm.get_nlists_list('servicegroup')
            if err:
                self.stepChanged.emit(f'iRED|{result}')
                return
            self.servicegroups_list = {x['id']: x['name'].strip().translate(trans_name) for x in result}

    def run(self):
        """Экспортируем всё в пакетном режиме"""
        for item in self.all_points:
            top_level_path = os.path.join(self.base_path, item['path'])
            for point in item['points']:
                current_path = os.path.join(top_level_path, point)
                print(current_path)
                if point in func:
#                    print(point)
                    func[point](self, current_path)
                else:
                    self.error = 1
                    self.stepChanged.emit(f'RED|Не найдена функция для экспорта {point}!')
        self.stepChanged.emit('iORANGE|Экспорт конфигурации прошёл с ошибками!\n' if self.error else 'iGREEN|Экспорт всей конфигурации прошёл успешно.\n')


class ExportSelectedPoints(QThread):
    """Экспортируем выделенный раздел конфигурации с NGFW"""
    stepChanged = pyqtSignal(str)
    
    def __init__(self, utm, selected_path, selected_points):
        super().__init__()
        self.utm = utm
        self.selected_path = selected_path
        self.selected_points = selected_points
        self.ssl_profiles = {}
        self.servicegroups_list = {}
        self.l7_categories = {}             # Устанавливаются через set_appps_values()
        self.l7_apps = {}                   # -- // --
        self.list_applicationgroup = {}     # -- // --
        self.scenarios_rules = {}           # Устанавливаются через функцию set_scenarios_rules()
        self.version = float(f'{self.utm.version_hight}.{self.utm.version_midle}')
        self.error = 0
        self.default_urlcategorygroup = {
            'Parental Control': 'URL_CATEGORY_GROUP_PARENTAL_CONTROL',
            'Productivity': 'URL_CATEGORY_GROUP_PRODUCTIVITY',
            'Safe categories': 'URL_CATEGORY_GROUP_SAFE',
            'Threats': 'URL_CATEGORY_GROUP_THREATS',
            'Recommended for morphology checking': 'URL_CATEGORY_MORPHO_RECOMMENDED',
            'Recommended for virus check': 'URL_CATEGORY_VIRUSCHECK_RECOMMENDED'
        }
        self.init_struct()

    def init_struct(self):
        """Звполняем служебные структуры данных"""
        err, result = self.utm.get_zones_list()
        if err:
            self.stepChanged.emit(f'iRED|{result}')
            return
        self.zones = {x['id']: x['name'].strip().translate(trans_name) for x in result}
        # Получаем список сертификатов
        err, result = self.utm.get_certificates_list()
        if err:
            self.stepChanged.emit(f'iRED|{result}')
            return
        self.ngfw_certs = {x['id']: x['name'].strip().translate(trans_name) for x in result}
        # Получаем список профилей аутентификации
        err, result = self.utm.get_auth_profiles()
        if err:
            self.stepChanged.emit(f'iRED|{result}')
            return
        self.auth_profiles = {x['id']: x['name'].strip().translate(trans_name) for x in result}
        # Получаем список локальных групп
        err, result = self.utm.get_groups_list()
        if err:
            self.stepChanged.emit(f'iRED|{result}')
            return
        self.list_groups = {x['id']: x['name'].strip().translate(trans_name) for x in result}
        # Получаем список локальных пользователей
        err, result = self.utm.get_users_list()
        if err:
            self.stepChanged.emit(f'iRED|{result}')
            return
        self.list_users = {x['id']: x['name'].strip().translate(trans_name) for x in result}
        # Получаем список профилей SSL
        if self.version > 5:
            err, result = self.utm.get_ssl_profiles_list()
            if err:
                self.stepChanged.emit(f'iRED|{result}')
                return
            self.ssl_profiles = {x['id']: x['name'].strip().translate(trans_name) for x in result}
        # Получаем список IP-листов
        err, result = self.utm.get_nlists_list('network')
        if err:
            self.stepChanged.emit(f'iRED|{result}')
            return
        self.ip_lists = {x['id']: x['name'].strip().translate(trans_name) for x in result}
        # Получаем список URL-листов
        err, result = self.utm.get_nlists_list('url')
        if err:
            self.stepChanged.emit(f'iRED|{result}')
            return
        self.url_lists = {x['id']: x['name'].strip().translate(trans_name) for x in result}
        # Получаем список групп категорий URL
        err, result = self.utm.get_nlists_list('urlcategorygroup')
        if err:
            self.stepChanged.emit(f'iRED|{result}')
            return
        self.list_urlcategorygroup = {x['id']: self.default_urlcategorygroup.get(x['name'], x['name'].strip().translate(trans_name)) for x in result}
        # Получаем список категорий URL
        err, result = self.utm.get_url_categories()
        if err:
            self.stepChanged.emit(f'iRED|{result}')
            return
        self.url_categories = {x['id']: x['name'].strip().translate(trans_name) for x in result}
        # Получаем список календарей
        err, result = self.utm.get_nlists_list('timerestrictiongroup')
        if err:
            self.stepChanged.emit(f'iRED|{result}')
            return
        self.list_calendar = {x['id']: x['name'].strip().translate(trans_name) for x in result}
        # Получаем список сервисов
        err, result = self.utm.get_services_list()
        if err:
            self.stepChanged.emit(f'iRED|{result}')
            return
        self.services_list = {x['id']: x['name'].strip().translate(trans_name) for x in result}
        # Получаем список групп сервисов
        if self.version >= 7:
            err, result = self.utm.get_nlists_list('servicegroup')
            if err:
                self.stepChanged.emit(f'iRED|{result}')
                return
            self.servicegroups_list = {x['id']: x['name'].strip().translate(trans_name) for x in result}

    def run(self):
        """Экспортируем определённый раздел конфигурации"""
        for point in self.selected_points:
            current_path = os.path.join(self.selected_path, point)
            if point in func:
                func[point](self, current_path)
            else:
                self.error = 1
                self.stepChanged.emit(f'RED|Не найдена функция для экспорта {point}!')
        self.stepChanged.emit('iORANGE|Экспорт конфигурации прошёл с ошибками!\n' if self.error else 'iGREEN|Экспорт конфигурации прошёл успешно.\n')


def export_general_settings(parent, path):
    """Экспортируем раздел 'UserGate/Настройки/Настройки интерфейса'"""
    parent.stepChanged.emit('BLUE|Экспорт раздела "UserGate/Настройки/Настройки интерфейса".')
    err, msg = create_dir(path)
    if err:
        parent.stepChanged.emit(f'RED|    {msg}')
        parent.error = 1
        return

    error = 0
    params = ['ui_timezone', 'ui_language']
    if parent.version > 5:
        params.extend(['web_console_ssl_profile_id', 'response_pages_ssl_profile_id'])
    if parent.version >= 7.1:
        params.append('api_session_lifetime')

    err, data = parent.utm.get_settings_params(params)
    if err:
        parent.stepChanged.emit(f'RED|    {data}')
        error = 1
        parent.error = 1
    else:
        err, result = parent.utm.get_webui_auth_mode()
        if err:
            parent.stepChanged.emit(f'RED|    {result}')
            error = 1
            parent.error = 1
        else:
            data['webui_auth_mode'] = result

        if parent.version > 5:
            if parent.ssl_profiles:
                data['web_console_ssl_profile_id'] = parent.ssl_profiles[data['web_console_ssl_profile_id']]
                data['response_pages_ssl_profile_id'] = parent.ssl_profiles[data['response_pages_ssl_profile_id']]
            else:
                data.pop('web_console_ssl_profile_id', None)
                data.pop('response_pages_ssl_profile_id', None)

        json_file = os.path.join(path, 'config_settings_ui.json')
        with open(json_file, 'w') as fh:
            json.dump(data, fh, indent=4, ensure_ascii=False)

    out_message = f'GREEN|    Настройки интерфейса выгружены в файл "{json_file}".'
    parent.stepChanged.emit('ORANGE|    Ошибка экспорта настроек интерфейса!' if error else out_message)


    """Экспортируем раздел 'UserGate/Настройки/Модули'"""
    parent.stepChanged.emit('BLUE|Экспорт раздела "UserGate/Настройки/Модули".')
    error = 0

    params = ["auth_captive", "logout_captive", "block_page_domain", "ftpclient_captive", "ftp_proxy_enabled"]
    if parent.version >= 7.1:
        params.extend(['tunnel_inspection_zone_config', 'lldp_config'])

    err, data = parent.utm.get_settings_params(params)
    if err:
        parent.stepChanged.emit(f'RED|    {data}')
        error = 1
        parent.error = 1
    else:
        if parent.version >= 7.1:
            zone_number = data['tunnel_inspection_zone_config']['target_zone']
            data['tunnel_inspection_zone_config']['target_zone'] = parent.zones.get(zone_number, 'Unknown')
        json_file = os.path.join(path, 'config_settings_modules.json')
        with open(json_file, 'w') as fh:
            json.dump(data, fh, indent=4, ensure_ascii=False)

    err, data = parent.utm.get_proxy_port()
    if err:
        parent.stepChanged.emit(f'RED|    {data}')
        error = 1
        parent.error = 1
    else:
        proxy_port_file = os.path.join(path, 'config_proxy_port.json')
        with open(proxy_port_file, 'w') as fh:
            json.dump(data, fh, indent=4, ensure_ascii=False)

    out_message = f'GREEN|    Настройки модулей выгружены в файл "{json_file}".'
    parent.stepChanged.emit('ORANGE|    Ошибка экспорта настроек модулей!' if error else out_message)


    """Экспортируем раздел 'UserGate/Настройки/Настройки кэширования HTTP'"""
    parent.stepChanged.emit('BLUE|Экспорт раздела "UserGate/Настройки/Настройки кэширования HTTP".')
    error = 0

    params = ['http_cache_mode', 'http_cache_docsize_max', 'http_cache_precache_size']
    if parent.version >= 7:
        params.extend([
            'add_via_enabled', 'add_forwarded_enabled', 'smode_enabled', 'module_l7_enabled',
            'module_idps_enabled', 'module_sip_enabled', 'module_h323_enabled', 'module_sunrpc_enabled', 
            'module_ftp_alg_enabled', 'module_tftp_enabled', 'legacy_ssl_enabled', 'http_connection_timeout',
            'http_loading_timeout', 'icap_wait_timeout'
        ])

    err, data = parent.utm.get_settings_params(params)
    if err:
        parent.stepChanged.emit(f'RED|    {data}')
        error = 1
        parent.error = 1
    else:
        json_file = os.path.join(path, 'config_proxy_settings.json')
        with open(json_file, 'w') as fh:
            json.dump(data, fh, indent=4, ensure_ascii=False)
        parent.stepChanged.emit(f'GREEN|    Настройки кэширования HTTP и доп.параметры выгружены в файл "{json_file}".')

    err, data = parent.utm.get_nlist_list('httpcwl')
    if err:
        parent.stepChanged.emit(f'RED|    {data}' if err == 1 else f'ORANGE|    {data}')
        error = 1
        parent.error = 1
    else:
        for content in data['content']:
            content.pop('id')
        json_file = os.path.join(path, 'config_proxy_exceptions.json')
        with open(json_file, 'w') as fh:
            json.dump(data['content'], fh, indent=4, ensure_ascii=False)

    out_message = f'GREEN|    Исключения из кэширования HTTP выгружены в файл "{json_file}".'
    parent.stepChanged.emit('ORANGE|    Ошибка экспорта настроек кэширования HTTP!' if error else out_message)


    """Экспортируем настройки NTP"""
    parent.stepChanged.emit('BLUE|Экспорт настроек NTP раздела "UserGate/Настройки/Настройка времени сервера".')
    error = 0

    err, result = parent.utm.get_ntp_config()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        error = 1
        parent.error = 1
    else:
        result.pop('local_time', None)
        result.pop('timezone', None)
        if parent.version >= 7.1:
            result['utc_time'] = dt.strptime(result['utc_time'].value, "%Y-%m-%dT%H:%M:%S").strftime("%Y-%m-%d %H:%M:%S")
        else:
            result['utc_time'] = dt.strptime(result['utc_time'].value, "%Y%m%dT%H:%M:%S").strftime("%Y-%m-%d %H:%M:%S")

        json_file = os.path.join(path, 'config_ntp.json')
        with open(json_file, 'w') as fh:
            json.dump(result, fh, indent=4, ensure_ascii=False)

    out_message = f'GREEN|    Настройки NTP выгружены в файл "{json_file}".'
    parent.stepChanged.emit('ORANGE|    Ошибка экспорта настроек NTP!' if error else out_message)


    """Экспортируем настройки веб-портала"""
    parent.stepChanged.emit('BLUE|Выгружаются настройки Веб-портала раздела "UserGate/Настройки/Веб-портал":')
    error = 0

    err, result = parent.utm.get_templates_list()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return
    list_templates = {x['id']: x['name'] for x in result}

    if parent.version >= 7.1:
        err, result = parent.utm.get_client_certificate_profiles()
        if err:
            parent.stepChanged.emit(f'RED|    {result}')
            parent.error = 1
            return
        client_certificate_profiles = {x['id']: x['name'] for x in result}

    err, data = parent.utm.get_proxyportal_config()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        error = 1
    else:
        if parent.version > 5:
            data['ssl_profile_id'] = parent.ssl_profiles[data['ssl_profile_id']]
        else:
            data['ssl_profile_id'] = "Default SSL profile"
        if parent.version >= 7.1:
            data['client_certificate_profile_id'] = client_certificate_profiles.get(data['client_certificate_profile_id'], 0)
        else:
            data['client_certificate_profile_id'] = 0

        data['user_auth_profile_id'] = parent.auth_profiles.get(data['user_auth_profile_id'], 1)
        data['proxy_portal_template_id'] = list_templates.get(data['proxy_portal_template_id'], -1)
        data['proxy_portal_login_template_id'] = list_templates.get(data['proxy_portal_login_template_id'], -1)
        data['certificate_id'] = parent.ngfw_certs.get(data['certificate_id'], -1)

        json_file = os.path.join(path, 'config_web_portal.json')
        with open(json_file, 'w') as fh:
            json.dump(data, fh, indent=4, ensure_ascii=False)

    out_message = f'GREEN|    Настройки Веб-портала выгружены в файл "{json_file}".'
    parent.stepChanged.emit('ORANGE|    Ошибка экспорта настроек Веб-портала!' if error else out_message)


    """Экспортируем настройки вышестоящего прокси"""
    if parent.version >= 7.1:
        parent.stepChanged.emit('BLUE|Экспорт настроек раздела "UserGate/Настройки/Вышестоящий прокси".')
        error = 0

        err, result = parent.utm.get_upstream_proxy_settings()
        if err:
            parent.stepChanged.emit(f'RED|    {result}')
            error = 1
            parent.error = 1
        else:
            json_file = os.path.join(path, 'upstream_proxy_settings.json')
            with open(json_file, 'w') as fh:
                json.dump(result, fh, indent=4, ensure_ascii=False)

        out_message = f'GREEN|    Настройки вышестоящего прокси выгружены в файл "{json_file}".'
        parent.stepChanged.emit('ORANGE|    Ошибка экспорта настроек вышестоящего прокси!' if error else out_message)


def export_certificates(parent, path):
    """Экспортируем сертификаты."""
    parent.stepChanged.emit('BLUE|Экспорт настроек раздела "UserGate/Сертификаты".')
    error = 0

    err, result = parent.utm.get_certificates_list()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        error = 1
    else:
        for item in result:
            item.pop('cc', None)
            if parent.version >= 7.1:
                item['not_before'] = dt.strptime(item['not_before'].value, "%Y-%m-%dT%H:%M:%SZ").strftime("%Y-%m-%d %H:%M:%S")
                item['not_after'] = dt.strptime(item['not_after'].value, "%Y-%m-%dT%H:%M:%SZ").strftime("%Y-%m-%d %H:%M:%S")
            else:
                item['not_before'] = dt.strptime(item['not_before'], "%Y-%m-%dT%H:%M:%SZ").strftime("%Y-%m-%d %H:%M:%S")
                item['not_after'] = dt.strptime(item['not_after'], "%Y-%m-%dT%H:%M:%SZ").strftime("%Y-%m-%d %H:%M:%S")

            # Для каждого сертификата создаём свой каталог.
            path_cert = os.path.join(path, item['name'])
            err, msg = create_dir(path_cert)
            if err:
                parent.stepChanged.emit(f'RED|    {msg}')
                parent.error = 1
                error = 1
            else:
                # Выгружаем сертификат в формат DER.
                err, base64_cert = parent.utm.get_certificate_data(item['id'])
                if err:
                    parent.stepChanged.emit(f'RED|    {base64_cert}')
                    parent.error = 1
                    error = 1
                else:
                    with open(os.path.join(path_cert, 'cert.der'), 'wb') as fh:
                        fh.write(base64_cert.data)

                # Выгружаем сертификат с цепочками в формат PEM.
                err, base64_cert = parent.utm.get_certificate_chain_data(item['id'])
                if err:
                    parent.stepChanged.emit(f'RED|    {base64_cert}')
                    parent.error = 1
                    error = 1
                else:
                    with open(os.path.join(path_cert, 'cert.pem'), 'wb') as fh:
                        fh.write(base64_cert.data)

                # Выгружаем детальную информацию сертификата в файл certificate_details.json.
                err, details_info = parent.utm.get_certificate_details(item['id'])
                if err:
                    parent.stepChanged.emit(f'RED|    {details_info}')
                    parent.error = 1
                    error = 1
                else:
                    if parent.version >= 7.1:
                        details_info['notBefore'] = dt.strptime(details_info['notBefore'].value, "%Y-%m-%dT%H:%M:%SZ").strftime("%Y-%m-%d %H:%M:%S")
                        details_info['notAfter'] = dt.strptime(details_info['notAfter'].value, "%Y-%m-%dT%H:%M:%SZ").strftime("%Y-%m-%d %H:%M:%S")
                    json_file = os.path.join(path_cert, 'certificate_details.json')
                    with open(json_file, 'w') as fh:
                        json.dump(details_info, fh, indent=4, ensure_ascii=False)

                # Выгружаем общую информацию сертификата в файл certificate_list.json.
                item.pop('id', None)
                json_file = os.path.join(path_cert, 'certificate_list.json')
                with open(json_file, 'w') as fh:
                    json.dump(item, fh, indent=4, ensure_ascii=False)

    out_message = f'GREEN|    Сертификаты выгружены в каталог "{path}".'
    parent.stepChanged.emit('ORANGE|    Ошибка экспорта сертификатов!' if error else out_message)


def export_users_certificate_profiles(parent, path):
    """Экспортируем профили пользовательских сертификатов. Только для версии 7.1 и выше."""
    parent.stepChanged.emit('BLUE|Экспорт настроек раздела "UserGate/Профили пользовательских сертификатов".')
    err, msg = create_dir(path)
    if err:
        parent.stepChanged.emit(f'RED|    {msg}')
        parent.error = 1
        return
    error = 0

    err, result = parent.utm.get_client_certificate_profiles()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        error = 1
        parent.error = 1
    else:
        for item in result:
            item.pop('id', None)
            item.pop('cc', None)
            item['ca_certificates'] = [parent.ngfw_certs[x] for x in item['ca_certificates']]

        json_file = os.path.join(path, 'users_certificate_profiles.json')
        with open(json_file, 'w') as fh:
            json.dump(result, fh, indent=4, ensure_ascii=False)

    out_message = f'GREEN|    Профили пользовательских сертификатов выгружены в файл "{json_file}".'
    parent.stepChanged.emit('ORANGE|    Ошибка экспорта профилей пользовательских сертификатов!' if error else out_message)


def export_zones(parent, path):
    """Экспортируем список зон."""
    parent.stepChanged.emit('BLUE|Экспорт настроек раздела "Сеть/Зоны".')
    err, msg = create_dir(path)
    if err:
        parent.stepChanged.emit(f'RED|    {msg}')
        parent.error = 1
        return
    error = 0

    err, data = parent.utm.get_zones_list()
    if err:
        parent.stepChanged.emit(f'RED|    {data}')
        parent.error = 1
        error = 1
    else:
        for zone in data:
            zone['name'] = zone['name'].strip().translate(trans_name)
            zone.pop('id', None)
            zone.pop('cc', None)
            if parent.version < 7:
                zone['sessions_limit_enabled'] = False
                zone['sessions_limit_threshold'] = 0
                zone['sessions_limit_exclusions'] = []
            elif parent.version == 7.0 and zone['sessions_limit_threshold'] == -1:
                zone['sessions_limit_threshold'] = 0
            elif parent.version >= 7.1:
                for net in zone['networks']:
                    if net[0] == 'list_id':
                        net[1] = parent.ip_lists[net[1]]
                for item in zone['sessions_limit_exclusions']:
                    item[1] = parent.ip_lists[item[1]]

            # Удаляем неиспользуемые в настоящий момент сервисы зон: 3, 16, 20, 21 (в zone_services = false).
            new_services_access = []
            for service in zone['services_access']:
                service['service_id'] = zone_services[service['service_id']]
                if service['service_id']:
                    new_services_access.append(service)
            zone['services_access'] = new_services_access

        json_file = os.path.join(path, 'config_zones.json')
        with open(json_file, 'w') as fh:
            json.dump(data, fh, indent=4, ensure_ascii=False)

    out_message = f'GREEN|    Настройки зон выгружены в файл "{json_file}".'
    parent.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте зон!' if error else out_message)


def export_interfaces_list(parent, path):
    """Экспортируем список интерфейсов"""
    parent.stepChanged.emit('BLUE|Экспорт интерфейсов из раздела "Сеть/Интерфейсы".')
    err, msg = create_dir(path)
    if err:
        parent.stepChanged.emit(f'RED|    {msg}')
        parent.error = 1
        return
    error = 0

    err, result = parent.utm.get_netflow_profiles_list()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return
    list_netflow = {x['id']: x['name'] for x in result}

    list_lldp = {}
    if parent.version >= 7.0:    
        err, result = parent.utm.get_lldp_profiles_list()
        if err:
            parent.stepChanged.emit(f'RED|    {result}')
            parent.error = 1
            return
        list_lldp = {x['id']: x['name'] for x in result}

    err, data = parent.utm.get_interfaces_list()
    if err:
        parent.stepChanged.emit(f'RED|    {data}')
        parent.error = 1
        error = 1
    else:
        iface_name = translate_iface_name(parent.version, path, data)     # Преобразуем имена интерфейсов для версии 5 из eth в port.

        for item in data:
            item['id'], _ = item['id'].split(':')
            item.pop('link_info', None)
            item.pop('speed', None)
            item.pop('errors', None)
            item.pop('running', None)
            item.pop('node_name', None)
            if item['zone_id']:
                item['zone_id'] = parent.zones.get(item['zone_id'], 0)
            item['netflow_profile'] = list_netflow.get(item['netflow_profile'], 'undefined')
            lldp_profile = item.get('lldp_profile', 'undefined')
            item['lldp_profile'] = list_lldp.get(lldp_profile, 'undefined')
            if parent.version < 7.1:
                item['ifalias'] = ''
                item['flow_control'] = False
                if item['mode'] == 'dhcp':
                    item['dhcp_default_gateway'] = True
            if parent.version < 6:
                item.pop('iface_id', None)
                item.pop('qlen', None)
                item.pop('nameservers', None)
                item.pop('ifindex', None)
                item['id'] = iface_name[item['id']]
                item['name'] = iface_name[item['name']]
                if item['kind'] == 'vlan':
                    item['link'] = iface_name[item['link']]
                elif item['kind'] == 'bridge':
                    ports = item['bridging']['ports']
                    ports = [iface_name[x] for x in ports]
                    item['bridging']['ports'] = ports
                elif item['kind'] == 'bond':
                    ports = item['bonding']['slaves']
                    ports = [iface_name[x] for x in ports]
                    item['bonding']['slaves'] = ports
                if item['kind'] == 'ppp':
                    item.pop('dhcp_relay', None)
                    item['pppoe'].pop('index', None)
                    item['pppoe'].pop('name', None)
                    item['pppoe'].pop('iface_id', None)
                    item['pppoe'].pop('id', None)
                    if item['pppoe']['peer'] is None:
                        item['pppoe']['peer'] = ""
                    item['pppoe']['ifname'] = iface_name[item['pppoe']['ifname']]
                if item['kind'] == 'tunnel':
                    item.pop('dhcp_relay', None)
                    item['tunnel'].pop('name', None)
                    item['tunnel'].pop('ttl', None)
                    item['tunnel'].pop('id', None)
                    if 'vni' not in item['tunnel'].keys():
                        item['tunnel']['vni'] = 0
                if item['kind'] not in ('vpn', 'ppp', 'tunnel'):
                    if not item['dhcp_relay']:
                        item['dhcp_relay'] = {
                            'enabled': False,
                            'host_ipv4': '',
                            'servers': []
                        }
                    else:
                        item['dhcp_relay'].pop('id', None)
                        item['dhcp_relay'].pop('iface_id', None)

        data.sort(key=lambda x: x['name'])

        json_file = os.path.join(path, 'config_interfaces.json')
        with open(json_file, 'w') as fh:
            json.dump(data, fh, indent=4, ensure_ascii=False)

    out_message = f'GREEN|    Настройки интерфейсов выгружены в файл "{json_file}".'
    parent.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте интерфейсов!' if error else out_message)


def export_gateways_list(parent, path):
    """Экспортируем список шлюзов"""
    parent.stepChanged.emit('BLUE|Экспорт шлюзов раздела "Сеть/Шлюзы".')
    err, msg = create_dir(path)
    if err:
        parent.stepChanged.emit(f'RED|    {msg}')
        parent.error = 1
        return
    error = 0

    err, result = parent.utm.get_interfaces_list()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return
    else:
        iface_names = translate_iface_name(parent.version, path, result)     # Преобразуем имена интерфейсов для версии 5 из eth в port.

    err, result = parent.utm.get_gateways_list()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        error = 1
    else:
        for item in result:
            item.pop('id', None)
            item.pop('node_name', None)
            item.pop('active', None)
            item.pop('mac', None)
            item.pop('protocol', None)
            item.pop('_appliance_iface', None)
            item.pop('index', None)
            item.pop('uid', None)
            item.pop('cc', None)
            if not 'name' in item or not item['name']:
                item['name'] = item['ipv4']
            item['iface'] = iface_names[item['iface']] if item['iface'] else 'undefined'
            if parent.version < 6:
                item['is_automatic'] = False
                item['vrf'] = 'default'

        json_file = os.path.join(path, 'config_gateways.json')
        with open(json_file, 'w') as fh:
            json.dump(result, fh, indent=4, ensure_ascii=False)

    out_message = f'GREEN|    Настройки шлюзов выгружены в файл "{json_file}".'
    parent.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте шлюзов!' if error else out_message)


    """Экспортируем настройки проверки сети шлюзов"""
    parent.stepChanged.emit('BLUE|Экспорт проверки сети раздела "Сеть/Шлюзы".')
    error = 0

    err, result = parent.utm.get_gateway_failover()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        error = 1
    else:
        json_file = os.path.join(path, 'config_gateway_failover.json')
        with open(json_file, 'w') as fh:
            json.dump(result, fh, indent=4, ensure_ascii=False)

    out_message = f'GREEN|    Настройки "Проверка сети" выгружены в файл "{json_file}".'
    parent.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте настроек проверки сети!' if error else out_message)


def export_dhcp_subnets(parent, path):
    """Экспортируем настройки DHCP"""
    parent.stepChanged.emit('BLUE|Экспорт настроек DHCP раздела "Сеть/DHCP".')
    err, msg = create_dir(path)
    if err:
        parent.stepChanged.emit(f'RED|    {msg}')
        parent.error = 1
        return
    error = 0

    err, result = parent.utm.get_interfaces_list()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return
    else:
        iface_names = translate_iface_name(parent.version, path, result)     # Преобразуем имена интерфейсов для версии 5 из eth в port.

    err, result = parent.utm.get_dhcp_list()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        error = 1
    else:
        for item in result:
            item['iface_id'] = iface_names[item['iface_id']]
            item.pop('id', None)
            item.pop('node_name', None)
            item.pop('cc', None)

        json_file = os.path.join(path, 'config_dhcp_subnets.json')
        with open(json_file, 'w') as fh:
            json.dump(result, fh, indent=4, ensure_ascii=False)

    out_message = f'GREEN|    Настройки DHCP выгружены в файл "{json_file}".'
    parent.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте настроек DHCP!' if error else out_message)


def export_dns_config(parent, path):
    """Экспортируем настройки DNS"""
    parent.stepChanged.emit('BLUE|Экспорт настройек DNS раздела "Сеть/DNS".')
    err, msg = create_dir(path)
    if err:
        parent.stepChanged.emit(f'RED|    {msg}')
        parent.error = 1
        return

    error = 0
    params = (
        'use_cache_enabled',
        'enable_dns_filtering',
        'recursive_enabled',
        'dns_max_ttl',
        'dns_max_queries_per_user',
        'only_a_for_unknown',
        'dns_receive_timeout',
        'dns_max_attempts'
    )
    err, result = parent.utm.get_settings_params(params)
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        error = 1
        parent.error = 1
    else:
        json_file = os.path.join(path, 'config_dns_proxy.json')
        with open(json_file, 'w') as fh:
            json.dump(result, fh, indent=4, ensure_ascii=False)
        parent.stepChanged.emit(f'BLACK|    Настройки DNS-прокси выгружены в файл "{json_file}".')

    err, result = parent.utm.get_dns_servers()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        error = 1
        parent.error = 1
    else:
        json_file = os.path.join(path, 'config_dns_servers.json')
        with open(json_file, 'w') as fh:
            json.dump(result, fh, indent=4, ensure_ascii=False)
        parent.stepChanged.emit(f'BLACK|    Список системных DNS серверов выгружен в файл "{json_file}".')
    
    err, result = parent.utm.get_dns_rules()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        error = 1
        parent.error = 1
    else:
        for item in result:
            item.pop('id', None)
            item.pop('cc', None)
            item.pop('position_layer', None)
        json_file = os.path.join(path, 'config_dns_rules.json')
        with open(json_file, 'w') as fh:
            json.dump(result, fh, indent=4, ensure_ascii=False)
        parent.stepChanged.emit(f'BLACK|    Список правил DNS прокси выгружен в файл "{json_file}".')
    
    err, result = parent.utm.get_dns_static_records()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        error = 1
        parent.error = 1
    else:
        for item in result:
            item.pop('id', None)
            item.pop('cc', None)
        json_file = os.path.join(path, 'config_dns_static.json')
        with open(json_file, 'w') as fh:
            json.dump(result, fh, indent=4, ensure_ascii=False)
        parent.stepChanged.emit(f'BLACK|    Статические записи DNS прокси выгружены в файл "{json_file}".')

    out_message = f'GREEN|    Настройки DNS экспортированы в каталог "{path}".'
    parent.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте настроек DNS!' if error else out_message)


def export_vrf_list(parent, path):
    """Экспортируем настройки VRF"""
    parent.stepChanged.emit('BLUE|Экспорт настроек VRF раздела "Сеть/Виртуальные маршрутизаторы".')
    err, msg = create_dir(path)
    if err:
        parent.stepChanged.emit(f'RED|    {msg}')
        parent.error = 1
        return
    error = 0

    if parent.version >= 7.1:
        err, result = parent.utm.get_bfd_profiles()
        if err:
            parent.stepChanged.emit(f'RED|    {result}')
            parent.error = 1
            return
        bfd_profiles = {x['id']: x['name'] for x in result}
        bfd_profiles[-1] = -1

    err, data = parent.utm.get_routes_list()
    if err:
        parent.stepChanged.emit(f'RED|    {data}')
        parent.error = 1
        error = 1
    else:
        for item in data:
            item.pop('id', None)
            item.pop('node_name', None)
            item.pop('cc', None)
            for x in item['routes']:
                x.pop('id', None)
            route_maps = {}
            filters = {}
            item['bgp'].pop('id', None)
            if item['bgp']['as_number'] == "null":
                item['bgp']['as_number'] = 0
            if parent.version < 7:
                item['bgp']['as_number'] = int(item['bgp']['as_number'])
            for x in item['bgp']['routemaps']:
                route_maps[x['id']] = x['name']
                x.pop('id', None)
            for x in item['bgp']['filters']:
                filters[x['id']] = x['name']
                x.pop('id', None)
            for x in item['bgp']['neighbors']:
                x.pop('id', None)
                x.pop('state', None)
                x['remote_asn'] = int(x['remote_asn'])
                for i, rmap in enumerate(x['filter_in']):
                    x['filter_in'][i] = filters[rmap]
                for i, rmap in enumerate(x['filter_out']):
                    x['filter_out'][i] = filters[rmap]
                for i, rmap in enumerate(x['routemap_in']):
                    x['routemap_in'][i] = route_maps[rmap]
                for i, rmap in enumerate(x['routemap_out']):
                    x['routemap_out'][i] = route_maps[rmap]
                x['bfd_profile'] = -1 if parent.version < 7.1 else bfd_profiles[x['bfd_profile']]
            item['ospf'].pop('id', None)
            for x in item['ospf']['interfaces']:
                x['bfd_profile'] = -1 if parent.version < 7.1 else bfd_profiles[x['bfd_profile']]
            for x in item['ospf']['areas']:
                x.pop('id', None)
            item['rip'].pop('id', None)
            if not isinstance(item['rip']['default_originate'], bool):
                item['rip']['default_originate'] = True
            item['pimsm'].pop('id', None)

        json_file = os.path.join(path, 'config_vrf.json')
        with open(json_file, 'w') as fh:
            json.dump(data, fh, indent=4, ensure_ascii=False)

        out_message = f'GREEN|    Настройки VRF выгружены в файл "{json_file}".'
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте настроек VRF!' if error else out_message)

def export_routes(parent, path):
    """Экспортируем список маршрутов. Только версия 5."""
    parent.stepChanged.emit('BLUE|Экспорт списка маршрутов раздела "Сеть/Маршруты".')
    path = path.replace('Routes', 'VRF', 1)
    err, msg = create_dir(path)
    if err:
        parent.stepChanged.emit(f'RED|    {msg}')
        parent.error = 1
        return
    error = 0

    err, result = parent.utm.get_interfaces_list()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return
    else:
        iface_names = translate_iface_name(parent.version, path, result)     # Преобразуем имена интерфейсов для версии 5 из eth в port.

    routes = []
    err, data = parent.utm.get_routes_list()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        error = 1
    else:
        for item in data:
            item.pop('id', None)
            item.pop('node_name', None)
            if 'name' not in item.keys() or not item['name']:
                item['name'] = item['dest']
            item.pop('multihop', None)
            item.pop('vrf', None)
            item.pop('active', None)
            item['ifname'] = iface_names[item['iface_id']] if item['iface_id'] else 'undefined'
            item.pop('iface_id', None)
            item['kind'] = 'unicast'

        routes.append({
            'name': 'default',
            'description': '',
#            'interfaces': [],
            'routes': data,
            'ospf': {},
            'bgp': {},
            'rip': {},
            'pimsm': {},
        })

        json_file = os.path.join(path, 'config_vrf.json')
        with open(json_file, 'w') as fh:
            json.dump(routes, fh, indent=4, ensure_ascii=False)

        out_message = f'GREEN|    Список маршрутов выгружен в файл "{json_file}".'
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте списка маршрутов!' if error else out_message)


def export_ospf_config(parent, path):
    """Экспортируем конфигурацию OSPF (только для v.5)"""
    parent.stepChanged.emit('BLUE|Экспорт конфигурации OSPF раздела "Сеть/OSPF".')
    path = path.replace('OSPF', 'VRF', 1)
    json_file = os.path.join(path, 'config_vrf.json')
    error = 0

    err, msg = create_dir(path)
    if err:
        parent.stepChanged.emit(f'RED|    {msg}')
        parent.error = 1
        return

    if os.path.exists(json_file):
        try:
            with open(json_file, 'r') as fh:
                data = json.load(fh)
        except Exception as err:
            parent.stepChanged.emit(f'RED|    {err}')
            parent.error = 1
            return
    else:
        data = [{
            'name': 'default',
            'description': '',
            'routes': [],
            'ospf': {},
            'bgp': {},
            'rip': {},
            'pimsm': {},
        },]

    err, result = parent.utm.get_interfaces_list()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return
    else:
        iface_names = translate_iface_name(parent.version, path, result)     # Преобразуем имена интерфейсов для версии 5 из eth в port.

    err, ospf, ifaces, areas = parent.utm.get_ospf_config()
    if err:
        parent.stepChanged.emit(f'RED|    {ospf}')
        parent.error = 1
        error = 1
    else:
        ospf['enabled'] = False
        for item in ifaces:
            item['iface_id'], _ = item['iface_id'].split(':')
            item['iface_id'] = iface_names[item['iface_id']]
            item['auth_params'].pop('md5_key', None)
            item['auth_params'].pop('plain_key', None)
            item['bfd_profile'] = -1
        for item in areas:
            item.pop('id', None)
            item.pop('area_range', None)

        ospf['interfaces'] = ifaces
        ospf['areas'] = areas
        for item in data:
            if item['name'] == 'default':
                item['ospf'] = ospf
                with open(json_file, 'w') as fh:
                    json.dump(data, fh, indent=4, ensure_ascii=False)
                break

    out_message = f'GREEN|    Конфигурация OSPF выгружена в файл "{json_file}".'
    parent.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте конфигурации OSPF!' if error else out_message)


def export_bgp_config(parent, path):
    """Экспортируем конфигурацию BGP (только для v.5)"""
    parent.stepChanged.emit('BLUE|Экспорт конфигурации BGP раздела "Сеть/BGP".')
    path = path.replace('BGP', 'VRF', 1)
    json_file = os.path.join(path, 'config_vrf.json')
    error = 0

    err, msg = create_dir(path)
    if err:
        parent.stepChanged.emit(f'RED|    {msg}')
        parent.error = 1
        return

    if os.path.exists(json_file):
        try:
            with open(json_file, 'r') as fh:
                data = json.load(fh)
        except Exception as err:
            parent.stepChanged.emit(f'RED|    {err}')
            parent.error = 1
            return
    else:
        data = [{
            'name': 'default',
            'description': '',
            'routes': [],
            'ospf': {},
            'bgp': {},
            'rip': {},
            'pimsm': {},
        },]

    err, bgp, neigh, rmaps, filters = parent.utm.get_bgp_config()
    if err:
        parent.stepChanged.emit(f'RED|    {bgp}')
        parent.error = 1
        error = 1
    else:
        route_maps = {}
        bgp_filters = {}
        if bgp['as_number'] == 'null':
            bgp['as_number'] = 0
        else:
            bgp['as_number'] = int(bgp['as_number'])
        bgp.pop('id', None)
        bgp.pop('strict_ip', None)
        bgp.pop('multiple_asn', None)
        for item in rmaps:
            route_maps[item['id']] = item['name']
            item.pop('id', None)
            item.pop('position', None)
            item['match_items'] = [x[:-4] for x in item['match_items']]
        for item in filters:
            bgp_filters[item['id']] = item['name']
            item.pop('id', None)
            item.pop('position', None)
            item['filter_items'] = [x[:-4] for x in item['filter_items']]
        for item in neigh:
            item.pop('id', None)
            item.pop('iface_id', None)
            item.pop('state', None)
            item['remote_asn'] = int(item['remote_asn'])
            for i, fmap in enumerate(item['filter_in']):
                item['filter_in'][i] = bgp_filters[fmap]
            for i, fmap in enumerate(item['filter_out']):
                item['filter_out'][i] = bgp_filters[fmap]
            for i, fmap in enumerate(item['routemap_in']):
                item['routemap_in'][i] = route_maps[fmap]
            for i, fmap in enumerate(item['routemap_out']):
                item['routemap_out'][i] = route_maps[fmap]
            item['bfd_profile'] = -1
        bgp['routemaps'] = rmaps
        bgp['filters'] = filters
        bgp['neighbors'] = neigh
        for item in data:
            if item['name'] == 'default':
                item['bgp'] = bgp
                with open(json_file, 'w') as fh:
                    json.dump(data, fh, indent=4, ensure_ascii=False)
                break

    out_message = f'GREEN|    Конфигурация BGP выгружена в файл "{json_file}".'
    parent.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте конфигурации BGP!' if error else out_message)


def export_wccp(parent, path):
    """Экспортируем список правил WCCP"""
    parent.stepChanged.emit('BLUE|Экспорт списка правил WCCP из раздела "Сеть/WCCP".')
    err, msg = create_dir(path)
    if err:
        parent.stepChanged.emit(f'RED|    {msg}')
        parent.error = 1
        return
    error = 0

    err, data = parent.utm.get_wccp_list()
    if err:
        parent.stepChanged.emit(f'RED|    {data}')
        parent.error = 1
        error = 1
    else:
        for item in data:
            item['name'] = item['name'].strip().translate(trans_name)
            item['ports'] = [int(x) for x in item['ports']]
            item.pop('id', None)
            item.pop('cc', None)
            if item['routers']:
                for x in item['routers']:
                    x[1] = parent.ip_lists[x[1]] if x[0] == 'list_id' else x[1]

        json_file = os.path.join(path, 'config_wccp.json')
        with open(json_file, 'w') as fh:
            json.dump(data, fh, indent=4, ensure_ascii=False)

    out_message = f'GREEN|    Список правил WCCP выгружен в файл "{json_file}".'
    parent.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте списка правил WCCP!' if error else out_message)


def export_local_groups(parent, path):
    """Экспортируем список локальных групп пользователей"""
    parent.stepChanged.emit('BLUE|Экспорт списка локальных групп из раздела "Пользователи и устройства/Группы".')
    err, msg = create_dir(path)
    if err:
        parent.stepChanged.emit(f'RED|    {msg}')
        parent.error = 1
        return
    error = 0

    err, data = parent.utm.get_groups_list()
    if err:
        parent.stepChanged.emit(f'RED|    {data}')
        parent.error = 1
        error = 1
    else:
        for item in data:
            item['name'] = item['name'].strip().translate(trans_name)
            item.pop('cc', None)
            err, users = parent.utm.get_group_users(item['id'])
            if err:
                parent.stepChanged.emit(f'RED|    {users}')
                parent.error = 1
                error = 1
                item['users'] = []
            else:
                if parent.version < 6:
                    item['users'] = [x['name'] for x in users]
                else:
                    item['users'] = [x[1] for x in users]
            item.pop('id', None)

        json_file = os.path.join(path, 'config_groups.json')
        with open(json_file, 'w') as fh:
            json.dump(data, fh, indent=4, ensure_ascii=False)

    out_message = f'GREEN|    Список локальных групп выгружен в файл "{json_file}".'
    parent.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте списка локальных групп!' if error else out_message)


def export_local_users(parent, path):
    """Экспортируем список локальных пользователей"""
    parent.stepChanged.emit('BLUE|Экспорт списка локальных пользователей из раздела "Пользователи и устройства/Пользователи".')
    err, msg = create_dir(path)
    if err:
        parent.stepChanged.emit(f'RED|    {msg}')
        parent.error = 1
        return
    error = 0

    err, data = parent.utm.get_users_list()
    if err:
        parent.stepChanged.emit(f'RED|    {data}')
        parent.error = 1
        error = 1
    else:
        for item in data:
            item.pop('icap_clients', None)
            item.pop('creation_date', None)
            item.pop('expiration_date', None)
            item.pop('cc', None)
            if not item['first_name']:
                item['first_name'] = ""
            if not item['last_name']:
                item['last_name'] = ""
            item['groups'] = [parent.list_groups[guid] for guid in item['groups']]

        json_file = os.path.join(path, 'config_users.json')
        with open(json_file, 'w') as fh:
            json.dump(data, fh, indent=4, ensure_ascii=False)

    out_message = f'GREEN|    Список локальных пользователей выгружен в файл "{json_file}".'
    parent.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте списка локальных пользователей!' if error else out_message)


def export_auth_servers(parent, path):
    """Экспортируем список серверов аутентификации"""
    parent.stepChanged.emit('BLUE|Экспорт списка серверов аутентификации из раздела "Пользователи и устройства/Серверы аутентификации".')
    err, msg = create_dir(path)
    if err:
        parent.stepChanged.emit(f'RED|    {msg}')
        parent.error = 1
        return
    error = 0

    err, ldap, radius, tacacs, ntlm, saml = parent.utm.get_auth_servers()
    if err:
        parent.stepChanged.emit(f'RED|    {ldap}')
        parent.error = 1
        error = 1
    else:
        json_file = os.path.join(path, 'config_ldap_servers.json')
        with open(json_file, 'w') as fh:
            json.dump(ldap, fh, indent=4, ensure_ascii=False)
        parent.stepChanged.emit(f'BLACK|    Список серверов LDAP выгружен в файл "{json_file}".')

        json_file = os.path.join(path, 'config_radius_servers.json')
        with open(json_file, 'w') as fh:
            json.dump(radius, fh, indent=4, ensure_ascii=False)
        parent.stepChanged.emit(f'BLACK|    Список серверов RADIUS выгружен в файл "{json_file}".')

        json_file = os.path.join(path, 'config_tacacs_servers.json')
        with open(json_file, 'w') as fh:
            json.dump(tacacs, fh, indent=4, ensure_ascii=False)
        parent.stepChanged.emit(f'BLACK|    Список серверов TACACS выгружен в файл "{json_file}".')

        json_file = os.path.join(path, 'config_ntlm_servers.json')
        with open(json_file, 'w') as fh:
            json.dump(ntlm, fh, indent=4, ensure_ascii=False)
        parent.stepChanged.emit(f'BLACK|    Список серверов NTLM выгружен в файл "{json_file}".')

        for item in saml:
            item['certificate_id'] = parent.ngfw_certs.get(item['certificate_id'], 0)
        json_file = os.path.join(path, 'config_saml_servers.json')
        with open(json_file, 'w') as fh:
            json.dump(saml, fh, indent=4, ensure_ascii=False)
        parent.stepChanged.emit(f'BLACK|    Список серверов SAML выгружен в файл "{json_file}".')

    out_message = f'GREEN|    Список серверов аутентификации экспортирован успешно.'
    parent.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте списка серверов аутентификации!' if error else out_message)


def export_2fa_profiles(parent, path):
    """Экспортируем список 2FA профилей"""
    parent.stepChanged.emit('BLUE|Экспорт списка 2FA профилей из раздела "Пользователи и устройства/Профили MFA".')
    err, msg = create_dir(path)
    if err:
        parent.stepChanged.emit(f'RED|    {msg}')
        parent.error = 1
        return
    error = 0

    err, result = parent.utm.get_notification_profiles_list()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return
    list_notifications = {x['id']: x['name'].strip().translate(trans_name) for x in result}

    err, data = parent.utm.get_2fa_profiles()
    if err:
        parent.stepChanged.emit(f'RED|    {data}')
        parent.error = 1
        error = 1
    else:
        for item in data:
            item.pop('id', None)
            item.pop('cc', None)
            item['name'] = item['name'].strip().translate(trans_name)
            if item['type'] == 'totp':
                item['init_notification_profile_id'] = list_notifications.get(item['init_notification_profile_id'], item['init_notification_profile_id'])
                item.pop('auth_notification_profile_id', None)
            else:
                item['auth_notification_profile_id'] = list_notifications.get(item['auth_notification_profile_id'], item['auth_notification_profile_id'])
                item.pop('init_notification_profile_id', None)

        json_file = os.path.join(path, 'config_2fa_profiles.json')
        with open(json_file, 'w') as fh:
            json.dump(data, fh, indent=4, ensure_ascii=False)

    out_message = f'GREEN|    Список 2FA профилей выгружен в файл "{json_file}".'
    parent.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте списка 2FA профилей!' if error else out_message)


def export_auth_profiles(parent, path):
    """Экспортируем список профилей аутентификации"""
    parent.stepChanged.emit('BLUE|Экспорт списка профилей авторизации из раздела "Пользователи и устройства/Профили аутентификации".')
    err, msg = create_dir(path)
    if err:
        parent.stepChanged.emit(f'RED|    {msg}')
        parent.error = 1
        return
    error = 0

    err, ldap, radius, tacacs, ntlm, saml = parent.utm.get_auth_servers()
    if err:
        parent.stepChanged.emit(f'RED|    {ldap}')
        parent.error = 1
        return
    auth_servers = {x['id']: x['name'].strip().translate(trans_name) for x in [*ldap, *radius, *tacacs, *ntlm, *saml]}

    err, result = parent.utm.get_2fa_profiles()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return
    profiles_2fa = {x['id']: x['name'].strip().translate(trans_name) for x in result}

    err, data = parent.utm.get_auth_profiles()
    if err:
        parent.stepChanged.emit(f'RED|    {data}')
        parent.error = 1
        error = 1
    else:
        for item in data:
            item.pop('id', None)
            item.pop('cc', None)
            item['name'] = item['name'].strip().translate(trans_name)
            item['2fa_profile_id'] = profiles_2fa.get(item['2fa_profile_id'], False)
            for auth_method in item['allowed_auth_methods']:
                if len(auth_method) == 2:
                    if 'saml_idp_server' in auth_method:
                        auth_method['saml_idp_server_id'] = auth_method.pop('saml_idp_server', False)
                    for key, value in auth_method.items():
                        if isinstance(value, int):
                            auth_method[key] = auth_servers[value]

        json_file = os.path.join(path, 'config_auth_profiles.json')
        with open(json_file, 'w') as fh:
            json.dump(data, fh, indent=4, ensure_ascii=False)

    out_message = f'GREEN|    Список профилей аутентификации выгружен в файл "{json_file}".'
    parent.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте профилей аутентификации!' if error else out_message)


def export_captive_profiles(parent, path):
    """Экспортируем список Captive-профилей"""
    parent.stepChanged.emit('BLUE|Экспорт списка Captive-профилей из раздела "Пользователи и устройства/Captive-профили".')
    err, msg = create_dir(path)
    if err:
        parent.stepChanged.emit(f'RED|    {msg}')
        parent.error = 1
        return
    error = 0

    err, result = parent.utm.get_templates_list()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return
    list_templates = {x['id']: x['name'] for x in result}

    err, result = parent.utm.get_notification_profiles_list()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return
    list_notifications = {x['id']: x['name'].strip().translate(trans_name) for x in result}

    if (6 <= parent.version < 7.1):
        result = parent.utm._server.v3.accounts.groups.list(parent.utm._auth_token, 0, 1000, {}, [])['items']
        list_groups = {x['id']: x['name'].strip().translate(trans_name) for x in result}

    if parent.version >= 7.1:
        err, result = parent.utm.get_client_certificate_profiles()
        if err:
            parent.stepChanged.emit(f'RED|    {result}')
            parent.error = 1
            return
        client_cert_profiles = {x['id']: x['name'] for x in result}

    err, data = parent.utm.get_captive_profiles()
    if err:
        parent.stepChanged.emit(f'RED|    {data}')
        parent.error = 1
        error = 1
    else:
        for item in data:
            item['name'] = item['name'].strip().translate(trans_name)
            item['captive_template_id'] = list_templates.get(item['captive_template_id'], -1)
            item['notification_profile_id'] = list_notifications.get(item['notification_profile_id'], -1)
            item['user_auth_profile_id'] = parent.auth_profiles[item['user_auth_profile_id']]
            if (6 <= parent.version < 7.1):
                item['ta_groups'] = [list_groups[guid] for guid in item['ta_groups']]
            else:
                item['ta_groups'] = [parent.list_groups[guid] for guid in item['ta_groups']]
            if parent.version < 6:
                item['ta_expiration_date'] = ''
            else:
                if item['ta_expiration_date']:
                    item['ta_expiration_date'] = dt.strptime(item['ta_expiration_date'].value, "%Y-%m-%dT%H:%M:%SZ").strftime("%Y-%m-%d %H:%M:%S")
            if parent.version >= 7.1:
                item['use_https_auth'] = True
                item['client_certificate_profile_id'] = client_cert_profiles.get(item['client_certificate_profile_id'], 0)
            else:
                item['captive_auth_mode'] = 'aaa'
                item['client_certificate_profile_id'] = 0
            item.pop('id', None)  # это есть в версии 5
            item.pop('guid', None)  # это есть в версии 6 и выше
            item.pop('cc', None)

        json_file = os.path.join(path, 'config_captive_profiles.json')
        with open(json_file, 'w') as fh:
            json.dump(data, fh, indent=4, ensure_ascii=False)

    out_message = f'GREEN|    Список Captive-профилей выгружен в файл "{json_file}".'
    parent.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте Captive-профилей.' if error else out_message)


def export_captive_portal_rules(parent, path):
    """Экспортируем список правил Captive-портала"""
    parent.stepChanged.emit('BLUE|Экспорт списка правил Captive-портала из раздела "Пользователи и устройства/Captive-портал".')
    err, msg = create_dir(path)
    if err:
        parent.stepChanged.emit(f'RED|    {msg}')
        parent.error = 1
        return
    error = 0

    err, result = parent.utm.get_captive_profiles()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return
    captive_profiles = {x['id']: x['name'].strip().translate(trans_name) for x in result}

    err, data = parent.utm.get_captive_portal_rules()
    if err:
        parent.stepChanged.emit(f'RED|    {data}')
        parent.error = 1
        error = 1
    else:
        for item in data:
            item['name'] = item['name'].strip().translate(trans_name)
            item.pop('id', None)
            item.pop('guid', None)
            item.pop('rownumber', None)
            item.pop('position_layer', None),
            item.pop('time_created', None)
            item.pop('time_updated', None)
            item['profile_id'] = captive_profiles.get(item['profile_id'], 0)
            item['src_zones'] = get_zones_name(parent, item['src_zones'], item['name'])
            item['dst_zones'] = get_zones_name(parent, item['dst_zones'], item['name'])
            item['src_ips'] = get_ips_name(parent, item['src_ips'], item['name'])
            item['dst_ips'] = get_ips_name(parent, item['dst_ips'], item['name'])
            item['urls'] = get_urls_name(parent, item['urls'], item['name'])
            item['url_categories'] = get_url_categories_name(parent, item['url_categories'], item['name'])
            item['time_restrictions'] = get_time_restrictions_name(parent, item['time_restrictions'], item['name'])

        json_file = os.path.join(path, 'config_captive_portal_rules.json')
        with open(json_file, 'w') as fh:
            json.dump(data, fh, indent=4, ensure_ascii=False)

    out_message = f'GREEN|    Список правил Captive-портала выгружен в файл "{json_file}".'
    parent.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте правил Captive-портала.' if error else out_message)


def export_terminal_servers(parent, path):
    """Экспортируем список терминальных серверов"""
    parent.stepChanged.emit('BLUE|Экспорт списка терминальных серверов из раздела "Пользователи и устройства/Терминальные серверы".')
    err, msg = create_dir(path)
    if err:
        parent.stepChanged.emit(f'RED|    {msg}')
        parent.error = 1
        return
    error = 0

    err, data = parent.utm.get_terminal_servers()
    if err:
        parent.stepChanged.emit(f'RED|    {data}')
        parent.error = 1
        error = 1
    else:
        for item in data:
            item['name'] = item['name'].strip().translate(trans_name)
            item.pop('id', None)
            item.pop('guid', None)
            item.pop('cc', None)

        json_file = os.path.join(path, 'config_terminal_servers.json')
        with open(json_file, 'w') as fh:
            json.dump(data, fh, indent=4, ensure_ascii=False)

    out_message = f'GREEN|    Список терминальных серверов выгружен в файл "{json_file}".'
    parent.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте списка терминальных серверов.' if error else out_message)


def export_byod_policy(parent, path):
    """Экспортируем список Политики BYOD"""
    parent.stepChanged.emit('BLUE|Экспорт списка Политики BYOD из раздела "Пользователи и устройства/Политики BYOD".')
    err, msg = create_dir(path)
    if err:
        parent.stepChanged.emit(f'RED|    {msg}')
        parent.error = 1
        return
    error = 0

    err, data = parent.utm.get_byod_policy()
    if err:
        parent.stepChanged.emit(f'RED|    {data}')
        parent.error = 1
        error = 1
    else:
        for item in data:
            item['name'] = item['name'].strip().translate(trans_name)
            item.pop('id', None)
            item.pop('position_layer', None)
            item.pop('deleted_users', None)
            item['users'] = get_names_users_and_groups(parent, item['users'], item['name'])

        json_file = os.path.join(path, 'config_byod_policy.json')
        with open(json_file, 'w') as fh:
            json.dump(data, fh, indent=4, ensure_ascii=False)

    out_message = f'GREEN|    Список "Политики BYOD" выгружен в файл "{json_file}".'
    parent.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте списка "Политики BYOD".' if error else out_message)


def export_userid_agent(parent, path):
    """Экспортируем настройки UserID агент"""
    parent.stepChanged.emit('BLUE|Экспорт настроек UserID агент из раздела "Пользователи и устройства/UserID агент".')
    err, msg = create_dir(path)
    if err:
        parent.stepChanged.emit(f'RED|    {msg}')
        parent.error = 1
        return
    error = 0

    err, result = parent.utm.get_useridagent_filters()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return
    useridagent_filters = {x['id']: x['name'] for x in result}

    err, data = parent.utm.get_useridagent_servers()
    if err:
        parent.stepChanged.emit(f'RED|    {data}')
        parent.error = 1
        error = 1
    else:
        for item in data:
            item.pop('id', None)
            item.pop('status', None)
            item.pop('cc', None)
            item['auth_profile_id'] = parent.auth_profiles[item['auth_profile_id']]
            if 'filters' in item:
                item['filters'] = [useridagent_filters[x] for x in item['filters']]

        json_file = os.path.join(path, 'userid_agent_servers.json')
        with open(json_file, 'w') as fh:
            json.dump(data, fh, indent=4, ensure_ascii=False)

    err, data = parent.utm.get_useridagent_config()
    if err:
        parent.stepChanged.emit(f'RED|    {data}')
        parent.error = 1
        error = 1
    else:
        data.pop('cc', None)
        data['tcp_ca_certificate_id'] = parent.ngfw_certs[data['tcp_ca_certificate_id']]
        data['tcp_server_certificate_id'] = parent.ngfw_certs[data['tcp_server_certificate_id']]
        data['ignore_networks'] = [['list_id', parent.ip_lists[x[1]]] for x in data['ignore_networks']]

        json_file = os.path.join(path, 'userid_agent_config.json')
        with open(json_file, 'w') as fh:
            json.dump(data, fh, indent=4, ensure_ascii=False)

    out_message = f'GREEN|    Настройки UserID агент выгружены в каталог "{path}".'
    parent.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте настроек UserID агент.' if error else out_message)


def export_firewall_rules(parent, path):
    """Экспортируем список правил межсетевого экрана"""
    parent.stepChanged.emit('BLUE|Экспорт правил межсетевого экрана из раздела "Политики сети/Межсетевой экран".')
    err, msg = create_dir(path)
    if err:
        parent.stepChanged.emit(f'RED|    {msg}')
        parent.error = 1
        return
    error = 0

    if not parent.l7_apps:
        err = set_apps_values(parent)
        if err:
            parent.error = 1
            return

    if not parent.scenarios_rules:
        err = set_scenarios_rules(parent)
        if err:
            parent.error = 1
            return

    if parent.version >= 7.1:
        err, result = parent.utm.get_idps_profiles_list()
        if err:
            parent.stepChanged.emit(f'RED|    {result}')
            parent.error = 1
            return
        idps_profiles = {x['id']: x['name'] for x in result}

        err, result = parent.utm.get_l7_profiles_list()
        if err:
            parent.stepChanged.emit(f'RED|    {result}')
            parent.error = 1
            return
        l7_profiles = {x['id']: x['name'] for x in result}

        err, result = parent.utm.get_hip_profiles_list()
        if err:
            parent.stepChanged.emit(f'RED|    {result}')
            parent.error = 1
            return
        hip_profiles = {x['id']: x['name'] for x in result}

    duplicate = {}
    err, data = parent.utm.get_firewall_rules()
    if err:
        parent.stepChanged.emit(f'RED|    {data}')
        parent.error = 1
        error = 1
    else:
        for item in data:
            item['name'] = item['name'].strip().translate(trans_name)
            if item['name'] in duplicate.keys():
                num = duplicate[item['name']]
                num = num + 1
                duplicate[item['name']] = num
                item['name'] = f"{item['name']} {num}"
            else:
                duplicate[item['name']] = 0
            item.pop('id', None)
            item.pop('guid', None)
            item.pop('rownumber', None)
            item.pop('active', None)
            item.pop('deleted_users', None)

            if item['scenario_rule_id']:
                item['scenario_rule_id'] = parent.scenarios_rules[item['scenario_rule_id']]
            item['src_zones'] = get_zones_name(parent, item['src_zones'], item['name'])
            item['dst_zones'] = get_zones_name(parent, item['dst_zones'], item['name'])
            item['src_ips'] = get_ips_name(parent, item['src_ips'], item['name'])
            item['dst_ips'] = get_ips_name(parent, item['dst_ips'], item['name'])
            item['services'] = get_services(parent, item['services'], item['name'])
            item['users'] = get_names_users_and_groups(parent, item['users'], item['name'])
            item['time_restrictions'] = get_time_restrictions_name(parent, item['time_restrictions'], item['name'])
            if 'apps' in item:
                item['apps'] = get_apps(parent, item['apps'], item['name'])
            if 'ips_profile' in item and item['ips_profile']:
                item['ips_profile'] = idps_profiles[item['ips_profile']]
            if 'l7_profile' in item and item['l7_profile']:
                item['l7_profile'] = l7_profiles[item['l7_profile']]
            if 'hip_profiles' in item:
                item['hip_profiles'] = [hip_profiles[x] for x in item['hip_profiles']]

        json_file = os.path.join(path, 'config_firewall_rules.json')
        with open(json_file, 'w') as fh:
            json.dump(data, fh, indent=4, ensure_ascii=False)

    out_message = f'GREEN|    Правила межсетевого экрана выгружены в файл "{json_file}".'
    parent.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте правил межсетевого экрана.' if error else out_message)


def export_nat_rules(parent, path):
    """Экспортируем список правил NAT"""
    parent.stepChanged.emit('BLUE|Экспорт правил NAT из раздела "Политики сети/NAT и маршрутизация".')
    err, msg = create_dir(path)
    if err:
        parent.stepChanged.emit(f'RED|    {msg}')
        parent.error = 1
        return
    error = 0

    err, result = parent.utm.get_gateways_list()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        error = 1
    ngfw_gateways = {f'{x["id"]}:{x["node_name"]}': x['name'] for x in result if 'name' in x}

    if not parent.scenarios_rules:
        err = set_scenarios_rules(parent)
        if err:
            parent.error = 1
            return

    err, data = parent.utm.get_traffic_rules()
    if err:
        parent.stepChanged.emit(f'RED|    {data}')
        parent.error = 1
        error = 1
    else:
        for item in data:
            item.pop('id', None)
            item.pop('cc', None)
            item.pop('guid', None)
            item['name'] = item['name'].strip().translate(trans_name)
            if item['scenario_rule_id']:
                item['scenario_rule_id'] = parent.scenarios_rules[item['scenario_rule_id']]
            item['zone_in'] = get_zones_name(parent, item['zone_in'], item['name'])
            item['zone_out'] = get_zones_name(parent, item['zone_out'], item['name'])
            item['source_ip'] = get_ips_name(parent, item['source_ip'], item['name'])
            item['dest_ip'] = get_ips_name(parent, item['dest_ip'], item['name'])
            item['service'] = get_services(parent, item['service'], item['name'])
            item['gateway'] = ngfw_gateways.get(item['gateway'], item['gateway'])
            if parent.version >= 6:
                item['users'] = get_names_users_and_groups(parent, item['users'], item['name'])
            else:
                item['users'] = []
                item['position_layer'] = 'local'
                item['time_created'] = ''
                item['time_updated'] = ''

        json_file = os.path.join(path, 'config_nat_rules.json')
        with open(json_file, 'w') as fh:
            json.dump(data, fh, indent=4, ensure_ascii=False)

    out_message = f'GREEN|    Правила NAT выгружены в файл "{json_file}".'
    parent.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте правил NAT.' if error else out_message)


def export_loadbalancing_rules(parent, path):
    """Экспортируем список правил балансировки нагрузки"""
    parent.stepChanged.emit('BLUE|Экспорт правил балансировки нагрузки из раздела "Политики сети/Балансировка нагрузки".')
    err, msg = create_dir(path)
    if err:
        parent.stepChanged.emit(f'RED|    {msg}')
        parent.error = 1
        return
    error = 0

    err, result = parent.utm.get_icap_servers()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return
    icap_servers = {x['id']: x['name'].strip().translate(trans_name) for x in result}

    err, result = parent.utm.get_reverseproxy_servers()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return
    reverse_servers = {x['id']: x['name'].strip().translate(trans_name) for x in result}

    err, tcpudp, icap, reverse = parent.utm.get_loadbalancing_rules()
    if err:
        parent.stepChanged.emit(f'RED|    {tcpudp}')
        parent.error = 1
        error = 1
    else:
        for item in tcpudp:
            item.pop('id', None)
            item.pop('guid', None)
            item.pop('cc', None)
            item['name'] = item['name'].strip().translate(trans_name)
            if parent.version < 7.1:
                item['src_zones'] = []
                item['src_zones_negate'] = False
                item['src_ips'] = []
                item['src_ips_negate'] = False
            else:
                item['src_zones'] = get_zones_name(parent, item['src_zones'], item['name'])
                item['src_ips'] = get_ips_name(parent, item['src_ips'], item['name'])
        json_file = os.path.join(path, 'config_loadbalancing_tcpudp.json')
        with open(json_file, 'w') as fh:
            json.dump(tcpudp, fh, indent=4, ensure_ascii=False)
        parent.stepChanged.emit(f'BLACK|    Список балансировщиков TCP/UDP выгружен в файл "{json_file}".')

        for item in icap:
            item.pop('id', None)
            item.pop('cc', None)
            item['name'] = item['name'].strip().translate(trans_name)
            item['profiles'] = [icap_servers[x] for x in item['profiles']]
        json_file = os.path.join(path, 'config_loadbalancing_icap.json')
        with open(json_file, 'w') as fh:
            json.dump(icap, fh, indent=4, ensure_ascii=False)
        parent.stepChanged.emit(f'BLACK|    Список балансировщиков ICAP выгружен в файл "{json_file}".')

        for item in reverse:
            item.pop('id', None)
            item.pop('cc', None)
            item['name'] = item['name'].strip().translate(trans_name)
            item['profiles'] = [reverse_servers[x] for x in item['profiles']]
        json_file = os.path.join(path, 'config_loadbalancing_reverse.json')
        with open(json_file, 'w') as fh:
            json.dump(reverse, fh, indent=4, ensure_ascii=False)
        parent.stepChanged.emit(f'BLACK|    Список балансировщиков reverse-прокси выгружен в файл "{json_file}".')

    out_message = f'GREEN|    Правила балансировки нагрузки выгружены в каталог "{path}".'
    parent.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте правил балансировки нагрузки.' if error else out_message)


def export_shaper_rules(parent, path):
    """Экспортируем список правил пропускной способности"""
    parent.stepChanged.emit('BLUE|Экспорт правил пропускной способности из раздела "Политики сети/Пропускная способность".')
    err, msg = create_dir(path)
    if err:
        parent.stepChanged.emit(f'RED|    {msg}')
        parent.error = 1
        return
    error = 0

    if not parent.l7_apps:
        err = set_apps_values(parent)
        if err:
            parent.error = 1
            return

    if not parent.scenarios_rules:
        err = set_scenarios_rules(parent)
        if err:
            parent.error = 1
            return

    err, result = parent.utm.get_shaper_list()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return
    shaper_list = {x['id']: x['name'].strip().translate(trans_name) for x in result}

    err, data = parent.utm.get_shaper_rules()
    if err:
        parent.stepChanged.emit(f'RED|    {data}')
        parent.error = 1
        error = 1
    else:
        for item in data:
            item.pop('id', None)
            item.pop('rownumber', None)
            item.pop('guid', None)
            item.pop('deleted_users', None)
            item.pop('active', None)
            item['name'] = item['name'].strip().translate(trans_name)
            if item['scenario_rule_id']:
                item['scenario_rule_id'] = parent.scenarios_rules[item['scenario_rule_id']]
            item['src_zones'] = get_zones_name(parent, item['src_zones'], item['name'])
            item['dst_zones'] = get_zones_name(parent, item['dst_zones'], item['name'])
            item['src_ips'] = get_ips_name(parent, item['src_ips'], item['name'])
            item['dst_ips'] = get_ips_name(parent, item['dst_ips'], item['name'])
            item['services'] = get_services(parent, item['services'], item['name'])
            item['users'] = get_names_users_and_groups(parent, item['users'], item['name'])
            item['apps'] = get_apps(parent, item['apps'], item['name'])
            item['time_restrictions'] = get_time_restrictions_name(parent, item['time_restrictions'], item['name'])
            item['pool'] = shaper_list[item['pool']]
            if parent.version < 6:
                item['position_layer'] = 'local'
                item['limit'] = True
                item['limit_value'] = '3/h'
                item['limit_burst'] = 5
                item['log'] = False
                item['log_session_start'] = True

        json_file = os.path.join(path, 'config_shaper_rules.json')
        with open(json_file, 'w') as fh:
            json.dump(data, fh, indent=4, ensure_ascii=False)

    out_message = f'GREEN|    Правила пропускной способности выгружены в файл "{json_file}".'
    parent.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте правил пропускной способности.' if error else out_message)


def pass_function(parent, path):
    """Функция заглушка"""
    parent.stepChanged.emit(f'GRAY|Экспорт раздела "{path.rpartition("/")[2]}" в настоящее время не реализован.')


func = {
    'GeneralSettings':  export_general_settings,
    'DeviceManagement': pass_function,
    'Administrators': pass_function,
    'Certificates': export_certificates,
    'UserCertificateProfiles': export_users_certificate_profiles,
    'Zones': export_zones,
    'Interfaces': export_interfaces_list,
    'Gateways': export_gateways_list,
    'DHCP': export_dhcp_subnets,
    'DNS': export_dns_config,
    'VRF': export_vrf_list,
    'WCCP': export_wccp,
    'Routes': export_routes,
    'OSPF': export_ospf_config,
    'BGP': export_bgp_config,
    'Groups': export_local_groups,
    'Users': export_local_users,
    'AuthServers': export_auth_servers,
    'AuthProfiles': export_auth_profiles,
    'CaptivePortal': export_captive_portal_rules,
    'CaptiveProfiles': export_captive_profiles,
    'TerminalServers': export_terminal_servers,
    'MFAProfiles': export_2fa_profiles,
    'UserIDagent': export_userid_agent,
    'BYODPolicies': export_byod_policy,
    'BYODDevices': pass_function,
    'Firewall': export_firewall_rules,
    'NATandRouting': export_nat_rules,
    'LoadBalancing': export_loadbalancing_rules,
    'TrafficShaping': export_shaper_rules,
}


def import_services(parent):
    """Импортируем список сервисов раздела библиотеки"""
    parent.stepChanged.emit('0|Импорт списка сервисов в раздел "Библиотеки/Сервисы"')

    json_file = "data_ug/Libraries/Services/config_services.json"
    err, data = read_json_file(json_file, '2|Ошибка импорта списка сервисов!', '2|Нет сервисов для импорта.')
    if err:
        parent.stepChanged.emit(data)
        parent.error = 1
        return

    err, result = parent.utm.get_services_list()
    if err:
        parent.stepChanged.emit(f'1|{result}')
        parent.error = 1
        return
    services_list = {x['name']: x['id'] for x in result}
    error = 0
    
    for item in data:
        if item['name'] in services_list:
            parent.stepChanged.emit(f'2|Сервис "{item["name"]}" уже существует.')
        else:
            err, result = parent.utm.add_service(item)
            if err:
                parent.stepChanged.emit(f'{err}|{result}')
                if err == 1:
                    error = 1
                    parent.error = 1
            else:
                services_list[item['name']] = result
                parent.stepChanged.emit(f'2|Сервис "{item["name"]}" добавлен.')

    out_message = '5|Список сервисов импортирован в раздел "Библиотеки/Сервисы"'
    parent.stepChanged.emit('6|Произошла ошибка при добавлении сервисов!' if error else out_message)

def import_services_groups(parent):
    """Импортируем группы сервисов в раздел Библиотеки/Группы сервисов"""
    parent.stepChanged.emit('0|Импорт групп сервисов раздела "Библиотеки/Группы сервисов".')

    if int(parent.utm.version[:1]) < 7:
        parent.stepChanged.emit('1|Ошибка! Импорт групп сервисов возможен только на версию 7 или выше.')
        return
        
    err, result = parent.utm.get_services_list()
    if err:
        parent.stepChanged.emit(f'1|{result}')
        parent.error = 1
        return
    services_list = {x['name']: x['id'] for x in result}

    err, result = parent.utm.get_nlists_list('servicegroup')
    if err:
        parent.stepChanged.emit(f'1|{result}')
        parent.error = 1
        return
    srv_groups = {x['name']: x['id'] for x in result}

    out_message = '5|Группы сервисов импортированы в раздел "Библиотеки/Группы сервисов".'
    error = 0
    
    if os.path.isdir('data_ug/Libraries/ServicesGroups'):
        files_list = os.listdir('data_ug/Libraries/ServicesGroups')
        if files_list:
            for file_name in files_list:
                json_file = f"data_ug/Libraries/ServicesGroups/{file_name}"
                err, services_group = read_json_file(json_file, '2|Ошибка импорта группы сервисов!', '2|Нет группы сервисов для импорта.')
                if err:
                    parent.stepChanged.emit(services_group)
                    parent.error = 1
                    return

                content = services_group.pop('content')
                err, result = parent.utm.add_nlist(services_group)
                if err:
                    parent.stepChanged.emit(f'{err}|{result}')
                    if err == 1:
                        parent.stepChanged.emit(f'1|Ошибка! Группа сервисов "{services_group["name"]}" не импортирована.')
                        error = 1
                        continue
                else:
                    parent.stepChanged.emit(f'2|Добавлена группа сервисов: "{services_group["name"]}".')
                    srv_groups[services_group['name']] = result
                if content:
                    for item in content:
                        try:
                            item['value'] = services_list[item['name']]
                        except KeyError:
                            parent.stepChanged.emit(f'4|   Ошибка! Нет сервиса "{item["name"]}" в списке сервисов NGFW.')
                            parent.stepChanged.emit(f'4|   Ошибка! Сервис "{item["name"]}" не добавлен в группу сервисов "{services_group["name"]}".')
                    err2, result2 = parent.utm.add_nlist_items(srv_groups[services_group['name']], content)
                    if err2:
                        parent.stepChanged.emit(f'{err2}|   {result2}')
                        if err2 == 1:
                            error = 1
                    else:
                        parent.stepChanged.emit(f'2|   Содержимое группы сервисов "{services_group["name"]}" обновлено.')
                else:
                    parent.stepChanged.emit(f'2|   Список "{services_group["name"]}" пуст.')
        else:
            out_message = "2|Нет групп сервисов для импорта."
    else:
        out_message = "2|Нет групп сервисов для импорта."
    if error:
        parent.error = 1
    parent.stepChanged.emit('6|Произошла ошибка при добавлении групп сервисов!' if error else out_message)

def import_ip_lists(parent):
    """Импортируем списки IP адресов"""
    parent.stepChanged.emit('0|Импорт списков IP-адресов раздела "Библиотеки/IP-адреса".')

    if not os.path.isdir('data_ug/Libraries/IPAddresses'):
        parent.stepChanged.emit("2|Нет списков IP-адресов для импорта.")
        return

    files_list = os.listdir('data_ug/Libraries/IPAddresses')
    if not files_list:
        parent.stepChanged.emit("2|Нет списков IP-адресов для импорта.")
        return

    error = 0
    err, result = parent.utm.get_nlists_list('network')
    if err:
        parent.stepChanged.emit(f'1|{result}')
        parent.error = 1
        return
    ngfw_ip_lists = {x['name']: x['id'] for x in result}

    # Добаляем списки IP-адресов без содержимого (пустые).
    for file_name in files_list:
        json_file = f"data_ug/Libraries/IPAddresses/{file_name}"
        err, ip_list = read_json_file(json_file, '2|Ошибка импорта списка IP-адресов!', '2|Нет списка IP-адресов для импорта.')
        if err:
            parent.stepChanged.emit(ip_list)
            parent.error = 1
            return

        content = ip_list.pop('content')
        err, result = parent.utm.add_nlist(ip_list)
        if err:
            parent.stepChanged.emit(f'{err}|{result}')
            if err == 1:
                parent.stepChanged.emit(f'1|Ошибка! Список IP-адресов "{ip_list["name"]}" не импортирован.')
                error = 1
                continue
        else:
            ngfw_ip_lists[ip_list['name']] = result
            parent.stepChanged.emit(f'2|Добавлен список IP-адресов: "{ip_list["name"]}".')

    # Добавляем содержимое в уже добавленные списки IP-адресов.
    for file_name in files_list:
        with open(f"data_ug/Libraries/IPAddresses/{file_name}", "r") as fh:
            ip_list = json.load(fh)
        content = ip_list.pop('content')
        if content:
            for item in content:
                if 'list' in item:
                    try:
                        item['list'] = ngfw_ip_lists[item['list'][1]]
                    except KeyError:
                        parent.stepChanged.emit(f'4|   Ошибка! Нет IP-листа "{item["list"][1]}" в списках IP-адресов NGFW.')
                        parent.stepChanged.emit(f'4|   Ошибка! Содержимое не добавлено в список IP-адресов "{ip_list["name"]}".')
                        error = 1
                        break
            try:
                named_list_id = ngfw_ip_lists[ip_list['name']]
            except KeyError:
                parent.stepChanged.emit(f'4|   Ошибка! Нет IP-листа "{ip_list["name"]}" в списках IP-адресов NGFW.')
                parent.stepChanged.emit(f'4|   Ошибка! Содержимое не добавлено в список IP-адресов "{ip_list["name"]}".')
                error = 1
                continue
            err2, result2 = parent.utm.add_nlist_items(named_list_id, content)
            if err2:
                parent.stepChanged.emit(f'{err2}|   {result2}')
                if err2 == 1:
                    error = 1
            else:
                parent.stepChanged.emit(f'2|Содержимое списка "{ip_list["name"]}" обновлено.')
        else:
            parent.stepChanged.emit(f'2|Список "{ip_list["name"]}" пуст.')

    if error:
        parent.error = 1
    out_message = '5|Списки IP-адресов импортированы в раздел "Библиотеки/IP-адреса".'
    parent.stepChanged.emit('6|Произошла ошибка при импорте списков IP-адресов!' if error else out_message)

def import_url_lists(parent):
    """Импортировать списки URL на UTM"""
    parent.stepChanged.emit('0|Импорт списков URL раздела "Библиотеки/Списки URL".')
        
    if not os.path.isdir('data_ug/Libraries/URLLists'):
        parent.stepChanged.emit('2|Нет списков URL для импорта.')
        return

    files_list = os.listdir('data_ug/Libraries/URLLists')
    if not files_list:
        parent.stepChanged.emit('2|Нет списков URL для импорта.')
        return

    error = 0
    err, result = parent.utm.get_nlists_list('url')
    if err:
        parent.stepChanged.emit(f'1|{result}')
        parent.error = 1
        return
    url_list = {x['name']: x['id'] for x in result}

    for file_name in files_list:
        json_file = f"data_ug/Libraries/URLLists/{file_name}"
        err, data = read_json_file(json_file, '2|Ошибка импорта списка URL!', '2|Нет списка URL для импорта.')
        if err:
            parent.stepChanged.emit(data)
            parent.error = 1
            return

        content = data.pop('content')
        err, result = parent.utm.add_nlist(data)
        if err:
            parent.stepChanged.emit(f'{err}|{result}')
            if err == 1:
                parent.stepChanged.emit(f'1|Ошибка! Список URL "{data["name"]}" не импортирован.')
                error = 1
                continue
        else:
            url_list[data['name']] = result
            parent.stepChanged.emit(f'2|Добавлен список URL: "{data["name"]}".')

        if content:
            err2, result2 = parent.utm.add_nlist_items(url_list[data['name']], content)
            if err2:
                parent.stepChanged.emit(f'{err2}|   {result2}')
                if err2 == 1:
                    error = 1
            else:
                parent.stepChanged.emit(f'2|   Содержимое списка "{data["name"]}" обновлено. Added {result2} record.')
        else:
            parent.stepChanged.emit(f'2|   Список "{data["name"]}" пуст.')

    if error:
        parent.error = 1
    out_message = '5|Списки URL импортированы в раздел "Библиотеки/Списки URL".'
    parent.stepChanged.emit('6|Произошла ошибка при импорте списков URL!' if error else out_message)

def import_url_categories(parent):
    """Импортировать группы URL категорий с содержимым на UTM"""
    parent.stepChanged.emit('0|Импорт групп URL категорий раздела "Библиотеки/Категории URL".')

    json_file = "data_ug/Libraries/URLCategories/config_categories_url.json"
    err, data = read_json_file(json_file, '2|Ошибка импорта групп URL категорий!', '2|Нет групп URL категорий для импорта.')
    if err:
        parent.stepChanged.emit(data)
        parent.error = 1
        return

    error = 0
    err, result = parent.utm.get_nlists_list('urlcategorygroup')
    if err:
        parent.stepChanged.emit(f'1|{result}')
        parent.error = 1
        return
    url_category_groups = {x['name']: x['id'] for x in result}

    err, result = parent.utm.get_url_categories()
    if err:
        parent.stepChanged.emit(f'1|{result}')
        parent.error = 1
        return
    url_categories = {x['name']: x['id'] for x in result}

    for item in data:
        content = item.pop('content')
        if item['name'] not in ['Parental Control', 'Productivity', 'Safe categories', 'Threats',
                                'Recommended for morphology checking', 'Recommended for virus check']:
            err, result = parent.utm.add_nlist(item)
            if err:
                parent.stepChanged.emit(f'{err}|{result}')
                if err == 1:
                    parent.stepChanged.emit(f'1|Ошибка! Группа URL категорий "{item["name"]}" не импортирована.')
                    error = 1
                    continue
            else:
                url_category_groups[item['name']] = result
                parent.stepChanged.emit(f'2|Группа URL категорий "{item["name"]}" добавлена.')
                
            for category in content:
                try:
                    category_url = {'category_id': url_categories[category['name']]}
                except KeyError as err:
                    parent.stepChanged.emit(f'4|   Ошибка! URL категория "{category["name"]}" не импортирована. Нет такой категории на UG NGFW.')
                    error = 1
                    continue
                err2, result2 = parent.utm.add_nlist_item(url_category_groups[item['name']], category_url)
                if err2:
                    parent.stepChanged.emit(f'{err2}|   {result2}')
                    if err2 == 1:
                        error = 1
                else:
                    parent.stepChanged.emit(f'2|   Добавлена категория "{category["name"]}".')
    if error:
        parent.error = 1
    out_message = '5|Группы URL категорий импортированы в раздел "Библиотеки/Категории URL".'
    parent.stepChanged.emit('6|Произошла ошибка при импорте групп URL категорий!' if error else out_message)

def import_application_groups(parent):
    """Импортировать список "Приложения" на UTM"""
    parent.stepChanged.emit('0|Импорт групп приложений в раздел "Библиотеки/Приложения".')

    json_file = "data_ug/Libraries/Applications/config_applications.json"
    err, data = read_json_file(json_file, '2|Ошибка импорта групп приложений!', '2|Нет групп приложений для импорта.')
    if err:
        parent.stepChanged.emit(data)
        parent.error = 1
        return

    err, result = parent.utm.get_l7_apps()
    if err:
        parent.stepChanged.emit(f'1|{result}')
        parent.error = 1
        return
    l7_app_id = {x['name']: x['id'] for x in result}

    err, result = parent.utm.get_nlists_list('applicationgroup')
    if err:
        parent.stepChanged.emit(f'1|{result}')
        parent.error = 1
        return
    list_applicationgroups = {x['name']: x['id'] for x in result}

    error = 0
    for item in data:
        content = item.pop('content')
        err, result = parent.utm.add_nlist(item)
        if err == 1:
            parent.stepChanged.emit(f'1|{result}')
            parent.stepChanged.emit(f'1|Ошибка! Группа приложений "{item["name"]}" не импортирована.')
            error = 1
            continue
        elif err == 2:
            parent.stepChanged.emit(f'2|Группа приложений "{item["name"]}" уже существует.')
        else:
            list_applicationgroups[item['name']] = result
            parent.stepChanged.emit(f'2|Группа приложений "{item["name"]}" добавлена.')

        for app in content:
            app_name = app['value']
            try:
                app['value'] = l7_app_id[app_name]
            except KeyError as err:
                parent.stepChanged.emit(f'4|   Ошибка! Приложение "{app_name}" не импортировано. Такого приложения нет на UG NGFW.')
                error = 1
                continue
            err2, result2 = parent.utm.add_nlist_item(list_applicationgroups[item['name']], app)
            if err2 == 1:
                error = 1
                parent.stepChanged.emit(f'1|   {result2}')
            elif err2 == 2:
                parent.stepChanged.emit(f'2|   Приложение "{app_name}" уже существует.')
            else:
                parent.stepChanged.emit(f'2|   Добавлено приложение "{app_name}".')

    if error:
        parent.error = 1
    out_message = '5|Группы приложений импортированы в раздел "Библиотеки/Приложения".'
    parent.stepChanged.emit('6|Произошла ошибка при импорте групп приложений!' if error else out_message)


def import_content_rules(parent):
    """Импортировать список правил фильтрации контента"""
    parent.stepChanged.emit('0|Импорт правил фильтрации контента в раздел "Политики безопасности/Фильтрация контента".')

    json_file = "data_ug/SecurityPolicies/ContentFiltering/config_content_rules.json"
    err, data = read_json_file(json_file, '2|Ошибка импорта правил фильтрации контента!', '2|Нет правил фильтрации контента для импорта.')
    if err:
        parent.stepChanged.emit(data)
        parent.error = 1
        return

    err, result = parent.utm.get_content_rules()
    if err:
        parent.stepChanged.emit(f'1|{result}')
        parent.stepChanged.emit('1|Импорт правил фильтрации контента прерван!')
        parent.error = 1
        return
    content_rules = {x['name']: x['id'] for x in result}

    err, result = parent.utm.get_zones_list()
    if err:
        parent.stepChanged.emit(f'1|{result}')
        parent.stepChanged.emit('1|Импорт правил межсетевого экрана прерван!')
        parent.error = 1
        return
    zones_list = {x['name']: x['id'] for x in result}

    err, result = parent.utm.get_nlists_list('network')
    if err:
        parent.stepChanged.emit(f'1|{result}')
        parent.stepChanged.emit('1|Импорт правил фильтрации контента прерван!')
        parent.error = 1
        return
    ips_list = {x['name']: x['id'] for x in result}

    err, result = parent.utm.get_nlists_list('urlcategorygroup')
    if err:
        parent.stepChanged.emit(f'1|{result}')
        parent.stepChanged.emit('1|Импорт правил фильтрации контента прерван!')
        parent.error = 1
        return
    url_category_groups = {x['name']: x['id'] for x in result}

    err, result = parent.utm.get_url_categories()
    if err:
        parent.stepChanged.emit(f'1|{result}')
        parent.stepChanged.emit('1|Импорт правил фильтрации контента прерван!')
        parent.error = 1
        return
    url_categories = {x['name']: x['id'] for x in result}

    err, result = parent.utm.get_nlists_list('url')
    if err:
        parent.stepChanged.emit(f'1|{result}')
        parent.stepChanged.emit('1|Импорт правил фильтрации контента прерван!')
        parent.error = 1
        return
    url_list = {x['name']: x['id'] for x in result}

    error = 0
    for item in data:
        item['position'] = 'last'
        get_guids_users_and_groups(parent, item)
        item['src_zones'] = get_zones(parent, item['src_zones'], zones_list, item["name"])
        item['dst_zones'] = get_zones(parent, item['dst_zones'], zones_list, item["name"])
        item['src_ips'] = get_ips(parent, item['src_ips'], ips_list, item["name"])
        item['dst_ips'] = get_ips(parent, item['dst_ips'], ips_list, item["name"])

        for x in item['url_categories']:
            try:
                x[1] = url_category_groups[x[1]] if x[0] == 'list_id' else url_categories[x[1]]
            except KeyError as err:
                error = 1
                parent.stepChanged.emit(f'1|Error! Не найдена группа URL-категорий {err} для правила "{item["name"]}". Загрузите ктегории URL и повторите попытку.')

        url_oids = []
        for url_name in item['urls']:
            try:
                url_oids.append(url_list[url_name])
            except KeyError as err:
                error = 1
                parent.stepChanged.emit(f'1|Error! Не найден URL {err} для правила "{item["name"]}".')
        item['urls'] = url_oids
#        parent.set_time_restrictions(item)

        if item['name'] in content_rules:
            parent.stepChanged.emit(f'2|Правило КФ "{item["name"]}" уже существует.')
            item.pop('position', None)
            err, result = parent.utm.update_content_rule(content_rules[item['name']], item)
            if err:
                error = 1
                parent.stepChanged.emit(f'1|{result}')
            else:
                parent.stepChanged.emit(f'2|   Правило КФ "{item["name"]}" обновлено.')
        else:
            err, result = parent.utm.add_content_rule(item)
            if err:
                error = 1
                parent.stepChanged.emit(f'1|{result}')
            else:
                content_rules[item['name']] = result
                parent.stepChanged.emit(f'2|   Правило КФ "{item["name"]}" добавлено.')

    if error:
        parent.error = 1
    out_message = '5|Правила контентной фильтрации импортированы в раздел "Политики безопасности/Фильтрация контента".'
    parent.stepChanged.emit('6|Произошла ошибка при импорте правил контентной фильтрации!' if error else out_message)

###################################### Служебные функции ##########################################
def get_ips_name(parent, rule_ips, rule_name):
    """Получаем имена списков IP-адресов, URL-листов и GeoIP. Если списки не существует на NGFW, то они пропускаются."""
    new_rule_ips = []
    for ips in rule_ips:
        if ips[0] == 'geoip_code':
            new_rule_ips.append(ips)
        try:
            if ips[0] == 'list_id':
                new_rule_ips.append(['list_id', parent.ip_lists[ips[1]]])
            elif ips[0] == 'urllist_id':
                new_rule_ips.append(['urllist_id', parent.url_lists[ips[1]]])
        except KeyError as err:
            parent.stepChanged.emit(f'bRED|    Error! Не найден список {ips[0]} для правила {rule_name}.')
    return new_rule_ips

def get_zones_name(parent, zones, rule_name):
    """Получаем имена зон. Если зона не существует на NGFW, то она пропускается."""
    new_zones = []
    for zone_id in zones:
        try:
            new_zones.append(parent.zones[zone_id])
        except KeyError as err:
            parent.stepChanged.emit(f'bRED|    Error! Не найдена зона c ID: {zone_id} для правила {rule_name}.')
    return new_zones

def get_urls_name(parent, urls, rule_name):
    """Получаем имена списков URL. Если список не существует на NGFW, то он пропускается."""
    new_urls = []
    for url_list_id in urls:
        try:
            new_urls.append(parent.url_lists[url_list_id])
        except KeyError as err:
            parent.stepChanged.emit(f'bRED|    Error! Не найден список URL c ID: {url_list_id} для правила {rule_name}.')
    return new_urls

def get_url_categories_name(parent, url_categories, rule_name):
    """Получаем имена категорий URL и групп категорий URL. Если список не существует на NGFW, то он пропускается."""
    new_urls = []
    for arr in url_categories:
        try:
            if arr[0] == 'list_id':
                new_urls.append(['list_id', parent.list_urlcategorygroup[arr[1]]])
            elif arr[0] == 'category_id':
                new_urls.append(['category_id', parent.url_categories[arr[1]]])
        except KeyError as err:
            parent.stepChanged.emit(f'bRED|    Error! Не найдена категория URL {arr} для правила {rule_name}.')
    return new_urls

def get_time_restrictions_name(parent, times, rule_name):
    """Получаем имена календарей. Если не существуют на NGFW, то пропускаются."""
    new_times = []
    for cal_id in times:
        try:
            new_times.append(parent.list_calendar[cal_id])
        except KeyError as err:
            parent.stepChanged.emit(f'bRED|    Error! Не найден календарь c ID: {cal_id} для правила {rule_name}.')
    return new_times

def get_names_users_and_groups(parent, users, rule_name):
    """
    Получаем имена групп и пользователей по их GUID.
    Заменяет GUID локальных/доменных пользователей и групп на имена.
    """
    new_users = []
    for item in users:
        match item[0]:
            case 'special':
                new_users.append(item)
            case 'user':
                try:
                    user_name = parent.list_users[item[1]]
                except KeyError:
                    err, user_name = parent.utm.get_ldap_user_name(item[1])
                    if err:
                        parent.stepChanged.emit(f'bRED|    {user_name}  [Rule: "{rule_name}"]')
                    elif not user_name:
                        parent.stepChanged.emit(f'NOTE|    Error [Rule: "{rule_name}"]. Нет LDAP-коннектора для домена! Импортируйте и настройте LDAP-коннектор. Затем повторите импорт.')
                    else:
                        new_users.append(['user', user_name])
                else:
                    new_users.append(['user', user_name])
            case 'group':
                try:
                    group_name = parent.list_groups[item[1]]
                except KeyError:
                    err, group_name = parent.utm.get_ldap_group_name(item[1])
                    if err:
                        parent.stepChanged.emit(f'bRED|    {group_name}  [Rule: "{rule_name}"]')
                    elif not group_name:
                        parent.stepChanged.emit(f'NOTE|    Error [Rule: "{rule_name}"]. Нет LDAP-коннектора для домена "{item[1].split(":")[0]}"! Импортируйте и настройте LDAP-коннектор. Затем повторите импорт.')
                    else:
                        new_users.append(['group', group_name])
                else:
                    new_users.append(['group', group_name])
    return new_users

def get_services(parent, service_list, rule_name):
    """Получаем имена сервисов по их ID. Если сервис не найден, то он пропускается."""
    new_service_list = []
    if parent.version < 7:
        for item in service_list:
            try:
                new_service_list.append(['service', parent.services_list[item]])
            except KeyError as err:
                parent.stepChanged.emit(f'bRED|    Error! Не найден сервис "{item}" для правила "{rule_name}".')
    else:
        for item in service_list:
            try:
                new_service_list.append(['service', parent.services_list[item[1]]] if item[0] == 'service' else ['list_id', parent.servicegroups_list[item[1]]])
            except KeyError as err:
                parent.stepChanged.emit(f'bRED|    Error! Не найдена группа сервисов "{item}" для правила "{rule_name}".')
    return new_service_list

def set_apps_values(parent):
    """Устанавливаем в parent значения атрибутов: l7_categories, l7_apps, list_applicationgroup"""
    err, result = parent.utm.get_l7_categories()
    if err:
        parent.stepChanged.emit(f'iRED|{result}')
        return 1
    parent.l7_categories = {x['id']: x['name'] for x in result}

    err, result = parent.utm.get_l7_apps()
    if err:
        parent.stepChanged.emit(f'iRED|{result}')
        return 1
    parent.l7_apps = {x['id']: x['name'] for x in result}

    err, result = parent.utm.get_nlists_list('applicationgroup')
    if err:
        parent.stepChanged.emit(f'iRED|{result}')
        return 1
    parent.list_applicationgroup = {x['id']: x['name'].strip().translate(trans_name) for x in result}

    return 0

def get_apps(parent, array_apps, rule_name):
    """Определяем имя приложения или группы приложений по ID."""
    new_app_list = []
    for app in array_apps:
        if app[0] == 'ro_group':
            if app[1] == 0:
                new_app_list.append(['ro_group', 'All'])
            else:
                try:
                    new_app_list.append(['ro_group', parent.l7_categories[app[1]]])
                except KeyError as err:
                    parent.stepChanged.emit(f'bRED|    Error! Не найдена категория l7 №{err} для правила "{rule_name}".')
                    parent.stepChanged.emit(f'bRED|    Возможно нет лицензии и UTM не получил список категорий l7. Установите лицензию и повторите попытку.')
        elif app[0] == 'group':
            try:
                new_app_list.append(['group', parent.list_applicationgroup[app[1]]])
            except KeyError as err:
                parent.stepChanged.emit(f'bRED|    Error! Не найдена группа приложений l7 №{err} для правила "{rule_name}".')
        elif app[0] == 'app':
            try:
                new_app_list.append(['app', parent.l7_apps[app[1]]])
            except KeyError as err:
                parent.stepChanged.emit(f'bRED|    Error! Не найдено приложение №{err} для правила "{rule_name}".')
                parent.stepChanged.emit(f'bRED|    Возможно нет лицензии и UTM не получил список приложений l7. Установите лицензию и повторите попытку.')
    return new_app_list

def set_scenarios_rules(parent):
    """Устанавливаем в parent значение атрибута: scenarios_rules"""
    err, result = parent.utm.get_scenarios_rules()
    if err:
        parent.stepChanged.emit(f'iRED|{data}')
        return 1
    parent.scenarios_rules = {x['id']: x['name'].strip().translate(trans_name) for x in result}
    return 0

def translate_iface_name(ngfw_version, path, data):
    """Преобразуем имена интерфейсов для версии 5 (eth меняется на port, так же меняются имена vlan)"""
    if ngfw_version < 6:
        iface_name = {x['name']: x['name'].replace('eth', 'port', 1) if x['name'].startswith('eth') else x['name'].replace('rename', 'port', 1) for x in data}
        ports_num = max([int(x[4:5]) if x.startswith('port') else 0 for x in iface_name.values()])
        for key in sorted(iface_name.keys()):
            if key.startswith('slot'):
                try:
                    name, vlan = iface_name[key].split('.')
                except ValueError:
                    ports_num += 1
                    iface_name[key] = f'port{ports_num}'
                else:
                    iface_name[key] = f'port{ports_num}.{vlan}'
        json_file = os.path.join(path, 'iface_translate.json')
        with open(json_file, 'w') as fh:
            json.dump(iface_name, fh, indent=4, ensure_ascii=False)
    else:
        iface_name = {x['name']: x['name'] for x in data}
    return iface_name

def create_dir(path):
    if not os.path.isdir(path):
        try:
            os.makedirs(path)
        except Exception as err:
            return 1, f'Ошибка создания каталога:/n{path}'
        else:
            return 0, f'Создан каталог {path}'
    return 0, f'Каталог {path} уже существует.'
