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
# Версия 0.6
#

import os, sys, json, time
from datetime import datetime as dt
import xmlrpc.client as rpc
from PyQt6.QtCore import QThread, pyqtSignal
from services import zone_services, character_map_file_name, character_map_for_name


trans_filename = str.maketrans(character_map_file_name)
trans_name = str.maketrans(character_map_for_name)


class ImportAll(QThread):
    """Импортируем всю конфигурацию на NGFW"""
    stepChanged = pyqtSignal(str)
    
    def __init__(self, utm, config_path, all_points, arguments):
        super().__init__()
        self.utm = utm
        self.config_path = config_path
        self.all_points = all_points
        self.iface_settings = arguments['iface_settings']
        self.ngfw_vlans = arguments['ngfw_vlans']
        self.new_vlans = arguments['new_vlans']
        self.ngfw_ports = arguments['ngfw_ports']
        self.dhcp_settings = arguments['dhcp_settings']
        self.version = float(f'{self.utm.version_hight}.{self.utm.version_midle}')
        self.ssl_profiles = {}
        self.servicegroups_list = {}
        self.l7_categories = {}             # Устанавливается через функцию set_apps_values()
        self.l7_apps = {}                   # -- // --
        self.list_applicationgroup = {}     # -- // --
        self.scenarios_rules = {}           # Устанавливается через функцию set_scenarios_rules()
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
        """Заполняем служебные структуры данных"""
        # Получаем список зон
        err, result = self.utm.get_zones_list()
        if err:
            self.stepChanged.emit(f'iRED|{result}')
            return
        self.ngfw_zones = {x['name'].strip().translate(trans_name): x['id'] for x in result}
        # Получаем список сертификатов
        err, result = self.utm.get_certificates_list()
        if err:
            self.stepChanged.emit(f'iRED|{result}')
            return
        self.ngfw_certs = {x['name'].strip().translate(trans_name): x['id'] for x in result}
        self.ngfw_certs[-1] = -1
        # Получаем список профилей аутентификации
        err, result = self.utm.get_auth_profiles()
        if err:
            self.stepChanged.emit(f'iRED|{result}')
            return
        self.auth_profiles = {x['name'].strip().translate(trans_name): x['id'] for x in result}
        # Получаем список локальных групп
        err, result = self.utm.get_groups_list()
        if err:
            self.stepChanged.emit(f'iRED|{result}')
            return
        self.list_groups = {x['name'].strip().translate(trans_name): x['id'] for x in result}
        # Получаем список локальных пользователей
        err, result = self.utm.get_users_list()
        if err:
            self.stepChanged.emit(f'iRED|{result}')
            return
        self.list_users = {x['name'].strip().translate(trans_name): x['id'] for x in result}
        # Получаем список профилей SSL
        if self.version > 5:
            err, result = self.utm.get_ssl_profiles_list()
            if err:
                self.stepChanged.emit(f'iRED|{result}')
                return
            self.ssl_profiles = {x['name'].strip().translate(trans_name): x['id'] for x in result}
        # Получаем список IP-листов
        err, result = self.utm.get_nlists_list('network')
        if err:
            self.stepChanged.emit(f'iRED|{result}')
            return
        self.ip_lists = {x['name'].strip().translate(trans_name): x['id'] for x in result}
        # Получаем список URL-листов
        err, result = self.utm.get_nlists_list('url')
        if err:
            self.stepChanged.emit(f'iRED|{result}')
            return
        self.url_lists = {x['name'].strip().translate(trans_name): x['id'] for x in result}
        # Получаем список групп категорий URL
        err, result = self.utm.get_nlists_list('urlcategorygroup')
        if err:
            self.stepChanged.emit(f'iRED|{result}')
            return
        self.list_urlcategorygroup = {self.default_urlcategorygroup.get(x['name'], x['name'].strip().translate(trans_name)): x['id'] for x in result}
        # Получаем список категорий URL
        err, result = self.utm.get_url_categories()
        if err:
            self.stepChanged.emit(f'iRED|{result}')
            return
        self.url_categories = {x['name'].strip().translate(trans_name): x['id'] for x in result}
        # Получаем список календарей
        err, result = self.utm.get_nlists_list('timerestrictiongroup')
        if err:
            self.stepChanged.emit(f'iRED|{result}')
            return
        self.list_calendar = {x['name'].strip().translate(trans_name): x['id'] for x in result}
        # Получаем список сервисов
        err, result = self.utm.get_services_list()
        if err:
            self.stepChanged.emit(f'iRED|{result}')
            return
        self.services_list = {x['name'].strip().translate(trans_name): x['id'] for x in result}
        # Получаем список групп сервисов
        if self.version >= 7:
            err, result = self.utm.get_nlists_list('servicegroup')
            if err:
                self.stepChanged.emit(f'iRED|{result}')
                return
            self.servicegroups_list = {x['name'].strip().translate(trans_name): x['id'] for x in result}
        # Получаем список типов контента
        err, result = self.utm.get_nlists_list('mime')
        if err:
            self.stepChanged.emit(f'iRED|{result}')
            return
        self.mime_list = {x['name'].strip().translate(trans_name): x['id'] for x in result}


    def run(self):
        """Импортируем всё в пакетном режиме"""
        for item in self.all_points:
            top_level_path = os.path.join(self.config_path, item['path'])
            for point in item['points']:
                current_path = os.path.join(top_level_path, point)
                if point in func:
                    func[point](self, current_path)
                else:
                    self.error = 1
                    self.stepChanged.emit(f'RED|Не найдена функция для импорта "{point}".')
        self.stepChanged.emit('iORANGE|Импорт конфигурации прошёл с ошибками!\n' if self.error else 'iGREEN|Импорт всей конфигурации прошёл успешно.\n')


class ImportSelectedPoints(QThread):
    """Импортируем выделенный раздел конфигурации на NGFW"""
    stepChanged = pyqtSignal(str)
    def __init__(self, utm, selected_path, selected_points, arguments):
        super().__init__()
        self.utm = utm
        self.selected_path = selected_path
        self.selected_points = selected_points
        self.iface_settings = arguments['iface_settings']
        self.ngfw_vlans = arguments['ngfw_vlans']
        self.new_vlans = arguments['new_vlans']
        self.ngfw_ports = arguments['ngfw_ports']
        self.dhcp_settings = arguments['dhcp_settings']
        self.version = float(f'{self.utm.version_hight}.{self.utm.version_midle}')
        self.ssl_profiles = {}
        self.servicegroups_list = {}
        self.l7_categories = {}             # Устанавливается через функцию set_apps_values()
        self.l7_apps = {}                   # -- // --
        self.list_applicationgroup = {}     # -- // --
        self.scenarios_rules = {}           # Устанавливается через функцию set_scenarios_rules()
        self.error = 0
        self.default_urlcategorygroup = {
            'URL_CATEGORY_GROUP_PARENTAL_CONTROL': 'Parental Control',
            'URL_CATEGORY_GROUP_PRODUCTIVITY': 'Productivity',
            'URL_CATEGORY_GROUP_SAFE': 'Safe categories',
            'URL_CATEGORY_GROUP_THREATS': 'Threats',
            'URL_CATEGORY_MORPHO_RECOMMENDED': 'Recommended for morphology checking',
            'URL_CATEGORY_VIRUSCHECK_RECOMMENDED': 'Recommended for virus check'
        }
        self.init_struct()

    def init_struct(self):
        """Заполняем служебные структуры данных"""
        # Получаем список зон
        err, result = self.utm.get_zones_list()
        if err:
            self.stepChanged.emit(f'iRED|{result}')
            return
        self.ngfw_zones = {x['name'].strip().translate(trans_name): x['id'] for x in result}
        # Получаем список сертификатов
        err, result = self.utm.get_certificates_list()
        if err:
            self.stepChanged.emit(f'iRED|{result}')
            return
        self.ngfw_certs = {x['name'].strip().translate(trans_name): x['id'] for x in result}
        self.ngfw_certs[-1] = -1
        # Получаем список профилей аутентификации
        err, result = self.utm.get_auth_profiles()
        if err:
            self.stepChanged.emit(f'iRED|{result}')
            return
        self.auth_profiles = {x['name'].strip().translate(trans_name): x['id'] for x in result}
        # Получаем список локальных групп
        err, result = self.utm.get_groups_list()
        if err:
            self.stepChanged.emit(f'iRED|{result}')
            return
        self.list_groups = {x['name'].strip().translate(trans_name): x['id'] for x in result}
        # Получаем список локальных пользователей
        err, result = self.utm.get_users_list()
        if err:
            self.stepChanged.emit(f'iRED|{result}')
            return
        self.list_users = {x['name'].strip().translate(trans_name): x['id'] for x in result}
        # Получаем список профилей SSL
        if self.version > 5:
            err, result = self.utm.get_ssl_profiles_list()
            if err:
                self.stepChanged.emit(f'iRED|{result}')
                return
            self.ssl_profiles = {x['name'].strip().translate(trans_name): x['id'] for x in result}
        # Получаем список IP-листов
        err, result = self.utm.get_nlists_list('network')
        if err:
            self.stepChanged.emit(f'iRED|{result}')
            return
        self.ip_lists = {x['name'].strip().translate(trans_name): x['id'] for x in result}
        # Получаем список URL-листов
        err, result = self.utm.get_nlists_list('url')
        if err:
            self.stepChanged.emit(f'iRED|{result}')
            return
        self.url_lists = {x['name'].strip().translate(trans_name): x['id'] for x in result}
        # Получаем список групп категорий URL
        err, result = self.utm.get_nlists_list('urlcategorygroup')
        if err:
            self.stepChanged.emit(f'iRED|{result}')
            return
        self.list_urlcategorygroup = {self.default_urlcategorygroup.get(x['name'], x['name'].strip().translate(trans_name)): x['id'] for x in result}
        # Получаем список категорий URL
        err, result = self.utm.get_url_categories()
        if err:
            self.stepChanged.emit(f'iRED|{result}')
            return
        self.url_categories = {x['name'].strip().translate(trans_name): x['id'] for x in result}
        # Получаем список календарей
        err, result = self.utm.get_nlists_list('timerestrictiongroup')
        if err:
            self.stepChanged.emit(f'iRED|{result}')
            return
        self.list_calendar = {x['name'].strip().translate(trans_name): x['id'] for x in result}
        # Получаем список сервисов
        err, result = self.utm.get_services_list()
        if err:
            self.stepChanged.emit(f'iRED|{result}')
            return
        self.services_list = {x['name'].strip().translate(trans_name): x['id'] for x in result}
        # Получаем список групп сервисов
        if self.version >= 7:
            err, result = self.utm.get_nlists_list('servicegroup')
            if err:
                self.stepChanged.emit(f'iRED|{result}')
                return
            self.servicegroups_list = {x['name'].strip().translate(trans_name): x['id'] for x in result}
        # Получаем список типов контента
        err, result = self.utm.get_nlists_list('mime')
        if err:
            self.stepChanged.emit(f'iRED|{result}')
            return
        self.mime_list = {x['name'].strip().translate(trans_name): x['id'] for x in result}

    def run(self):
        """Импортируем определённый раздел конфигурации"""
        for point in self.selected_points:
            current_path = os.path.join(self.selected_path, point)
            if point in func:
                func[point](self, current_path)
            else:
                self.error = 1
                self.stepChanged.emit(f'RED|Не найдена функция для импорта {point}!')
        self.stepChanged.emit('iORANGE|Импорт конфигурации прошёл с ошибками!\n' if self.error else 'iGREEN|Импорт конфигурации завершён.\n')


def import_general_settings(parent, path):
    """Импортируем раздел 'UserGate/Настройки'"""
    import_ui(parent, path)
    import_ntp_settings(parent, path)
    import_modules(parent, path)
    import_cache_settings(parent, path)
    import_web_portal_settings(parent, path)
    import_upstream_proxy_settings(parent, path)

def import_ui(parent, path):
    """Импортируем раздел 'UserGate/Настройки/Настройки интерфейса'"""
    parent.stepChanged.emit('BLUE|Импорт раздела "UserGate/Настройки/Настройки интерфейса".')
    json_file = os.path.join(path, 'config_settings_ui.json')
    err, data = read_json_file(parent, json_file)
    if err:
        return

    params = {
        'ui_timezone': 'Часовой пояс',
        'ui_language': 'Язык интерфейса по умолчанию',
        'web_console_ssl_profile_id': 'Профиль SSL для веб-консоли',
        'response_pages_ssl_profile_id': 'Профиль SSL для страниц блокировки/аутентификации',
        'api_session_lifetime': 'Таймер автоматическогозакрытия сессии'
    }
    error = 0

    data.pop('webui_auth_mode', None)
    for key, value in data.items():
        params[value] = value
    if parent.version < 7.1:
        data.pop('api_session_lifetime', None)
    if parent.version == 5.0:
        data.pop('web_console_ssl_profile_id', None)
        data.pop('response_pages_ssl_profile_id', None)
    else:
        try:
            params[parent.ssl_profiles[data['web_console_ssl_profile_id']]] = data['web_console_ssl_profile_id']
            params[parent.ssl_profiles[data['response_pages_ssl_profile_id']]] = data['response_pages_ssl_profile_id']
            data['web_console_ssl_profile_id'] = parent.ssl_profiles[data['web_console_ssl_profile_id']]
            data['response_pages_ssl_profile_id'] = parent.ssl_profiles[data['response_pages_ssl_profile_id']]
        except KeyError as err:
            data.pop('web_console_ssl_profile_id', None)
            data.pop('response_pages_ssl_profile_id', None)
            parent.stepChanged.emit(f'RED|    Не найден профиль SSL "{err}". Загрузите профили SSL и повторите попытку.')
            error = 1
            parent.error = 1

    for key, value in data.items():
        err, result = parent.utm.set_settings_param(key, value)
        if err:
            parent.stepChanged.emit(f'RED|    {result}')
            error = 1
            parent.error = 1
        else:
            parent.stepChanged.emit(f'BLACK|    Параметр "{params[key]}" установлен в значение "{params[value]}".')

    out_message = 'GREEN|    Импортирован раздел "UserGate/Настройки/Настройки интерфейса".'
    parent.stepChanged.emit('ORANGE|    Ошибка импорта настроек интерфейса.' if error else out_message)

def import_ntp_settings(parent, path):
    """Импортируем настройки NTP"""
    parent.stepChanged.emit('BLUE|Импорт настроек NTP раздела "UserGate/Настройки/Настройка времени сервера".')
    error = 0

    json_file = os.path.join(path, 'config_ntp.json')
    err, data = read_json_file(parent, json_file)
    if err:
        error = 1
    else:
        data.pop('utc_time', None)
        data.pop('ntp_synced', None)
        err, result = parent.utm.add_ntp_config(data)
        if err:
            parent.stepChanged.emit(f'RED|    {result}')
            error = 1
            parent.error = 1

    out_message = 'GREEN|    Импортированы настройки NTP в раздел "UserGate/Настройки/Настройка времени сервера".'
    parent.stepChanged.emit('ORANGE|    Ошибка импорта настроек NTP.' if error else out_message)

def import_modules(parent, path):
    """Импортируем раздел 'UserGate/Настройки/Модули'"""
    parent.stepChanged.emit('BLUE|Импорт раздела "UserGate/Настройки/Модули".')
    error = 0

    json_file = os.path.join(path, 'config_proxy_port.json')
    err, data = read_json_file(parent, json_file)
    if err:
        parent.stepChanged.emit(f'{data}|        HTTP(S)-прокси порт не установлен.')
        if err != 3: error = 1
    else:
        err, result = parent.utm.set_proxy_port(data)
        if err:
            parent.stepChanged.emit(f'RED|    {result}')
            error = 1
            parent.error = 1
        else:
            parent.stepChanged.emit(f'BLACK|    HTTP(S)-прокси порт установлен в значение "{data}"')

    json_file = os.path.join(path, 'config_settings_modules.json')
    err, data = read_json_file(parent, json_file)
    if err:
        error = 1
    else:
        params = {
            'auth_captive': 'Домен Auth captive-портала',
            'logout_captive': 'Домен Logout captive-портала',
            'block_page_domain': 'Домен страницы блокировки',
            'ftpclient_captive': 'FTP поверх HTTP домен',
            'ftp_proxy_enabled': 'FTP поверх HTTP',
            'tunnel_inspection_zone_config': 'Зона для инспектируемых туннелей',
            'lldp_config': 'Настройка LLDP'
        }
        if parent.version < 7.1:
            data.pop('tunnel_inspection_zone_config', None)
            data.pop('lldp_config', None)
        else:
            zone_name = data['tunnel_inspection_zone_config']['target_zone']
            data['tunnel_inspection_zone_config']['target_zone'] = parent.ngfw_zones.get(zone_name, 8)

        for key, value in data.items():
            err, result = parent.utm.set_settings_param(key, value)
            if err:
                parent.stepChanged.emit(f'RED|    {result}')
                error = 1
                parent.error = 1
            else:
                parent.stepChanged.emit(f'BLACK|    Параметр "{params[key]}" установлен в значение "{value}".')

    out_message = 'GREEN|    Импортирован раздел "UserGate/Настройки/Модули".'
    parent.stepChanged.emit('ORANGE|    Ошибка импорта настроек модулей.' if error else out_message)

def import_cache_settings(parent, path):
    """Импортируем раздел 'UserGate/Настройки/Настройки кэширования HTTP'"""
    parent.stepChanged.emit('BLUE|Импорт раздела "UserGate/Настройки/Настройки кэширования HTTP".')
    error = 0

    json_file = os.path.join(path, 'config_proxy_settings.json')
    err, data = read_json_file(parent, json_file)
    if err:
        error = 1
    else:
        if parent.version < 7:
            data.pop('add_via_enabled', None)
            data.pop('add_forwarded_enabled', None)
            data.pop('smode_enabled', None)
            data.pop('module_l7_enabled', None)
            data.pop('module_idps_enabled', None)
            data.pop('module_sip_enabled', None)
            data.pop('module_h323_enabled', None)
            data.pop('module_sunrpc_enabled', None)
            data.pop('module_ftp_alg_enabled', None)
            data.pop('module_tftp_enabled', None)
            data.pop('legacy_ssl_enabled', None)
            data.pop('http_connection_timeout', None)
            data.pop('http_loading_timeout', None)
            data.pop('icap_wait_timeout', None)
        if parent.version == 7.0:
            data.pop('module_tftp_enabled', None)
        for key, value in data.items():
            err, result = parent.utm.set_settings_param(key, value)
            if err:
                parent.stepChanged.emit(f'RED|    {result}')
                error = 1
                parent.error = 1
            else:
                parent.stepChanged.emit(f'BLACK|    Параметр "{key}" установлен в значение "{value}".')

    json_file = os.path.join(path, 'config_proxy_exceptions.json')
    err, exceptions = read_json_file(parent, json_file)
    if err:
        parent.stepChanged.emit(f'{exceptions}|        Исключения кеширования не импортированы.')
        if err != 3: error = 1
    else:
        err, nlist = parent.utm.get_nlist_list('httpcwl')
        for item in exceptions:
            err, result = parent.utm.add_nlist_item(nlist['id'], item)
            if err == 1:
                parent.stepChanged.emit(f'RED|    {result}')
                error = 1
                parent.error = 1
            elif err == 2:
                parent.stepChanged.emit(f'GRAY|    URL "{item["value"]}" уже существует в исключениях кэширования.')
            else:
                parent.stepChanged.emit(f'BLACK|    В исключения кэширования добавлен URL "{item["value"]}".')

    out_message = 'GREEN|    Импортирован раздел "UserGate/Настройки/Настройки кэширования HTTP".'
    parent.stepChanged.emit('ORANGE|    Ошибка импорта настроек кэширования HTTP.' if error else out_message)

def import_web_portal_settings(parent, path):
    """Импортируем раздел 'UserGate/Настройки/Веб-портал'"""
    parent.stepChanged.emit('BLUE|Импорт раздела "UserGate/Настройки/Веб-портал".')
    error = 0
    error_message = 'ORANGE|    Ошибка импорта настроек Веб-портала!'
    out_message = 'GREEN|    Импортирован раздел "UserGate/Настройки/Веб-портал".'

    json_file = os.path.join(path, 'config_web_portal.json')
    err, data = read_json_file(parent, json_file)
    if err:
        error = 1
    else:
        err, result = parent.utm.get_templates_list()
        if err:
            parent.stepChanged.emit(f'RED|    {result}')
            parent.error = 1
            return
        list_templates = {x['name']: x['id'] for x in result}

        if parent.version >= 7.1:
            err, result = parent.utm.get_client_certificate_profiles()
            if err:
                parent.stepChanged.emit(f'RED|    {result}')
                parent.error = 1
                return
            client_certificate_profiles = {x['name']: x['id'] for x in result}

        if parent.version >= 6:
            try:
                data['ssl_profile_id'] = parent.ssl_profiles[data['ssl_profile_id']]
            except KeyError as err:
                parent.stepChanged.emit(f'RED|    Не найден профиль SSL {err}". Загрузите профили SSL и повторите попытку.')
                parent.stepChanged.emit(error_message)
                parent.error = 1
                return
        else:
            data.pop('ssl_profile_id', None)

        if parent.version >= 7.1:
            data['client_certificate_profile_id'] = client_certificate_profiles.get(data['client_certificate_profile_id'], 0)
            if not data['client_certificate_profile_id']:
                data['cert_auth_enabled'] = False
        else:
            data.pop('client_certificate_profile_id', None)

        try:
            data['user_auth_profile_id'] = parent.auth_profiles[data['user_auth_profile_id']]
        except KeyError as err:
            parent.stepChanged.emit(f'RED|    Не найден профиль аутентификации {err}". Загрузите профили аутентификации и повторите попытку.')
            parent.stepChanged.emit(error_message)
            parent.error = 1
            return
        try:
            data['certificate_id'] = parent.ngfw_certs[data['certificate_id']]
        except KeyError as err:
            parent.stepChanged.emit(f'RED|    Не найден сертификат {err}". Загрузите сертификаты и повторите попытку.')
            parent.stepChanged.emit(error_message)
            parent.error = 1
            return

        data['proxy_portal_template_id'] = list_templates.get(data['proxy_portal_template_id'], -1)
        data['proxy_portal_login_template_id'] = list_templates.get(data['proxy_portal_login_template_id'], -1)


        err, result = parent.utm.set_proxyportal_config(data)
        if err:
            parent.stepChanged.emit(f'RED|    {result}')
            parent.error = 1
            error = 1

    parent.stepChanged.emit(error_message if error else out_message)

def import_upstream_proxy_settings(parent, path):
    """Импортируем настройки вышестоящего прокси"""
    if parent.version >= 7.1:
        parent.stepChanged.emit('BLUE|Импорт настроек раздела "UserGate/Настройки/Вышестоящий прокси".')
        error = 0

        json_file = os.path.join(path, 'upstream_proxy_settings.json')
        err, data = read_json_file(parent, json_file)
        if err:
            error = 1
        else:
            err, result = parent.utm.set_upstream_proxy_settings(data)
            if err:
                parent.stepChanged.emit(f'RED|    {result}')
                error = 1
                parent.error = 1

        out_message = 'GREEN|    Импортированы настройки вышестоящего прокси в раздел "UserGate/Настройки/Вышестоящий прокси".'
        parent.stepChanged.emit('ORANGE|    Ошибка импорта настроек вышестоящего прокси!' if error else out_message)

def import_users_certificate_profiles(parent, path):
    """Импортируем профили пользовательских сертификатов. Только для версии 7.1 и выше."""
    parent.stepChanged.emit('BLUE|Импорт настроек раздела "UserGate/Профили пользовательских сертификатов".')
    error = 0

    json_file = os.path.join(path, 'users_certificate_profiles.json')
    err, data = read_json_file(parent, json_file)
    if err:
        error = 1
    else:
        for item in data:
            item['ca_certificates'] = [parent.ngfw_certs[x] for x in item['ca_certificates']]

            err, result = parent.utm.add_client_certificate_profile(item)
            if err == 1:
                parent.stepChanged.emit(f'RED|    {result}')
                error = 1
                parent.error = 1
            elif err == 2:
                parent.stepChanged.emit(f'GRAY|    {result}')
            else:
                parent.stepChanged.emit(f'BLACK|    Импортирован профиль "{item["name"]}".')

    out_message = 'GREEN|    Импортированы профили пользовательских сертификатов в раздел "UserGate/Профили пользовательских сертификатов".'
    parent.stepChanged.emit('ORANGE|    Ошибка импорта профилей пользовательских сертификатов!' if error else out_message)


def import_zones(parent, path):
    """Импортируем зоны на NGFW, если они есть."""
    parent.stepChanged.emit('BLUE|Импорт зон в раздел "Сеть/Зоны".')
    error = 0

    json_file = os.path.join(path, 'config_zones.json')
    err, zones = read_json_file(parent, json_file)
    if err:
        error = 1
    else:
        service_for_zones = {v: k for k, v in zone_services.items()}

        for zone in zones:
            zone['name'] = zone['name'].translate(trans_name)
            for service in zone['services_access']:
                service['service_id'] = service_for_zones[service['service_id']]
            if parent.version < 7.1:
                zone.pop('sessions_limit_enabled', None)
                zone.pop('sessions_limit_threshold', None)
                zone.pop('sessions_limit_exclusions', None)
                if zone['networks'] and isinstance(zone['networks'][0], list):
                    zone['networks'] = []
                    zone['enable_antispoof'] = False
                    zone['antispoof_invert'] = False
                    parent.stepChanged.emit(f'ORANGE|    Для зоны "{zone["name"]}" удалены списки IP-адресов в защите от IP-спуфинга. Списки поддерживаются только в версии 7.1 и выше.')

                # Удаляем сервисы зон версии 7.1 которых нет в более старых версиях.
                new_services_access = []
                for service in zone['services_access']:
                    if service['service_id'] not in (31, 32, 33):
                        new_services_access.append(service)
                zone['services_access'] = new_services_access

            elif parent.version >= 7.1:
                sessions_limit_exclusions = []
                for item in zone['sessions_limit_exclusions']:
                    try:
                        item[1] = parent.ip_lists[item[1]]
                    except KeyError as err:
                        parent.stepChanged.emit(f'ORANGE|    Для зоны "{zone["name"]}" не найден список IP-адресов {err}. Список IP-адресов для ограничения сессий не импортирован.')
                        parent.error = 1
                        error = 1
                        continue
                    sessions_limit_exclusions.append(item)
                zone['sessions_limit_exclusions'] = sessions_limit_exclusions

                content = []
                zone_networks = []
                for net in zone['networks']:
                    if isinstance(net, str):
                        content.append({'value': net})
                    else:
                        if net[0] == 'list_id':
                            try:
                                net[1] = parent.ip_lists[net[1]]
                            except KeyError as err:
                                parent.stepChanged.emit(f'ORANGE|    Для зоны "{zone["name"]}" не найден список IP-адресов {err}. Список IP-адресов в защите от IP-спуфинга не импортирован.')
                                parent.error = 1
                                error = 1
                                continue
                        zone_networks.append(net)
                zone['networks'] = zone_networks
                if content:
                    nlist_name = f'For zone {zone["name"]}'
                    err, list_id = add_new_nlist(parent.utm, nlist_name, 'network', content)
                    if err == 1:
                        parent.stepChanged.emit(f'RED|    {list_id}')
                        parent.stepChanged.emit(f'ORANGE|    Для зоны "{zone["name"]}" не создан список IP-адресов в защите от IP-спуфинга.')
                        parent.error = 1
                        error = 1
                        zone['networks'] = []
                    elif err == 2:
                        parent.stepChanged.emit(f'BLACK|    Список IP-адресов "{nlist_name}" защиты от IP-спуфинга для зоны "{zone["name"]}" уже существует.')
                        zone['networks'] = [['list_id', parent.ip_lists[nlist_name]]]
                    else:
                        zone['networks'] = [['list_id', list_id]]
                        parent.ip_lists[nlist_name] = list_id
                        parent.stepChanged.emit(f'BLACK|    Cоздан список IP-адресов "{nlist_name}" защиты от IP-спуфинга для зоны "{zone["name"]}".')

            err, result = parent.utm.add_zone(zone)
            if err == 1:
                error = 1
                parent.error = 1
                parent.stepChanged.emit(f'RED|    {result}')
            elif err == 2:
                parent.stepChanged.emit(f'GRAY|    {result}')
                err, result2 = parent.utm.update_zone(parent.ngfw_zones[zone['name']], zone)
                if err == 1:
                    error = 1
                    parent.error = 1
                    parent.stepChanged.emit(f'RED|    {result2}')
                elif err == 2:
                    parent.stepChanged.emit(f'GRAY|    {result2}')
                else:
                    parent.stepChanged.emit(f'BLACK|    Зона "{zone["name"]}" updated.')
            else:
                parent.ngfw_zones[zone["name"]] = result
                parent.stepChanged.emit(f'BLACK|    Зона "{zone["name"]}" добавлена.')

    out_message = 'GREEN|    Зоны импортированы в раздел "Сеть/Зоны".'
    parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте зон.' if error else out_message)


def import_vlans(parent, path):
    """Импортируем интерфесы VLAN. Нельзя использовать интерфейсы Management и slave."""
    parent.stepChanged.emit('BLUE|Импорт VLAN в раздел "Сеть/Интерфейсы".')
    error = 0
    if isinstance(parent.ngfw_vlans, int):
        parent.stepChanged.emit(parent.new_vlans)
        if parent.ngfw_vlans == 1:
            parent.error = 1
        return

    err, result = parent.utm.get_netflow_profiles_list()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return
    list_netflow = {x['name']: x['id'] for x in result}
    list_netflow['undefined'] = 'undefined'

    if parent.version >= 7:
        err, result = parent.utm.get_lldp_profiles_list()
        if err:
            parent.stepChanged.emit(f'RED|    {result}')
            parent.error = 1
            return
        list_lldp = {x['name']: x['id'] for x in result}
        list_lldp['undefined'] = 'undefined'

    for item in parent.iface_settings:
        if 'kind' in item and item['kind'] == 'vlan':
            current_port = parent.new_vlans[item['vlan_id']]['port']
            current_zone = parent.new_vlans[item['vlan_id']]['zone']
            if item["vlan_id"] in parent.ngfw_vlans:
                parent.stepChanged.emit(f'GRAY|    VLAN {item["vlan_id"]} уже существует на порту {parent.ngfw_vlans[item["vlan_id"]]}')
                continue
            if current_port == "Undefined":
                parent.stepChanged.emit(f"dGRAY|    VLAN {item['vlan_id']} не импортирован так как для него не назначен порт.")
                continue
            item['link'] = current_port
            item['name'] = f'{current_port}.{item["vlan_id"]}'
            item['zone_id'] = 0 if current_zone == "Undefined" else parent.ngfw_zones[current_zone]
            item.pop('id', None)      # удаляем readonly поле
            item.pop('master', None)      # удаляем readonly поле
            item.pop('kind', None)    # удаляем readonly поле
            item.pop('mac', None)
            item['enabled'] = False   # Отключаем интерфейс. После импорта надо включить руками.

            if parent.version < 7.1:
                item.pop('ifalias', None)
                item.pop('flow_control', None)
            if parent.version < 7.0:
                item.pop('dhcp_default_gateway', None)
                item.pop('lldp_profile', None)
            else:
                try:
                    item['lldp_profile'] = list_lldp[item['lldp_profile']]
                except KeyError:
                    parent.stepChanged.emit(f'bRED|    Для VLAN "{item["name"]}" не найден lldp profile "{item["netflow_profile"]}". Импортируйте профили lldp.')
                    item['lldp_profile'] = 'undefined'
            try:
                item['netflow_profile'] = list_netflow[item['netflow_profile']]
            except KeyError:
                parent.stepChanged.emit(f'bRED|    Для VLAN "{item["name"]}" не найден netflow profile "{item["netflow_profile"]}". Импортируйте профили netflow.')
                item['netflow_profile'] = 'undefined'

            err, result = parent.utm.add_interface_vlan(item)
            if err:
                parent.stepChanged.emit(f'RED|    Error: Интерфейс {item["name"]} не импортирован!')
                parent.stepChanged.emit(f'RED|    {result}')
                error = 1
                parent.error = 1
            else:
                parent.ngfw_vlans[item['vlan_id']] = item['name']
                parent.stepChanged.emit(f'BLACK|    Добавлен VLAN {item["vlan_id"]}, name: {item["name"]}, zone: {current_zone}, ip: {", ".join(item["ipv4"])}.')

    out_message = 'GREEN|    Интерфейсы VLAN импортированы в раздел "Сеть/Интерфейсы".'
    parent.stepChanged.emit('ORANGE|    Произошла ошибка создания интерфейса VLAN!' if error else out_message)


def import_gateways(parent, path):
    """Импортируем список шлюзов"""
    parent.stepChanged.emit('BLUE|Импорт шлюзов в раздел "Сеть/Шлюзы".')
    parent.stepChanged.emit('bRED|    После импорта шлюзы будут в не активном состоянии. Необходимо проверить и включить нужные.')
    error = 0
    json_file = os.path.join(path, 'config_gateways.json')
    err, data = read_json_file(parent, json_file)
    if err:
        error = 1
    else:
        err, result = parent.utm.get_gateways_list()
        if err:
            parent.stepChanged.emit(f'RED|    {result}')
            parent.error = 1
            return
        gateways_list = {x.get('name', x['ipv4']): x['id'] for x in result}
        gateways_read_only = {x.get('name', x['ipv4']): x.get('is_automatic', False) for x in result}

        if parent.version >= 6:
            err, result = parent.utm.get_routes_list()
            if err:
                parent.stepChanged.emit(f'RED|    {result}')
                parent.error = 1
                return
            vrf_list = [x['name'] for x in result]

        for item in data:
            if parent.version >= 6:
                if item['vrf'] not in vrf_list:
                    err, result = add_empty_vrf(parent.utm, item['vrf'])
                    if err:
                        parent.stepChanged.emit(f'RED|    {result}')
                        parent.stepChanged.emit(f'RED|    Для шлюза "{item["name"]}" не удалось добавить VRF "{item["vrf"]}". Установлен VRF по умолчанию.')
                        item['vrf'] = 'default'
                        item['default'] = False
                    else:
                        parent.stepChanged.emit(f'NOTE|    Для шлюза "{item["name"]}" создан VRF "{item["vrf"]}".')
                        time.sleep(3)   # Задержка, т.к. vrf долго применяет конфигурацию.
            else:
                item['iface'] = 'undefined'
                item.pop('is_automatic', None)
                item.pop('vrf', None)
            
            if item['name'] in gateways_list:
                if not gateways_read_only[item['name']]:
                    err, result = parent.utm.update_gateway(gateways_list[item['name']], item)
                    if err:
                        parent.stepChanged.emit(f'RED|    {result} Шлюз "{item["name"]}"')
                        error = 1
                    else:
                        parent.stepChanged.emit(f'BLACK|    Шлюз "{item["name"]}" уже существует - Updated!')
                else:
                    parent.stepChanged.emit(f'NOTE|    Шлюз "{item["name"]}" - объект только для чтения. Not updated!')
            else:
                item['enabled'] = False
                err, result = parent.utm.add_gateway(item)
                if err:
                    parent.stepChanged.emit(f'RED|    {result}')
                    error = 1
                else:
                    gateways_list[item['name']] = result
                    parent.stepChanged.emit(f'BLACK|    Шлюз "{item["name"]}" добавлен.')
    if error:
        parent.error = 1
    parent.stepChanged.emit('ORANGE|    Ошибка импорта шлюзов!' if error else 'GREEN|    Шлюзы импортированы в раздел "Сеть/Шлюзы".')

    """Импортируем настройки проверки сети"""
    parent.stepChanged.emit('BLUE|Импорт настроек проверки сети раздела "Сеть/Шлюзы/Проверка сети".')
    error = 0
    json_file = os.path.join(path, 'config_gateway_failover.json')
    err, data = read_json_file(parent, json_file)
    if err:
        error = 1
    else:
        err, result = parent.utm.set_gateway_failover(data)
        if err:
            parent.stepChanged.emit(f'RED|    {result}')
            parent.error = 1
            error = 1

    out_message = 'GREEN|    Настройки проверки сети обновлены.'
    parent.stepChanged.emit('ORANGE|    Произошла ошибка при обновлении настроек проверки сети!' if error else out_message)


def import_dhcp_subnets(parent, path):
    """Импортируем настойки DHCP"""
    parent.stepChanged.emit('BLUE|Импорт настроек DHCP раздела "Сеть/DHCP".')
    if isinstance(parent.ngfw_ports, int):
        parent.stepChanged.emit(parent.dhcp_settings)
        if parent.ngfw_ports == 1:
            parent.error = 1
        return
    error = 0

    err, result = parent.utm.get_dhcp_list()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return
    ngfw_dhcp_subnets = [x['name'] for x in result]

    for item in parent.dhcp_settings:
        if item['iface_id'] == 'Undefined':
            parent.stepChanged.emit(f'GRAY|    DHCP subnet "{item["name"]}" не добавлен так как для него не указан порт.')
            continue
        if item['name'] in ngfw_dhcp_subnets:
            parent.stepChanged.emit(f'GRAY|    DHCP subnet "{item["name"]}" не добавлен так как уже существует.')
            continue
        if item['iface_id'] not in parent.ngfw_ports:
            parent.stepChanged.emit(f'rNOTE|    DHCP subnet "{item["name"]}" не добавлен так как порт: {item["iface_id"]} не существует.')
            continue

        err, result = parent.utm.add_dhcp_subnet(item)
        if err == 1:
            parent.stepChanged.emit(f'RED|    {result}   [subnet "{item["name"]}"]')
            parent.error = 1
            error = 1
        elif err == 2:
            parent.stepChanged.emit(f'NOTE|    {result}')
        else:
            parent.stepChanged.emit(f'BLACK|    DHCP subnet "{item["name"]}" добавлен.')

    out_message = 'GREEN|    Настройки DHCP импортированы.'
    parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте настроек DHCP!' if error else out_message)


def import_dns_proxy(parent, path):
    """Импортируем настройки DNS прокси"""
    parent.stepChanged.emit('BLUE|Импорт настроек DNS-прокси раздела "Сеть/DNS/Настройки DNS-прокси".')
    error = 0
    json_file = os.path.join(path, 'config_dns_proxy.json')
    err, result = read_json_file(parent, json_file)
    if err:
        error = 1
    else:
        if parent.version < 6.0:
            result.pop('dns_receive_timeout', None)
            result.pop('dns_max_attempts', None)
        for key, value in result.items():
            err, result = parent.utm.set_settings_param(key, value)
            if err:
                parent.stepChanged.emit(f'RED|    {result}')
                parent.error = 1
                error = 1

    out_message = 'GREEN|    Настройки DNS-прокси импортированы.'
    parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте настроек DNS-прокси!' if error else out_message)


def import_dns_servers(parent, path):
    """Импортируем список системных DNS серверов"""
    parent.stepChanged.emit('BLUE|Импорт системных DNS серверов раздела "Сеть/DNS/Системные DNS-серверы".')
    error = 0
    json_file = os.path.join(path, 'config_dns_servers.json')
    err, data = read_json_file(parent, json_file)
    if err:
        error = 1
    else:
        for item in data:
            item.pop('id', None)
            item.pop('is_bad', None)
            err, result = parent.utm.add_dns_server(item)
            if err == 1:
                parent.stepChanged.emit(f'RED|    {result}')
                parent.error = 1
                error = 1
            elif err == 2:
                parent.stepChanged.emit(f'GRAY|    {result}')
            else:
                parent.stepChanged.emit(f'BLACK|    DNS сервер "{item["dns"]}" добавлен.')

    out_message = 'GREEN|    Системные DNS-сервера импортированы.'
    parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте системных DNS-серверов!' if error else out_message)


def import_dns_rules(parent, path):
    """Импортируем список правил DNS прокси"""
    parent.stepChanged.emit('BLUE|Импорт списка правил DNS-прокси раздела "Сеть/DNS/Правила DNS".')
    error = 0
    json_file = os.path.join(path, 'config_dns_rules.json')
    err, rules = read_json_file(parent, json_file)
    if err:
        error = 1
    else:
        dns_rules = [x['name'] for x in parent.utm._server.v1.dns.rules.list(parent.utm._auth_token, 0, 1000, {})['items']]
        for item in rules:
            if parent.version >= 6.0:
                item['position'] = 'last'
            if item['name'] in dns_rules:
                parent.stepChanged.emit(f'GRAY|    Правило DNS прокси "{item["name"]}" уже существует.')
            else:
                err, result = parent.utm.add_dns_rule(item)
                if err == 1:
                    parent.stepChanged.emit(f'RED|    {result}')
                    parent.error = 1
                    error = 1
                elif err == 2:
                    parent.stepChanged.emit(f'GRAY|    {result}')
                else:
                    parent.stepChanged.emit(f'BLACK|    Правило DNS прокси "{item["name"]}" добавлено.')

    out_message = 'GREEN|    Список правил DNS-прокси импортирован.'
    parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте списка правил DNS-прокси!' if error else out_message)


def import_dns_static(parent, path):
    """Импортируем статические записи DNS прокси"""
    parent.stepChanged.emit('BLUE|Импорт статических записей DNS-прокси раздела "Сеть/DNS/Статические записи".')
    error = 0
    json_file = os.path.join(path, 'config_dns_static.json')
    err, data = read_json_file(parent, json_file)
    if err:
        error = 1
    else:
        for item in data:
            err, result = parent.utm.add_dns_static_record(item)
            if err == 1:
                parent.stepChanged.emit(f'RED|    {result}')
                parent.error = 1
                error = 1
            elif err == 2:
                parent.stepChanged.emit(f'GRAY|    {result}')
            else:
                parent.stepChanged.emit(f'BLACK|    Статическая запись DNS "{item["name"]}" добавлена.')

    out_message = 'GREEN|    Статические записи DNS-прокси импортированы.'
    parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте статических записей DNS-прокси!' if error else out_message)

    
def import_dns_config(parent, path):
    """Импортируем настройки DNS"""
    import_dns_proxy(parent, path)
    import_dns_servers(parent, path)
    import_dns_rules(parent, path)
    import_dns_static(parent, path)


def import_vrf(parent, path):
    """Импортируем список виртуальных маршрутизаторов"""
    parent.stepChanged.emit('BLUE|Импорт списка виртуальных маршрутизаторов в раздел "Сеть/Виртуальные маршрутизаторы".')
    parent.stepChanged.emit('bRED|    Добавляемые маршруты будут в не активном состоянии. Необходимо будет проверить маршрутизацию и включить их.')
    parent.stepChanged.emit('bRED|    Если вы используете BGP, по окончании импорта включите фильтры BGP-соседей и Routemaps в свойствах соседей.')
    error = 0
    json_file = os.path.join(path, 'config_vrf.json')
    err, data = read_json_file(parent, json_file)
    if err:
        error = 1
    else:
        err, result = parent.utm.get_routes_list()
        if err:
            parent.stepChanged.emit(f'RED|    {result}')
            parent.error = 1
            return
        virt_routes = {x['name']: x['id'] for x in result}

        if parent.version >= 7.1:
            err, result = parent.utm.get_bfd_profiles()
            if err:
                parent.stepChanged.emit(f'RED|    {result}')
                parent.error = 1
                return
            bfd_profiles = {x['name']: x['id'] for x in result}
            bfd_profiles[-1] = -1
    
        for item in data:
            for x in item['routes']:
                x['enabled'] = False
            if item['ospf']:
                item['ospf']['enabled'] = False
                for x in item['ospf']['interfaces']:
                    if parent.version < 7.1:
                        x.pop('bfd_profile', None) 
                    else:
                        try:
                            x['bfd_profile'] = bfd_profiles[x['bfd_profile']]
                        except KeyError:
                            x['bfd_profile'] = -1
                            parent.stepChanged.emit(f'rNOTE|    Не найден профиль BFD для VRF "{item["name"]}". Установлено значение по умолчанию.')
            if item['rip']:
                item['rip']['enabled'] = False
            if item['pimsm']:
                item['pimsm']['enabled'] = False
            if item['bgp']:
                item['bgp']['enabled'] = False
                if parent.version < 7:
                    item['bgp']['as_number'] = str(item['bgp']['as_number'])
                for x in item['bgp']['neighbors']:
                    x['filter_in'] = []
                    x['filter_out'] = []
                    x['routemap_in'] = []
                    x['routemap_out'] = []
                    if parent.version < 7:
                        x['remote_asn'] = str(x['remote_asn'])
                    if parent.version < 7.1:
                        x.pop('bfd_profile', None) 
                    else:
                        try:
                            x['bfd_profile'] = bfd_profiles[x['bfd_profile']]
                        except KeyError:
                            x['bfd_profile'] = -1
                            parent.stepChanged.emit(f'rNOTE|    Не найден профиль BFD для VRF "{item["name"]}". Установлено значение по умолчанию.')

            if item['name'] in virt_routes:
                err, result = parent.utm.update_vrf(virt_routes[item['name']], item)
                if err:
                    parent.stepChanged.emit(f'RED|    {result}  [vrf: "{item["name"]}"]')
                    parent.error = 1
                    error = 1
                else:
                    parent.stepChanged.emit(f'BLACK|    Виртуальный маршрутизатор "{item["name"]}" updated.')
            else:
                err, result = parent.utm.add_vrf(item)
                if err:
                    parent.stepChanged.emit(f'RED|    {result}  [vrf: "{item["name"]}"]')
                    parent.error = 1
                    error = 1
                else:
                    parent.stepChanged.emit(f'BLACK|    Создан виртуальный маршрутизатор "{item["name"]}".')

    out_message = 'GREEN|    Виртуальные маршрутизаторы импортированы в раздел "Сеть/Виртуальные маршрутизаторы".'
    parent.stepChanged.emit('ORANGE|    Ошибка импорта виртуальных маршрутизаторов!' if error else out_message)


def import_wccp_rules(parent, path):
    """Импортируем список правил WCCP"""
    parent.stepChanged.emit('BLUE|Импорт списка правил WCCP в раздел "Сеть/WCCP".')
    error = 0
    json_file = os.path.join(path, 'config_wccp.json')
    err, data = read_json_file(parent, json_file)
    if err:
        error = 1
    else:
        err, result = parent.utm.get_wccp_list()
        if err:
            parent.stepChanged.emit(f'RED|    {result}')
            parent.error = 1
            return
        wccp_rules = {x['name']: x['id'] for x in result}

        for item in data:
            if parent.version < 7:
                item['ports'] = [str(x) for x in item['ports']]
            if parent.version == 7.0:
                item['mask_value'] = ""
            if item['routers']:
                routers = []
                for x in item['routers']:
                    if x[0] == 'list_id':
                        try:
                            x[1] = parent.ip_lists[x[1]]
                        except KeyError as err:
                            parent.stepChanged.emit(f'ORANGE|    Не найден список {err} для правила "{item["name"]}". Загрузите списки IP-адресов и повторите попытку.')
                            continue
                    routers.append(x)
                item['routers'] = routers

            if item['name'] in wccp_rules:
                if parent.version >= 6:
                    err, result = parent.utm.update_wccp_rule(wccp_rules[item['name']], item)
                    if err:
                        parent.stepChanged.emit(f'RED|    {result}')
                        parent.error = 1
                        error = 1
                    else:
                        parent.stepChanged.emit(f'GRAY|    Правило WCCP "{item["name"]}" уже существует. Произведено обновление.')
                else:
                    parent.stepChanged.emit(f'GRAY|    Правило WCCP "{item["name"]}" уже существует.')
            else:
                err, result = parent.utm.add_wccp_rule(item)
                if err:
                    parent.stepChanged.emit(f'RED|    {result}')
                    parent.error = 1
                    error = 1
                else:
                    parent.stepChanged.emit(f'BLACK|    Правило WCCP "{item["name"]}" добавлено.')

    out_message = 'GREEN|    Список правил WCCP импортирован в раздел "Сеть/WCCP".'
    parent.stepChanged.emit('ORANGE|    Ошибка импорта списка правил WCCP!' if error else out_message)


def import_local_groups(parent, path):
    """Импортируем список локальных групп пользователей"""
    parent.stepChanged.emit('BLUE|Импорт списка локальных групп пользователей в раздел "Пользователи и устройства/Группы".')
    error = 0
    json_file = os.path.join(path, 'config_groups.json')
    err, groups = read_json_file(parent, json_file)
    if err:
        parent.error = 1
        return

    for item in groups:
        users = item.pop('users')
        # В версии 5 API добавления группы не проверяет что группа уже существует.
        if item['name'] in parent.list_groups:
            parent.stepChanged.emit(f'GRAY|    Группа "{item["name"]}" уже существует.')
        else:
            err, result = parent.utm.add_group(item)
            if err == 1:
                parent.stepChanged.emit(f'RED|    {result}')
                parent.error = 1
                error = 1
                continue
            elif err == 2:
                parent.stepChanged.emit(f'GRAY|    {result}.') # В версиях 6 и выше проверяется что группа уже существует.
            else:
                parent.list_groups[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Локальная группа "{item["name"]}" добавлена.')

        # В версии 5 в группах нет доменных пользователей.
        if parent.version <= 6:
            continue
        # Добавляем доменных пользователей в группу.
        for user_name in users:
            user_array = user_name.split(' ')
            if len(user_array) > 1 and ('\\' in user_array[1]):
                domain, name = user_array[1][1:len(user_array[1])-1].split('\\')
                err1, result1 = parent.utm.get_ldap_user_guid(domain, name)
                if err1:
                    parent.stepChanged.emit(f'RED|    {result1}')
                    parent.error = 1
                    error = 1
                    break
                elif not result1:
                    parent.stepChanged.emit(f'bRED|    Нет LDAP-коннектора для домена "{domain}"! Доменные пользователи не импортированы в группу "{item["name"]}".')
                    parent.stepChanged.emit(f'bRED|    Импортируйте и настройте LDAP-коннектор. Затем повторите импорт групп.')
                    break
                err2, result2 = parent.utm.add_user_in_group(parent.list_groups[item['name']], result1)
                if err2:
                    parent.stepChanged.emit(f'RED|    {result2}  [{user_name}]')
                    parent.error = 1
                    error = 1
                else:
                    parent.stepChanged.emit(f'BLACK|       Пользователь "{user_name}" добавлен в группу "{item["name"]}".')

    out_message = 'GREEN|    Список локальных групп пользователей импортирован в раздел "Пользователи и устройства/Группы".'
    parent.stepChanged.emit('ORANGE|    Ошибка импорта списка локальных групп пользователей!' if error else out_message)


def import_local_users(parent, path):
    """Импортируем список локальных пользователей"""
    parent.stepChanged.emit('BLUE|Импорт списка локальных пользователей в раздел "Пользователи и устройства/Пользователи".')
    error = 0
    json_file = os.path.join(path, 'config_users.json')
    err, users = read_json_file(parent, json_file)
    if err:
        parent.error = 1
        return

    for item in users:
        user_groups = item.pop('groups', None)
        # В версии 5 API добавления пользователя не проверяет что он уже существует.
        if item['name'] in parent.list_users:
            parent.stepChanged.emit(f'GRAY|    Пользователь "{item["name"]}" уже существует.')
        else:
            err, result = parent.utm.add_user(item)
            if err == 1:
                parent.stepChanged.emit(f'RED|    {result}')
                parent.error = 1
                error = 1
                break
            elif err == 2:
                parent.stepChanged.emit(f'GRAY|    {result}.') # В версиях 6 и выше проверяется что пользователь уже существует.
            else:
                parent.list_users[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Добавлен локальный пользователь "{item["name"]}".')

        # Добавляем пользователя в группу.
        for group in user_groups:
            try:
                group_guid = parent.list_groups[group]
            except KeyError as err:
                parent.stepChanged.emit(f'bRED|       Не найдена группа {err} для пользователя {item["name"]}. Импортируйте список групп и повторите импорт пользователей.')
            else:
                err2, result2 = parent.utm.add_user_in_group(group_guid, parent.list_users[item['name']])
                if err2:
                    parent.stepChanged.emit(f'RED|       {result2}  [User: {item["name"]}, Group: {group}]')
                    parent.error = 1
                    error = 1
                else:
                    parent.stepChanged.emit(f'BLACK|       Пользователь "{item["name"]}" добавлен в группу "{group}".')

    out_message = 'GREEN|    Список локальных пользователей импортирован в раздел "Пользователи и устройства/Пользователи".'
    parent.stepChanged.emit('ORANGE|    Ошибка импорта списка локальных пользователей!' if error else out_message)


def import_ldap_servers(parent, path):
    """Импортируем список серверов LDAP"""
    parent.stepChanged.emit('BLUE|Импорт списка серверов LDAP в раздел "Пользователи и устройства/Серверы аутентификации".')
    error = 0
    json_file = os.path.join(path, 'config_ldap_servers.json')
    err, data = read_json_file(parent, json_file)
    if err:
        if err in (1, 2):
            parent.error = 1
        return

    err, result = parent.utm.get_ldap_servers()
    if err == 1:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        error = 1
    else:
        ldap_servers = {x['name'].strip().translate(trans_name): x['id'] for x in result}

        for item in data:
            item['name'] = item['name'].strip().translate(trans_name)
            if item['name'] in ldap_servers:
                parent.stepChanged.emit(f'GRAY|    LDAP-сервер "{item["name"]}" уже существует.')
            else:
                item['enabled'] = False
                item['keytab_exists'] = False
                item.pop("cc", None)
                err, result = parent.utm.add_auth_server('ldap', item)
                if err:
                    parent.stepChanged.emit(f'RED|    {result}')
                    parent.error = 1
                    error = 1
                else:
                    ldap_servers[item['name']] = result
                    parent.stepChanged.emit(f'BLACK|    Сервер аутентификации LDAP "{item["name"]}" добавлен.')
                    parent.stepChanged.emit(f'NOTE|    Необходимо включить "{item["name"]}", ввести пароль и импортировать keytab файл.')

    out_message = 'GREEN|    Список серверов LDAP импортирован в раздел "Пользователи и устройства/Серверы аутентификации".'
    parent.stepChanged.emit('ORANGE|    Ошибка импорта серверов LDAP!' if error else out_message)


def import_ntlm_server(parent, path):
    """Импортируем список серверов NTLM"""
    parent.stepChanged.emit('BLUE|Импорт списка серверов NTLM в раздел "Пользователи и устройства/Серверы аутентификации".')
    error = 0
    json_file = os.path.join(path, 'config_ntlm_servers.json')
    err, data = read_json_file(parent, json_file)
    if err:
        if err in (1, 2):
            parent.error = 1
        return

    err, result = parent.utm.get_ntlm_servers()
    if err == 1:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        error = 1
    else:
        ntlm_servers = {x['name'].strip().translate(trans_name): x['id'] for x in result}

        for item in data:
            item['name'] = item['name'].strip().translate(trans_name)
            if item['name'] in ntlm_servers:
                parent.stepChanged.emit(f'GRAY|    NTLM-сервер "{item["name"]}" уже существует.')
            else:
                item['enabled'] = False
                item.pop("cc", None)
                err, result = parent.utm.add_auth_server('ntlm', item)
                if err:
                    parent.stepChanged.emit(f'RED|    {result}')
                    parent.error = 1
                    error = 1
                else:
                    ntlm_servers[item['name']] = result
                    parent.stepChanged.emit(f'BLACK|    Сервер аутентификации NTLM "{item["name"]}" добавлен.')
                    parent.stepChanged.emit(f'NOTE|    Необходимо включить "{item["name"]}".')

    out_message = 'GREEN|    Список серверов NTLM импортирован в раздел "Пользователи и устройства/Серверы аутентификации".'
    parent.stepChanged.emit('ORANGE|    Ошибка импорта серверов NTLM!' if error else out_message)


def import_radius_server(parent, path):
    """Импортируем список серверов RADIUS"""
    parent.stepChanged.emit('BLUE|Импорт списка серверов RADIUS в раздел "Пользователи и устройства/Серверы аутентификации".')
    error = 0
    json_file = os.path.join(path, 'config_radius_servers.json')
    err, data = read_json_file(parent, json_file)
    if err:
        if err in (1, 2):
            parent.error = 1
        return

    err, result = parent.utm.get_radius_servers()
    if err == 1:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        error = 1
    else:
        radius_servers = {x['name'].strip().translate(trans_name): x['id'] for x in result}

        for item in data:
            item['name'] = item['name'].strip().translate(trans_name)
            if item['name'] in radius_servers:
                parent.stepChanged.emit(f'GRAY|    RADIUS-сервер "{item["name"]}" уже существует.')
            else:
                item['enabled'] = False
                item.pop("cc", None)
                err, result = parent.utm.add_auth_server('radius', item)
                if err:
                    parent.stepChanged.emit(f'RED|    {result}')
                    parent.error = 1
                    error = 1
                else:
                    radius_servers[item['name']] = result
                    parent.stepChanged.emit(f'BLACK|    Сервер аутентификации RADIUS "{item["name"]}" добавлен.')
                    parent.stepChanged.emit(f'NOTE|    Необходимо включить "{item["name"]}" и ввести пароль.')

    out_message = 'GREEN|    Список серверов RADIUS импортирован в раздел "Пользователи и устройства/Серверы аутентификации".'
    parent.stepChanged.emit('ORANGE|    Ошибка импорта серверов RADIUS!' if error else out_message)


def import_tacacs_server(parent, path):
    """Импортируем список серверов TACACS+"""
    parent.stepChanged.emit('BLUE|Импорт списка серверов TACACS+ в раздел "Пользователи и устройства/Серверы аутентификации".')
    error = 0
    json_file = os.path.join(path, 'config_tacacs_servers.json')
    err, data = read_json_file(parent, json_file)
    if err:
        if err in (1, 2):
            parent.error = 1
        return

    err, result = parent.utm.get_tacacs_servers()
    if err == 1:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        error = 1
    else:
        tacacs_servers = {x['name'].strip().translate(trans_name): x['id'] for x in result}

        for item in data:
            item['name'] = item['name'].strip().translate(trans_name)
            if item['name'] in tacacs_servers:
                parent.stepChanged.emit(f'GRAY|    TACACS-сервер "{item["name"]}" уже существует.')
            else:
                item['enabled'] = False
                item.pop("cc", None)
                err, result = parent.utm.add_auth_server('tacacs', item)
                if err:
                    parent.stepChanged.emit(f'RED|    {result}')
                    parent.error = 1
                    error = 1
                else:
                    tacacs_servers[item['name']] = result
                    parent.stepChanged.emit(f'BLACK|    Сервер аутентификации TACACS+ "{item["name"]}" добавлен.')
                    parent.stepChanged.emit(f'NOTE|    Необходимо включить "{item["name"]}" и ввести секретный ключ.')

    out_message = 'GREEN|    Список серверов TACACS+ импортирован в раздел "Пользователи и устройства/Серверы аутентификации".'
    parent.stepChanged.emit('ORANGE|    Ошибка импорта серверов TACACS+!' if error else out_message)


def import_saml_server(parent, path):
    """Импортируем список серверов SAML"""
    parent.stepChanged.emit('BLUE|Импорт списка серверов SAML в раздел "Пользователи и устройства/Серверы аутентификации".')
    error = 0
    json_file = os.path.join(path, 'config_saml_servers.json')
    err, data = read_json_file(parent, json_file)
    if err:
        if err in (1, 2):
            parent.error = 1
        return

    err, result = parent.utm.get_saml_servers()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        error = 1
    else:
        saml_servers = {x['name'].strip().translate(trans_name): x['id'] for x in result}

        for item in data:
            item['name'] = item['name'].strip().translate(trans_name)
            if item['name'] in saml_servers:
                parent.stepChanged.emit(f'GRAY|    SAML-сервер "{item["name"]}" уже существует.')
            else:
                item['enabled'] = False
                item.pop("cc", None)
                try:
                    item['certificate_id'] = parent.ngfw_certs[item['certificate_id']]
                except KeyError:
                    parent.stepChanged.emit(f'bRED|    Для "{item["name"]}" не найден сертификат "{item["certificate_id"]}".')
                    item['certificate_id'] = 0

                err, result = parent.utm.add_auth_server('saml', item)
                if err:
                    parent.stepChanged.emit(f'RED|    {result}')
                    parent.error = 1
                    error = 1
                else:
                    saml_servers[item['name']] = result
                    parent.stepChanged.emit(f'BLACK|    Сервер аутентификации SAML "{item["name"]}" добавлен.')
                    parent.stepChanged.emit(f'NOTE|    Необходимо включить "{item["name"]}" и загрузить SAML metadata.')

    out_message = 'GREEN|    Список серверов SAML импортирован в раздел "Пользователи и устройства/Серверы аутентификации".'
    parent.stepChanged.emit('ORANGE|    Ошибка импорта серверов SAML!' if error else out_message)


def import_auth_servers(parent, path):
    """Импортируем список серверов аутентификации"""
    import_ldap_servers(parent, path)
    import_ntlm_server(parent, path)
    import_radius_server(parent, path)
    import_tacacs_server(parent, path)
    import_saml_server(parent, path)
    

def import_2fa_profiles(parent, path):
    """Импортируем список 2FA профилей"""
    parent.stepChanged.emit('BLUE|Импорт списка 2FA профилей в раздел "Пользователи и устройства/Профили MFA".')
    error = 0
    json_file = os.path.join(path, 'config_2fa_profiles.json')
    err, data = read_json_file(parent, json_file)
    if err:
        if err in (1, 2):
            parent.error = 1
        return

    err, result = parent.utm.get_notification_profiles_list()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return
    else:
        list_notifications = {x['name'].strip().translate(trans_name): x['id'] for x in result}
        list_notifications[-5] = -5

    err, result = parent.utm.get_2fa_profiles()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return
    else:
        profiles_2fa = {x['name'].strip().translate(trans_name): x['id'] for x in result}

    for item in data:
        item['name'] = item['name'].strip().translate(trans_name)
        if item['name'] in profiles_2fa:
            parent.stepChanged.emit(f'GRAY|    Профиль MFA "{item["name"]}" уже существует.')
        else:
            if item['type'] == 'totp':
                if item['init_notification_profile_id'] not in list_notifications.keys():
                    parent.stepChanged.emit(f'bRED|       Профиль MFA "{item["name"]}" не добавлен. Не найден профиль оповещения. Загрузите профили оповещения и повторите попытку.')
                    parent.error = 1
                    error = 1
                    continue
                item['init_notification_profile_id'] = list_notifications[item['init_notification_profile_id']]
            else:
                if item['auth_notification_profile_id'] not in list_notifications.keys():
                    parent.stepChanged.emit(f'bRED|       Профиль MFA "{item["name"]}" не добавлен. Не найден профиль оповещения. Загрузите профили оповещения и повторите попытку.')
                    parent.error = 1
                    error = 1
                    continue
                item['auth_notification_profile_id'] = list_notifications[item['auth_notification_profile_id']]
            err, result = parent.utm.add_2fa_profile(item)
            if err:
                parent.stepChanged.emit(f'RED|    {result}  [Profile: item["name"]]')
                parent.error = 1
                error = 1
            else:
                profiles_2fa[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Профиль MFA "{item["name"]}" добавлен.')

    out_message = 'GREEN|    Список 2FA профилей импортирован в раздел "Пользователи и устройства/Профили MFA".'
    parent.stepChanged.emit('ORANGE|    Ошибка импорта списка 2FA профилей!' if error else out_message)


def import_auth_profiles(parent, path):
    """Импортируем список профилей аутентификации"""
    parent.stepChanged.emit('BLUE|Импорт списка профилей аутентификации в раздел "Пользователи и устройства/Профили аутентификации".')
    error = 0
    json_file = os.path.join(path, 'config_auth_profiles.json')
    err, data = read_json_file(parent, json_file)
    if err:
        if err in (1, 2):
            parent.error = 1
        return

    err, ldap, radius, tacacs, ntlm, saml = parent.utm.get_auth_servers()
    if err:
        parent.stepChanged.emit(f'RED|    {ldap}')
        parent.error = 1
        return
    auth_servers = {x['name'].strip().translate(trans_name): x['id'] for x in [*ldap, *radius, *tacacs, *ntlm, *saml]}

    err, result = parent.utm.get_2fa_profiles()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return
    profiles_2fa = {x['name'].strip().translate(trans_name): x['id'] for x in result}

    auth_type = {
        'ldap': 'ldap_server_id',
        'radius': 'radius_server_id',
        'tacacs_plus': 'tacacs_plus_server_id',
        'ntlm': 'ntlm_server_id',
        'saml_idp': 'saml_idp_server_id'
    }

    for item in data:
        item['name'] = item['name'].strip().translate(trans_name)
        if item['2fa_profile_id']:
            try:
                item['2fa_profile_id'] = profiles_2fa[item['2fa_profile_id']]
            except KeyError:
                parent.stepChanged.emit(f'bRED|    Для "{item["name"]}" не найден профиль MFA "{item["2fa_profile_id"]}". Загрузите профили MFA и повторите попытку.')
                item['2fa_profile_id'] = False
                parent.error = 1
                error = 1

        for auth_method in item['allowed_auth_methods']:
            if len(auth_method) == 2:
                method_server_id = auth_type[auth_method['type']]
                try:
                    auth_method[method_server_id] = auth_servers[auth_method[method_server_id]]
                except KeyError:
                    parent.stepChanged.emit(f'bRED|    Для "{item["name"]}" не найден сервер аутентификации "{auth_method[method_server_id]}". Загрузите серверы аутентификации и повторите попытку.')
                    auth_method.clear()
                    parent.error = 1
                    error = 1

                if 'saml_idp_server_id' in auth_method and parent.version < 6:
                    auth_method['saml_idp_server'] = auth_method.pop('saml_idp_server_id', False)

        item['allowed_auth_methods'] = [x for x in item['allowed_auth_methods'] if x]

        if item['name'] in parent.auth_profiles:
            parent.stepChanged.emit(f'GRAY|    Профиль аутентификации "{item["name"]}" уже существует.')
            err, result = parent.utm.update_auth_profile(parent.auth_profiles[item['name']], item)
            if err:
                parent.stepChanged.emit(f'RED|       {result}  [Profile: item["name"]]')
                parent.error = 1
                error = 1
            else:
                parent.stepChanged.emit(f'BLACK|       Профиль аутентификации "{item["name"]}" updated.')
        else:
            err, result = parent.utm.add_auth_profile(item)
            if err:
                parent.stepChanged.emit(f'RED|    {result}  [Profile: item["name"]]')
                parent.error = 1
                error = 1
            else:
                parent.auth_profiles[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Профиль аутентификации "{item["name"]}" добавлен.')

    out_message = 'GREEN|    Список профилей аутентификации импортирован в раздел "Пользователи и устройства/Профили аутентификации".'
    parent.stepChanged.emit('ORANGE|    Ошибка импорта профилей аутентификации.' if error else out_message)


def import_captive_profiles(parent, path):
    """Импортируем список Captive-профилей"""
    parent.stepChanged.emit('BLUE|Импорт списка Captive-профилей в раздел "Пользователи и устройства/Captive-профили".')
    error = 0
    json_file = os.path.join(path, 'config_captive_profiles.json')
    err, data = read_json_file(parent, json_file)
    if err:
        if err in (1, 2):
            parent.error = 1
        return

    err, result = parent.utm.get_templates_list()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return
    list_templates = {x['name']: x['id'] for x in result}

    err, result = parent.utm.get_notification_profiles_list()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return
    list_notifications = {x['name'].strip().translate(trans_name): x['id'] for x in result}

    err, result = parent.utm.get_captive_profiles()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return
    captive_profiles = {x['name'].strip().translate(trans_name): x['id'] for x in result}

    if (6 <= parent.version < 7.1):
        result = parent.utm._server.v3.accounts.groups.list(parent.utm._auth_token, 0, 1000, {}, [])['items']
        list_groups = {x['name'].strip().translate(trans_name): x['id'] for x in result}

    if parent.version >= 7.1:
        err, result = parent.utm.get_client_certificate_profiles()
        if err:
            parent.stepChanged.emit(f'RED|    {result}')
            parent.error = 1
            return
        client_cert_profiles = {x['name']: x['id'] for x in result}
        client_cert_profiles[0] = 0

    for item in data:
        item['name'] = item['name'].strip().translate(trans_name)
        item['captive_template_id'] = list_templates.get(item['captive_template_id'], -1)
        try:
            item['user_auth_profile_id'] = parent.auth_profiles[item['user_auth_profile_id']]
        except KeyError:
            parent.stepChanged.emit(f'bRED|    Не найден профиль аутентификации "{item["user_auth_profile_id"]}". Загрузите профили аутентификации и повторите попытку.')
            item['user_auth_profile_id'] = 1

        if item['notification_profile_id'] != -1:
            try:
                item['notification_profile_id'] = list_notifications[item['notification_profile_id']]
            except KeyError:
                parent.stepChanged.emit(f'bRED|    Не найден профиль оповещения "{item["notification_profile_id"]}". Загрузите профили оповещения и повторите попытку.')
                item['notification_profile_id'] = -1
        try:
            if (6 <= parent.version < 7.1):
                item['ta_groups'] = [list_groups[name] for name in item['ta_groups']]
            else:
                item['ta_groups'] = [parent.list_groups[name] for name in item['ta_groups']]
        except KeyError as err:
            parent.stepChanged.emit(f'bRED|    Группа пользователей "{err}" не найдена. Загрузите локальные группы и повторите попытку.')
            item['ta_groups'] = []

        if item['ta_expiration_date']:
            item['ta_expiration_date'] = item['ta_expiration_date'].replace(' ', 'T')
        else:
            item.pop('ta_expiration_date', None)

        if parent.version >= 7.1:
            item.pop('use_https_auth', None)
            try:
                item['client_certificate_profile_id'] = client_cert_profiles[item['client_certificate_profile_id']]
            except KeyError:
                parent.stepChanged.emit(f'bRED|    Не найден профиль сертификата пользователя "{item["client_certificate_profile_id"]}". Загрузите профили сертификата пользователя и повторите попытку.')
                item['captive_auth_mode'] = 'aaa'
                item['client_certificate_profile_id'] = 0
        else:
            item.pop('captive_auth_mode', None)
            item.pop('client_certificate_profile_id', None)

        if item['name'] in captive_profiles:
            parent.stepChanged.emit(f'GRAY|    Captive-профиль "{item["name"]}" уже существует.')
            err, result = parent.utm.update_captive_profile(captive_profiles[item['name']], item)
            if err:
                parent.stepChanged.emit(f'RED|    {result}  [Captive-profile: {item["name"]}]')
                parent.error = 1
                error = 1
            else:
                parent.stepChanged.emit(f'BLACK|    Captive-профиль "{item["name"]}" updated.')
        else:
            err, result = parent.utm.add_captive_profile(item)
            if err:
                parent.stepChanged.emit(f'RED|    {result}  [Captive-profile: {item["name"]}]')
                parent.error = 1
                error = 1
            else:
                captive_profiles[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Captive-профиль "{item["name"]}" добавлен.')

    out_message = 'GREEN|    Список Captive-профилей импортирован в раздел "Пользователи и устройства/Captive-профили".'
    parent.stepChanged.emit('ORANGE|    Ошибка импорта Captive-профилей.' if error else out_message)


def import_captive_portal_rules(parent, path):
    """Импортируем список правил Captive-портала"""
    parent.stepChanged.emit('BLUE|Импорт списка правил Captive-портала в раздел "Пользователи и устройства/Captive-портал".')
    error = 0
    json_file = os.path.join(path, 'config_captive_portal_rules.json')
    err, data = read_json_file(parent, json_file)
    if err:
        if err in (1, 2):
            parent.error = 1
        return

    err, result = parent.utm.get_captive_profiles()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return
    captive_profiles = {x['name'].strip().translate(trans_name): x['id'] for x in result}

    err, result = parent.utm.get_captive_portal_rules()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return
    captive_portal_rules = {x['name'].strip().translate(trans_name): x['id'] for x in result}

    for item in data:
        item['name'] = item['name'].strip().translate(trans_name)
        if item['profile_id']:
            try:
                item['profile_id'] = captive_profiles[item['profile_id']]
            except KeyError:
                parent.stepChanged.emit('bRED|    Captive-профиль "{item["profile_id"]}"  в правиле "{item["name"]}" не найден. Загрузите Captive-профили и повторите попытку.')
                item['profile_id'] = 0
        item['src_zones'] = get_zones_id(parent, item['src_zones'], item['name'])
        item['dst_zones'] = get_zones_id(parent, item['dst_zones'], item['name'])
        item['src_ips'] = get_ips_id(parent, item['src_ips'], item['name'])
        item['dst_ips'] = get_ips_id(parent, item['dst_ips'], item['name'])
        item['urls'] = get_urls_id(parent, item['urls'], item['name'])
        item['url_categories'] = get_url_categories_id(parent, item['url_categories'], item['name'])
        item['time_restrictions'] = get_time_restrictions_id(parent, item['time_restrictions'], item['name'])

        if item['name'] in captive_portal_rules:
            parent.stepChanged.emit(f'GRAY|    Правило Captive-портала "{item["name"]}" уже существует.')
            err, result = parent.utm.update_captive_portal_rule(captive_portal_rules[item['name']], item)
            if err:
                parent.stepChanged.emit(f'RED|    {result}  [Captive-portal: {item["name"]}]')
                parent.error = 1
                error = 1
            else:
                parent.stepChanged.emit(f'BLACK|    Правило Captive-портала "{item["name"]}" updated.')
        else:
            err, result = parent.utm.add_captive_portal_rules(item)
            if err:
                parent.stepChanged.emit(f'RED|    {result}  [Captive-portal: {item["name"]}]')
                parent.error = 1
                error = 1
            else:
                captive_portal_rules[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Правило Captive-портала "{item["name"]}" добавлено.')

    out_message = 'GREEN|    Список правил Captive-портала импортирован в раздел "Пользователи и устройства/Captive-портал".'
    parent.stepChanged.emit('ORANGE|    Ошибка импорта правил Captive-портала.' if error else out_message)


def import_terminal_servers(parent, path):
    """Импортируем список терминальных серверов"""
    parent.stepChanged.emit('BLUE|Импорт списка терминальных серверов в раздел "Пользователи и устройства/Терминальные серверы".')
    error = 0
    json_file = os.path.join(path, 'config_terminal_servers.json')
    err, data = read_json_file(parent, json_file)
    if err:
        if err in (1, 2):
            parent.error = 1
        return

    err, result = parent.utm.get_terminal_servers()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return
    terminal_servers = {x['name'].strip().translate(trans_name): x['id'] for x in result}

    for item in data:
        item['name'] = item['name'].strip().translate(trans_name)
        if item['name'] in terminal_servers:
            parent.stepChanged.emit(f'GRAY|    Терминальный сервер "{item["name"]}" уже существует.')
            err, result = parent.utm.update_terminal_server(terminal_servers[item['name']], item)
            if err:
                parent.stepChanged.emit(f'RED|    {result}  [Terminal Server: {item["name"]}]')
                parent.error = 1
                error = 1
            else:
                parent.stepChanged.emit(f'BLACK|    Терминальный сервер "{item["name"]}" updated.')
        else:
            err, result = parent.utm.add_terminal_server(item)
            if err:
                parent.stepChanged.emit(f'RED|    {result}  [Terminal Server: {item["name"]}]')
                parent.error = 1
                error = 1
            else:
                terminal_servers[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Терминальный сервер "{item["name"]}" добавлен.')

    out_message = 'GREEN|    Список терминальных серверов импортирован в раздел "Пользователи и устройства/Терминальные серверы".'
    parent.stepChanged.emit('ORANGE|    Ошибка импорта списка терминальных серверов.' if error else out_message)


def import_byod_policy(parent, path):
    """Импортируем список Политики BYOD"""
    parent.stepChanged.emit('BLUE|Импорт списка "Политики BYOD" в раздел "Пользователи и устройства/Политики BYOD".')
    error = 0
    json_file = os.path.join(path, 'config_byod_policy.json')
    err, data = read_json_file(parent, json_file)
    if err:
        if err in (1, 2):
            parent.error = 1
        return

    err, result = parent.utm.get_byod_policy()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return
    byod_rules = {x['name'].strip().translate(trans_name): x['id'] for x in result}

    for item in data:
        item['name'] = item['name'].strip().translate(trans_name)
        item['users'] = get_guids_users_and_groups(parent, item['users'], item['name'])
        if item['name'] in byod_rules:
            parent.stepChanged.emit(f'GRAY|    Политика BYOD "{item["name"]}" уже существует.')
            err, result = parent.utm.update_byod_policy(byod_rules[item['name']], item)
            if err:
                parent.stepChanged.emit(f'RED|    {result}  [BYOD policy: {item["name"]}]')
                parent.error = 1
                error = 1
            else:
                parent.stepChanged.emit(f'BLACK|    BYOD policy "{item["name"]}" updated.')
        else:
            err, result = parent.utm.add_byod_policy(item)
            if err:
                parent.stepChanged.emit(f'RED|    {result}  [Terminal Server: {item["name"]}]')
                parent.error = 1
                error = 1
            else:
                byod_rules[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Политика BYOD "{item["name"]}" добавлена.')

    out_message = 'GREEN|    Список "Политики BYOD" импортирован в раздел "Пользователи и устройства/Политики BYOD".'
    parent.stepChanged.emit('ORANGE|    Ошибка импорта списка "Политики BYOD".' if error else out_message)


def import_userid_agent(parent, path):
    """Импортируем настройки UserID агент"""
    parent.stepChanged.emit('BLUE|Импорт настроек UserID агент в раздел "Пользователи и устройства/UserID агент".')
    error = 0
    json_file = os.path.join(path, 'userid_agent_config.json')
    err, data = read_json_file(parent, json_file)
    if err:
        if err in (1, 2):
            parent.error = 1
        return
    else:
        data['tcp_ca_certificate_id'] = parent.ngfw_certs[data['tcp_ca_certificate_id']]
        data['tcp_server_certificate_id'] = parent.ngfw_certs[data['tcp_server_certificate_id']]
        data['ignore_networks'] = [['list_id', parent.ip_lists[x[1]]] for x in data['ignore_networks']]

        err, result = parent.utm.set_useridagent_config(data)
        if err:
            parent.stepChanged.emit(f'RED|    {result}')
            parent.error = 1
            error = 1
        else:
            parent.stepChanged.emit('BLACK|    Свойства агента UserID обновлены.')

    json_file = os.path.join(path, 'userid_agent_servers.json')
    err, data = read_json_file(parent, json_file)
    if err:
        if err in (1, 2):
            parent.error = 1
        return

    err, result = parent.utm.get_useridagent_filters()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return
    useridagent_filters = {x['name']: x['id'] for x in result}

    err, result = parent.utm.get_useridagent_servers()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return
    useridagent_servers = {x['name']: x['id'] for x in result}

    for item in data:
        item['name'] = item['name'].strip().translate(trans_name)
        item['enabled'] = False
        try:
            item['auth_profile_id'] = parent.auth_profiles[item['auth_profile_id']]
        except KeyError:
            parent.stepChanged.emit(f'bRED|    UserID агент "{item["name"]}": не найден профиль аутентификации "{item["auth_profile_id"]}". Загрузите профили аутентификации и повторите попытку.')
            item['auth_profile_id'] = 1
        if 'filters' in item:
            new_filters = []
            for filter_name in item['filters']:
                try:
                    new_filters.append(useridagent_filters[filter_name])
                except KeyError:
                    parent.stepChanged.emit(f'bRED|    UserID агент "{item["name"]}": не найден Syslog фильтр UserID агента "{filter_name}". Загрузите фильтры UserID агента и повторите попытку.')
            item['filters'] = new_filters

        if item['name'] in useridagent_servers:
            parent.stepChanged.emit(f'GRAY|    UserID агент "{item["name"]}" уже существует.')
            err, result = parent.utm.update_useridagent_server(useridagent_servers[item['name']], item)
            if err:
                parent.stepChanged.emit(f'RED|    {result}  [UserID агент: {item["name"]}]')
                parent.error = 1
                error = 1
            else:
                parent.stepChanged.emit(f'BLACK|    UserID агент "{item["name"]}" updated.')
        else:
            err, result = parent.utm.add_useridagent_server(item)
            if err:
                parent.stepChanged.emit(f'RED|    {result}  [UserID агент: {item["name"]}]')
                parent.error = 1
                error = 1
            else:
                useridagent_servers[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    UserID агент "{item["name"]}" добавлен.')
                parent.stepChanged.emit(f'NOTE|    Необходимо включить "{item["name"]}" и, если вы используете Microsoft AD, ввести пароль.')

    out_message = 'GREEN|    Настройки UserID агент импортированы в раздел "Пользователи и устройства/UserID агент".'
    parent.stepChanged.emit('ORANGE|    Ошибка импорта настроек UserID агент.' if error else out_message)


def import_firewall_rules(parent, path):
    """Импортируем список правил межсетевого экрана"""
    parent.stepChanged.emit('BLUE|Импорт правил межсетевого экрана в раздел "Политики сети/Межсетевой экран".')
    parent.stepChanged.emit('LBLUE|    После импорта правила МЭ будут в не активном состоянии. Необходимо проверить и включить нужные.')
    json_file = os.path.join(path, 'config_firewall_rules.json')
    err, data = read_json_file(parent, json_file)
    if err:
        if err in (1, 2):
            parent.error = 1
        return

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
        idps_profiles = {x['name']: x['id'] for x in result}

        err, result = parent.utm.get_l7_profiles_list()
        if err:
            parent.stepChanged.emit(f'RED|    {result}')
            parent.error = 1
            return
        l7_profiles = {x['name']: x['id'] for x in result}

        err, result = parent.utm.get_hip_profiles_list()
        if err:
            parent.stepChanged.emit(f'RED|    {result}')
            parent.error = 1
            return
        hip_profiles = {x['name']: x['id'] for x in result}

    err, result = parent.utm.get_firewall_rules()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        error = 1
    firewall_rules = {x['name'].strip().translate(trans_name): x['id'] for x in result}

    error = 0
    for item in data:
        item['name'] = item['name'].strip().translate(trans_name)
        item.pop('position_layer', None)
        item.pop('time_created', None)
        item.pop('time_updated', None)
        if parent.version >= 6:
            item['position'] = 'last' 

        if item['scenario_rule_id']:
            try:
                item['scenario_rule_id'] = parent.scenarios_rules[item['scenario_rule_id']]
            except KeyError as err:
                parent.stepChanged.emit(f'bRED|    Правило МЭ "{item["name"]}": не найден сценарий "{err}". Загрузите сценарии и повторите попытку.')
                item['scenario_rule_id'] = False

        item['src_zones'] = get_zones_id(parent, item['src_zones'], item['name'])
        item['dst_zones'] = get_zones_id(parent, item['dst_zones'], item['name'])
        item['src_ips'] = get_ips_id(parent, item['src_ips'], item['name'])
        item['dst_ips'] = get_ips_id(parent, item['dst_ips'], item['name'])
        item['services'] = get_services(parent, item['services'], item['name'])
        item['users'] = get_guids_users_and_groups(parent, item['users'], item['name'])
        item['time_restrictions'] = get_time_restrictions_id(parent, item['time_restrictions'], item['name'])

        if parent.version < 7.1:
            if 'apps' in item:
                item['apps'] = get_apps(parent, item['apps'], item['name'])
            else:
                item['apps'] = []
            item.pop('ips_profile', None)
            item.pop('l7_profile', None)
            item.pop('hip_profiles', None)
        else:
            item.pop('apps', None)
            if 'ips_profile' in item and item['ips_profile']:
                try:
                    item['ips_profile'] = idps_profiles[item['ips_profile']]
                except KeyError as err:
                    parent.stepChanged.emit(f'bRED|    Правило МЭ "{item["name"]}": не найден профиль СОВ "{err}". Загрузите профили СОВ и повторите попытку.')
                    item['ips_profile'] = False
            else:
                item['ips_profile'] = False
            if 'l7_profile' in item and item['l7_profile']:
                try:
                    item['l7_profile'] = l7_profiles[item['l7_profile']]
                except KeyError as err:
                    parent.stepChanged.emit(f'bRED|    Правило МЭ "{item["name"]}": не найден профиль приложений "{err}". Загрузите профили приложений и повторите попытку.')
                    item['l7_profile'] = False
            else:
                item['l7_profile'] = False
            if 'hip_profiles' in item:
                try:
                    item['hip_profiles'] = [hip_profiles[x] for x in item['hip_profiles']]
                except KeyError as err:
                    parent.stepChanged.emit(f'bRED|    Правило МЭ "{item["name"]}": не найден профиль HIP "{err}". Загрузите профили HIP и повторите попытку.')
                    item['hip_profile'] = []
            else:
                item['hip_profile'] = []

        if item['name'] in firewall_rules:
            parent.stepChanged.emit(f'GRAY|    Правило МЭ "{item["name"]}" уже существует.')
            err, result = parent.utm.update_firewall_rule(firewall_rules[item['name']], item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Правило МЭ: {item["name"]}]')
            else:
                parent.stepChanged.emit(f'BLACK|    Правило МЭ "{item["name"]}" updated.')
        else:
            item['enabled'] = False
            err, result = parent.utm.add_firewall_rule(item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Правило МЭ: {item["name"]}]')
            else:
                firewall_rules[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Правило МЭ "{item["name"]}" добавлено.')
    if error:
        parent.error = 1
    out_message = 'GREEN|    Правила межсетевого экрана импортированы в раздел "Политики сети/Межсетевой экран".'
    parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил межсетевого экрана.' if error else out_message)


def import_nat_rules(parent, path):
    """Импортируем список правил NAT"""
    parent.stepChanged.emit('BLUE|Импорт списка правил NAT в раздел "Политики сети/NAT и маршрутизация".')
    parent.stepChanged.emit('LBLUE|    После импорта правила NAT будут в не активном состоянии. Необходимо проверить и включить нужные.')
    error = 0
    json_file = os.path.join(path, 'config_nat_rules.json')
    err, data = read_json_file(parent, json_file)
    if err:
        if err in (1, 2):
            parent.error = 1
        return

    if not parent.scenarios_rules:
        err = set_scenarios_rules(parent)
        if err:
            parent.error = 1
            return

    err, result = parent.utm.get_gateways_list()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return
    ngfw_gateways = {x['name']: f'{x["id"]}:{x["node_name"]}' for x in result if 'name' in x}

    err, result = parent.utm.get_traffic_rules()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return
    nat_rules = {x['name'].strip().translate(trans_name): x['id'] for x in result}

    for item in data:
        item['name'] = item['name'].strip().translate(trans_name)
        item.pop('position_layer', None)
        item.pop('time_created', None)
        item.pop('time_updated', None)
        if parent.version >= 6:
            item['position'] = 'last' 
        if item['scenario_rule_id']:
            try:
                item['scenario_rule_id'] = parent.scenarios_rules[item['scenario_rule_id']]
            except KeyError as err:
                parent.stepChanged.emit(f'bRED|    Правило "{item["name"]}": не найден сценарий "{err}". Загрузите сценарии и повторите попытку.')
                item['scenario_rule_id'] = False
        if parent.version >= 6:
            item['users'] = get_guids_users_and_groups(parent, item['users'], item['name'])
        else:
            item.pop('users', None)
        item['zone_in'] = get_zones_id(parent, item['zone_in'], item['name'])
        item['zone_out'] = get_zones_id(parent, item['zone_out'], item['name'])
        item['source_ip'] = get_ips_id(parent, item['source_ip'], item['name'])
        item['dest_ip'] = get_ips_id(parent, item['dest_ip'], item['name'])
        item['service'] = get_services(parent, item['service'], item['name'])
        item['gateway'] = ngfw_gateways.get(item['gateway'], item['gateway'])
            
        if item['action'] == 'route':
            parent.stepChanged.emit(f'LBLUE|    Проверьте шлюз для правила ПБР "{item["name"]}". В случае отсутствия, установите вручную.')

        if item['name'] in nat_rules:
            parent.stepChanged.emit(f'GRAY|    Правило "{item["name"]}" уже существует.')
            err, result = parent.utm.update_traffic_rule(nat_rules[item['name']], item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Правило: {item["name"]}]')
            else:
                parent.stepChanged.emit(f'BLACK|    Правило "{item["name"]}" updated.')
        else:
            item['enabled'] = False
            err, result = parent.utm.add_traffic_rule(item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Правило: {item["name"]}]')
            else:
                nat_rules[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Правило "{item["name"]}" добавлено.')
    if error:
        parent.error = 1
    out_message = 'GREEN|    Правила NAT импортированы в раздел "Политики сети/NAT и маршрутизация".'
    parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил NAT.' if error else out_message)


def import_loadbalancing_rules(parent, path):
    """Импортируем список правил балансировки нагрузки"""
    parent.stepChanged.emit('BLUE|Импорт списка правил балансировки нагрузки в раздел "Политики сети/Балансировка нагрузки".')
    parent.stepChanged.emit('LBLUE|    После импорта правила балансировки будут в не активном состоянии. Необходимо проверить и включить нужные.')
    error = 0
    err, tcpudp, icap, reverse = parent.utm.get_loadbalancing_rules()
    if err:
        parent.stepChanged.emit(f'RED|    {data}')
        parent.error = 1
        return
    tcpudp_rules = {x['name'].strip().translate(trans_name): x['id'] for x in tcpudp}
    icap_loadbalancing = {x['name'].strip().translate(trans_name): x['id'] for x in icap}
    reverse_rules = {x['name'].strip().translate(trans_name): x['id'] for x in reverse}

    json_file = os.path.join(path, 'config_loadbalancing_tcpudp.json')
    err, data = read_json_file(parent, json_file)
    if err:
        if err in (1, 2):
            parent.error = 1
    else:
        if data:
            for item in data:
                if parent.version < 7.1:
                    item.pop('src_zones', None)
                    item.pop('src_zones_negate', None)
                    item.pop('src_ips', None)
                    item.pop('src_ips_negate', None)
                else:
                    item['src_zones'] = get_zones_id(parent, item['src_zones'], item['name'])
                    item['src_ips'] = get_ips_id(parent, item['src_ips'], item['name'])
                item['name'] = item['name'].strip().translate(trans_name)
                if item['name'] in tcpudp_rules:
                    parent.stepChanged.emit(f'GRAY|    Правило балансировки TCP/UDP "{item["name"]}" уже существует.')
                    err, result = parent.utm.update_virtualserver_rule(tcpudp_rules[item['name']], item)
                    if err:
                        error = 1
                        parent.stepChanged.emit(f'RED|    {result}  [Правило: {item["name"]}]')
                    else:
                        parent.stepChanged.emit(f'BLACK|    Правило балансировки TCP/UDP "{item["name"]}" updated.')
                else:
                    item['enabled'] = False
                    err, result = parent.utm.add_virtualserver_rule(item)
                    if err:
                        error = 1
                        parent.stepChanged.emit(f'RED|    {result}  [Правило: {item["name"]}]')
                    else:
                        tcpudp_rules[item['name']] = result
                        parent.stepChanged.emit(f'BLACK|    Правило балансировки TCP/UDP "{item["name"]}" добавлено.')
        else:
            parent.stepChanged.emit(f'dGRAY|    Нет правил в списке балансировщиков TCP/UDP для импорта.')

    json_file = os.path.join(path, 'config_loadbalancing_icap.json')
    err, data = read_json_file(parent, json_file)
    if err:
        if err in (1, 2):
            parent.error = 1
    else:
        err, result = parent.utm.get_icap_servers()
        if err:
            parent.stepChanged.emit(f'RED|    {result}')
            parent.error = 1
            return
        icap_servers = {x['name'].strip().translate(trans_name): x['id'] for x in result}

        if data:
            for item in data:
                try:
                    item['profiles'] = [icap_servers[x] for x in item['profiles']]
                except KeyError as err:
                    parent.stepChanged.emit(f'bRED|    Правило "{item["name"]}": не найден сервер ICAP "{err}". Импортируйте серверы ICAP и повторите попытку.')
                    item['profiles'] = []
                    error = 1
                item['name'] = item['name'].strip().translate(trans_name)
                if item['name'] in icap_loadbalancing:
                    parent.stepChanged.emit(f'GRAY|    Правило балансировки ICAP "{item["name"]}" уже существует.')
                    err, result = parent.utm.update_icap_loadbalancing_rule(icap_loadbalancing[item['name']], item)
                    if err:
                        error = 1
                        parent.stepChanged.emit(f'RED|    {result}  [Правило: {item["name"]}]')
                    else:
                        parent.stepChanged.emit(f'BLACK|    Правило балансировки ICAP "{item["name"]}" updated.')
                else:
                    item['enabled'] = False
                    err, result = parent.utm.add_icap_loadbalancing_rule(item)
                    if err:
                        error = 1
                        parent.stepChanged.emit(f'RED|    {result}  [Правило: {item["name"]}]')
                    else:
                        icap_loadbalancing[item['name']] = result
                        parent.stepChanged.emit(f'BLACK|    Правило балансировки ICAP "{item["name"]}" добавлено.')
        else:
            parent.stepChanged.emit(f'dGRAY|    Нет правил в списке балансировщиков ICAP для импорта.')

    json_file = os.path.join(path, 'config_loadbalancing_reverse.json')
    err, data = read_json_file(parent, json_file)
    if err:
        if err in (1, 2):
            parent.error = 1
    else:
        err, result = parent.utm.get_reverseproxy_servers()
        if err:
            parent.stepChanged.emit(f'RED|    {result}')
            parent.error = 1
            return
        reverse_servers = {x['name'].strip().translate(trans_name): x['id'] for x in result}

        if data:
            for item in data:
                try:
                    item['profiles'] = [reverse_servers[x] for x in item['profiles']]
                except KeyError as err:
                    parent.stepChanged.emit(f'bRED|    Правило "{item["name"]}": не найден сервер reverse-proxy "{err}". Загрузите серверы reverse-proxy и повторите попытку.')
                    item['profiles'] = []
                    error = 1
                item['name'] = item['name'].strip().translate(trans_name)
                if item['name'] in reverse_rules:
                    parent.stepChanged.emit(f'GRAY|    Правило балансировки reverse-proxy "{item["name"]}" уже существует.')
                    err, result = parent.utm.update_reverse_loadbalancing_rule(reverse_rules[item['name']], item)
                    if err:
                        error = 1
                        parent.stepChanged.emit(f'RED|    {result}  [Правило: {item["name"]}]')
                    else:
                        parent.stepChanged.emit(f'BLACK|    Правило балансировки reverse-proxy "{item["name"]}" updated.')
                else:
                    item['enabled'] = False
                    err, result = parent.utm.add_reverse_loadbalancing_rule(item)
                    if err:
                        error = 1
                        parent.stepChanged.emit(f'RED|    {result}  [Правило: {item["name"]}]')
                    else:
                        reverse_rules[item['name']] = result
                        parent.stepChanged.emit(f'BLACK|    Правило балансировки reverse-proxy "{item["name"]}" добавлено.')
        else:
            parent.stepChanged.emit(f'dGRAY|    Нет правил в списке балансировщиков reverse-proxy для импорта.')

    if error:
        parent.error = 1
    out_message = 'GREEN|    Правила балансировки нагрузки импортированы в раздел "Политики сети/Балансировка нагрузки".'
    parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил балансировки нагрузки.' if error else out_message)


def import_shaper_rules(parent, path):
    """Импортируем список правил пропускной способности"""
    parent.stepChanged.emit('BLUE|Импорт списка правил пропускной способности в раздел "Политики сети/Пропускная способность".')
    parent.stepChanged.emit('LBLUE|    После импорта правила пропускной способности будут в не активном состоянии. Необходимо проверить и включить нужные.')
    error = 0
    json_file = os.path.join(path, 'config_shaper_rules.json')
    err, data = read_json_file(parent, json_file)
    if err:
        if err in (1, 2):
            parent.error = 1
        return

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
    shaper_list = {x['name'].strip().translate(trans_name): x['id'] for x in result}

    err, result = parent.utm.get_shaper_rules()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return
    shaper_rules = {x['name'].strip().translate(trans_name): x['id'] for x in result}

    for item in data:
        item['name'] = item['name'].strip().translate(trans_name)
        item.pop('position_layer', None)
        if parent.version < 6:
            item.pop('limit', None)
            item.pop('limit_value', None)
            item.pop('limit_burst', None)
            item.pop('log', None)
            item.pop('log_session_start', None)
        if item['scenario_rule_id']:
            try:
                item['scenario_rule_id'] = parent.scenarios_rules[item['scenario_rule_id']]
            except KeyError as err:
                parent.stepChanged.emit(f'bRED|    Правило "{item["name"]}": не найден сценарий "{err}". Загрузите сценарии и повторите попытку.')
                item['scenario_rule_id'] = False
        item['src_zones'] = get_zones_id(parent, item['src_zones'], item['name'])
        item['dst_zones'] = get_zones_id(parent, item['dst_zones'], item['name'])
        item['src_ips'] = get_ips_id(parent, item['src_ips'], item['name'])
        item['dst_ips'] = get_ips_id(parent, item['dst_ips'], item['name'])
        item['services'] = get_services(parent, item['services'], item['name'])
        item['users'] = get_guids_users_and_groups(parent, item['users'], item['name'])
        item['apps'] = get_apps(parent, item['apps'], item['name'])
        item['time_restrictions'] = get_time_restrictions_id(parent, item['time_restrictions'], item['name'])
        try:
            item['pool'] = shaper_list[item['pool']]
        except KeyError as err:
            parent.stepChanged.emit(f'bRED|    Правило "{item["name"]}": не найдена полоса пропускания "{err}". Импортируйте полосы пропускания и повторите попытку.')
            item['pool'] = 1
            error = 1

        if item['name'] in shaper_rules:
            parent.stepChanged.emit(f'GRAY|    Правило пропускной способности "{item["name"]}" уже существует.')
            err, result = parent.utm.update_shaper_rule(shaper_rules[item['name']], item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Правило: {item["name"]}]')
            else:
                parent.stepChanged.emit(f'BLACK|    Правило пропускной способности "{item["name"]}" updated.')
        else:
            item['enabled'] = False
            err, result = parent.utm.add_shaper_rule(item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Правило: {item["name"]}]')
            else:
                shaper_rules[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Правило пропускной способности "{item["name"]}" добавлено.')
    if error:
        parent.error = 1
    out_message = 'GREEN|    Правила пропускной способности импортированы в раздел "Политики сети/Пропускная способность".'
    parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил пропускной способности.' if error else out_message)


def import_content_rules(parent, path):
    """Импортируем список правил фильтрации контента"""
    parent.stepChanged.emit('BLUE|Импорт правил фильтрации контента в раздел "Политики безопасности/Фильтрация контента".')
    json_file = os.path.join(path, 'config_content_rules.json')
    err, data = read_json_file(parent, json_file)
    if err:
        if err in (1, 2):
            parent.error = 1
        return

    err, result = parent.utm.get_nlists_list('morphology')
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return
    morphology_list = {x['name'].strip().translate(trans_name): x['id'] for x in result}

    err, result = parent.utm.get_nlists_list('useragent')
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return
    useragent_list = {x['name'].strip().translate(trans_name): x['id'] for x in result}

    err, result = parent.utm.get_templates_list()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return
    templates_list = {x['name'].strip().translate(trans_name): x['id'] for x in result}

    if not parent.scenarios_rules:
        err = set_scenarios_rules(parent)
        if err:
            parent.error = 1
            return

    err, result = parent.utm.get_content_rules()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return
    content_rules = {x['name'].strip().translate(trans_name): x['id'] for x in result}

    error = 0
    for item in data:
        item['name'] = item['name'].strip().translate(trans_name)
        item['position'] = 'last'
        item.pop('position_layer', None)
        item.pop('time_created', None)
        item.pop('time_updated', None)
        item['blockpage_template_id'] = templates_list.get(item['blockpage_template_id'], -1)
        item['src_zones'] = get_zones_id(parent, item['src_zones'], item['name'])
        item['dst_zones'] = get_zones_id(parent, item['dst_zones'], item['name'])
        item['src_ips'] = get_ips_id(parent, item['src_ips'], item['name'])
        item['dst_ips'] = get_ips_id(parent, item['dst_ips'], item['name'])
        item['users'] = get_guids_users_and_groups(parent, item['users'], item['name'])
        item['url_categories'] = get_url_categories_id(parent, item['url_categories'], item['name'])
        item['urls'] = get_urls_id(parent, item['urls'], item['name'])
        new_morph_categories = []
        for x in item['morph_categories']:
            try:
                new_morph_categories.append(morphology_list[x])
            except KeyError as err:
                parent.stepChanged.emit(f'bRED|    Error! Правило "{item["name"]}": Не найден список морфрлогии "{err}". Загрузите списки морфологии и повторите попытку.')
        item['morph_categories'] = new_morph_categories
        item['referers'] = get_urls_id(parent, item['referers'], item['name'])
        if parent.version < 6:
            item.pop('referer_categories', None)
            item.pop('users_negate', None)
            item.pop('position_layer', None)
        else:
            item['referer_categories'] = get_url_categories_id(parent, item['referer_categories'], item['name'])
        new_user_agents = []
        for x in item['user_agents']:
            try:
                new_user_agents.append(['list_id', useragent_list[x[1]]])
            except KeyError as err:
                parent.stepChanged.emit(f'bRED|    Error! Правило "{item["name"]}": Не найден список UserAgent "{err}". Загрузите списки Useragent браузеров и повторите попытку.')
        item['user_agents'] = new_user_agents
        item['time_restrictions'] = get_time_restrictions_id(parent, item['time_restrictions'], item['name'])
        new_content_types = []
        for x in item['content_types']:
            try:
                new_content_types.append(parent.mime_list[x])
            except KeyError as err:
                parent.stepChanged.emit(f'bRED|    Error! Правило "{item["name"]}": Не найден список типов контента "{err}". Загрузите списки Типов контента и повторите попытку.')
        item['content_types'] = new_content_types
        if item['scenario_rule_id']:
            try:
                item['scenario_rule_id'] = parent.scenarios_rules[item['scenario_rule_id']]
            except KeyError as err:
                parent.stepChanged.emit(f'bRED|    Правило "{item["name"]}": не найден сценарий "{err}". Загрузите сценарии и повторите попытку.')
                item['scenario_rule_id'] = False

        if item['name'] in content_rules:
            parent.stepChanged.emit(f'GRAY|    Правило контентной фильтрации "{item["name"]}" уже существует.')
            err, result = parent.utm.update_content_rule(content_rules[item['name']], item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Правило КФ: {item["name"]}]')
            else:
                parent.stepChanged.emit(f'BLACK|    Правило контентной фильтрации "{item["name"]}" updated.')
        else:
            item['enabled'] = False
            err, result = parent.utm.add_content_rule(item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Правило КФ: {item["name"]}]')
            else:
                content_rules[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Правило контентной фильтрации "{item["name"]}" добавлено.')
    if error:
        parent.error = 1
    out_message = 'GREEN|    Правила контентной фильтрации импортированы в раздел "Политики безопасности/Фильтрация контента".'
    parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил контентной фильтрации.' if error else out_message)


def import_safebrowsing_rules(parent, path):
    """Импортируем список правил веб-безопасности"""
    parent.stepChanged.emit('BLUE|Импорт правил веб-безопасности в раздел "Политики безопасности/Веб-безопасность".')
    error = 0
    json_file = os.path.join(path, 'config_safebrowsing_rules.json')
    err, data = read_json_file(parent, json_file)
    if err:
        if err in (1, 2):
            parent.error = 1
        return

    err, result = parent.utm.get_safebrowsing_rules()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return
    safebrowsing_rules = {x['name'].strip().translate(trans_name): x['id'] for x in result}

    for item in data:
        item['name'] = item['name'].strip().translate(trans_name)
        item['position'] = 'last'
        item.pop('position_layer', None)
        item.pop('time_created', None)
        item.pop('time_updated', None)
        item['src_zones'] = get_zones_id(parent, item['src_zones'], item['name'])
        item['src_ips'] = get_ips_id(parent, item['src_ips'], item['name'])
        item['users'] = get_guids_users_and_groups(parent, item['users'], item['name'])
        item['time_restrictions'] = get_time_restrictions_id(parent, item['time_restrictions'], item['name'])
        item['url_list_exclusions'] = get_urls_id(parent, item['url_list_exclusions'], item['name'])

        if item['name'] in safebrowsing_rules:
            parent.stepChanged.emit(f'GRAY|    Правило веб-безопасности "{item["name"]}" уже существует.')
            err, result = parent.utm.update_safebrowsing_rule(safebrowsing_rules[item['name']], item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Правило веб-безопасности: {item["name"]}]')
                continue
            else:
                parent.stepChanged.emit(f'BLACK|    Правило веб-безопасности "{item["name"]}" updated.')
        else:
            err, result = parent.utm.add_safebrowsing_rule(item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Правило веб-безопасности: "{item["name"]}"]')
                continue
            else:
                safebrowsing_rules[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Правило веб-безопасности "{item["name"]}" добавлено.')
    if error:
        parent.error = 1
    out_message = 'GREEN|    Правила веб-безопасности импортированны в раздел "Политики безопасности/Веб-безопасность".'
    parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил веб-безопасности.' if error else out_message)


def import_tunnel_inspection_rules(parent, path):
    """Импортируем список правил инспектирования туннелей"""
    parent.stepChanged.emit('BLUE|Импорт правил инспектирования туннелей в раздел "Политики безопасности/Инспектирование туннелей".')
    error = 0
    json_file = os.path.join(path, 'config_tunnelinspection_rules.json')
    err, data = read_json_file(parent, json_file)
    if err:
        if err in (1, 2):
            parent.error = 1
        return

    err, rules = parent.utm.get_tunnel_inspection_rules()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return
    tunnel_inspect_rules = {x['name']: x['id'] for x in rules}

    for item in data:
        item['name'] = item['name'].strip().translate(trans_name)
        item['position'] = 'last'
        item.pop('position_layer', None)
        item['src_zones'] = get_zones_id(parent, item['src_zones'], item['name'])
        item['src_ips'] = get_ips_id(parent, item['src_ips'], item['name'])
        item['dst_zones'] = get_zones_id(parent, item['dst_zones'], item['name'])
        item['dst_ips'] = get_ips_id(parent, item['dst_ips'], item['name'])

        if item['name'] in tunnel_inspect_rules:
            parent.stepChanged.emit(f'GRAY|    Правило инспектирования туннелей "{item["name"]}" уже существует.')
            err, result = parent.utm.update_tunnel_inspection_rule(tunnel_inspect_rules[item['name']], item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Правило инспектирования туннелей: {item["name"]}]')
                continue
            else:
                parent.stepChanged.emit(f'BLACK|    Правило инспектирования туннелей "{item["name"]}" updated.')
        else:
            err, result = parent.utm.add_tunnel_inspection_rule(item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Правило инспектирования туннелей: "{item["name"]}"]')
                continue
            else:
                tunnel_inspect_rules[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Правило инспектирования туннелей "{item["name"]}" добавлено.')
    if error:
        parent.error = 1
    out_message = 'GREEN|    Правила инспектирования туннелей импортированны в раздел "Политики безопасности/Инспектирование туннелей".'
    parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил инспектирования туннелей.' if error else out_message)


def import_ssldecrypt_rules(parent, path):
    """Импортируем список правил инспектирования SSL"""
    parent.stepChanged.emit('BLUE|Импорт правил инспектирования SSL в раздел "Политики безопасности/Инспектирование SSL".')
    error = 0
    json_file = os.path.join(path, 'config_ssldecrypt_rules.json')
    err, data = read_json_file(parent, json_file)
    if err:
        if err in (1, 2):
            parent.error = 1
        return

    ssl_forward_profiles = {}
    if parent.version >= 7:
        err, rules = parent.utm.get_ssl_forward_profiles()
        if err:
            parent.stepChanged.emit(f'RED|    {result}')
            parent.error = 1
            return
        ssl_forward_profiles = {x['name']: x['id'] for x in rules}
        ssl_forward_profiles[-1] = -1

    err, rules = parent.utm.get_ssldecrypt_rules()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return
    ssldecrypt_rules = {x['name'].strip().translate(trans_name): x['id'] for x in rules}

    for item in data:
        item['name'] = item['name'].strip().translate(trans_name)
        item['position'] = 'last'
        item.pop('position_layer', None)
        item.pop('time_created', None)
        item.pop('time_updated', None)
        item['users'] = get_guids_users_and_groups(parent, item['users'], item['name'])
        item['src_zones'] = get_zones_id(parent, item['src_zones'], item['name'])
        item['src_ips'] = get_ips_id(parent, item['src_ips'], item['name'])
        item['dst_ips'] = get_ips_id(parent, item['dst_ips'], item['name'])
        item['url_categories'] = get_url_categories_id(parent, item['url_categories'], item['name'])
        item['urls'] = get_urls_id(parent, item['urls'], item['name'])
        item['time_restrictions'] = get_time_restrictions_id(parent, item['time_restrictions'], item['name'])
        if parent.version < 6:
            item.pop('ssl_profile_id', None)
        else:
            try:
                item['ssl_profile_id'] = parent.ssl_profiles[item['ssl_profile_id']]
            except KeyError as err:
                parent.stepChanged.emit(f'bRED|    Error! Правило "{item["name"]}": Не найден профиль SSL "{err}" для правила "{item["name"]}". Загрузите профили SSL и повторите попытку.')
                item['ssl_profile_id'] = parent.ssl_profiles['Default SSL profile']
        if parent.version < 7:
            item.pop('ssl_forward_profile_id', None)
            if item['action'] == 'decrypt_forward':
                item['action'] = 'decrypt'
        else:
            try:
                item['ssl_forward_profile_id'] = ssl_forward_profiles[item['ssl_forward_profile_id']]
            except KeyError as err:
                parent.stepChanged.emit(f'bRED|    Error! Правило "{item["name"]}": Не найден профиль SSL "{err}" для правила "{item["name"]}". Загрузите профили SSL и повторите попытку.')
                item['ssl_forward_profile_id'] = -1

        if item['name'] in ssldecrypt_rules:
            parent.stepChanged.emit(f'GRAY|    Правило инспектирования SSL "{item["name"]}" уже существует.')
            err, result = parent.utm.update_ssldecrypt_rule(ssldecrypt_rules[item['name']], item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Правило инспектирования SSL: {item["name"]}]')
                continue
            else:
                parent.stepChanged.emit(f'BLACK|    Правило инспектирования SSL "{item["name"]}" updated.')
        else:
            err, result = parent.utm.add_ssldecrypt_rule(item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Правило инспектирования SSL: "{item["name"]}"]')
                continue
            else:
                ssldecrypt_rules[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Правило инспектирования SSL "{item["name"]}" добавлено.')
    if error:
        parent.error = 1
    out_message = 'GREEN|    Правила инспектирования SSL импортированны в раздел "Политики безопасности/Инспектирование SSL".'
    parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил инспектирования SSL.' if error else out_message)


def import_sshdecrypt_rules(parent, path):
    """Импортируем список правил инспектирования SSH"""
    parent.stepChanged.emit('BLUE|Импорт правил инспектирования SSH в раздел "Политики безопасности/Инспектирование SSH".')
    error = 0
    json_file = os.path.join(path, 'config_sshdecrypt_rules.json')
    err, data = read_json_file(parent, json_file)
    if err:
        if err in (1, 2):
            parent.error = 1
        return

    err, rules = parent.utm.get_sshdecrypt_rules()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return
    sshdecrypt_rules = {x['name']: x['id'] for x in rules}

    for item in data:
        item['name'] = item['name'].strip().translate(trans_name)
        item['position'] = 'last'
        item.pop('position_layer', None)
        item.pop('time_created', None)
        item.pop('time_updated', None)
        if parent.version < 7.1:
            item.pop('layer', None)
        item['users'] = get_guids_users_and_groups(parent, item['users'], item['name'])
        item['src_zones'] = get_zones_id(parent, item['src_zones'], item['name'])
        item['src_ips'] = get_ips_id(parent, item['src_ips'], item['name'])
        item['dst_ips'] = get_ips_id(parent, item['dst_ips'], item['name'])
        item['time_restrictions'] = get_time_restrictions_id(parent, item['time_restrictions'], item['name'])
        item['protocols'] = get_services(parent, item['protocols'], item['name'])

        if item['name'] in sshdecrypt_rules:
            parent.stepChanged.emit(f'GRAY|    Правило инспектирования SSH "{item["name"]}" уже существует.')
            err, result = parent.utm.update_sshdecrypt_rule(sshdecrypt_rules[item['name']], item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Правило инспектирования SSH: {item["name"]}]')
                continue
            else:
                parent.stepChanged.emit(f'BLACK|    Правило инспектирования SSH "{item["name"]}" updated.')
        else:
            err, result = parent.utm.add_sshdecrypt_rule(item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Правило инспектирования SSH: "{item["name"]}"]')
                continue
            else:
                sshdecrypt_rules[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Правило инспектирования SSH "{item["name"]}" добавлено.')
    if error:
        parent.error = 1
    out_message = 'GREEN|    Правила инспектирования SSH импортированны в раздел "Политики безопасности/Инспектирование SSH".'
    parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил инспектирования SSH.' if error else out_message)


def import_idps_rules(parent, path):
    """Импортируем список правил СОВ"""
    parent.stepChanged.emit('BLUE|Импорт правил СОВ в раздел "Политики безопасности/СОВ".')
    error = 0
    json_file = os.path.join(path, 'config_idps_rules.json')
    err, data = read_json_file(parent, json_file)
    if err:
        if err in (1, 2):
            parent.error = 1
        return

    err, result = parent.utm.get_nlists_list('ipspolicy')
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return
    idps_profiles = {x['name'].strip().translate(trans_name): x['id'] for x in result}

    err, result = parent.utm.get_idps_rules()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return
    idps_rules = {x['name'].strip().translate(trans_name): x['id'] for x in result}

    for item in data:
        item['name'] = item['name'].strip().translate(trans_name)
        item['position'] = 'last'
        item['enabled'] = False
        item.pop('position_layer', None)
        if parent.version < 7.0 and item['action'] == 'reset':
            item['action'] = 'drop'
        item['src_zones'] = get_zones_id(parent, item['src_zones'], item['name'])
        item['dst_zones'] = get_zones_id(parent, item['dst_zones'], item['name'])
        item['src_ips'] = get_ips_id(parent, item['src_ips'], item['name'])
        item['dst_ips'] = get_ips_id(parent, item['dst_ips'], item['name'])
        item['services'] = get_services(parent, item['services'], item['name'])
        try:
            item['idps_profiles'] = [idps_profiles[x] for x in item['idps_profiles']]
        except KeyError as err:
            parent.stepChanged.emit(f'bRED|    Error! Правило "{item["name"]}": Не найден профиль СОВ "{err}". Загрузите профили СОВ и повторите попытку.')
            item['idps_profiles'] = [idps_profiles['ENTENSYS_IPS_POLICY'],]
        if parent.version < 6:
            item.pop('idps_profiles_exclusions', None)
        else:
            try:
                item['idps_profiles_exclusions'] = [idps_profiles[x] for x in item['idps_profiles_exclusions']]
            except KeyError as err:
                parent.stepChanged.emit(f'bRED|    Error! Правило "{item["name"]}": Не найден профиль исключения СОВ "{err}". Загрузите профили СОВ и повторите попытку.')
                item['idps_profiles_exclusions'] = []

        if item['name'] in idps_rules:
            parent.stepChanged.emit(f'GRAY|    Правило СОВ "{item["name"]}" уже существует.')
            err, result = parent.utm.update_idps_rule(idps_rules[item['name']], item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Правило СОВ: {item["name"]}]')
                continue
            else:
                parent.stepChanged.emit(f'BLACK|    Правило СОВ "{item["name"]}" updated.')
        else:
            err, result = parent.utm.add_idps_rule(item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Правило СОВ: "{item["name"]}"]')
                continue
            else:
                idps_rules[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Правило СОВ "{item["name"]}" добавлено.')
    if error:
        parent.error = 1
    out_message = 'GREEN|    Правила СОВ импортированны в раздел "Политики безопасности/СОВ".'
    parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил СОВ.' if error else out_message)


def import_scada_rules(parent, path):
    """Импортируем список правил АСУ ТП"""
    parent.stepChanged.emit('BLUE|Импорт правил АСУ ТП в раздел "Политики безопасности/Правила АСУ ТП".')
    json_file = os.path.join(path, 'config_scada_rules.json')
    err, data = read_json_file(parent, json_file)
    if err:
        if err in (1, 2):
            parent.error = 1
        return
    error = 0

    err, rules = parent.utm.get_scada_list()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return
    scada_profiles = {x['name']: x['id'] for x in rules}

    err, rules = parent.utm.get_scada_rules()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return
    scada_rules = {x['name']: x['id'] for x in rules}

    for item in data:
        if parent.version < 6:
            item.pop('position', None)
        else:
            item['position'] = 'last'
        item.pop('position_layer', None)
        item['enabled'] = False
        item['src_zones'] = get_zones_id(parent, item['src_zones'], item['name'])
        item['src_ips'] = get_ips_id(parent, item['src_ips'], item['name'])
        item['dst_ips'] = get_ips_id(parent, item['dst_ips'], item['name'])
        try:
            item['services'] = [parent.services_list[x] for x in item['services']]
        except KeyError as err:
            parent.stepChanged.emit(f'bRED|    Error! Правило "{item["name"]}": Не найден сервис "{err}". Загрузите список сервисов и повторите попытку.')
            item['services'] = []
        try:
            item['scada_profiles'] = [scada_profiles[x] for x in item['scada_profiles']]
        except KeyError as err:
            parent.stepChanged.emit(f'bRED|    Error! Правило "{item["name"]}": Не найден профиль СОВ "{err}". Загрузите профили СОВ и повторите попытку.')
            item['scada_profiles'] = []

        if item['name'] in scada_rules:
            parent.stepChanged.emit(f'GRAY|    Правило АСУ ТП "{item["name"]}" уже существует.')
            err, result = parent.utm.update_scada_rule(scada_rules[item['name']], item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Правило АСУ ТП: {item["name"]}]')
                continue
            else:
                parent.stepChanged.emit(f'BLACK|    Правило АСУ ТП "{item["name"]}" updated.')
        else:
            err, result = parent.utm.add_scada_rule(item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Правило АСУ ТП: "{item["name"]}"]')
                continue
            else:
                scada_rules[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Правило АСУ ТП "{item["name"]}" добавлено.')
    if error:
        parent.error = 1
    out_message = 'GREEN|    Правила АСУ ТП импортированны в раздел "Политики безопасности/Правила АСУ ТП".'
    parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил АСУ ТП.' if error else out_message)


def import_scenarios(parent, path):
    """Импортируем список сценариев"""
    parent.stepChanged.emit('BLUE|Импорт списка сценариев в раздел "Политики безопасности/Сценарии".')
    json_file = os.path.join(path, 'config_scenarios.json')
    err, data = read_json_file(parent, json_file)
    if err:
        if err in (1, 2):
            parent.error = 1
        return
    error = 0

    if not parent.l7_apps:
        err = set_apps_values(parent)
        if err:
            parent.error = 1
            return

    err, result = parent.utm.get_scenarios_rules()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return
    scenarios_rules = {x['name'].strip().translate(trans_name): x['id'] for x in result}

    for item in data:
        item['name'] = item['name'].strip().translate(trans_name)
        new_conditions = []
        for condition in item['conditions']:
            if condition['kind'] == 'application':
                condition['apps'] = get_apps(parent, condition['apps'], item['name'])
            elif condition['kind'] == 'mime_types':
                try:
                    condition['content_types'] = [parent.mime_list[x] for x in condition['content_types']]
                except KeyError as err:
                    parent.stepChanged.emit(f'bRED|    Error! Сценарий "{item["name"]}": Не найден тип контента "{err}". Загрузите типы контента и повторите попытку.')
                    condition['content_types'] = []
            elif condition['kind'] == 'url_category':
                condition['url_categories'] = get_url_categories_id(parent, condition['url_categories'], item['name'])
            elif condition['kind'] == 'health_check':
                if parent.version < 6:
                    parent.stepChanged.emit(f'bRED|    Error! Сценарий "{item["name"]}": Условие "Проверка состояния" не поддерживается в версии 5.')
                    continue
                elif parent.version == 7.0:
                    parent.stepChanged.emit(f'bRED|    Error! Сценарий "{item["name"]}": Условие "Проверка состояния" нельзя импортировать в версию 7.0.')
                    continue
            new_conditions.append(condition)
        item['conditions'] = new_conditions

        if item['name'] in scenarios_rules:
            parent.stepChanged.emit(f'GRAY|    Сценарий "{item["name"]}" уже существует.')
            err, result = parent.utm.update_scenarios_rule(scenarios_rules[item['name']], item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Сценарий: {item["name"]}]')
                continue
            else:
                parent.stepChanged.emit(f'BLACK|    Сценарий "{item["name"]}" updated.')
        else:
            err, result = parent.utm.add_scenarios_rule(item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Сценарий: "{item["name"]}"]')
                continue
            else:
                scenarios_rules[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Сценарий "{item["name"]}" добавлен.')
    if error:
        parent.error = 1
    out_message = 'GREEN|    Список сценариев импортирован в раздел "Политики безопасности/Сценарии".'
    parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте списка сценариев.' if error else out_message)


def import_mailsecurity(parent, path):
    import_mailsecurity_rules(parent, path)
    import_mailsecurity_antispam(parent, path)

def import_mailsecurity_rules(parent, path):
    """Импортируем список правил защиты почтового трафика"""
    parent.stepChanged.emit('BLUE|Импорт правил защиты почтового трафика в раздел "Политики безопасности/Защита почтового трафика".')
    json_file = os.path.join(path, 'config_mailsecurity_rules.json')
    err, data = read_json_file(parent, json_file)
    if err:
        if err in (1, 2):
            parent.error = 1
        return
    error = 0

    err, result = parent.utm.get_nlist_list('emailgroup')
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return
    email = {x['name'].strip().translate(trans_name): x['id'] for x in result}

    err, result = parent.utm.get_mailsecurity_rules()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return
    mailsecurity_rules = {x['name'].strip().translate(trans_name): x['id'] for x in result}

    for item in data:
        item['name'] = item['name'].strip().translate(trans_name)
        item.pop('position_layer', None)
        item['position'] = 'last'
        item['enabled'] = False
        item['src_zones'] = get_zones_id(parent, item['src_zones'], item['name'])
        item['dst_zones'] = get_zones_id(parent, item['dst_zones'], item['name'])
        item['src_ips'] = get_ips_id(parent, item['src_ips'], item['name'])
        item['dst_ips'] = get_ips_id(parent, item['dst_ips'], item['name'])
        item['users'] = get_guids_users_and_groups(parent, item['users'], item['name'])
        if parent.version < 6:
            item['protocol'] = list({'pop' if x[1] in ['POP3', 'POP3S'] else 'smtp' for x in item['services']})
            item.pop('services', None)
            item.pop('envelope_to_negate', None)
            item.pop('envelope_from_negate', None)
        else:
            if not item['services']:
                item['services'] = [['service', 'SMTP'], ['service', 'POP3'], ['service', 'SMTPS'], ['service', 'POP3S']]
            item['services'] = get_services(parent, item['services'], item['name'])

        try:
            item['envelope_from'] = [[x[0], email[x[1]]] for x in item['envelope_from']]
        except KeyError as err:
            parent.stepChanged.emit(f'bRED|    Error! Правило "{item["name"]}": Не найден список почтовых адресов "{err}". Загрузите список почтовых адресов и повторите попытку.')
            item['envelope_from'] = []

        try:
            item['envelope_to'] = [[x[0], email[x[1]]] for x in item['envelope_to']]
        except KeyError as err:
            parent.stepChanged.emit(f'bRED|    Error! Правило "{item["name"]}": Не найден список почтовых адресов "{err}". Загрузите список почтовых адресов и повторите попытку.')
            item['envelope_to'] = []

        if parent.version < 7.1:
            item.pop('rule_log', None)
        if parent.version < 7:
            item.pop('dst_zones_negate', None)

        if item['name'] in mailsecurity_rules:
            parent.stepChanged.emit(f'GRAY|    Правило "{item["name"]}" уже существует.')
            err, result = parent.utm.update_mailsecurity_rule(mailsecurity_rules[item['name']], item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Правило: {item["name"]}]')
                continue
            else:
                parent.stepChanged.emit(f'BLACK|    Правило "{item["name"]}" updated.')
        else:
            err, result = parent.utm.add_mailsecurity_rule(item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Правило: "{item["name"]}"]')
                continue
            else:
                mailsecurity_rules[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Правило "{item["name"]}" добавлено.')
    if error:
        parent.error = 1
    out_message = 'GREEN|    Правила защиты почтового трафика импортированы в раздел "Политики безопасности/Защита почтового трафика".'
    parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил защиты почтового трафика.' if error else out_message)


def import_mailsecurity_antispam(parent, path):
    """Импортируем dnsbl и batv защиты почтового трафика"""
    parent.stepChanged.emit('BLUE|Импорт настроек антиспама защиты почтового трафика в раздел "Политики безопасности/Защита почтового трафика".')
    error = 0
    parent.stepChanged.emit('LBLUE|    Импорт настроек DNSBL.')
    json_file = os.path.join(path, 'config_mailsecurity_dnsbl.json')
    err, data = read_json_file(parent, json_file)
    if err:
        if err in [1, 2]:
            error = 1
    else:
        data['white_list'] = get_ips_id(parent, data['white_list'], 'antispam DNSBL')
        data['black_list'] = get_ips_id(parent, data['black_list'], 'antispam DNSBL')
                
        err, result = parent.utm.set_mailsecurity_dnsbl(data)
        if err:
            error = 1
            parent.stepChanged.emit(f'RED|    {result}')
        else:
            parent.stepChanged.emit(f'BLACK|    Список DNSBL импортирован.')

    parent.stepChanged.emit('LBLUE|    Импорт настройки BATV.')
    json_file = os.path.join(path, 'config_mailsecurity_batv.json')
    err, data = read_json_file(parent, json_file)
    if err:
        if err in [1, 2]:
            error = 1
    else:
        err, result = parent.utm.set_mailsecurity_batv(data)
        if err:
            error = 1
            parent.stepChanged.emit(f'RED|    {result}')
        else:
            parent.stepChanged.emit(f'BLACK|    Настройка BATV импортирована.')

    if error:
        parent.error = 1
    out_message = 'GREEN|    Настройки антиспама импортированы в раздел "Политики безопасности/Защита почтового трафика".'
    parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте настроек антиспама.' if error else out_message)


def import_icap_rules(parent, path):
    """Импортируем список правил ICAP"""
    parent.stepChanged.emit('BLUE|Импорт правил ICAP в раздел "Политики безопасности/ICAP-правила".')
    json_file = os.path.join(path, 'config_icap_rules.json')
    err, data = read_json_file(parent, json_file)
    if err:
        if err in (1, 2):
            parent.error = 1
        return
    error = 0

    err, result = parent.utm.get_icap_servers()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return
    icap_servers = {x['name'].strip().translate(trans_name): x['id'] for x in result}

    err, err_msg, result, _ = parent.utm.get_loadbalancing_rules()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return
    icap_loadbalancing = {x['name'].strip().translate(trans_name): x['id'] for x in result}

    err, result = parent.utm.get_icap_rules()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return
    icap_rules = {x['name'].strip().translate(trans_name): x['id'] for x in result}

    for item in data:
        item['name'] = item['name'].strip().translate(trans_name)
        item.pop('position_layer', None)
        item.pop('time_created', None)
        item.pop('time_updated', None)

        new_servers = []
        for server in item['servers']:
            if server[0] == 'lbrule':
                try:
                    new_servers.append(['lbrule', icap_loadbalancing[server[1]]])
                except KeyError as err:
                    parent.stepChanged.emit(f'bRED|    Error [Правило "{item["name"]}"]. Не найден балансировщик серверов ICAP "{err}". Импортируйте балансировщики ICAP и повторите попытку.')
            elif server[0] == 'profile':
                try:
                    new_servers.append(['profile', icap_servers[server[1]]])
                except KeyError as err:
                    parent.stepChanged.emit(f'bRED|    Error [Правило "{item["name"]}"]. Не найден сервер ICAP "{err}". Импортируйте сервера ICAP и повторите попытку.')
        item['servers'] = new_servers

        item['users'] = get_guids_users_and_groups(parent, item['users'], item['name'])
        item['src_zones'] = get_zones_id(parent, item['src_zones'], item['name'])
        item['src_ips'] = get_ips_id(parent, item['src_ips'], item['name'])
        item['dst_ips'] = get_ips_id(parent, item['dst_ips'], item['name'])
        item['url_categories'] = get_url_categories_id(parent, item['url_categories'], item['name'])
        item['urls'] = get_urls_id(parent, item['urls'], item['name'])
        item['content_types'] = [parent.mime_list[x] for x in item['content_types']]

        if item['name'] in icap_rules:
            parent.stepChanged.emit(f'GRAY|    ICAP-правило "{item["name"]}" уже существует.')
            err, result = parent.utm.update_icap_rule(icap_rules[item['name']], item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [ICAP-правило: {item["name"]}]')
                continue
            else:
                parent.stepChanged.emit(f'BLACK|    ICAP-правило "{item["name"]}" updated.')
        else:
            item['position'] = 'last'
            err, result = parent.utm.add_icap_rule(item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [ICAP-правило: "{item["name"]}"]')
                continue
            else:
                icap_rules[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    ICAP-правило "{item["name"]}" добавлено.')
    if error:
        parent.error = 1
    out_message = 'GREEN|    Правила ICAP импортированы в раздел "Политики безопасности/ICAP-правила".'
    parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил ICAP.' if error else out_message)


def import_icap_servers(parent, path):
    """Импортируем список серверов ICAP"""
    parent.stepChanged.emit('BLUE|Импорт серверов ICAP в раздел "Политики безопасности/ICAP-серверы".')
    json_file = os.path.join(path, 'config_icap_servers.json')
    err, data = read_json_file(parent, json_file)
    if err:
        if err in (1, 2):
            parent.error = 1
        return
    error = 0

    err, result = parent.utm.get_icap_servers()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return
    icap_servers = {x['name'].strip().translate(trans_name): x['id'] for x in result}

    for item in data:
        item['name'] = item['name'].strip().translate(trans_name)
        if item['name'] in icap_servers:
            parent.stepChanged.emit(f'GRAY|    ICAP-сервер "{item["name"]}" уже существует.')
            err, result = parent.utm.update_icap_server(icap_servers[item['name']], item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [ICAP-сервер: {item["name"]}]')
                continue
            else:
                parent.stepChanged.emit(f'BLACK|    ICAP-сервер "{item["name"]}" updated.')
        else:
            item['position'] = 'last'
            err, result = parent.utm.add_icap_server(item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [ICAP-сервер: "{item["name"]}"]')
                continue
            else:
                icap_servers[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    ICAP-сервер "{item["name"]}" добавлен.')
    if error:
        parent.error = 1
    out_message = 'GREEN|    Серверы ICAP импортированы в раздел "Политики безопасности/ICAP-серверы".'
    parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте серверов ICAP.' if error else out_message)


def import_dos_profiles(parent, path):
    """Импортируем список профилей DoS"""
    parent.stepChanged.emit('BLUE|Импорт профилей DoS в раздел "Политики безопасности/Профили DoS".')
    json_file = os.path.join(path, 'config_dos_profiles.json')
    err, data = read_json_file(parent, json_file)
    if err:
        if err in (1, 2):
            parent.error = 1
        return
    error = 0

    err, result = parent.utm.get_dos_profiles()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return
    dos_profiles = {x['name'].strip().translate(trans_name): x['id'] for x in result}

    for item in data:
        item['name'] = item['name'].strip().translate(trans_name)
        if item['name'] in dos_profiles:
            parent.stepChanged.emit(f'GRAY|    Профиль DoS "{item["name"]}" уже существует.')
            err, result = parent.utm.update_dos_profile(dos_profiles[item['name']], item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Профиль DoS: {item["name"]}]')
                continue
            else:
                parent.stepChanged.emit(f'BLACK|    Профиль DoS "{item["name"]}" updated.')
        else:
            err, result = parent.utm.add_dos_profile(item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Профиль DoS: "{item["name"]}"]')
                continue
            else:
                dos_profiles[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Профиль DoS "{item["name"]}" добавлен.')
    if error:
        parent.error = 1
    out_message = 'GREEN|    Профили DoS импортированы в раздел "Политики безопасности/Профили DoS".'
    parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей DoS.' if error else out_message)


def import_dos_rules(parent, path):
    """Импортируем список правил защиты DoS"""
    parent.stepChanged.emit('BLUE|Импорт правил защиты DoS в раздел "Политики безопасности/Правила защиты DoS".')
    json_file = os.path.join(path, 'config_dos_rules.json')
    err, data = read_json_file(parent, json_file)
    if err:
        if err in (1, 2):
            parent.error = 1
        return
    error = 0

    if not parent.scenarios_rules:
        err = set_scenarios_rules(parent)
        if err:
            parent.error = 1
            return

    err, result = parent.utm.get_dos_profiles()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return
    dos_profiles = {x['name'].strip().translate(trans_name): x['id'] for x in result}

    err, result = parent.utm.get_dos_rules()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return
    dos_rules = {x['name'].strip().translate(trans_name): x['id'] for x in result}

    for item in data:
        item['name'] = item['name'].strip().translate(trans_name)
        item.pop('position_layer', None)
        item['position'] = 'last'
        item['src_zones'] = get_zones_id(parent, item['src_zones'], item['name'])
        item['dst_zones'] = get_zones_id(parent, item['dst_zones'], item['name'])
        item['src_ips'] = get_ips_id(parent, item['src_ips'], item['name'])
        item['dst_ips'] = get_ips_id(parent, item['dst_ips'], item['name'])
        item['users'] = get_guids_users_and_groups(parent, item['users'], item['name'])
        item['services'] = get_services(parent, item['services'], item['name'])
        item['time_restrictions'] = get_time_restrictions_id(parent, item['time_restrictions'], item['name'])
        if item['dos_profile']:
            try:
                item['dos_profile'] = dos_profiles[item['dos_profile']]
            except KeyError as err:
                parent.stepChanged.emit(f'bRED|    Error [Правило "{item["name"]}"]. Не найден профиль DoS "{err}". Импортируйте профили DoS и повторите попытку.')
                item['dos_profile'] = False
        if item['scenario_rule_id']:
            try:
                item['scenario_rule_id'] = parent.scenarios_rules[item['scenario_rule_id']]
            except KeyError as err:
                parent.stepChanged.emit(f'bRED|    Error [Правило "{item["name"]}"]. Не найден сценарий "{err}". Импортируйте сценарии и повторите попытку.')
                item['scenario_rule_id'] = False

        if item['name'] in dos_rules:
            parent.stepChanged.emit(f'GRAY|    Правило защиты DoS "{item["name"]}" уже существует.')
            err, result = parent.utm.update_dos_rule(dos_rules[item['name']], item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Правило защиты DoS: {item["name"]}]')
                continue
            else:
                parent.stepChanged.emit(f'BLACK|    Правило защиты DoS "{item["name"]}" updated.')
        else:
            err, result = parent.utm.add_dos_rule(item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Правило защиты DoS: "{item["name"]}"]')
                continue
            else:
                dos_rules[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Правило защиты DoS "{item["name"]}" добавлено.')
    if error:
        parent.error = 1
    out_message = 'GREEN|    Правила защиты DoS импортированы в раздел "Политики безопасности/Правила защиты DoS".'
    parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил защиты DoS.' if error else out_message)


#------------------------------------------------ Библиотека ---------------------------------------------------------
def import_morphology_lists(parent, path):
    """Импортируем списки морфологии"""
    parent.stepChanged.emit('BLUE|Импорт списков морфологии в раздел "Библиотеки/Морфология".')
    error = 0
    json_file = os.path.join(path, 'config_morphology_lists.json')
    err, data = read_json_file(parent, json_file)
    if err:
        if err in (1, 2):
            parent.error = 1
        return

    err, result = parent.utm.get_nlists_list('morphology')
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return
    morphology_list = {x['name'].strip().translate(trans_name): x['id'] for x in result}

    for item in data:
        item['name'] = item['name'].strip().translate(trans_name)
        content = item.pop('content')
        item.pop('last_update', None)
        if parent.version < 6:
            item.pop('list_type_update', None)
            item.pop('schedule', None)
            attributes = []
            attributes.append({'name': 'weight', 'value': item['attributes']['threshold']})
            attributes.append({'name': 'threat_level', 'value': item['attributes']['threat_level']})
            item['attributes'] = attributes

        if item['name'] in morphology_list:
            parent.stepChanged.emit(f'GRAY|    Список морфологии "{item["name"]}" уже существует.')
            err, result = parent.utm.update_nlist(morphology_list[item['name']], item)
            if err == 1:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Список морфологии: {item["name"]}]')
                continue
            elif err == 2:
                parent.stepChanged.emit(f'GRAY|    {result}')
            else:
                parent.stepChanged.emit(f'BLACK|    Список морфологии "{item["name"]}" updated.')
        else:
            err, result = parent.utm.add_nlist(item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Список морфологии: "{item["name"]}"]')
                continue
            else:
                morphology_list[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Список морфологии "{item["name"]}" добавлен.')

        err2, result2 = parent.utm.add_nlist_items(morphology_list[item['name']], content)
        if err2 == 2:
            parent.stepChanged.emit(f'GRAY|       {result2}')
        elif err2 == 1:
            error = 1
            parent.stepChanged.emit(f'RED|       {result2}  [Список морфологии: "{item["name"]}"]')
        else:
            parent.stepChanged.emit(f'BLACK|       Содержимое списка морфологии "{item["name"]}" обновлено.')

    if parent.version == 7.0:
        parent.stepChanged.emit(f'rNOTE|    В версии 7.0 не импортируется содержимое списков морфологии, если прописаны слова в русском регистре.')

    if error:
        parent.error = 1
    out_message = 'GREEN|    Списки морфологии импортированны в раздел "Библиотеки/Морфология".'
    parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте списков морфологии.' if error else out_message)


def import_services_list(parent, path):
    """Импортируем список сервисов раздела библиотеки"""
    parent.stepChanged.emit('BLUE|Импорт списка сервисов в раздел "Библиотеки/Сервисы"')
    json_file = os.path.join(path, 'config_services_list.json')
    err, data = read_json_file(parent, json_file)
    if err:
        if err in (1, 2):
            parent.error = 1
        return

    error = 0
    
    for item in data:
        item['name'] = item['name'].strip().translate(trans_name)
        for value in item['protocols']:
            if parent.version < 7.1:
                value.pop('alg', None)
                if parent.version < 6:
                    value.pop('app_proto', None)
                    if value['port'] in ('110', '995'):
                        value['proto'] = 'tcp'
        
        if item['name'] in parent.services_list:
            parent.stepChanged.emit(f'GRAY|    Сервис "{item["name"]}" уже существует.')
        else:
            err, result = parent.utm.add_service(item)
            if err == 1:
                parent.stepChanged.emit(f'RED|    {result}  [Сервис: "{item["name"]}"]')
                error = 1
                parent.error = 1
            elif err == 2:
                parent.stepChanged.emit(f'GRAY|    {result}')
            else:
                parent.services_list[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Сервис "{item["name"]}" добавлен.')

    out_message = 'GREEN|    Список сервисов импортирован в раздел "Библиотеки/Сервисы"'
    parent.stepChanged.emit('ORANGE|    Произошла ошибка при добавлении сервисов!' if error else out_message)


def import_services_groups(parent, path):
    """Импортируем группы сервисов в раздел Библиотеки/Группы сервисов"""
    parent.stepChanged.emit('BLUE|Импорт групп сервисов в раздел "Библиотеки/Группы сервисов".')
    json_file = os.path.join(path, 'config_services_groups_list.json')
    err, data = read_json_file(parent, json_file)
    if err:
        if err in (1, 2):
            parent.error = 1
        return
    error = 0

    for item in data:
        content = item.pop('content')
        item.pop('last_update', None)
        item['name'] = item['name'].strip().translate(trans_name)
        
        if item['name'] in parent.servicegroups_list:
            parent.stepChanged.emit(f'GRAY|    Группа сервисов "{item["name"]}" уже существует.')
            err, result = parent.utm.update_nlist(parent.servicegroups_list[item['name']], item)
            if err == 1:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Группа сервисов: "{item["name"]}"]')
                continue
            elif err == 2:
                parent.stepChanged.emit(f'GRAY|    {result}')
            else:
                parent.stepChanged.emit(f'BLACK|    Группа сервисов "{item["name"]}" updated.')
        else:
            err, result = parent.utm.add_nlist(item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Группа сервисов: "{item["name"]}"]')
                continue
            else:
                parent.servicegroups_list[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Группа сервисов "{item["name"]}" добавлена.')

        if content:
            err2, result2 = parent.utm.add_nlist_items(parent.servicegroups_list[item['name']], content)
            if err2 == 1:
                parent.stepChanged.emit(f'RED|       {result2}  [Группа сервисов: "{item["name"]}"]')
                error = 1
            elif err2 == 2:
                parent.stepChanged.emit(f'GRAY|       {result2}')
            else:
                parent.stepChanged.emit(f'BLACK|       Содержимое группы сервисов "{item["name"]}" обновлено.')

    if error:
        parent.error = 1
    out_message = 'GREEN|    Группы сервисов импортированы в раздел "Библиотеки/Группы сервисов".'
    parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте групп сервисов.' if error else out_message)


def import_ip_lists(parent, path):
    """Импортируем списки IP адресов"""
    parent.stepChanged.emit('BLUE|Импорт списков IP-адресов в раздел "Библиотеки/IP-адреса".')
    error = 0

    if not os.path.isdir(path):
        parent.stepChanged.emit("GRAY|    Нет списков IP-адресов для импорта.")
        return
    files_list = os.listdir(path)
    if not files_list:
        parent.stepChanged.emit("GRAY|    Нет списков IP-адресов для импорта.")
        return

    # Импортируем все списки IP-адресов без содержимого (пустые).
    parent.stepChanged.emit(f'LBLUE|    Импортируем списки IP-адресов без содержимого.')
    for file_name in files_list:
        json_file = os.path.join(path, file_name)
        err, data = read_json_file(parent, json_file)
        if err:
            if err in (1, 2):
                parent.error = 1
            continue

        data['name'] = data['name'].strip().translate(trans_name)
        content = data.pop('content')
        data.pop('last_update', None)
        if parent.version < 6:
            data['attributes'] = [{'name': 'threat_level', 'value': data['attributes']['threat_level']}]
            data.pop('list_type_update', None)
            data.pop('schedule', None)
        if data['name'] in parent.ip_lists:
            parent.stepChanged.emit(f'GRAY|    Список IP-адресов "{data["name"]}" уже существует.')
            err, result = parent.utm.update_nlist(parent.ip_lists[data['name']], data)
            if err == 1:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Список IP-адресов: "{data["name"]}"]')
                continue
            elif err == 2:
                parent.stepChanged.emit(f'GRAY|    {result}')
            else:
                parent.stepChanged.emit(f'BLACK|    Список IP-адресов "{data["name"]}" updated.')
        else:
            err, result = parent.utm.add_nlist(data)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Список IP-адресов: "{data["name"]}"]')
                continue
            else:
                parent.ip_lists[data['name']] = result
                parent.stepChanged.emit(f'BLACK|    Список IP-адресов "{data["name"]}" импортирован.')
    # Добавляем содержимое в уже добавленные списки IP-адресов.
    parent.stepChanged.emit(f'LBLUE|    Импортируем содержимое списков IP-адресов.')
    for file_name in files_list:
        json_file = os.path.join(path, file_name)
        err, data = read_json_file(parent, json_file)
        if err:
            if err in (1, 2):
                parent.error = 1
            continue

        data['name'] = data['name'].strip().translate(trans_name)
        try:
            list_id = parent.ip_lists[data['name']]
        except KeyError:
            parent.stepChanged.emit(f'RED|    Ошибка! Нет IP-листа "{data["name"]}" в списках IP-адресов NGFW.')
            parent.stepChanged.emit(f'RED|    Ошибка! Содержимое не добавлено в список IP-адресов "{data["name"]}".')
            error = 1
            continue
        if data['content']:
            new_content = []
            for item in data['content']:
                if 'list' in item:
                    if parent.version >= 7:
                        try:
                            item['list'] = parent.ip_lists[item['list']]
                            new_content.append(item)
                        except KeyError:
                            parent.stepChanged.emit(f'RED|    Ошибка! Нет IP-листа "{item["list"]}" в списках IP-адресов NGFW.')
                            parent.stepChanged.emit(f'RED|    Ошибка! Список "{item["list"]}" не добавлен в список IP-адресов "{data["name"]}".')
                            error = 1
                    else:
                        parent.stepChanged.emit(f'GRAY|    В список "{data["name"]}" не добавлен "{item["list"]}". Данная версия не поддерживает содержимое в виде списков IP-адресов.')
                else:
                    new_content.append(item)
            data['content'] = new_content
            err2, result2 = parent.utm.add_nlist_items(list_id, data['content'])
            if err2 == 1:
                parent.stepChanged.emit(f'RED|    {result2}  [Список IP-адресов: "{data["name"]}"]')
                error = 1
            elif err2 == 2:
                parent.stepChanged.emit(f'GRAY|    {result2}')
            else:
                parent.stepChanged.emit(f'BLACK|    Содержимое списка IP-адресов "{data["name"]}" обновлено.')
        else:
            parent.stepChanged.emit(f'GRAY|    Список "{data["name"]}" пуст.')

    if error:
        parent.error = 1
    out_message = 'GREEN|    Списки IP-адресов импортированы в раздел "Библиотеки/IP-адреса".'
    parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте списков IP-адресов.' if error else out_message)


def import_useragent_lists(parent, path):
    """Импортируем списки Useragent браузеров"""
    parent.stepChanged.emit('BLUE|Импорт списка "Useragent браузеров" в раздел "Библиотеки/Useragent браузеров".')
    json_file = os.path.join(path, 'config_useragents_list.json')
    err, data = read_json_file(parent, json_file)
    if err:
        if err in (1, 2):
            parent.error = 1
        return

    error = 0
    err, result = parent.utm.get_nlists_list('useragent')
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return
    useragent_list = {x['name'].strip().translate(trans_name): x['id'] for x in result}

    for item in data:
        content = item.pop('content')
        item.pop('last_update', None)
        item['name'] = item['name'].strip().translate(trans_name)
        if parent.version < 6:
            item['attributes'] = []
            item.pop('list_type_update', None)
            item.pop('schedule', None)

        if item['name'] in useragent_list:
            parent.stepChanged.emit(f'GRAY|    Список Useragent "{item["name"]}" уже существует.')
            err, result = parent.utm.update_nlist(useragent_list[item['name']], item)
            if err == 1:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Список Useragent: {item["name"]}]')
                continue
            elif err == 2:
                parent.stepChanged.emit(f'GRAY|    {result}')
            else:
                parent.stepChanged.emit(f'BLACK|    Список Useragent "{item["name"]}" updated.')
        else:
            err, result = parent.utm.add_nlist(item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Список Useragent: "{item["name"]}"]')
                continue
            else:
                useragent_list[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Список Useragent "{item["name"]}" импортирован.')

        if content:
            err2, result2 = parent.utm.add_nlist_items(useragent_list[item['name']], content)
            if err2 == 2:
                parent.stepChanged.emit(f'GRAY|       {result2}')
            elif err2 == 1:
                error = 1
                parent.stepChanged.emit(f'RED|       {result2}  [Список Useragent: "{item["name"]}"]')
            else:
                parent.stepChanged.emit(f'BLACK|       Содержимое списка Useragent "{item["name"]}" обновлено.')
        else:
            parent.stepChanged.emit(f'GRAY|       Список Useragent "{item["name"]}" пуст.')

    if error:
        parent.error = 1
    out_message = 'GREEN|    Список "Useragent браузеров" импортирован в раздел "Библиотеки/Useragent браузеров".'
    parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте списков Useragent браузеров.' if error else out_message)


def import_mime_lists(parent, path):
    """Импортируем списки Типов контента"""
    parent.stepChanged.emit('BLUE|Импорт списка "Типы контента" в раздел "Библиотеки/Типы контента".')
    json_file = os.path.join(path, 'config_mime_types.json')
    err, data = read_json_file(parent, json_file)
    if err:
        if err in (1, 2):
            parent.error = 1
        return

    error = 0
    err, result = parent.utm.get_nlists_list('mime')
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return
    mime_list = {x['name'].strip().translate(trans_name): x['id'] for x in result}

    for item in data:
        content = item.pop('content')
        item.pop('last_update', None)
        item['name'] = item['name'].strip().translate(trans_name)
        if parent.version < 6:
            item['attributes'] = []
            item.pop('list_type_update', None)
            item.pop('schedule', None)

        if item['name'] in mime_list:
            parent.stepChanged.emit(f'GRAY|    Список Типов контента "{item["name"]}" уже существует.')
            err, result = parent.utm.update_nlist(mime_list[item['name']], item)
            if err == 1:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Список Типов контента: {item["name"]}]')
                continue
            elif err == 2:
                parent.stepChanged.emit(f'GRAY|    {result}')
            else:
                parent.stepChanged.emit(f'BLACK|    Список Типов контента "{item["name"]}" updated.')
        else:
            err, result = parent.utm.add_nlist(item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Список Типов контента: "{item["name"]}"]')
                continue
            else:
                mime_list[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Список Типов контента "{item["name"]}" импортирован.')

        if content:
            err2, result2 = parent.utm.add_nlist_items(mime_list[item['name']], content)
            if err2 == 2:
                parent.stepChanged.emit(f'GRAY|       {result2}')
            elif err2 == 1:
                error = 1
                parent.stepChanged.emit(f'RED|       {result2}  [Список Типов контента: "{item["name"]}"]')
            else:
                parent.stepChanged.emit(f'BLACK|       Содержимое списка Типов контента "{item["name"]}" обновлено.')
        else:
            parent.stepChanged.emit(f'GRAY|       Список Типов контента "{item["name"]}" пуст.')

    if error:
        parent.error = 1
    out_message = 'GREEN|    Списки "Типы контента" импортированы в раздел "Библиотеки/Типы контента".'
    parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте списков "Типы контента".' if error else out_message)


def import_url_lists(parent, path):
    """Импортируем списки URL"""
    parent.stepChanged.emit('BLUE|Импорт списков URL в раздел "Библиотеки/Списки URL".')
    error = 0

    if not os.path.isdir(path):
        parent.stepChanged.emit("GRAY|    Нет списков URL для импорта.")
        return
    files_list = os.listdir(path)
    if not files_list:
        parent.stepChanged.emit("GRAY|    Нет списков URL для импорта.")
        return

    # Импортируем все списки URL без содержимого (пустые).
    parent.stepChanged.emit(f'LBLUE|    Импортируем списки URL без содержимого.')
    for file_name in files_list:
        json_file = os.path.join(path, file_name)
        err, data = read_json_file(parent, json_file)
        if err:
            if err in (1, 2):
                parent.error = 1
            continue

        data['name'] = data['name'].strip().translate(trans_name)
        content = data.pop('content')
        data.pop('last_update', None)
        if parent.version < 6:
            data['attributes'] = [{'name': 'threat_level', 'value': 3}]
            data.pop('list_type_update', None)
            data.pop('schedule', None)
        elif parent.version < 7.1:
            data['attributes'] = {}
        else:
            if not data['attributes'] or 'threat_level' in data['attributes']:
                data['attributes'] = {'list_compile_type': 'case_sensitive'}

        if data['name'] in parent.url_lists:
            parent.stepChanged.emit(f'GRAY|    Список URL "{data["name"]}" уже существует.')
            err, result = parent.utm.update_nlist(parent.url_lists[data['name']], data)
            if err == 1:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Список URL: "{data["name"]}"]')
                continue
            elif err == 2:
                parent.stepChanged.emit(f'GRAY|    {result}')
            else:
                parent.stepChanged.emit(f'BLACK|    Список URL "{data["name"]}" updated.')
        else:
            err, result = parent.utm.add_nlist(data)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Список URL: "{data["name"]}"]')
                continue
            else:
                parent.url_lists[data['name']] = result
                parent.stepChanged.emit(f'BLACK|    Список URL "{data["name"]}" импортирован.')

    # Добавляем содержимое в уже добавленные списки URL.
    parent.stepChanged.emit(f'LBLUE|    Импортируем содержимое списков URL.')
    for file_name in files_list:
        json_file = os.path.join(path, file_name)
        err, data = read_json_file(parent, json_file)
        if err:
            if err in (1, 2):
                parent.error = 1
            continue

        data['name'] = data['name'].strip().translate(trans_name)
        try:
            list_id = parent.url_lists[data['name']]
        except KeyError:
            parent.stepChanged.emit(f'RED|    Ошибка! Нет листа URL "{data["name"]}" в списках URL листов NGFW.')
            parent.stepChanged.emit(f'RED|    Ошибка! Содержимое не добавлено в список URL "{data["name"]}".')
            error = 1
            continue
        if data['content']:
            err2, result2 = parent.utm.add_nlist_items(list_id, data['content'])
            if err2 == 1:
                parent.stepChanged.emit(f'RED|    {result2}  [Список URL: "{data["name"]}"]')
                error = 1
            elif err2 == 2:
                parent.stepChanged.emit(f'GRAY|    {result2}')
            else:
                parent.stepChanged.emit(f'BLACK|    Содержимое списка URL "{data["name"]}" обновлено. Added {result2} record.')
        else:
            parent.stepChanged.emit(f'GRAY|    Список "{data["name"]}" пуст.')

    if error:
        parent.error = 1
    out_message = 'GREEN|    Списки URL импортированы в раздел "Библиотеки/Списки URL".'
    parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте списков URL.' if error else out_message)


def import_time_restricted_lists(parent, path):
    """Импортируем содержимое календарей"""
    parent.stepChanged.emit('BLUE|Импорт списка "Календари" в раздел "Библиотеки/Календари".')
    json_file = os.path.join(path, 'config_calendars.json')
    err, data = read_json_file(parent, json_file)
    if err:
        if err in (1, 2):
            parent.error = 1
        return

    error = 0
    for item in data:
        content = item.pop('content')
        item.pop('last_update', None)
        item['name'] = item['name'].strip().translate(trans_name)
        if parent.version < 6:
            item['attributes'] = []
            item.pop('list_type_update', None)
            item.pop('schedule', None)

        if item['name'] in parent.list_calendar:
            parent.stepChanged.emit(f'GRAY|    Список "{item["name"]}" уже существует.')
            err, result = parent.utm.update_nlist(parent.list_calendar[item['name']], item)
            if err == 1:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Список: {item["name"]}]')
                continue
            elif err == 2:
                parent.stepChanged.emit(f'GRAY|    {result}')
            else:
                parent.stepChanged.emit(f'BLACK|    Список "{item["name"]}" updated.')
        else:
            err, result = parent.utm.add_nlist(item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Список: "{item["name"]}"]')
                continue
            else:
                parent.list_calendar[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Список "{item["name"]}" импортирован.')

        if parent.version < 6:
            parent.stepChanged.emit(f'GRAY|       На версию 5 невозможно импортировать сожержимое календарей. Добавьте содержимое вручную.')
            continue
        if content:
            err2, result2 = parent.utm.add_nlist_items(parent.list_calendar[item['name']], content)
            if err2 == 2:
                parent.stepChanged.emit(f'GRAY|       {result2}')
            elif err2 == 1:
                error = 1
                parent.stepChanged.emit(f'RED|       {result2}  [Список: "{item["name"]}"]')
            else:
                parent.stepChanged.emit(f'BLACK|       Содержимое списка "{item["name"]}" обновлено.')
        else:
            parent.stepChanged.emit(f'GRAY|       Список "{item["name"]}" пуст.')

    if error:
        parent.error = 1
    out_message = 'GREEN|    Список "Календари" импортирован в раздел "Библиотеки/Календари".'
    parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте списка "Календари".' if error else out_message)


def import_shaper_list(parent, path):
    """Импортируем список Полос пропускания раздела библиотеки"""
    parent.stepChanged.emit('BLUE|Импорт списка "Полосы пропускания" в раздел "Библиотеки/Полосы пропускания".')
    json_file = os.path.join(path, 'config_shaper_list.json')
    err, data = read_json_file(parent, json_file)
    if err:
        if err in (1, 2):
            parent.error = 1
        return

    err, result = parent.utm.get_shaper_list()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return
    shaper_list = {x['name'].strip().translate(trans_name): x['id'] for x in result}
    error = 0

    for item in data:
        item['name'] = item['name'].strip().translate(trans_name)
        if item['name'] in shaper_list:
            parent.stepChanged.emit(f'GRAY|    Полоса пропускания "{item["name"]}" уже существует.')
            err, result = parent.utm.update_shaper(shaper_list[item['name']], item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Полоса пропускания: {item["name"]}]')
            else:
                parent.stepChanged.emit(f'BLACK|    Полоса пропускания "{item["name"]}" updated.')
        else:
            err, result = parent.utm.add_shaper(item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Полоса пропускания: "{item["name"]}"]')
            else:
                shaper_list[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Полоса пропускания "{item["name"]}" импортирована.')
    if error:
        parent.error = 1
    out_message = 'GREEN|    Список "Полосы пропускания" импортирован в раздел "Библиотеки/Полосы пропускания".'
    parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте списка "Полосы пропускания".' if error else out_message)


def import_scada_profiles(parent, path):
    """Импортируем список профилей АСУ ТП"""
    parent.stepChanged.emit('BLUE|Импорт списка профилей АСУ ТП в раздел "Библиотеки/Профили АСУ ТП".')
    json_file = os.path.join(path, 'config_scada_profiles.json')
    err, data = read_json_file(parent, json_file)
    if err:
        if err in (1, 2):
            parent.error = 1
        return

    err, result = parent.utm.get_scada_list()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return
    scada_profiles = {x['name'].strip().translate(trans_name): x['id'] for x in result}
    error = 0

    for item in data:
        item['name'] = item['name'].strip().translate(trans_name)
        if parent.version < 6:
            new_units = []
            for unit in item['units']:
                if unit['protocol'] != 'opcua':
                    new_units.append(unit)
            item['units'] = new_units

        if item['name'] in scada_profiles:
            parent.stepChanged.emit(f'GRAY|    Профиль АСУ ТП "{item["name"]}" уже существует.')
            err, result = parent.utm.update_scada(scada_profiles[item['name']], item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Профиль АСУ ТП: {item["name"]}]')
            else:
                parent.stepChanged.emit(f'BLACK|    Профиль АСУ ТП "{item["name"]}" updated.')
        else:
            err, result = parent.utm.add_scada(item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Профиль АСУ ТП: "{item["name"]}"]')
            else:
                scada_profiles[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Профиль АСУ ТП "{item["name"]}" импортирован.')
    if error:
        parent.error = 1
    out_message = 'GREEN|    Список профилей АСУ ТП импортирован в раздел "Библиотеки/Профили АСУ ТП".'
    parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте списка "Профили АСУ ТП".' if error else out_message)


def import_templates_list(parent, path):
    """
    Импортируем список шаблонов страниц.
    После создания шаблона, он инициализируется страницей HTML по умолчанию для данного типа шаблона.
    """
    parent.stepChanged.emit('BLUE|Импорт списка шаблонов страниц в раздел "Библиотеки/Шаблоны страниц".')
    json_file = os.path.join(path, 'config_templates_list.json')
    err, data = read_json_file(parent, json_file)
    if err:
        if err in (1, 2):
            parent.error = 1
        return

    html_files = os.listdir(path)

    err, result = parent.utm.get_templates_list()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return
    templates_list = {x['name']: x['id'] for x in result}
    error = 0

    for item in data:
        if item['name'] in templates_list:
            parent.stepChanged.emit(f'GRAY|    Шаблон страницы "{item["name"]}" уже существует.')
            err, result = parent.utm.update_template(templates_list[item['name']], item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Шаблон страницы: {item["name"]}]')
            else:
                parent.stepChanged.emit(f'BLACK|    Шаблон страницы "{item["name"]}" updated.')
        else:
            err, result = parent.utm.add_template(item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Шаблон страницы: "{item["name"]}"]')
            else:
                templates_list[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Шаблон страницы "{item["name"]}" импортирован.')

        if f"{item['name']}.html" in html_files:
            with open(os.path.join(path, f'{item["name"]}.html'), "br") as fh:
                file_data = fh.read()
            err2, result2 = parent.utm.set_template_data(templates_list[item['name']], file_data)
            if err2:
                parent.stepChanged.emit(f'RED|       {result2}')
                parent.error = 1
            else:
                parent.stepChanged.emit(f'BLACK|       Страница "{item["name"]}.html" импортирован.')
    if error:
        parent.error = 1
    out_message = 'GREEN|    Список шаблонов страниц импортирован в раздел "Библиотеки/Шаблоны страниц".'
    parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте списка шаблонов страниц.' if error else out_message)


def import_url_categories(parent, path):
    """Импортируем группы URL категорий с содержимым на UTM"""
    parent.stepChanged.emit('BLUE|Импорт категорий URL раздела "Библиотеки/Категории URL".')
    json_file = os.path.join(path, 'config_url_categories.json')
    err, data = read_json_file(parent, json_file)
    if err:
        if err in (1, 2):
            parent.error = 1
        return

    error = 0

    for item in data:
        if item['name'] not in ['Parental Control', 'Productivity', 'Safe categories', 'Threats',
                                'Recommended for morphology checking', 'Recommended for virus check']:
            content = item.pop('content')
            item.pop('last_update', None)
            item.pop('guid', None)
            item['name'] = item['name'].strip().translate(trans_name)
            if parent.version < 6:
                item['attributes'] = []
                item.pop('list_type_update', None)
                item.pop('schedule', None)
            if item['name'] in parent.list_urlcategorygroup:
                parent.stepChanged.emit(f'GRAY|    Группа URL категорий "{item["name"]}" уже существует.')
                err, result = parent.utm.update_nlist(parent.list_urlcategorygroup[item['name']], item)
                if err:
                    error = 1
                    parent.stepChanged.emit(f'RED|    {result}  [Группа URL категорий: {item["name"]}]')
                    continue
                else:
                    parent.stepChanged.emit(f'BLACK|    Группа URL категорий "{item["name"]}" updated.')
            else:
                err, result = parent.utm.add_nlist(item)
                if err:
                    error = 1
                    parent.stepChanged.emit(f'RED|    {result}  [Группа URL категорий: "{item["name"]}"]')
                    continue
                else:
                    parent.list_urlcategorygroup[item['name']] = result
                    parent.stepChanged.emit(f'BLACK|    Группа URL категорий "{item["name"]}" импортирована.')
                
            if parent.version < 6:
                parent.stepChanged.emit(f'GRAY|       На версию 5 невозможно импортировать сожержимое URL категорий. Добавьте содержимое вручную.')
                continue
            if content:
                err2, result2 = parent.utm.add_nlist_items(parent.list_urlcategorygroup[item['name']], content)
                if err2 == 2:
                    parent.stepChanged.emit(f'GRAY|       {result2}')
                elif err2 == 1:
                    error = 1
                    parent.stepChanged.emit(f'RED|       {result2}  [Список: "{item["name"]}"]')
                else:
                    parent.stepChanged.emit(f'BLACK|       Содержимое списка "{item["name"]}" обновлено.')
            else:
                parent.stepChanged.emit(f'GRAY|       Список "{item["name"]}" пуст.')
    if error:
        parent.error = 1
    out_message = 'GREEN|    Категории URL категорий импортированы в раздел "Библиотеки/Категории URL".'
    parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте URL категорий.' if error else out_message)


def import_custom_url_category(parent, path):
    """Импортируем изменённые категории URL"""
    parent.stepChanged.emit('BLUE|Импорт категорий URL раздела "Библиотеки/Изменённые категории URL".')
    json_file = os.path.join(path, 'custom_url_categories.json')
    err, data = read_json_file(parent, json_file)
    if err:
        if err in (1, 2):
            parent.error = 1
        return

    error = 0
    err, result = parent.utm.get_custom_url_list()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return
    custom_url = {x['name']: x['id'] for x in result}

    for item in data:
        try:
            item['categories'] = [parent.url_categories[x] for x in item['categories']]
        except KeyError as keyerr:
            parent.stepChanged.emit(f'RED|    Error: В правиле "{item["name"]}" обнаружена несуществующая категория {keyerr}. Правило  не добавлено.')
            continue
        if item['name'] in custom_url:
            parent.stepChanged.emit(f'GRAY|    URL категория "{item["name"]}" уже существует.')
            err, result = parent.utm.update_custom_url(custom_url[item['name']], item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [URL категория: {item["name"]}]')
                continue
            else:
                parent.stepChanged.emit(f'BLACK|    URL категория "{item["name"]}" updated.')
        else:
            err, result = parent.utm.add_custom_url(item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [URL категория: "{item["name"]}"]')
                continue
            else:
                custom_url[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Изменённая категория URL "{item["name"]}" импортирована.')

    if error:
        parent.error = 1
    out_message = 'GREEN|    Изменённые категории URL категорий импортированы в раздел "Библиотеки/Изменённые категории URL".'
    parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте изменённых категорий URL.' if error else out_message)


def import_application_signature(parent, path):
    """Импортируем список "Приложения" на UTM для версии 7.1 и выше"""
    parent.stepChanged.emit('BLUE|Импорт пользовательских приложений в раздел "Библиотеки/Приложения".')
    json_file = os.path.join(path, 'config_applications.json')
    err, data = read_json_file(parent, json_file)
    if err:
        if err in (1, 2):
            parent.error = 1
        return

    if not parent.l7_apps:
        err = set_apps_values(parent)
        if err:
            parent.error = 1
            return

    err, result = parent.utm.get_version71_apps(query={'query': 'owner = You'})
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return
    apps = {x['name']: x['id'] for x in result}

    error = 0
    for item in data:
        item.pop('signature_id', None)

        new_l7categories = []
        for category in item['l7categories']:
            try:
                new_l7categories.append(parent.l7_categories[category])
            except KeyError as err:
                parent.stepChanged.emit(f'RED|    Error: Категория "{err}" не существует [Правило "{item["name"]}"]. Категория не добавлена.')
        item['l7categories'] = new_l7categories

        if item['name'] in apps:
            parent.stepChanged.emit(f'GRAY|    Приложение "{item["name"]}" уже существует.')
            err, result = parent.utm.update_version71_app(apps[item['name']], item)
            if err == 1:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Приложение: {item["name"]}]')
                continue
            elif err == 2:
                parent.stepChanged.emit(f'GRAY|    {result}')
            else:
                parent.stepChanged.emit(f'BLACK|    Приложение "{item["name"]}" updated.')
        else:
            err, result = parent.utm.add_version71_app(item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Приложение: "{item["name"]}"]')
                continue
            else:
                apps[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Приложение "{item["name"]}" импортировано.')
    if error:
        parent.error = 1
    out_message = 'GREEN|    Пользовательские приложения импортированы в раздел "Библиотеки/Приложения".'
    parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте пользовательских приложений.' if error else out_message)


def import_app_profiles(parent, path):
    """Импортируем профили приложений. Только для версии 7.1 и выше."""
    parent.stepChanged.emit('BLUE|Импорт профилей приложений раздела "Библиотеки/Профили приложений".')
    json_file = os.path.join(path, 'config_app_profiles.json')
    err, data = read_json_file(parent, json_file)
    if err:
        if err in (1, 2):
            parent.error = 1
        return

    if not parent.l7_apps:
        err = set_apps_values(parent)
        if err:
            parent.error = 1
            return

    err, result = parent.utm.get_l7_profiles_list()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return
    l7profiles = {x['name']: x['id'] for x in result}

    error = 0
    for item in data:
        new_overrides = []
        for app in item['overrides']:
            try:
                app['id'] = parent.l7_apps[app['id']]
                new_overrides.append(app)
            except KeyError as err:
                parent.stepChanged.emit(f'RED|    Error: Не найдено приложение "{err}" [Правило: "{item["name"]}"].')
        item['overrides'] = new_overrides

        if item['name'] in l7profiles:
            parent.stepChanged.emit(f'GRAY|    Профиль приложений "{item["name"]}" уже существует.')
            err, result = parent.utm.update_l7_profile(l7profiles[item['name']], item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Профиль приложений: {item["name"]}]')
            else:
                parent.stepChanged.emit(f'BLACK|    Профиль приложений "{item["name"]}" updated.')
        else:
            err, result = parent.utm.add_l7_profile(item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Профиль приложений: "{item["name"]}"]')
            else:
                l7profiles[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Профиль приложений "{item["name"]}" импортирован.')

    if error:
        parent.error = 1
    out_message = 'GREEN|    Профили приложений импортированы в раздел "Библиотеки/Профили приложений".'
    parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей приложений.' if error else out_message)


def import_application_groups(parent, path):
    """Импортируем группы приложений."""
    parent.stepChanged.emit('BLUE|Импорт групп приложений раздела "Библиотеки/Группы приложений".')
    json_file = os.path.join(path, 'config_application_groups.json')
    err, data = read_json_file(parent, json_file)
    if err:
        if err in (1, 2):
            parent.error = 1
        return

    if not parent.l7_apps:
        err = set_apps_values(parent)
        if err:
            parent.error = 1
            return
    error = 0

    if parent.version >= 7.1:
        err, result = parent.utm.get_version71_apps()
        if err:
            parent.stepChanged.emit(f'RED|    {result}')
            parent.error = 1
            return
        apps = {x['name']: x['signature_id'] for x in result}
    else:
        apps = parent.l7_apps

    for item in data:
        item['name'] = item['name'].strip().translate(trans_name)
        content = item.pop('content')
        item.pop('last_update', None)
        if parent.version < 6:
            item['attributes'] = []
            item.pop('list_type_update', None)
            item.pop('schedule', None)

        err = execute_add_update_nlist(parent, parent.list_applicationgroup, item, 'Группа приложений')
        if err:
            error = 1
            continue

        if content:
            new_content = []
            for app in content:
                if 'name' not in app:     # Это бывает при некорректном добавлении приложения через API
                    continue
                try:
                    signature_id = apps[app['name']]
                except KeyError as err:
                    parent.stepChanged.emit(f'RED|       Error: Не найдено приложение "{app["name"]}" [Группа приложений "{item["name"]}"]. Приложение не импортировано.')
                    error = 1
                    continue
                new_content.append({'value': signature_id})
            content = new_content

            err = execute_add_nlist_items(parent, parent.list_applicationgroup[item['name']], item['name'], content)
            if err:
                error = 1
        else:
            parent.stepChanged.emit(f'GRAY|       Список "{item["name"]}" пуст.')

    if error:
        parent.error = 1
    out_message = 'GREEN|    Группы приложений импортированы в раздел "Библиотеки/Группы приложений".'
    parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте групп приложений.' if error else out_message)


def import_email_groups(parent, path):
    """Импортируем группы почтовых адресов."""
    parent.stepChanged.emit('BLUE|Импорт групп почтовых адресов раздела "Библиотеки/Почтовые адреса".')
    json_file = os.path.join(path, 'config_email_groups.json')
    err, data = read_json_file(parent, json_file)
    if err:
        if err in (1, 2):
            parent.error = 1
        return

    err, result = parent.utm.get_nlist_list('emailgroup')
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return
    emailgroups = {x['name'].strip().translate(trans_name): x['id'] for x in result}

    error = 0
    for item in data:
        item['name'] = item['name'].strip().translate(trans_name)
        content = item.pop('content')
        item.pop('last_update', None)
        if parent.version < 6:
            item['attributes'] = []
            item.pop('list_type_update', None)
            item.pop('schedule', None)

        err = execute_add_update_nlist(parent, emailgroups, item, 'Группа почтовых адресов')
        if err:
            error = 1
            continue

        if content:
            err = execute_add_nlist_items(parent, emailgroups[item['name']], item['name'], content)
            if err:
                error = 1
        else:
            parent.stepChanged.emit(f'GRAY|       Список "{item["name"]}" пуст.')

    if error:
        parent.error = 1
    out_message = 'GREEN|    Группы почтовых адресов импортированы в раздел "Библиотеки/Почтовые адреса".'
    parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте групп почтовых адресов.' if error else out_message)


def import_phone_groups(parent, path):
    """Импортируем группы телефонных номеров."""
    parent.stepChanged.emit('BLUE|Импорт групп телефонных номеров раздела "Библиотеки/Номера телефонов".')
    json_file = os.path.join(path, 'config_phone_groups.json')
    err, data = read_json_file(parent, json_file)
    if err:
        if err in (1, 2):
            parent.error = 1
        return

    err, result = parent.utm.get_nlist_list('phonegroup')
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return
    phonegroups = {x['name'].strip().translate(trans_name): x['id'] for x in result}

    error = 0
    for item in data:
        item['name'] = item['name'].strip().translate(trans_name)
        content = item.pop('content')
        item.pop('last_update', None)
        if parent.version < 6:
            item['attributes'] = []
            item.pop('list_type_update', None)
            item.pop('schedule', None)

        err = execute_add_update_nlist(parent, phonegroups, item, 'Группа телефонных номеров')
        if err:
            error = 1
            continue

        if content:
            err = execute_add_nlist_items(parent, phonegroups[item['name']], item['name'], content)
            if err:
                error = 1
        else:
            parent.stepChanged.emit(f'GRAY|       Список "{item["name"]}" пуст.')

    if error:
        parent.error = 1
    out_message = 'GREEN|    Группы телефонных номеров импортированы в раздел "Библиотеки/Номера телефонов".'
    parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте групп телефонных номеров.' if error else out_message)


def import_custom_idps_signature(parent, path):
    """Импортируем пользовательские сигнатуры СОВ. Только для версии 7.1 и выше"""
    parent.stepChanged.emit('BLUE|Импорт пользовательских сигнатур СОВ в раздел "Библиотеки/Сигнатуры СОВ".')
    json_file = os.path.join(path, 'custom_idps_signatures.json')
    err, data = read_json_file(parent, json_file)
    if err:
        if err in (1, 2):
            parent.error = 1
        return

    err, result = parent.utm.get_idps_signatures_list(query={'query': 'owner = You'})
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return
    signatures = {x['msg']: x['id'] for x in result}

    error = 0
    for item in data:
        item.pop('signature_id', None)

        if item['msg'] in signatures:
            parent.stepChanged.emit(f'GRAY|    Сигнатура СОВ "{item["msg"]}" уже существует.')
            err, result = parent.utm.update_idps_signature(signatures[item['msg']], item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Сигнатура СОВ: {item["msg"]}]')
                continue
            else:
                parent.stepChanged.emit(f'BLACK|    Сигнатура СОВ "{item["msg"]}" updated.')
        else:
            err, result = parent.utm.add_idps_signature(item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Сигнатура СОВ: "{item["msg"]}"]')
                continue
            else:
                signatures[item['msg']] = result
                parent.stepChanged.emit(f'BLACK|    Сигнатура СОВ "{item["msg"]}" импортирована.')
    if error:
        parent.error = 1
    out_message = 'GREEN|    Пользовательские сигнатуры СОВ импортированы в раздел "Библиотеки/Сигнатуры СОВ".'
    parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте пользовательских сигнатур СОВ.' if error else out_message)


def import_idps_profiles(parent, path):
    """Импортируем профили СОВ"""
    parent.stepChanged.emit('BLUE|Импорт профилей СОВ в раздел "Библиотеки/Профили СОВ".')
    json_file = os.path.join(path, 'config_idps_profiles.json')
    err, data = read_json_file(parent, json_file)
    if err:
        if err in (1, 2):
            parent.error = 1
        return
    error = 0

    if parent.version < 6:
        parent.stepChanged.emit('RED|    Импорт профилей СОВ на версию 5 не поддерживается.')
        error = 1
    elif parent.version < 7.1:
        err, result = parent.utm.get_nlist_list('ipspolicy')
        if err:
            parent.stepChanged.emit(f'RED|    {result}')
            parent.error = 1
            return
        idps = {x['name'].strip().translate(trans_name): x['id'] for x in result}

        for item in data:
            if 'filters' in item:
                parent.stepChanged.emit('RED|    Импорт профилей СОВ версий 7.1 и выше на более старые версии не поддерживается.')
                error = 1
                break

            item['name'] = item['name'].strip().translate(trans_name)
            content = item.pop('content')
            item.pop('last_update', None)

            err = execute_add_update_nlist(parent, idps, item, 'Профиль СОВ')
            if err:
                error = 1
                continue
            if content:
                new_content = []
                for signature in content:
                    if 'value' not in signature:
                        parent.stepChanged.emit(f'bRED|    Сигнатура "{signature["msg"]}" пропущена так как формат не соответствует целевой системе.')
                        error = 1
                        continue
                    new_content.append({'value': signature['value']})
                content = new_content

                err = execute_add_nlist_items(parent, idps[item['name']], item['name'], content)
                if err:
                    error = 1
            else:
                parent.stepChanged.emit(f'GRAY|       Список "{item["name"]}" пуст.')
    else:
        err, result = parent.utm.get_idps_profiles_list()
        if err:
            parent.stepChanged.emit(f'RED|    {result}')
            parent.error = 1
            return
        profiles = {x['name']: x['id'] for x in result}

        err, result = parent.utm.get_idps_signatures_list(query={'query': 'owner = You'})
        if err:
            parent.stepChanged.emit(f'RED|    {result}')
            parent.error = 1
            return
        custom_idps = {x['msg']: x['id'] for x in result}

        for item in data:
            if 'filters' not in item:
                parent.stepChanged.emit('RED|    Импорт профилей СОВ старых версий не поддерживается для версий 7.1 и выше.')
                error = 1
                break

            new_overrides = []
            for signature in item['overrides']:
                try:
                    if 1000000 < signature['signature_id'] < 1099999:
                        signature['id'] = custom_idps[signature['msg']]
                    signature.pop('signature_id', None)
                    signature.pop('msg', None)
                    new_overrides.append(signature)
                except KeyError as err:
                    parent.stepChanged.emit(f'RED|    Error: Не найдена сигнатура "{err}" [Профиль СОВ "{item["name"]}"].')
                    error = 1
            item['overrides'] = new_overrides

            if item['name'] in profiles:
                parent.stepChanged.emit(f'GRAY|    Профиль СОВ "{item["name"]}" уже существует.')
                err, result = parent.utm.update_idps_profile(profiles[item['name']], item)
                if err:
                    error = 1
                    parent.stepChanged.emit(f'RED|    {result}  [Профиль СОВ: {item["name"]}]')
                    continue
                else:
                    parent.stepChanged.emit(f'BLACK|    Профиль СОВ "{item["name"]}" updated.')
            else:
                err, result = parent.utm.add_idps_profile(item)
                if err:
                    error = 1
                    parent.stepChanged.emit(f'RED|    {result}  [Профиль СОВ: "{item["name"]}"]')
                    continue
                else:
                    profiles[item['name']] = result
                    parent.stepChanged.emit(f'BLACK|    Профиль СОВ "{item["name"]}" импортирован.')
    if error:
        parent.error = 1
    out_message = 'GREEN|    Профили СОВ импортированы в раздел "Библиотеки/Профили СОВ".'
    parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей СОВ.' if error else out_message)


def import_notification_profiles(parent, path):
    """Импортируем список профилей оповещения"""
    parent.stepChanged.emit('BLUE|Импорт профилей оповещений в раздел "Библиотеки/Профили оповещений".')
    json_file = os.path.join(path, 'config_notification_profiles.json')
    err, data = read_json_file(parent, json_file)
    if err:
        if err in (1, 2):
            parent.error = 1
        return
    error = 0

    err, result = parent.utm.get_notification_profiles_list()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return
    profiles = {x['name'].strip().translate(trans_name): x['id'] for x in result}

    for item in data:
        item['name'] = item['name'].strip().translate(trans_name)
        if item['name'] in profiles:
            parent.stepChanged.emit(f'GRAY|    Профиль оповещения "{item["name"]}" уже существует.')
            err, result = parent.utm.update_notification_profile(profiles[item['name']], item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Профиль оповещения: {item["name"]}]')
                continue
            else:
                parent.stepChanged.emit(f'BLACK|    Профиль оповещения "{item["name"]}" updated.')
        else:
            err, result = parent.utm.add_notification_profile(item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Профиль оповещения: "{item["name"]}"]')
                continue
            else:
                profiles[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Профиль оповещения "{item["name"]}" импортирован.')
    if error:
        parent.error = 1
    out_message = 'GREEN|    Профили оповещений импортированы в раздел "Библиотеки/Профили оповещений".'
    parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей оповещений.' if error else out_message)


def import_netflow_profiles(parent, path):
    """Импортируем список профилей netflow"""
    parent.stepChanged.emit('BLUE|Импорт профилей netflow в раздел "Библиотеки/Профили netflow".')
    json_file = os.path.join(path, 'config_netflow_profiles.json')
    err, data = read_json_file(parent, json_file)
    if err:
        if err in (1, 2):
            parent.error = 1
        return
    error = 0

    err, result = parent.utm.get_netflow_profiles_list()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return
    profiles = {x['name'].strip().translate(trans_name): x['id'] for x in result}

    for item in data:
        item['name'] = item['name'].strip().translate(trans_name)
        if item['name'] in profiles:
            parent.stepChanged.emit(f'GRAY|    Профиль netflow "{item["name"]}" уже существует.')
            err, result = parent.utm.update_netflow_profile(profiles[item['name']], item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Профиль netflow: {item["name"]}]')
                continue
            else:
                parent.stepChanged.emit(f'BLACK|    Профиль netflow "{item["name"]}" updated.')
        else:
            err, result = parent.utm.add_netflow_profile(item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Профиль netflow: "{item["name"]}"]')
                continue
            else:
                profiles[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Профиль netflow "{item["name"]}" импортирован.')
    if error:
        parent.error = 1
    out_message = 'GREEN|    Профили netflow импортированы в раздел "Библиотеки/Профили netflow".'
    parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей netflow.' if error else out_message)


def import_ssl_profiles(parent, path):
    """Импортируем список профилей SSL"""
    parent.stepChanged.emit('BLUE|Импорт профилей SSL в раздел "Библиотеки/Профили SSL".')
    json_file = os.path.join(path, 'config_ssl_profiles.json')
    err, data = read_json_file(parent, json_file)
    if err:
        if err in (1, 2):
            parent.error = 1
        return
    error = 0

    err, result = parent.utm.get_ssl_profiles_list()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return
    profiles = {x['name'].strip().translate(trans_name): x['id'] for x in result}

    for item in data:
        if parent.version < 7.1:
            item.pop('supported_groups', None)
        else:
            if 'supported_groups' not in item:
                item['supported_groups'] = []
        item['name'] = item['name'].strip().translate(trans_name)
        if item['name'] in profiles:
            parent.stepChanged.emit(f'GRAY|    Профиль SSL "{item["name"]}" уже существует.')
            err, result = parent.utm.update_ssl_profile(profiles[item['name']], item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Профиль SSL: {item["name"]}]')
                continue
            else:
                parent.stepChanged.emit(f'BLACK|    Профиль SSL "{item["name"]}" updated.')
        else:
            err, result = parent.utm.add_ssl_profile(item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Профиль SSL: "{item["name"]}"]')
                continue
            else:
                profiles[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Профиль SSL "{item["name"]}" импортирован.')
    if error:
        parent.error = 1
    out_message = 'GREEN|    Профили SSL импортированы в раздел "Библиотеки/Профили SSL".'
    parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей SSL.' if error else out_message)


def import_lldp_profiles(parent, path):
    """Импортируем список профилей LLDP"""
    parent.stepChanged.emit('BLUE|Импорт профилей LLDP в раздел "Библиотеки/Профили LLDP".')
    json_file = os.path.join(path, 'config_lldp_profiles.json')
    err, data = read_json_file(parent, json_file)
    if err:
        if err in (1, 2):
            parent.error = 1
        return
    error = 0

    err, result = parent.utm.get_lldp_profiles_list()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return
    profiles = {x['name'].strip().translate(trans_name): x['id'] for x in result}

    for item in data:
        item['name'] = item['name'].strip().translate(trans_name)
        if item['name'] in profiles:
            parent.stepChanged.emit(f'GRAY|    Профиль LLDP "{item["name"]}" уже существует.')
            err, result = parent.utm.update_lldp_profile(profiles[item['name']], item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Профиль LLDP: {item["name"]}]')
                continue
            else:
                parent.stepChanged.emit(f'BLACK|    Профиль LLDP "{item["name"]}" updated.')
        else:
            err, result = parent.utm.add_lldp_profile(item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Профиль LLDP: "{item["name"]}"]')
                continue
            else:
                profiles[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Профиль LLDP "{item["name"]}" импортирован.')
    if error:
        parent.error = 1
    out_message = 'GREEN|    Профили LLDP импортированы в раздел "Библиотеки/Профили LLDP".'
    parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей LLDP.' if error else out_message)


def import_ssl_forward_profiles(parent, path):
    """Импортируем профили пересылки SSL"""
    parent.stepChanged.emit('BLUE|Импорт профилей пересылки SSL в раздел "Библиотеки/Профили пересылки SSL".')
    json_file = os.path.join(path, 'config_ssl_forward_profiles.json')
    err, data = read_json_file(parent, json_file)
    if err:
        if err in (1, 2):
            parent.error = 1
        return
    error = 0

    err, result = parent.utm.get_ssl_forward_profiles()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return
    profiles = {x['name'].strip().translate(trans_name): x['id'] for x in result}

    for item in data:
        item['name'] = item['name'].strip().translate(trans_name)
        if item['name'] in profiles:
            parent.stepChanged.emit(f'GRAY|    Профиль пересылки SSL "{item["name"]}" уже существует.')
            err, result = parent.utm.update_ssl_forward_profile(profiles[item['name']], item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Профиль пересылки SSL: {item["name"]}]')
                continue
            else:
                parent.stepChanged.emit(f'BLACK|    Профиль пересылки SSL "{item["name"]}" updated.')
        else:
            err, result = parent.utm.add_ssl_forward_profile(item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Профиль пересылки SSL: "{item["name"]}"]')
                continue
            else:
                profiles[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Профиль пересылки SSL "{item["name"]}" импортирован.')
    if error:
        parent.error = 1
    out_message = 'GREEN|    Профили пересылки SSL импортированы в раздел "Библиотеки/Профили пересылки SSL".'
    parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей пересылки SSL.' if error else out_message)


def import_hip_objects(parent, path):
    """Импортируем HIP объекты"""
    parent.stepChanged.emit('BLUE|Импорт HIP объектов в раздел "Библиотеки/HIP объекты".')
    json_file = os.path.join(path, 'config_hip_objects.json')
    err, data = read_json_file(parent, json_file)
    if err:
        if err in (1, 2):
            parent.error = 1
        return
    error = 0

    err, result = parent.utm.get_hip_objects_list()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return
    profiles = {x['name']: x['id'] for x in result}

    for item in data:
        if item['name'] in profiles:
            parent.stepChanged.emit(f'GRAY|    HIP объект "{item["name"]}" уже существует.')
            err, result = parent.utm.update_hip_object(profiles[item['name']], item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [HIP объект: {item["name"]}]')
                continue
            else:
                parent.stepChanged.emit(f'BLACK|    HIP объект "{item["name"]}" updated.')
        else:
            err, result = parent.utm.add_hip_object(item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [HIP объект: "{item["name"]}"]')
                continue
            else:
                profiles[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    HIP объект "{item["name"]}" импортирован.')
    if error:
        parent.error = 1
    out_message = 'GREEN|    HIP объекты импортированы в раздел "Библиотеки/HIP объекты".'
    parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте HIP объектов.' if error else out_message)


def import_hip_profiles(parent, path):
    """Импортируем HIP профили"""
    parent.stepChanged.emit('BLUE|Импорт HIP профилей в раздел "Библиотеки/HIP профили".')
    json_file = os.path.join(path, 'config_hip_profiles.json')
    err, data = read_json_file(parent, json_file)
    if err:
        if err in (1, 2):
            parent.error = 1
        return
    error = 0

    err, result = parent.utm.get_hip_objects_list()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return
    hip_objects = {x['name']: x['id'] for x in result}

    err, result = parent.utm.get_hip_profiles_list()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return
    profiles = {x['name']: x['id'] for x in result}

    for item in data:
        for obj in item['hip_objects']:
            obj['id'] = hip_objects[obj['id']]
        if item['name'] in profiles:
            parent.stepChanged.emit(f'GRAY|    HIP профиль "{item["name"]}" уже существует.')
            err, result = parent.utm.update_hip_profile(profiles[item['name']], item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [HIP профиль: {item["name"]}]')
                continue
            else:
                parent.stepChanged.emit(f'BLACK|    HIP профиль "{item["name"]}" updated.')
        else:
            err, result = parent.utm.add_hip_profile(item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [HIP профиль: "{item["name"]}"]')
                continue
            else:
                profiles[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    HIP профиль "{item["name"]}" импортирован.')
    if error:
        parent.error = 1
    out_message = 'GREEN|    HIP профили импортированы в раздел "Библиотеки/HIP профили".'
    parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте HIP профилей.' if error else out_message)


def import_bfd_profiles(parent, path):
    """Импортируем профили BFD"""
    parent.stepChanged.emit('BLUE|Импорт профилей BFD в раздел "Библиотеки/Профили BFD".')
    json_file = os.path.join(path, 'config_bfd_profiles.json')
    err, data = read_json_file(parent, json_file)
    if err:
        if err in (1, 2):
            parent.error = 1
        return
    error = 0

    err, result = parent.utm.get_bfd_profiles_list()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return
    profiles = {x['name']: x['id'] for x in result}

    for item in data:
        if item['name'] in profiles:
            parent.stepChanged.emit(f'GRAY|    Профиль BFD "{item["name"]}" уже существует.')
            err, result = parent.utm.update_bfd_profile(profiles[item['name']], item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Профиль BFD: {item["name"]}]')
                continue
            else:
                parent.stepChanged.emit(f'BLACK|    Профиль BFD "{item["name"]}" updated.')
        else:
            err, result = parent.utm.add_bfd_profile(item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Профиль BFD: "{item["name"]}"]')
                continue
            else:
                profiles[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Профиль BFD "{item["name"]}" импортирован.')
    if error:
        parent.error = 1
    out_message = 'GREEN|    Профили BFD импортированы в раздел "Библиотеки/Профили BFD".'
    parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей BFD.' if error else out_message)


def import_useridagent_syslog_filters(parent, path):
    """Импортируем syslog фильтры UserID агента"""
    parent.stepChanged.emit('BLUE|Импорт syslog фильтров UserID агента в раздел "Библиотеки/Syslog фильтры UserID агента".')
    json_file = os.path.join(path, 'config_useridagent_syslog_filters.json')
    err, data = read_json_file(parent, json_file)
    if err:
        if err in (1, 2):
            parent.error = 1
        return
    error = 0

    err, result = parent.utm.get_useridagent_filters_list()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return
    filters = {x['name']: x['id'] for x in result}

    for item in data:
        if item['name'] in filters:
            parent.stepChanged.emit(f'GRAY|    Фильтр "{item["name"]}" уже существует.')
            err, result = parent.utm.update_useridagent_filter(filters[item['name']], item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Фильтр: {item["name"]}]')
                continue
            else:
                parent.stepChanged.emit(f'BLACK|    Фильтр "{item["name"]}" updated.')
        else:
            err, result = parent.utm.add_useridagent_filter(item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Фильтр: "{item["name"]}"]')
                continue
            else:
                filters[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Фильтр "{item["name"]}" импортирован.')
    if error:
        parent.error = 1
    out_message = 'GREEN|    Профили BFD импортированы в раздел "Библиотеки/Syslog фильтры UserID агента".'
    parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте syslog фильтров UserID агента.' if error else out_message)


def pass_function(parent, path):
    """Функция заглушка"""
    parent.stepChanged.emit(f'GRAY|Импорт раздела "{path.rpartition("/")[2]}" в настоящее время не реализован.')

func = {
    'GeneralSettings': import_general_settings,
    'DeviceManagement': pass_function,
    'Administrators': pass_function,
    'Certificates': pass_function,
    'UserCertificateProfiles': import_users_certificate_profiles,
    'Zones': import_zones,
    'Interfaces': import_vlans,
    'Gateways': import_gateways,
    'DHCP': import_dhcp_subnets,
    'DNS': import_dns_config,
    'VRF': import_vrf,
    'WCCP': import_wccp_rules,
    'Routes': pass_function,
    'OSPF': pass_function,
    'BGP': pass_function,
    'Groups': import_local_groups,
    'Users': import_local_users,
    'AuthServers': import_auth_servers,
    'AuthProfiles': import_auth_profiles,
    'CaptivePortal': import_captive_portal_rules,
    'CaptiveProfiles': import_captive_profiles,
    'TerminalServers': import_terminal_servers,
    'MFAProfiles': import_2fa_profiles,
    'UserIDagent': import_userid_agent,
    'BYODPolicies': import_byod_policy,
    'BYODDevices': pass_function,
    'Firewall': import_firewall_rules,
    'NATandRouting': import_nat_rules,
    'LoadBalancing': import_loadbalancing_rules,
    'TrafficShaping': import_shaper_rules,
    "ContentFiltering": import_content_rules,
    "SafeBrowsing": import_safebrowsing_rules,
    "TunnelInspection": import_tunnel_inspection_rules,
    "SSLInspection": import_ssldecrypt_rules,
    "SSHInspection": import_sshdecrypt_rules,
    "IntrusionPrevention": import_idps_rules,
    "Scenarios": import_scenarios,
    "MailSecurity": import_mailsecurity,
    "ICAPRules": import_icap_rules,
    "ICAPServers": import_icap_servers,
    "DoSRules": import_dos_rules,
    "DoSProfiles": import_dos_profiles,
    "SCADARules": import_scada_rules,
    "WebPortal": pass_function,
    "ReverseProxyRules": pass_function,
    "ReverseProxyServers": pass_function,
    "WAF": pass_function,
    "WAFprofiles": pass_function,
    "CustomWafLayers": pass_function,
    "SystemWafRules": pass_function,
    "VPN": pass_function,
    "ServerRules": pass_function,
    "ClientRules": pass_function,
    "VPNNetworks": pass_function,
    "SecurityProfiles": pass_function,
    "ServerSecurityProfiles": pass_function,
    "ClientSecurityProfiles": pass_function,
    "Morphology": import_morphology_lists,
    "Services": import_services_list,
    "ServicesGroups": import_services_groups,
    "IPAddresses": import_ip_lists,
    "Useragents": import_useragent_lists,
    "ContentTypes": import_mime_lists,
    "URLLists": import_url_lists,
    "TimeSets": import_time_restricted_lists,
    "BandwidthPools": import_shaper_list,
    "SCADAProfiles": import_scada_profiles,
    "ResponcePages": import_templates_list,
    "URLCategories": import_url_categories,
    "OverURLCategories": import_custom_url_category,
    "Applications": import_application_signature,
    "ApplicationProfiles": import_app_profiles,
    "ApplicationGroups": import_application_groups,
    "Emails": import_email_groups,
    "Phones": import_phone_groups,
    "IPDSSignatures": import_custom_idps_signature,
    "IDPSProfiles": import_idps_profiles,
    "NotificationProfiles": import_notification_profiles,
    "NetflowProfiles": import_netflow_profiles,
    "LLDPProfiles": import_lldp_profiles,
    "SSLProfiles": import_ssl_profiles,
    "SSLForwardingProfiles": import_ssl_forward_profiles,
    "HIDObjects": import_hip_objects,
    "HIDProfiles": import_hip_profiles,
    "BfdProfiles": import_bfd_profiles,
    "UserIdAgentSyslogFilters": import_useridagent_syslog_filters,
}


############################# Служебные функции #####################################
def get_ips_id(parent, rule_ips, rule_name):
    """Получить ID списков IP-адресов. Если список IP-адресов не существует на NGFW, он пропускается."""
    new_rule_ips = []
    for ips in rule_ips:
        if ips[0] == 'geoip_code':
            new_rule_ips.append(ips)
        if ips[0] == 'mac':
            new_rule_ips.append(ips)
        try:
            if ips[0] == 'list_id':
                new_rule_ips.append(['list_id', parent.ip_lists[ips[1]]])
            elif ips[0] == 'urllist_id':
                if parent.version < 6:
                    parent.stepChanged.emit(f'bRED|    Error! Правило "{rule_name}": Список доменов "{ips[1]}" не добавлен в источник/назначение. Версия 5 не поддерживает данный функционал.')
                else:
                    new_rule_ips.append(['urllist_id', parent.url_lists[ips[1]]])
        except KeyError as err:
            parent.stepChanged.emit(f'bRED|    Error! Правило "{rule_name}": Не найден список адреса источника/назначения "{ips[1]}". Загрузите списки в библиотеки и повторите импорт.')
    return new_rule_ips

def get_zones_id(parent, zones, rule_name):
    """Получить ID зон. Если зона не существует на NGFW, то она пропускается."""
    new_zones = []
    for zone_name in zones:
        try:
            new_zones.append(parent.ngfw_zones[zone_name])
        except KeyError as err:
            parent.stepChanged.emit(f'bRED|    Error! Правило "{rule_name}": Не найдена зона "{zone_name}".')
    return new_zones

def get_urls_id(parent, urls, rule_name):
    """Получить ID списков URL. Если список не существует на NGFW, он пропускается."""
    new_urls = []
    for url_list_name in urls:
        try:
            new_urls.append(parent.url_lists[url_list_name])
        except KeyError as err:
            parent.stepChanged.emit(f'bRED|    Error! Правило "{rule_name}": Не найден список URL "{url_list_name}". Загрузите списки URL и повторите импорт.')
    return new_urls

def get_url_categories_id(parent, url_categories, rule_name):
    """Получить ID категорий URL и групп категорий URL. Если список не существует на NGFW, он пропускается."""
    new_urls = []
    for arr in url_categories:
        try:
            if arr[0] == 'list_id':
                new_urls.append(['list_id', parent.list_urlcategorygroup[arr[1]]])
            elif arr[0] == 'category_id':
                new_urls.append(['category_id', parent.url_categories[arr[1]]])
        except KeyError as err:
            parent.stepChanged.emit(f'bRED|    Error! Правило "{rule_name}": Не найдена категория URL "{arr[1]}". Загрузите категории URL и повторите импорт.')
    return new_urls

def get_time_restrictions_id(parent, times, rule_name):
    """Получить ID календарей. Если не существуют на NGFW, то пропускается."""
    new_times = []
    for cal_name in times:
        try:
            new_times.append(parent.list_calendar[cal_name])
        except KeyError as err:
            parent.stepChanged.emit(f'bRED|    Error! Правило "{rule_name}": Не найден календарь "{cal_name}".')
    return new_times

def get_guids_users_and_groups(parent, users, rule_name):
    """
    Получить GUID-ы групп и пользователей по их именам.
    Заменяет имена локальных и доменных пользователей и групп на GUID-ы.
    """
    new_users = []
    for item in users:
        match item[0]:
            case 'special':
                new_users.append(item)
            case 'user':
                i = item[1].partition("\\")
                if i[2]:
                    err, result = parent.utm.get_ldap_user_guid(i[0], i[2])
                    if err:
                        parent.stepChanged.emit(f'bRED|    {result}  [Rule: "{rule_name}"]')
                    elif not result:
                        parent.stepChanged.emit(f'NOTE|    Error [Rule: "{rule_name}"]. Нет LDAP-коннектора для домена "{i[0]}"! Импортируйте и настройте LDAP-коннектор. Затем повторите импорт.')
                    else:
                        new_users.append(['user', result])
                else:
                    try:
                        result = parent.list_users[item[1]]
                    except KeyError:
                        parent.stepChanged.emit(f'bRED|    Не найден пользователь для правила "{rule_name}"]. Импортируйте локальных пользователей и повторите импорт.')
                    else:
                        new_users.append(['user', result])
            case 'group':
                i = item[1].partition("\\")
                if i[2]:
                    err, result = parent.utm.get_ldap_group_guid(i[0], i[2])
                    if err:
                        parent.stepChanged.emit(f'bRED|    {result}  [Rule: "{rule_name}"]')
                    elif not result:
                        parent.stepChanged.emit(f'NOTE|    Error [Rule: "{rule_name}"]. Нет LDAP-коннектора для домена "{i[0]}"! Импортируйте и настройте LDAP-коннектор. Затем повторите импорт.')
                    else:
                        new_users.append(['group', result])
                else:
                    try:
                        result = parent.list_groups[item[1]]
                    except KeyError:
                        parent.stepChanged.emit(f'bRED|    Не найдена группа для правила "{rule_name}"]. Импортируйте локальные группы и повторите импорт.')
                    else:
                        new_users.append(['group', result])
    return new_users

def get_services(parent, service_list, rule_name):
    """Получаем ID сервисов по их именам. Если сервис не найден, то он пропускается."""
    new_service_list = []
    if parent.version < 7:
        for item in service_list:
            if item[0] == 'list_id':
                parent.stepChanged.emit(f'bRED|    Error! Правило "{rule_name}": Группа сервисов "{item[1]}" не добавлена. В версии 6 группы сервисов не поддерживаются.')
            else:
                try:
                    new_service_list.append(parent.services_list[item[1]])
                except KeyError as err:
                    parent.stepChanged.emit(f'bRED|    Error! Правило "{rule_name}": Не найден сервис "{item[1]}". Импортируйте сервисы и повторите попытку.')
    else:
        for item in service_list:
            try:
                new_service_list.append(['service', parent.services_list[item[1]]] if item[0] == 'service' else ['list_id', parent.servicegroups_list[item[1]]])
            except KeyError as err:
                parent.stepChanged.emit(f'bRED|    Error! Правило "{rule_name}": Не найден сервис "{item[1]}".')
    return new_service_list

def set_apps_values(parent):
    """Устанавливаем в parent значения атрибутов: l7_categories, l7_apps, list_applicationgroup"""
    err, result = parent.utm.get_l7_categories()
    if err:
        parent.stepChanged.emit(f'iRED|{result}')
        return 1
    parent.l7_categories = {x['name']: x['id'] for x in result}

    err, result = parent.utm.get_l7_apps()
    if err:
        parent.stepChanged.emit(f'iRED|{result}')
        return 1
    parent.l7_apps = {value: key for key, value in result.items()}

    err, result = parent.utm.get_nlists_list('applicationgroup')
    if err:
        parent.stepChanged.emit(f'iRED|{result}')
        return 1
    parent.list_applicationgroup = {x['name'].strip().translate(trans_name): x['id'] for x in result}

    return 0

def get_apps(parent, array_apps, rule_name):
    """Определяем ID приложения или группы приложений по именам."""
    new_app_list = []
    for app in array_apps:
        if app[0] == 'ro_group':
            if app[1] == 'All':
                if parent.version >= 6:
                    new_app_list.append(['ro_group', 0])
                else:
                    parent.stepChanged.emit(f'bRED|    Error! Правило "{rule_name}": Категорию "All" нельзя добавить в версии 5.')
            else:
                try:
                    new_app_list.append(['ro_group', parent.l7_categories[app[1]]])
                except KeyError as err:
                    parent.stepChanged.emit(f'bRED|    Error! Правило "{rule_name}": Не найдена категория l7 "{err}".')
                    parent.stepChanged.emit(f'bRED|    Возможно нет лицензии и UTM не получил список категорий l7. Установите лицензию и повторите попытку.')
        elif app[0] == 'group':
            try:
                new_app_list.append(['group', parent.list_applicationgroup[app[1]]])
            except KeyError as err:
                parent.stepChanged.emit(f'bRED|    Error! Правило "{rule_name}": Не найдена группа приложений l7 "{err}".')
        elif app[0] == 'app':
            if parent.version < 7:
                try:
                    new_app_list.append(['app', parent.l7_apps[app[1]]])
                except KeyError as err:
                    parent.stepChanged.emit(f'bRED|    Error! Правило "{rule_name}": Не найдено приложение "{err}".')
                    parent.stepChanged.emit(f'bRED|    Возможно нет лицензии и UTM не получил список приложений l7. Установите лицензию и повторите попытку.')
            else:
                parent.stepChanged.emit(f'NOTE|    Правило "{rule_name}": приложение {app[1]} не добавлено, так как в версии 7.0 отдельное приложение добавить нельзя.')

    return new_app_list

def set_scenarios_rules(parent):
    """Устанавливаем в parent значение атрибута: scenarios_rules"""
    err, result = parent.utm.get_scenarios_rules()
    if err:
        parent.stepChanged.emit(f'RED|    {data}')
        parent.error = 1
        return
    parent.scenarios_rules = {x['name'].strip().translate(trans_name): x['id'] for x in result}

def execute_add_update_nlist(parent, ngfw_named_list, item, item_note):
    """Обновляем существующий именованный список или создаём новый именованный список"""
    if item['name'] in ngfw_named_list:
        parent.stepChanged.emit(f'GRAY|    {item_note} "{item["name"]}" уже существует.')
        err, result = parent.utm.update_nlist(ngfw_named_list[item['name']], item)
        if err == 1:
            parent.stepChanged.emit(f'RED|    {result}  [{item_note}: {item["name"]}]')
            return 1
        elif err == 2:
            parent.stepChanged.emit(f'GRAY|    {result}')
        else:
            parent.stepChanged.emit(f'BLACK|    {item_note} "{item["name"]}" updated.')
    else:
        err, result = parent.utm.add_nlist(item)
        if err:
            parent.stepChanged.emit(f'RED|    {result}  [{item_note}: "{item["name"]}"]')
            return 1
        else:
            ngfw_named_list[item['name']] = result
            parent.stepChanged.emit(f'BLACK|    {item_note} "{item["name"]}" импортирована.')
    return 0

def execute_add_nlist_items(parent, list_id, item_name, content):
    """Импортируем содержимое в именованный список"""
    err, result = parent.utm.add_nlist_items(list_id, content)
    if err == 2:
        parent.stepChanged.emit(f'GRAY|       {result}')
    elif err == 1:
        parent.stepChanged.emit(f'RED|       {result}  [Список: "{item_name}"]')
        return 1
    else:
        parent.stepChanged.emit(f'BLACK|       Содержимое списка "{item_name}" обновлено.')
    return 0

def add_new_nlist(utm, name, nlist_type, content):
    """Добавляем в библиотеку новый nlist с содержимым."""
    nlist = {
        'name': name,
        'description': '',
        'type': nlist_type,
        'list_type_update': 'static',
        'schedule': 'disabled',
        'attributes': {'threat_level': 3},
    }
    err, list_id = utm.add_nlist(nlist)
    if err:
        return err, list_id
    err, result = utm.add_nlist_items(list_id, content)
    if err:
        return err, result
    return 0, list_id

def add_empty_vrf(utm, vrf_name):
    """Добавляем пустой VRF"""
    vrf = {
        'name': vrf_name,
        'description': '',
        'interfaces': [],
        'routes': [],
        'ospf': {},
        'bgp': {},
        'rip': {},
        'pimsm': {}
    }
    err, result = utm.add_vrf(vrf)
    if err:
        return err, result
    return 0, result    # Возвращаем ID добавленного VRF

def read_json_file(parent, json_file_path):
    """Читаем json-файл с конфигурацией."""
    try:
        with open(json_file_path, "r") as fh:
            data = json.load(fh)
    except FileNotFoundError as err:
        parent.stepChanged.emit(f'RED|    Error: Не найден файл "{json_file_path}" с сохранённой конфигурацией!')
        parent.error = 1
        return 2, 'RED'
    except ValueError as err:
        parent.error = 1
        parent.stepChanged.emit(f'RED|    Error: JSONDecodeError - {err} "{json_file_path}".')
        return 1, 'RED'
    if not data:
        parent.stepChanged.emit(f'GRAY|    Файл "{json_file_path}" пуст.')
        return 3, 'GRAY'
    return 0, data

