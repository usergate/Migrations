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
# Версия 0.3
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

def import_firewall_rules(parent):
    """Импортировать список правил межсетевого экрана"""
    parent.stepChanged.emit('0|Импорт правил межсетевого экрана в раздел "Политики сети/Межсетевой экран".')

    json_file = "data_ug/NetworkPolicies/Firewall/config_firewall_rules.json"
    err, data = read_json_file(json_file, '2|Ошибка импорта правил межсетевого экрана!', '2|Нет правил межсетевого экрана для импорта.')
    if err:
        parent.stepChanged.emit(data)
        parent.error = 1
        return

    err, result = parent.utm.get_firewall_rules()
    if err:
        parent.stepChanged.emit(f'1|{result}')
        parent.stepChanged.emit('1|Импорт правил межсетевого экрана прерван!')
        parent.error = 1
        return
    firewall_rules = {x['name']: x['id'] for x in result}

    err, result = parent.utm.get_zones_list()
    if err:
        parent.stepChanged.emit(f'1|{result}')
        parent.stepChanged.emit('1|Импорт правил межсетевого экрана прерван!')
        parent.error = 1
        return
    zones_list = {x['name']: x['id'] for x in result}

    err, result = parent.utm.get_services_list()
    if err:
        parent.stepChanged.emit(f'1|{result}')
        parent.stepChanged.emit('1|Импорт правил межсетевого экрана прерван!')
        parent.error = 1
        return
    services_list = {x['name']: x['id'] for x in result}

    err, result = parent.utm.get_nlists_list('servicegroup')
    if err:
        parent.stepChanged.emit(f'1|{result}')
        parent.stepChanged.emit('1|Импорт правил межсетевого экрана прерван!')
        parent.error = 1
        return
    servicegroups_list = {x['name']: x['id'] for x in result}

    err, result = parent.utm.get_nlists_list('network')
    if err:
        parent.stepChanged.emit(f'1|{result}')
        parent.stepChanged.emit('1|Импорт правил межсетевого экрана прерван!')
        parent.error = 1
        return
    ips_list = {x['name']: x['id'] for x in result}

    err, result = parent.utm.get_l7_categories()
    if err:
        parent.stepChanged.emit(f'1|{result}')
        parent.stepChanged.emit('1|Импорт правил межсетевого экрана прерван!')
        parent.error = 1
        return
    l7categories = {x['name']: x['id'] for x in result}

    err, result = parent.utm.get_nlists_list('applicationgroup')
    if err:
        parent.stepChanged.emit(f'1|{result}')
        parent.stepChanged.emit('1|Импорт правил межсетевого экрана прерван!')
        parent.error = 1
        return
    applicationgroup = {x['name']: x['id'] for x in result}

    error = 0
    for item in data:
        item['position'] = 'last'
        item['src_zones'] = get_zones(parent, item['src_zones'], zones_list, item["name"])
        item['dst_zones'] = get_zones(parent, item['dst_zones'], zones_list, item["name"])
        item['src_ips'] = get_ips(parent, item['src_ips'], ips_list, item["name"])
        item['dst_ips'] = get_ips(parent, item['dst_ips'], ips_list, item["name"])
        for service in item['services']:
            try:
                service[1] = services_list[service[1]] if service[0] == 'service' else servicegroups_list[service[1]]
            except KeyError as err:
                error = 1
                parent.stepChanged.emit(f'1|Error! Не найден сервис {service} для правила {item["name"]}.')
        for app in item['apps']:
            try:
                app[1] = l7categories[app[1]] if app[0] == 'ro_group' else applicationgroup[app[1]]
            except KeyError as err:
                error = 1
                parent.stepChanged.emit(f'1|Error! Не найдена группа приложений {err} для правила "{item["name"]}". Загрузите группы приложений и повторите попытку.')

        get_guids_users_and_groups(parent, item)
#        parent.set_time_restrictions(item)
        if item['name'] in firewall_rules:
            parent.stepChanged.emit(f'2|Правило МЭ "{item["name"]}" уже существует.')
            item.pop('position', None)
            err, result = parent.utm.update_firewall_rule(firewall_rules[item['name']], item)
            if err:
                error = 1
                parent.stepChanged.emit(f'1|{result}')
            else:
                parent.stepChanged.emit(f'2|   Правило МЭ "{item["name"]}" обновлено.')
        else:
            err, result = parent.utm.add_firewall_rule(item)
            if err:
                error = 1
                parent.stepChanged.emit(f'1|{result}')
            else:
                firewall_rules[item['name']] = result
                parent.stepChanged.emit(f'2|   Правило МЭ "{item["name"]}" добавлено.')
    if error:
        parent.error = 1
    out_message = '5|Правила межсетевого экрана импортированы в раздел "Политики сети/Межсетевой экран".'
    parent.stepChanged.emit('6|Произошла ошибка при импорте правил межсетевого экрана!' if error else out_message)

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

############################# Служебные функции #####################################
def get_ips_id(parent, rule_ips, rule_name):
    """Получить ID списков IP-адресов. Если список IP-адресов не существует на NGFW, он пропускается."""
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
            parent.stepChanged.emit(f'bRED|    Error! Не найден список адреса источника/назначения: {ips} для правила {rule_name}.')
    return new_rule_ips

def get_zones_id(parent, zones, rule_name):
    """Получить ID зон. Если зона не существует на NGFW, то она пропускается."""
    new_zones = []
    for zone_name in zones:
        try:
            new_zones.append(parent.ngfw_zones[zone_name])
        except KeyError as err:
            parent.stepChanged.emit(f'bRED|    Error! Не найдена зона "{zone_name}" для правила {rule_name}.')
    return new_zones

def get_urls_id(parent, urls, rule_name):
    """Получить ID списков URL. Если список не существует на NGFW, он пропускается."""
    new_urls = []
    for url_list_name in urls:
        try:
            new_urls.append(parent.url_lists[url_list_name])
        except KeyError as err:
            parent.stepChanged.emit(f'bRED|    Error! Не найден список URL "{url_list_name}" для правила {rule_name}.')
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
            parent.stepChanged.emit(f'bRED|    Error! Не найдена категория URL {arr} для правила {rule_name}.')
    return new_urls

def get_time_restrictions_id(parent, times, rule_name):
    """Получить ID календарей. Если не существуют на NGFW, то пропускается."""
    new_times = []
    for cal_name in times:
        try:
            new_times.append(parent.list_calendar[cal_name])
        except KeyError as err:
            parent.stepChanged.emit(f'bRED|    Error! Не найден календарь "{cal_name}" для правила {rule_name}.')
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
                        parent.stepChanged.emit(f'bRED|   {result}  [Rule: "{rule_name}"]')
                    elif not result:
                        parent.stepChanged.emit(f'NOTE|   Error [Rule: "{rule_name}"]. Нет LDAP-коннектора для домена "{i[0]}"! Импортируйте и настройте LDAP-коннектор. Затем повторите импорт.')
                    else:
                        new_users.append(['user', result])
                else:
                    try:
                        result = parent.list_users[item[1]]
                    except KeyError:
                        parent.stepChanged.emit(f'bRED|   Не найден пользователь для правила "{rule_name}"]. Импортируйте локальных пользователей и повторите импорт.')
                    else:
                        new_users.append(['user', result])
            case 'group':
                i = item[1].partition("\\")
                if i[2]:
                    err, result = parent.utm.get_ldap_group_guid(i[0], i[2])
                    if err:
                        parent.stepChanged.emit(f'bRED|   {result}  [Rule: "{rule_name}"]')
                    elif not result:
                        parent.stepChanged.emit(f'NOTE|   Error [Rule: "{rule_name}"]. Нет LDAP-коннектора для домена "{i[0]}"! Импортируйте и настройте LDAP-коннектор. Затем повторите импорт.')
                    else:
                        new_users.append(['group', result])
                else:
                    try:
                        result = parent.list_groups[item[1]]
                    except KeyError:
                        parent.stepChanged.emit(f'bRED|   Не найдена группа для правила "{rule_name}"]. Импортируйте локальные группы и повторите импорт.')
                    else:
                        new_users.append(['group', result])
    return new_users

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

