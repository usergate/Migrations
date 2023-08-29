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
# Версия 2.0
#

import os, sys, json
from PyQt6.QtCore import QThread, pyqtSignal
from services import (ServicePorts, dict_risk, character_map, character_map_file_name, character_map_for_name,
                      url_category, l7categories, l7apps, none_apps)


class ImportAll(QThread):
    """Импортируем список шлюзов"""
    stepChanged = pyqtSignal(str)
    
    def __init__(self, utm, utm_vlans, utm_zones, new_vlans, ifaces):
        super().__init__()
        self.utm = utm
        self.utm_vlans = utm_vlans
        self.utm_zones = utm_zones
        self.new_vlans = new_vlans
        self.ifaces = ifaces
        self.error = 0

    def run(self):
        """Импортируем всё в пакетном режиме"""
        import_vlans(self)
        import_gateways(self)
        import_ui(self)
        import_dns_servers(self)
        import_ntp_settings(self)
        import_static_routes(self)
        import_services(self)
        import_services_groups(self)
        import_ip_lists(self)
        import_url_lists(self)
        self.stepChanged.emit('5|Импорт конфигурации прошёл с ошибками!' if self.error else '5|Импорт всей конфигурации прошёл успешно.')


class ImportGateways(QThread):
    """Импортируем список шлюзов"""
    stepChanged = pyqtSignal(str)
    
    def __init__(self, utm):
        super().__init__()
        self.utm = utm
        self.error = 0

    def run(self):
        import_gateways(self)


class ImportUi(QThread):
    """Импортируем часовой пояс"""
    stepChanged = pyqtSignal(str)
    
    def __init__(self, utm):
        super().__init__()
        self.utm = utm
        self.error = 0

    def run(self):
        import_ui(self)


class ImportDnsServers(QThread):
    """Импортируем список системных DNS серверов"""
    stepChanged = pyqtSignal(str)
    
    def __init__(self, utm):
        super().__init__()
        self.utm = utm
        self.error = 0

    def run(self):
        import_dns_servers(self)


class ImportNtpSettings(QThread):
    """Импортируем настройки NTP"""
    stepChanged = pyqtSignal(str)
    
    def __init__(self, utm):
        super().__init__()
        self.utm = utm
        self.error = 0

    def run(self):
        import_ntp_settings(self)


class ImportStaticRoutes(QThread):
    """Импортируем статические маршруты в Виртуальный маршрутизатор по умолчанию"""
    stepChanged = pyqtSignal(str)
    
    def __init__(self, utm):
        super().__init__()
        self.utm = utm
        self.error = 0

    def run(self):
        import_static_routes(self)


class ImportVlans(QThread):
    """Импортируем интерфесы VLAN. Нельзя использовать интерфейсы Management и slave."""
    stepChanged = pyqtSignal(str)
    
    def __init__(self, utm, utm_vlans, utm_zones, new_vlans, ifaces):
        super().__init__()
        self.utm = utm
        self.utm_vlans = utm_vlans
        self.utm_zones = utm_zones
        self.new_vlans = new_vlans
        self.ifaces = ifaces
        self.error = 0

    def run(self):
        import_vlans(self)


class ImportServices(QThread):
    """Импортируем список сервисов раздела библиотеки"""
    stepChanged = pyqtSignal(str)
    
    def __init__(self, utm):
        super().__init__()
        self.utm = utm
        self.error = 0

    def run(self):
        import_services(self)


class ImportServicesGroups(QThread):
    """Импортируем группы сервисов в раздел Библиотеки/Группы сервисов"""
    stepChanged = pyqtSignal(str)
    
    def __init__(self, utm):
        super().__init__()
        self.utm = utm
        self.error = 0

    def run(self):
        import_services_groups(self)


class ImportIpLists(QThread):
    """Импортируем списки IP адресов"""
    stepChanged = pyqtSignal(str)
    
    def __init__(self, utm):
        super().__init__()
        self.utm = utm
        self.error = 0

    def run(self):
        import_ip_lists(self)


class ImportUrlLists(QThread):
    """Импортировать списки URL на UTM"""
    stepChanged = pyqtSignal(str)
    
    def __init__(self, utm):
        super().__init__()
        self.utm = utm
        self.error = 0

    def run(self):
        import_url_lists(self)


def read_json_file(json_file, err_file_not_found, err_data):
    try:
        with open(json_file, "r") as fh:
            data = json.load(fh)
    except FileNotFoundError as err:
        return 1, f'{err_file_not_found} Не найден файл "{json_file}" с сохранённой конфигурацией!'
    except ValueError as err:
        return 1, f'1|Error: JSONDecodeError - {err} "{json_file}".'

    if not data:
        return 1, f'{err_data} Файл "{json_file}" пуст.'
    return 0, data

def import_gateways(parent):
    """Импортируем список шлюзов"""
    parent.stepChanged.emit('0|Импорт шлюзов в раздел "Сеть/Шлюзы".')
    json_file = "data_ug/Network/Gateways/config_gateways.json"
    err, data = read_json_file(json_file, '1|Ошибка импорта шлюзов!', '1|Нет шлюзов для импорта.')
    if err:
        parent.stepChanged.emit(data)
        parent.error = 1
        return

    err, result = parent.utm.get_gateways_list()
    if err:
        parent.stepChanged.emit(f'1|{result}')
        parent.error = 1
        return

    gateways_list = {x.get('name', x['ipv4']): x['id'] for x in result}
    error = 0

    for item in data:
        if not item['is_automatic']:
            if item['name'] in gateways_list:
                err, result = parent.utm.update_gateway(gateways_list[item['name']], item)
                if err:
                    parent.stepChanged.emit(f'2|{result} Шлюз "{item["name"]}"')
                    error = 1
                else:
                    parent.stepChanged.emit(f'2|Шлюз "{item["name"]}" уже существует - Updated!')
            else:
                err, result = parent.utm.add_gateway(item)
                if err:
                    parent.stepChanged.emit(f'2|{result}')
                    error = 1
                else:
                    gateways_list[item['name']] = result
                    parent.stepChanged.emit(f'2|Шлюз "{item["name"]}" добавлен.')
    if error:
        parent.error = 1
    parent.stepChanged.emit('1|Ошибка импорта шлюзов!' if error else '1|Шлюзы импортированы в раздел "Сеть/Шлюзы".')

def import_ui(parent):
    """Импортируем часовой пояс"""
    parent.stepChanged.emit('0|Импорт часового пояса в "Настройки/Настройки интерфейса/Часовой пояс".')
    json_file = "data_ug/UserGate/GeneralSettings/config_settings_ui.json"
    err, data = read_json_file(json_file, '1|Ошибка импорта часового пояса!', '1|Нет часового пояса для импорта.')
    if err:
        parent.stepChanged.emit(data)
        parent.error = 1
        return

    params = {'ui_timezone': 'Часовой пояс'}
    error = 0

    for key, value in data.items():
        err, result = parent.utm.set_settings_param(key, value)
        if err:
            parent.stepChanged.emit(f'2|{result}')
            error = 1
            parent.error = 1
        else:
            parent.stepChanged.emit(f'2|Параметр {params[key]} - Updated!')
    out_message = '1|Импортирован часовой пояс в раздел "Настройки/Настройки интерфейса/Часовой пояс".'
    parent.stepChanged.emit('1|Ошибка импорта часового пояса!' if error else out_message)

def import_dns_servers(parent):
    """Импортируем список системных DNS серверов"""
    parent.stepChanged.emit('0|Импорт системных DNS серверов в раздел "Сеть/DNS/Системные DNS-серверы".')
    json_file = "data_ug/Network/DNS/config_dns_servers.json"
    err, data = read_json_file(json_file, '1|Ошибка импорта серверов DNS!', '1|Нет серверов DNS для импорта.')
    if err:
        parent.stepChanged.emit(data)
        parent.error = 1
        return

    error = 0
    for item in data:
        err, result = parent.utm.add_dns_server(item)
        if err:
            parent.stepChanged.emit(f'2|{result}')
            if err == 1:
                error = 1
                parent.error = 1
        else:
            parent.stepChanged.emit(f'2|DNS сервер "{item["dns"]}" добавлен.')
    out_message = '1|Импортированы системные DNS серверов в раздел "Сеть/DNS/Системные DNS-серверы".'
    parent.stepChanged.emit('1|Ошибка импорта DNS-сервера!' if error else out_message)

def import_ntp_settings(parent):
    """Импортируем настройки NTP"""
    parent.stepChanged.emit('0|Импорт настроек NTP раздела "Настройки/Настройки времени сервера".')
    json_file = "data_ug/UserGate/GeneralSettings/config_ntp.json"
    err, data = read_json_file(json_file, '1|Ошибка импорта серверов NTP!', '1|Нет серверов NTP для импорта.')
    if err:
        parent.stepChanged.emit(data)
        parent.error = 1
        return

    error = 0
    err, result = parent.utm.add_ntp_config(data)
    if err:
        parent.stepChanged.emit(f'2|{result}')
        error = 1
        parent.error = 1
    else:
        parent.stepChanged.emit('2|Настройки NTP обновлены.')
    out_message = '1|Импортированы сервера NTP в раздел "Настройки/Настройки времени сервера".'
    parent.stepChanged.emit('1|Ошибка импорта настроек NTP!' if error else out_message)

def import_static_routes(parent):
    """Импортируем статические маршруты в Виртуальный маршрутизатор по умолчанию"""
    parent.stepChanged.emit('0|Импорт статических маршрутов в Виртуальный маршрутизатор по умолчанию.')
    json_file = "data_ug/Network/VRF/config_routers.json"
    err, data = read_json_file(json_file, '1|Ошибка импорта статических маршрутов!', '1|Нет статических маршрутов для импорта.')
    if err:
        parent.stepChanged.emit(data)
        parent.error = 1
        return

    err, result = parent.utm.get_routers_list()
    if err:
        parent.stepChanged.emit(f'1|{result}')
        parent.error = 1
        return
    virt_routers = {x['name']: x['id'] for x in result}
    error = 0    
    out_message = '1|Статические маршруты импортированы в Виртуальный маршрутизатор по умолчанию.'
    
    for item in data:
        if item['name'] in virt_routers:
            err, result = parent.utm.update_vrf(virt_routers[item['name']], item)
            if err:
                parent.stepChanged.emit(f'2|{result}')
                error = 1
        else:
            err, result = parent.utm.add_vrf(item)
            if err:
                parent.stepChanged.emit(f'2|{result}')
                error = 1
            else:
                out_message = f'1|Создан виртуальный маршрутизатор "{item["name"]}".'
    if not error:
        parent.stepChanged.emit('2|Добавленные маршруты не активны. Необходимо проверить маршрутизацию и включить их.')
    else:
        parent.error = 1
    parent.stepChanged.emit('1|Ошибка импорта статических маршрутов!' if error else out_message)

def import_vlans(parent):
    """Импортируем интерфесы VLAN. Нельзя использовать интерфейсы Management и slave."""
    error = 0
    if not parent.new_vlans or isinstance(parent.new_vlans, str):
        parent.stepChanged.emit(parent.new_vlans if parent.new_vlans else '1|Импорт VLAN отменён пользователем.')
        return
    for item in parent.ifaces:
        current_port = parent.new_vlans[item['vlan_id']]['port']
        current_zone = parent.new_vlans[item['vlan_id']]['zone']
        if item['kind'] == 'vlan':
            if item["vlan_id"] in parent.utm_vlans:
                parent.stepChanged.emit(f'2|VLAN {item["vlan_id"]} уже существует на порту {parent.utm_vlans[item["vlan_id"]]}')
                continue
            if current_port == "Undefined":
                parent.stepChanged.emit(f"2|VLAN {item['vlan_id']} не импортирован так как для него не назначен порт.")
                continue
            item['link'] = current_port
            item['name'] = f'{current_port}.{item["vlan_id"]}'
            item['zone_id'] = 0 if current_zone == "Undefined" else parent.utm_zones[current_zone]
            item.pop('kind')

            err, result = parent.utm.add_interface_vlan(item)
            if err:
                parent.stepChanged.emit(f'2|Error: Интерфейс {item["name"]} не импортирован!')
                parent.stepChanged.emit(f'2|{result}')
                error = 1
                parent.error = 1
            else:
                parent.utm_vlans[item['vlan_id']] = item['name']
                parent.stepChanged.emit(f'2|Добавлен VLAN {item["vlan_id"]}, name: {item["name"]}, zone: {current_zone}, ip: {", ".join(item["ipv4"])}.')

    out_message = '1|Интерфейсы VLAN импортированы в раздел "Сеть/Интерфейсы".'
    parent.stepChanged.emit('1|Произошла ошибка создания интерфейса VLAN!' if error else out_message)

def import_services(parent):
    """Импортируем список сервисов раздела библиотеки"""
    parent.stepChanged.emit('0|Импорт списка сервисов в раздел "Библиотеки/Сервисы"')
    json_file = "data_ug/Libraries/Services/config_services.json"
    err, data = read_json_file(json_file, '1|Ошибка импорта списка сервисов!', '1|Нет сервисов для импорта.')
    if err:
        parent.stepChanged.emit(data)
        parent.error = 1
        return

    err, result = parent.utm.get_services_list()
    if err:
        parent.stepChanged.emit(f'1|{result}')
        parent.error = 1
        return
    services_list = {x['name']: x['id'] for x in result['items']}
    error = 0
    
    for item in data:
        if item['name'] in services_list:
            parent.stepChanged.emit(f'2|Сервис "{item["name"]}" уже существует.')
        else:
            err, result = parent.utm.add_service(item)
            if err:
                parent.stepChanged.emit(f'2|Произошла ошибка при добавлении сервиса "{item["name"]}".')
                parent.stepChanged.emit(f'2|result')
                error = 1
                parent.error = 1
            else:
                services_list[item['name']] = result
                parent.stepChanged.emit(f'2|Сервис "{item["name"]}" добавлен.')

    out_message = '1|Список сервисов импортирован в раздел "Библиотеки/Сервисы"'
    parent.stepChanged.emit('1|Произошла ошибка при добавлении сервисов!' if error else out_message)

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
    services_list = {x['name']: x['id'] for x in result['items']}
    out_message = '1|Группы сервисов импортированы в раздел "Библиотеки/Группы сервисов".'
    error = 0
    
    if os.path.isdir('data_ug/Libraries/ServicesGroups'):
        files_list = os.listdir('data_ug/Libraries/ServicesGroups')
        if files_list:
            for file_name in files_list:
                json_file = f"data_ug/Libraries/ServicesGroups/{file_name}"
                err, services_group = read_json_file(json_file, '1|Ошибка импорта группы сервисов!', '1|Нет группы сервисов для импорта.')
                if err:
                    parent.stepChanged.emit(services_group)
                    parent.error = 1
                    return

                content = services_group.pop('content')
                err1, result1 = parent.utm.add_nlist(services_group)
                if err1 == 1:
                    parent.stepChanged.emit(f'1|{result1}')
                    parent.stepChanged.emit(f'2|Ошибка! Группа сервисов "{services_group["name"]}" не импортирована.')
                    error = 1
                elif err1 == 3:
                    parent.stepChanged.emit(f'2|{result1}')
                    continue
                else:
                    parent.stepChanged.emit(f'2|Добавлена группа сервисов: "{services_group["name"]}".')
                if content:
                    for item in content:
                        try:
                            item['value'] = services_list[item['name']]
                        except KeyError:
                            parent.stepChanged.emit(f'2|Ошибка! Нет сервиса "{item["name"]}" в списке сервисов NGFW.')
                            parent.stepChanged.emit(f'2|Ошибка! Сервис "{item["name"]}" не добавлен в группу сервисов "{services_group["name"]}".')
                    err2, result2 = parent.utm.add_nlist_items(result1, content)
                    if err2:
                        parent.stepChanged.emit(f'2|{result2}')
                        if err2 == 1:
                            error = 1
                    else:
                        parent.stepChanged.emit(f'2|Содержимое группы сервисов "{services_group["name"]}" обновлено.')
                else:
                    parent.stepChanged.emit(f'2|Список "{services_group["name"]}" пуст.')
        else:
            out_message = "1|Нет групп сервисов для импорта."
    else:
        out_message = "1|Нет групп сервисов для импорта."
    if error:
        parent.error = 1
    parent.stepChanged.emit('1|Произошла ошибка при добавлении групп сервисов!' if error else out_message)

def import_ip_lists(parent):
    """Импортируем списки IP адресов"""
    parent.stepChanged.emit('0|Импорт списков IP-адресов раздела "Библиотеки/IP-адреса".')

    if not os.path.isdir('data_ug/Libraries/IPAddresses'):
        parent.stepChanged.emit("1|Нет списков IP-адресов для импорта.")
        return

    files_list = os.listdir('data_ug/Libraries/IPAddresses')
    if not files_list:
        parent.stepChanged.emit("1|Нет списков IP-адресов для импорта.")
        return

    error = 0
    err, result = parent.utm.get_nlists_list('network')
    if err:
        parent.stepChanged.emit(f'1|{result}')
        parent.error = 1
        return
    list_ip = {x['name']: x['id'] for x in result}

    # Добаляем списки IP-адресов без содержимого (пустые).
    for file_name in files_list:
        json_file = f"data_ug/Libraries/IPAddresses/{file_name}"
        err, ip_list = read_json_file(json_file, '1|Ошибка импорта списка IP-адресов!', '1|Нет списка IP-адресов для импорта.')
        if err:
            parent.stepChanged.emit(services_group)
            parent.error = 1
            return

        content = ip_list.pop('content')
        err, result1 = parent.utm.add_nlist(ip_list)
        if err == 1:
            parent.stepChanged.emit(f'1|{result1}')
            parent.stepChanged.emit(f'2|Ошибка! Список IP-адресов "{ip_list["name"]}" не импортирован.')
            error = 1
        elif err == 3:
            parent.stepChanged.emit(f'2|{result1}')
        else:
            list_ip[ip_list['name']] = result1
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
                        item['list'] = list_ip[item['list']]
                    except KeyError:
                        err1 = f'Ошибка! Нет IP-листа "{item["value"]}" в Библиотеке списков IP-адресов NGFW.'
                        err2 = f'Ошибка! Содержимое не добавлено в список IP-адресов "{ip_list["name"]}".'
                        parent.stepChanged.emit(f'2|{err1}')
                        parent.stepChanged.emit(f'2|{err2}')
                        error = 1
                        break
            try:
                named_list_id = list_ip[ip_list['name']]
            except KeyError:
                parent.stepChanged.emit(f'2|Ошибка! Нет IP-листа "{ip_list["name"]}" в Библиотеке списков IP-адресов NGFW.')
                parent.stepChanged.emit(f'2|Ошибка! Содержимое не добавлено в список IP-адресов "{ip_list["name"]}".')
                error = 1
                continue
            err2, result2 = parent.utm.add_nlist_items(named_list_id, content)
            if err2:
                parent.stepChanged.emit(f'2|{result2}')
                if err2 == 1:
                    error = 1
            else:
                parent.stepChanged.emit(f'2|Содержимое списка "{ip_list["name"]}" обновлено.')
        else:
            parent.stepChanged.emit(f'2|Список "{ip_list["name"]}" пуст.')

    if error:
        parent.error = 1
    out_message = '1|Списки IP-адресов импортированы в раздел "Библиотеки/IP-адреса".'
    parent.stepChanged.emit('1|Произошла ошибка при импорте списков IP-адресов!' if error else out_message)

def import_url_lists(parent):
    """Импортировать списки URL на UTM"""
    parent.stepChanged.emit('0|Импорт списков URL раздела "Библиотеки/Списки URL":')
        
    if not os.path.isdir('data_ug/Libraries/URLLists'):
        parent.stepChanged.emit('1|Нет списков URL для импорта.')
        return

    files_list = os.listdir('data_ug/Libraries/URLLists')
    if not files_list:
        parent.stepChanged.emit('1|Нет списков URL для импорта.')
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
        err, data = read_json_file(json_file, '1|Ошибка импорта списка URL!', '1|Нет списка URL для импорта.')
        if err:
            parent.stepChanged.emit(services_group)
            parent.error = 1
            return

        content = data.pop('content')
        err, result = parent.utm.add_nlist(data)
        if err == 1:
            parent.stepChanged.emit(f'1|{result}')
            parent.stepChanged.emit(f'2|Ошибка! Содержимое не добавлено в список URL "{data["name"]}".')
            error = 1
            continue
        elif err == 3:
            parent.stepChanged.emit(f'2|{result}')
        else:
            url_list[data['name']] = result
            parent.stepChanged.emit(f'2|Добавлен список URL: "{data["name"]}".')

        if content:
            err2, result2 = parent.utm.add_nlist_items(url_list[data['name']], content)
            if err2:
                parent.stepChanged.emit(f'2|{result2}')
                if err2 == 1:
                    error = 1
            else:
                parent.stepChanged.emit(f'2|Содержимое списка "{data["name"]}" обновлено. Added {result2} record.')
        else:
            parent.stepChanged.emit(f'2|Список "{data["name"]}" пуст.')

    if error:
        parent.error = 1
    out_message = '1|Списки URL импортированы в раздел "Библиотеки/Списки URL".'
    parent.stepChanged.emit('1|Произошла ошибка при импорте списков URL!' if error else out_message)

