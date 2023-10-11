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
# Версия 2.5
#

import os, sys, json
from PyQt6.QtCore import QThread, pyqtSignal


class ImportAll(QThread):
    """Импортируем всю конфигурацию на NGFW"""
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
        import_zones(self)
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
        import_url_categories(self)
        import_application_groups(self)
        import_firewall_rules(self)
        import_content_rules(self)
        self.stepChanged.emit('6|Импорт конфигурации прошёл с ошибками!' if self.error else '5|Импорт всей конфигурации прошёл успешно.')


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


class ImportZones(QThread):
    """Импортируем Зоны"""
    stepChanged = pyqtSignal(str)
    
    def __init__(self, utm):
        super().__init__()
        self.utm = utm
        self.error = 0

    def run(self):
        import_zones(self)


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


class ImportUrlCategories(QThread):
    """Импортировать группы категорий URL на UTM"""
    stepChanged = pyqtSignal(str)

    def __init__(self, utm):
        super().__init__()
        self.utm = utm
        self.error = 0

    def run(self):
        import_url_categories(self)


class ImportApplicationGroups(QThread):
    """Импортировать группы приложений на UTM"""
    stepChanged = pyqtSignal(str)

    def __init__(self, utm):
        super().__init__()
        self.utm = utm
        self.error = 0

    def run(self):
        import_application_groups(self)


class ImportFirewallRules(QThread):
    """Импортировать правила МЭ на UTM"""
    stepChanged = pyqtSignal(str)

    def __init__(self, utm):
        super().__init__()
        self.utm = utm
        self.error = 0

    def run(self):
        import_firewall_rules(self)


class ImportContentRules(QThread):
    """Импортировать правила КФ на UTM"""
    stepChanged = pyqtSignal(str)

    def __init__(self, utm):
        super().__init__()
        self.utm = utm
        self.error = 0

    def run(self):
        import_content_rules(self)


def import_gateways(parent):
    """Импортируем список шлюзов"""
    parent.stepChanged.emit('0|Импорт шлюзов в раздел "Сеть/Шлюзы".')
    json_file = "data_ug/Network/Gateways/config_gateways.json"
    err, data = read_json_file(json_file, '2|Ошибка импорта шлюзов!', '2|Нет шлюзов для импорта.')
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
                    parent.stepChanged.emit(f'1|{result} Шлюз "{item["name"]}"')
                    error = 1
                else:
                    parent.stepChanged.emit(f'2|Шлюз "{item["name"]}" уже существует - Updated!')
            else:
                err, result = parent.utm.add_gateway(item)
                if err:
                    parent.stepChanged.emit(f'1|{result}')
                    error = 1
                else:
                    gateways_list[item['name']] = result
                    parent.stepChanged.emit(f'2|Шлюз "{item["name"]}" добавлен.')
    if error:
        parent.error = 1
    parent.stepChanged.emit('6|Ошибка импорта шлюзов!' if error else '5|Шлюзы импортированы в раздел "Сеть/Шлюзы".')

def import_ui(parent):
    """Импортируем часовой пояс"""
    parent.stepChanged.emit('0|Импорт часового пояса в "Настройки/Настройки интерфейса/Часовой пояс".')
    json_file = "data_ug/UserGate/GeneralSettings/config_settings_ui.json"
    err, data = read_json_file(json_file, '2|Ошибка импорта часового пояса!', '2|Нет часового пояса для импорта.')
    if err:
        parent.stepChanged.emit(data)
        parent.error = 1
        return

    params = {'ui_timezone': 'Часовой пояс'}
    error = 0

    for key, value in data.items():
        err, result = parent.utm.set_settings_param(key, value)
        if err:
            parent.stepChanged.emit(f'1|{result}')
            error = 1
            parent.error = 1
        else:
            parent.stepChanged.emit(f'2|Параметр {params[key]} - Updated!')
    out_message = '5|Импортирован часовой пояс в раздел "Настройки/Настройки интерфейса/Часовой пояс".'
    parent.stepChanged.emit('6|Ошибка импорта часового пояса!' if error else out_message)

def import_dns_servers(parent):
    """Импортируем список системных DNS серверов"""
    parent.stepChanged.emit('0|Импорт системных DNS серверов в раздел "Сеть/DNS/Системные DNS-серверы".')
    json_file = "data_ug/Network/DNS/config_dns_servers.json"
    err, data = read_json_file(json_file, '2|Ошибка импорта серверов DNS!', '2|Нет серверов DNS для импорта.')
    if err:
        parent.stepChanged.emit(data)
        parent.error = 1
        return

    error = 0
    for item in data:
        err, result = parent.utm.add_dns_server(item)
        if err:
            parent.stepChanged.emit(f'{err}|{result}')
            if err == 1:
                error = 1
                parent.error = 1
        else:
            parent.stepChanged.emit(f'2|DNS сервер "{item["dns"]}" добавлен.')
    out_message = '5|Импортированы системные DNS серверов в раздел "Сеть/DNS/Системные DNS-серверы".'
    parent.stepChanged.emit('6|Ошибка импорта DNS-сервера!' if error else out_message)

def import_ntp_settings(parent):
    """Импортируем настройки NTP"""
    parent.stepChanged.emit('0|Импорт настроек NTP раздела "Настройки/Настройки времени сервера".')
    json_file = "data_ug/UserGate/GeneralSettings/config_ntp.json"
    err, data = read_json_file(json_file, '2|Ошибка импорта серверов NTP!', '2|Нет серверов NTP для импорта.')
    if err:
        parent.stepChanged.emit(data)
        parent.error = 1
        return

    error = 0
    err, result = parent.utm.add_ntp_config(data)
    if err:
        parent.stepChanged.emit(f'1|{result}')
        error = 1
        parent.error = 1
    else:
        parent.stepChanged.emit('2|Настройки NTP обновлены.')
    out_message = '5|Импортированы сервера NTP в раздел "Настройки/Настройки времени сервера".'
    parent.stepChanged.emit('6|Ошибка импорта настроек NTP!' if error else out_message)

def import_static_routes(parent):
    """Импортируем статические маршруты в Виртуальный маршрутизатор по умолчанию"""
    parent.stepChanged.emit('0|Импорт статических маршрутов в Виртуальный маршрутизатор по умолчанию.')

    json_file = "data_ug/Network/VRF/config_routers.json"
    err, data = read_json_file(json_file, '2|Ошибка импорта статических маршрутов!', '2|Нет статических маршрутов для импорта.')
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
    out_message = '5|Статические маршруты импортированы в Виртуальный маршрутизатор по умолчанию.'
    
    for item in data:
        if item['name'] in virt_routers:
            err, result = parent.utm.update_vrf(virt_routers[item['name']], item)
            if err:
                parent.stepChanged.emit(f'1|{result}')
                error = 1
        else:
            err, result = parent.utm.add_vrf(item)
            if err:
                parent.stepChanged.emit(f'1|{result}')
                error = 1
            else:
                out_message = f'5|Создан виртуальный маршрутизатор "{item["name"]}".'
    if not error:
        parent.stepChanged.emit('3|Добавленные маршруты не активны. Необходимо проверить маршрутизацию и включить их.')
    else:
        parent.error = 1
    parent.stepChanged.emit('6|Ошибка импорта статических маршрутов!' if error else out_message)

def import_zones(parent):
    """Импортируем зоны на NGFW, если они есть."""
    parent.stepChanged.emit('0|Импорт зон в раздел "Сеть/Зоны".')

    json_file = "data_ug/Network/Zones/config_zones.json"
    err, data = read_json_file(json_file, '2|Ошибка импорта зон!', '2|Нет зон для импорта.')
    if err:
        parent.stepChanged.emit('0|Импорт зон в раздел "Сеть/Зоны".')
        parent.stepChanged.emit(data)
        parent.error = 1
        return

    error = 0
    for item in data:
        err, result = parent.utm.add_zone(item)
        if err:
            error = 1 if err == 1 else 0
            parent.stepChanged.emit(f'1|{result}' if error else f'2|{result}')
        else:
            parent.stepChanged.emit(f'2|Зона "{item["name"]}" добавлена.')

    out_message = '5|Зоны импортированы в раздел "Сеть/Зоны".'
    parent.stepChanged.emit('6|Произошла ошибка при импорте зон.' if error else out_message)

def import_vlans(parent):
    """Импортируем интерфесы VLAN. Нельзя использовать интерфейсы Management и slave."""
    error = 0
    if not parent.new_vlans or isinstance(parent.new_vlans, str):
        parent.stepChanged.emit(parent.new_vlans if parent.new_vlans else '2|Импорт VLAN отменён пользователем.')
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
                parent.stepChanged.emit(f'1|Error: Интерфейс {item["name"]} не импортирован!')
                parent.stepChanged.emit(f'1|{result}')
                error = 1
                parent.error = 1
            else:
                parent.utm_vlans[item['vlan_id']] = item['name']
                parent.stepChanged.emit(f'2|Добавлен VLAN {item["vlan_id"]}, name: {item["name"]}, zone: {current_zone}, ip: {", ".join(item["ipv4"])}.')

    out_message = '5|Интерфейсы VLAN импортированы в раздел "Сеть/Интерфейсы".'
    parent.stepChanged.emit('6|Произошла ошибка создания интерфейса VLAN!' if error else out_message)

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
                parent.stepChanged.emit(f'1|{result}')
            else:
                parent.stepChanged.emit(f'2|   Правило МЭ "{item["name"]}" обновлено.')
        else:
            err, result = parent.utm.add_firewall_rule(item)
            if err:
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
                parent.stepChanged.emit(f'1|{result}')
            else:
                parent.stepChanged.emit(f'2|   Правило КФ "{item["name"]}" обновлено.')
        else:
            err, result = parent.utm.add_content_rule(item)
            if err:
                parent.stepChanged.emit(f'1|{result}')
            else:
                content_rules[item['name']] = result
                parent.stepChanged.emit(f'2|   Правило КФ "{item["name"]}" добавлено.')

    if error:
        parent.error = 1
    out_message = '5|Правила контентной фильтрации импортированы в раздел "Политики безопасности/Фильтрация контента".'
    parent.stepChanged.emit('6|Произошла ошибка при импорте правил контентной фильтрации!' if error else out_message)

def get_ips(parent, rule_ips, utm_ips, rule_name):
    """Получить UID-ы списков IP-адресов. Если список IP-адресов не существует на NGFW, то он пропускается."""
    new_rule_ips = []
    for ips in rule_ips:
        try:
            new_rule_ips.append(['list_id', utm_ips[ips[1]]])
        except KeyError as err:
            error = 1
            parent.stepChanged.emit(f'1|Error! Не найден список IP-адресов {ips} для правила {rule_name}.')
    return new_rule_ips

def get_zones(parent, zones, zones_list, rule_name):
    """Получить UID-ы зон. Если зона не существует на NGFW, то она пропускается."""
    new_zones = []
    for i, zone in enumerate(zones):
        try:
            new_zones.append(zones_list[zone])
        except KeyError as err:
            error = 1
            parent.stepChanged.emit(f'1|Error! Не найдена зона {zone} для правила {rule_name}.')
    return new_zones

def get_guids_users_and_groups(parent, item):
    """
    Получить GUID-ы групп и пользователей по их именам.
    Заменяет имена локальных и доменных пользователей и групп на GUID-ы.
    """
    if 'users' in item.keys() and item['users']:
        users = []
        for x in item['users']:
            if x[0] == 'user' and x[1]:
                i = x[1].partition("\\")
                if i[2]:
                    err, result = parent.utm.get_ldap_user_guid(i[0], i[2])
                    if err:
                        parent.stepChanged.emit(f'1|   {result}')
                    elif not result:
                        parent.stepChanged.emit(f'3|   Ошибка! Нет LDAP-коннектора для домена "{i[0]}"! Импортируйте и настройте LDAP-коннектор. Затем повторите импорт.')
                    else:
                        x[1] = result
                        users.append(x)

            elif x[0] == 'group' and x[1]:
                i = x[1].partition("\\")
                if i[2]:
                    err, result = parent.utm.get_ldap_group_guid(i[0], i[2])
                    if err:
                        parent.stepChanged.emit(f'1|   {result}')
                    elif not result:
                        parent.stepChanged.emit(f'3|   Ошибка! Нет LDAP-коннектора для домена "{i[0]}"! Импортируйте и настройте LDAP-коннектор. Затем повторите импорт.')
                    else:
                        x[1] = result
                        users.append(x)
            elif x[0] == 'special' and x[1]:
                users.append(x)
        item['users'] = users
    else:
        item['users'] = []

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

