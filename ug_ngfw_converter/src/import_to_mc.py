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
# Классы импорта разделов конфигурации в шаблон UserGate Management Center версии 7 и выше.
# Версия 2.7 01.11.2024
#

import os, sys, json, time
import copy
import common_func as func
from PyQt6.QtCore import QThread, pyqtSignal


class ImportAll(QThread):
    """Импортируем всю конфигурацию в шаблон MC"""
    stepChanged = pyqtSignal(str)
    
    def __init__(self, utm, config_path, all_points, template_id, templates, arguments, node_name):
        super().__init__()
        self.utm = utm

        self.config_path = config_path
        self.all_points = all_points

        self.template_id = template_id
        self.templates = templates      # Список шаблонов {template_id: template_name}
        self.node_name = node_name
        self.ngfw_ports = arguments['ngfw_ports']
        self.dhcp_settings = arguments['dhcp_settings']
        self.ngfw_vlans = arguments['ngfw_vlans']
        self.new_vlans = arguments['new_vlans']
        self.iface_settings = arguments['iface_settings']

        self.response_pages = {}
        self.client_certificate_profiles = {}
        self.notification_profiles = {}
        self.captive_profiles = {}
        self.icap_servers = {}
        self.reverseproxy_servers = {}
        self.error = 0

    def run(self):
        """Импортируем всё в пакетном режиме"""
        # Читаем бинарный файл библиотечных данных.
        err, self.mc_data = func.read_bin_file(self)
        if err:
            self.stepChanged.emit('iRED|Импорт конфигурации в шаблон Management Center прерван! Не удалось прочитать служебные данные.')
            return

        path_dict = {}
        try:
            for item in self.all_points:
                top_level_path = os.path.join(self.config_path, item['path'])
                for point in item['points']:
                    path_dict[point] = os.path.join(top_level_path, point)
            for key, value in import_funcs.items():
                if key in path_dict:
                    value(self, path_dict[key])
        except Exception as err:
            self.error = 1
            self.stepChanged.emit(f'RED|Ошибка функции "{value.__name__}":  {err}')

        # Сохраняем бинарный файл библиотечных данных после изменений во время работы.
        if func.write_bin_file(self, self.mc_data):
            self.stepChanged.emit('iRED|Импорт конфигурации в шаблон Management Center прерван! Не удалось записать служебные данные.')
            return

        if self.error:
            self.stepChanged.emit('iORANGE|Импорт конфигурации прошёл с ошибками!\n')
        else:
            self.stepChanged.emit('iGREEN|Импорт конфигурации завершён.\n')


class ImportSelectedPoints(QThread):
    """Импортируем выделенный раздел конфигурации на NGFW"""
    stepChanged = pyqtSignal(str)

    def __init__(self, utm, config_path, selected_path, selected_points, template_id, templates, arguments, node_name):
        super().__init__()
        self.utm = utm

        self.config_path = config_path
        self.selected_path = selected_path
        self.selected_points = selected_points
        self.template_id = template_id
        self.templates = templates      # Список шаблонов {template_id: template_name}
        self.node_name = node_name
        self.ngfw_ports = arguments['ngfw_ports']
        self.dhcp_settings = arguments['dhcp_settings']
        self.ngfw_vlans = arguments['ngfw_vlans']
        self.new_vlans = arguments['new_vlans']
        self.iface_settings = arguments['iface_settings']

        self.response_pages = {}
        self.client_certificate_profiles = {}
        self.notification_profiles = {}
        self.captive_profiles = {}
        self.icap_servers = {}
        self.reverseproxy_servers = {}
        self.error = 0


    def run(self):
        """Импортируем определённый раздел конфигурации"""
        # Читаем бинарный файл библиотечных данных.
        err, self.mc_data = func.read_bin_file(self)
        if err:
            self.stepChanged.emit('iRED|Импорт конфигурации в шаблон Management Center прерван! Не удалось прочитать служебные данные.')
            return

#        try:
        for point in self.selected_points:
            current_path = os.path.join(self.selected_path, point)
            if point in import_funcs:
                import_funcs[point](self, current_path)
            else:
                self.error = 1
                self.stepChanged.emit(f'RED|Не найдена функция для импорта {point}!')
#        except Exception as err:
#            self.error = 1
#            self.stepChanged.emit(f'RED|Ошибка функции "{import_funcs[point].__name__}":  {err}')

        # Сохраняем бинарный файл библиотечных данных после изменений во время работы.
        if func.write_bin_file(self, self.mc_data):
            self.stepChanged.emit('iRED|Импорт конфигурации в шаблон Management Center прерван! Не удалось записать служебные данные.')
            return

        if self.error:
            self.stepChanged.emit('iORANGE|Импорт конфигурации прошёл с ошибками!\n')
        else:
            self.stepChanged.emit('iGREEN|Импорт конфигурации завершён.\n')


#-------------------------------------------- Библиотека ------------------------------------------------------------
def import_morphology_lists(parent, path):
    """Импортируем списки морфологии"""
    json_file = os.path.join(path, 'config_morphology_lists.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт списков морфологии в раздел "Библиотеки/Морфология".')
    error = 0

    err, result = parent.utm.get_template_nlists_list(parent.template_id, 'morphology')
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте списков морфологии.')
        parent.error = 1
        return
    morphology_list = {x['name']: x['id'] for x in result}

    for item in data:
        item['name'] = func.get_restricted_name(item['name'])
        content = item.pop('content')
        item.pop('last_update', None)

        if item['name'] in morphology_list:
            parent.stepChanged.emit(f'uGRAY|    Список морфологии "{item["name"]}" уже существует.')
            err, result = parent.utm.update_template_nlist(parent.template_id, morphology_list[item['name']], item)
            if err == 1:
                error = 1
                parent.stepChanged.emit(f'RED|       {result}  [Список морфологии "{item["name"]}"]')
                continue
            elif err == 3:
                parent.stepChanged.emit(f'GRAY|       {result}')
            else:
                parent.stepChanged.emit(f'uGRAY|       Список морфологии "{item["name"]}" обновлён.')
        else:
            err, result = parent.utm.add_template_nlist(parent.template_id, item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Список морфологии "{item["name"]}" не импортирован]')
                continue
            else:
                morphology_list[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Список морфологии "{item["name"]}" импортирован.')

        if item['list_type_update'] == 'static':
            if content:
#                err2, result2 = parent.utm.add_template_nlist_items(parent.template_id, morphology_list[item['name']], content)
#                print(err2, result2)
#                print(parent.template_id, morphology_list[item['name']])

                for value in content:
                    err2, result2 = parent.utm.add_template_nlist_item(parent.template_id, morphology_list[item['name']], value)
                    if err2 == 3:
                        parent.stepChanged.emit(f'uGRAY|       {result2}')
                    elif err2 == 1:
                        error = 1
                        parent.stepChanged.emit(f'RED|       {result2}  [Список морфологии "{item["name"]}"]')
                    else:
                        parent.stepChanged.emit(f'BLACK|       Добавлено "{value["value"]}".')
            else:
                parent.stepChanged.emit(f'GRAY|       Содержимое списка морфологии "{item["name"]}" не обновлено так как он пуст.')
        else:
            parent.stepChanged.emit(f'GRAY|       Содержимое списка морфологии "{item["name"]}" не обновлено так как он обновляется удалённо.')

    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте списков морфологии.')
    else:
        parent.stepChanged.emit('GREEN|    Списки морфологии импортированны в раздел "Библиотеки/Морфология".')


def import_services_list(parent, path):
    """Импортируем список сервисов раздела библиотеки"""
    json_file = os.path.join(path, 'config_services_list.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт списка сервисов в раздел "Библиотеки/Сервисы"')
    error = 0

    for item in data:
        item['name'] = func.get_restricted_name(item['name'])
        if item['name'] in parent.mc_data['services']:
            parent.stepChanged.emit(f'uGRAY|    Сервис "{item["name"]}" уже существует.')
        else:
            err, result = parent.utm.add_template_service(parent.template_id, item)
            if err == 3:
                parent.stepChanged.emit(f'GRAY|    {result}')
            elif err == 1:
                error = 1
                parent.stepChanged.emit(f'RED|    {result} [Сервис "{item["name"]}"]')
            else:
                parent.mc_data['services'][item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Сервис "{item["name"]}" добавлен.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при добавлении сервисов.')
    else:
        parent.stepChanged.emit('GREEN|    Список сервисов импортирован в раздел "Библиотеки/Сервисы"')


def import_services_groups(parent, path):
    """Импортируем группы сервисов в раздел Библиотеки/Группы сервисов"""
    json_file = os.path.join(path, 'config_services_groups_list.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт групп сервисов раздела "Библиотеки/Группы сервисов".')
    out_message = 'GREEN|    Группы сервисов импортированы в раздел "Библиотеки/Группы сервисов".'
    error = 0
    
    for item in data:
        content = item.pop('content')
        item.pop('last_update', None)
        item['name'] = func.get_restricted_name(item['name'])
        mc_servicegroups = parent.mc_data['service_groups']

        if item['name'] in mc_servicegroups:
            parent.stepChanged.emit(f'uGRAY|    Группа сервисов "{item["name"]}" уже существует.')
            err, result = parent.utm.update_template_nlist(parent.template_id, mc_servicegroups[item['name']], item)
            if err == 1:
                error = 1
                parent.stepChanged.emit(f'RED|       {result} [Группа сервисов "{item["name"]}"]')
                continue
            elif err == 3:
                parent.stepChanged.emit(f'GRAY|       {result}.')
            else:
                parent.stepChanged.emit(f'uGRAY|       Группа сервисов "{item["name"]}" обновлена.')
        else:
            err, result = parent.utm.add_template_nlist(parent.template_id, item)
            if err == 1:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Группа сервисов "{item["name"]}" не импортирована]')
                continue
            elif err == 3:
                parent.stepChanged.emit(f'GRAY|    {result}.')
            else:
                mc_servicegroups[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Группа сервисов "{item["name"]}" импортирована.')

        if content:
            new_content = []
            for service in content:
                try:
                    service['value'] = parent.mc_data['services'][service['name']]
                    new_content.append(service)
                except KeyError as err:
                    parent.stepChanged.emit(f'bRED|      Error: Не найден сервис "{err}". Загрузите сервисы в шаблон и повторите попытку.')

            err2, result2 = parent.utm.add_template_nlist_items(parent.template_id, mc_servicegroups[item['name']], new_content)
            if err2:
                error = 1
                parent.stepChanged.emit(f'RED|       {result2} [Группа сервисов "{item["name"]}"]')
            else:
                parent.stepChanged.emit(f'BLACK|       Содержимое группы сервисов "{item["name"]}" обновлено.')
        else:
            parent.stepChanged.emit(f'GRAY|       Нет содержимого в группе сервисов "{item["name"]}".')

    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте групп сервисов.')
    else:
        parent.stepChanged.emit('GREEN|    Группы сервисов импортированы в раздел "Библиотеки/Группы сервисов".')


def import_ip_lists(parent, path):
    """Импортируем списки IP адресов"""
    parent.stepChanged.emit('BLUE|Импорт списков IP-адресов раздела "Библиотеки/IP-адреса".')

    if not os.path.isdir(path):
        parent.stepChanged.emit('GRAY|    Нет списков IP-адресов для импорта.')
        return
    files_list = os.listdir(path)
    if not files_list:
        parent.stepChanged.emit('GRAY|    Нет списков IP-адресов для импорта.')
        return

    error = 0
    # Импортируем все списки IP-адресов без содержимого (пустые).
    parent.stepChanged.emit('LBLUE|    Импортируем списки IP-адресов без содержимого.')
    for file_name in files_list:
        json_file = os.path.join(path, file_name)
        err, data = func.read_json_file(parent, json_file)
        if err:
            continue

        data['name'] = func.get_restricted_name(data['name'])
        content = data.pop('content')
        data.pop('last_update', None)
        err, result = parent.utm.add_template_nlist(parent.template_id, data)
        if err == 1:
            error = 1
            parent.stepChanged.emit(f'RED|    {result}  [Список IP-адресов "{data["name"]}" не импортирована]')
        elif err == 3:
            parent.stepChanged.emit(f'GRAY|    {result}.')
        else:
            parent.mc_data['ip_lists'][data['name']] = result
            parent.stepChanged.emit(f'BLACK|    Список IP-адресов "{data["name"]}" импортирован.')

    # Добавляем содержимое в уже добавленные списки IP-адресов.
    parent.stepChanged.emit('LBLUE|    Импортируем содержимое списков IP-адресов.')
    for file_name in files_list:
        json_file = os.path.join(path, file_name)
        err, data = func.read_json_file(parent, json_file)
        if err:
            continue

        data['name'] = func.get_restricted_name(data['name'])
        try:
            list_id = parent.mc_data['ip_lists'][data['name']]
        except KeyError:
            parent.stepChanged.emit(f'RED|   Error: Нет IP-листа "{data["name"]}" в списках IP-адресов шаблона МС.')
            parent.stepChanged.emit(f'RED|   Error: Содержимое не добавлено в список IP-адресов "{data["name"]}".')
            error = 1
            continue
        if data['content']:
            new_content = []
            for item in data['content']:
                if 'list' in item:
                    try:
                        item['list'] = parent.mc_data['ip_lists'][item['list']]
                        new_content.append(item)
                    except KeyError:
                        parent.stepChanged.emit(f'RED|   Error: Нет IP-листа "{item["list"]}" в списках IP-адресов шаблона МС.')
                        parent.stepChanged.emit(f'RED|   Error: Содержимое "{item["list"]}" не добавлено в список IP-адресов "{data["name"]}".')
                        error = 1
                else:
                    new_content.append(item)

            err, result = parent.utm.add_template_nlist_items(parent.template_id, list_id, new_content)
            if err == 1:
                error = 1
                parent.stepChanged.emit(f'RED|    {result} [Список IP-адресов "{data["name"]}"]')
            else:
                parent.stepChanged.emit(f'BLACK|    Содержимое списка IP-адресов "{data["name"]}" обновлено.')
        else:
            parent.stepChanged.emit(f'GRAY|    Список "{data["name"]}" пуст.')

    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте списков IP-адресов.')
    else:
        parent.stepChanged.emit('GREEN|    Списки IP-адресов импортированы в раздел "Библиотеки/IP-адреса".')


def import_useragent_lists(parent, path):
    """Импортируем списки Useragent браузеров"""
    json_file = os.path.join(path, 'config_useragents_list.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт списка "Useragent браузеров" в раздел "Библиотеки/Useragent браузеров".')
    error = 0

    err, result = parent.utm.get_template_nlists_list(parent.template_id, 'useragent')
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте списков Useragent браузеров.')
        parent.error = 1
        return
    useragent_list = {x['name']: x['id'] for x in result}

    for item in data:
        content = item.pop('content')
        item.pop('last_update', None)
        item['name'] = func.get_restricted_name(item['name'])

        if item['name'] in useragent_list:
            parent.stepChanged.emit(f'uGRAY|    Список Useragent "{item["name"]}" уже существует.')
            err, result = parent.utm.update_template_nlist(parent.template_id, useragent_list[item['name']], item)
            if err == 1:
                error = 1
                parent.stepChanged.emit(f'RED|       {result}  [Список Useragent {item["name"]}]')
                continue
            elif err == 3:
                parent.stepChanged.emit(f'GRAY|    {result}')
            else:
                parent.stepChanged.emit(f'uGRAY|       Список Useragent "{item["name"]}" обновлён.')
        else:
            err, result = parent.utm.add_template_nlist(parent.template_id, item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Список Useragent "{item["name"]}" не импортирован]')
                continue
            else:
                useragent_list[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Список Useragent "{item["name"]}" импортирован.')

        if content:
            err2, result2 = parent.utm.add_template_nlist_items(parent.template_id, useragent_list[item['name']], content)
            if err2 == 3:
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
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте списков Useragent браузеров.')
    else:
        parent.stepChanged.emit('GREEN|    Список "Useragent браузеров" импортирован в раздел "Библиотеки/Useragent браузеров".')


def import_mime_lists(parent, path):
    """Импортируем списки Типов контента"""
    json_file = os.path.join(path, 'config_mime_types.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт списка "Типы контента" в раздел "Библиотеки/Типы контента".')
    error = 0

    for item in data:
        content = item.pop('content')
        item.pop('last_update', None)
        item['name'] = func.get_restricted_name(item['name'])

        if item['name'] in parent.mc_data['mime']:
            parent.stepChanged.emit(f'GRAY|    Список Типов контента "{item["name"]}" уже существует.')
            err, result = parent.utm.update_template_nlist(parent.template_id, parent.mc_data['mime'][item['name']], item)
            if err == 1:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Список Типов контента: {item["name"]}]')
                continue
            elif err == 3:
                parent.stepChanged.emit(f'GRAY|    {result}')
            else:
                parent.stepChanged.emit(f'BLACK|    Список Типов контента "{item["name"]}" updated.')
        else:
            err, result = parent.utm.add_template_nlist(parent.template_id, item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Список Типов контента: "{item["name"]}"]')
                continue
            else:
                parent.mc_data['mime'][item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Список Типов контента "{item["name"]}" импортирован.')

        if content:
            err2, result2 = parent.utm.add_template_nlist_items(parent.template_id, parent.mc_data['mime'][item['name']], content)
            if err2 == 3:
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
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте списков "Типы контента".')
    else:
        parent.stepChanged.emit('GREEN|    Списки "Типы контента" импортированы в раздел "Библиотеки/Типы контента".')


def import_url_lists(parent, path):
    """Импортировать списки URL на UTM"""
    parent.stepChanged.emit('BLUE|Импорт списков URL раздела "Библиотеки/Списки URL".')
        
    if not os.path.isdir(path):
        parent.stepChanged.emit('GRAY|    Нет списков URL для импорта.')
        return
    files_list = os.listdir(path)
    if not files_list:
        parent.stepChanged.emit('GRAY|    Нет списков URL для импорта.')
        return

    error = 0
    # Импортируем все списки URL без содержимого (пустые).
    parent.stepChanged.emit('LBLUE|    Импортируем списки URL без содержимого.')
    for file_name in files_list:
        json_file = os.path.join(path, file_name)
        err, data = func.read_json_file(parent, json_file)
        if err:
            continue

        data['name'] = func.get_restricted_name(data['name'])
        content = data.pop('content')
        data.pop('last_update', None)
        if not data['attributes'] or 'threat_level' in data['attributes']:
            data['attributes'] = {'list_compile_type': 'case_insensitive'}

        err, result = parent.utm.add_template_nlist(parent.template_id, data)
        if err == 1:
            error = 1
            parent.stepChanged.emit(f'RED|    {result}  [Список URL "{data["name"]}" не импортирован]')
        elif err == 3:
            parent.stepChanged.emit(f'GRAY|    {result}')
        else:
            parent.mc_data['url_lists'][data['name']] = result
            parent.stepChanged.emit(f'BLACK|    Список URL "{data["name"]}" импортирован.')

    # Импортируем содержимое в уже добавленные списки URL.
    parent.stepChanged.emit('LBLUE|    Импортируем содержимое списков URL.')
    for file_name in files_list:
        json_file = os.path.join(path, file_name)
        err, data = func.read_json_file(parent, json_file)
        if err:
            continue

        data['name'] = func.get_restricted_name(data['name'])
        try:
            list_id = parent.mc_data['url_lists'][data['name']]
        except KeyError:
            parent.stepChanged.emit(f'RED|   Error: Нет листа URL "{data["name"]}" в списках URL шаблона МС.')
            parent.stepChanged.emit(f'RED|   Error: Содержимое не добавлено в список URL "{data["name"]}".')
            error = 1
            continue
        if data['content']:
            err, result = parent.utm.add_template_nlist_items(parent.template_id, list_id, data['content'])
            if err == 1:
                error = 1
                parent.stepChanged.emit(f'RED|    {result} [Список URL: "{data["name"]}"]')
            else:
                parent.stepChanged.emit(f'BLACK|    Содержимое списка URL "{data["name"]}" обновлено.')
        else:
            parent.stepChanged.emit(f'GRAY|   Список URL "{data["name"]}" пуст.')

    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте списков URL.')
    else:
        parent.stepChanged.emit('GREEN|    Списки URL импортированы в раздел "Библиотеки/Списки URL".')


def import_time_restricted_lists(parent, path):
    """Импортируем содержимое календарей"""
    json_file = os.path.join(path, 'config_calendars.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт списка "Календари" в раздел "Библиотеки/Календари".')
    error = 0

    for item in data:
        content = item.pop('content')
        item.pop('last_update', None)
        item['name'] = func.get_restricted_name(item['name'])
        err, result = parent.utm.add_template_nlist(parent.template_id, item)
        if err == 1:
            error = 1
            parent.stepChanged.emit(f'RED|    {result}  [Календарь "{item["name"]}" не импортирован]')
            continue
        elif err == 3:
            parent.stepChanged.emit(f'GRAY|    {result}')
        else:
            parent.mc_data['calendars'][item['name']] = result
            parent.stepChanged.emit(f'BLACK|    Календарь "{item["name"]}" импортирован.')

        if content:
            for value in content:
                err2, result2 = parent.utm.add_template_nlist_item(parent.template_id, parent.mc_data['calendars'][item['name']], value)
                if err2 == 1:
                    error = 1
                    parent.stepChanged.emit(f'RED|       {result2}  [Календарь: "{item["name"]}"]')
                elif err2 == 3:
                    parent.stepChanged.emit(f'GRAY|       Элемент "{value["name"]}" уже существует в календаре "{item["name"]}".')
                else:
                    parent.stepChanged.emit(f'BLACK|       Элемент "{value["name"]}" календаря "{item["name"]}" добавлен.')
        else:
            parent.stepChanged.emit(f'GRAY|       Календарь "{item["name"]}" пуст.')

    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте списка "Календари".')
    else:
        parent.stepChanged.emit('GREEN|    Список "Календари" импортирован в раздел "Библиотеки/Календари".')


def import_shaper_list(parent, path):
    """Импортируем список Полос пропускания раздела библиотеки"""
    json_file = os.path.join(path, 'config_shaper_list.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт списка "Полосы пропускания" в раздел "Библиотеки/Полосы пропускания".')
    error = 0

    err, result = parent.utm.get_template_shapers_list(parent.template_id)
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте списка "Полосы пропускания".')
        parent.error = 1
        return
    shaper_list = {x['name']: x['id'] for x in result}

    for item in data:
        item['name'] = func.get_restricted_name(item['name'])
        if item['name'] in shaper_list:
            parent.stepChanged.emit(f'GRAY|    Полоса пропускания "{item["name"]}" уже существует.')
            err, result = parent.utm.update_template_shaper(parent.template_id, shaper_list[item['name']], item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Полоса пропускания: {item["name"]}]')
            else:
                parent.stepChanged.emit(f'BLACK|    Полоса пропускания "{item["name"]}" updated.')
        else:
            err, result = parent.utm.add_template_shaper(parent.template_id, item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Полоса пропускания: "{item["name"]}" не импортирована]')
            elif err == 3:
                parent.stepChanged.emit(f'GRAY|    {result}')
            else:
                shaper_list[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Полоса пропускания "{item["name"]}" импортирована.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте списка "Полосы пропускания".')
    else:
        parent.stepChanged.emit('GREEN|    Список "Полосы пропускания" импортирован в раздел "Библиотеки/Полосы пропускания".')


def import_templates_list(parent, path):
    """
    Импортируем список шаблонов страниц.
    После создания шаблона, он инициализируется страницей HTML по умолчанию для данного типа шаблона.
    """
    json_file = os.path.join(path, 'config_templates_list.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт списка шаблонов страниц в раздел "Библиотеки/Шаблоны страниц".')
    error = 0
    html_files = os.listdir(path)

    if not parent.response_pages:
        if get_response_pages(parent):    # Устанавливаем атрибут parent.response_pages
            parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте списка шаблонов страниц.')
            return

    for item in data:
        if item['name'] in parent.response_pages:
            parent.stepChanged.emit(f'GRAY|    Шаблон страницы "{item["name"]}" уже существует.')
            err, result = parent.utm.update_template_responsepage(parent.template_id, parent.response_pages[item['name']], item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Шаблон страницы: {item["name"]}]')
            else:
                parent.stepChanged.emit(f'BLACK|    Шаблон страницы "{item["name"]}" updated.')
        else:
            err, result = parent.utm.add_template_responsepage(parent.template_id, item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Шаблон страницы: "{item["name"]}" не импортирован]')
                continue
            else:
                parent.response_pages[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Шаблон страницы "{item["name"]}" импортирован.')

        if f"{item['name']}.html" in html_files:
            upload_file = os.path.join(path, f"{item['name']}.html")
            err, result = parent.utm.get_realm_upload_session(upload_file)
            if err:
                parent.stepChanged.emit(f'RED|       {result}')
                parent.error = 1
            elif result['success']:
                err2, result2 = parent.utm.set_template_responsepage_data(parent.template_id, parent.response_pages[item['name']], result['storage_file_uid'])
                if err2:
                    parent.stepChanged.emit(f'RED|       {result2} [Страница "{item["name"]}.html" не импортирована]')
                    parent.error = 1
                else:
                    parent.stepChanged.emit(f'BLACK|       Страница "{item["name"]}.html" импортирована.')
            else:
                parent.error = 1
                parent.stepChanged.emit(f'ORANGE|       Error: Не удалось импортировать страницу "{item["name"]}.html".')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте списка шаблонов страниц.')
    else:
        parent.stepChanged.emit('GREEN|    Список шаблонов страниц импортирован в раздел "Библиотеки/Шаблоны страниц".')


def import_url_categories(parent, path):
    """Импортировать группы URL категорий с содержимым"""
    json_file = os.path.join(path, 'config_url_categories.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт групп URL категорий раздела "Библиотеки/Категории URL".')
    error = 0

    for item in data:
#        if item['name'] not in ['Parental Control', 'Productivity', 'Safe categories', 'Threats',
#                                'Recommended for morphology checking', 'Recommended for virus check']:
        content = item.pop('content')
        item.pop('last_update', None)
        item.pop('guid', None)
        item['name'] = func.get_restricted_name(item['name'])
        err, result = parent.utm.add_template_nlist(parent.template_id, item)
        if err == 1:
            error = 1
            parent.stepChanged.emit(f'RED|    {result}  [Группа URL категорий "{item["name"]}" не импортирована]')
            continue
        elif err == 3:
            parent.stepChanged.emit(f'GRAY|    {result}')
        else:
            parent.mc_data['url_categorygroups'][item['name']] = result
            parent.stepChanged.emit(f'BLACK|    Группа URL категорий "{item["name"]}" импортирована.')

        for category in content:
            err2, result2 = parent.utm.add_template_nlist_item(parent.template_id, parent.mc_data['url_categorygroups'][item['name']], category)
            if err2 == 3:
                parent.stepChanged.emit(f'GRAY|       Категория "{category["name"]}" уже существует.')
            elif err2 == 1:
                parent.stepChanged.emit(f'RED|       {result2}  [Группа категорий "{item["name"]}"]')
                error = 1
            else:
                parent.stepChanged.emit(f'BLACK|       Добавлена категория "{category["name"]}".')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте групп URL категорий.')
    else:
        parent.stepChanged.emit('GREEN|    Группы URL категорий импортированы в раздел "Библиотеки/Категории URL".')


def import_custom_url_category(parent, path):
    """Импортируем изменённые категории URL"""
    json_file = os.path.join(path, 'custom_url_categories.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт категорий URL раздела "Библиотеки/Изменённые категории URL".')
    error = 0

    err, result = parent.utm.get_template_custom_url_list(parent.template_id)
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте изменённых категорий URL.')
        parent.error = 1
        return
    custom_url = {x['name']: x['id'] for x in result}

    for item in data:
        try:
            item['categories'] = [parent.mc_data['url_categories'][x] for x in item['categories']]
        except KeyError as keyerr:
            parent.stepChanged.emit(f'RED|    Error: В правиле "{item["name"]}" обнаружена несуществующая категория {keyerr}. Правило  не добавлено.')
            continue
        if item['name'] in custom_url:
            parent.stepChanged.emit(f'GRAY|    URL категория "{item["name"]}" уже существует.')
            err, result = parent.utm.update_template_custom_url(parent.template_id, custom_url[item['name']], item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [URL категория: {item["name"]}]')
            else:
                parent.stepChanged.emit(f'BLACK|    URL категория "{item["name"]}" updated.')
        else:
            err, result = parent.utm.add_template_custom_url(parent.template_id, item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [URL категория: "{item["name"]}" не импортирована]')
            else:
                custom_url[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Изменённая категория URL "{item["name"]}" импортирована.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте изменённых категорий URL.')
    else:
        parent.stepChanged.emit('GREEN|    Изменённые категории URL категорий импортированы в раздел "Библиотеки/Изменённые категории URL".')


def import_application_signature(parent, path):
    """Импортируем список Приложения"""
    json_file = os.path.join(path, 'config_applications.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт пользовательских приложений в раздел "Библиотеки/Приложения".')
    error = 0

    err, result = parent.utm.get_template_app_signatures(parent.template_id, query={'query': 'owner = You'})
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте пользовательских приложений.')
        parent.error = 1
        return
    apps = {x['name']: x['id'] for x in result}

    for item in data:
        item.pop('signature_id', None)

        new_l7categories = []
        for category in item['l7categories']:
            try:
                new_l7categories.append(parent.mc_data['l7_categories'][category])
            except KeyError as err:
                parent.stepChanged.emit(f'RED|    Error: Категория "{err}" не существует [Правило "{item["name"]}"]. Категория не добавлена.')
                error = 1
        item['l7categories'] = new_l7categories

        if item['name'] in apps:
            parent.stepChanged.emit(f'GRAY|    Приложение "{item["name"]}" уже существует.')
            err, result = parent.utm.update_template_app_signature(parent.template_id, apps[item['name']], item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Приложение: {item["name"]}]')
            else:
                parent.stepChanged.emit(f'BLACK|    Приложение "{item["name"]}" updated.')
        else:
            err, result = parent.utm.add_template_app_signature(parent.template_id, item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Приложение: "{item["name"]}" не импортировано]')
            else:
                apps[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Приложение "{item["name"]}" импортировано.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте пользовательских приложений.')
    else:
        parent.stepChanged.emit('GREEN|    Пользовательские приложения импортированы в раздел "Библиотеки/Приложения".')


def import_app_profiles(parent, path):
    """Импортируем профили приложений"""
    json_file = os.path.join(path, 'config_app_profiles.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт профилей приложений раздела "Библиотеки/Профили приложений".')
    error = 0

    err, result = parent.utm.get_template_l7_profiles_list(parent.template_id)
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей приложений.')
        parent.error = 1
        return
    l7profiles = {x['name']: x['id'] for x in result}

    err, result = parent.utm.get_template_app_signatures(parent.template_id)
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей приложений.')
        parent.error = 1
        return
    id_l7apps = {x['name']: x['id'] for x in result}

    for item in data:
        new_overrides = []
        for app in item['overrides']:
            try:
                app['id'] = id_l7apps[app['id']]
                new_overrides.append(app)
            except KeyError as err:
                parent.stepChanged.emit(f'RED|    Error: Не найдено приложение "{err}" [Правило: "{item["name"]}"]. Приложение не добавлено.')
                error = 1
        item['overrides'] = new_overrides

        if item['name'] in l7profiles:
            parent.stepChanged.emit(f'GRAY|    Профиль приложений "{item["name"]}" уже существует.')
            err, result = parent.utm.update_template_l7_profile(parent.template_id, l7profiles[item['name']], item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|       {result}  [Профиль приложений: {item["name"]}]')
            else:
                parent.stepChanged.emit(f'BLACK|       Профиль приложений "{item["name"]}" updated.')
        else:
            err, result = parent.utm.add_template_l7_profile(parent.template_id, item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Профиль приложений: "{item["name"]}" не импортирован]')
            else:
                l7profiles[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Профиль приложений "{item["name"]}" импортирован.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей приложений.')
    else:
        parent.stepChanged.emit('GREEN|    Профили приложений импортированы в раздел "Библиотеки/Профили приложений".')


def import_application_groups(parent, path):
    """Импортировать группы приложений на UTM"""
    json_file = os.path.join(path, 'config_application_groups.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт групп приложений в раздел "Библиотеки/Группы приложений".')

    err, result = parent.utm.get_template_app_signatures(parent.template_id)
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте групп приложений.')
        parent.error = 1
        return
    signature_l7apps = {x['name']: x['signature_id'] for x in result}

    error = 0
    for item in data:
        item['name'] = func.get_restricted_name(item['name'])
        content = item.pop('content')
        item.pop('last_update', None)
        err, result = parent.utm.add_template_nlist(parent.template_id, item)
        if err == 1:
            error = 1
            parent.stepChanged.emit(f'RED|    {result}  [Группа приложений "{item["name"]}" не импортирована]')
            continue
        elif err == 3:
            parent.stepChanged.emit(f'GRAY|    {result}')
        else:
            parent.mc_data['application_groups'][item['name']] = result
            parent.stepChanged.emit(f'BLACK|    Группа приложений "{item["name"]}" импортирована.')

        for app in content:
            if 'name' not in app:   # Так бывает при некорректном добавлении приложения через API
                parent.stepChanged.emit(f'bRED|       Приложение "{app}" не добавлено, так как не содержит имя. [Группа приложений "{item["name"]}"]')
                error = 1
                continue
            try:
                app['value'] = signature_l7apps[app['name']]
            except KeyError as err:
                parent.stepChanged.emit(f'RED|       Error: Приложение "{app["name"]}" не импортировано. Такого приложения нет на UG MC. [Группа приложений "{item["name"]}"]')
                error = 1
                continue

            err2, result2 = parent.utm.add_template_nlist_item(parent.template_id, parent.mc_data['application_groups'][item['name']], app) 
            if err2 == 1:
                error = 1
                parent.stepChanged.emit(f'RED|       {result2}  [Группа приложений "{item["name"]}"]')
            elif err2 == 3:
                parent.stepChanged.emit(f'GRAY|       Приложение "{app["name"]}" уже существует в группе приложений "{item["name"]}".')
            else:
                parent.stepChanged.emit(f'BLACK|       Приложение "{app["name"]}" импортировано.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте групп приложений.')
    else:
        parent.stepChanged.emit('GREEN|    Группы приложений импортированы в раздел "Библиотеки/Группы приложений".')


def import_email_groups(parent, path):
    """Импортируем группы почтовых адресов."""
    json_file = os.path.join(path, 'config_email_groups.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт групп почтовых адресов раздела "Библиотеки/Почтовые адреса".')
    error = 0

    err, result = parent.utm.get_template_nlists_list(parent.template_id, 'emailgroup')
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте групп почтовых адресов.')
        parent.error = 1
        return
    emailgroups = {x['name']: x['id'] for x in result}

    for item in data:
        item['name'] = func.get_restricted_name(item['name'])
        content = item.pop('content')
        item.pop('last_update', None)

        err, result = parent.utm.add_template_nlist(parent.template_id, item)
        if err == 1:
            error = 1
            parent.stepChanged.emit(f'RED|    {result}  [Группа почтовых адресов "{item["name"]}" не импортирована]')
            continue
        elif err == 3:
            parent.stepChanged.emit(f'GRAY|    {result}')
        else:
            emailgroups[item['name']] = result
            parent.stepChanged.emit(f'BLACK|    Группа почтовых адресов "{item["name"]}" импортирована.')

        if content:
            for email in content:
                err2, result2 = parent.utm.add_template_nlist_item(parent.template_id, emailgroups[item['name']], email)
                if err2 == 1:
                    error = 1
                    parent.stepChanged.emit(f'RED|       {result2} [Группа почтовых адресов: "{item["name"]}"]')
                elif err2 == 3:
                    parent.stepChanged.emit(f'GRAY|       Адрес "{email["value"]}" уже существует.')
                else:
                    parent.stepChanged.emit(f'BLACK|       Адрес "{email["value"]}" импортирован.')
        else:
            parent.stepChanged.emit(f'GRAY|       Нет содержимого в группе почтовых адресов "{item["name"]}".')

    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте групп почтовых адресов.')
    else:
        parent.stepChanged.emit('GREEN|    Группы почтовых адресов импортированы в раздел "Библиотеки/Почтовые адреса".')


def import_phone_groups(parent, path):
    """Импортируем группы телефонных номеров."""
    json_file = os.path.join(path, 'config_phone_groups.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт групп телефонных номеров раздела "Библиотеки/Номера телефонов".')
    error = 0

    err, result = parent.utm.get_template_nlists_list(parent.template_id, 'phonegroup')
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте групп телефонных номеров.')
        parent.error = 1
        return
    phonegroups = {x['name']: x['id'] for x in result}

    for item in data:
        item['name'] = func.get_restricted_name(item['name'])
        content = item.pop('content')
        item.pop('last_update', None)

        err, result = parent.utm.add_template_nlist(parent.template_id, item)
        if err == 1:
            error = 1
            parent.stepChanged.emit(f'RED|    {result}  [Группа телефонных номеров "{item["name"]}" не импортирована]')
            continue
        elif err == 3:
            parent.stepChanged.emit(f'GRAY|    {result}')
        else:
            phonegroups[item['name']] = result
            parent.stepChanged.emit(f'BLACK|    Группа телефонных номеров "{item["name"]}" импортирована.')

        if content:
            for number in content:
                err2, result2 = parent.utm.add_template_nlist_item(parent.template_id, phonegroups[item['name']], number)
                if err2 == 1:
                    error = 1
                    parent.stepChanged.emit(f'RED|       {result2} [Группа телефонных номеров: "{item["name"]}"]')
                elif err2 == 3:
                    parent.stepChanged.emit(f'GRAY|       Номер "{number["value"]}" уже существует.')
                else:
                    parent.stepChanged.emit(f'BLACK|       Номер "{number["value"]}" импортирован.')
        else:
            parent.stepChanged.emit(f'GRAY|       Нет содержимого в группе телефонных номеров "{item["name"]}".')

    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте групп телефонных номеров.')
    else:
        parent.stepChanged.emit('GREEN|    Группы телефонных номеров импортированы в раздел "Библиотеки/Номера телефонов".')


def import_custom_idps_signature(parent, path):
    """Импортируем пользовательские сигнатуры СОВ."""
    json_file = os.path.join(path, 'custom_idps_signatures.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт пользовательских сигнатур СОВ в раздел "Библиотеки/Сигнатуры СОВ".')
    error = 0

    err, result = parent.utm.get_template_idps_signatures_list(parent.template_id, query={'query': 'owner = You'})
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте пользовательских сигнатур СОВ.')
        parent.error = 1
        return
    signatures = {x['msg']: x['id'] for x in result}

    for item in data:
        if item['msg'] in signatures:
            parent.stepChanged.emit(f'GRAY|    Сигнатура СОВ "{item["msg"]}" уже существует.')
            err, result = parent.utm.update_template_idps_signature(parent.template_id, signatures[item['msg']], item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|       {result}  [Сигнатура СОВ: {item["msg"]}]')
                continue
            else:
                parent.stepChanged.emit(f'BLACK|       Сигнатура СОВ "{item["msg"]}" updated.')
        else:
            err, result = parent.utm.add_template_idps_signature(parent.template_id, item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Сигнатура СОВ: "{item["msg"]}" не импортирована]')
                continue
            else:
                signatures[item['msg']] = result
                parent.stepChanged.emit(f'BLACK|    Сигнатура СОВ "{item["msg"]}" импортирована.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте пользовательских сигнатур СОВ.')
    else:
        parent.stepChanged.emit('GREEN|    Пользовательские сигнатуры СОВ импортированы в раздел "Библиотеки/Сигнатуры СОВ".')


def import_idps_profiles(parent, path):
    """Импортируем профили СОВ"""
    json_file = os.path.join(path, 'config_idps_profiles.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт профилей СОВ в раздел "Библиотеки/Профили СОВ".')
    error = 0

    err, result = parent.utm.get_template_idps_profiles_list(parent.template_id)
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей СОВ.')
        parent.error = 1
        return
    profiles = {x['name']: x['id'] for x in result}

    err, result = parent.utm.get_template_idps_signatures_list(parent.template_id)
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей СОВ.')
        parent.error = 1
        return
    idps_signatures = {x['msg']: x['id'] for x in result}

    for item in data:
        if 'filters' not in item:
            parent.stepChanged.emit('RED|    Импорт профилей СОВ старых версий не поддерживается для версий 7.1 и выше.')
            error = 1
            break

        # Исключаем отсутствующие сигнатуры. И получаем ID сигнатур по имени так как ID может не совпадать.
        new_overrides = []
        for signature in item['overrides']:
            try:
                signature['id'] = idps_signatures[signature['msg']]
                new_overrides.append(signature)
            except KeyError as err:
                parent.stepChanged.emit(f'RED|    Error: Не найдена сигнатура "{err}" [Профиль СОВ "{item["name"]}"].')
                error = 1
        item['overrides'] = new_overrides

        if item['name'] in profiles:
            parent.stepChanged.emit(f'GRAY|    Профиль СОВ "{item["name"]}" уже существует.')
            err, result = parent.utm.update_template_idps_profile(parent.template_id, profiles[item['name']], item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|       {result}  [Профиль СОВ: {item["name"]}]')
            else:
                parent.stepChanged.emit(f'BLACK|       Профиль СОВ "{item["name"]}" updated.')
        else:
            err, result = parent.utm.add_template_idps_profile(parent.template_id, item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Профиль СОВ: "{item["name"]}" не импортирован]')
            else:
                profiles[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Профиль СОВ "{item["name"]}" импортирован.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей СОВ.')
    else:
        parent.stepChanged.emit('GREEN|    Профили СОВ импортированы в раздел "Библиотеки/Профили СОВ".')


def import_notification_profiles(parent, path):
    """Импортируем список профилей оповещения"""
    json_file = os.path.join(path, 'config_notification_profiles.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт профилей оповещений в раздел "Библиотеки/Профили оповещений".')
    error = 0

    err, result = parent.utm.get_template_notification_profiles_list(parent.template_id)
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей оповещений.')
        parent.error = 1
        return
    profiles = {x['name']: x['id'] for x in result}

    for item in data:
        item['name'] = func.get_restricted_name(item['name'])
        if item['name'] in profiles:
            parent.stepChanged.emit(f'GRAY|    Профиль оповещения "{item["name"]}" уже существует.')
            err, result = parent.utm.update_template_notification_profile(parent.template_id, profiles[item['name']], item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|       {result}  [Профиль оповещения: {item["name"]}]')
            else:
                parent.stepChanged.emit(f'BLACK|       Профиль оповещения "{item["name"]}" updated.')
        else:
            err, result = parent.utm.add_template_notification_profile(parent.template_id, item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Профиль оповещения: "{item["name"]}" не импортирован]')
            elif err == 3:
                parent.stepChanged.emit(f'GRAY|    {result}')
            else:
                profiles[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Профиль оповещения "{item["name"]}" импортирован.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей оповещений.')
    else:
        parent.stepChanged.emit('GREEN|    Профили оповещений импортированы в раздел "Библиотеки/Профили оповещений".')


def import_netflow_profiles(parent, path):
    """Импортируем список профилей netflow"""
    json_file = os.path.join(path, 'config_netflow_profiles.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт профилей netflow в раздел "Библиотеки/Профили netflow".')
    error = 0

    err, result = parent.utm.get_template_netflow_profiles_list(parent.template_id)
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей netflow.')
        parent.error = 1
        return
    profiles = {x['name']: x['id'] for x in result}

    for item in data:
        item['name'] = func.get_restricted_name(item['name'])
        if item['name'] in profiles:
            parent.stepChanged.emit(f'GRAY|    Профиль netflow "{item["name"]}" уже существует.')
            err, result = parent.utm.update_template_netflow_profile(parent.template_id, profiles[item['name']], item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|       {result}  [Профиль netflow: {item["name"]}]')
            else:
                parent.stepChanged.emit(f'BLACK|       Профиль netflow "{item["name"]}" updated.')
        else:
            err, result = parent.utm.add_template_netflow_profile(parent.template_id, item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Профиль netflow: "{item["name"]}" не импортирован]')
            else:
                profiles[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Профиль netflow "{item["name"]}" импортирован.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей netflow.')
    else:
        parent.stepChanged.emit('GREEN|    Профили netflow импортированы в раздел "Библиотеки/Профили netflow".')


def import_lldp_profiles(parent, path):
    """Импортируем список профилей LLDP"""
    json_file = os.path.join(path, 'config_lldp_profiles.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт профилей LLDP в раздел "Библиотеки/Профили LLDP".')
    error = 0

    err, result = parent.utm.get_template_lldp_profiles_list(parent.template_id)
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей LLDP.')
        parent.error = 1
        return
    profiles = {x['name']: x['id'] for x in result}

    for item in data:
        item['name'] = func.get_restricted_name(item['name'])
        if item['name'] in profiles:
            parent.stepChanged.emit(f'GRAY|    Профиль LLDP "{item["name"]}" уже существует.')
            err, result = parent.utm.update_template_lldp_profile(parent.template_id, profiles[item['name']], item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|       {result}  [Профиль LLDP: {item["name"]}]')
            else:
                parent.stepChanged.emit(f'BLACK|       Профиль LLDP "{item["name"]}" updated.')
        else:
            err, result = parent.utm.add_template_lldp_profile(parent.template_id, item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Профиль LLDP: "{item["name"]}" не импортирован]')
            else:
                profiles[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Профиль LLDP "{item["name"]}" импортирован.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей LLDP.')
    else:
        parent.stepChanged.emit('GREEN|    Профили LLDP импортированы в раздел "Библиотеки/Профили LLDP".')


def import_ssl_profiles(parent, path):
    """Импортируем список профилей SSL"""
    json_file = os.path.join(path, 'config_ssl_profiles.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт профилей SSL в раздел "Библиотеки/Профили SSL".')
    error = 0

    for item in data:
        if 'supported_groups' not in item:
            item['supported_groups'] = []
        item['name'] = func.get_restricted_name(item['name'])
        ssl_profiles = parent.mc_data['ssl_profiles']
        if item['name'] in ssl_profiles:
            parent.stepChanged.emit(f'GRAY|    Профиль SSL "{item["name"]}" уже существует.')
            err, result = parent.utm.update_template_ssl_profile(parent.template_id, ssl_profiles[item['name']], item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|       {result}  [Профиль SSL: {item["name"]}]')
            else:
                parent.stepChanged.emit(f'BLACK|       Профиль SSL "{item["name"]}" updated.')
        else:
            err, result = parent.utm.add_template_ssl_profile(parent.template_id, item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Профиль SSL: "{item["name"]}" не импортирован]')
            else:
                ssl_profiles[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Профиль SSL "{item["name"]}" импортирован.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей SSL.')
    else:
        parent.stepChanged.emit('GREEN|    Профили SSL импортированы в раздел "Библиотеки/Профили SSL".')


def import_ssl_forward_profiles(parent, path):
    """Импортируем профили пересылки SSL"""
    json_file = os.path.join(path, 'config_ssl_forward_profiles.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт профилей пересылки SSL в раздел "Библиотеки/Профили пересылки SSL".')
    error = 0

    err, result = parent.utm.get_template_ssl_forward_profiles(parent.template_id)
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей пересылки SSL.')
        parent.error = 1
        return
    profiles = {x['name']: x['id'] for x in result}

    for item in data:
        item['name'] = func.get_restricted_name(item['name'])
        if item['name'] in profiles:
            parent.stepChanged.emit(f'GRAY|    Профиль пересылки SSL "{item["name"]}" уже существует.')
            err, result = parent.utm.update_template_ssl_forward_profile(parent.template_id, profiles[item['name']], item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|       {result}  [Профиль пересылки SSL: {item["name"]}]')
            else:
                parent.stepChanged.emit(f'BLACK|       Профиль пересылки SSL "{item["name"]}" updated.')
        else:
            err, result = parent.utm.add_template_ssl_forward_profile(parent.template_id, item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Профиль пересылки SSL: "{item["name"]}" не импортирован]')
            else:
                profiles[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Профиль пересылки SSL "{item["name"]}" импортирован.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей пересылки SSL.')
    else:
        parent.stepChanged.emit('GREEN|    Профили пересылки SSL импортированы в раздел "Библиотеки/Профили пересылки SSL".')


def import_hip_objects(parent, path):
    """Импортируем HIP объекты"""
    json_file = os.path.join(path, 'config_hip_objects.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт HIP объектов в раздел "Библиотеки/HIP объекты".')
    error = 0

    err, result = parent.utm.get_template_hip_objects_list(parent.template_id)
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте HIP объектов.')
        parent.error = 1
        return
    profiles = {x['name']: x['id'] for x in result}

    for item in data:
        if item['name'] in profiles:
            parent.stepChanged.emit(f'GRAY|    HIP объект "{item["name"]}" уже существует.')
            err, result = parent.utm.update_template_hip_object(parent.template_id, profiles[item['name']], item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|       {result}  [HIP объект: {item["name"]}]')
            else:
                parent.stepChanged.emit(f'BLACK|       HIP объект "{item["name"]}" updated.')
        else:
            err, result = parent.utm.add_template_hip_object(parent.template_id, item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [HIP объект: "{item["name"]}" не импортирован]')
            else:
                profiles[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    HIP объект "{item["name"]}" импортирован.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте HIP объектов.')
    else:
        parent.stepChanged.emit('GREEN|    HIP объекты импортированы в раздел "Библиотеки/HIP объекты".')


def import_hip_profiles(parent, path):
    """Импортируем HIP профили"""
    json_file = os.path.join(path, 'config_hip_profiles.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт HIP профилей в раздел "Библиотеки/HIP профили".')
    error = 0

    err, result = parent.utm.get_template_hip_objects_list(parent.template_id)
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте HIP профилей.')
        parent.error = 1
        return
    hip_objects = {x['name']: x['id'] for x in result}

    err, result = parent.utm.get_template_hip_profiles_list(parent.template_id)
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте HIP профилей.')
        parent.error = 1
        return
    profiles = {x['name']: x['id'] for x in result}

    for item in data:
        for obj in item['hip_objects']:
            obj['id'] = hip_objects[obj['id']]
        if item['name'] in profiles:
            parent.stepChanged.emit(f'GRAY|    HIP профиль "{item["name"]}" уже существует.')
            err, result = parent.utm.update_template_hip_profile(parent.template_id, profiles[item['name']], item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|       {result}  [HIP профиль: {item["name"]}]')
            else:
                parent.stepChanged.emit(f'BLACK|       HIP профиль "{item["name"]}" updated.')
        else:
            err, result = parent.utm.add_template_hip_profile(parent.template_id, item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [HIP профиль: "{item["name"]}" не импортирован]')
            else:
                profiles[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    HIP профиль "{item["name"]}" импортирован.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте HIP профилей.')
    else:
        parent.stepChanged.emit('GREEN|    HIP профили импортированы в раздел "Библиотеки/HIP профили".')


def import_bfd_profiles(parent, path):
    """Импортируем профили BFD"""
    json_file = os.path.join(path, 'config_bfd_profiles.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт профилей BFD в раздел "Библиотеки/Профили BFD".')
    error = 0

    err, result = parent.utm.get_template_bfd_profiles_list(parent.template_id)
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей BFD.')
        parent.error = 1
        return
    profiles = {x['name']: x['id'] for x in result}

    for item in data:
        if item['name'] in profiles:
            parent.stepChanged.emit(f'GRAY|    Профиль BFD "{item["name"]}" уже существует.')
            err, result = parent.utm.update_template_bfd_profile(parent.template_id, profiles[item['name']], item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|       {result}  [Профиль BFD: {item["name"]}]')
            else:
                parent.stepChanged.emit(f'BLACK|       Профиль BFD "{item["name"]}" updated.')
        else:
            err, result = parent.utm.add_template_bfd_profile(parent.template_id, item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Профиль BFD: "{item["name"]}" не импортирован]')
            else:
                profiles[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Профиль BFD "{item["name"]}" импортирован.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей BFD.')
    else:
        parent.stepChanged.emit('GREEN|    Профили BFD импортированы в раздел "Библиотеки/Профили BFD".')


def import_useridagent_syslog_filters(parent, path):
    """Импортируем syslog фильтры UserID агента"""
    json_file = os.path.join(path, 'config_useridagent_syslog_filters.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт syslog фильтров UserID агента в раздел "Библиотеки/Syslog фильтры UserID агента".')
    error = 0

    err, result = parent.utm.get_template_useridagent_filters_list(parent.template_id)
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте syslog фильтров UserID агента.')
        parent.error = 1
        return
    filters = {x['name']: x['id'] for x in result}

    for item in data:
        if item['name'] in filters:
            parent.stepChanged.emit(f'GRAY|    Фильтр "{item["name"]}" уже существует.')
            err, result = parent.utm.update_template_useridagent_filter(parent.template_id, filters[item['name']], item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|       {result}  [Фильтр: {item["name"]}]')
            else:
                parent.stepChanged.emit(f'BLACK|       Фильтр "{item["name"]}" updated.')
        else:
            err, result = parent.utm.add_template_useridagent_filter(parent.template_id, item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Фильтр: "{item["name"]}" не импортирован]')
            else:
                filters[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Фильтр "{item["name"]}" импортирован.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте syslog фильтров UserID агента.')
    else:
        parent.stepChanged.emit('GREEN|    Syslog фильтры UserID агента импортированы в раздел "Библиотеки/Syslog фильтры UserID агента".')


def import_scenarios(parent, path):
    """Импортируем список сценариев"""
    json_file = os.path.join(path, 'config_scenarios.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт списка сценариев в раздел "Библиотеки/Сценарии".')
    error = 0

    for item in data:
        item['name'] = func.get_restricted_name(item['name'])
        new_conditions = []
        for condition in item['conditions']:
            if condition['kind'] == 'application':
                condition['apps'] = get_apps(parent, condition['apps'], item['name'])
            elif condition['kind'] == 'mime_types':
                try:
                    condition['content_types'] = [parent.mc_data['mime'][x] for x in condition['content_types']]
                except KeyError as err:
                    parent.stepChanged.emit(f'bRED|    Error! Сценарий "{item["name"]}": Не найден тип контента "{err}". Загрузите типы контента и повторите попытку.')
                    condition['content_types'] = []
            elif condition['kind'] == 'url_category':
                condition['url_categories'] = get_url_categories_id(parent, condition['url_categories'], item['name'])
            new_conditions.append(condition)
        item['conditions'] = new_conditions

        scenarios = parent.mc_data['scenarios']
        if item['name'] in scenarios:
            parent.stepChanged.emit(f'GRAY|    Сценарий "{item["name"]}" уже существует.')
            err, result = parent.utm.update_template_scenarios_rule(parent.template_id, scenarios[item['name']], item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|       {result}  [Сценарий: {item["name"]}]')
                continue
            else:
                parent.stepChanged.emit(f'BLACK|       Сценарий "{item["name"]}" updated.')
        else:
            err, result = parent.utm.add_template_scenarios_rule(parent.template_id, item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Сценарий: "{item["name"]}" не импортирован]')
                continue
            else:
                scenarios[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Сценарий "{item["name"]}" импортирован.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте списка сценариев.')
    else:
        parent.stepChanged.emit('GREEN|    Список сценариев импортирован в раздел "Библиотеки/Сценарии".')


#-------------------------------------------- Сеть ------------------------------------------------------------
def import_zones(parent, path):
    """Импортируем зоны на NGFW, если они есть."""
    json_file = os.path.join(path, 'config_zones.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт зон в раздел "Сеть/Зоны".')

    service_ids = {
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
#        'SCADA': 'ffffff03-ffff-ffff-ffff-ffffff000017',
        'Reverse-прокси': 'ffffff03-ffff-ffff-ffff-ffffff000018',
        'Веб-портал': 'ffffff03-ffff-ffff-ffff-ffffff000019',
        'SAML сервер': 'ffffff03-ffff-ffff-ffff-ffffff000022',
        'Log analyzer': 'ffffff03-ffff-ffff-ffff-ffffff000023',
        'OSPF': 'ffffff03-ffff-ffff-ffff-ffffff000024',
        'BGP': 'ffffff03-ffff-ffff-ffff-ffffff000025',
        'RIP': 'ffffff03-ffff-ffff-ffff-ffffff000030',
        'SNMP-прокси': 'ffffff03-ffff-ffff-ffff-ffffff000026',
        'SSH-прокси': 'ffffff03-ffff-ffff-ffff-ffffff000027',
        'Multicast': 'ffffff03-ffff-ffff-ffff-ffffff000028',
        'NTP сервис': 'ffffff03-ffff-ffff-ffff-ffffff000029',
        'UserID syslog collector': 'ffffff03-ffff-ffff-ffff-ffffff000031',
        'BFD': 'ffffff03-ffff-ffff-ffff-ffffff000032',
        'Endpoints connect': 'ffffff03-ffff-ffff-ffff-ffffff000033'
    }

    error = 0
    for zone in data:
        zone['name'] = func.get_restricted_name(zone['name'])
        new_services_access = []
        for service in zone['services_access']:
            if service['enabled']:
                if service['allowed_ips'] and isinstance(service['allowed_ips'][0], list):
                    allowed_ips = []
                    for item in service['allowed_ips']:
                        if item[0] == 'list_id':
                            try:
                                item[1] = parent.mc_data['ip_lists'][item[1]]
                            except KeyError as err:
                                parent.stepChanged.emit(f'RED|    Error [Зона "{zone["name"]}"]. В контроле доступа "{service["service_id"]}" не найден список IP-адресов "{err}".')
                                zone['description'] = f'{zone["description"]}\nError: В контроле доступа "{service["service_id"]}" не найден список IP-адресов "{err}".'
                                error = 1
                                continue
                        allowed_ips.append(item)
                    service['allowed_ips'] = allowed_ips
                try:
                    service['service_id'] = service_ids[service['service_id']]
                    new_services_access.append(service)
                except KeyError as err:
                    parent.stepChanged.emit(f'RED|    Error [Зона "{zone["name"]}"]. Не корректный сервис "{service["service_id"]}" в контроле доступа.')
                    zone['description'] = f'{zone["description"]}\nError: Не импортирован сервис "{service["service_id"]}" в контроль доступа.'
                    error = 1
        zone['services_access'] = new_services_access

        zone_networks = []
        for net in zone['networks']:
            if net[0] == 'list_id':
                try:
                    net[1] = parent.mc_data['ip_lists'][net[1]]
                except KeyError as err:
                    parent.stepChanged.emit(f'RED|    Error [Зона "{zone["name"]}"]. В разделе "Защита от IP-спуфинга" не найден список IP-адресов "{err}".')
                    zone['description'] = f'{zone["description"]}\nError: В разделе "Защита от IP-спуфинга" не найден список IP-адресов "{err}".'
                    error = 1
                    continue
            zone_networks.append(net)
        zone['networks'] = zone_networks

        sessions_limit_exclusions = []
        for item in zone['sessions_limit_exclusions']:
            try:
                item[1] = parent.mc_data['ip_lists'][item[1]]
                sessions_limit_exclusions.append(item)
            except KeyError as err:
                parent.stepChanged.emit(f'RED|    Error [Зона "{zone["name"]}"]. В разделе "Ограничение сессий" не найден список IP-адресов "{err}".')
                zone['description'] = f'{zone["description"]}\nError: В разделе "Ограничение сессий" не найден список IP-адресов "{err}".'
                error = 1
        zone['sessions_limit_exclusions'] = sessions_limit_exclusions

        err, result = parent.utm.add_template_zone(parent.template_id, zone)
        if err == 3:
            parent.stepChanged.emit(f'GRAY|    {result}')
        elif err == 1:
            parent.stepChanged.emit(f'RED|    {result}. Зона "{zone["name"]}" не импортирована.')
            error = 1
        else:
            parent.mc_data['zones'][zone['name']] = result
            parent.stepChanged.emit(f'BLACK|    Зона "{zone["name"]}" импортирована.')

    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте зон.')
    else:
        parent.stepChanged.emit('GREEN|    Зоны импортированы в раздел "Сеть/Зоны".')


def import_interfaces(parent, path):
    if isinstance(parent.ngfw_vlans, int):
        parent.stepChanged.emit(parent.new_vlans)
        return

    import_vlans(parent, path)
    import_ipip_interface(parent, path)

def import_ipip_interface(parent, path):
    """Импортируем интерфесы IP-IP."""
    json_file = os.path.join(path, 'config_interfaces.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    # Проверяем что есть интерфейсы IP-IP для импорта.
    is_gre = False
    for item in data:
        if 'kind' in item and item['kind'] == 'tunnel' and item['name'][:3] == 'gre':
            is_gre = True
    if not is_gre:
        return

    parent.stepChanged.emit('BLUE|Импорт интерфейсов GRE/IPIP/VXLAN в раздел "Сеть/Интерфейсы".')
    err, result = parent.utm.get_template_interfaces_list(parent.template_id)
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при создания интерфейсов GRE/IPIP/VXLAN.')
        parent.error = 1
        return
    mc_gre = [int(x['name'][3:]) for x in result if x['kind'] == 'tunnel' and x['name'].startswith('gre')]
    gre_num = max(mc_gre) if mc_gre else 0
    error = 0

    for item in data:
        if 'kind' in item and item['kind'] == 'tunnel' and item['name'].startswith('gre'):
            gre_num += 1
            item.pop('id', None)      # удаляем readonly поле
            item.pop('master', None)      # удаляем readonly поле
            item.pop('mac', None)
            if 'node_name' in item:
                 if item['node_name'] != parent.node_name:
                    continue
            else:
                item['node_name'] = parent.node_name

            item['name'] = f"gre{gre_num}"
            if item['zone_id']:
                try:
                    item['zone_id'] = parent.mc_data['zones'][item['zone_id']]
                except KeyError as err:
                    parent.stepChanged.emit(f'bRED|    Для интерфейса "{item["name"]}" не найдена зона "{item["zone_id"]}". Импортируйте зоны и повторите попытку.')
                    item['zone_id'] = 0

            new_ipv4 = []
            for ip in item['ipv4']:
                err, result = func.unpack_ip_address(ip)
                if err:
                    parent.stepChanged.emit(f'bRED|    Не удалось преобразовать IP: "{ip}" для VLAN {item["vlan_id"]}. IP-адрес использован не будет. Error: {result}')
                else:
                    new_ipv4.append(result)
            if not new_ipv4:
                item['config_on_device'] = True
            item['ipv4'] = new_ipv4

            err, result = parent.utm.add_template_interface(parent.template_id, item)
            if err:
                parent.stepChanged.emit(f'RED|    {result} [Интерфейс {item["tunnel"]["mode"]} - {item["name"]} не импортирован]')
                error = 1
            else:
                parent.stepChanged.emit(f'BLACK|    Добавлен интерфейс {item["tunnel"]["mode"]} - {item["name"]}.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при создания интерфейсов GRE/IPIP/VXLAN.')
    else:
        parent.stepChanged.emit('GREEN|    Интерфейсы GRE/IPIP/VXLAN импортированы в раздел "Сеть/Интерфейсы".')


def import_vlans(parent, path):
    """Импортируем интерфесы VLAN. Нельзя использовать интерфейсы Management и slave."""
    parent.stepChanged.emit('BLUE| Импорт VLAN в раздел "Сеть/Интерфейсы"')
    error = 0
    if isinstance(parent.ngfw_vlans, int):
        parent.stepChanged.emit(parent.new_vlans)
        if parent.ngfw_vlans == 1:
            parent.error = 1
        return

    err, result = parent.utm.get_template_netflow_profiles_list(parent.template_id)
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при создания интерфейсов VLAN.')
        parent.error = 1
        return
    netflow_profiles = {x['name']: x['id'] for x in result}
    netflow_profiles['undefined'] = 'undefined'

    err, result = parent.utm.get_template_lldp_profiles_list(parent.template_id)
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при создания интерфейсов VLAN.')
        parent.error = 1
        return
    lldp_profiles = {x['name']: x['id'] for x in result}
    lldp_profiles['undefined'] = 'undefined'

    for item in parent.iface_settings:
        if 'kind' in item and item['kind'] == 'vlan':
            current_port = parent.new_vlans[item['vlan_id']]['port']
            current_zone = parent.new_vlans[item['vlan_id']]['zone']
            if item["vlan_id"] in parent.ngfw_vlans:
                parent.stepChanged.emit(f"GRAY|    VLAN {item['vlan_id']} уже существует на порту {parent.ngfw_vlans[item['vlan_id']]}")
                continue
            if current_port == "Undefined":
                parent.stepChanged.emit(f"rNOTE|    VLAN {item['vlan_id']} не импортирован так как для него не назначен порт.")
                continue

            item.pop('running', None)
            item.pop('master', None)
            item.pop('mac', None)
            item.pop('id', None)

            if 'node_name' in item:
                 if item['node_name'] != parent.node_name:
                    continue
            else:
                item['node_name'] = parent.node_name

            item['link'] = current_port
            item['name'] = f'{current_port}.{item["vlan_id"]}'

            if current_zone != "Undefined":
                try:
                    item['zone_id'] = parent.mc_data['zones'][current_zone]
                except KeyError as err:
                    parent.stepChanged.emit(f"RED|    Error: В шаблоне не найдена зона {err} для VLAN {item['vlan_id']}. Импортируйте зоны и повторите попытку.")
                    item['zone_id'] = 0
                    error = 1
            else:
                try:
                    item['zone_id'] = parent.mc_data['zones'][item['zone_id']]
                except KeyError as err:
                    parent.stepChanged.emit(f"RED|    Error: В шаблоне не найдена зона {err} для VLAN {item['vlan_id']}. Импортируйте зоны и повторите попытку.")
                    item['zone_id'] = 0
                    error = 1

            new_ipv4 = []
            for ip in item['ipv4']:
                err, result = func.unpack_ip_address(ip)
                if err:
                    parent.stepChanged.emit(f'bRED|    Не удалось преобразовать IP: "{ip}" для VLAN {item["vlan_id"]}. IP-адрес использован не будет. Error: {result}')
                else:
                    new_ipv4.append(result)
            if not new_ipv4:
                item['mode'] = 'manual'
            item['ipv4'] = new_ipv4

            try:
                item['lldp_profile'] = lldp_profiles[item['lldp_profile']]
            except KeyError:
                parent.stepChanged.emit(f'bRED|    Для VLAN "{item["name"]}" не найден lldp profile "{item["lldp_profile"]}" . Импортируйте профили LLDP и повторите попытку.')
                item['lldp_profile'] = 'undefined'
            try:
                item['netflow_profile'] = netflow_profiles[item['netflow_profile']]
            except KeyError:
                parent.stepChanged.emit(f'bRED|    Для VLAN "{item["name"]}" не найден netflow profile "{item["netflow_profile"]}" . Импортируйте профили netflow и повторите попытку.')
                item['netflow_profile'] = 'undefined'

            err, result = parent.utm.add_template_interface(parent.template_id, item)
            if err:
                parent.stepChanged.emit(f'RED|    {result} [Интерфейс {item["name"]} не импортирован]')
                error = 1
            else:
                parent.ngfw_vlans[item['vlan_id']] = item['name']
                parent.stepChanged.emit(f'BLACK|    Добавлен VLAN {item["vlan_id"]}, name: {item["name"]}, zone: {current_zone}.')

    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при создания интерфейсов VLAN.')
    else:
        parent.stepChanged.emit('GREEN|    Интерфейсы VLAN импортированы в раздел "Сеть/Интерфейсы".')


def import_gateways(parent, path):
    import_gateways_list(parent, path)
    import_gateway_failover(parent, path)

def import_gateways_list(parent, path):
    """Импортируем список шлюзов"""
    json_file = os.path.join(path, 'config_gateways.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт шлюзов в раздел "Сеть/Шлюзы".')
    if isinstance(parent.ngfw_ports, int):
        if parent.ngfw_ports == 1:
            parent.error = 1
            return
        elif parent.ngfw_ports == 3:
            parent.stepChanged.emit(f'NOTE|    Интерфейсы будут установлены в значение "Автоматически" так как порты отсутствуют на узле {parent.node_name} шаблона.')
    error = 0

    err, result = parent.utm.get_template_gateways_list(parent.template_id)
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте шлюзов.')
        parent.error = 1
        return
    gateways_list = {x.get('name', x['ipv4']): x['id'] for x in result}

    err, result = parent.utm.get_template_interfaces_list(parent.template_id, node_name=parent.node_name)
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте шлюзов.')
        parent.error = 1
        return
    mc_ifaces = {x['name'] for x in result}

    err, result = parent.utm.get_template_vrf_list(parent.template_id)
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте шлюзов.')
        parent.error = 1
        return
    mc_vrf = {x['name']: x['interfaces'] for x in result}

    config_vrf = {item['vrf']: [] for item in data}
    for item in data:
        if item['iface'] in mc_ifaces:
            config_vrf[item['vrf']].append(item['iface'])
    if 'default' in mc_vrf:
        mc_vrf['default'] = config_vrf.get('default', [])

    for item in data:
        item['is_automatic'] = False

        if 'node_name' in item:
            if item['node_name'] != parent.node_name:
                continue
        else:
            item['node_name'] = parent.node_name

        if item['vrf'] not in mc_vrf:
            err, result = add_empty_vrf(parent, item['vrf'], config_vrf[item['vrf']])
            if err:
                parent.stepChanged.emit(f'RED|    {result}')
                parent.stepChanged.emit(f'RED|    Error: Для шлюза "{item["name"]}" не удалось добавить VRF "{item["vrf"]}". Установлен VRF по умолчанию.')
                error = 1
                item['vrf'] = 'default'
                item['default'] = False
            else:
                parent.stepChanged.emit(f'NOTE|    Для шлюза "{item["name"]}" создан VRF "{item["vrf"]}".')
                mc_vrf[item['vrf']] = config_vrf[item['vrf']]

        if item['iface'] not in mc_vrf[item['vrf']]:
            item['iface'] = 'undefined'

        if item['name'] in gateways_list:
            err, result = parent.utm.update_template_gateway(parent.template_id, gateways_list[item['name']], item)
            if err:
                parent.stepChanged.emit(f'RED|    Error: Шлюз "{item["name"]}" не обновлён. {result}')
                error = 1
            else:
                parent.stepChanged.emit(f'BLACK|    Шлюз "{item["name"]}" уже существует - Updated!')
        else:
            err, result = parent.utm.add_template_gateway(parent.template_id, item)
            if err:
                parent.stepChanged.emit(f'RED|    Error:  Шлюз "{item["name"]}" не импортирован. {result}')
                error = 1
            else:
                gateways_list[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Шлюз "{item["name"]}" импортирован.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте шлюзов.')
    else:
        parent.stepChanged.emit('GREEN|    Шлюзы импортированы в раздел "Сеть/Шлюзы".')


def import_gateway_failover(parent, path):
    """Импортируем настройки проверки сети"""
    json_file = os.path.join(path, 'config_gateway_failover.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт настроек проверки сети раздела "Сеть/Шлюзы/Проверка сети".')

    err, result = parent.utm.update_template_gateway_failover(parent.template_id, data)
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при обновлении настроек проверки сети!')
    else:
        parent.stepChanged.emit('GREEN|    Настройки проверки сети обновлены.')


def import_dhcp_subnets(parent, path):
    """Импортируем настойки DHCP"""
    parent.stepChanged.emit('BLUE|Импорт настроек DHCP раздела "Сеть/DHCP".')
    if isinstance(parent.ngfw_ports, int):
        parent.stepChanged.emit(parent.dhcp_settings)
        if parent.ngfw_ports == 1:
            parent.error = 1
        return
    error = 0

    err, result = parent.utm.get_template_dhcp_list(parent.template_id)
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте настроек DHCP.')
        parent.error = 1
        return
    mc_dhcp_subnets = [x['name'] for x in result]

    for item in parent.dhcp_settings:
        if 'node_name' in item:
            if item['node_name'] != parent.node_name:
                continue
        else:
            item['node_name'] = parent.node_name

        if item['iface_id'] == 'Undefined':
            parent.stepChanged.emit(f'GRAY|    DHCP subnet "{item["name"]}" не добавлен так как для него не указан порт.')
            continue
        item['name'] = func.get_restricted_name(item['name'])
        if item['name'] in mc_dhcp_subnets:
            parent.stepChanged.emit(f'GRAY|    DHCP subnet "{item["name"]}" не добавлен так как уже существует.')
            continue
        if item['iface_id'] not in parent.ngfw_ports:
            parent.stepChanged.emit(f'rNOTE|    DHCP subnet "{item["name"]}" не добавлен так как порт: {item["iface_id"]} не существует на МС.')
            continue

        err, result = parent.utm.add_template_dhcp_subnet(parent.template_id, item)
        if err == 1:
            parent.stepChanged.emit(f'RED|    {result}  [subnet "{item["name"]}" не импортирован]')
            error = 1
        elif err == 3:
            parent.stepChanged.emit(f'GRAY|    {result}.')
        else:
            parent.stepChanged.emit(f'BLACK|    DHCP subnet "{item["name"]}" импортирован.')

    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте настроек DHCP.')
    else:
        parent.stepChanged.emit('GREEN|    Настройки DHCP импортированы в раздел "Сеть/DHCP".')


def import_dns_config(parent, path):
    """Импортируем раздел 'UserGate/DNS'."""
    import_dns_proxy(parent, path)
    import_dns_servers(parent, path)
    import_dns_rules(parent, path)
    import_dns_static(parent, path)

def import_dns_proxy(parent, path):
    """Импортируем настройки DNS прокси"""
    json_file = os.path.join(path, 'config_dns_proxy.json')
    err, result = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт настроек DNS-прокси раздела "Сеть/DNS/Настройки DNS-прокси".')
    error = 0

    for key, value in result.items():
        value = {'enabled': True, 'code': key, 'value': value}
        err, result = parent.utm.update_template_dns_setting(parent.template_id, key, value)
        if err:
            parent.stepChanged.emit(f'RED|    {result}')
            error = 1
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте настроек DNS-прокси!')
    else:
        parent.stepChanged.emit('GREEN|    Настройки DNS-прокси импортированы.')

def import_dns_servers(parent, path):
    """Импортируем список системных DNS серверов"""
    json_file = os.path.join(path, 'config_dns_servers.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт системных DNS серверов в раздел "Сеть/DNS/Системные DNS-серверы".')
    error = 0

    for item in data:
        item.pop('is_bad', None)
        err, result = parent.utm.add_template_dns_server(parent.template_id, item)
        if err == 3:
            parent.stepChanged.emit(f'GRAY|    {result}')
        elif err == 1:
            parent.stepChanged.emit(f'RED|    {result} [DNS сервер "{item["dns"]}" не импортирован]')
            error = 1
        else:
            parent.stepChanged.emit(f'BLACK|    DNS сервер "{item["dns"]}" импортирован.')

    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте DNS-серверов.')
    else:
        parent.stepChanged.emit('GREEN|    Cистемные DNS-сервера Импортированы в раздел "Сеть/DNS/Системные DNS-серверы".')

def import_dns_rules(parent, path):
    """Импортируем правила DNS-прокси"""
    json_file = os.path.join(path, 'config_dns_rules.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт правил DNS-прокси в раздел "Сеть/DNS/DNS-прокси/Правила DNS".')
    error = 0

    for item in data:
        err, result = parent.utm.add_template_dns_rule(parent.template_id, item)
        if err == 3:
            parent.stepChanged.emit(f'GRAY|    {result}')
        elif err == 1:
            parent.stepChanged.emit(f'RED|    {result} [Правило DNS-прокси "{item["name"]}" не импортировано]')
            error = 1
        else:
            parent.stepChanged.emit(f'BLACK|    Правило DNS-прокси "{item["name"]}" импортировано.')

    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил DNS-прокси.')
    else:
        parent.stepChanged.emit('GREEN|    Импортированы правила DNS-прокси в раздел "Сеть/DNS/DNS-прокси/Правила DNS".')

def import_dns_static(parent, path):
    """Импортируем статические записи DNS"""
    json_file = os.path.join(path, 'config_dns_static.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт статических записей DNS в раздел "Сеть/DNS/DNS-прокси/Статические записи".')
    error = 0

    for item in data:
        err, result = parent.utm.add_template_dns_static_record(parent.template_id, item)
        if err == 3:
            parent.stepChanged.emit(f'GRAY|    {result}')
        elif err == 1:
            parent.stepChanged.emit(f'RED|    {result} [Статическая запись DNS "{item["name"]}" не импортирована]')
            error = 1
        else:
            parent.stepChanged.emit(f'BLACK|    Статическая запись DNS "{item["name"]}" импортирована.')

    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте статических записей DNS.')
    else:
        parent.stepChanged.emit('GREEN|    Статические записи DNS импортированы в раздел "Сеть/DNS/DNS-прокси/Статические записи".')


def import_vrf(parent, path):
    """Импортируем виртуальный маршрутизатор по умолчанию"""
    json_file = os.path.join(path, 'config_vrf.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт виртуальных маршрутизаторов в раздел "Сеть/Виртуальные маршрутизаторы".')
    if isinstance(parent.ngfw_ports, int):
        if parent.ngfw_ports == 1:
            parent.error = 1
            return
        elif parent.ngfw_ports == 3:
            parent.stepChanged.emit(f'NOTE|    Интерфейсы не будут добавлены в виртуальный маршрутизатор так как отсутствуют порты на узле {parent.node_name} шаблона.')

    parent.stepChanged.emit('LBLUE|    Если вы используете BGP, после импорта включите нужные фильтры in/out для BGP-соседей и Routemaps в свойствах соседей.')
    parent.stepChanged.emit('LBLUE|    Если вы используете OSPF, после импорта установите нужный профиль BFD для каждого интерфейса в настройках OSPF.')
    error = 0
    
    err, result = parent.utm.get_template_vrf_list(parent.template_id)
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте виртуального маршрутизатора.')
        parent.error = 1
        return
    virt_routers = {x['name']: x['id'] for x in result}

    err, result = parent.utm.get_template_bfd_profiles_list(parent.template_id)
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте виртуального маршрутизатора.')
        parent.error = 1
        return
    bfd_profiles = {x['name']: x['id'] for x in result}
    bfd_profiles[-1] = -1
    
    for item in data:
        if 'node_name' in item:
            if item['node_name'] != parent.node_name:
                continue
        else:
            item['node_name'] = parent.node_name

        for x in item['routes']:
            x['name'] = func.get_restricted_name(x['name'])
        if item['ospf']:
            for x in item['ospf']['interfaces']:
                try:
                    x['bfd_profile'] = bfd_profiles[x['bfd_profile']]
                except KeyError as err:
                    x['bfd_profile'] = -1
                    parent.stepChanged.emit(f'rNOTE|    Не найден профиль BFD "{err}". Установлено значение по умолчанию. [vrf: "{item["name"]}"]')
        if item['bgp']:
            for x in item['bgp']['neighbors']:
                x['filter_in'] = []
                x['filter_out'] = []
                x['routemap_in'] = []
                x['routemap_out'] = []
                try:
                    x['bfd_profile'] = bfd_profiles[x['bfd_profile']]
                except KeyError as err:
                    x['bfd_profile'] = -1
                    parent.stepChanged.emit(f'rNOTE|    Не найден профиль BFD "{err}". Установлено значение по умолчанию. [vrf: "{item["name"]}"]')

        try:
            if item['name'] in virt_routers:
                parent.stepChanged.emit(f'GRAY|    VRF "{item["name"]}" уже существует.')
                err, result = parent.utm.update_template_vrf(parent.template_id, virt_routers[item['name']], item)
                if err:
                    parent.stepChanged.emit(f'RED|    {result} [vrf: "{item["name"]}"]')
                    error = 1
                else:
                    parent.stepChanged.emit(f'BLACK|    VRF "{item["name"]}" - Updated!')
            else:
                err, result = parent.utm.add_template_vrf(parent.template_id, item)
                if err:
                    parent.stepChanged.emit(f'RED|    {result} [vrf: "{item["name"]}" не импортирован]')
                    error = 1
                else:
                    parent.stepChanged.emit(f'BLACK|    Создан виртуальный маршрутизатор "{item["name"]}".')
        except OverflowError as err:
            parent.stepChanged.emit(f'RED|    Произошла ошибка при импорте виртуального маршрутизатора "{item["name"]}" [{err}].')
            error = 1
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте виртуального маршрутизатора.')
    else:
        parent.stepChanged.emit('GREEN|    Виртуальный маршрутизатор импортирован в раздел "Сеть/Виртуальные маршрутизаторы".')


def import_wccp_rules(parent, path):
    """Импортируем список правил WCCP"""
    json_file = os.path.join(path, 'config_wccp.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт правил WCCP в раздел "Сеть/WCCP".')
    error = 0

    err, result = parent.utm.get_template_wccp_rules(parent.template_id)
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил WCCP.')
        parent.error = 1
        return
    wccp_rules = {x['name']: x['id'] for x in result}

    for item in data:
        item.pop('cc_network_devices', None)    # Если конфиг был экспортирован с МС.
        item.pop('cc_network_devices_negate', None)
        if item['routers']:
            routers = []
            for x in item['routers']:
                if x[0] == 'list_id':
                    try:
                        x[1] = parent.mc_data['ip_lists'][x[1]]
                    except KeyError as err:
                        parent.stepChanged.emit(f'ORANGE|    Не найден список {err} для правила "{item["name"]}". Загрузите списки IP-адресов и повторите попытку.')
                        continue
                routers.append(x)
            item['routers'] = routers

        if item['name'] in wccp_rules:
            parent.stepChanged.emit(f'GRAY|    Правило WCCP "{item["name"]}" уже существует.')
            err, result = parent.utm.update_template_wccp_rule(parent.template_id, wccp_rules[item['name']], item)
            if err:
                parent.stepChanged.emit(f'RED|       {result}')
                error = 1
            else:
                parent.stepChanged.emit(f'GRAY|       Правило WCCP "{item["name"]}" обновлено.')
        else:
            err, result = parent.utm.add_template_wccp_rule(parent.template_id, item)
            if err:
                parent.stepChanged.emit(f'RED|    {result} [Правило WCCP "{item["name"]}" не импортировано]')
                error = 1
            else:
                parent.stepChanged.emit(f'BLACK|    Правило WCCP "{item["name"]}" импортировано.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил WCCP.')
    else:
        parent.stepChanged.emit('GREEN|    Правила WCCP импортированы в раздел "Сеть/WCCP".')

#------------------------------------------- UserGate ------------------------------------------------------------
def import_certificates(parent, path):
    """Импортируем сертификаты"""
    parent.stepChanged.emit('BLUE|Импорт сертификатов в раздел "UserGate/Сертификаты".')

    if not os.path.isdir(path):
        return
    certificates = {entry.name: entry.path for entry in os.scandir(path) if entry.is_dir()}
    if not certificates:
        parent.stepChanged.emit('GRAY|    Нет сертификатов для импорта.')
        return
    error = 0
    
    for cert_name, cert_path in certificates.items():
        files = [entry.name for entry in os.scandir(cert_path) if entry.is_file()]

        json_file = os.path.join(cert_path, 'certificate_list.json')
        err, data = func.read_json_file(parent, json_file, mode=1)
        if err:
            continue

        if 'cert.pem' in files:
            with open(os.path.join(cert_path, 'cert.pem'), mode='rb') as fh:
                cert_data = fh.read()
        elif 'cert.der' in files:
            with open(os.path.join(cert_path, 'cert.der'), mode='rb') as fh:
                cert_data = fh.read()
        else:
            parent.stepChanged.emit(f'NOTE|    Не найден файл сертификата "{cert_name}" для импорта. Будет сгенерирован новый сертификат "{cert_name}".')
            data.update(data['issuer'])
            err, result = parent.utm.new_template_certificate(parent.template_id, data)
            if err == 1:
                parent.stepChanged.emit(f'RED|    {result}')
                error = 1
            elif err == 3:
                parent.stepChanged.emit(f'GRAY|       {result}')
                continue
            else:
                parent.mc_data['certs'][cert_name] = result
                parent.stepChanged.emit(f'BLACK|    Создан новый сертификат "{cert_name}".')
                parent.stepChanged.emit(f'LBLUE|       Необходимо назначить роль новому сертификату "{cert_name}".')
                continue

        if 'key.der' in files:
            with open(os.path.join(cert_path, 'key.der'), mode='rb') as fh:
                key_data = fh.read()
        elif 'key.pem' in files:
            with open(os.path.join(cert_path, 'key.pem'), mode='rb') as fh:
                key_data = fh.read()
        else:
            key_data = None

        if data['name'] in parent.mc_data['certs']:
            parent.stepChanged.emit(f'GRAY|    Сертификат "{cert_name}" уже существует.')
            err, result = parent.utm.update_template_certificate(parent.template_id, parent.mc_data['certs'][data['name']], data, cert_data, private_key=key_data)
            if err:
                parent.stepChanged.emit(f'RED|    {result}')
                error = 1
            else:
                parent.stepChanged.emit(f'BLACK|       Cертификат "{cert_name}" updated.')
        else:
            err, result = parent.utm.add_template_certificate(parent.template_id, data, cert_data, private_key=key_data)
            if err:
                parent.stepChanged.emit(f'RED|    {result}')
                error = 1
            else:
                parent.mc_data['certs'][cert_name] = result
                parent.stepChanged.emit(f'BLACK|    Импортирован сертификат "{cert_name}".')

    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте сертификатов.')
    else:
        parent.stepChanged.emit('GREEN|    Сертификаты импортированы в раздел "UserGate/Сертификаты".')


def import_client_certificate_profiles(parent, path):
    """Импортируем профили пользовательских сертификатов в шаблон"""
    json_file = os.path.join(path, 'users_certificate_profiles.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    if not parent.client_certificate_profiles:
        if get_client_certificate_profiles(parent): # Заполняем атрибут parent.client_certificate_profiles
            return

    parent.stepChanged.emit('BLUE|Импорт раздела "UserGate/Профили клиентских сертификатов".')
    error = 0

    for item in data:
        item['ca_certificates'] = [parent.mc_data['certs'][x] for x in item['ca_certificates']]

        err, result = parent.utm.add_template_client_certificate_profile(parent.template_id, item)
        if err == 1:
            parent.stepChanged.emit(f'RED|    {result}')
            error = 1
        elif err == 3:
            parent.stepChanged.emit(f'GRAY|    {result}')
        else:
            parent.stepChanged.emit(f'BLACK|    Импортирован профиль "{item["name"]}".')
            parent.client_certificate_profiles[item['name']] = result

    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Ошибка импорта профилей клиентских сертификатов!')
    else:
        parent.stepChanged.emit('GREEN|    Импортированы профили клиентских сертификатов в раздел "UserGate/Профили клиентских сертификатов".')


def import_general_settings(parent, path):
    """Импортируем раздел 'UserGate/Настройки'."""
    import_ui(parent, path)
    import_ntp_settings(parent, path)
    import_proxy_port(parent, path)
    import_modules(parent, path)
    import_cache_settings(parent, path)
    import_proxy_exceptions(parent, path)
    import_web_portal_settings(parent, path)
    import_upstream_proxy_settings(parent, path)


def import_ui(parent, path):
    """Импортируем раздел UserGate/Настройки/Настройки интерфейса"""
    json_file = os.path.join(path, 'config_settings_ui.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт раздела "UserGate/Настройки/Настройки интерфейса".')
    params = {
        'ui_timezone': 'Часовой пояс',
        'ui_language': 'Язык интерфейса по умолчанию',
        'web_console_ssl_profile_id': 'Профиль SSL для веб-консоли',
        'response_pages_ssl_profile_id': 'Профиль SSL для страниц блокировки/аутентификации',
        'endpoint_ssl_profile_id': 'Профиль SSL конечного устройства',
        'endpoint_certificate_id': 'Сертификат конечного устройства'
    }
    error = 0

    data.pop('webui_auth_mode', None)
    for key in data:
        if key in params:
            value = data[key]
            if key == 'web_console_ssl_profile_id':
                try:
                    value = parent.mc_data['ssl_profiles'][data[key]]
                except KeyError as err:
                    parent.stepChanged.emit(f'RED|    Не найден профиль SSL "{err}" для "{params[key]}". Загрузите профили SSL и повторите попытку.')
                    error = 1
                    continue
            if key == 'response_pages_ssl_profile_id':
                try:
                    value = parent.mc_data['ssl_profiles'][data[key]]
                except KeyError as err:
                    parent.stepChanged.emit(f'RED|    Не найден профиль SSL "{err}" для "{params[key]}". Загрузите профили SSL и повторите попытку.')
                    error = 1
                    continue
            if key == 'endpoint_ssl_profile_id':
                try:
                    value = parent.mc_data['ssl_profiles'][data[key]]
                except KeyError as err:
                    parent.stepChanged.emit(f'RED|    Не найден профиль SSL "{err}" для "{params[key]}". Загрузите профили SSL и повторите попытку.')
                    error = 1
                    continue
            if key == 'endpoint_certificate_id':
                try:
                    value = parent.mc_data['certs'][data[key]]
                except KeyError as err:
                    parent.stepChanged.emit(f'RED|    Не найден сертификат "{err}" для "{params[key]}". Загрузите сертификаты и повторите попытку.')
                    error = 1
                    continue
            setting = {}
            setting[key] = {'value': value}
            err, result = parent.utm.set_template_settings(parent.template_id, setting)
            if err:
                parent.stepChanged.emit(f'RED|    {result}')
                error = 1
            else:
                parent.stepChanged.emit(f'BLACK|    "{params[key]}" установлен в значение "{data[key]}".')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте настроек интерфейса.')
    else:
        parent.stepChanged.emit('GREEN|    Настройки интерфейса импортированы в раздел "UserGate/Настройки/Настройки интерфейса".')


def import_ntp_settings(parent, path):
    """Импортируем настройки NTP в шаблон"""
    json_file = os.path.join(path, 'config_ntp.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт настроек NTP раздела "UserGate/Настройки/Настройки времени сервера".')
    error = 0
    for i, ntp_server in enumerate(data['ntp_servers']):
        ns = {f'ntp_server{i+1}': {'value': ntp_server}}
        err, result = parent.utm.set_template_settings(parent.template_id, ns)
        if err:
            parent.stepChanged.emit(f'RED|    {result}')
            error = 1
        else:
            parent.stepChanged.emit(f'BLACK|    NTP-сервер {ntp_server} добавлен.')
        if i >= 1:
            break

    err, result = parent.utm.set_template_settings(parent.template_id, {'ntp_enabled': {'value': data['ntp_enabled']}})
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        error = 1
    else:
        parent.stepChanged.emit(f'BLACK|    Использование NTP {"включено" if data["ntp_enabled"] else "отключено"}.')

    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произоша ошибка при импорте настроек NTP.')
    else:
        parent.stepChanged.emit('GREEN|    Импортированы сервера NTP в раздел "Настройки/Настройки времени сервера".')


def import_proxy_port(parent, path):
    """Импортируем HTTP(S)-прокси порт в шаблон"""
    json_file = os.path.join(path, 'config_proxy_port.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт раздела "UserGate/Настройки/Модули/HTTP(S)-прокси порт".')

    err, result = parent.utm.set_template_settings(parent.template_id, {'proxy_server_port': {'value': data}})
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте HTTP(S)-прокси порта.')
    else:
        parent.stepChanged.emit(f'BLACK|    HTTP(S)-прокси порт установлен в значение "{data}"')


def import_modules(parent, path):
    """Импортируем модули"""
    json_file = os.path.join(path, 'config_settings_modules.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт раздела "UserGate/Настройки/Модули".')
    params = {
        'auth_captive': 'Домен Auth captive-портала',
        'logout_captive': 'Домен Logout captive-портала',
        'block_page_domain': 'Домен страницы блокировки',
        'ftpclient_captive': 'FTP поверх HTTP домен',
        'ftp_proxy_enabled': 'FTP поверх HTTP',
        'tunnel_inspection_zone_config': 'Зона для инспектируемых туннелей',
        'lldp_config': 'Настройка LLDP',
    }
    error = 0
    
    for key in data:
        if key in params:
            value = copy.deepcopy(data[key])
            if key == 'tunnel_inspection_zone_config':
                try:
                    value['target_zone'] = parent.mc_data['zones'][value['target_zone']]
                    value.pop('cc', None)
                    data[key].pop('cc', None)   # Удаляем для корректного вывода в лог.
                except KeyError as err:
                    parent.stepChanged.emit(f'RED|    Не найдена зона "{err}" для "{params[key]}". Загрузите зоны и повторите попытку.')
                    error = 1
                    continue
            setting = {}
            setting[key] = {'value': value}
            err, result = parent.utm.set_template_settings(parent.template_id, setting)
            if err:
                parent.stepChanged.emit(f'RED|    {result}')
                error = 1
            else:
                parent.stepChanged.emit(f'BLACK|    Параметр "{params[key]}" установлен в знчение "{data[key]}".')

    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Импорт модулей прошёл с ошибками.')
    else:
        parent.stepChanged.emit('GREEN|    Модули импортированы в раздел "UserGate/Настройки/Модули".')


def import_cache_settings(parent, path):
    """Импортируем раздел 'UserGate/Настройки/Настройки кэширования HTTP'"""
    json_file = os.path.join(path, 'config_proxy_settings.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт разделов "Расширенные настройки" и "Настройки кэширования HTTP" из "UserGate/Настройки".')
    error = 0
    settings = {
        'Настройки кэширования HTTP': {
            'http_cache': {
                'value': {},
                'enabled': False
            }
        },
        'Расширенные настройки': {
            'advanced': {
                'value': {},
                'enabled': False
            }
        }
    }
    for key, value in data.items():
        if key in {'http_cache_mode', 'http_cache_docsize_max', 'http_cache_precache_size'}:
            settings['Настройки кэширования HTTP']['http_cache']['value'][key] = value
        else:
            settings['Расширенные настройки']['advanced']['value'][key] = value
    
    for key in settings:
        err, result = parent.utm.set_template_settings(parent.template_id, settings[key])
        if err:
            parent.stepChanged.emit(f'RED|    {result}')
            error = 1
        else:
            parent.stepChanged.emit(f'BLACK|    {key} импортированы.')

    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка импорта настроек.')
    else:
        parent.stepChanged.emit('GREEN|    Импортированы "Расширенные настройки" и "Настройки кэширования HTTP".')


def import_proxy_exceptions(parent, path):
    """Импортируем раздел UserGate/Настройки/Настройки кэширования HTTP/Исключения кэширования"""
    json_file = os.path.join(path, 'config_proxy_exceptions.json')
    err, exceptions = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт раздела "UserGate/Настройки/Настройки кэширования HTTP/Исключения кэширования".')
    error = 0

    err, nlist = parent.utm.get_template_nlists_list(parent.template_id, 'httpcwl')
    list_id = nlist[0]['id']
    
    for item in exceptions:
        err, result = parent.utm.add_template_nlist_item(parent.template_id, list_id, item)
        if err == 1:
            parent.stepChanged.emit(f'RED|    {result}')
            error = 1
        elif err == 3:
            parent.stepChanged.emit(f'GRAY|    URL "{item["value"]}" уже существует в исключениях кэширования.')
        else:
            parent.stepChanged.emit(f'BLACK|    В исключения кэширования добавлен URL "{item["value"]}".')

#    if exceptions:
#        err, result = parent.utm.set_template_settings(parent.template_id, {'http_cache_exceptions': {'enabled': True}})
#        if err:
#            parent.stepChanged.emit(f'RED|    {result}')
#            error = 1
#            parent.stepChanged.emit('ORANGE|    Произошла ошибка при установке статуса исключения кэширования.')
#        else:
#            parent.stepChanged.emit(f'BLACK|    Исключения кэширования включено.')

    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Ошибка импорта исключений кэширования HTTP.')
    else:
        parent.stepChanged.emit('GREEN|    Исключения кэширования HTTP импортированы".')


def import_web_portal_settings(parent, path):
    """Импортируем раздел 'UserGate/Настройки/Веб-портал'"""
    json_file = os.path.join(path, 'config_web_portal.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт раздела "UserGate/Настройки/Веб-портал".')
    error = 0
    error_message = 'ORANGE|    Произошла ошибка при импорте настроек Веб-портала!'
    out_message = 'GREEN|    Импортирован раздел "UserGate/Настройки/Веб-портал".'

    if not parent.response_pages:
        if get_response_pages(parent):    # Устанавливаем атрибут parent.response_pages
            return

    if not parent.client_certificate_profiles:
        if get_client_certificate_profiles(parent): # Устанавливаем атрибут parent.client_certificate_profiles
            return

    try:
        data['ssl_profile_id'] = parent.mc_data['ssl_profiles'][data['ssl_profile_id']]
    except KeyError as err:
        parent.stepChanged.emit(f'RED|    Error: Не найден профиль SSL {err}". Загрузите профили SSL и повторите попытку.')
        parent.stepChanged.emit(error_message)
        parent.error = 1
        return

    try:
        data['user_auth_profile_id'] = parent.mc_data['auth_profiles'][data['user_auth_profile_id']]
    except KeyError as err:
        parent.stepChanged.emit(f'RED|    Error: Не найден профиль аутентификации {err}". Загрузите профили аутентификации и повторите попытку.')
        parent.stepChanged.emit(error_message)
        parent.error = 1
        return

    if data['client_certificate_profile_id']:
        try:
            data['client_certificate_profile_id'] = parent.client_certificate_profiles[data['client_certificate_profile_id']]
        except KeyError as err:
            parent.stepChanged.emit(f'rNOTE|    Не найден профиль клиентского сертификата {err}". Укажите его вручную или загрузите профили клиентских сертификатов и повторите попытку.')
            data['client_certificate_profile_id'] = 0
            data['cert_auth_enabled'] = False

    if data['certificate_id']:
        try:
            data['certificate_id'] = parent.mc_data['certs'][data['certificate_id']]
        except KeyError as err:
            data['certificate_id'] = -1
            parent.stepChanged.emit(f'rNOTE|    Не найден сертификат {err}". Укажите сертификат вручную или загрузите сертификаты и повторите попытку.')
    else:
        data['certificate_id'] = -1

    if data['proxy_portal_template_id'] != -1:
        try:
            data['proxy_portal_template_id'] = parent.response_pages[data['proxy_portal_template_id']]
        except KeyError as err:
            data['proxy_portal_template_id'] = -1
            parent.stepChanged.emit(f'rNOTE|    Не найден шаблон портала {err}". Укажите шаблон портала вручную или загрузите шаблоны страниц и повторите попытку.')

    if data['proxy_portal_login_template_id'] != -1:
        try:
            data['proxy_portal_login_template_id'] = parent.response_pages[data['proxy_portal_login_template_id']]
        except KeyError as err:
            data['proxy_portal_login_template_id'] = -1
            parent.stepChanged.emit(f'rNOTE|    Не найден шаблон страницы аутентификации {err}". Укажите её вручную или загрузите шаблоны страниц и повторите попытку.')

    settings = {
        'proxy_portal': {
            'value': {},
            'enabled': False
        }
    }
    for key, value in data.items():
        settings['proxy_portal']['value'][key] = value
    
    err, result = parent.utm.set_template_settings(parent.template_id, settings)
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        parent.stepChanged.emit(error_message)
    else:
        parent.stepChanged.emit(out_message)


def import_upstream_proxy_settings(parent, path):
    """Импортируем настройки вышестоящего прокси"""
    json_file = os.path.join(path, 'upstream_proxy_settings.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт настроек раздела "UserGate/Настройки/Вышестоящий прокси".')

    settings = {
        'upstream_proxy': {
            'value': {},
            'enabled': False
        }
    }
    for key, value in data.items():
        settings['upstream_proxy']['value'][key] = value
    
    err, result = parent.utm.set_template_settings(parent.template_id, settings)
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Ошибка импорта настроек вышестоящего прокси!')
    else:
        parent.stepChanged.emit('GREEN|    Импортированы настройки вышестоящего прокси в раздел "UserGate/Настройки/Вышестоящий прокси".')


#---------------------------------------- Пользователи и устройства --------------------------------------------------------
def import_local_groups(parent, path):
    """Импортируем список локальных групп пользователей"""
    json_file = os.path.join(path, 'config_groups.json')
    err, groups = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт локальных групп пользователей в раздел "Пользователи и устройства/Группы".')
    parent.stepChanged.emit(f'LBLUE|    Если используются доменные пользователи, необходимы настроенные LDAP-коннекторы в "Управление областью/Каталоги пользователей"')
    error = 0

    for item in groups:
        users = item.pop('users')
        item['name'] = func.get_restricted_name(item['name'])
        err, result = parent.utm.add_template_group(parent.template_id, item)
        if err == 1:
            parent.stepChanged.emit(f'RED|    {result} [Локальная группа "{item["name"]}" не импортирована]')
            error = 1
            continue
        elif err == 3:
            parent.stepChanged.emit(f'GRAY|    {result}') # В версиях 6 и выше проверяется что группа уже существует.
        else:
            parent.mc_data['local_groups'][item['name']] = result
            parent.stepChanged.emit(f'BLACK|    Локальная группа "{item["name"]}" импортирована.')

        # Добавляем доменных пользователей в группу.
        parent.stepChanged.emit(f'NOTE|       Добавляем доменных пользователей в группу "{item["name"]}".')
        n = 0
        for user_name in users:
            user_array = user_name.split(' ')
            if len(user_array) > 1 and ('\\' in user_array[1]):
                n += 1
                domain, name = user_array[1][1:len(user_array[1])-1].split('\\')
                try:
                    ldap_id = parent.mc_data['ldap_servers'][domain.lower()]
                except KeyError:
                    parent.stepChanged.emit(f'bRED|       Доменный пользователь "{user_name}" не импортирован в группу "{item["name"]}". Нет LDAP-коннектора для домена "{domain}".')
                else:
                    err1, result1 = parent.utm.get_usercatalog_ldap_user_guid(ldap_id, name)
                    if err1:
                        parent.stepChanged.emit(f'RED|       {result1}')
                        error = 1
                        continue
                    elif not result1:
                        parent.stepChanged.emit(f'NOTE|       Нет пользователя "{user_name}" в домене "{domain}". Доменный пользователь не импортирован в группу "{item["name"]}".')
                        continue
                    err2, result2 = parent.utm.add_user_in_template_group(parent.template_id, parent.mc_data['local_groups'][item['name']], result1)
                    if err2:
                        parent.stepChanged.emit(f'RED|       {result2}  [{user_name}]')
                        error = 1
                    else:
                        parent.stepChanged.emit(f'BLACK|       Пользователь "{user_name}" добавлен в группу "{item["name"]}".')
        if not n:
            parent.stepChanged.emit(f'GRAY|       Нет доменных пользователей в группе "{item["name"]}".')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте локальных групп пользователей.')
    else:
        parent.stepChanged.emit('GREEN|    Локальные группы пользователей импортирован в раздел "Пользователи и устройства/Группы".')


def import_local_users(parent, path):
    """Импортируем список локальных пользователей"""
    json_file = os.path.join(path, 'config_users.json')
    err, users = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт локальных пользователей в раздел "Пользователи и устройства/Пользователи".')
    error = 0
    for item in users:
        user_groups = item.pop('groups', None)
        item['name'] = func.get_restricted_name(item['name'])
        item['auth_login'] = func.get_restricted_userlogin(item['auth_login'])
        err, result = parent.utm.add_template_user(parent.template_id, item)
        if err == 1:
            parent.stepChanged.emit(f'RED|    {result}')
            error = 1
            continue
        elif err == 3:
            parent.stepChanged.emit(f'GRAY|    {result}.') # В версиях 6 и выше проверяется что пользователь уже существует.
        else:
            parent.mc_data['local_users'][item['name']] = result
            parent.stepChanged.emit(f'BLACK|    Добавлен локальный пользователь "{item["name"]}".')

        # Добавляем пользователя в группу.
        for group in user_groups:
            try:
                group_guid = parent.mc_data['local_groups'][group]
            except KeyError as err:
                parent.stepChanged.emit(f'bRED|       Не найдена группа {err} для пользователя {item["name"]}. Импортируйте список групп и повторите импорт пользователей.')
            else:
                err2, result2 = parent.utm.add_user_in_template_group(parent.template_id, group_guid, parent.mc_data['local_users'][item['name']])
                if err2:
                    parent.stepChanged.emit(f'RED|       {result2}  [User "{item["name"]}" не добавлен в группу "{group}"]')
                    error = 1
                else:
                    parent.stepChanged.emit(f'BLACK|       Пользователь "{item["name"]}" добавлен в группу "{group}".')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте локальных пользователей.')
    else:
        parent.stepChanged.emit('GREEN|    Локальные пользователи импортированы в раздел "Пользователи и устройства/Пользователи".')


def import_auth_servers(parent, path):
    """Импортируем список серверов аутентификации"""
    import_ldap_servers(parent, path)
    import_ntlm_server(parent, path)
    import_radius_server(parent, path)
    import_tacacs_server(parent, path)
    import_saml_server(parent, path)
    

def import_ldap_servers(parent, path):
    """Импортируем список серверов LDAP"""
    json_file = os.path.join(path, 'config_ldap_servers.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    error = 0
    parent.stepChanged.emit('BLUE|Импорт серверов LDAP в раздел "Пользователи и устройства/Серверы аутентификации".')
    parent.stepChanged.emit(f'LBLUE|    После импорта необходимо включить LDAP-коннекторы, ввести пароль и импортировать keytab файл.')
 
    err, result = parent.utm.get_template_auth_servers(parent.template_id, servers_type='ldap')
    if err == 1:
        parent.stepChanged.emit(f'RED|    {result}')
        error = 1
    else:
        ldap_servers = {x['name']: x['id'] for x in result}

        for item in data:
            item['name'] = func.get_restricted_name(item['name'])
            if item['name'] in ldap_servers:
                parent.stepChanged.emit(f'GRAY|    LDAP-сервер "{item["name"]}" уже существует.')
            else:
                item['enabled'] = False
                item['keytab_exists'] = False
                item['type'] = 'ldap'
                item.pop("cc", None)
                err, result = parent.utm.add_template_auth_server(parent.template_id, item)
                if err:
                    parent.stepChanged.emit(f'RED|    {result}')
                    error = 1
                else:
                    ldap_servers[item['name']] = result
                    parent.stepChanged.emit(f'BLACK|    Сервер аутентификации LDAP "{item["name"]}" импортирован.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте серверов LDAP.')
    else:
        parent.stepChanged.emit('GREEN|    Сервера LDAP импортированы в раздел "Пользователи и устройства/Серверы аутентификации".')


def import_ntlm_server(parent, path):
    """Импортируем список серверов NTLM"""
    json_file = os.path.join(path, 'config_ntlm_servers.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    error = 0
    parent.stepChanged.emit('BLUE|Импорт серверов NTLM в раздел "Пользователи и устройства/Серверы аутентификации".')
    parent.stepChanged.emit(f'LBLUE|    После импорта необходимо включить импортированные сервера аутентификации.')

    err, result = parent.utm.get_template_auth_servers(parent.template_id, servers_type='ntlm')
    if err == 1:
        parent.stepChanged.emit(f'RED|    {result}')
        error = 1
    else:
        ntlm_servers = {x['name']: x['id'] for x in result}

        for item in data:
            item['name'] = func.get_restricted_name(item['name'])
            if item['name'] in ntlm_servers:
                parent.stepChanged.emit(f'GRAY|    NTLM-сервер "{item["name"]}" уже существует.')
            else:
                item['enabled'] = False
                item['type'] = 'ntlm'
                item.pop("cc", None)
                err, result = parent.utm.add_template_auth_server(parent.template_id, item)
                if err:
                    parent.stepChanged.emit(f'RED|    {result}')
                    error = 1
                else:
                    ntlm_servers[item['name']] = result
                    parent.stepChanged.emit(f'BLACK|    Сервер аутентификации NTLM "{item["name"]}" импортироан.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте серверов NTLM.')
    else:
        parent.stepChanged.emit('GREEN|    Сервера NTLM импортированы в раздел "Пользователи и устройства/Серверы аутентификации".')


def import_radius_server(parent, path):
    """Импортируем список серверов RADIUS"""
    json_file = os.path.join(path, 'config_radius_servers.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт серверов RADIUS в раздел "Пользователи и устройства/Серверы аутентификации".')
    parent.stepChanged.emit(f'LBLUE|    После импорта необходимо включить сервера RADIUS и ввести пароль.')
    error = 0

    err, result = parent.utm.get_template_auth_servers(parent.template_id, servers_type='radius')
    if err == 1:
        parent.stepChanged.emit(f'RED|    {result}')
        error = 1
    else:
        radius_servers = {x['name']: x['id'] for x in result}

        for item in data:
            item['name'] = func.get_restricted_name(item['name'])
            if item['name'] in radius_servers:
                parent.stepChanged.emit(f'GRAY|    RADIUS-сервер "{item["name"]}" уже существует.')
            else:
                item['enabled'] = False
                item['type'] = 'radius'
                item.pop("cc", None)
                err, result = parent.utm.add_template_auth_server(parent.template_id, item)
                if err:
                    parent.stepChanged.emit(f'RED|    {result}')
                    error = 1
                else:
                    radius_servers[item['name']] = result
                    parent.stepChanged.emit(f'BLACK|    Сервер аутентификации RADIUS "{item["name"]}" импортирован.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте серверов RADIUS.')
    else:
        parent.stepChanged.emit('GREEN|    Сервера RADIUS импортированы в раздел "Пользователи и устройства/Серверы аутентификации".')


def import_tacacs_server(parent, path):
    """Импортируем список серверов TACACS+"""
    json_file = os.path.join(path, 'config_tacacs_servers.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт серверов TACACS+ в раздел "Пользователи и устройства/Серверы аутентификации".')
    parent.stepChanged.emit(f'LBLUE|    После импорта необходимо включить сервера TACACS+ и ввести секретный ключ.')
    error = 0

    err, result = parent.utm.get_template_auth_servers(parent.template_id, servers_type='tacacs_plus')
    if err == 1:
        parent.stepChanged.emit(f'RED|    {result}')
        error = 1
    else:
        tacacs_servers = {x['name']: x['id'] for x in result}

        for item in data:
            item['name'] = func.get_restricted_name(item['name'])
            if item['name'] in tacacs_servers:
                parent.stepChanged.emit(f'GRAY|    TACACS-сервер "{item["name"]}" уже существует.')
            else:
                item['enabled'] = False
                item['type'] = 'tacacs_plus'
                item.pop("cc", None)
                err, result = parent.utm.add_template_auth_server(parent.template_id, item)
                if err:
                    parent.stepChanged.emit(f'RED|    {result}')
                    error = 1
                else:
                    tacacs_servers[item['name']] = result
                    parent.stepChanged.emit(f'BLACK|    Сервер аутентификации TACACS+ "{item["name"]}" импортирован.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте серверов TACACS+.')
    else:
        parent.stepChanged.emit('GREEN|    Сервера TACACS+ импортированы в раздел "Пользователи и устройства/Серверы аутентификации".')


def import_saml_server(parent, path):
    """Импортируем список серверов SAML"""
    json_file = os.path.join(path, 'config_saml_servers.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт серверов SAML в раздел "Пользователи и устройства/Серверы аутентификации".')
    parent.stepChanged.emit(f'LBLUE|    После импорта необходимо включить сервера SAML и загрузить SAML metadata.')
    error = 0

    err, result = parent.utm.get_template_auth_servers(parent.template_id, servers_type='saml_idp')
    if err == 1:
        parent.stepChanged.emit(f'RED|    {result}')
        error = 1
    else:
        saml_servers = {x['name']: x['id'] for x in result}

        for item in data:
            item['name'] = func.get_restricted_name(item['name'])
            if item['name'] in saml_servers:
                parent.stepChanged.emit(f'GRAY|    SAML-сервер "{item["name"]}" уже существует.')
            else:
                item['enabled'] = False
                item['type'] = 'saml_idp'
                item.pop("cc", None)
                if item['certificate_id']:
                    try:
                        item['certificate_id'] = parent.mc_data['certs'][item['certificate_id']]
                    except KeyError:
                        parent.stepChanged.emit(f'RED|    Error [Сервер SAML "{item["name"]}"]. Не найден сертификат "{item["certificate_id"]}".')
                        item['certificate_id'] = 0
                        error = 1
                err, result = parent.utm.add_template_auth_server(parent.template_id, item)
                if err:
                    parent.stepChanged.emit(f'RED|    {result}')
                    error = 1
                else:
                    saml_servers[item['name']] = result
                    parent.stepChanged.emit(f'BLACK|    Сервер аутентификации SAML "{item["name"]}" добавлен.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте серверов SAML.')
    else:
        parent.stepChanged.emit('GREEN|    Сервера SAML импортированы в раздел "Пользователи и устройства/Серверы аутентификации".')


def import_2fa_profiles(parent, path):
    """Импортируем список 2FA профилей"""
    json_file = os.path.join(path, 'config_2fa_profiles.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт профилей MFA в раздел "Пользователи и устройства/Профили MFA".')
    error = 0

    if not parent.notification_profiles:
        if get_notification_profiles(parent):      # Устанавливаем атрибут parent.notification_profiles
            parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей MFA.')
            return

    err, result = parent.utm.get_template_2fa_profiles(parent.template_id)
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей MFA.')
        parent.error = 1
        return
    else:
        profiles_2fa = {x['name']: x['id'] for x in result}

    for item in data:
        item['name'] = func.get_restricted_name(item['name'])
        if item['name'] in profiles_2fa:
            parent.stepChanged.emit(f'GRAY|    Профиль MFA "{item["name"]}" уже существует.')
        else:
            if item['type'] == 'totp':
                if item['init_notification_profile_id'] not in parent.notification_profiles:
                    parent.stepChanged.emit(f'RED|    Error: Профиль MFA "{item["name"]}" не добавлен. Не найден профиль оповещения "{item["init_notification_profile_id"]}". Загрузите профили оповещения и повторите попытку.')
                    error = 1
                    continue
                item['init_notification_profile_id'] = parent.notification_profiles[item['init_notification_profile_id']]
            else:
                if item['auth_notification_profile_id'] not in parent.notification_profiles:
                    parent.stepChanged.emit(f'RED|    Error: Профиль MFA "{item["name"]}" не добавлен. Не найден профиль оповещения "{item["auth_notification_profile_id"]}". Загрузите профили оповещения и повторите попытку.')
                    error = 1
                    continue
                item['auth_notification_profile_id'] = parent.notification_profiles[item['auth_notification_profile_id']]

            err, result = parent.utm.add_template_2fa_profile(parent.template_id, item)
            if err:
                parent.stepChanged.emit(f'RED|    {result}  [Профиль MFA "{item["name"]}" не импортирован]')
                error = 1
            else:
                profiles_2fa[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Профиль MFA "{item["name"]}" импортирован.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей MFA.')
    else:
        parent.stepChanged.emit('GREEN|    Профили MFA импортированы в раздел "Пользователи и устройства/Профили MFA".')


def import_auth_profiles(parent, path):
    """Импортируем список профилей аутентификации"""
    json_file = os.path.join(path, 'config_auth_profiles.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт профилей аутентификации в раздел "Пользователи и устройства/Профили аутентификации".')
    error = 0

    err, result = parent.utm.get_realm_auth_servers()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей аутентификации.')
        parent.error = 1
        return
    auth_servers = {x['name']: x['id'] for x in result}

    err, result = parent.utm.get_realm_2fa_profiles()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей аутентификации.')
        parent.error = 1
        return
    profiles_2fa = {x['name']: x['id'] for x in result}

    auth_type = {
        'ldap': 'ldap_server_id',
        'radius': 'radius_server_id',
        'tacacs_plus': 'tacacs_plus_server_id',
        'ntlm': 'ntlm_server_id',
        'saml_idp': 'saml_idp_server_id'
    }

    for item in data:
        item['name'] = func.get_restricted_name(item['name'])
        if item['2fa_profile_id']:
            try:
                item['2fa_profile_id'] = profiles_2fa[item['2fa_profile_id']]
            except KeyError:
                parent.stepChanged.emit(f'bRED|    Error [Профиль аутентификации "{item["name"]}"]. Не найден профиль MFA "{item["2fa_profile_id"]}". Загрузите профили MFA и повторите попытку.')
                item['2fa_profile_id'] = False
                error = 1

        for auth_method in item['allowed_auth_methods']:
            if len(auth_method) == 2:
                method_server_id = auth_type[auth_method['type']]
                try:
                    auth_method[method_server_id] = auth_servers[auth_method[method_server_id]]
                except KeyError:
                    parent.stepChanged.emit(f'bRED|    Error [ "{item["name"]}"]. Не найден сервер аутентификации "{auth_method[method_server_id]}". Загрузите серверы аутентификации и повторите попытку.')
                    auth_method.clear()
                    error = 1
        item['allowed_auth_methods'] = [x for x in item['allowed_auth_methods'] if x]

        if item['name'] in parent.mc_data['auth_profiles']:
            parent.stepChanged.emit(f'uGRAY|    Профиль аутентификации "{item["name"]}" уже существует в шаблоне "{parent.mc_data["auth_profiles"][item["name"]]["template_name"]}".')
            if parent.template_id == parent.mc_data['auth_profiles'][item['name']]['template_id']:
                err, result = parent.utm.update_template_auth_profile(parent.template_id, parent.mc_data['auth_profiles'][item['name']]['id'], item)
                if err:
                    parent.stepChanged.emit(f'RED|       {result}  [Profile: "{item["name"]}"]')
                    error = 1
                else:
                    parent.stepChanged.emit(f'uGRAY|       Профиль аутентификации "{item["name"]}" updated.')
        else:
            err, result = parent.utm.add_template_auth_profile(parent.template_id, item)
            if err:
                parent.stepChanged.emit(f'RED|    {result}  [Профиль аутентификации "{item["name"]}" не импортирован]')
                error = 1
            else:
                parent.mc_data['auth_profiles'][item['name']] = {'id': result, 'template_name': parent.templates[parent.template_id] , 'template_id': parent.template_id}
                parent.stepChanged.emit(f'BLACK|    Профиль аутентификации "{item["name"]}" импортирован.')

    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей аутентификации.')
    else:
        parent.stepChanged.emit('GREEN|    Профили аутентификации импортированы в раздел "Пользователи и устройства/Профили аутентификации".')


def import_captive_profiles(parent, path):
    """Импортируем список Captive-профилей"""
    json_file = os.path.join(path, 'config_captive_profiles.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт Captive-профилей в раздел "Пользователи и устройства/Captive-профили".')
    error = 0

    if not parent.response_pages:
        if get_response_pages(parent):    # Устанавливаем атрибут parent.response_pages
            parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте Captive-профилей.')
            return

    if not parent.notification_profiles:
        if get_notification_profiles(parent):      # Устанавливаем атрибут parent.notification_profiles
            parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте Captive-профилей.')
            return

    if not parent.client_certificate_profiles:
        if get_client_certificate_profiles(parent): # Устанавливаем атрибут parent.client_certificate_profiles
            parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте Captive-профилей.')
            return

    if not parent.captive_profiles:
        if get_realm_captive_profiles(parent):      # Устанавливаем атрибут parent.captive_profiles
            parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте Captive-профилей.')
            return

    for item in data:
        item['name'] = func.get_restricted_name(item['name'])
        item['captive_template_id'] = parent.response_pages.get(item['captive_template_id'], -1)
        try:
            item['user_auth_profile_id'] = parent.mc_data['auth_profiles'][item['user_auth_profile_id']]['id']
        except KeyError:
            parent.stepChanged.emit(f'RED|    Error [Captive-profile "{item["name"]}"]. Не найден профиль аутентификации "{item["user_auth_profile_id"]}". Загрузите профили аутентификации и повторите попытку.')
            item['user_auth_profile_id'] = 1
            item['description'] = f'{item["description"]}\nError: Не найден профиль аутентификации "{item["user_auth_profile_id"]}".'
            error = 1

        if item['notification_profile_id'] != -1:
            try:
                item['notification_profile_id'] = parent.notification_profiles[item['notification_profile_id']]
            except KeyError:
                parent.stepChanged.emit(f'RED|    Error [Captive-profile "{item["name"]}"]. Не найден профиль оповещения "{item["notification_profile_id"]}". Загрузите профили оповещения и повторите попытку.')
                item['notification_profile_id'] = -1
                item['description'] = f'{item["description"]}\nError: Не найден профиль оповещения "{item["notification_profile_id"]}".'
                error = 1
        try:
            item['ta_groups'] = [parent.mc_data['local_groups'][name] for name in item['ta_groups']]
        except KeyError as err:
            parent.stepChanged.emit(f'RED|    Error [Captive-profile "{item["name"]}"]. Группа гостевых пользователей "{err}" не найдена в шаблоне. Загрузите локальные группы и повторите попытку.')
            item['ta_groups'] = []
            item['description'] = f'{item["description"]}\nError: Не найдена группа гостевых пользователей "{err}".'
            error = 1

        if item['ta_expiration_date']:
            item['ta_expiration_date'] = item['ta_expiration_date'].replace(' ', 'T')
        else:
            item.pop('ta_expiration_date', None)

        item.pop('use_https_auth', None)
        if item['captive_auth_mode'] != 'aaa':
            item['client_certificate_profile_id'] = parent.client_certificate_profiles.get(item['client_certificate_profile_id'], 0)
            if not item['client_certificate_profile_id']:
                parent.stepChanged.emit(f'RED|    Error [Captive-profile "{item["name"]}"]. Не найден профиль сертификата пользователя "{item["client_certificate_profile_id"]}". Загрузите профили сертификата пользователя и повторите попытку.')
                item['captive_auth_mode'] = 'aaa'
                item['description'] = f'{item["description"]}\nError: Не найден профиль сертификата пользователя "{item["client_certificate_profile_id"]}".'
                error = 1

        if item['name'] in parent.captive_profiles:
            parent.stepChanged.emit(f'uGRAY|    Captive-профиль "{item["name"]}" уже существует.')
            err, result = parent.utm.update_template_captive_profile(parent.template_id, parent.captive_profiles[item['name']], item)
            if err:
                parent.stepChanged.emit(f'RED|       {result}  [Captive-profile "{item["name"]}"]')
                error = 1
            else:
                parent.stepChanged.emit(f'uGRAY|       Captive-профиль "{item["name"]}" updated.')
        else:
            err, result = parent.utm.add_template_captive_profile(parent.template_id, item)
            if err:
                parent.stepChanged.emit(f'RED|    {result}  [Captive-profile "{item["name"]}" не импортирован]')
                error = 1
            else:
                parent.captive_profiles[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Captive-профиль "{item["name"]}" импортирован.')

    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте Captive-профилей.')
    else:
        parent.stepChanged.emit('GREEN|    Captive-профили импортированы в раздел "Пользователи и устройства/Captive-профили".')


def import_captive_portal_rules(parent, path):
    """Импортируем список правил Captive-портала"""
    json_file = os.path.join(path, 'config_captive_portal_rules.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт правил Captive-портала в раздел "Пользователи и устройства/Captive-портал".')
    error = 0

    err, result = parent.utm.get_realm_captive_profiles()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил Captive-портала.')
        parent.error = 1
        return
    captive_profiles = {x['name']: x['id'] for x in result}

    err, result = parent.utm.get_template_captive_portal_rules(parent.template_id)
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил Captive-портала.')
        parent.error = 1
        return
    captive_portal_rules = {x['name']: x['id'] for x in result}

    for item in data:
        item['name'] = func.get_restricted_name(item['name'])
        item.pop('time_created', None)
        item.pop('time_updated', None)
        if item['profile_id']:
            try:
                item['profile_id'] = captive_profiles[item['profile_id']]
            except KeyError:
                parent.stepChanged.emit(f'RED|    Error [Captive-portal "{item["name"]}"]. Captive-профиль "{item["profile_id"]}" не найден. Загрузите Captive-профили и повторите попытку.')
                item['description'] = f'{item["description"]}\nError: Не найден Captive-профиль "{item["profile_id"]}".'
                item['profile_id'] = 0
                error = 1
        item['src_zones'] = get_zones_id(parent, 'src', item['src_zones'], item)
        item['dst_zones'] = get_zones_id(parent, 'dst', item['dst_zones'], item)
        item['src_ips'] = get_ips_id(parent, 'src', item['src_ips'], item)
        item['dst_ips'] = get_ips_id(parent, 'dst', item['dst_ips'], item)
        item['urls'] = get_urls_id(parent, item['urls'], item)
        item['url_categories'] = get_url_categories_id(parent, item)
        item['time_restrictions'] = get_time_restrictions(parent, item)

        if item['name'] in captive_portal_rules:
            parent.stepChanged.emit(f'uGRAY|    Правило Captive-портала "{item["name"]}" уже существует.')
            err, result = parent.utm.update_template_captive_portal_rule(parent.template_id, captive_portal_rules[item['name']], item)
            if err:
                parent.stepChanged.emit(f'RED|       {result}  [Captive-portal "{item["name"]}"]')
                error = 1
            else:
                parent.stepChanged.emit(f'uGRAY|       Правило Captive-портала "{item["name"]}" updated.')
        else:
            err, result = parent.utm.add_template_captive_portal_rule(parent.template_id, item)
            if err:
                parent.stepChanged.emit(f'RED|    {result}  [Captive-portal "{item["name"]}" не импортирован]')
                error = 1
            else:
                captive_portal_rules[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Правило Captive-портала "{item["name"]}" импортировано.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил Captive-портала.')
    else:
        parent.stepChanged.emit('GREEN|    Правила Captive-портала импортированы в раздел "Пользователи и устройства/Captive-портал".')


def import_terminal_servers(parent, path):
    """Импортируем список терминальных серверов"""
    json_file = os.path.join(path, 'config_terminal_servers.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт списка терминальных серверов в раздел "Пользователи и устройства/Терминальные серверы".')
    error = 0

    err, result = parent.utm.get_template_terminal_servers(parent.template_id)
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте списка терминальных серверов.')
        parent.error = 1
        return
    terminal_servers = {x['name']: x['id'] for x in result}

    for item in data:
        item['name'] = func.get_restricted_name(item['name'])
        if item['name'] in terminal_servers:
            parent.stepChanged.emit(f'uGRAY|    Терминальный сервер "{item["name"]}" уже существует.')
            err, result = parent.utm.update_template_terminal_server(parent.template_id, terminal_servers[item['name']], item)
            if err:
                parent.stepChanged.emit(f'RED|       {result}  [Terminal Server: {item["name"]}]')
                error = 1
            else:
                parent.stepChanged.emit(f'uGRAY|       Терминальный сервер "{item["name"]}" updated.')
        else:
            err, result = parent.utm.add_template_terminal_server(parent.template_id, item)
            if err:
                parent.stepChanged.emit(f'RED|    {result}  [Terminal Server "{item["name"]}" не импортирован]')
                error = 1
            else:
                terminal_servers[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Терминальный сервер "{item["name"]}" импортирован.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте списка терминальных серверов.')
    else:
        parent.stepChanged.emit('GREEN|    Список терминальных серверов импортирован в раздел "Пользователи и устройства/Терминальные серверы".')


def import_userid_agent(parent, path):
    """Импортируем настройки UserID агент"""
    import_agent_config(parent, path)
    import_agent_servers(parent, path)


def import_agent_config(parent, path):
    """Импортируем настройки UserID агент"""
    json_file = os.path.join(path, 'userid_agent_config.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    error = 0
    parent.stepChanged.emit('BLUE|Импорт свойств агента UserID в раздел "Пользователи и устройства/Агент UserID".')
    if data['tcp_ca_certificate_id']:
        try:
            data['tcp_ca_certificate_id'] = parent.mc_data['certs'][data['tcp_ca_certificate_id']]
        except KeyError as err:
            parent.stepChanged.emit(f'RED|    Error: Не найден сертификат "{err}". Загрузите сертификаты и повторите попытку.')
            data.pop('tcp_ca_certificate_id', None)
            error = 1
    else:
        data.pop('tcp_ca_certificate_id', None)

    if data['tcp_server_certificate_id']:
        try:
            data['tcp_server_certificate_id'] = parent.mc_data['certs'][data['tcp_server_certificate_id']]
        except KeyError as err:
            parent.stepChanged.emit(f'RED|    Error: Не найден сертификат УЦ "{err}". Загрузите сертификаты и повторите попытку.')
            data.pop('tcp_server_certificate_id', None)
            error = 1
    else:
        data.pop('tcp_server_certificate_id', None)

    new_networks = []
    for x in data['ignore_networks']:
        try:
            new_networks.append(['list_id', parent.mc_data['ip_lists'][x[1]]])
        except KeyError as err:
            parent.stepChanged.emit(f'RED|    Error: Не найден список IP-адресов "{err}" для Ignore Networks. Загрузите списки IP-адресов и повторите попытку.')
            error = 1
    data['ignore_networks'] = new_networks

    err, result = parent.utm.set_template_useridagent_config(parent.template_id, data)
    if err:
        parent.stepChanged.emit(f'RED|    {result} [Свойства агента UserID не импортированы]')
        error = 1

    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте свойств агента UserID.')
    else:
        parent.stepChanged.emit('GREEN|    Свойства агента UserID обновлены.')


def import_agent_servers(parent, path):
    """Импортируем настройки AD и свойств отправителя syslog UserID агент"""
    json_file = os.path.join(path, 'userid_agent_servers.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт Агент UserID в раздел "Пользователи и устройства/Агент UserID".')
    parent.stepChanged.emit(f'LBLUE|    Фильтры Агентов UserID в этой версии МС не переносятся. Необходимо добавить их руками.')
    error = 0

# В версии 7.1 это не работает!!!!!!
#    err, result = parent.utm.get_template_useridagent_filters_list(parent.template_id)
#    if err:
#        parent.stepChanged.emit(f'RED|    {result}')
#        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте агентов UserID.')
#        parent.error = 1
#        return
#    useridagent_filters = {x['name']: x['id'] for x in result}

    err, result = parent.utm.get_template_useridagent_servers(parent.template_id)
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте агентов UserID.')
        parent.error = 1
        return
    useridagent_servers = {x['name']: x['id'] for x in result}

    for item in data:
        item['name'] = func.get_restricted_name(item['name'])
        try:
            item['auth_profile_id'] = parent.mc_data['auth_profiles'][item['auth_profile_id']]
        except KeyError:
            parent.stepChanged.emit(f'RED|    Error [UserID агент "{item["name"]}"]. Не найден профиль аутентификации "{item["auth_profile_id"]}". Загрузите профили аутентификации и повторите попытку.')
            item['description'] = f'{item["description"]}\nError: Не найден профиль аутентификации "{item["auth_profile_id"]}".'
            item['auth_profile_id'] = 1
            error = 1
        if 'filters' in item:
            new_filters = []
            parent.stepChanged.emit(f'ORANGE|    Error [UserID агент "{item["name"]}"]. Не импортированы Syslog фильтры. В вашей версии МС это не работает.')
            for filter_name in item['filters']:
                item['description'] = f'{item["description"]}\nError: Не найден Syslog фильтр UserID агента "{filter_name}".'
#                try:
#                    new_filters.append(useridagent_filters[filter_name])
#                except KeyError:
#                    parent.stepChanged.emit(f'RED|    Error [UserID агент "{item["name"]}"]. Не найден Syslog фильтр "{filter_name}". Загрузите фильтры UserID агента и повторите попытку.')
#                    item['description'] = f'{item["description"]}\nError: Не найден Syslog фильтр UserID агента "{filter_name}".'
#                    error = 1
            item['filters'] = new_filters

        if item['name'] in useridagent_servers:
            parent.stepChanged.emit(f'uGRAY|    UserID агент "{item["name"]}" уже существует.')
            err, result = parent.utm.update_template_useridagent_server(parent.template_id, useridagent_servers[item['name']], item)
            if err:
                parent.stepChanged.emit(f'RED|       {result}  [UserID агент "{item["name"]}"]')
                error = 1
            else:
                parent.stepChanged.emit(f'uGRAY|       UserID агент "{item["name"]}" updated.')
        else:
            err, result = parent.utm.add_template_useridagent_server(parent.template_id, item)
            if err:
                parent.stepChanged.emit(f'RED|    {result}  [UserID агент "{item["name"]}" не импортирован]')
                error = 1
            else:
                useridagent_servers[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    UserID агент "{item["name"]}" импортирован.')
                parent.stepChanged.emit(f'NOTE|       Если вы используете Microsoft AD, необходимо указать пароль.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте агентов UserID.')
    else:
        parent.stepChanged.emit('GREEN|    Агенты UserID импортированы в раздел "Пользователи и устройства/Агент UserID".')

#-------------------------------------- Политики сети ---------------------------------------------------------
def import_firewall_rules(parent, path):
    """Импортировать список правил межсетевого экрана"""
    json_file = os.path.join(path, 'config_firewall_rules.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт правил межсетевого экрана в раздел "Политики сети/Межсетевой экран".')
    err, result = parent.utm.get_template_idps_profiles_list(parent.template_id)
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил межсетевого экрана.')
        parent.error = 1
        return
    idps_profiles = {x['name']: x['id'] for x in result}

    err, result = parent.utm.get_template_l7_profiles_list(parent.template_id)
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил межсетевого экрана.')
        parent.error = 1
        return
    l7_profiles = {x['name']: x['id'] for x in result}

    err, result = parent.utm.get_template_hip_profiles_list(parent.template_id)
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил межсетевого экрана.')
        parent.error = 1
        return
    hip_profiles = {x['name']: x['id'] for x in result}

    err, result = parent.utm.get_template_firewall_rules(parent.template_id)
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил межсетевого экрана.')
        parent.error = 1
        return
    firewall_rules = {x['name']: x['id'] for x in result}

    error = 0
    for item in data:
        item.pop('time_created', None)
        item.pop('time_updated', None)
        item.pop('apps', None)
        item.pop('apps_negate', None)

        item['name'] = func.get_restricted_name(item['name'])
        item['position_layer'] = 'pre'
        if item['scenario_rule_id']:
            try:
                item['scenario_rule_id'] = parent.mc_data['scenarios'][item['scenario_rule_id']]
            except KeyError as err:
                parent.stepChanged.emit(f'RED|    Error [Правило "{item["name"]}"]. Не найден сценарий {err}. Загрузите сценарии и повторите попытку.')
                item['description'] = f'{item["description"]}\nError: Не найден сценарий {err}.'
                item['scenario_rule_id'] = False
                item['enabled'] = False
                error = 1
        if 'ips_profile' in item and item['ips_profile']:
            try:
                item['ips_profile'] = idps_profiles[item['ips_profile']]
            except KeyError as err:
                parent.stepChanged.emit(f'RED|    Error [Правило "{item["name"]}"]: Не найден профиль СОВ {err}. Загрузите профили СОВ и повторите попытку.')
                item['description'] = f'{item["description"]}\nError: Не найден профиль СОВ {err}.'
                item['ips_profile'] = False
                item['enabled'] = False
                error = 1
        else:
            item['ips_profile'] = False
        if 'l7_profile' in item and item['l7_profile']:
            try:
                item['l7_profile'] = l7_profiles[item['l7_profile']]
            except KeyError as err:
                parent.stepChanged.emit(f'RED|    Error [Правило "{item["name"]}"]: Не найден профиль приложений {err}. Загрузите профили приложений и повторите попытку.')
                item['description'] = f'{item["description"]}\nError: Не найден профиль приложений {err}.'
                item['l7_profile'] = False
                item['enabled'] = False
                error = 1
        else:
            item['l7_profile'] = False
        if 'hip_profiles' in item:
            new_hip_profiles = []
            for hip in item['hip_profiles']:
                try:
                    new_hip_profiles.append(hip_profiles[hip])
                except KeyError as err:
                    parent.stepChanged.emit(f'RED|    Error [Правило "{item["name"]}"]: Не найден профиль HIP {err}. Загрузите профили HIP и повторите попытку.')
                    item['description'] = f'{item["description"]}\nError: Не найден профиль HIP {err}.'
                    item['enabled'] = False
                    error = 1
            item['hip_profiles'] = new_hip_profiles
        else:
            item['hip_profiles'] = []

        item['src_zones'] = get_zones_id(parent, 'src', item['src_zones'], item)
        item['dst_zones'] = get_zones_id(parent, 'dst', item['dst_zones'], item)
        item['src_ips'] = get_ips_id(parent, 'src', item['src_ips'], item)
        item['dst_ips'] = get_ips_id(parent, 'dst', item['dst_ips'], item)
        item['users'] = get_guids_users_and_groups(parent, item) if parent.mc_data['ldap_servers'] else []
        item['services'] = get_services(parent, item['services'], item)
        item['time_restrictions'] = get_time_restrictions(parent, item)
        
        if item['name'] in firewall_rules:
            parent.stepChanged.emit(f'uGRAY|    Правило МЭ "{item["name"]}" уже существует.')
            item.pop('position', None)
            err, result = parent.utm.update_template_firewall_rule(parent.template_id, firewall_rules[item['name']], item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|       {result}  [Правило МЭ "{item["name"]}"]')
            else:
                parent.stepChanged.emit(f'uGRAY|       Правило МЭ "{item["name"]}" обновлено.')
        else:
            item['position'] = 'last'
            err, result = parent.utm.add_template_firewall_rule(parent.template_id, item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Правило МЭ "{item["name"]}" не импортировано]')
            else:
                firewall_rules[item['name']] = result
                parent.stepChanged.emit(f'BLACK|   Правило МЭ "{item["name"]}" импортировано.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил межсетевого экрана.')
    else:
        parent.stepChanged.emit('GREEN|    Правила межсетевого экрана импортированы в раздел "Политики сети/Межсетевой экран".')


def import_nat_rules(parent, path):
    """Импортируем список правил NAT"""
    json_file = os.path.join(path, 'config_nat_rules.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт правил NAT в раздел "Политики сети/NAT и маршрутизация".')
    error = 0

    err, result = parent.utm.get_template_gateways_list(parent.template_id)
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил NAT.')
        parent.error = 1
        return
    mc_gateways = {x['name']: f'{x["id"]}:{x["node_name"]}' for x in result if 'name' in x}

    err, result = parent.utm.get_template_traffic_rules(parent.template_id)
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил NAT.')
        parent.error = 1
        return
    nat_rules = {x['name']: x['id'] for x in result}

    for item in data:
        item.pop('time_created', None)
        item.pop('time_updated', None)
        item['name'] = func.get_restricted_name(item['name'])
        item['position_layer'] = 'pre'
        item['zone_in'] = get_zones_id(parent, 'src', item['zone_in'], item)
        item['zone_out'] = get_zones_id(parent, 'dst', item['zone_out'], item)
        item['source_ip'] = get_ips_id(parent, 'src', item['source_ip'], item)
        item['dest_ip'] = get_ips_id(parent, 'dst', item['dest_ip'], item)
        item['service'] = get_services(parent, item['service'], item)
        item['gateway'] = mc_gateways.get(item['gateway'], item['gateway'])
        item['users'] = get_guids_users_and_groups(parent, item) if parent.mc_data['ldap_servers'] else []
        if item['scenario_rule_id']:
            try:
                item['scenario_rule_id'] = parent.mc_data['scenarios'][item['scenario_rule_id']]
            except KeyError as err:
                parent.stepChanged.emit(f'RED|    Error [Правило "{item["name"]}"]: Не найден сценарий {err}. Загрузите сценарии и повторите попытку.')
                item['description'] = f'{item["description"]}\nError: Не найден сценарий {err}.'
                item['scenario_rule_id'] = False
                item['enabled'] = False
                error = 1
        if item['action'] == 'route':
            parent.stepChanged.emit(f'LBLUE|    [Правило "{item["name"]}"]: Проверьте шлюз для правила ПБР. В случае отсутствия, установите вручную.')
            
        if item['name'] in nat_rules:
            parent.stepChanged.emit(f'uGRAY|    Правило "{item["name"]}" уже существует.')
            item.pop('position', None)
            err, result = parent.utm.update_template_traffic_rule(parent.template_id, nat_rules[item['name']], item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|       {result}  [Правило "{item["name"]}"]')
            else:
                parent.stepChanged.emit(f'uGRAY|       Правило "{item["name"]}" updated.')
        else:
            item['position'] = 'last'
            err, result = parent.utm.add_template_traffic_rule(parent.template_id, item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Правило "{item["name"]}" не импортировано]')
            else:
                nat_rules[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Правило "{item["name"]}" импортировано.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил NAT.')
    else:
        parent.stepChanged.emit('GREEN|    Правила NAT импортированы в раздел "Политики сети/NAT и маршрутизация".')


def import_loadbalancing_rules(parent, path):
    """Импортируем правила балансировки нагрузки"""
    parent.stepChanged.emit('BLUE|Импорт правил балансировки нагрузки в раздел "Политики сети/Балансировка нагрузки".')
    err, result = parent.utm.get_template_loadbalancing_rules(parent.template_id)
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил балансировки нагрузки.')
        parent.error = 1
        return
    return

    import_loadbalancing_tcpudp(parent, path, result)
    import_loadbalancing_icap(parent, path, result)
    import_loadbalancing_reverse(parent, path, result)


def import_loadbalancing_tcpudp(parent, path, balansing_servers):
    """Импортируем балансировщики TCP/UDP"""
    json_file = os.path.join(path, 'config_loadbalancing_tcpudp.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err in (2, 3):
        parent.stepChanged.emit(f'GRAY|    Нет балансировщиков TCP/UDP для импорта.')
        return
    elif err == 1:
        return

    parent.stepChanged.emit('BLUE|    Импорт балансировщиков TCP/UDP.')
    tcpudp_rules = {x['name']: x['id'] for x in balansing_servers if x['type'] == 'ipvs'}
    error = 0

    for item in data:
        item['src_zones'] = get_zones_id(parent, 'src', item['src_zones'], item)
        item['src_ips'] = get_ips_id(parent, 'src', item['src_ips'], item)
        item['type'] = 'ipvs'

        item['name'] = func.get_restricted_name(item['name'])
        if item['name'] in tcpudp_rules:
            parent.stepChanged.emit(f'uGRAY|       Правило балансировки TCP/UDP "{item["name"]}" уже существует.')
            err, result = parent.utm.update_template_loadbalancing_rule(parent.template_id, tcpudp_rules[item['name']], item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|          {result}  [Правило "{item["name"]}"]')
            else:
                parent.stepChanged.emit(f'uGRAY|          Правило балансировки TCP/UDP "{item["name"]}" updated.')
        else:
            err, result = parent.utm.add_template_loadbalancing_rule(parent.template_id, item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|       {result}  [Правило "{item["name"]}" не импортировано]')
            else:
                tcpudp_rules[item['name']] = result
                parent.stepChanged.emit(f'BLACK|       Правило балансировки TCP/UDP "{item["name"]}" импортировано.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил балансировки TCP/UDP.')
    else:
        parent.stepChanged.emit('GREEN|    Правила балансировки TCP/UDP импортированы в раздел "Политики сети/Балансировка нагрузки".')


def import_loadbalancing_icap(parent, path, balansing_servers):
    """Импортируем балансировщики ICAP"""
    json_file = os.path.join(path, 'config_loadbalancing_icap.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err in (2, 3):
        parent.stepChanged.emit(f'GRAY|    Нет балансировщиков ICAP для импорта.')
        return
    elif err == 1:
        return

    parent.stepChanged.emit('BLUE|    Импорт балансировщиков ICAP.')
    if not parent.icap_servers:
        if get_icap_servers(parent):      # Устанавливаем атрибут parent.icap_servers
            parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил балансировки ICAP.')
            return

    icap_loadbalancing = {x['name']: x['id'] for x in balansing_servers if x['type'] == 'icap'}
    error = 0

    for item in data:
        item['type'] = 'icap'
        try:
            item['profiles'] = [parent.icap_servers[x] for x in item['profiles']]
        except KeyError as err:
            parent.stepChanged.emit(f'RED|       Error [Правило "{item["name"]}"]: Не найден сервер ICAP {err}. Импортируйте серверы ICAP и повторите попытку.')
            item['description'] = f'{item["description"]}\nError: Не найден сервер ICAP {err}.'
            item['profiles'] = []
            item['enabled'] = False
            error = 1

        item['name'] = func.get_restricted_name(item['name'])
        if item['name'] in icap_loadbalancing:
            parent.stepChanged.emit(f'uGRAY|       Правило балансировки ICAP "{item["name"]}" уже существует.')
            err, result = parent.utm.update_template_loadbalancing_rule(parent.template_id, icap_loadbalancing[item['name']], item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|          {result}  [Правило "{item["name"]}"]')
            else:
                parent.stepChanged.emit(f'uGRAY|          Правило балансировки ICAP "{item["name"]}" updated.')
        else:
            err, result = parent.utm.add_template_loadbalancing_rule(parent.template_id, item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|       {result}  [Правило "{item["name"]}" не импортировано]')
            else:
                icap_loadbalancing[item['name']] = result
                parent.stepChanged.emit(f'BLACK|       Правило балансировки ICAP "{item["name"]}" импортировано.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил балансировки ICAP.')
    else:
        parent.stepChanged.emit('GREEN|    Правила балансировки ICAP импортированы.')


def import_loadbalancing_reverse(parent, path, balansing_servers):
    """Импортируем балансировщики reverse-proxy"""
    json_file = os.path.join(path, 'config_loadbalancing_reverse.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err in (2, 3):
        parent.stepChanged.emit(f'GRAY|    Нет балансировщиков Reverse-proxy для импорта.')
        return
    elif err == 1:
        return

    parent.stepChanged.emit('BLUE|    Импорт балансировщиков Reverse-proxy.')
    if not parent.reverseproxy_servers:
        if get_reverseproxy_servers(parent):      # Устанавливаем атрибут parent.reverseproxy_servers
            parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил балансировки Reverse-proxy.')
            return

    reverse_rules = {x['name']: x['id'] for x in balansing_servers if x['type'] == 'rp'}
    error = 0

    for item in data:
        item['type'] = 'rp'
        try:
            item['profiles'] = [parent.reverseproxy_servers[x] for x in item['profiles']]
        except KeyError as err:
            parent.stepChanged.emit(f'RED|       Error [Правило "{item["name"]}"]. Не найден сервер reverse-proxy {err}. Загрузите серверы reverse-proxy и повторите попытку.')
            item['description'] = f'{item["description"]}\nError: Не найден сервер reverse-proxy {err}.'
            item['enabled'] = False
            item['profiles'] = []
            error = 1

        item['name'] = func.get_restricted_name(item['name'])
        if item['name'] in reverse_rules:
            parent.stepChanged.emit(f'uGRAY|       Правило балансировки reverse-proxy "{item["name"]}" уже существует.')
            err, result = parent.utm.update_template_loadbalancing_rule(parent.template_id, reverse_rules[item['name']], item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|          {result}  [Правило "{item["name"]}"]')
            else:
                parent.stepChanged.emit(f'uGRAY|          Правило балансировки reverse-proxy "{item["name"]}" updated.')
        else:
            err, result = parent.utm.add_template_loadbalancing_rule(parent.template_id, item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|       {result}  [Правило "{item["name"]}" не импортировано]')
            else:
                reverse_rules[item['name']] = result
                parent.stepChanged.emit(f'BLACK|       Правило балансировки reverse-proxy "{item["name"]}" импортировано.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил балансировки Reverse-proxy.')
    else:
        parent.stepChanged.emit('GREEN|    Правила балансировки Reverse-proxy импортированы.')


def import_shaper_rules(parent, path):
    """Импортируем список правил пропускной способности"""
    json_file = os.path.join(path, 'config_shaper_rules.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт правил пропускной способности в раздел "Политики сети/Пропускная способность".')
    error = 0

    err, result = parent.utm.get_template_shapers_list(parent.template_id)
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил пропускной способности.')
        parent.error = 1
        return
    shaper_list = {x['name']: x['id'] for x in result}

    err, result = parent.utm.get_template_shaper_rules(parent.template_id)
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил пропускной способности.')
        parent.error = 1
        return
    shaper_rules = {x['name']: x['id'] for x in result}

    for item in data:
        item['name'] = func.get_restricted_name(item['name'])
        item['position_layer'] = 'pre'
        if item['scenario_rule_id']:
            try:
                item['scenario_rule_id'] = parent.mc_data['scenarios'][item['scenario_rule_id']]
            except KeyError as err:
                parent.stepChanged.emit(f'RED|    Error [Правило "{item["name"]}"]: Не найден сценарий {err}. Загрузите сценарии и повторите попытку.')
                item['description'] = f'{item["description"]}\nError: Не найден сценарий {err}.'
                item['scenario_rule_id'] = False
                item['enabled'] = False
                error = 1
        item['src_zones'] = get_zones_id(parent, 'src', item['src_zones'], item)
        item['dst_zones'] = get_zones_id(parent, 'dst', item['dst_zones'], item)
        item['src_ips'] = get_ips_id(parent, 'src', item['src_ips'], item)
        item['dst_ips'] = get_ips_id(parent, 'dst', item['dst_ips'], item)
        item['services'] = get_services(parent, item['services'], item)
        item['users'] = get_guids_users_and_groups(parent, item) if parent.mc_data['ldap_servers'] else []
        item['apps'] = get_apps(parent, item)
        item['time_restrictions'] = get_time_restrictions(parent, item)
        try:
            item['pool'] = shaper_list[item['pool']]
        except KeyError as err:
            parent.stepChanged.emit(f'RED|    Error [Правило "{item["name"]}"]: Не найдена полоса пропускания "{item["pool"]}". Импортируйте полосы пропускания и повторите попытку.')
            item['description'] = f'{item["description"]}\nError: Не найдена полоса пропускания "{item["pool"]}".'
            item['enabled'] = False
            item['pool'] = 1
            error = 1

        if item['name'] in shaper_rules:
            parent.stepChanged.emit(f'uGRAY|    Правило пропускной способности "{item["name"]}" уже существует.')
            err, result = parent.utm.update_template_shaper_rule(parent.template_id, shaper_rules[item['name']], item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|       {result}  [Правило "{item["name"]}"]')
            else:
                parent.stepChanged.emit(f'uGRAY|       Правило пропускной способности "{item["name"]}" updated.')
        else:
            item['position'] = 'last'
            err, result = parent.utm.add_template_shaper_rule(parent.template_id, item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Правило "{item["name"]}" не импортировано]')
            else:
                shaper_rules[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Правило пропускной способности "{item["name"]}" импортировано.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил пропускной способности.')
    else:
        parent.stepChanged.emit('GREEN|    Правила пропускной способности импортированы в раздел "Политики сети/Пропускная способность".')

#-------------------------------------------- Политики безопасности --------------------------------------------------
def import_content_rules(parent, path):
    """Импортировать список правил фильтрации контента"""
    json_file = os.path.join(path, 'config_content_rules.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт правил фильтрации контента в раздел "Политики безопасности/Фильтрация контента".')
    error = 0

    if not parent.response_pages:
        if get_response_pages(parent):    # Устанавливаем атрибут parent.response_pages
            parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил контентной фильтрации.')
            return

    err, result = parent.utm.get_template_nlists_list(parent.template_id, 'morphology')
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил контентной фильтрации.')
        parent.error = 1
        return
    morphology_list = {x['name']: x['id'] for x in result}

    err, result = parent.utm.get_template_nlists_list(parent.template_id, 'useragent')
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил контентной фильтрации.')
        parent.error = 1
        return
    useragent_list = {x['name']: x['id'] for x in result}

    err, result = parent.utm.get_template_content_rules(parent.template_id)
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил контентной фильтрации.')
        parent.error = 1
        return
    content_rules = {x['name']: x['id'] for x in result}

    for item in data:
        item.pop('time_created', None)
        item.pop('time_updated', None)
        item['name'] = func.get_restricted_name(item['name'])
        item['position_layer'] = 'pre'
        try:
            item['blockpage_template_id'] = parent.response_pages[item['blockpage_template_id']]
        except KeyError as err:
            parent.stepChanged.emit(f'RED|    Error [Правило "{item["name"]}"]. Не найден шаблон страницы блокировки {err}. Импортируйте шаблоны страниц и повторите попытку.')
            item['description'] = f'{item["description"]}\nError: Не найден шаблон страницы блокировки {err}.'
            item['blockpage_template_id'] = -1
            item['enabled'] = False
            error = 1

        item['src_zones'] = get_zones_id(parent, 'src', item['src_zones'], item)
        item['dst_zones'] = get_zones_id(parent, 'dst', item['dst_zones'], item)
        item['src_ips'] = get_ips_id(parent, 'src', item['src_ips'], item)
        item['dst_ips'] = get_ips_id(parent, 'dst', item['dst_ips'], item)
        item['users'] = get_guids_users_and_groups(parent, item) if parent.mc_data['ldap_servers'] else []
        item['url_categories'] = get_url_categories_id(parent, item)
        item['urls'] = get_urls_id(parent, item['urls'], item)
        item['referers'] = get_urls_id(parent, item['referers'], item)
        item['referer_categories'] = get_url_categories_id(parent, item, referer=1)
        item['time_restrictions'] = get_time_restrictions(parent, item)

        if item['scenario_rule_id']:
            try:
                item['scenario_rule_id'] = parent.mc_data['scenarios'][item['scenario_rule_id']]
            except KeyError as err:
                parent.stepChanged.emit(f'RED|    Error [Правило "{item["name"]}"]. Не найден сценарий {err}. Загрузите сценарии и повторите попытку.')
                item['description'] = f'{item["description"]}\nError: Не найден сценарий {err}.'
                item['scenario_rule_id'] = False
                item['enabled'] = False
                error = 1

        new_morph_categories = []
        for x in item['morph_categories']:
            if x in parent.mc_data['ug_morphology']:
                new_morph_categories.append(f'id-{x}')
            else:
                try:
                    new_morph_categories.append(morphology_list[x])
                except KeyError as err:
                    parent.stepChanged.emit(f'RED|    Error [Правило "{item["name"]}"]. Не найден список морфологии {err}. Загрузите списки морфологии и повторите попытку.')
                    item['description'] = f'{item["description"]}\nError: Не найден список морфологии {err}.'
                    item['enabled'] = False
                    error = 1
        item['morph_categories'] = new_morph_categories

        new_user_agents = []
        for x in item['user_agents']:
            if x[1] in parent.mc_data['ug_useragents']:
                new_user_agents.append(['list_id', f'id-{x[1]}'])
            else:
                try:
                    new_user_agents.append(['list_id', useragent_list[x[1]]])
                except KeyError as err:
                    parent.stepChanged.emit(f'RED|    Error [Правило "{item["name"]}"]. Не найден список UserAgent {err}. Загрузите списки UserAgent браузеров и повторите попытку.')
                    item['description'] = f'{item["description"]}\nError: Не найден список UserAgent {err}.'
                    item['enabled'] = False
                    error = 1
        item['user_agents'] = new_user_agents

        new_content_types = []
        for x in item['content_types']:
            try:
                new_content_types.append(parent.mc_data['mime'][x])
            except KeyError as err:
                parent.stepChanged.emit(f'RED|    Error [Правило "{item["name"]}"]. Не найден список типов контента {err}. Загрузите списки типов контента и повторите попытку.')
                item['description'] = f'{item["description"]}\nError: Не найден список типов контента {err}.'
                item['enabled'] = False
                error = 1
        item['content_types'] = new_content_types

        if item['name'] in content_rules:
            parent.stepChanged.emit(f'uGRAY|    Правило контентной фильтрации "{item["name"]}" уже существует.')
            item.pop('position', None)
            err, result = parent.utm.update_template_content_rule(parent.template_id, content_rules[item['name']], item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|       {result}  [Правило "{item["name"]}"]')
            else:
                parent.stepChanged.emit(f'uGRAY|       Правило контентной фильтрации "{item["name"]}" обновлено.')
        else:
            item['position'] = 'last'
            err, result = parent.utm.add_template_content_rule(parent.template_id, item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Правило "{item["name"]}"]')
            else:
                content_rules[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Правило контентной фильтрации "{item["name"]}" импортировано.')

    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил контентной фильтрации.')
    else:
        parent.stepChanged.emit('GREEN|    Правила контентной фильтрации импортированы в раздел "Политики безопасности/Фильтрация контента".')


def import_safebrowsing_rules(parent, path):
    """Импортируем список правил веб-безопасности"""
    json_file = os.path.join(path, 'config_safebrowsing_rules.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт правил веб-безопасности в раздел "Политики безопасности/Веб-безопасность".')
    error = 0

    err, result = parent.utm.get_template_safebrowsing_rules(parent.template_id)
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил веб-безопасности.')
        parent.error = 1
        return
    safebrowsing_rules = {x['name']: x['id'] for x in result}

    for item in data:
        item['name'] = func.get_restricted_name(item['name'])
        item['position_layer'] = 'pre'
        item.pop('time_created', None)
        item.pop('time_updated', None)
        item['src_zones'] = get_zones_id(parent, 'src', item['src_zones'], item)
        item['src_ips'] = get_ips_id(parent, 'src', item['src_ips'], item)
        item['users'] = get_guids_users_and_groups(parent, item) if parent.mc_data['ldap_servers'] else []
        item['time_restrictions'] = get_time_restrictions(parent, item)
        item['url_list_exclusions'] = get_urls_id(parent, item['url_list_exclusions'], item)

        if item['name'] in safebrowsing_rules:
            parent.stepChanged.emit(f'uGRAY|    Правило веб-безопасности "{item["name"]}" уже существует.')
            err, result = parent.utm.update_template_safebrowsing_rule(parent.template_id, safebrowsing_rules[item['name']], item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|       {result}  [Правило веб-безопасности "{item["name"]}"]')
            else:
                parent.stepChanged.emit(f'uGRAY|       Правило веб-безопасности "{item["name"]}" обновлено.')
        else:
            item['position'] = 'last'
            err, result = parent.utm.add_template_safebrowsing_rule(parent.template_id, item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Правило веб-безопасности "{item["name"]}" не импортировано]')
            else:
                safebrowsing_rules[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Правило веб-безопасности "{item["name"]}" импортировано.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил веб-безопасности.')
    else:
        parent.stepChanged.emit('GREEN|    Правила веб-безопасности импортированны в раздел "Политики безопасности/Веб-безопасность".')


def import_tunnel_inspection_rules(parent, path):
    """Импортируем список правил инспектирования туннелей"""
    json_file = os.path.join(path, 'config_tunnelinspection_rules.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт правил инспектирования туннелей в раздел "Политики безопасности/Инспектирование туннелей".')
    error = 0

    err, rules = parent.utm.get_template_tunnel_inspection_rules(parent.template_id)
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил инспектирования туннелей.')
        parent.error = 1
        return
    tunnel_inspect_rules = {x['name']: x['id'] for x in rules}

    for item in data:
        item['name'] = func.get_restricted_name(item['name'])
        item['position_layer'] = 'pre'
        item['src_zones'] = get_zones_id(parent, 'src', item['src_zones'], item)
        item['dst_zones'] = get_zones_id(parent, 'dst', item['dst_zones'], item)
        item['src_ips'] = get_ips_id(parent, 'src', item['src_ips'], item)
        item['dst_ips'] = get_ips_id(parent, 'dst', item['dst_ips'], item)

        if item['name'] in tunnel_inspect_rules:
            parent.stepChanged.emit(f'uGRAY|    Правило инспектирования туннелей "{item["name"]}" уже существует.')
            err, result = parent.utm.update_template_tunnel_inspection_rule(parent.template_id, tunnel_inspect_rules[item['name']], item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|       {result}  [Правило инспектирования туннелей "{item["name"]}"]')
            else:
                parent.stepChanged.emit(f'uGRAY|       Правило инспектирования туннелей "{item["name"]}" обновлено.')
        else:
            item['position'] = 'last'
            err, result = parent.utm.add_template_tunnel_inspection_rule(parent.template_id, item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Правило инспектирования туннелей "{item["name"]}" не импортировано]')
            else:
                tunnel_inspect_rules[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Правило инспектирования туннелей "{item["name"]}" импортировано.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил инспектирования туннелей.')
    else:
        parent.stepChanged.emit('GREEN|    Правила инспектирования туннелей импортированны в раздел "Политики безопасности/Инспектирование туннелей".')


def import_ssldecrypt_rules(parent, path):
    """Импортируем список правил инспектирования SSL"""
    json_file = os.path.join(path, 'config_ssldecrypt_rules.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт правил инспектирования SSL в раздел "Политики безопасности/Инспектирование SSL".')
    error = 0

    err, rules = parent.utm.get_template_ssl_forward_profiles(parent.template_id)
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил инспектирования SSL.')
        parent.error = 1
        return
    ssl_forward_profiles = {x['name']: x['id'] for x in rules}
    ssl_forward_profiles[-1] = -1

    err, rules = parent.utm.get_template_ssldecrypt_rules(parent.template_id)
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил инспектирования SSL.')
        parent.error = 1
        return
    ssldecrypt_rules = {x['name']: x['id'] for x in rules}

    for item in data:
        item['name'] = func.get_restricted_name(item['name'])
        item['position_layer'] = 'pre'
        item.pop('time_created', None)
        item.pop('time_updated', None)
        item['users'] = get_guids_users_and_groups(parent, item) if parent.mc_data['ldap_servers'] else []
        item['src_zones'] = get_zones_id(parent, 'src', item['src_zones'], item)
        item['src_ips'] = get_ips_id(parent, 'src', item['src_ips'], item)
        item['dst_ips'] = get_ips_id(parent, 'dst', item['dst_ips'], item)
        item['url_categories'] = get_url_categories_id(parent, item)
        item['urls'] = get_urls_id(parent, item['urls'], item)
        item['time_restrictions'] = get_time_restrictions(parent, item)
        try:
            item['ssl_profile_id'] = parent.mc_data['ssl_profiles'][item['ssl_profile_id']]
        except KeyError as err:
            parent.stepChanged.emit(f'RED|    Error [Правило "{item["name"]}"]. Не найден профиль SSL {err}. Загрузите профили SSL и повторите импорт.')
            item['description'] = f'{item["description"]}\nError: Не найден профиль SSL {err}.'
            item['ssl_profile_id'] = parent.mc_data['ssl_profiles']['Default SSL profile']
            item['enabled'] = False
            error = 1
        try:
            item['ssl_forward_profile_id'] = ssl_forward_profiles[item['ssl_forward_profile_id']]
        except KeyError as err:
            parent.stepChanged.emit(f'RED|    Error [Правило "{item["name"]}"]. Не найден профиль пересылки SSL {err}. Загрузите профили пересылки SSL и повторите импорт.')
            item['description'] = f'{item["description"]}\nError: Не найден профиль пересылки SSL {err}.'
            item['ssl_forward_profile_id'] = -1
            item['enabled'] = False
            error = 1

        if item['name'] in ssldecrypt_rules:
            parent.stepChanged.emit(f'uGRAY|    Правило инспектирования SSL "{item["name"]}" уже существует.')
            err, result = parent.utm.update_template_ssldecrypt_rule(parent.template_id, ssldecrypt_rules[item['name']], item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|       {result}  [Правило инспектирования SSL "{item["name"]}"]')
                continue
            else:
                parent.stepChanged.emit(f'uGRAY|       Правило инспектирования SSL "{item["name"]}" обновлено.')
        else:
            item['position'] = 'last'
            err, result = parent.utm.add_template_ssldecrypt_rule(parent.template_id, item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Правило инспектирования SSL "{item["name"]}" не импортировано]')
                continue
            else:
                ssldecrypt_rules[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Правило инспектирования SSL "{item["name"]}" импортировано.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил инспектирования SSL.')
    else:
        parent.stepChanged.emit('GREEN|    Правила инспектирования SSL импортированны в раздел "Политики безопасности/Инспектирование SSL".')


def import_sshdecrypt_rules(parent, path):
    """Импортируем список правил инспектирования SSH"""
    json_file = os.path.join(path, 'config_sshdecrypt_rules.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт правил инспектирования SSH в раздел "Политики безопасности/Инспектирование SSH".')
    error = 0

    err, rules = parent.utm.get_template_sshdecrypt_rules(parent.template_id)
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил инспектирования SSH.')
        parent.error = 1
        return
    sshdecrypt_rules = {x['name']: x['id'] for x in rules}

    for item in data:
        item['name'] = func.get_restricted_name(item['name'])
        item['position_layer'] = 'pre'
        item.pop('time_created', None)
        item.pop('time_updated', None)
        item['users'] = get_guids_users_and_groups(parent, item) if parent.mc_data['ldap_servers'] else []
        item['src_zones'] = get_zones_id(parent, 'src', item['src_zones'], item)
        item['src_ips'] = get_ips_id(parent, 'src', item['src_ips'], item)
        item['dst_ips'] = get_ips_id(parent, 'dst', item['dst_ips'], item)
        item['time_restrictions'] = get_time_restrictions(parent, item)
        item['protocols'] = get_services(parent, item['protocols'], item)

        if item['name'] in sshdecrypt_rules:
            parent.stepChanged.emit(f'uGRAY|    Правило инспектирования SSH "{item["name"]}" уже существует.')
            err, result = parent.utm.update_template_sshdecrypt_rule(parent.template_id, sshdecrypt_rules[item['name']], item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|       {result}  [Правило инспектирования SSH "{item["name"]}"]')
                continue
            else:
                parent.stepChanged.emit(f'uGRAY|       Правило инспектирования SSH "{item["name"]}" обновлено.')
        else:
            item['position'] = 'last'
            err, result = parent.utm.add_template_sshdecrypt_rule(parent.template_id, item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Правило инспектирования SSH "{item["name"]}" не импортировано]')
                continue
            else:
                sshdecrypt_rules[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Правило инспектирования SSH "{item["name"]}" импортировано.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил инспектирования SSH.')
    else:
        parent.stepChanged.emit('GREEN|    Правила инспектирования SSH импортированны в раздел "Политики безопасности/Инспектирование SSH".')


def import_mailsecurity(parent, path):
    import_mailsecurity_rules(parent, path)
    import_mailsecurity_antispam(parent, path)

def import_mailsecurity_rules(parent, path):
    """Импортируем список правил защиты почтового трафика"""
    json_file = os.path.join(path, 'config_mailsecurity_rules.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт правил защиты почтового трафика в раздел "Политики безопасности/Защита почтового трафика".')
    error = 0

    err, result = parent.utm.get_template_nlists_list(parent.template_id, 'emailgroup')
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил защиты почтового трафика.')
        parent.error = 1
        return
    email = {x['name']: x['id'] for x in result}

    err, result = parent.utm.get_template_mailsecurity_rules(parent.template_id)
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил защиты почтового трафика.')
        parent.error = 1
        return
    mailsecurity_rules = {x['name']: x['id'] for x in result}

    for item in data:
        item['name'] = func.get_restricted_name(item['name'])
        item['position_layer'] = 'pre'
        item['src_zones'] = get_zones_id(parent, 'src', item['src_zones'], item)
        item['dst_zones'] = get_zones_id(parent, 'dst', item['dst_zones'], item)
        item['src_ips'] = get_ips_id(parent, 'src', item['src_ips'], item)
        item['dst_ips'] = get_ips_id(parent, 'dst', item['dst_ips'], item)
        item['users'] = get_guids_users_and_groups(parent, item) if parent.mc_data['ldap_servers'] else []
        if not item['services']:
            item['services'] = [['service', 'SMTP'], ['service', 'POP3'], ['service', 'SMTPS'], ['service', 'POP3S']]
        item['services'] = get_services(parent, item['services'], item)

        try:
            item['envelope_from'] = [[x[0], email[x[1]]] for x in item['envelope_from']]
        except KeyError as err:
            parent.stepChanged.emit(f'RED|    Error [Правило "{item["name"]}"]. Не найден список почтовых адресов {err}. Загрузите список почтовых адресов и повторите попытку.')
            item['description'] = f'{item["description"]}\nError: Не найден список почтовых адресов {err}.'
            item['envelope_from'] = []
            item['enabled'] = False
            error = 1

        try:
            item['envelope_to'] = [[x[0], email[x[1]]] for x in item['envelope_to']]
        except KeyError as err:
            parent.stepChanged.emit(f'RED|    Error [Правило "{item["name"]}"]. Не найден список почтовых адресов {err}. Загрузите список почтовых адресов и повторите попытку.')
            item['description'] = f'{item["description"]}\nError: Не найден список почтовых адресов {err}.'
            item['envelope_to'] = []
            item['enabled'] = False
            error = 1

        if item['name'] in mailsecurity_rules:
            parent.stepChanged.emit(f'uGRAY|    Правило "{item["name"]}" уже существует.')
            err, result = parent.utm.update_template_mailsecurity_rule(parent.template_id, mailsecurity_rules[item['name']], item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|       {result}  [Правило "{item["name"]}"]')
            else:
                parent.stepChanged.emit(f'uGRAY|       Правило "{item["name"]}" обновлено.')
        else:
            item['position'] = 'last'
            err, result = parent.utm.add_template_mailsecurity_rule(parent.template_id, item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Правило "{item["name"]}" не импортировано]')
            else:
                mailsecurity_rules[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Правило "{item["name"]}" импортировано.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил защиты почтового трафика.')
    else:
        parent.stepChanged.emit('GREEN|    Правила защиты почтового трафика импортированы в раздел "Политики безопасности/Защита почтового трафика".')


def import_mailsecurity_antispam(parent, path):
    """Импортируем dnsbl и batv защиты почтового трафика"""
    json_file = os.path.join(path, 'config_mailsecurity_dnsbl.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    json_file = os.path.join(path, 'config_mailsecurity_batv.json')
    err, batv = func.read_json_file(parent, json_file, mode=1)
    if err:
        data['enabled'] = False
    else:
        data['enabled'] = batv['enabled']

    parent.stepChanged.emit('BLUE|Импорт настроек антиспама защиты почтового трафика в раздел "Политики безопасности/Защита почтового трафика".')

    data['white_list'] = get_ips_id(parent, 'white_list', data['white_list'], {'name': 'antispam DNSBL'})
    data['black_list'] = get_ips_id(parent, 'black_list', data['black_list'], {'name': 'antispam DNSBL'})

    err, result = parent.utm.set_template_mailsecurity_antispam(parent.template_id, data)
    if err:
        parent.error = 1
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте настроек антиспама.')
    else:
        parent.stepChanged.emit(f'GREEN|    Настройки антиспама импортированы.')


def import_icap_servers(parent, path):
    """Импортируем список серверов ICAP"""
    json_file = os.path.join(path, 'config_icap_servers.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт серверов ICAP в раздел "Политики безопасности/ICAP-серверы".')
    error = 0

    if not parent.icap_servers:
        if get_icap_servers(parent):      # Устанавливаем атрибут parent.icap_servers
            parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте серверов ICAP.')
            return

    for item in data:
        item['name'] = func.get_restricted_name(item['name'])
        if item['name'] in parent.icap_servers:
            parent.stepChanged.emit(f'uGRAY|    ICAP-сервер "{item["name"]}" уже существует.')
            err, result = parent.utm.update_template_icap_server(parent.template_id, parent.icap_servers[item['name']], item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|       {result}  [ICAP-сервер "{item["name"]}"]')
            else:
                parent.stepChanged.emit(f'uGRAY|       ICAP-сервер "{item["name"]}" обновлён.')
        else:
            item['position'] = 'last'
            err, result = parent.utm.add_template_icap_server(parent.template_id, item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [ICAP-сервер "{item["name"]}" не импортирован]')
            else:
                parent.icap_servers[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    ICAP-сервер "{item["name"]}" импортирован.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте серверов ICAP.')
    else:
        parent.stepChanged.emit('GREEN|    Серверы ICAP импортированы в раздел "Политики безопасности/ICAP-серверы".')


def import_icap_rules(parent, path):
    """Импортируем список правил ICAP"""
    json_file = os.path.join(path, 'config_icap_rules.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт правил ICAP в раздел "Политики безопасности/ICAP-правила".')
    error = 0

    if not parent.icap_servers:
        if get_icap_servers(parent):      # Устанавливаем атрибут parent.icap_servers
            parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил ICAP.')
            return

    err, result = parent.utm.get_template_loadbalancing_rules(parent.template_id, query={'query': 'type = icap'})
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил ICAP.')
        parent.error = 1
        return
    icap_loadbalancing = {x['name']: x['id'] for x in result}

    err, result = parent.utm.get_template_icap_rules(parent.template_id)
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил ICAP.')
        parent.error = 1
        return
    icap_rules = {x['name']: x['id'] for x in result}

    for item in data:
        item['name'] = func.get_restricted_name(item['name'])
        item['position_layer'] = 'pre'
        item.pop('time_created', None)
        item.pop('time_updated', None)

        new_servers = []
        for server in item['servers']:
            if server[0] == 'lbrule':
                try:
                    new_servers.append(['lbrule', icap_loadbalancing[server[1]]])
                except KeyError as err:
                    parent.stepChanged.emit(f'RED|    Error [Правило "{item["name"]}"]. Не найден балансировщик серверов ICAP {err}. Импортируйте балансировщики ICAP и повторите попытку.')
                    item['description'] = f'{item["description"]}\nError: Не найден балансировщик серверов ICAP {err}.'
                    item['enabled'] = False
                    error = 1
            elif server[0] == 'profile':
                try:
                    new_servers.append(['profile', parent.icap_servers[server[1]]])
                except KeyError as err:
                    parent.stepChanged.emit(f'RED|    Error [Правило "{item["name"]}"]. Не найден сервер ICAP {err}. Импортируйте сервера ICAP и повторите попытку.')
                    item['description'] = f'{item["description"]}\nError: Не найден сервер ICAP {err}.'
                    item['enabled'] = False
                    error = 1
        item['servers'] = new_servers

        item['users'] = get_guids_users_and_groups(parent, item) if parent.mc_data['ldap_servers'] else []
        item['src_zones'] = get_zones_id(parent, 'src', item['src_zones'], item)
        item['src_ips'] = get_ips_id(parent, 'src', item['src_ips'], item)
        item['dst_ips'] = get_ips_id(parent, 'dst', item['dst_ips'], item)
        item['url_categories'] = get_url_categories_id(parent, item)
        item['urls'] = get_urls_id(parent, item['urls'], item)
        new_content_types = []
        for x in item['content_types']:
            try:
                new_content_types.append(parent.mc_data['mime'][x])
            except KeyError as err:
                parent.stepChanged.emit(f'RED|    Error [Правило "{item["name"]}"]: Не найден список типов контента {err}. Загрузите списки типов контента и повторите попытку.')
                item['description'] = f'{item["description"]}\nError: Не найден список типов контента {err}.'
                item['enabled'] = False
                error = 1
        item['content_types'] = new_content_types

        if item['name'] in icap_rules:
            parent.stepChanged.emit(f'uGRAY|    ICAP-правило "{item["name"]}" уже существует.')
            err, result = parent.utm.update_template_icap_rule(parent.template_id, icap_rules[item['name']], item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|       {result}  [ICAP-правило "{item["name"]}"]')
            else:
                parent.stepChanged.emit(f'uGRAY|       ICAP-правило "{item["name"]}" обновлено.')
        else:
            item['position'] = 'last'
            err, result = parent.utm.add_template_icap_rule(parent.template_id, item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [ICAP-правило "{item["name"]}" не импортировано]')
            else:
                icap_rules[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    ICAP-правило "{item["name"]}" импортировано.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил ICAP.')
    else:
        parent.stepChanged.emit('GREEN|    Правила ICAP импортированы в раздел "Политики безопасности/ICAP-правила".')


def import_dos_profiles(parent, path):
    """Импортируем список профилей DoS"""
    json_file = os.path.join(path, 'config_dos_profiles.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт профилей DoS в раздел "Политики безопасности/Профили DoS".')
    error = 0

    err, result = parent.utm.get_template_dos_profiles(parent.template_id)
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей DoS.')
        parent.error = 1
        return
    dos_profiles = {x['name']: x['id'] for x in result}

    for item in data:
        item['name'] = func.get_restricted_name(item['name'])
        if item['name'] in dos_profiles:
            parent.stepChanged.emit(f'uGRAY|    Профиль DoS "{item["name"]}" уже существует.')
            err, result = parent.utm.update_template_dos_profile(parent.template_id, dos_profiles[item['name']], item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|       {result}  [Профиль DoS "{item["name"]}"]')
            else:
                parent.stepChanged.emit(f'uGRAY|       Профиль DoS "{item["name"]}" обновлён.')
        else:
            err, result = parent.utm.add_template_dos_profile(parent.template_id, item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Профиль DoS "{item["name"]}" не импортирован]')
            else:
                dos_profiles[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Профиль DoS "{item["name"]}" импортирован.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей DoS.')
    else:
        parent.stepChanged.emit('GREEN|    Профили DoS импортированы в раздел "Политики безопасности/Профили DoS".')


def import_dos_rules(parent, path):
    """Импортируем список правил защиты DoS"""
    json_file = os.path.join(path, 'config_dos_rules.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт правил защиты DoS в раздел "Политики безопасности/Правила защиты DoS".')
    error = 0

    err, result = parent.utm.get_template_dos_profiles(parent.template_id)
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил защиты DoS.')
        parent.error = 1
        return
    dos_profiles = {x['name']: x['id'] for x in result}

    err, result = parent.utm.get_template_dos_rules(parent.template_id)
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил защиты DoS.')
        parent.error = 1
        return
    dos_rules = {x['name']: x['id'] for x in result}

    for item in data:
        item['name'] = func.get_restricted_name(item['name'])
        item['position_layer'] = 'pre'
        item['src_zones'] = get_zones_id(parent, 'src', item['src_zones'], item)
        item['dst_zones'] = get_zones_id(parent, 'dst', item['dst_zones'], item)
        item['src_ips'] = get_ips_id(parent, 'src', item['src_ips'], item)
        item['dst_ips'] = get_ips_id(parent, 'dst', item['dst_ips'], item)
        item['users'] = get_guids_users_and_groups(parent, item) if parent.mc_data['ldap_servers'] else []
        item['services'] = get_services(parent, item['services'], item)
        item['time_restrictions'] = get_time_restrictions(parent, item)
        if item['dos_profile']:
            try:
                item['dos_profile'] = dos_profiles[item['dos_profile']]
            except KeyError as err:
                parent.stepChanged.emit(f'RED|    Error [Правило "{item["name"]}"]. Не найден профиль DoS {err}. Импортируйте профили DoS и повторите попытку.')
                item['description'] = f'{item["description"]}\nError: Не найден профиль DoS {err}.'
                item['dos_profile'] = False
                item['enabled'] = False
                error = 1
        if item['scenario_rule_id']:
            try:
                item['scenario_rule_id'] = parent.mc_data['scenarios'][item['scenario_rule_id']]
            except KeyError as err:
                parent.stepChanged.emit(f'RED|    Error [Правило "{item["name"]}"]. Не найден сценарий {err}. Импортируйте сценарии и повторите попытку.')
                item['description'] = f'{item["description"]}\nError: Не найден сценарий {err}.'
                item['scenario_rule_id'] = False
                item['enabled'] = False
                error = 1

        if item['name'] in dos_rules:
            parent.stepChanged.emit(f'uGRAY|    Правило защиты DoS "{item["name"]}" уже существует.')
            err, result = parent.utm.update_template_dos_rule(parent.template_id, dos_rules[item['name']], item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|       {result}  [Правило защиты DoS "{item["name"]}"]')
            else:
                parent.stepChanged.emit(f'uGRAY|       Правило защиты DoS "{item["name"]}" обновлено.')
        else:
            item['position'] = 'last'
            err, result = parent.utm.add_template_dos_rule(parent.template_id, item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Правило защиты DoS "{item["name"]}" не импортировано]')
            else:
                dos_rules[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Правило защиты DoS "{item["name"]}" импортировано.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил защиты DoS.')
    else:
        parent.stepChanged.emit('GREEN|    Правила защиты DoS импортированы в раздел "Политики безопасности/Правила защиты DoS".')


#-------------------------------------------- Глобальный портал --------------------------------------------------
def import_proxyportal_rules(parent, path):
    """Импортируем список URL-ресурсов веб-портала"""
    parent.stepChanged.emit('BLUE|Импорт списка ресурсов веб-портала в раздел "Глобальный портал/Веб-портал".')
    json_file = os.path.join(path, 'config_web_portal.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return
    error = 0

    err, result = parent.utm.get_template_proxyportal_rules(parent.template_id)
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте ресурсов веб-портала.')
        parent.error = 1
        return
    list_proxyportal = {x['name']: x['id'] for x in result}

    for item in data:
        item['name'] = func.get_restricted_name(item['name'])
        item['position_layer'] = 'pre'
        item['users'] = get_guids_users_and_groups(parent, item) if parent.mc_data['ldap_servers'] else []
        try:
            if item['mapping_url_ssl_profile_id']:
                item['mapping_url_ssl_profile_id'] = parent.mc_data['ssl_profiles'][item['mapping_url_ssl_profile_id']]
        except KeyError as err:
            parent.stepChanged.emit(f'RED|    Error [Правило "{item["name"]}"]. Не найден профиль SSL {err}. Загрузите профили SSL и повторите попытку.')
            item['description'] = f'{item["description"]}\nError: Не найден профиль SSL {err}.'
            item['mapping_url_ssl_profile_id'] = 0
            item['enabled'] = False
            error = 1
        try:
            if item['mapping_url_certificate_id']:
                item['mapping_url_certificate_id'] = parent.mc_data['certs'][item['mapping_url_certificate_id']]
        except KeyError as err:
            parent.stepChanged.emit(f'RED|    Error [Правило "{item["name"]}"]. Не найден сертификат {err}. Создайте сертификат и повторите попытку.')
            item['description'] = f'{item["description"]}\nError: Не найден сертификат {err}.'
            item['mapping_url_certificate_id'] = 0
            item['enabled'] = False
            error = 1

        if item['name'] in list_proxyportal:
            parent.stepChanged.emit(f'uGRAY|    Ресурс веб-портала "{item["name"]}" уже существует.')
            err, result = parent.utm.update_template_proxyportal_rule(parent.template_id, list_proxyportal[item['name']], item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|       {result}  [Ресурс веб-портала "{item["name"]}"]')
            else:
                parent.stepChanged.emit(f'uGRAY|       Ресурс веб-портала "{item["name"]}" обновлён.')
        else:
            item['position'] = 'last'
            err, result = parent.utm.add_template_proxyportal_rule(parent.template_id, item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Ресурс веб-портала "{item["name"]}" не импортирован]')
            else:
                list_proxyportal[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Ресурс веб-портала "{item["name"]}" импортирован.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте ресурсов веб-портала.')
    else:
        parent.stepChanged.emit('GREEN|    Список ресурсов веб-портала импортирован в раздел "Глобальный портал/Веб-портал".')


def import_reverseproxy_servers(parent, path):
    """Импортируем список серверов reverse-прокси"""
    json_file = os.path.join(path, 'config_reverseproxy_servers.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт серверов reverse-прокси в раздел "Глобальный портал/Серверы reverse-прокси".')
    error = 0

    if not parent.reverseproxy_servers:
        if get_reverseproxy_servers(parent):      # Устанавливаем атрибут parent.reverseproxy_servers
            parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте серверов reverse-прокси.')
            return

    for item in data:
        item['name'] = func.get_restricted_name(item['name'])
        if item['name'] in parent.reverseproxy_servers:
            parent.stepChanged.emit(f'uGRAY|    Сервер reverse-прокси "{item["name"]}" уже существует.')
            err, result = parent.utm.update_template_reverseproxy_server(parent.template_id, parent.reverseproxy_servers[item['name']], item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|       {result}  [Сервер reverse-прокси "{item["name"]}"]')
            else:
                parent.stepChanged.emit(f'uGRAY|       Сервер reverse-прокси "{item["name"]}" обновлён.')
        else:
            err, result = parent.utm.add_template_reverseproxy_server(parent.template_id, item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Сервер reverse-прокси "{item["name"]}" не импортирован]')
            else:
                parent.reverseproxy_servers[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Сервер reverse-прокси "{item["name"]}" импортирован.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте серверов reverse-прокси.')
    else:
        parent.stepChanged.emit('GREEN|    Сервера reverse-прокси импортированы в раздел "Глобальный портал/Серверы reverse-прокси".')


def import_reverseproxy_rules(parent, path):
    """Импортируем список правил reverse-прокси"""
    json_file = os.path.join(path, 'config_reverseproxy_rules.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт правил reverse-прокси в раздел "Глобальный портал/Правила reverse-прокси".')
    error = 0

    err, result = parent.utm.get_template_loadbalancing_rules(parent.template_id, query={'query': 'type = reverse'})
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил reverse-прокси.')
        parent.error = 1
        return
    reverse_loadbalancing = {x['name']: x['id'] for x in result}

    if not parent.reverseproxy_servers:
        if get_reverseproxy_servers(parent):      # Устанавливаем атрибут parent.reverseproxy_servers
            parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил reverse-прокси.')
            return

    err, result = parent.utm.get_template_nlists_list(parent.template_id, 'useragent')
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил reverse-прокси.')
        parent.error = 1
        return
    useragent_list = {x['name']: x['id'] for x in result}

    if not parent.client_certificate_profiles:
        if get_client_certificate_profiles(parent): # Устанавливаем атрибут parent.client_certificate_profiles
            parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил reverse-прокси.')
            return

    waf_profiles = {}
    if parent.utm.waf_license:  # Проверяем что есть лицензия на WAF
        # Получаем список профилей WAF. Если err=2, лицензия истекла или нет прав на API.
        err, result = parent.utm.get_template_waf_profiles(parent.template_id)
        if err == 1:
            parent.stepChanged.emit(f'RED|    {result}')
            parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил reverse-прокси.')
            parent.error = 1
            return
        elif not err:
            waf_profiles = {x['name']: x['id'] for x in result}
    else:
        parent.stepChanged.emit('NOTE|    Нет лицензии на WAF. Защита приложений WAF будет выключена в правилах.')

    err, result = parent.utm.get_template_reverseproxy_rules(parent.template_id)
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил reverse-прокси.')
        parent.error = 1
        return
    reverseproxy_rules = {x['name']: x['id'] for x in result}

    for item in data:
        item['name'] = func.get_restricted_name(item['name'])
        item['position_layer'] = 'pre'
        item['src_zones'] = get_zones_id(parent, 'src', item['src_zones'], item)
        item['src_ips'] = get_ips_id(parent, 'src', item['src_ips'], item)
        item['dst_ips'] = get_ips_id(parent, 'dst', item['dst_ips'], item)
        item['users'] = get_guids_users_and_groups(parent, item) if parent.mc_data['ldap_servers'] else []

        if not item['src_zones']:
            parent.stepChanged.emit(f'RED|    Error: Правило "{item["name"]}" не импортировано. Не указана src-зона.')
            continue

        try:
            for x in item['servers']:
                x[1] = parent.reverseproxy_servers[x[1]] if x[0] == 'profile' else reverse_loadbalancing[x[1]]
        except KeyError as err:
            parent.stepChanged.emit(f'RED|    Error: Правило "{item["name"]}" не импортировано. Не найден сервер reverse-прокси или балансировщик {err}. Импортируйте reverse-прокси или балансировщик и повторите попытку.')
            continue

        if item['ssl_profile_id']:
            try:
                item['ssl_profile_id'] = parent.mc_data['ssl_profiles'][item['ssl_profile_id']]
            except KeyError as err:
                parent.stepChanged.emit(f'RED|    Error [Правило "{item["name"]}"]. Не найден профиль SSL {err}. Загрузите профили SSL и повторите попытку.')
                item['description'] = f'{item["description"]}\nError: Не найден профиль SSL {err}.'
                item['ssl_profile_id'] = 0
                item['is_https'] = False
                item['enabled'] = False
                error = 1
        else:
            item['is_https'] = False

        if item['certificate_id']:
            try:
                item['certificate_id'] = parent.mc_data['certs'][item['certificate_id']]
            except KeyError as err:
                parent.stepChanged.emit(f'RED|    Error [Правило "{item["name"]}"]. Не найден сертификат {err}. Создайте сертификат и повторите попытку.')
                item['description'] = f'{item["description"]}\nError: Не найден сертификат {err}.'
                item['certificate_id'] = -1
                item['is_https'] = False
                item['enabled'] = False
                error = 1
        else:
            item['certificate_id'] = -1
            item['is_https'] = False

        new_user_agents = []
        for x in item['user_agents']:
            if x[1] in parent.mc_data['ug_useragents']:
                new_user_agents.append(['list_id', f'id-{x[1]}'])
            else:
                try:
                    new_user_agents.append(['list_id', useragent_list[x[1]]])
                except KeyError as err:
                    parent.stepChanged.emit(f'RED|    Error [Правило "{item["name"]}"]. Не найден список Useragent {err}. Импортируйте списки useragent браузеров и повторите попытку.')
                    item['description'] = f'{item["description"]}\nError: Не найден Useragent {err}.'
                    item['enabled'] = False
                    error = 1
        item['user_agents'] = new_user_agents

        if item['client_certificate_profile_id']:
            item['client_certificate_profile_id'] = parent.client_certificate_profiles.get(item['client_certificate_profile_id'], 0)
            if not item['client_certificate_profile_id']:
                parent.stepChanged.emit(f'RED|    Error [Правило "{item["name"]}"]. Не найден профиль сертификата пользователя "{item["client_certificate_profile_id"]}". Импортируйте профили пользовательских сертификатов и повторите попытку.')
                item['description'] = f'{item["description"]}\nError: Не найден профиль сертификата пользователя "{item["client_certificate_profile_id"]}".'
                item['enabled'] = False
                error = 1

        if item['waf_profile_id']:
            if parent.utm.waf_license:
                try:
                    item['waf_profile_id'] = waf_profiles[item['waf_profile_id']]
                except KeyError as err:
                    parent.stepChanged.emit(f'RED|    Error [Правило "{item["name"]}"]. Не найден профиль WAF {err}. Импортируйте профили WAF и повторите попытку.')
                    item['description'] = f'{item["description"]}\nError: Не найден профиль WAF {err}.'
                    item['waf_profile_id'] = 0
                    item['enabled'] = False
                    error = 1
            else:
                item['waf_profile_id'] = 0
                item['description'] = f'{item["description"]}\nError: Нет лицензии на модуль WAF. Профиль WAF "{item["waf_profile_id"]}" не импортирован в правило.'

        if item['name'] in reverseproxy_rules:
            parent.stepChanged.emit(f'uGRAY|    Правило reverse-прокси "{item["name"]}" уже существует.')
            err, result = parent.utm.update_template_reverseproxy_rule(parent.template_id, reverseproxy_rules[item['name']], item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|       {result}  [Правило reverse-прокси "{item["name"]}"]')
            else:
                parent.stepChanged.emit(f'uGRAY|       Правило reverse-прокси "{item["name"]}" обновлено.')
        else:
            item['position'] = 'last'
            err, result = parent.utm.add_template_reverseproxy_rule(parent.template_id, item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Правило reverse-прокси "{item["name"]}" не импортировано]')
            else:
                reverseproxy_rules[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Правило reverse-прокси "{item["name"]}" импортировано.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил reverse-прокси.')
    else:
        parent.stepChanged.emit('GREEN|    Правила reverse-прокси импортированы в раздел "Глобальный портал/Правила reverse-прокси".')
    parent.stepChanged.emit('LBLUE|    Проверьте флаг "Использовать HTTPS" во всех импортированных правилах! Если не установлен профиль SSL, выберите нужный.')

#-------------------------------------------- VPN -----------------------------------------------------------------------
def import_vpnclient_security_profiles(parent, path):
    """Импортируем клиентские профилей безопасности VPN"""
    json_file = os.path.join(path, 'config_vpnclient_security_profiles.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт клиентских профилей безопасности VPN в раздел "VPN/Клиентские профили безопасности".')
    error = 0

    err, result = parent.utm.get_template_vpn_client_security_profiles(parent.template_id)
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте клиентских профилей безопасности VPN.')
        parent.error = 1
        return
    security_profiles = {x['name']: x['id'] for x in result}

    for item in data:
        if item['certificate_id']:
            try:
                item['certificate_id'] = parent.mc_data['certs'][item['certificate_id']]
            except KeyError as err:
                parent.stepChanged.emit(f'RED|    Error [Правило "{item["name"]}"]. Не найден сертификат {err}. Импортируйте сертификаты и повторите попытку.')
                item['description'] = f'{item["description"]}\nError: Не найден сертификат {err}.'
                item['certificate_id'] = 0
                error = 1

        if item['name'] in security_profiles:
            parent.stepChanged.emit(f'uGRAY|    Профиль безопасности VPN "{item["name"]}" уже существует.')
            err, result = parent.utm.update_template_vpn_client_security_profile(parent.template_id, security_profiles[item['name']], item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|       {result}  [Профиль безопасности VPN "{item["name"]}"]')
            else:
                parent.stepChanged.emit(f'uGRAY|       Профиль безопасности VPN "{item["name"]}" обновлён.')
        else:
            err, result = parent.utm.add_template_vpn_client_security_profile(parent.template_id, item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Профиль безопасности VPN "{item["name"]}" не импортирован]')
            else:
                security_profiles[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Профиль безопасности VPN "{item["name"]}" импортирован.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте клиентских профилей безопасности VPN.')
    else:
        parent.stepChanged.emit('GREEN|    Клиентские профили безопасности импортированы в раздел "VPN/Клиентские профили безопасности".')


def import_vpnserver_security_profiles(parent, path):
    """Импортируем серверные профилей безопасности VPN"""
    json_file = os.path.join(path, 'config_vpnserver_security_profiles.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт серверных профилей безопасности VPN в раздел "VPN/Серверные профили безопасности".')
    error = 0

    if not parent.client_certificate_profiles:
        if get_client_certificate_profiles(parent): # Устанавливаем атрибут parent.client_certificate_profiles
            parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте серверных профилей безопасности VPN.')
            return

    err, result = parent.utm.get_template_vpn_server_security_profiles(parent.template_id)
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте серверных профилей безопасности VPN.')
        parent.error = 1
        return
    security_profiles = {x['name']: x['id'] for x in result}

    for item in data:
        if item['certificate_id']:
            try:
                item['certificate_id'] = parent.mc_data['certs'][item['certificate_id']]
            except KeyError as err:
                parent.stepChanged.emit(f'RED|    Error [Правило "{item["name"]}"]. Не найден сертификат {err}. Импортируйте сертификаты и повторите попытку.')
                item['description'] = f'{item["description"]}\nError: Не найден сертификат {err}.'
                item['certificate_id'] = 0
                error = 1
        if item['client_certificate_profile_id']:
            try:
                item['client_certificate_profile_id'] = parent.client_certificate_profiles[item['client_certificate_profile_id']]
            except KeyError as err:
                parent.stepChanged.emit(f'RED|    Error [Правило "{item["name"]}"]. Не найден профиль сертификата пользователя {err}. Импортируйте профили пользовательских сертификатов и повторите попытку.')
                item['description'] = f'{item["description"]}\nError: Не найден профиль сертификата пользователя {err}.'
                item['client_certificate_profile_id'] = 0
                error = 1

        if item['name'] in security_profiles:
            parent.stepChanged.emit(f'uGRAY|    Профиль безопасности VPN "{item["name"]}" уже существует.')
            err, result = parent.utm.update_template_vpn_server_security_profile(parent.template_id, security_profiles[item['name']], item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|       {result}  [Профиль безопасности VPN "{item["name"]}"]')
            else:
                parent.stepChanged.emit(f'uGRAY|       Профиль безопасности VPN "{item["name"]}" обновлён.')
        else:
            err, result = parent.utm.add_template_vpn_server_security_profile(parent.template_id, item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Профиль безопасности VPN "{item["name"]}" не импортирован]')
            else:
                security_profiles[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Профиль безопасности VPN "{item["name"]}" импортирован.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте серверных профилей безопасности VPN.')
    else:
        parent.stepChanged.emit('GREEN|    Серверные профили безопасности импортированы в раздел "VPN/Серверные профили безопасности".')


def import_vpn_networks(parent, path):
    """Импортируем список сетей VPN"""
    json_file = os.path.join(path, 'config_vpn_networks.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт списка сетей VPN в раздел "VPN/Сети VPN".')
    error = 0

    err, result = parent.utm.get_template_vpn_networks(parent.template_id)
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте списка сетей VPN.')
        parent.error = 1
        return
    vpn_networks = {x['name']: x['id'] for x in result}

    for item in data:
        item['name'] = func.get_restricted_name(item['name'])
        item['networks'] = get_networks(parent, item['networks'], item)
        item['ep_routes_include'] = get_networks(parent, item['ep_routes_include'], item)
        item['ep_routes_exclude'] = get_networks(parent, item['ep_routes_exclude'], item)
        if 'error' in item:
            error = 1
            item.pop('error', None)

        if item['name'] in vpn_networks:
            parent.stepChanged.emit(f'uGRAY|    Сеть VPN "{item["name"]}" уже существует.')
            err, result = parent.utm.update_template_vpn_network(parent.template_id, vpn_networks[item['name']], item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|       {result}  [Сеть VPN "{item["name"]}"]')
            else:
                parent.stepChanged.emit(f'uGRAY|       Сеть VPN "{item["name"]}" обновлена.')
        else:
            err, result = parent.utm.add_template_vpn_network(parent.template_id, item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Сеть VPN "{item["name"]}" не импортирована]')
            else:
                vpn_networks[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Сеть VPN "{item["name"]}" импортирована.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте списка сетей VPN.')
    else:
        parent.stepChanged.emit('GREEN|    Список сетей VPN импортирован в раздел "VPN/Сети VPN".')


def get_networks(parent, networks, rule):
    new_networks = []
    for x in networks:
        try:
            new_networks.append(['list_id', parent.mc_data['ip_lists'][x[1]]]  if x[0] == 'list_id' else x)
        except KeyError as err:
            parent.stepChanged.emit(f'RED|    Error [Правило "{rule["name"]}"]. Не найден список IP-адресов {err}. Импортируйте списки IP-адресов и повторите попытку.')
            rule['description'] = f'{rule["description"]}\nError: Не найден список IP-адресов {err}.'
            rule['error'] = 1
    return new_networks


def import_vpn_client_rules(parent, path):
    """Импортируем список клиентских правил VPN"""
    json_file = os.path.join(path, 'config_vpn_client_rules.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт клиентских правил VPN в раздел "VPN/Клиентские правила".')
    error = 0

    err, result = parent.utm.get_template_vpn_client_security_profiles(parent.template_id)
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте клиентских правил VPN.')
        parent.error = 1
        return
    vpn_security_profiles = {x['name']: x['id'] for x in result}

    err, result = parent.utm.get_template_vpn_client_rules(parent.template_id)
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте клиентских правил VPN.')
        parent.error = 1
        return
    vpn_client_rules = {x['name']: x['id'] for x in result}

    for item in data:
        item['name'] = func.get_restricted_name(item['name'])
        item.pop('xauth_login', None)
        item.pop('xauth_password', None)
        item.pop('protocol', None)
        item.pop('subnet1', None)
        item.pop('subnet2', None)

        try:
            item['security_profile_id'] = vpn_security_profiles[item['security_profile_id']]
        except KeyError as err:
            parent.stepChanged.emit(f'RED|    Error [Правило "{item["name"]}"]. Не найден профиль безопасности VPN {err}. Загрузите профили безопасности VPN и повторите попытку.')
            item['description'] = f'{item["description"]}\nError: Не найден профиль безопасности VPN {err}.'
            item['security_profile_id'] = ""
            item['enabled'] = False
            error = 1

        if item['name'] in vpn_client_rules:
            parent.stepChanged.emit(f'uGRAY|    Клиентское правило VPN "{item["name"]}" уже существует.')
            err, result = parent.utm.update_template_vpn_client_rule(parent.template_id, vpn_client_rules[item['name']], item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|       {result}  [Клиентское правило VPN "{item["name"]}"]')
            else:
                parent.stepChanged.emit(f'uGRAY|       Клиентское правило VPN "{item["name"]}" обновлено.')
        else:
            err, result = parent.utm.add_template_vpn_client_rule(parent.template_id, item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Клиентское правило VPN "{item["name"]}" не импортировано]')
            else:
                vpn_client_rules[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Клиентское правило VPN "{item["name"]}" импортировано.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте клиентских правил VPN.')
    else:
        parent.stepChanged.emit('GREEN|    Клиентские правила VPN импортированы в раздел "VPN/Клиентские правила".')


def import_vpn_server_rules(parent, path):
    """Импортируем список серверных правил VPN"""
    json_file = os.path.join(path, 'config_vpn_server_rules.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт серверных правил VPN в раздел "VPN/Серверные правила".')
    error = 0

    err, result = parent.utm.get_template_vpn_server_security_profiles(parent.template_id)
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте серверных правил VPN.')
        parent.error = 1
        return
    vpn_security_profiles = {x['name']: x['id'] for x in result}

    err, result = parent.utm.get_template_vpn_networks(parent.template_id)
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте серверных правил VPN.')
        parent.error = 1
        return
    vpn_networks = {x['name']: x['id'] for x in result}

    err, result = parent.utm.get_template_vpn_server_rules(parent.template_id)
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте серверных правил VPN.')
        parent.error = 1
        return
    vpn_server_rules = {x['name']: x['id'] for x in result}

    for item in data:
        item['name'] = func.get_restricted_name(item['name'])
        item['position_layer'] = 'pre'
        item['src_zones'] = get_zones_id(parent, 'src', item['src_zones'], item)
        item['source_ips'] = get_ips_id(parent, 'src', item['source_ips'], item)
        item['dst_ips'] = get_ips_id(parent, 'dst', item['dst_ips'], item)
        item['users'] = get_guids_users_and_groups(parent, item) if parent.mc_data['ldap_servers'] else []
        try:
            item['security_profile_id'] = vpn_security_profiles[item['security_profile_id']]
        except KeyError as err:
            parent.stepChanged.emit(f'RED|    Error [Правило "{item["name"]}"]. Не найден профиль безопасности VPN {err}. Загрузите профили безопасности VPN и повторите попытку.')
            item['description'] = f'{item["description"]}\nError: Не найден профиль безопасности VPN {err}.'
            item['security_profile_id'] = ""
            item['enabled'] = False
            error = 1
        try:
            item['tunnel_id'] = vpn_networks[item['tunnel_id']]
        except KeyError as err:
            parent.stepChanged.emit(f'RED|    Error [Правило "{item["name"]}"]. Не найдена сеть VPN "{err}". Загрузите сети VPN и повторите попытку.')
            item['description'] = f'{item["description"]}\nError: Не найдена сеть VPN "{err}".'
            item['tunnel_id'] = ""
            item['enabled'] = False
            error = 1
        try:
            item['auth_profile_id'] = parent.mc_data['auth_profiles'][item['auth_profile_id']]
        except KeyError as err:
            parent.stepChanged.emit(f'RED|    Error [Правило "{item["name"]}"]. Не найден профиль авторизации {err}. Загрузите профили авторизации и повторите попытку.')
            item['description'] = f'{item["description"]}\nError: Не найден профиль авторизации {err}.'
            item['auth_profile_id'] = ""
            item['enabled'] = False
            error = 1

        if item['name'] in vpn_server_rules:
            parent.stepChanged.emit(f'uGRAY|    Серверное правило VPN "{item["name"]}" уже существует.')
            err, result = parent.utm.update_template_vpn_server_rule(parent.template_id, vpn_server_rules[item['name']], item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|       {result}  [Серверное правило VPN "{item["name"]}"]')
            else:
                parent.stepChanged.emit(f'uGRAY|       Серверное правило VPN "{item["name"]}" обновлено.')
        else:
            item['position'] = 'last'
            err, result = parent.utm.add_template_vpn_server_rule(parent.template_id, item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Серверное правило VPN "{item["name"]}" не импортировано]')
            else:
                vpn_server_rules[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Серверное правило VPN "{item["name"]}" импортировано.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте серверных правил VPN.')
    else:
        parent.stepChanged.emit('GREEN|    Серверные правила VPN импортированы в раздел "VPN/Серверные правила".')


#--------------------------------------------------- Оповещения ---------------------------------------------------------
def import_notification_alert_rules(parent, path):
    """Импортируем список правил оповещений"""
    json_file = os.path.join(path, 'config_alert_rules.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт правил оповещений в раздел "Диагностика и мониторинг/Правила оповещений".')
    error = 0

    if not parent.notification_profiles:
        if get_notification_profiles(parent):      # Устанавливаем атрибут parent.notification_profiles
            parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил оповещений.')
            return

    err, result = parent.utm.get_template_nlists_list(parent.template_id, 'emailgroup')
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил оповещений.')
        parent.error = 1
        return
    email_group = {x['name']: x['id'] for x in result}

    err, result = parent.utm.get_template_nlists_list(parent.template_id, 'phonegroup')
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил оповещений.')
        parent.error = 1
        return
    phone_group = {x['name']: x['id'] for x in result}

    err, result = parent.utm.get_template_notification_alert_rules(parent.template_id)
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил оповещений.')
        parent.error = 1
        return
    alert_rules = {x['name']: x['id'] for x in result}

    for item in data:
        try:
            item['notification_profile_id'] = parent.notification_profiles[item['notification_profile_id']]
        except KeyError as err:
            parent.stepChanged.emit(f'RED|    Error [Правило "{item["name"]}"]. Не найден профиль оповещений {err}. Импортируйте профили оповещений и повторите попытку.')
            parent.stepChanged.emit(f'RED|       Error: Правило "{item["name"]}" не импортировано.')
            error = 1
            continue

        new_emails = []
        for x in item['emails']:
            try:
                new_emails.append(['list_id', email_group[x[1]]])
            except KeyError as err:
                parent.stepChanged.emit(f'RED|    Error [Правило "{item["name"]}"]. Не найдена группа почтовых адресов {err}. Загрузите почтовые адреса и повторите попытку.')
                item['description'] = f'{item["description"]}\nError: Не найдена группа почтовых адресов {err}.'
                item['enabled'] = False
                error = 1
        item['emails'] = new_emails

        new_phones = []
        for x in item['phones']:
            try:
                new_phones.append(['list_id', phone_group[x[1]]])
            except KeyError as err:
                parent.stepChanged.emit(f'RED|    Error [Правило "{item["name"]}"]. Не найдена группа телефонных номеров {err}. Загрузите номера телефонов и повторите попытку.')
                item['description'] = f'{item["description"]}\nError: Не найдена группа телефонных номеров {err}.'
                item['enabled'] = False
                error = 1
        item['phones'] = new_phones

        if item['name'] in alert_rules:
            parent.stepChanged.emit(f'uGRAY|    Правило оповещения "{item["name"]}" уже существует.')
            err, result = parent.utm.update_template_notification_alert_rule(parent.template_id, alert_rules[item['name']], item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|       {result}  [Правило оповещения "{item["name"]}"]')
            else:
                parent.stepChanged.emit(f'uGRAY|       Правило оповещения "{item["name"]}" обновлено.')
        else:
            err, result = parent.utm.add_template_notification_alert_rule(parent.template_id, item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Правило оповещения "{item["name"]}" не импортировано]')
            else:
                alert_rules[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Правило оповещения "{item["name"]}" импортировано.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил оповещений.')
    else:
        parent.stepChanged.emit('GREEN|    Правила оповещений импортированы в раздел "Диагностика и мониторинг/Правила оповещений".')


def import_snmp_security_profiles(parent, path):
    """Импортируем профили безопасности SNMP"""
    json_file = os.path.join(path, 'config_snmp_profiles.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт профилей безопасности SNMP в раздел "Диагностика и мониторинг/Профили безопасности SNMP".')
    error = 0

    err, result = parent.utm.get_template_snmp_security_profiles(parent.template_id)
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей безопасности SNMP.')
        parent.error = 1
        return
    snmp_security_profiles = {x['name']: x['id'] for x in result}

    for item in data:
        if not isinstance(item['auth_password'], str):
            item['auth_password'] = ''
        if not isinstance(item['private_password'], str):
            item['private_password'] = ''

        if item['name'] in snmp_security_profiles:
            parent.stepChanged.emit(f'uGRAY|    Профиль безопасности SNMP "{item["name"]}" уже существует.')
            err, result = parent.utm.update_template_snmp_security_profile(parent.template_id, snmp_security_profiles[item['name']], item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|       {result}  [Профиль безопасности SNMP "{item["name"]}"]')
            else:
                parent.stepChanged.emit(f'uGRAY|       Профиль безопасности SNMP "{item["name"]}" обновлён.')
        else:
            err, result = parent.utm.add_template_snmp_security_profile(parent.template_id, item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Профиль безопасности SNMP: "{item["name"]}" не импортирован]')
            else:
                snmp_security_profiles[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Профиль безопасности SNMP "{item["name"]}" импортирован.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей безопасности SNMP.')
    else:
        parent.stepChanged.emit('GREEN|    Профили безопасности SNMP импортированы в раздел "Диагностика и мониторинг/Профили безопасности SNMP".')


def import_snmp_settings(parent, path):
    """Импортируем параметры SNMP"""
    parent.stepChanged.emit('BLUE|Импорт параметров SNMP в раздел "Диагностика и мониторинг/Параметры SNMP".')
    json_file = os.path.join(path, 'config_snmp_engine.json')
    err, engine = func.read_json_file(parent, json_file, mode=1)
    if err:
        return
    json_file = os.path.join(path, 'config_snmp_sysname.json')
    err, sysname = func.read_json_file(parent, json_file, mode=1)
    if err:
        return
    json_file = os.path.join(path, 'config_snmp_syslocation.json')
    err, syslocation = func.read_json_file(parent, json_file, mode=1)
    if err:
        return
    json_file = os.path.join(path, 'config_snmp_sysdescription.json')
    err, sysdescription = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    data = {
        'name': parent.node_name,
        'engine_id': engine,
        'sys_name': sysname,
        'sys_location': syslocation,
        'sys_description': sysdescription,
        'enabled_sync': False
    }
    err, result = parent.utm.add_template_snmp_parameters(parent.template_id, data)
    if err == 1:
        parent.error = 1
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('RED|    Произошла ошибка при импорте параметров SNMP.')
    elif err == 3:
        parent.stepChanged.emit(f'GRAY|    {result}')
    else:
        parent.stepChanged.emit('GREEN|    Параметры SNMP импортированы  в раздел "Диагностика и мониторинг/Параметры SNMP".')


def import_snmp_rules(parent, path):
    """Импортируем список правил SNMP"""
    json_file = os.path.join(path, 'config_snmp_rules.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт списка правил SNMP в раздел "Диагностика и мониторинг/SNMP".')
    error = 0

    err, result = parent.utm.get_template_snmp_security_profiles(parent.template_id)
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил SNMP.')
        parent.error = 1
        return
    snmp_security_profiles = {x['name']: x['id'] for x in result}

    err, result = parent.utm.get_template_snmp_rules(parent.template_id)
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил SNMP.')
        parent.error = 1
        return
    snmp_rules = {x['name']: x['id'] for x in result}

    for item in data:
        item['name'] = func.get_restricted_name(item['name'])
        if 'snmp_security_profile' in item:
            if item['snmp_security_profile']:
                try:
                    item['snmp_security_profile'] = snmp_security_profiles[item['snmp_security_profile']]
                except KeyError as err:
                    parent.stepChanged.emit(f'RED|    Error [Правило "{item["name"]}"]. Не найден профиль безопасности SNMP {err}. Импортируйте профили безопасности SNMP и повторите попытку.')
                    item['description'] = f'{item["description"]}\nError: Не найден профиль безопасности SNMP {err}.'
                    item['snmp_security_profile'] = 0
                    item['enabled'] = False
                    error = 1
        else:
            item['snmp_security_profile'] = 0
            item['enabled'] = False
            item.pop('username', None)
            item.pop('auth_type', None)
            item.pop('auth_alg', None)
            item.pop('auth_password', None)
            item.pop('private_alg', None)
            item.pop('private_password', None)
            if item['version'] == 3:
                item['version'] = 2
                item['community'] = 'public'

        if item['name'] in snmp_rules:
            parent.stepChanged.emit(f'uGRAY|    Правило SNMP "{item["name"]}" уже существует.')
            err, result = parent.utm.update_template_snmp_rule(parent.template_id, snmp_rules[item['name']], item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|       {result}  [Правило SNMP "{item["name"]}"]')
            else:
                parent.stepChanged.emit(f'uGRAY|       Правило SNMP "{item["name"]}" обновлено.')
        else:
            err, result = parent.utm.add_template_snmp_rule(parent.template_id, item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Правило SNMP "{item["name"]}" не импортировано]')
            else:
                snmp_rules[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Правило SNMP "{item["name"]}" импортировано.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил SNMP.')
    else:
        parent.stepChanged.emit('GREEN|    Правила SNMP импортированы в раздел "Диагностика и мониторинг/SNMP".')

#------------------------------------------------------------------------------------------------------------------------
def pass_function(parent, path):
    """Функция заглушка"""
    parent.stepChanged.emit(f'GRAY|Импорт раздела "{path.rpartition("/")[2]}" в настоящее время не реализован.')

import_funcs = {
    "Morphology": import_morphology_lists,
    "Services": import_services_list,
    "ServicesGroups": import_services_groups,
    "IPAddresses": import_ip_lists,
    "Useragents": import_useragent_lists,
    "ContentTypes": import_mime_lists,
    "URLLists": import_url_lists,
    "TimeSets": import_time_restricted_lists,
    "BandwidthPools": import_shaper_list,
    "SCADAProfiles": pass_function, # import_scada_profiles
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
    "UserIdAgentSyslogFilters": pass_function, # import_useridagent_syslog_filters,
    "Scenarios": import_scenarios,
    'Zones': import_zones,
    'Interfaces': import_interfaces,
    'Gateways': import_gateways,
    'DNS': import_dns_config,
    'DHCP': import_dhcp_subnets,
    'VRF': import_vrf,
    'WCCP': import_wccp_rules,
    'Certificates': import_certificates,
    'UserCertificateProfiles': import_client_certificate_profiles,
    'GeneralSettings': import_general_settings,
#    'DeviceManagement': pass_function,
#    'Administrators': pass_function,
    'Groups': import_local_groups,
    'Users': import_local_users,
    'MFAProfiles': import_2fa_profiles,
    'AuthServers': import_auth_servers,
    'AuthProfiles': import_auth_profiles,
    'CaptiveProfiles': import_captive_profiles,
    'CaptivePortal': import_captive_portal_rules,
    'TerminalServers': import_terminal_servers,
    'UserIDagent': import_userid_agent,
    'BYODPolicies': pass_function, # import_byod_policy,
    'BYODDevices': pass_function,
    'Firewall': import_firewall_rules,
    'NATandRouting': import_nat_rules,
    "ICAPServers": import_icap_servers,
    "ReverseProxyServers": import_reverseproxy_servers,
    'LoadBalancing': import_loadbalancing_rules,
    'TrafficShaping': import_shaper_rules,
    "ContentFiltering": import_content_rules,
    "SafeBrowsing": import_safebrowsing_rules,
    "TunnelInspection": import_tunnel_inspection_rules,
    "SSLInspection": import_ssldecrypt_rules,
    "SSHInspection": import_sshdecrypt_rules,
    "IntrusionPrevention": pass_function, # import_idps_rules,
    "MailSecurity": import_mailsecurity,
    "ICAPRules": import_icap_rules,
    "DoSProfiles": import_dos_profiles,
    "DoSRules": import_dos_rules,
    "SCADARules": pass_function, # import_scada_rules,
    "WebPortal": import_proxyportal_rules,
    "ReverseProxyRules": import_reverseproxy_rules,
    "CustomWafLayers": pass_function, # import_waf_custom_layers,
    "SystemWafRules": pass_function,
    "WAFprofiles": pass_function, # import_waf_profiles,
    "ServerSecurityProfiles": import_vpnserver_security_profiles,
    "ClientSecurityProfiles": import_vpnclient_security_profiles,
    "SecurityProfiles": pass_function, # import_vpn_security_profiles,
    "VPNNetworks": import_vpn_networks,
    "ServerRules": import_vpn_server_rules,
    "ClientRules": import_vpn_client_rules,
    "AlertRules": import_notification_alert_rules,
    "SNMPSecurityProfiles": import_snmp_security_profiles,
    "SNMPParameters": import_snmp_settings,
    "SNMP": import_snmp_rules,
}

######################################### Служебные функции ################################################
def get_ips_id(parent, mode, rule_ips, rule):
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
                new_rule_ips.append(['list_id', parent.mc_data['ip_lists'][ips[1]]])
            elif ips[0] == 'urllist_id':
                new_rule_ips.append(['urllist_id', parent.mc_data['url_lists'][ips[1]]])
        except KeyError as err:
            parent.stepChanged.emit(f'RED|    Error [Правило "{rule["name"]}"]: Не найден список {mode}-адресов "{ips[1]}". Загрузите списки в библиотеку и повторите импорт.')
            rule['description'] = f'{rule["description"]}\nError: Не найден список {mode}-адресов "{ips[1]}".'
            rule['enabled'] = False
            parent.error = 1
    return new_rule_ips


def get_zones_id(parent, mode, zones, rule):
    """
    Получить UID-ы зон. Если зона не существует на MC, то она пропускается.
    mode - принимает значения: src | dst (для формирования сообщений)
    """
    new_zones = []
    for zone in zones:
        try:
            new_zones.append(parent.mc_data['zones'][zone])
        except KeyError as err:
            parent.stepChanged.emit(f'RED|    Error [Правило "{rule["name"]}"]: Не найдена {mode}-зона "{zone}". Импортируйте зоны и повторите попытку.')
            rule['description'] = f'{rule["description"]}\nError: Не найдена {mode}-зона "{zone}".'
            rule['enabled'] = False
            parent.error = 1
    return new_zones


def get_guids_users_and_groups(parent, rule):
    """
    Получить GUID-ы групп и пользователей по их именам.
    Заменяет имена локальных и доменных пользователей и групп на GUID-ы.
    """
    new_users = []
    for item in rule['users']:
        match item[0]:
            case 'special':
                new_users.append(item)
            case 'user':
                user_name = None
                try:
                    ldap_domain, _, user_name = item[1].partition("\\")
                except IndexError:
                    parent.stepChanged.emit(f'NOTE|    Error [Правило "{rule["name"]}"]: Не указано имя пользователя в {item}.')
                if user_name:
                    try:
                        ldap_id = parent.mc_data['ldap_servers'][ldap_domain.lower()]
                    except KeyError:
                        parent.stepChanged.emit(f'RED|    Error [Правило "{rule["name"]}"]: Нет LDAP-коннектора для домена "{ldap_domain}".')
                        rule['description'] = f'{rule["description"]}\nError: Нет LDAP-коннектора для домена "{ldap_domain}".'
                        rule['enabled'] = False
                        parent.error = 1
                    else:
                        err, result = parent.utm.get_usercatalog_ldap_user_guid(ldap_id, user_name)
                        if err:
                            parent.stepChanged.emit(f'RED|    {result}  [Правило "{rule["name"]}"]')
                            rule['description'] = f'{rule["description"]}\nError: Не удалось получить ID пользователя "{user_name}" - {result}.'
                            rule['enabled'] = False
                            parent.error = 1
                        elif not result:
                            parent.stepChanged.emit(f'RED|    Error [Правило "{rule["name"]}"]: Нет пользователя "{user_name}" в домене "{ldap_domain}".')
                            rule['description'] = f'{rule["description"]}\nError: Нет пользователя "{user_name}" в домене "{ldap_domain}".'
                            rule['enabled'] = False
                            parent.error = 1
                        else:
                            new_users.append(['user', result])
                else:
                    try:
                        new_users.append(['user', parent.mc_data['local_users'][item[1]]])
                    except KeyError as err:
                        parent.stepChanged.emit(f'RED|    Error [Правило "{rule["name"]}"]: Не найден локальный пользователь "{err}". Импортируйте локальных пользователей.')
                        rule['description'] = f'{rule["description"]}\nError: Не найден локальный пользователь "{err}".'
                        rule['enabled'] = False
                        parent.error = 1
            case 'group':
                group_name = None
                try:
                    ldap_domain, _, group_name = item[1].partition("\\")
                except IndexError:
                    parent.stepChanged.emit(f'NOTE|    Error [Правило "{rule["name"]}"]: Не указано имя группы в {item}')
                if group_name:
                    try:
                        ldap_id = parent.mc_data['ldap_servers'][ldap_domain.lower()]
                    except KeyError:
                        parent.stepChanged.emit(f'RED|    Error [Правило "{rule["name"]}"]: Нет LDAP-коннектора для домена "{ldap_domain}"')
                        rule['description'] = f'{rule["description"]}\nError: Нет LDAP-коннектора для домена "{ldap_domain}".'
                        rule['enabled'] = False
                        parent.error = 1
                    else:
                        err, result = parent.utm.get_usercatalog_ldap_group_guid(ldap_id, group_name)
                        if err:
                            parent.stepChanged.emit(f'RED|    {result}  [Правило "{rule["name"]}"]')
                            rule['description'] = f'{rule["description"]}\nError: Не удалось получить ID группы "{group_name}" - {result}.'
                            rule['enabled'] = False
                            parent.error = 1
                        elif not result:
                            parent.stepChanged.emit(f'RED|    Error [Правило "{rule["name"]}"]: Нет группы "{group_name}" в домене "{ldap_domain}"!')
                            rule['description'] = f'{rule["description"]}\nError: Нет группы "{group_name}" в домене "{ldap_domain}".'
                            rule['enabled'] = False
                            parent.error = 1
                        else:
                            new_users.append(['group', result])
                else:
                    try:
                        new_users.append(['group', parent.mc_data['local_groups'][item[1]]])
                    except KeyError as err:
                        parent.stepChanged.emit(f'RED|    Error [Правило "{rule["name"]}"]. Не найдена группа пользователей "{err}". Импортируйте группы пользователей.')
                        rule['description'] = f'{rule["description"]}\nError: Не найдена группа пользователей "{err}".'
                        rule['enabled'] = False
                        parent.error = 1
    return new_users


def get_services(parent, service_list, rule):
    """Получаем ID сервисов по из именам. Если сервис не найден, то он пропускается."""
    new_service_list = []
    for item in service_list:
        try:
            if item[0] == 'service':
                new_service_list.append(['service', parent.mc_data['services'][item[1]]])
            elif item[0] == 'list_id':
                new_service_list.append(['list_id', parent.mc_data['service_groups'][item[1]]])
        except KeyError as err:
            parent.stepChanged.emit(f'RED|    Error [Правило "{rule["name"]}"]. Не найден сервис "{item[1]}". Загрузите сервисы и повторите импорт.')
            rule['description'] = f'{rule["description"]}\nError: Не найден сервис "{item[1]}".'
            rule['enabled'] = False
            parent.error = 1
    return new_service_list


def get_url_categories_id(parent, rule, referer=0):
    """Получаем ID категорий URL и групп категорий URL. Если список не существует на MC, то он пропускается."""
    new_categories = []
    rule_data = rule['referer_categories'] if referer else rule['url_categories']
    for item in rule_data:
        try:
            if item[0] == 'list_id':
                new_categories.append(['list_id', parent.mc_data['url_categorygroups'][item[1]]])
            elif item[0] == 'category_id':
                new_categories.append(['category_id', parent.mc_data['url_categories'][item[1]]])
        except KeyError as err:
            parent.stepChanged.emit(f'RED|    Error [Правило "{rule["name"]}"]. Не найдена категория URL "{item[1]}". Загрузите категории URL и повторите импорт.')
            rule['description'] = f'{rule["description"]}\nError: Не найдена категория URL "{item[1]}".'
            rule['enabled'] = False
            parent.error = 1
    return new_categories


def get_urls_id(parent, urls, rule):
    """Получаем ID списков URL. Если список не существует на MC, то он пропускается."""
    new_urls = []
    for item in urls:
        try:
            new_urls.append(parent.mc_data['url_lists'][item])
        except KeyError as err:
            parent.stepChanged.emit(f'RED|    Error [Правило "{rule["name"]}"]. Не найден список URL "{item}". Загрузите списки URL и повторите импорт.')
            rule['description'] = f'{rule["description"]}\nError: Не найден список URL "{item}".'
            rule['enabled'] = False
            parent.error = 1
    return new_urls


def get_apps(parent, rule):
    """Определяем ID приложения или группы приложений по именам."""
    new_app_list = []
    for app in rule['apps']:
        if app[0] == 'ro_group':
            if app[1] == 'All':
                new_app_list.append(['ro_group', 0])
            else:
                try:
                    new_app_list.append(['ro_group', parent.mc_data['l7_categories'][app[1]]])
                except KeyError as err:
                    parent.stepChanged.emit(f'RED|    Error [Правило "{rule["name"]}"]. Не найдена категория l7 "{app[1]}".')
                    parent.stepChanged.emit('RED|    Возможно нет лицензии и MC не получил список категорий l7. Установите лицензию и повторите попытку.')
                    rule['description'] = f'{rule["description"]}\nError: Не найдена категория l7 "{app[1]}".'
                    rule['enabled'] = False
                    parent.error = 1
        elif app[0] == 'group':
            try:
                new_app_list.append(['group', parent.mc_data['application_groups'][app[1]]])
            except KeyError as err:
                parent.stepChanged.emit(f'RED|    Error [Правило "{rule["name"]}"]: Не найдена группа приложений l7 "{app[1]}".')
                rule['description'] = f'{rule["description"]}\nError: Не найдена группа приложений l7 "{app[1]}".'
                rule['enabled'] = False
                parent.error = 1
    return new_app_list


def get_time_restrictions(parent, rule):
    """Получаем ID календарей шаблона по их именам. Если календарь не найден в шаблоне, то он пропускается."""
    new_schedules = []
    for name in rule['time_restrictions']:
        try:
            new_schedules.append(parent.mc_data['calendars'][name])
        except KeyError:
            parent.stepChanged.emit(f'RED|    Error [Правило "{rule["name"]}"]: Не найден календарь "{name}".')
            rule['description'] = f'{rule["description"]}\nError: Не найден календарь "{name}".'
            rule['enabled'] = False
            parent.error = 1
    return new_schedules


def get_response_pages(parent):
    """Получаем список шаблонов страниц области и устанавливаем значение атрибута parent.response_pages."""
    err, result = parent.utm.get_realm_responsepages_list()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return 1
    parent.response_pages = {x['name']: x['id'] for x in result}
    parent.response_pages[-1] = -1
    return 0

def get_client_certificate_profiles(parent):
    """
    Получаем список профилей клиентских сертификатов области и
    устанавливаем значение атрибута parent.client_certificate_profiles
    """
    err, result = parent.utm.get_realm_client_certificate_profiles()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return 1
    parent.client_certificate_profiles = {x['name']: x['id'] for x in result}
    return 0

def get_notification_profiles(parent):
    """
    Получаем список профилей оповещения и
    устанавливаем значение атрибута parent.notification_profiles
    """
    err, result = parent.utm.get_realm_notification_profiles()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return 1
    parent.notification_profiles = {x['name']: x['id'] for x in result}
    parent.notification_profiles[-5] = -5
    return 0

def get_realm_captive_profiles(parent):
    """
    Получаем список Captive-профилей и устанавливаем атрибут parent.captive_profiles
    """
    for uid, name in parent.templates.items():
        err, result = parent.utm.get_template_captive_profiles(uid)
        if err:
            parent.stepChanged.emit(f'RED|    {result}')
            parent.error = 1
            return 1
        parent.captive_profiles.update({x['name']: {'id': x['id'], 'template_name': name, 'template_id': uid} for x in result})
    return 0

def get_icap_servers(parent):
    """Получаем список серверов ICAP и устанавливаем значение атрибута parent.icap_servers"""
    err, result = parent.utm.get_template_icap_servers(parent.template_id)
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return 1
    parent.icap_servers = {x['name']: x['id'] for x in result}
    return 0

def get_reverseproxy_servers(parent):
    """Получаем список серверов reverse-proxy и устанавливаем значение атрибута parent.reverseproxy_servers"""
    err, result = parent.utm.get_template_reverseproxy_servers(parent.template_id)
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return 1
    parent.reverseproxy_servers = {x['name']: x['id'] for x in result}
    return 0

def add_empty_vrf(parent, vrf_name, ports):
    """Добавляем пустой VRF"""
    vrf = {
        'name': vrf_name,
        'description': '',
        'interfaces': ports if vrf_name != 'default' else [],
        'routes': [],
        'ospf': {},
        'bgp': {},
        'rip': {},
        'pimsm': {}
    }
    err, result = parent.utm.add_template_vrf(parent.template_id, vrf)
    if err:
        return err, result
    return 0, result    # Возвращаем ID добавленного VRF

