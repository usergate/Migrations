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
# Классы импорта разделов конфигурации на UserGate Management Center версии 7.
# Версия 1.9
#

import os, sys, json, time
import common_func as func
from PyQt6.QtCore import QThread, pyqtSignal


class ImportAll(QThread):
    """Импортируем всю конфигурацию в шаблон MC"""
    stepChanged = pyqtSignal(str)
    
    def __init__(self, utm, config_path, all_points, template_id, arguments, node_name):
        super().__init__()
        self.utm = utm

        self.config_path = config_path
        self.all_points = all_points

        self.template_id = template_id
        self.node_name = node_name
        self.ngfw_ports = arguments['ngfw_ports']
        self.dhcp_settings = arguments['dhcp_settings']
        self.ngfw_vlans = arguments['ngfw_vlans']
        self.new_vlans = arguments['new_vlans']
        self.iface_settings = arguments['iface_settings']

        self.version = float(f'{self.utm.version_hight}.{self.utm.version_midle}')
        self.response_pages = {}
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

    def __init__(self, utm, config_path, selected_path, selected_points, template_id, arguments, node_name):
        super().__init__()
        self.utm = utm

        self.config_path = config_path
        self.selected_path = selected_path
        self.selected_points = selected_points
        self.template_id = template_id
        self.node_name = node_name
        self.ngfw_ports = arguments['ngfw_ports']
        self.dhcp_settings = arguments['dhcp_settings']
        self.ngfw_vlans = arguments['ngfw_vlans']
        self.new_vlans = arguments['new_vlans']
        self.iface_settings = arguments['iface_settings']

        self.version = float(f'{self.utm.version_hight}.{self.utm.version_midle}')
        self.response_pages = {}
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
        parent.error = 1
        return
    morphology_list = {x['name']: x['id'] for x in result}

    for item in data:
        item['name'] = func.get_restricted_name(item['name'])
        content = item.pop('content')
        item.pop('last_update', None)

        if item['name'] in morphology_list:
            parent.stepChanged.emit(f'GRAY|    Список морфологии "{item["name"]}" уже существует.')
            err, result = parent.utm.update_template_nlist(parent.template_id, morphology_list[item['name']], item)
            if err == 1:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Список морфологии: {item["name"]}]')
                continue
            elif err == 3:
                parent.stepChanged.emit(f'GRAY|    {result}')
            else:
                parent.stepChanged.emit(f'BLACK|    Список морфологии "{item["name"]}" updated.')
        else:
            err, result = parent.utm.add_template_nlist(parent.template_id, item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Список морфологии: "{item["name"]}"]')
                continue
            else:
                morphology_list[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Список морфологии "{item["name"]}" добавлен.')

        if item['list_type_update'] == 'static':
            if content:
#                err2, result2 = parent.utm.add_template_nlist_items(parent.template_id, morphology_list[item['name']], content)
#                print(err2, result2)
#                print(parent.template_id, morphology_list[item['name']])

                for value in content:
                    err2, result2 = parent.utm.add_template_nlist_item(parent.template_id, morphology_list[item['name']], value)
                    if err2 == 3:
                        parent.stepChanged.emit(f'GRAY|       {result2}')
                    elif err2 == 1:
                        error = 1
                        parent.stepChanged.emit(f'RED|       {result2}  [Список морфологии: "{item["name"]}"]')
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
            parent.stepChanged.emit(f'GRAY|    Сервис "{item["name"]}" уже существует.')
        else:
            err, result = parent.utm.add_template_service(parent.template_id, item)
            if err == 3:
                parent.stepChanged.emit(f'GRAY|    {result}')
            elif err == 1:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}')
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
            parent.stepChanged.emit(f'GRAY|    Группа сервисов "{item["name"]}" уже существует.')
            err, result = parent.utm.update_template_nlist(parent.template_id, mc_servicegroups[item['name']], item)
            if err == 1:
                error = 1
                parent.stepChanged.emit(f'RED|    {result} [Группа сервисов: "{item["name"]}"]')
                continue
            elif err == 3:
                parent.stepChanged.emit(f'GRAY|    {result}.')
            else:
                parent.stepChanged.emit(f'BLACK|    Группа сервисов "{item["name"]}" updated.')
        else:
            err, result = parent.utm.add_template_nlist(parent.template_id, item)
            if err == 1:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Группа сервисов: "{item["name"]}" не импортирована]')
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
                parent.stepChanged.emit(f'RED|       {result2} [Группа сервисов: "{item["name"]}"]')
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
                parent.stepChanged.emit(f'RED|    {result} [Список IP-адресов: "{data["name"]}"]')
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
        parent.error = 1
        return
    useragent_list = {x['name']: x['id'] for x in result}

    for item in data:
        content = item.pop('content')
        item.pop('last_update', None)
        item['name'] = func.get_restricted_name(item['name'])

        if item['name'] in useragent_list:
            parent.stepChanged.emit(f'GRAY|    Список Useragent "{item["name"]}" уже существует.')
            err, result = parent.utm.update_template_nlist(parent.template_id, useragent_list[item['name']], item)
            if err == 1:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Список Useragent: {item["name"]}]')
                continue
            elif err == 3:
                parent.stepChanged.emit(f'GRAY|    {result}')
            else:
                parent.stepChanged.emit(f'BLACK|    Список Useragent "{item["name"]}" updated.')
        else:
            err, result = parent.utm.add_template_nlist(parent.template_id, item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Список Useragent: "{item["name"]}"]')
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
            parent.stepChanged.emit(f'RED|    {result}  [Список URL "{data["name"]}" не импортирована]')
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

    err, result = parent.utm.get_template_shapers_list(parent.template_id)
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return
    shaper_list = {x['name']: x['id'] for x in result}

    parent.stepChanged.emit('BLUE|Импорт списка "Полосы пропускания" в раздел "Библиотеки/Полосы пропускания".')
    error = 0

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
                parent.stepChanged.emit(f'RED|    {result}  [Полоса пропускания: "{item["name"]}"]')
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
                parent.stepChanged.emit(f'RED|    {result}  [Шаблон страницы: "{item["name"]}"]')
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
                    parent.stepChanged.emit(f'RED|       {result2}')
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
                parent.stepChanged.emit(f'RED|    {result}  [URL категория: "{item["name"]}"]')
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
                parent.stepChanged.emit(f'RED|    {result}  [Приложение: "{item["name"]}"]')
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
        parent.error = 1
        return
    l7profiles = {x['name']: x['id'] for x in result}

    err, result = parent.utm.get_template_app_signatures(parent.template_id)
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
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
                parent.stepChanged.emit(f'RED|    Error: Не найдено приложение "{err}" [Правило: "{item["name"]}"].')
        item['overrides'] = new_overrides

        if item['name'] in l7profiles:
            parent.stepChanged.emit(f'GRAY|    Профиль приложений "{item["name"]}" уже существует.')
            err, result = parent.utm.update_template_l7_profile(parent.template_id, l7profiles[item['name']], item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Профиль приложений: {item["name"]}]')
            else:
                parent.stepChanged.emit(f'BLACK|    Профиль приложений "{item["name"]}" updated.')
        else:
            err, result = parent.utm.add_template_l7_profile(parent.template_id, item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Профиль приложений: "{item["name"]}"]')
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
                parent.stepChanged.emit(f'BLACK|       Добавлено приложение "{app["name"]}".')
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
                parent.stepChanged.emit(f'RED|    {result}  [Сигнатура СОВ: "{item["msg"]}"]')
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
        parent.error = 1
        return
    profiles = {x['name']: x['id'] for x in result}

    err, result = parent.utm.get_template_idps_signatures_list(parent.template_id)
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
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
                parent.stepChanged.emit(f'RED|    {result}  [Профиль СОВ: "{item["name"]}"]')
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
                parent.stepChanged.emit(f'RED|    {result}  [Профиль оповещения: "{item["name"]}"]')
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
                parent.stepChanged.emit(f'RED|    {result}  [Профиль netflow: "{item["name"]}"]')
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
                parent.stepChanged.emit(f'RED|    {result}  [Профиль LLDP: "{item["name"]}"]')
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
                parent.stepChanged.emit(f'RED|    {result}  [Профиль SSL: "{item["name"]}"]')
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
                parent.stepChanged.emit(f'RED|    {result}  [Профиль пересылки SSL: "{item["name"]}"]')
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
                parent.stepChanged.emit(f'RED|    {result}  [HIP объект: "{item["name"]}"]')
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
        parent.error = 1
        return
    hip_objects = {x['name']: x['id'] for x in result}

    err, result = parent.utm.get_template_hip_profiles_list(parent.template_id)
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
                parent.stepChanged.emit(f'RED|    {result}  [HIP профиль: "{item["name"]}"]')
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
                parent.stepChanged.emit(f'RED|    {result}  [Профиль BFD: "{item["name"]}"]')
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
        parent.error = 1
        return
    filters = {x['name']: x['id'] for x in result}

    for item in data:
        if item['name'] in filters:
            parent.stepChanged.emit(f'GRAY|    Фильтр "{item["name"]}" уже существует.')
            err, result = parent.utm.update_template_useridagent_filter(parent.template_id, filters[item['name']], item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Фильтр: {item["name"]}]')
            else:
                parent.stepChanged.emit(f'BLACK|    Фильтр "{item["name"]}" updated.')
        else:
            err, result = parent.utm.add_template_useridagent_filter(parent.template_id, item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Фильтр: "{item["name"]}"]')
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
                parent.stepChanged.emit(f'RED|    {result}  [Сценарий: "{item["name"]}"]')
                continue
            else:
                scenarios[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Сценарий "{item["name"]}" добавлен.')
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
        'SCADA': 'ffffff03-ffff-ffff-ffff-ffffff000017',
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
                                parent.stepChanged.emit(f'bRED|    Зона "{zone["name"]}": в контроле доступа "{service["service_id"]}" не найден список IP-адресов "{err}".')
                                error = 1
                        allowed_ips.append(item)
                    service['allowed_ips'] = allowed_ips
                service['service_id'] = service_ids.get(service['service_id'], 'ffffff03-ffff-ffff-ffff-ffffff000001')
                new_services_access.append(service)
        zone['services_access'] = new_services_access

        zone_networks = []
        for net in zone['networks']:
            if net[0] == 'list_id':
                try:
                    net[1] = parent.mc_data['ip_lists'][net[1]]
                except KeyError as err:
                    parent.stepChanged.emit(f'ORANGE|    Зона "{zone["name"]}": В защите от IP-спуфинга не найден список IP-адресов "{err}".')
                    error = 1
                    continue
            zone_networks.append(net)
        zone['networks'] = zone_networks

        sessions_limit_exclusions = []
        for item in zone['sessions_limit_exclusions']:
            try:
                item[1] = parent.mc_data['ip_lists'][item[1]]
            except KeyError as err:
                parent.stepChanged.emit(f'ORANGE|    Зона "{zone["name"]}": В ограничении сессий не найден список IP-адресов "{err}".')
                error = 1
                continue
            sessions_limit_exclusions.append(item)
        zone['sessions_limit_exclusions'] = sessions_limit_exclusions

        err, result = parent.utm.add_template_zone(parent.template_id, zone)
        if err == 3:
            parent.stepChanged.emit(f'GRAY|    {result}')
        elif err == 1:
            parent.stepChanged.emit(f'RED|    {result}')
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
                parent.stepChanged.emit(f'RED|    Error: Интерфейс {item["tunnel"]["mode"]} - {item["name"]} не импортирован!')
                parent.stepChanged.emit(f'RED|    {result}')
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
        parent.error = 1
        return
    netflow_profiles = {x['name']: x['id'] for x in result}
    netflow_profiles['undefined'] = 'undefined'

    err, result = parent.utm.get_template_lldp_profiles_list(parent.template_id)
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
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
            item['node_name'] = parent.node_name
            item['config_on_device'] = False
            item['link'] = current_port
            item['name'] = f'{current_port}.{item["vlan_id"]}'
            try:
                item['zone_id'] = 0 if current_zone == "Undefined" else parent.mc_data['zones'][current_zone]
            except KeyError as err:
                parent.stepChanged.emit(f"bRED|    В шаблоне не найдена зона {err} для VLAN {item['vlan_id']}. Импортируйте зоны и повторите попытку.")
                item['zone_id'] = 0
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
                parent.stepChanged.emit(f'RED|    Интерфейс {item["name"]} не импортирован. Error: {result}')
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
        parent.error = 1
        return
    gateways_list = {x.get('name', x['ipv4']): x['id'] for x in result}

    err, result = parent.utm.get_template_interfaces_list(parent.template_id, node_name=parent.node_name)
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return
    mc_ifaces = {x['name'] for x in result}

    err, result = parent.utm.get_template_vrf_list(parent.template_id)
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
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
        parent.error = 1
        return
    mc_dhcp_subnets = [x['name'] for x in result]

    for item in parent.dhcp_settings:
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
        item['node_name'] = parent.node_name

        err, result = parent.utm.add_template_dhcp_subnet(parent.template_id, item)
        if err == 1:
            error = 1
            parent.stepChanged.emit(f'RED|    {result}  [subnet "{item["name"]}"]')
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
            parent.stepChanged.emit(f'RED|    {result}')
            error = 1
        else:
            parent.stepChanged.emit(f'BLACK|    DNS сервер "{item["dns"]}" добавлен.')

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
            parent.stepChanged.emit(f'RED|    {result}')
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
            parent.stepChanged.emit(f'RED|    {result}')
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
        parent.error = 1
        return
    virt_routers = {x['name']: x['id'] for x in result}

    err, result = parent.utm.get_template_bfd_profiles_list(parent.template_id)
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return
    bfd_profiles = {x['name']: x['id'] for x in result}
    bfd_profiles[-1] = -1
    
    for item in data:
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
                err, result = parent.utm.update_template_vrf(parent.template_id, virt_routers[item['name']], item)
                if err:
                    parent.stepChanged.emit(f'RED|    {result} [vrf: "{item["name"]}"]')
                    error = 1
                else:
                    parent.stepChanged.emit(f'BLACK|    VRF "{item["name"]}" уже существует - Updated!')
            else:
                err, result = parent.utm.add_template_vrf(parent.template_id, item)
                if err:
                    parent.stepChanged.emit(f'RED|    {result} [vrf: "{item["name"]}"]')
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
        parent.error = 1
        return
    wccp_rules = {x['name']: x['id'] for x in result}

    for item in data:
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
            err, result = parent.utm.update_template_wccp_rule(parent.template_id, wccp_rules[item['name']], item)
            if err:
                parent.stepChanged.emit(f'RED|    {result}')
                error = 1
            else:
                parent.stepChanged.emit(f'GRAY|    Правило WCCP "{item["name"]}" уже существует. Произведено обновление.')
        else:
            err, result = parent.utm.add_template_wccp_rule(parent.template_id, item)
            if err:
                parent.stepChanged.emit(f'RED|    {result}')
                error = 1
            else:
                parent.stepChanged.emit(f'BLACK|    Правило WCCP "{item["name"]}" добавлено.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Ошибка импорта правил WCCP!')
    else:
        parent.stepChanged.emit('GREEN|    Правила WCCP импортированы в раздел "Сеть/WCCP".')

###########################################
def import_general_settings(parent, path):
    """Импортируем раздел 'UserGate/Настройки'."""
#    import_ui(parent, path)
#    import_modules(parent, path)
#    import_ntp_settings(parent, path)
    import_proxy_port(parent, path)

def import_ui(parent, path):
    """Импортируем часовой пояс"""
    json_file = os.path.join(path, 'config_settings_ui.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт часового пояса и локализации интерфейса в "Настройки/Настройки интерфейса".')
    params = {
        'ui_timezone': 'Часовой пояс',
        'ui_language': 'Язык интерфейса по умолчанию',
    }
    error = 0

    for key in data:
        if key in params:
            setting = {}
            setting[key] = {'value': data[key]}
            err, result = parent.utm.set_template_settings(parent.template_id, setting)
            if err:
                parent.stepChanged.emit(f'RED|    {result}')
                error = 1
                parent.error = 1
            else:
                parent.stepChanged.emit(f'BLACK|    "{params[key]}" установлен в знчение "{data[key]}".')

    out_message = 'GREEN|    Часовой пояс и локализация интерфейса импортированы в раздел "Настройки/Настройки интерфейса".'
    parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте часового пояса и локализации интерфейса.' if error else out_message)


def import_modules(parent, path):
    """Импортируем модули"""
    json_file = os.path.join(path, 'config_settings_modules.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт домена captive-портала в "Настройки/Модули".')
    params = {
        'auth_captive': 'Домен Auth captive-портала',
        'logout_captive': 'Домен Logout captive-портала',
        'block_page_domain': 'Домен страницы блокировки',
        'ftpclient_captive': 'FTP поверх HTTP домен',
        'ftp_proxy_enabled': 'FTP поверх HTTP',
        'lldp_config': 'Настройка LLDP',
    }
    error = 0
    
    for key in data:
        if key in params:
            setting = {}
            setting[key] = {'value': data[key]}
            err, result = parent.utm.set_template_settings(parent.template_id, setting)
            if err:
                parent.stepChanged.emit(f'RED|    {result}')
                error = 1
                parent.error = 1
            else:
                parent.stepChanged.emit(f'BLACK|    "{params[key]}" установлен в знчение "{data[key]}".')

    out_message = 'GREEN|    Настройки домена captive-портала импортированы в раздел "Настройки/Модули".'
    parent.stepChanged.emit('ORANGE|    Импорт домена captive-портала прошёл с ошибками.' if error else out_message)


def import_ntp_settings(parent, path):
    """Импортируем настройки NTP"""
    json_file = os.path.join(path, 'config_ntp.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт настроек NTP раздела "Настройки/Настройки времени сервера".')
    error = 0
    for i, ntp_server in enumerate(data['ntp_servers']):
        ns = {f'ntp_server{i+1}': {'value': ntp_server}}
        err, result = parent.utm.set_template_settings(parent.template_id, ns)
        if err:
            parent.stepChanged.emit(f'RED|    {result}')
            error = 1
            parent.error = 1
        else:
            parent.stepChanged.emit(f'BLACK|    NTP-сервер {ntp_server} добавлен.')

    err, result = parent.utm.set_template_settings(parent.template_id, {'ntp_enabled': {'value': data['ntp_enabled']}})
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        error = 1
        parent.error = 1
    else:
        parent.stepChanged.emit(f'BLACK|    Использование NTP {"включено" if data["ntp_enabled"] else "отключено"}.')

    out_message = 'GREEN|    Импортированы сервера NTP в раздел "Настройки/Настройки времени сервера".'
    parent.stepChanged.emit('ORANGE|    Произоша ошибка при импорте настроек NTP.' if error else out_message)


def import_proxy_port(parent, path):
    """Импортируем раздел UserGate/Настройки/Модули/HTTP(S)-прокси порт"""
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

#---------------------------------------- Пользователи и устройства --------------------------------------------------------
def import_local_groups(parent, path):
    """Импортируем список локальных групп пользователей"""
    json_file = os.path.join(path, 'config_groups.json')
    err, groups = func.read_json_file(parent, json_file)
    if err:
        return
    err, result = parent.utm.get_template_groups_list(parent.template_id)
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return
    local_groups = {x['name']: x['id'] for x in result}

    parent.stepChanged.emit('BLUE|Импорт локальных групп пользователей в раздел "Пользователи и устройства/Группы".')
    parent.stepChanged.emit(f'LBLUE|    Если используются доменные пользователи, необходимы настроенные LDAP-коннекторы в "Управление областью/Каталоги пользователей"')
    error = 0

    for item in groups:
        users = item.pop('users')
        item['name'] = func.get_restricted_name(item['name'])
        err, result = parent.utm.add_template_group(parent.template_id, item)
        if err == 1:
            parent.stepChanged.emit(f'RED|    {result}')
            error = 1
            continue
        elif err == 3:
            parent.stepChanged.emit(f'GRAY|    {result}') # В версиях 6 и выше проверяется что группа уже существует.
        else:
            local_groups[item['name']] = result
            parent.stepChanged.emit(f'BLACK|    Локальная группа "{item["name"]}" импортирована.')

        # Добавляем доменных пользователей в группу.
        parent.stepChanged.emit(f'LBLUE|       Добавляем доменных пользователей в группу "{item["name"]}".')
        for user_name in users:
            user_array = user_name.split(' ')
            if len(user_array) > 1 and ('\\' in user_array[1]):
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
                    err2, result2 = parent.utm.add_user_in_template_group(parent.template_id, local_groups[item['name']], result1)
                    if err2:
                        parent.stepChanged.emit(f'RED|       {result2}  [{user_name}]')
                        error = 1
                    else:
                        parent.stepChanged.emit(f'BLACK|       Пользователь "{user_name}" добавлен в группу "{item["name"]}".')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте локальных групп пользователей.')
    else:
        parent.stepChanged.emit('GREEN|    Локальные группы пользователей импортирован в раздел "Пользователи и устройства/Группы".')


def import_local_users(parent, path):
    """Импортируем список локальных пользователей"""
    json_file = os.path.join(path, 'config_users.json')
    err, users = func.read_json_file(parent, json_file)
    if err:
        return

    err, result = parent.utm.get_template_users_list(parent.template_id)
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return
    local_users = {x['name']: x['id'] for x in result}

    err, result = parent.utm.get_template_groups_list(parent.template_id)
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return
    local_groups = {x['name']: x['id'] for x in result}

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
            local_users[item['name']] = result
            parent.stepChanged.emit(f'BLACK|    Добавлен локальный пользователь "{item["name"]}".')

        # Добавляем пользователя в группу.
        for group in user_groups:
            try:
                group_guid = local_groups[group]
            except KeyError as err:
                parent.stepChanged.emit(f'bRED|       Не найдена группа {err} для пользователя {item["name"]}. Импортируйте список групп и повторите импорт пользователей.')
            else:
                err2, result2 = parent.utm.add_user_in_template_group(parent.template_id, group_guid, local_users[item['name']])
                if err2:
                    parent.stepChanged.emit(f'RED|       {result2}  [User: {item["name"]}, Group: {group}]')
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

    err, result = parent.utm.get_template_certificates_list(parent.template_id)
    if err == 1:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return
    template_certs = {x['name']: x['id'] for x in result}

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
                        item['certificate_id'] = template_certs[item['certificate_id']]
                    except KeyError:
                        parent.stepChanged.emit(f'bRED|    Для "{item["name"]}" не найден сертификат "{item["certificate_id"]}".')
                        item['certificate_id'] = 0
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


def import_firewall_rules(parent, path):
    """Импортировать список правил межсетевого экрана"""
    parent.stepChanged.emit('BLUE|Импорт правил межсетевого экрана в раздел "Политики сети/Межсетевой экран".')
    json_file = os.path.join(path, 'config_firewall_rules.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    err, result = parent.utm.get_template_firewall_rules(parent.template_id)
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return
    firewall_rules = {x['name']: x['id'] for x in result}

    if not parent.mc_zones:
        if set_mc_zones(parent):     # Устанавливаем атрибут parent.mc_zones
            return

    if not parent.mc_services:
        if set_mc_services(parent):     # Устанавливаем атрибут parent.mc_services
            return

    if not parent.mc_servicegroups:
        if set_mc_servicegroups(parent):     # Устанавливаем атрибут parent.mc_servicegroups
            return

    if not parent.mc_iplists:
        if set_mc_iplists(parent):     # Устанавливаем атрибут parent.mc_iplists
            return

    if not parent.mc_url_lists:
        if set_mc_url_lists(parent):     # Устанавливаем атрибут parent.mc_url_lists
            return

    if not parent.mc_time_restrictions:
        if set_mc_time_restrictions(parent):     # Устанавливаем атрибут parent.mc_time_restrictions
            return

    error = 0
    for item in data:
        item.pop('time_created', None)
        item.pop('time_updated', None)
        item.pop('apps', None)
        item.pop('apps_negate', None)
        item['name'] = func.get_restricted_name(item['name'])
    
        item['position'] = 'last'
        item['position_layer'] = 'pre'
        item['ips_profile'] = False
        item['l7_profile'] = False
        item['hip_profile'] = []
        item['src_zones'] = get_zones(parent, item['src_zones'], item["name"])
        item['dst_zones'] = get_zones(parent, item['dst_zones'], item["name"])
        item['src_ips'] = get_ips(parent, item['src_ips'], item["name"])
        item['dst_ips'] = get_ips(parent, item['dst_ips'], item["name"])
        item['users'] = get_guids_users_and_groups(parent, item['users'], item['name']) if parent.mc_data['ldap_servers'] else []
        item['services'] = get_services(parent, item['services'], item['name'])
        item['time_restrictions'] = get_time_restrictions(parent, item['time_restrictions'], item['name'])
        
        if item['name'] in firewall_rules:
            parent.stepChanged.emit(f'GRAY|    Правило МЭ "{item["name"]}" уже существует.')
            item.pop('position', None)
            err, result = parent.utm.update_template_firewall_rule(parent.template_id, firewall_rules[item['name']], item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|       {result}  [Правило МЭ: "{item["name"]}"]')
            else:
                parent.stepChanged.emit(f'BLACK|       Правило МЭ "{item["name"]}" обновлено.')
        else:
            item['enabled'] = False
            err, result = parent.utm.add_template_firewall_rule(parent.template_id, item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Правило МЭ: "{item["name"]}"]')
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
    parent.stepChanged.emit('LBLUE|    После импорта правила NAT будут в не активном состоянии. Необходимо проверить и включить нужные.')
    error = 0

    if not parent.scenarios_rules:
        set_scenarios_rules(parent)

    err, result = parent.utm.get_template_gateways_list(parent.template_id)
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return
    mc_gateways = {x['name']: f'{x["id"]}:{x["node_name"]}' for x in result if 'name' in x}

    if not parent.mc_zones:
        if set_mc_zones(parent):     # Устанавливаем атрибут parent.mc_zones
            return

    if not parent.mc_services:
        if set_mc_services(parent):     # Устанавливаем атрибут parent.mc_services
            return

    if not parent.mc_servicegroups:
        if set_mc_servicegroups(parent):     # Устанавливаем атрибут parent.mc_servicegroups
            return

    if not parent.mc_iplists:
        if set_mc_iplists(parent):     # Устанавливаем атрибут parent.mc_iplists
            return

    if not parent.mc_url_lists:
        if set_mc_url_lists(parent):     # Устанавливаем атрибут parent.mc_url_lists
            return

    err, result = parent.utm.get_template_traffic_rules(parent.template_id)
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return
    nat_rules = {x['name']: x['id'] for x in result}

    for item in data:
        item.pop('time_created', None)
        item.pop('time_updated', None)
        item['name'] = func.get_restricted_name(item['name'])
        item['position'] = 'last'
        item['position_layer'] = 'pre'
        item['zone_in'] = get_zones(parent, item['zone_in'], item['name'])
        item['zone_out'] = get_zones(parent, item['zone_out'], item['name'])
        item['source_ip'] = get_ips(parent, item['source_ip'], item['name'])
        item['dest_ip'] = get_ips(parent, item['dest_ip'], item['name'])
        item['service'] = get_services(parent, item['service'], item['name'])
        item['gateway'] = mc_gateways.get(item['gateway'], item['gateway'])
        item['users'] = get_guids_users_and_groups(parent, item['users'], item['name']) if parent.mc_data['ldap_servers'] else []
        if item['scenario_rule_id']:
            try:
                item['scenario_rule_id'] = parent.scenarios_rules[item['scenario_rule_id']]
            except KeyError as err:
                parent.stepChanged.emit(f'bRED|    Правило "{item["name"]}": не найден сценарий "{err}". Загрузите сценарии и повторите попытку.')
                item['scenario_rule_id'] = False
            
        if item['action'] == 'route':
            parent.stepChanged.emit(f'LBLUE|    Проверьте шлюз для правила ПБР "{item["name"]}". В случае отсутствия, установите вручную.')

        if item['name'] in nat_rules:
            parent.stepChanged.emit(f'GRAY|    Правило "{item["name"]}" уже существует.')
            item.pop('position', None)
            err, result = parent.utm.update_template_traffic_rule(parent.template_id, nat_rules[item['name']], item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|       {result}  [Правило: {item["name"]}]')
            else:
                parent.stepChanged.emit(f'BLACK|       Правило "{item["name"]}" updated.')
        else:
            item['enabled'] = False
            err, result = parent.utm.add_template_traffic_rule(parent.template_id, item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Правило: {item["name"]}]')
            else:
                nat_rules[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Правило "{item["name"]}" импортировано.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил NAT.')
    else:
        parent.stepChanged.emit('GREEN|    Правила NAT импортированы в раздел "Политики сети/NAT и маршрутизация".')


def import_shaper_rules(parent, path):
    """Импортируем список правил пропускной способности"""
    parent.stepChanged.emit('BLUE|Импорт правил пропускной способности в раздел "Политики сети/Пропускная способность".')
    json_file = os.path.join(path, 'config_shaper_rules.json')
    err, data = func.read_json_file(parent, json_file)
    if err:
        return
    error = 0

    if not parent.scenarios_rules:
        set_scenarios_rules(parent)

    if not parent.mc_zones:
        if set_mc_zones(parent):     # Устанавливаем атрибут parent.mc_zones
            return

    if not parent.mc_services:
        if set_mc_services(parent):     # Устанавливаем атрибут parent.mc_services
            return

    if not parent.mc_servicegroups:
        if set_mc_servicegroups(parent):     # Устанавливаем атрибут parent.mc_servicegroups
            return

    if not parent.mc_iplists:
        if set_mc_iplists(parent):     # Устанавливаем атрибут parent.mc_iplists
            return

    if not parent.mc_url_lists:
        if set_mc_url_lists(parent):     # Устанавливаем атрибут parent.mc_url_lists
            return

    if not parent.mc_time_restrictions:
        if set_mc_time_restrictions(parent):     # Устанавливаем атрибут parent.mc_time_restrictions
            return

    err, result = parent.utm.get_template_shapers_list(parent.template_id)
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return
    shaper_list = {x['name']: x['id'] for x in result}

    err, result = parent.utm.get_template_shaper_rules(parent.template_id)
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return
    shaper_rules = {x['name']: x['id'] for x in result}

    err, result = parent.utm.get_l7_categories()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return
    parent.l7categories = {x['name']: x['id'] for x in result}

    if not parent.application_groups:
        err, result = parent.utm.get_template_nlists_list(parent.template_id, 'applicationgroup')
        if err:
            parent.stepChanged.emit(f'RED|    {result}')
            parent.error = 1
            return
        parent.application_groups = {x['name']: x['id'] for x in result}

    parent.stepChanged.emit('LBLUE|    После импорта правила пропускной способности будут в не активном состоянии. Необходимо проверить и включить нужные.')
    for item in data:
        item['name'] = func.get_restricted_name(item['name'])
        item['position'] = 'last'
        item['position_layer'] = 'pre'
        if item['scenario_rule_id']:
            try:
                item['scenario_rule_id'] = parent.scenarios_rules[item['scenario_rule_id']]
            except KeyError as err:
                parent.stepChanged.emit(f'bRED|    Правило "{item["name"]}": не найден сценарий "{err}". Загрузите сценарии и повторите попытку.')
                item['scenario_rule_id'] = False
        item['src_zones'] = get_zones(parent, item['src_zones'], item['name'])
        item['dst_zones'] = get_zones(parent, item['dst_zones'], item['name'])
        item['src_ips'] = get_ips(parent, item['src_ips'], item['name'])
        item['dst_ips'] = get_ips(parent, item['dst_ips'], item['name'])
        item['services'] = get_services(parent, item['services'], item['name'])
        item['users'] = get_guids_users_and_groups(parent, item['users'], item['name']) if parent.mc_data['ldap_servers'] else []
        item['apps'] = get_apps(parent, item['apps'], item['name'])
        item['time_restrictions'] = get_time_restrictions(parent, item['time_restrictions'], item['name'])
        try:
            item['pool'] = shaper_list[item['pool']]
        except KeyError as err:
            parent.stepChanged.emit(f'bRED|    Правило "{item["name"]}": не найдена полоса пропускания "{item["pool"]}". Импортируйте полосы пропускания и повторите попытку.')
            item['pool'] = 1
            error = 1

        if item['name'] in shaper_rules:
            parent.stepChanged.emit(f'GRAY|    Правило пропускной способности "{item["name"]}" уже существует.')
            err, result = parent.utm.update_template_shaper_rule(parent.template_id, shaper_rules[item['name']], item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|       {result}  [Правило: {item["name"]}]')
            else:
                parent.stepChanged.emit(f'BLACK|       Правило пропускной способности "{item["name"]}" updated.')
        else:
            item['enabled'] = False
            err, result = parent.utm.add_template_shaper_rule(parent.template_id, item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Правило: {item["name"]}]')
            else:
                shaper_rules[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Правило пропускной способности "{item["name"]}" добавлено.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил пропускной способности.')
    else:
        parent.stepChanged.emit('GREEN|    Правила пропускной способности импортированы в раздел "Политики сети/Пропускная способность".')


def import_content_rules(parent, path):
    """Импортировать список правил фильтрации контента"""
    parent.stepChanged.emit('BLUE|Импорт правил фильтрации контента в раздел "Политики безопасности/Фильтрация контента".')
    json_file = os.path.join(path, 'config_content_rules.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    if not parent.scenarios_rules:
        set_scenarios_rules(parent)

    err, result = parent.utm.get_template_content_rules(parent.template_id)
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return
    content_rules = {x['name']: x['id'] for x in result}

    if not parent.mc_zones:     # Устанавливаем атрибут parent.mc_zones
        if set_mc_zones(parent):
            return

    if not parent.mc_iplists:
        if set_mc_iplists(parent):     # Устанавливаем атрибут parent.mc_iplists
            return

    if not parent.mc_url_lists:
        if set_mc_url_lists(parent):     # Устанавливаем атрибут parent.mc_url_lists
            return

    if not parent.mc_time_restrictions:
        if set_mc_time_restrictions(parent):     # Устанавливаем атрибут parent.mc_time_restrictions
            return

    err, result = parent.utm.get_template_nlists_list(parent.template_id, 'urlcategorygroup')
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return
    url_category_groups = {x['name']: x['id'] for x in result}

    err, result = parent.utm.get_url_categories()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return
    url_categories = {x['name']: x['id'] for x in result}

    error = 0
    for item in data:
        item.pop('time_created', None)
        item.pop('time_updated', None)
        item['name'] = func.get_restricted_name(item['name'])
        item['position'] = 'last'
        item['position_layer'] = 'pre'
        item['src_zones'] = get_zones(parent, item['src_zones'], item["name"])
        item['dst_zones'] = get_zones(parent, item['dst_zones'], item["name"])
        item['src_ips'] = get_ips(parent, item['src_ips'], item["name"])
        item['dst_ips'] = get_ips(parent, item['dst_ips'], item["name"])
        item['users'] = get_guids_users_and_groups(parent, item['users'], item['name']) if parent.mc_data['ldap_servers'] else []
        item['url_categories'] = get_url_categories_id(parent, item['url_categories'], url_category_groups, url_categories, item["name"])
        item['urls'] = get_urls_id(parent, item['urls'], item["name"])
        item['time_restrictions'] = get_time_restrictions(parent, item['time_restrictions'], item['name'])
        if item['scenario_rule_id']:
            try:
                item['scenario_rule_id'] = parent.scenarios_rules[item['scenario_rule_id']]
            except KeyError as err:
                parent.stepChanged.emit(f'bRED|    Правило "{item["name"]}": не найден сценарий "{err}". Загрузите сценарии и повторите попытку.')
                item['scenario_rule_id'] = False
            

        if item['name'] in content_rules:
            parent.stepChanged.emit(f'GRAY|    Правило контентной фильтрации "{item["name"]}" уже существует.')
            item.pop('position', None)
            err, result = parent.utm.update_template_content_rule(parent.template_id, content_rules[item['name']], item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|       {result}  [Правило "{item["name"]}"]')
            else:
                parent.stepChanged.emit(f'BLACK|       Правило контентной фильтрации "{item["name"]}" обновлено.')
        else:
            err, result = parent.utm.add_template_content_rule(parent.template_id, item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Правило "{item["name"]}"]')
            else:
                content_rules[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Правило контентной фильтрации "{item["name"]}" добавлено.')

    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил контентной фильтрации.')
    else:
        parent.stepChanged.emit('GREEN|    Правила контентной фильтрации импортированы в раздел "Политики безопасности/Фильтрация контента".')


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
    'Certificates': pass_function,
    'UserCertificateProfiles': pass_function, # import_users_certificate_profiles,
    'GeneralSettings': import_general_settings,
#    'DeviceManagement': pass_function,
#    'Administrators': pass_function,
    'AuthServers': import_auth_servers,
    'AuthProfiles': pass_function, # import_auth_profiles,
    'CaptiveProfiles': pass_function, # import_captive_profiles,
    'CaptivePortal': pass_function, # import_captive_portal_rules,
    'Groups': import_local_groups,
    'Users': import_local_users,
    'TerminalServers': pass_function, # import_terminal_servers,
    'MFAProfiles': pass_function, # import_2fa_profiles,
    'UserIDagent': pass_function, # import_userid_agent,
    'BYODPolicies': pass_function, # import_byod_policy,
    'BYODDevices': pass_function,
    'Firewall': import_firewall_rules,
    'NATandRouting': import_nat_rules,
    "ICAPServers": pass_function, # import_icap_servers,
    "ReverseProxyServers": pass_function, # import_reverseproxy_servers,
    'LoadBalancing': pass_function, # import_loadbalancing_rules,
    'TrafficShaping': import_shaper_rules,
    "ContentFiltering": import_content_rules,
    "SafeBrowsing": pass_function, # import_safebrowsing_rules,
    "TunnelInspection": pass_function, # import_tunnel_inspection_rules,
    "SSLInspection": pass_function, # import_ssldecrypt_rules,
    "SSHInspection": pass_function, # import_sshdecrypt_rules,
    "IntrusionPrevention": pass_function, # import_idps_rules,
    "MailSecurity": pass_function, # import_mailsecurity,
    "ICAPRules": pass_function, # import_icap_rules,
    "DoSProfiles": pass_function, # import_dos_profiles,
    "DoSRules": pass_function, # import_dos_rules,
    "SCADARules": pass_function, # import_scada_rules,
    "CustomWafLayers": pass_function, # import_waf_custom_layers,
    "SystemWafRules": pass_function, # pass_function,
    "WAFprofiles": pass_function, # import_waf_profiles,
    "WebPortal": pass_function, # import_proxyportal_rules,
    "ReverseProxyRules": pass_function, # import_reverseproxy_rules,
    "ServerSecurityProfiles": pass_function, # import_vpnserver_security_profiles,
    "ClientSecurityProfiles": pass_function, # import_vpnclient_security_profiles,
    "SecurityProfiles": pass_function, # import_vpn_security_profiles,
    "VPNNetworks": pass_function, # import_vpn_networks,
    "ServerRules": pass_function, # import_vpn_server_rules,
    "ClientRules": pass_function, # import_vpn_client_rules,
    "AlertRules": pass_function, # import_notification_alert_rules,
    "SNMPSecurityProfiles": pass_function, # import_snmp_security_profiles,
    "SNMP": pass_function, # import_snmp_rules,
    "SNMPParameters": pass_function, # import_snmp_settings,
}

######################################### Служебные функции ################################################
def get_ips(parent, rule_ips, rule_name):
    """Получить UID-ы списков IP-адресов. Если список IP-адресов не существует на MC, то он пропускается."""
    new_rule_ips = []
    for ips in rule_ips:
        if ips[0] == 'geoip_code':
            new_rule_ips.append(ips)
        try:
            if ips[0] == 'list_id':
                new_rule_ips.append(['list_id', parent.mc_iplists[ips[1]]])
            elif ips[0] == 'urllist_id':
                new_rule_ips.append(['urllist_id', parent.mc_url_lists[ips[1]]])
        except KeyError as err:
            parent.stepChanged.emit(f'bRED|    Error! Правило "{rule_name}": Не найден список IP-адресов "{ips[1]}". Загрузите списки в библиотеку и повторите импорт.')
    return new_rule_ips


def get_zones(parent, zones, rule_name):
    """Получить UID-ы зон. Если зона не существует на MC, то она пропускается."""
    new_zones = []
    for zone in zones:
        try:
            new_zones.append(parent.mc_zones[zone])
        except KeyError as err:
            error = 1
            parent.stepChanged.emit(f'bRED|    Error! Не найдена зона {zone} для правила {rule_name}.')
    return new_zones


def get_guids_users_and_groups(parent, users, rule_name):
    """
    Получить GUID-ы групп и пользователей по их именам.
    Заменяет имена локальных и доменных пользователей и групп на GUID-ы.
    """
    if not users:
        return []

    new_users = []
    for item in users:
        match item[0]:
            case 'special':
                new_users.append(item)
            case 'user':
                user_name = None
                try:
                    ldap_domain, _, user_name = item[1].partition("\\")
                except IndexError:
                    parent.stepChanged.emit(f'NOTE|    Error [Правило "{rule_name}"]: Не указано имя пользователя в {item}')
                if user_name:
                    try:
                        ldap_id = parent.mc_data['ldap_servers'][ldap_domain.lower()]
                    except KeyError:
                        parent.stepChanged.emit(f'NOTE|    Error [Правило "{rule_name}"]: Нет LDAP-коннектора для домена "{ldap_domain}"')
                    else:
                        err, result = parent.utm.get_usercatalog_ldap_user_guid(ldap_id, user_name)
                        if err:
                            parent.stepChanged.emit(f'bRED|    {result}  [Правило "{rule_name}"]')
                        elif not result:
                            parent.stepChanged.emit(f'NOTE|    Error [Правило "{rule_name}"]: Нет пользователя "{user_name}" в домене "{ldap_domain}"!')
                        else:
                            new_users.append(['user', result])
            case 'group':
                group_name = None
                try:
                    ldap_domain, _, group_name = item[1].partition("\\")
                except IndexError:
                    parent.stepChanged.emit(f'NOTE|    Error [Правило "{rule_name}"]: Не указано имя группы в {item}')
                if group_name:
                    try:
                        ldap_id = parent.mc_data['ldap_servers'][ldap_domain.lower()]
                    except KeyError:
                        parent.stepChanged.emit(f'NOTE|    Error [Правило "{rule_name}"]: Нет LDAP-коннектора для домена "{ldap_domain}"')
                    else:
                        err, result = parent.utm.get_usercatalog_ldap_group_guid(ldap_id, group_name)
                        if err:
                            parent.stepChanged.emit(f'bRED|    {result}  [Правило "{rule_name}"]')
                        elif not result:
                            parent.stepChanged.emit(f'NOTE|    Error [Правило "{rule_name}"]: Нет группы "{group_name}" в домене "{ldap_domain}"!')
                        else:
                            new_users.append(['group', result])
    return new_users


def get_services(parent, service_list, rule_name):
    """Получаем ID сервисов по из именам. Если сервис не найден, то он пропускается."""
    new_service_list = []
    for item in service_list:
        try:
            if item[0] == 'service':
                new_service_list.append(['service', parent.mc_services[item[1]]])
            elif item[0] == 'list_id':
                new_service_list.append(['list_id', parent.mc_servicegroups[item[1]]])
        except KeyError as err:
            parent.stepChanged.emit(f'bRED|    Error [Правило {rule_name}]: Не найден сервис "{item[1]}".')
    return new_service_list


def get_url_categories_id(parent, url_categories, rule_name):
    """Получаем ID категорий URL и групп категорий URL. Если список не существует на MC, то он пропускается."""
    new_categories = []
    for item in url_categories:
        try:
            if item[0] == 'list_id':
                new_categories.append(['list_id', parent.mc_data['url_categorygroups'][item[1]]])
            if item[0] == 'category_id':
                new_categories.append(['category_id', parent.mc_data['url categories'][item[1]]])
        except KeyError as err:
            parent.stepChanged.emit(f'bRED|    Error [Правило {rule_name}]: Не найдена категория URL "{item[1]}". Загрузите категории URL и повторите импорт.')
    return new_categories


def get_urls_id(parent, urls, rule_name):
    """Получаем ID списков URL. Если список не существует на MC, то он пропускается."""
    new_urls = []
    for item in urls:
        try:
            new_urls.append(parent.mc_url_lists[item])
        except KeyError as err:
            parent.stepChanged.emit(f'bRED|    Error [Правило {rule_name}]: Не найден список URL "{item}". Загрузите списки URL и повторите импорт.')
    return new_urls


def get_apps(parent, array_apps, rule_name):
    """Определяем ID приложения или группы приложений по именам."""
    new_app_list = []
    for app in array_apps:
        if app[0] == 'ro_group':
            if app[1] == 'All':
                new_app_list.append(['ro_group', 0])
            else:
                try:
                    new_app_list.append(['ro_group', parent.mc_data['l7_categories'][app[1]]])
                except KeyError as err:
                    parent.stepChanged.emit(f'bRED|    Error! Правило "{rule_name}": Не найдена категория l7 "{app[1]}".')
                    parent.stepChanged.emit(f'bRED|    Возможно нет лицензии и MC не получил список категорий l7. Установите лицензию и повторите попытку.')
        elif app[0] == 'group':
            try:
                new_app_list.append(['group', parent.mc_data['application_groups'][app[1]]])
            except KeyError as err:
                parent.stepChanged.emit(f'bRED|    Error! Правило "{rule_name}": Не найдена группа приложений l7 "{app[1]}".')
    return new_app_list


def get_time_restrictions(parent, time_restrictions, rule_name):
    """Получаем ID календарей шаблона по их именам. Если календарь не найден в шаблоне, то он пропускается."""
    new_schedules = []
    for name in time_restrictions:
        try:
            new_schedules.append(parent.mc_time_restrictions[name])
        except KeyError:
            parent.stepChanged.emit(f'bRED|    Error [Правило "{rule_name}"]: Не найден календарь "{name}".')
    return new_schedules


def get_response_pages(parent):
    """Получаем список шаблонов страниц и устанавливаем значение атрибута parent.response_pages."""
    err, result = parent.utm.get_template_responsepages_list(parent.template_id)
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return 1
    parent.response_pages = {x['name']: x['id'] for x in result}
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

