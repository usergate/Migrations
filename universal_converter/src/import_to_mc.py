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
# Версия 3.6   21.01.2025  (только для universal_converter)
#

import os, sys, json, time
import copy
import common_func as func
from dataclasses import dataclass
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

        self.waf_custom_layers = {}
        self.users_signatures = {}
        self.error = 0

    def run(self):
        """Импортируем всё в пакетном режиме"""
        # Читаем бинарный файл библиотечных данных.
        err, self.mc_data = func.read_bin_file(self)
        if err:
            self.stepChanged.emit('iRED|Импорт конфигурации в шаблон Management Center прерван! Не удалось прочитать служебные данные.')
            return

        path_dict = {}
#        try:
        for item in self.all_points:
            top_level_path = os.path.join(self.config_path, item['path'])
            for point in item['points']:
                path_dict[point] = os.path.join(top_level_path, point)
        for key, value in import_funcs.items():
            if key in path_dict:
                value(self, path_dict[key])
#        except Exception as err:
#            self.error = 1
#            self.stepChanged.emit(f'RED|Ошибка функции "{value.__name__}":  {err}')

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

        self.waf_custom_layers = {}
        self.users_signatures = {}
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
    err, data = func.read_json_file(parent, json_file, mode=2)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт списков морфологии в раздел "Библиотеки/Морфология".')
    error = 0

    if not parent.mc_data['morphology']:
        if get_morphology_list(parent):        # Заполняем parent.mc_data['morphology']
            parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте списков морфологии.')
            return

    morphology = parent.mc_data['morphology']

    for item in data:
        item['name'] = func.get_restricted_name(item['name'])
        content = item.pop('content')
        item.pop('last_update', None)

        if item['name'] in morphology:
            if parent.template_id == morphology[item['name']].template_id:
                parent.stepChanged.emit(f'uGRAY|    Список морфологии "{item["name"]}" уже существует в текущем шаблоне.')
                err, result = parent.utm.update_template_nlist(parent.template_id, morphology[item['name']].id, item)
                if err == 1:
                    parent.stepChanged.emit(f'RED|       {result}  [Список морфологии "{item["name"]}"]')
                    error = 1
                    continue
                elif err == 3:
                    parent.stepChanged.emit(f'GRAY|       {result}')
                else:
                    parent.stepChanged.emit(f'uGRAY|       Список морфологии "{item["name"]}" обновлён.')
            else:
                parent.stepChanged.emit(f'sGREEN|    Список морфологии "{item["name"]}" уже существует в шаблоне "{morphology[item["name"]].template_name}".')
                continue
        else:
            err, result = parent.utm.add_template_nlist(parent.template_id, item)
            if err:
                parent.stepChanged.emit(f'RED|    {result}  [Список морфологии "{item["name"]}" не импортирован]')
                error = 1
                continue
            else:
                morphology[item['name']] = BaseObject(id=result, template_id=parent.template_id, template_name=parent.templates[parent.template_id])
                parent.stepChanged.emit(f'BLACK|    Список морфологии "{item["name"]}" импортирован.')

        if item['list_type_update'] == 'static':
            if content:
                for value in content:
                    err2, result2 = parent.utm.add_template_nlist_item(parent.template_id, morphology[item['name']].id, value)
                    if err2 == 3:
                        parent.stepChanged.emit(f'GRAY|       {result2}')
                    elif err2 == 1:
                        parent.stepChanged.emit(f'RED|       {result2}  [Список морфологии "{item["name"]}"]')
                        error = 1
                    elif err2 == 7:
                        parent.stepChanged.emit(f'bRED|       Error: Список морфологии "{item["name"]}" не найден в шаблоне "{morphology[item["name"]].template_name}".')
                        parent.stepChanged.emit(f'RED|          Error: Импорт прерван. Перелогиньтесь в МС и повторите попытку.')
                        parent.error = 1
                        return
                    else:
                        parent.stepChanged.emit(f'BLACK|       Добавлено "{value["value"]}".')
            else:
                parent.stepChanged.emit(f'GRAY|       Содержимое списка морфологии "{item["name"]}" не обновлено так как он пуст.')
        else:
            parent.stepChanged.emit(f'GRAY|       Содержимое списка морфологии "{item["name"]}" не обновлено так как он обновляется удалённо.')
        time.sleep(0.01)

    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте списков морфологии.')
    else:
        parent.stepChanged.emit('GREEN|    Импорт списков морфологии завершён.')


def import_services_list(parent, path):
    """Импортируем список сервисов раздела библиотеки"""
    json_file = os.path.join(path, 'config_services_list.json')
    err, data = func.read_json_file(parent, json_file, mode=2)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт списка сервисов в раздел "Библиотеки/Сервисы"')
    error = 0

    services = parent.mc_data['services']

    for item in data:
        item['name'] = func.get_restricted_name(item['name'])
        if item['name'] in services:
            if parent.template_id == services[item['name']].template_id:
                parent.stepChanged.emit(f'uGRAY|    Сервис "{item["name"]}" уже существует в текущем шаблоне.')
            else:
                parent.stepChanged.emit(f'sGREEN|    Сервис "{item["name"]}" уже существует в шаблоне "{services[item["name"]].template_name}".')
        else:
            err, result = parent.utm.add_template_service(parent.template_id, item)
            if err == 3:
                parent.stepChanged.emit(f'GRAY|    {result}')
            elif err == 1:
                parent.stepChanged.emit(f'RED|    {result} [Сервис "{item["name"]}" не импортирован]')
                error = 1
            else:
                services[item['name']] = BaseObject(id=result, template_id=parent.template_id, template_name=parent.templates[parent.template_id])
                parent.stepChanged.emit(f'BLACK|    Сервис "{item["name"]}" импортирован.')
        time.sleep(0.01)
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при добавлении сервисов.')
    else:
        parent.stepChanged.emit('GREEN|    Импорт списков сервисов завершён.')


def import_services_groups(parent, path):
    """Импортируем группы сервисов в раздел Библиотеки/Группы сервисов"""
    json_file = os.path.join(path, 'config_services_groups_list.json')
    err, data = func.read_json_file(parent, json_file, mode=2)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт групп сервисов раздела "Библиотеки/Группы сервисов".')
    out_message = 'GREEN|    Группы сервисов импортированы в раздел "Библиотеки/Группы сервисов".'
    error = 0

    servicegroups = parent.mc_data['service_groups']
    
    for item in data:
        item['name'] = func.get_restricted_name(item['name'])
        content = item.pop('content')
        item.pop('last_update', None)

        if item['name'] in servicegroups:
            if parent.template_id == servicegroups[item['name']].template_id:
                parent.stepChanged.emit(f'uGRAY|    Группа сервисов "{item["name"]}" уже существует в текущем шаблоне.')
                err, result = parent.utm.update_template_nlist(parent.template_id, servicegroups[item['name']].id, item)
                if err == 1:
                    parent.stepChanged.emit(f'RED|       {result} [Группа сервисов "{item["name"]}"]')
                    error = 1
                    continue
                elif err == 3:
                    parent.stepChanged.emit(f'GRAY|       {result}.')
                else:
                    parent.stepChanged.emit(f'uGRAY|       Группа сервисов "{item["name"]}" обновлена.')
            else:
                parent.stepChanged.emit(f'sGREEN|    Группа сервисов "{item["name"]}" уже существует в шаблоне "{servicegroups[item["name"]].template_name}".')
                continue
        else:
            err, result = parent.utm.add_template_nlist(parent.template_id, item)
            if err == 1:
                parent.stepChanged.emit(f'RED|    {result}  [Группа сервисов "{item["name"]}" не импортирована]')
                error = 1
                continue
            elif err == 3:
                parent.stepChanged.emit(f'GRAY|    {result}.')
            else:
                servicegroups[item['name']] = BaseObject(id=result, template_id=parent.template_id, template_name=parent.templates[parent.template_id])
                parent.stepChanged.emit(f'BLACK|    Группа сервисов "{item["name"]}" импортирована.')

        if item['list_type_update'] == 'static':
            if content:
                for service in content:
                    try:
                        tmp = parent.mc_data['services'][service['name']]
                    except KeyError as err:
                        parent.stepChanged.emit(f'RED|       Error: Не найден сервис "{err}". Загрузите сервисы в шаблон и повторите попытку.')
                        error = 1
                        continue
                    if tmp.template_id == parent.template_id:
                        service['value'] = tmp.id
                    else:
                        parent.stepChanged.emit(f'bRED|       Error: Сервис "{service["name"]}" не добавлен так как находиться в другом шаблоне ("{tmp.template_name}"). Можно добавлять сервисы только из текущего шаблона.')
                        continue
                    err2, result2 = parent.utm.add_template_nlist_item(parent.template_id, servicegroups[item['name']].id, service)
                    if err2 == 3:
                        parent.stepChanged.emit(f'GRAY|       Сервис "{service["name"]}" уже существует в этой группе сервисов.')
                    elif err2 == 1:
                        parent.stepChanged.emit(f'RED|       {result2}  [Группа сервисов "{item["name"]}"]')
                        error = 1
                    elif err2 == 7:
                        parent.stepChanged.emit(f'bRED|       Error: Группа сервисов "{item["name"]}" не найдена в шаблоне "{servicegroups[item["name"]].template_name}".')
                        parent.stepChanged.emit(f'RED|          Error: Импорт прерван. Перелогиньтесь в МС и повторите попытку.')
                        parent.error = 1
                        return
                    else:
                        parent.stepChanged.emit(f'BLACK|       Добавлен сервис "{service["name"]}".')
            else:
                parent.stepChanged.emit(f'GRAY|       Нет содержимого в группе сервисов "{item["name"]}".')
        else:
            parent.stepChanged.emit(f'GRAY|       Содержимое группы сервисов "{item["name"]}" не обновлено так как она обновляется удалённо.')
        time.sleep(0.01)

    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте групп сервисов.')
    else:
        parent.stepChanged.emit('GREEN|    Импорт групп сервисов завершён.')


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
    ip_lists = parent.mc_data['ip_lists']

    # Импортируем все списки IP-адресов без содержимого (пустые).
    parent.stepChanged.emit('LBLUE|    Импортируем списки IP-адресов без содержимого.')
    for file_name in files_list:
        json_file = os.path.join(path, file_name)
        err, data = func.read_json_file(parent, json_file, mode=2)
        if err:
            continue

        data['name'] = func.get_restricted_name(data['name'])
        content = data.pop('content')
        data.pop('last_update', None)

        if data['name'] in ip_lists:
            if parent.template_id == ip_lists[data['name']].template_id:
                parent.stepChanged.emit(f'uGRAY|    Список IP-адресов "{data["name"]}" уже существует в текущем шаблоне.')
            else:
                parent.stepChanged.emit(f'sGREEN|    Список IP-адресов "{data["name"]}" уже существует в шаблоне "{ip_lists[data["name"]].template_name}".')
                continue
        else:
            err, result = parent.utm.add_template_nlist(parent.template_id, data)
            if err == 1:
                parent.stepChanged.emit(f'RED|    {result}  [Список IP-адресов "{data["name"]}" не импортирован]')
                error = 1
            elif err == 3:
                parent.stepChanged.emit(f'GRAY|    {result}.')
            else:
                ip_lists[data['name']] = BaseObject(id=result, template_id=parent.template_id, template_name=parent.templates[parent.template_id])
                parent.stepChanged.emit(f'BLACK|    Список IP-адресов "{data["name"]}" импортирован.')

    # Импортируем содержимое в уже добавленные списки IP-адресов.
    parent.stepChanged.emit('LBLUE|    Импортируем содержимое списков IP-адресов.')
    for file_name in files_list:
        json_file = os.path.join(path, file_name)
        err, data = func.read_json_file(parent, json_file)
        if err:
            continue

        data['name'] = func.get_restricted_name(data['name'])
        parent.stepChanged.emit(f'BLACK|    Импортируем содержимое списка IP-адресов "{data["name"]}".')

        if parent.template_id == ip_lists[data['name']].template_id:
            if data['list_type_update'] == 'static':
                if data['content']:
                    new_content = []
                    for item in data['content']:
                        if 'list' in item:
                            item_list = func.get_restricted_name(item['list'])
                            item_value = f'IP-лист "{item_list}"'
                            try:
                                item['list'] = ip_lists[item_list].id
                                new_content.append(item)
                            except KeyError:
                                parent.stepChanged.emit(f'RED|       Error: {item_value} не добавлен в список так как не найден в данной группе шаблонов. ')
                                error = 1
                        else:
                            new_content.append(item)
#                            item_value = f'IP-адрес "{item["value"]}"'
                    if not new_content:
                        parent.stepChanged.emit(f'uGRAY|       Список "{data["name"]}" не имеет содержимого.')
                        continue

#                        err, result = parent.utm.add_template_nlist_item(parent.template_id, iplist['id'], item)
#                        if err == 1:
#                            parent.stepChanged.emit(f'RED|       {result} [{item_value}] не добавлен в список IP-адресов "{data["name"]}"')
#                            error = 1
#                        elif err == 3:
#                            parent.stepChanged.emit(f'uGRAY|       {item_value} уже существует.')
#                        else:
#                            parent.stepChanged.emit(f'BLACK|       Добавлен {item_value}.')
                    err, result = parent.utm.add_template_nlist_items(parent.template_id, ip_lists[data['name']].id, new_content)
                    if err == 1:
                        parent.stepChanged.emit(f'RED|       {result} [Список IP-адресов "{data["name"]}" содержимое не импортировано]')
                        error = 1
                    else:
                        parent.stepChanged.emit(f'BLACK|       Содержимое списка IP-адресов "{data["name"]}" обновлено.')
                else:
                    parent.stepChanged.emit(f'GRAY|       Список "{data["name"]}" пуст.')
            else:
                parent.stepChanged.emit(f'GRAY|       Содержимое списка IP-адресов "{data["name"]}" не обновлено так как он обновляется удалённо.')
        else:
            parent.stepChanged.emit(f'sGREEN|       Содержимое списка IP-адресов "{data["name"]}" не обновлено так как он находится в другом шаблоне.')
        time.sleep(0.01)

    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте списков IP-адресов.')
    else:
        parent.stepChanged.emit('GREEN|    Импорт списков IP-адресов завершён.')


def import_useragent_lists(parent, path):
    """Импортируем списки Useragent браузеров"""
    json_file = os.path.join(path, 'config_useragents_list.json')
    err, data = func.read_json_file(parent, json_file, mode=2)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт списка "Useragent браузеров" в раздел "Библиотеки/Useragent браузеров".')
    error = 0

    if not parent.mc_data['useragents']:
        if get_useragent_list(parent):        # Заполняем parent.mc_data['useragents']
            parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте списков Useragent браузеров.')
            return

    useragents = parent.mc_data['useragents']

    for item in data:
        item['name'] = func.get_restricted_name(item['name'])
        content = item.pop('content')
        item.pop('last_update', None)

        if item['name'] in useragents:
            if parent.template_id == useragents[item['name']].template_id:
                parent.stepChanged.emit(f'uGRAY|    Список Useragent "{item["name"]}" уже существует в текущем шаблоне.')
                err, result = parent.utm.update_template_nlist(parent.template_id, useragents[item['name']].id, item)
                if err == 1:
                    parent.stepChanged.emit(f'RED|       {result}  [Список Useragent {item["name"]}]')
                    error = 1
                    continue
                elif err == 3:
                    parent.stepChanged.emit(f'GRAY|       {result}')
                else:
                    parent.stepChanged.emit(f'uGRAY|       Список Useragent "{item["name"]}" обновлён.')
            else:
                parent.stepChanged.emit(f'sGREEN|    Список Useragent "{item["name"]}" уже существует в шаблоне "{useragents[item["name"]].template_name}".')
                continue
        else:
            err, result = parent.utm.add_template_nlist(parent.template_id, item)
            if err:
                parent.stepChanged.emit(f'RED|    {result}  [Список Useragent "{item["name"]}" не импортирован]')
                error = 1
                continue
            else:
                useragents[item['name']] = BaseObject(id=result, template_id=parent.template_id, template_name=parent.templates[parent.template_id])
                parent.stepChanged.emit(f'BLACK|    Список Useragent "{item["name"]}" импортирован.')

        if item['list_type_update'] == 'static':
            if content:
                err2, result2 = parent.utm.add_template_nlist_items(parent.template_id, useragents[item['name']].id, content)
                if err2 == 3:
                    parent.stepChanged.emit(f'GRAY|       {result2}')
                elif err2 == 1:
                    parent.stepChanged.emit(f'RED|       {result2}  [Список Useragent: "{item["name"]}"]')
                    error = 1
                else:
                    parent.stepChanged.emit(f'BLACK|       Содержимое списка Useragent "{item["name"]}" импортировано.')
            else:
                parent.stepChanged.emit(f'GRAY|       Список Useragent "{item["name"]}" пуст.')
        else:
            parent.stepChanged.emit(f'GRAY|       Содержимое списка Useragent "{item["name"]}" не импортировано так как он обновляется удалённо.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте списков Useragent браузеров.')
    else:
        parent.stepChanged.emit('GREEN|    Импорт списка "Useragent браузеров" завершён.')


def import_mime_lists(parent, path):
    """Импортируем списки Типов контента"""
    json_file = os.path.join(path, 'config_mime_types.json')
    err, data = func.read_json_file(parent, json_file, mode=2)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт списка "Типы контента" в раздел "Библиотеки/Типы контента".')
    error = 0

    mimes = parent.mc_data['mime']

    for item in data:
        item['name'] = func.get_restricted_name(item['name'])
        content = item.pop('content')
        item.pop('last_update', None)

        if item['name'] in mimes:
            if parent.template_id == mimes[item['name']].template_id:
                parent.stepChanged.emit(f'uGRAY|    Список Типов контента "{item["name"]}" уже существует в текущем шаблоне.')
                err, result = parent.utm.update_template_nlist(parent.template_id, mimes[item['name']].id, item)
                if err == 1:
                    parent.stepChanged.emit(f'RED|       {result}  [Список Типов контента "{item["name"]}"]')
                    error = 1
                    continue
                elif err == 3:
                    parent.stepChanged.emit(f'GRAY|       {result}')
                else:
                    parent.stepChanged.emit(f'uGRAY|       Список Типов контента "{item["name"]}" обновлён.')
            else:
                parent.stepChanged.emit(f'sGREEN|    Список Типов контента "{item["name"]}" уже существует в шаблоне "{mimes[item["name"]].template_name}".')
                continue
        else:
            err, result = parent.utm.add_template_nlist(parent.template_id, item)
            if err:
                parent.stepChanged.emit(f'RED|    {result}  [Список Типов контента "{item["name"]}" не импортирован]')
                error = 1
                continue
            else:
                mimes[item['name']] = BaseObject(id=result, template_id=parent.template_id, template_name=parent.templates[parent.template_id])
                parent.stepChanged.emit(f'BLACK|    Список Типов контента "{item["name"]}" импортирован.')

        if item['list_type_update'] == 'static':
            if content:
                err2, result2 = parent.utm.add_template_nlist_items(parent.template_id, mimes[item['name']].id, content)
                if err2 == 3:
                    parent.stepChanged.emit(f'GRAY|       {result2}')
                elif err2 == 1:
                    parent.stepChanged.emit(f'RED|       {result2}  [Список Типов контента "{item["name"]}"]')
                    error = 1
                else:
                    parent.stepChanged.emit(f'BLACK|       Содержимое списка Типов контента "{item["name"]}" импортировано.')
            else:
                parent.stepChanged.emit(f'GRAY|       Список Типов контента "{item["name"]}" пуст.')
        else:
            parent.stepChanged.emit(f'GRAY|       Содержимое списка Типов контента "{item["name"]}" не импортировано так как он обновляется удалённо.')

    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте списков "Типы контента".')
    else:
        parent.stepChanged.emit('GREEN|    Импорт списка "Типы контента" завершён.')


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
    url_lists = parent.mc_data['url_lists']

    # Импортируем все списки URL без содержимого (пустые).
    parent.stepChanged.emit('LBLUE|    Импортируем списки URL без содержимого.')
    for file_name in files_list:
        json_file = os.path.join(path, file_name)
        err, data = func.read_json_file(parent, json_file, mode=2)
        if err:
            continue

        data['name'] = func.get_restricted_name(data['name'])
        content = data.pop('content')
        data.pop('last_update', None)
        if not data['attributes'] or 'threat_level' in data['attributes']:
            data['attributes'] = {'list_compile_type': 'case_insensitive'}

        if data['name'] in url_lists:
            if parent.template_id == url_lists[data['name']].template_id:
                parent.stepChanged.emit(f'uGRAY|    Список URL "{data["name"]}" уже существует в текущем шаблоне.')
            else:
                parent.stepChanged.emit(f'sGREEN|    Список URL "{data["name"]}" уже существует в шаблоне "{url_lists[data["name"]].template_name}".')
                continue
        else:
            err, result = parent.utm.add_template_nlist(parent.template_id, data)
            if err == 1:
                parent.stepChanged.emit(f'RED|    {result}  [Список URL "{data["name"]}" не импортирован]')
                error = 1
            elif err == 3:
                parent.stepChanged.emit(f'GRAY|    {result}')
            else:
                url_lists[data['name']] = BaseObject(id=result, template_id=parent.template_id, template_name=parent.templates[parent.template_id])
                parent.stepChanged.emit(f'BLACK|    Список URL "{data["name"]}" импортирован.')

    # Импортируем содержимое в уже добавленные списки URL.
    parent.stepChanged.emit('LBLUE|    Импортируем содержимое списков URL.')
    for file_name in files_list:
        json_file = os.path.join(path, file_name)
        err, data = func.read_json_file(parent, json_file)
        if err:
            continue

        data['name'] = func.get_restricted_name(data['name'])
        parent.stepChanged.emit(f'BLACK|    Импортируем содержимое списка URL "{data["name"]}".')

        if parent.template_id == url_lists[data['name']].template_id:
            if data['list_type_update'] == 'static':
                if data['content']:
                    err, result = parent.utm.add_template_nlist_items(parent.template_id, url_lists[data['name']].id, data['content'])
                    if err == 1:
                        parent.stepChanged.emit(f'RED|       {result} [Список URL "{data["name"]}" - содержимое не импортировано]')
                        error = 1
                    else:
                        parent.stepChanged.emit(f'BLACK|       Содержимое списка URL "{data["name"]}" обновлено.')
                else:
                    parent.stepChanged.emit(f'GRAY|      Список URL "{data["name"]}" пуст.')
            else:
                parent.stepChanged.emit(f'GRAY|       Содержимое списка URL "{data["name"]}" не импортировано так как он обновляется удалённо.')
        else:
            parent.stepChanged.emit(f'sGREEN|       Содержимое списка URL "{data["name"]}" не обновлено так как он находится в другом шаблоне.')
        time.sleep(0.01)

    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте списков URL.')
    else:
        parent.stepChanged.emit('GREEN|    Импорт списков URL завершён.')


def import_time_restricted_lists(parent, path):
    """Импортируем содержимое календарей"""
    json_file = os.path.join(path, 'config_calendars.json')
    err, data = func.read_json_file(parent, json_file, mode=2)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт списка "Календари" в раздел "Библиотеки/Календари".')
    error = 0

    calendars = parent.mc_data['calendars']

    for item in data:
        item['name'] = func.get_restricted_name(item['name'])
        content = item.pop('content')
        item.pop('last_update', None)

        if item['name'] in calendars:
            if parent.template_id == calendars[item['name']].template_id:
                parent.stepChanged.emit(f'uGRAY|    Календарь "{item["name"]}" уже существует в текущем шаблоне.')
            else:
                parent.stepChanged.emit(f'sGREEN|    Календарь "{item["name"]}" уже существует в шаблоне "{calendars[item["name"]].template_name}".')
                continue
        else:
            err, result = parent.utm.add_template_nlist(parent.template_id, item)
            if err == 1:
                parent.stepChanged.emit(f'RED|    {result}  [Календарь "{item["name"]}" не импортирован]')
                error = 1
                continue
            elif err == 3:
                parent.stepChanged.emit(f'uGRAY|    {result}')
            else:
                calendars[item['name']] = BaseObject(id=result, template_id=parent.template_id, template_name=parent.templates[parent.template_id])
                parent.stepChanged.emit(f'BLACK|    Календарь "{item["name"]}" импортирован.')

        if item['list_type_update'] == 'static':
            if content:
                for value in content:
                    err2, result2 = parent.utm.add_template_nlist_item(parent.template_id, calendars[item['name']].id, value)
                    if err2 == 1:
                        error = 1
                        parent.stepChanged.emit(f'RED|       {result2}  [TimeSet "{value["name"]}"] не импортирован')
                    elif err2 == 3:
                        parent.stepChanged.emit(f'GRAY|       TimeSet "{value["name"]}" уже существует.')
                    elif err2 == 7:
                        parent.stepChanged.emit(f'bRED|       Error: Календарь "{item["name"]}" не найден в шаблоне "{calendars[item["name"]].template_name}".')
                        parent.stepChanged.emit(f'RED|          Error: Импорт прерван. Перелогиньтесь в МС и повторите попытку.')
                        parent.error = 1
                        return
                    else:
                        parent.stepChanged.emit(f'BLACK|       TimeSet "{value["name"]}" импортирован.')
            else:
                parent.stepChanged.emit(f'GRAY|       Календарь "{item["name"]}" пуст.')
        else:
            parent.stepChanged.emit(f'GRAY|       Содержимое календаря "{item["name"]}" не импортировано так как он обновляется удалённо.')

    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте списка "Календари".')
    else:
        parent.stepChanged.emit('GREEN|    Импорт списка "Календари" завершён.')


def import_shaper_list(parent, path):
    """Импортируем список Полос пропускания раздела библиотеки"""
    json_file = os.path.join(path, 'config_shaper_list.json')
    err, data = func.read_json_file(parent, json_file, mode=2)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт списка "Полосы пропускания" в раздел "Библиотеки/Полосы пропускания".')
    error = 0

    if not parent.mc_data['shapers']:
        if get_shapers_list(parent):        # Заполняем parent.mc_data['shapers']
            parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте списка "Полосы пропускания".')
            return

    shapers = parent.mc_data['shapers']

    for item in data:
        item['name'] = func.get_restricted_name(item['name'])
        if item['name'] in shapers:
            if parent.template_id == shapers[item['name']].template_id:
                parent.stepChanged.emit(f'uGRAY|    Полоса пропускания "{item["name"]}" уже существует в текущем шаблоне.')
                err, result = parent.utm.update_template_shaper(parent.template_id, shapers[item['name']].id, item)
                if err:
                    parent.stepChanged.emit(f'RED|    {result}  [Полоса пропускания "{item["name"]}"]')
                    error = 1
                else:
                    parent.stepChanged.emit(f'uGRAY|       Полоса пропускания "{item["name"]}" обновлена.')
            else:
                parent.stepChanged.emit(f'sGREEN|    Полоса пропускания "{item["name"]}" уже существует в шаблоне "{shapers[item["name"]].template_name}".')
        else:
            err, result = parent.utm.add_template_shaper(parent.template_id, item)
            if err:
                parent.stepChanged.emit(f'RED|    {result}  [Полоса пропускания "{item["name"]}" не импортирована]')
                error = 1
            elif err == 3:
                parent.stepChanged.emit(f'GRAY|    {result}')
            else:
                shapers[item['name']] = BaseObject(id=result, template_id=parent.template_id, template_name=parent.templates[parent.template_id])
                parent.stepChanged.emit(f'BLACK|    Полоса пропускания "{item["name"]}" импортирована.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте списка "Полосы пропускания".')
    else:
        parent.stepChanged.emit('GREEN|    Импорт списка "Полосы пропускания" завершён.')


def import_templates_list(parent, path):
    """
    Импортируем список шаблонов страниц.
    После создания шаблона, он инициализируется страницей HTML по умолчанию для данного типа шаблона.
    """
    json_file = os.path.join(path, 'config_templates_list.json')
    err, data = func.read_json_file(parent, json_file, mode=2)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт списка шаблонов страниц в раздел "Библиотеки/Шаблоны страниц".')
    parent.stepChanged.emit('LBLUE|    Импортируются только шаблоны страниц у которых есть HTML-файл страницы.')
    error = 0
    html_files = os.listdir(path)

    if not parent.mc_data['response_pages']:
        if get_response_pages(parent):    # Заполняем parent.mc_data['response_pages']
            parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте списка шаблонов страниц.')
            return

    response_pages = parent.mc_data['response_pages']

    n = 0
    for item in data:
        if f"{item['name']}.html" in html_files:
            n += 1
            if item['name'] in response_pages:
                if parent.template_id == response_pages[item['name']].template_id:
                    parent.stepChanged.emit(f'uGRAY|    Шаблон страницы "{item["name"]}" уже существует в текущем шаблоне.')
                    err, result = parent.utm.update_template_responsepage(parent.template_id, response_pages[item['name']].id, item)
                    if err:
                        parent.stepChanged.emit(f'RED|    {result}  [Шаблон страницы "{item["name"]}"]')
                        error = 1
                        continue
                    else:
                        parent.stepChanged.emit(f'uGRAY|    Шаблон страницы "{item["name"]}" обновлён.')
                else:
                    parent.stepChanged.emit(f'sGREEN|    Шаблон страницы "{item["name"]}" уже существует в шаблоне "{response_pages[item["name"]].template_name}".')
                    continue
            else:
                err, result = parent.utm.add_template_responsepage(parent.template_id, item)
                if err:
                    parent.stepChanged.emit(f'RED|    {result}  [Шаблон страницы "{item["name"]}" не импортирован]')
                    error = 1
                    continue
                else:
                    response_pages[item['name']] = BaseObject(id=result, template_id=parent.template_id, template_name=parent.templates[parent.template_id])
                    parent.stepChanged.emit(f'BLACK|    Шаблон страницы "{item["name"]}" импортирован.')

            upload_file = os.path.join(path, f"{item['name']}.html")
            err, result = parent.utm.get_realm_upload_session(upload_file)
            if err:
                parent.stepChanged.emit(f'RED|       {result}')
                parent.error = 1
            elif result['success']:
                err2, result2 = parent.utm.set_template_responsepage_data(parent.template_id, response_pages[item['name']].id, result['storage_file_uid'])
                if err2:
                    parent.stepChanged.emit(f'RED|       {result2} [Страница "{item["name"]}.html" не импортирована]')
                    parent.error = 1
                else:
                    parent.stepChanged.emit(f'BLACK|       Страница "{item["name"]}.html" импортирована.')
            else:
                parent.error = 1
                parent.stepChanged.emit(f'ORANGE|       Error: Не удалось импортировать страницу "{item["name"]}.html".')
    if not n:
        parent.stepChanged.emit('GRAY|    Нет шаблонов страниц у которых есть HTML-файл страницы.')

    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте списка шаблонов страниц.')
    else:
        parent.stepChanged.emit('GREEN|    Импорт списка шаблонов страниц завершён.')


def import_url_categories(parent, path):
    """Импортировать группы URL категорий с содержимым"""
    json_file = os.path.join(path, 'config_url_categories.json')
    err, data = func.read_json_file(parent, json_file, mode=2)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт групп URL категорий раздела "Библиотеки/Категории URL".')
    error = 0

    url_category_groups = parent.mc_data['url_categorygroups']

    for item in data:
        item['name'] = func.get_restricted_name(item['name'])
        content = item.pop('content')
        item.pop('last_update', None)
        item.pop('guid', None)

        if item['name'] in url_category_groups:
            if parent.template_id == url_category_groups[item['name']].template_id:
                parent.stepChanged.emit(f'uGRAY|    Группа URL категорий "{item["name"]}" уже существует в текущем шаблоне.')
            else:
                parent.stepChanged.emit(f'sGREEN|    Группа URL категорий "{item["name"]}" уже существует в шаблоне "{url_category_groups[item["name"]].template_name}".')
                continue
        else:
            err, result = parent.utm.add_template_nlist(parent.template_id, item)
            if err == 1:
                parent.stepChanged.emit(f'RED|    {result}  [Группа URL категорий "{item["name"]}" не импортирована]')
                error = 1
                continue
            elif err == 3:
                parent.stepChanged.emit(f'uGRAY|    {result}')
            else:
                url_category_groups[item['name']] = BaseObject(id=result, template_id=parent.template_id, template_name=parent.templates[parent.template_id])
                parent.stepChanged.emit(f'BLACK|    Группа URL категорий "{item["name"]}" импортирована.')

        if item['list_type_update'] == 'static':
            if content:
                for category in content:
                    err2, result2 = parent.utm.add_template_nlist_item(parent.template_id, url_category_groups[item['name']].id, category)
                    if err2 == 3:
                        parent.stepChanged.emit(f'GRAY|       Категория "{category["name"]}" уже существует.')
                    elif err2 == 1:
                        parent.stepChanged.emit(f'RED|       {result2}  [Категория "{category["name"]}"]')
                        error = 1
                    elif err2 == 7:
                        parent.stepChanged.emit(f'bRED|       Error: Группа URL категорий "{item["name"]}" не найдена в шаблоне "{url_category_groups[item["name"]].template_name}".')
                        parent.stepChanged.emit(f'RED|          Error: Импорт прерван. Перелогиньтесь в МС и повторите попытку.')
                        parent.error = 1
                        return
                    else:
                        parent.stepChanged.emit(f'BLACK|       Добавлена категория "{category["name"]}".')
            else:
                parent.stepChanged.emit(f'GRAY|       Группа URL категорий "{item["name"]}" не содержит категорий.')
        else:
            parent.stepChanged.emit(f'GRAY|       Содержимое группы URL категорий "{item["name"]}" не импортировано так как она обновляется удалённо.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте групп URL категорий.')
    else:
        parent.stepChanged.emit('GREEN|    Импорт групп URL категорий завершён.')


def import_custom_url_category(parent, path):
    """Импортируем изменённые категории URL"""
    json_file = os.path.join(path, 'custom_url_categories.json')
    err, data = func.read_json_file(parent, json_file, mode=2)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт категорий URL раздела "Библиотеки/Изменённые категории URL".')
    error = 0

    custom_url = {}
    for uid, name in parent.templates.items():
        err, result = parent.utm.get_template_custom_url_list(uid)
        if err:
            parent.stepChanged.emit(f'RED|    {result}')
            parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте изменённых категорий URL.')
            parent.error = 1
            return
        for x in result:
            if x['name'] in custom_url:
                parent.stepChanged.emit('RED|    Категория для URL "{x["name"]}" изменена в нескольких шаблонах группы. Запись из шаблона "{name}" не будет испольована.')
            else:
                custom_url[x['name']] = BaseObject(id=x['id'], template_id=uid, template_name=name)

    for item in data:
        try:
            item['categories'] = [parent.mc_data['url_categories'][x] for x in item['categories']]
        except KeyError as err:
            parent.stepChanged.emit(f'RED|    Error: В правиле "{item["name"]}" обнаружена несуществующая категория {err}. Правило  не добавлено.')
            continue

        if item['name'] in custom_url:
            if parent.template_id == custom_url[item['name']].template_id:
                parent.stepChanged.emit(f'uGRAY|    Изменение категории URL "{item["name"]}" уже существует в текущем шаблоне.')
                err, result = parent.utm.update_template_custom_url(parent.template_id, custom_url[item['name']].id, item)
                if err:
                    parent.stepChanged.emit(f'RED|    {result}  [URL категория "{item["name"]}"]')
                    error = 1
                else:
                    parent.stepChanged.emit(f'uGRAY|       URL категория "{item["name"]}" updated.')
            else:
                parent.stepChanged.emit(f'sGREEN|    Изменение категории URL "{item["name"]}" уже существует в шаблоне "{custom_url[item["name"]].template_name}".')
        else:
            err, result = parent.utm.add_template_custom_url(parent.template_id, item)
            if err:
                parent.stepChanged.emit(f'RED|    {result}  [Изменение категорий для URL "{item["name"]}" не импортировано]')
                error = 1
            else:
                custom_url[item['name']] = BaseObject(id=result, template_id=parent.template_id, template_name=parent.templates[parent.template_id])
                parent.stepChanged.emit(f'BLACK|    Изменение категории для URL "{item["name"]}" импортировано.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте изменённых категорий URL.')
    else:
        parent.stepChanged.emit('GREEN|    Импорт изменённых категорий URL завершён.')


def import_application_signature(parent, path):
    """Импортируем список Приложения"""
    json_file = os.path.join(path, 'config_applications.json')
    err, data = func.read_json_file(parent, json_file, mode=2)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт пользовательских приложений в раздел "Библиотеки/Приложения".')
    error = 0

    users_apps = {}
    for uid, name in parent.templates.items():
        err, result = parent.utm.get_template_app_signatures(uid, query={'query': 'owner = You'})
        if err:
            parent.stepChanged.emit(f'RED|    {result}')
            parent.error = 1
            return
        for x in result:
            if x['name'] in users_apps:
                parent.stepChanged.emit(f'RED|    Пользовательское приложение "{x["name"]}" обнаружено в нескольких шаблонах группы. Приложение из шаблона "{name}" не будет использовано.')
            else:
                users_apps[x['name']] = BaseObject(id=x['id'], template_id=uid, template_name=name)

    for item in data:
        item.pop('signature_id', None)

        new_l7categories = []
        for category in item['l7categories']:
            try:
                new_l7categories.append(parent.mc_data['l7_categories'][category])
            except KeyError as err:
                parent.stepChanged.emit(f'RED|    Error [Правило "{item["name"]}"]. Категория {err} не существует. Категория не добавлена.')
                error = 1
        item['l7categories'] = new_l7categories

        if item['name'] in users_apps:
            if parent.template_id == users_apps[item['name']].template_id:
                parent.stepChanged.emit(f'uGRAY|    Пользовательское приложение "{item["name"]}" уже существует в текущем шаблоне.')
                err, result = parent.utm.update_template_app_signature(parent.template_id, users_apps[item['name']].id, item)
                if err:
                    parent.stepChanged.emit(f'RED|       {result}  [Приложение "{item["name"]}"]')
                    error = 1
                else:
                    parent.stepChanged.emit(f'uGRAY|       Пользовательское приложение "{item["name"]}" обновлено.')
            else:
                parent.stepChanged.emit(f'sGREEN|    Пользовательское приложение "{item["name"]}" уже существует в шаблоне "{users_apps[item["name"]].template_name}".')
        else:
            err, result = parent.utm.add_template_app_signature(parent.template_id, item)
            if err:
                parent.stepChanged.emit(f'RED|    {result}  [Пользовательское приложение "{item["name"]}" не импортировано]')
                error = 1
            else:
                users_apps[item['name']] = BaseObject(id=result, template_id=parent.template_id, template_name=parent.templates[parent.template_id])
                parent.stepChanged.emit(f'BLACK|    Приложение "{item["name"]}" импортировано.')
        time.sleep(0.01)
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте пользовательских приложений.')
    else:
        parent.stepChanged.emit('GREEN|    Импорт пользовательских приложений завершён.')


def import_app_profiles(parent, path):
    """Импортируем профили приложений"""
    json_file = os.path.join(path, 'config_app_profiles.json')
    err, data = func.read_json_file(parent, json_file, mode=2)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт профилей приложений раздела "Библиотеки/Профили приложений".')
    error = 0

    if not parent.mc_data['l7_apps']:
        if get_app_signatures(parent):        # Заполняем parent.mc_data['l7_apps']
            parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей приложений.')
            return
    l7_apps = parent.mc_data['l7_apps']

    if not parent.mc_data['l7_profiles']:
        if get_l7_profiles(parent):        # Заполняем parent.mc_data['l7_profiles']
            parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей приложений.')
            return
    l7_profiles = parent.mc_data['l7_profiles']

    for item in data:
        new_overrides = []
        for app in item['overrides']:
            try:
                app['id'] = l7_apps[app['id']].id
                new_overrides.append(app)
            except KeyError as err:
                parent.stepChanged.emit(f'RED|    Error [Правило "{item["name"]}"]. Не найдено приложение {err}. Приложение не добавлено.')
                error = 1
        item['overrides'] = new_overrides

        if item['name'] in l7_profiles:
            if parent.template_id == l7_profiles[item['name']].template_id:
                parent.stepChanged.emit(f'uGRAY|    Профиль приложений "{item["name"]}" уже существует в текущем шаблоне.')
                err, result = parent.utm.update_template_l7_profile(parent.template_id, l7_profiles[item['name']].id, item)
                if err:
                    parent.stepChanged.emit(f'RED|       {result}  [Профиль приложений "{item["name"]}"]')
                    error = 1
                else:
                    parent.stepChanged.emit(f'uGRAY|       Профиль приложений "{item["name"]}" обновлён.')
            else:
                parent.stepChanged.emit(f'sGREEN|    Профиль приложений "{item["name"]}" уже существует в шаблоне "{l7_profiles[item["name"]].template_name}".')
        else:
            err, result = parent.utm.add_template_l7_profile(parent.template_id, item)
            if err:
                parent.stepChanged.emit(f'RED|    {result}  [Профиль приложений "{item["name"]}" не импортирован]')
                error = 1
            else:
                l7_profiles[item['name']] = BaseObject(id=result, template_id=parent.template_id, template_name=parent.templates[parent.template_id])
                parent.stepChanged.emit(f'BLACK|    Профиль приложений "{item["name"]}" импортирован.')
        time.sleep(0.01)
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей приложений.')
    else:
        parent.stepChanged.emit('GREEN|    Импорт профилей приложений завершён.')


def import_application_groups(parent, path):
    """Импортировать группы приложений на UTM"""
    json_file = os.path.join(path, 'config_application_groups.json')
    err, data = func.read_json_file(parent, json_file, mode=2)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт групп приложений в раздел "Библиотеки/Группы приложений".')

    if not parent.mc_data['l7_apps']:
        if get_app_signatures(parent):        # Заполняем parent.mc_data['l7_apps']
            parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте групп приложений.')
            return

    l7_apps = parent.mc_data['l7_apps']
    apps_groups = parent.mc_data['apps_groups']

    error = 0
    for item in data:
        item['name'] = func.get_restricted_name(item['name'])
        content = item.pop('content')
        item.pop('last_update', None)

        if item['name'] in apps_groups:
            if parent.template_id == apps_groups[item['name']].template_id:
                parent.stepChanged.emit(f'uGRAY|    Группа приложений "{item["name"]}" уже существует в текущем шаблоне.')
            else:
                parent.stepChanged.emit(f'sGREEN|    Группа приложений "{item["name"]}" уже существует в шаблоне "{apps_groups[item["name"]].template_name}".')
                continue
        else:
            err, result = parent.utm.add_template_nlist(parent.template_id, item)
            if err == 1:
                parent.stepChanged.emit(f'RED|    {result}  [Группа приложений "{item["name"]}" не импортирована]')
                error = 1
                continue
            elif err == 3:
                parent.stepChanged.emit(f'uGRAY|    {result}')
            else:
                apps_groups[item['name']] = BaseObject(id=result, template_id=parent.template_id, template_name=parent.templates[parent.template_id])
                parent.stepChanged.emit(f'BLACK|    Группа приложений "{item["name"]}" импортирована.')

        if item['list_type_update'] == 'static':
            if content:
                for app in content:
                    if 'name' not in app:   # Так бывает при некорректном добавлении приложения через API
                        parent.stepChanged.emit(f'RED|       Error: Приложение "{app}" не добавлено, так как не содержит имя.')
                        error = 1
                        continue
                    try:
                        app['value'] = l7_apps[app['name']].signature_id
                    except KeyError as err:
                        parent.stepChanged.emit(f'RED|       Error: Приложение "{app["name"]}" не импортировано. Такого приложения нет на UG MC.')
                        error = 1
                        continue

                    err2, result2 = parent.utm.add_template_nlist_item(parent.template_id, apps_groups[item['name']].id, app) 
                    if err2 == 1:
                        parent.stepChanged.emit(f'RED|       {result2}  [Группа приложений "{item["name"]}"]')
                        error = 1
                    elif err2 == 7:
                        parent.stepChanged.emit(f'bRED|       Error: Группа приложений "{item["name"]}" не найдена в шаблоне "{apps_groups[item["name"]].template_name}".')
                        parent.stepChanged.emit(f'RED|          Error: Импорт прерван. Перелогиньтесь в МС и повторите попытку.')
                        parent.error = 1
                        return
                    elif err2 == 3:
                        parent.stepChanged.emit(f'GRAY|       Приложение "{app["name"]}" уже существует в группе приложений "{item["name"]}".')
                    else:
                        parent.stepChanged.emit(f'BLACK|       Приложение "{app["name"]}" импортировано.')
            else:
                parent.stepChanged.emit(f'GRAY|       Группа приложений "{item["name"]}" не имеет содержимого.')
        else:
            parent.stepChanged.emit(f'GRAY|       Содержимое группы приложений "{item["name"]}" не импортировано так как она обновляется удалённо.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте групп приложений.')
    else:
        parent.stepChanged.emit('GREEN|    Импорт групп приложений завершён.')


def import_email_groups(parent, path):
    """Импортируем группы почтовых адресов."""
    json_file = os.path.join(path, 'config_email_groups.json')
    err, data = func.read_json_file(parent, json_file, mode=2)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт групп почтовых адресов раздела "Библиотеки/Почтовые адреса".')
    error = 0

    if not parent.mc_data['email_groups']:
        if get_email_groups(parent):        # Заполняем parent.mc_data['email_groups']
            parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте групп почтовых адресов.')
            return

    email_groups = parent.mc_data['email_groups']

    for item in data:
        item['name'] = func.get_restricted_name(item['name'])
        content = item.pop('content')
        item.pop('last_update', None)

        if item['name'] in email_groups:
            if parent.template_id == email_groups[item['name']].template_id:
                parent.stepChanged.emit(f'uGRAY|    Группа почтовых адресов "{item["name"]}" уже существует в текущем шаблоне.')
            else:
                parent.stepChanged.emit(f'sGREEN|    Группа почтовых адресов "{item["name"]}" уже существует в шаблоне "{email_groups[item["name"]].template_name}".')
                continue
        else:
            err, result = parent.utm.add_template_nlist(parent.template_id, item)
            if err == 1:
                parent.stepChanged.emit(f'RED|    {result}  [Группа почтовых адресов "{item["name"]}" не импортирована]')
                error = 1
                continue
            elif err == 3:
                parent.stepChanged.emit(f'uGRAY|    {result}')
            else:
                email_groups[item['name']] = BaseObject(id=result, template_id=parent.template_id, template_name=parent.templates[parent.template_id])
                parent.stepChanged.emit(f'BLACK|    Группа почтовых адресов "{item["name"]}" импортирована.')

        if item['list_type_update'] == 'static':
            if content:
                for email in content:
                    err2, result2 = parent.utm.add_template_nlist_item(parent.template_id, email_groups[item['name']].id, email)
                    if err2 == 1:
                        parent.stepChanged.emit(f'RED|       {result2} [Группа почтовых адресов "{item["name"]}"]')
                        error = 1
                    elif err2 == 3:
                        parent.stepChanged.emit(f'GRAY|       Адрес "{email["value"]}" уже существует.')
                    elif err2 == 7:
                        parent.stepChanged.emit(f'bRED|       Error: Группа почтовых адресов "{item["name"]}" не найдена в шаблоне "{email_groups[item["name"]].template_name}".')
                        parent.stepChanged.emit(f'RED|          Error: Импорт прерван. Перелогиньтесь в МС и повторите попытку.')
                        parent.error = 1
                        return
                    else:
                        parent.stepChanged.emit(f'BLACK|       Адрес "{email["value"]}" импортирован.')
            else:
                parent.stepChanged.emit(f'GRAY|       Группа почтовых адресов "{item["name"]}" не имеет содержимого.')
        else:
            parent.stepChanged.emit(f'GRAY|       Содержимое группы почтовых адресов "{item["name"]}" не импортировано так как она обновляется удалённо.')

    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте групп почтовых адресов.')
    else:
        parent.stepChanged.emit('GREEN|    Импорт групп почтовых адресов завершён.')


def import_phone_groups(parent, path):
    """Импортируем группы телефонных номеров."""
    json_file = os.path.join(path, 'config_phone_groups.json')
    err, data = func.read_json_file(parent, json_file, mode=2)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт групп телефонных номеров раздела "Библиотеки/Номера телефонов".')
    error = 0

    if not parent.mc_data['phone_groups']:
        if get_phone_groups(parent):        # Заполняем parent.mc_data['phone_groups']
            parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте групп телефонных номеров.')
            return

    phone_groups = parent.mc_data['phone_groups']

    for item in data:
        item['name'] = func.get_restricted_name(item['name'])
        content = item.pop('content')
        item.pop('last_update', None)

        if item['name'] in phone_groups:
            if parent.template_id == phone_groups[item['name']].template_id:
                parent.stepChanged.emit(f'uGRAY|    Группа телефонных номеров "{item["name"]}" уже существует в текущем шаблоне.')
            else:
                parent.stepChanged.emit(f'sGREEN|    Группа телефонных номеров "{item["name"]}" уже существует в шаблоне "{phone_groups[item["name"]].template_name}".')
                continue
        else:
            err, result = parent.utm.add_template_nlist(parent.template_id, item)
            if err == 1:
                parent.stepChanged.emit(f'RED|    {result}  [Группа телефонных номеров "{item["name"]}" не импортирована]')
                error = 1
                continue
            elif err == 3:
                parent.stepChanged.emit(f'uGRAY|    {result}')
            else:
                phone_groups[item['name']] = BaseObject(id=result, template_id=parent.template_id, template_name=parent.templates[parent.template_id])
                parent.stepChanged.emit(f'BLACK|    Группа телефонных номеров "{item["name"]}" импортирована.')

        if item['list_type_update'] == 'static':
            if content:
                for number in content:
                    err2, result2 = parent.utm.add_template_nlist_item(parent.template_id, phone_groups[item['name']].id, number)
                    if err2 == 1:
                        parent.stepChanged.emit(f'RED|       {result2} [Группа телефонных номеров "{item["name"]}"]')
                        error = 1
                    elif err2 == 3:
                        parent.stepChanged.emit(f'GRAY|       Номер "{number["value"]}" уже существует.')
                    elif err2 == 7:
                        parent.stepChanged.emit(f'bRED|       Error: Группа телефонных номеров "{item["name"]}" не найдена в шаблоне "{phone_groups[item["name"]].template_name}".')
                        parent.stepChanged.emit(f'RED|          Error: Импорт прерван. Перелогиньтесь в МС и повторите попытку.')
                        parent.error = 1
                        return
                    else:
                        parent.stepChanged.emit(f'BLACK|       Номер "{number["value"]}" импортирован.')
            else:
                parent.stepChanged.emit(f'GRAY|       Нет содержимого в группе телефонных номеров "{item["name"]}".')
        else:
            parent.stepChanged.emit(f'GRAY|       Содержимое группы телефонных номеров "{item["name"]}" не импортировано так как она обновляется удалённо.')

    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте групп телефонных номеров.')
    else:
        parent.stepChanged.emit('GREEN|    Импорт групп телефонных номеров завершён.')


def import_custom_idps_signature(parent, path):
    """Импортируем пользовательские сигнатуры СОВ."""
    json_file = os.path.join(path, 'custom_idps_signatures.json')
    err, data = func.read_json_file(parent, json_file, mode=2)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт пользовательских сигнатур СОВ в раздел "Библиотеки/Сигнатуры СОВ".')
    error = 0

#    users_signatures = {}
#    for uid, name in parent.templates.items():
#        err, result = parent.utm.get_template_idps_signatures_list(uid, query={'query': 'owner = You'})
#        if err:
#            parent.stepChanged.emit(f'RED|    {result}')
#            parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте пользовательских сигнатур СОВ.')
#            parent.error = 1
#            return
#        for x in result:
#            if x['msg'] in users_signatures:
#                parent.stepChanged.emit(f'RED|    Пользовательская сигнатура "{x["msg"]}" обнаружена в нескольких шаблонах группы. Сигнатура из шаблона "{name}" не будет использована.')
#            else:
#                users_signatures[x['msg']] = BaseObject(id=x['id'], template_id=uid, template_name=name)

    if not parent.users_signatures:
        if get_idps_users_signatures(parent):        # Заполняем атрибут parent.users_signatures
            parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте пользовательских сигнатур СОВ.')
            return
            
    for item in data:
        if item['msg'] in parent.users_signatures:
            if parent.template_id == parent.users_signatures[item['msg']].template_id:
                parent.stepChanged.emit(f'uGRAY|    Сигнатура СОВ "{item["msg"]}" уже существует в текущем шаблоне.')
                err, result = parent.utm.update_template_idps_signature(parent.template_id, parent.users_signatures[item['msg']].id, item)
                if err:
                    parent.stepChanged.emit(f'RED|       {result}  [Сигнатура СОВ "{item["msg"]}"]')
                    error = 1
                else:
                    parent.stepChanged.emit(f'uGRAY|       Сигнатура СОВ "{item["msg"]}" обновлена.')
            else:
                parent.stepChanged.emit(f'sGREEN|    Сигнатура СОВ "{item["msg"]}" уже существует в шаблоне "{parent.users_signatures[item["msg"]].template_name}".')
        else:
            err, result = parent.utm.add_template_idps_signature(parent.template_id, item)
            if err:
                parent.stepChanged.emit(f'RED|    {result}  [Сигнатура СОВ "{item["msg"]}" не импортирована]')
                error = 1
            else:
                parent.users_signatures[item['msg']] = BaseObject(id=result, template_id=parent.template_id, template_name=parent.templates[parent.template_id])
                parent.stepChanged.emit(f'BLACK|    Сигнатура СОВ "{item["msg"]}" импортирована.')
        time.sleep(0.01)
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте пользовательских сигнатур СОВ.')
    else:
        parent.stepChanged.emit('GREEN|    Импорт пользовательских сигнатур СОВ завершён.')


def import_idps_profiles(parent, path):
    """Импортируем профили СОВ"""
    json_file = os.path.join(path, 'config_idps_profiles.json')
    err, data = func.read_json_file(parent, json_file, mode=2)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт профилей СОВ в раздел "Библиотеки/Профили СОВ".')
    error = 0

    # Получаем пользовательские сигнатуры СОВ.
    if not parent.users_signatures:
        if get_idps_users_signatures(parent):        # Заполняем атрибут parent.users_signatures
            parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей СОВ.')
            return

    parent.stepChanged.emit(f'NOTE|    Получаем список сигнатур СОВ с МС, это может быть долго...')
    err, result = parent.utm.get_template_idps_signatures_list(parent.template_id)
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей СОВ.')
        parent.error = 1
        return
    idps_signatures = {x['msg']: BaseObject(id=x['id'], template_id=parent.template_id, template_name=parent.templates[parent.template_id]) for x in result}
    idps_signatures.update(parent.users_signatures) # Добавляем пользовательские сигнатуры к стандартным.

    if not parent.mc_data['idps_profiles']:
        if get_idps_profiles(parent):        # Заполняем parent.mc_data['idps_profiles']
            parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей СОВ.')
            return

    idps_profiles = parent.mc_data['idps_profiles']

    for item in data:
        if 'filters' not in item:
            parent.stepChanged.emit('RED|    Импорт профилей СОВ старых версий не поддерживается для версий 7.1 и выше.')
            error = 1
            break

        # Исключаем отсутствующие сигнатуры. И получаем ID сигнатур по имени так как ID может не совпадать.
        new_overrides = []
        for signature in item['overrides']:
            try:
                signature['id'] = idps_signatures[signature['msg']].id
                new_overrides.append(signature)
            except KeyError as err:
                parent.stepChanged.emit(f'RED|    Error [Профиль СОВ "{item["name"]}"]. Не найдена сигнатура СОВ: {err}.')
                error = 1
        item['overrides'] = new_overrides

        if item['name'] in idps_profiles:
            if parent.template_id == idps_profiles[item['name']].template_id:
                parent.stepChanged.emit(f'uGRAY|    Профиль СОВ "{item["name"]}" уже существует в текущем шаблоне.')
                err, result = parent.utm.update_template_idps_profile(parent.template_id, idps_profiles[item['name']].id, item)
                if err:
                    parent.stepChanged.emit(f'RED|       {result}  [Профиль СОВ "{item["name"]}"]')
                    error = 1
                else:
                    parent.stepChanged.emit(f'uGRAY|       Профиль СОВ "{item["name"]}" обновлён.')
            else:
                parent.stepChanged.emit(f'sGREEN|    Профиль СОВ "{item["name"]}" уже существует в шаблоне "{idps_profiles[item["name"]].template_name}".')
        else:
            err, result = parent.utm.add_template_idps_profile(parent.template_id, item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Профиль СОВ "{item["name"]}" не импортирован]')
            else:
                idps_profiles[item['name']] = BaseObject(id=result, template_id=parent.template_id, template_name=parent.templates[parent.template_id])
                parent.stepChanged.emit(f'BLACK|    Профиль СОВ "{item["name"]}" импортирован.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей СОВ.')
    else:
        parent.stepChanged.emit('GREEN|    Импорт профилей СОВ завершён.')


def import_notification_profiles(parent, path):
    """Импортируем список профилей оповещения"""
    json_file = os.path.join(path, 'config_notification_profiles.json')
    err, data = func.read_json_file(parent, json_file, mode=2)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт профилей оповещений в раздел "Библиотеки/Профили оповещений".')
    error = 0

    if not parent.mc_data['notification_profiles']:
        if get_notification_profiles(parent):        # Заполняем parent.mc_data['notification_profiles']
            parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей оповещений.')
            return
    notification_profiles = parent.mc_data['notification_profiles']

    for item in data:
        item['name'] = func.get_restricted_name(item['name'])
        if item['name'] in notification_profiles:
            if parent.template_id == notification_profiles[item['name']].template_id:
                parent.stepChanged.emit(f'uGRAY|    Профиль оповещения "{item["name"]}" уже существует в текущем шаблоне.')
                err, result = parent.utm.update_template_notification_profile(parent.template_id, notification_profiles[item['name']].id, item)
                if err:
                    parent.stepChanged.emit(f'RED|       {result}  [Профиль оповещения "{item["name"]}"]')
                    error = 1
                else:
                    parent.stepChanged.emit(f'uGRAY|       Профиль оповещения "{item["name"]}" обновлён.')
            else:
                parent.stepChanged.emit(f'sGREEN|    Профиль оповещения "{item["name"]}" уже существует в шаблоне "{notification_profiles[item["name"]].template_name}".')
        else:
            err, result = parent.utm.add_template_notification_profile(parent.template_id, item)
            if err:
                parent.stepChanged.emit(f'RED|    {result}  [Профиль оповещения "{item["name"]}" не импортирован]')
                error = 1
            elif err == 3:
                parent.stepChanged.emit(f'GRAY|    {result}')
            else:
                notification_profiles[item['name']] = BaseObject(id=result, template_id=parent.template_id, template_name=parent.templates[parent.template_id])
                parent.stepChanged.emit(f'BLACK|    Профиль оповещения "{item["name"]}" импортирован.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей оповещений.')
    else:
        parent.stepChanged.emit('GREEN|    Импорт профилей оповещений завершён.')


def import_netflow_profiles(parent, path):
    """Импортируем список профилей netflow"""
    json_file = os.path.join(path, 'config_netflow_profiles.json')
    err, data = func.read_json_file(parent, json_file, mode=2)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт профилей netflow в раздел "Библиотеки/Профили netflow".')
    error = 0

    if not parent.mc_data['netflow_profiles']:
        if get_netflow_profiles(parent):        # Заполняем parent.mc_data['netflow_profiles']
            parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей netflow.')
            return
    netflow_profiles = parent.mc_data['netflow_profiles']

    for item in data:
        item['name'] = func.get_restricted_name(item['name'])
        if item['name'] in netflow_profiles:
            if parent.template_id == netflow_profiles[item['name']].template_id:
                parent.stepChanged.emit(f'uGRAY|    Профиль netflow "{item["name"]}" уже существует в текущем шаблоне.')
                err, result = parent.utm.update_template_netflow_profile(parent.template_id, netflow_profiles[item['name']].id, item)
                if err:
                    parent.stepChanged.emit(f'RED|       {result}  [Профиль netflow "{item["name"]}"]')
                    error = 1
                else:
                    parent.stepChanged.emit(f'uGRAY|       Профиль netflow "{item["name"]}" обновлён.')
            else:
                parent.stepChanged.emit(f'sGREEN|    Профиль netflow "{item["name"]}" уже существует в шаблоне "{netflow_profiles[item["name"]].template_name}".')
        else:
            err, result = parent.utm.add_template_netflow_profile(parent.template_id, item)
            if err:
                parent.stepChanged.emit(f'RED|    {result}  [Профиль netflow "{item["name"]}" не импортирован]')
                error = 1
            else:
                netflow_profiles[item['name']] = BaseObject(id=result, template_id=parent.template_id, template_name=parent.templates[parent.template_id])
                parent.stepChanged.emit(f'BLACK|    Профиль netflow "{item["name"]}" импортирован.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей netflow.')
    else:
        parent.stepChanged.emit('GREEN|    Импорт профилей netflow завершён.')


def import_lldp_profiles(parent, path):
    """Импортируем список профилей LLDP"""
    json_file = os.path.join(path, 'config_lldp_profiles.json')
    err, data = func.read_json_file(parent, json_file, mode=2)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт профилей LLDP в раздел "Библиотеки/Профили LLDP".')
    error = 0

    if not parent.mc_data['lldp_profiles']:
        if get_lldp_profiles(parent):        # Заполняем parent.mc_data['lldp_profiles']
            parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей LLDP.')
            return
    lldp_profiles = parent.mc_data['lldp_profiles']

    for item in data:
        item['name'] = func.get_restricted_name(item['name'])
        if item['name'] in lldp_profiles:
            if parent.template_id == lldp_profiles[item['name']].template_id:
                parent.stepChanged.emit(f'uGRAY|    Профиль LLDP "{item["name"]}" уже существует в текущем шаблоне.')
                err, result = parent.utm.update_template_lldp_profile(parent.template_id, lldp_profiles[item['name']].id, item)
                if err:
                    parent.stepChanged.emit(f'RED|       {result}  [Профиль LLDP "{item["name"]}"]')
                    error = 1
                else:
                    parent.stepChanged.emit(f'uGRAY|       Профиль LLDP "{item["name"]}" обновлён.')
            else:
                parent.stepChanged.emit(f'sGREEN|    Профиль LLDP "{item["name"]}" уже существует в шаблоне "{lldp_profiles[item["name"]].template_name}".')
        else:
            err, result = parent.utm.add_template_lldp_profile(parent.template_id, item)
            if err:
                parent.stepChanged.emit(f'RED|    {result}  [Профиль LLDP "{item["name"]}" не импортирован]')
                error = 1
            else:
                lldp_profiles[item['name']] = BaseObject(id=result, template_id=parent.template_id, template_name=parent.templates[parent.template_id])
                parent.stepChanged.emit(f'BLACK|    Профиль LLDP "{item["name"]}" импортирован.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей LLDP.')
    else:
        parent.stepChanged.emit('GREEN|    Импорт профилей LLDP завершён.')


def import_ssl_profiles(parent, path):
    """Импортируем список профилей SSL"""
    json_file = os.path.join(path, 'config_ssl_profiles.json')
    err, data = func.read_json_file(parent, json_file, mode=2)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт профилей SSL в раздел "Библиотеки/Профили SSL".')
    error = 0
    ssl_profiles = parent.mc_data['ssl_profiles']

    for item in data:
        if 'supported_groups' not in item:
            item['supported_groups'] = []
        item['name'] = func.get_restricted_name(item['name'])

        if item['name'] in ssl_profiles:
            if parent.template_id == ssl_profiles[item['name']].template_id:
                parent.stepChanged.emit(f'uGRAY|    Профиль SSL "{item["name"]}" уже существует в текущем шаблоне.')
                err, result = parent.utm.update_template_ssl_profile(parent.template_id, ssl_profiles[item['name']].id, item)
                if err:
                    parent.stepChanged.emit(f'RED|       {result}  [Профиль SSL "{item["name"]}"]')
                    error = 1
                else:
                    parent.stepChanged.emit(f'uGRAY|       Профиль SSL "{item["name"]}" обновлён.')
            else:
                parent.stepChanged.emit(f'sGREEN|    Профиль SSL "{item["name"]}" уже существует в шаблоне "{ssl_profiles[item["name"]].template_name}".')
        else:
            err, result = parent.utm.add_template_ssl_profile(parent.template_id, item)
            if err:
                parent.stepChanged.emit(f'RED|    {result}  [Профиль SSL "{item["name"]}" не импортирован]')
                error = 1
            else:
                ssl_profiles[item['name']] = BaseObject(id=result, template_id=parent.template_id, template_name=parent.templates[parent.template_id])
                parent.stepChanged.emit(f'BLACK|    Профиль SSL "{item["name"]}" импортирован.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей SSL.')
    else:
        parent.stepChanged.emit('GREEN|    Импорт профилей SSL завершён.')


def import_ssl_forward_profiles(parent, path):
    """Импортируем профили пересылки SSL"""
    json_file = os.path.join(path, 'config_ssl_forward_profiles.json')
    err, data = func.read_json_file(parent, json_file, mode=2)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт профилей пересылки SSL в раздел "Библиотеки/Профили пересылки SSL".')
    error = 0

    if not parent.mc_data['ssl_forward_profiles']:
        if get_ssl_forward_profiles(parent):        # Заполняем parent.mc_data['ssl_forward_profiles']
            parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей пересылки SSL.')
            return
    ssl_forward_profiles = parent.mc_data['ssl_forward_profiles']

    for item in data:
        item['name'] = func.get_restricted_name(item['name'])
        if item['name'] in ssl_forward_profiles:
            if parent.template_id == ssl_forward_profiles[item['name']].template_id:
                parent.stepChanged.emit(f'uGRAY|    Профиль пересылки SSL "{item["name"]}" уже существует в текущем шаблоне.')
                err, result = parent.utm.update_template_ssl_forward_profile(parent.template_id, ssl_forward_profiles[item['name']].id, item)
                if err:
                    parent.stepChanged.emit(f'RED|       {result}  [Профиль пересылки SSL "{item["name"]}"]')
                    error = 1
                else:
                    parent.stepChanged.emit(f'uGRAY|       Профиль пересылки SSL "{item["name"]}" обновлён.')
            else:
                parent.stepChanged.emit(f'sGREEN|    Профиль пересылки SSL "{item["name"]}" уже существует в шаблоне "{ssl_forward_profiles[item["name"]].template_name}".')
        else:
            err, result = parent.utm.add_template_ssl_forward_profile(parent.template_id, item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Профиль пересылки SSL "{item["name"]}" не импортирован]')
            else:
                ssl_forward_profiles[item['name']] = BaseObject(id=result, template_id=parent.template_id, template_name=parent.templates[parent.template_id])
                parent.stepChanged.emit(f'BLACK|    Профиль пересылки SSL "{item["name"]}" импортирован.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей пересылки SSL.')
    else:
        parent.stepChanged.emit('GREEN|    Импорт профилей пересылки SSL завершён.')


def import_hip_objects(parent, path):
    """Импортируем HIP объекты"""
    json_file = os.path.join(path, 'config_hip_objects.json')
    err, data = func.read_json_file(parent, json_file, mode=2)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт HIP объектов в раздел "Библиотеки/HIP объекты".')
    error = 0

    if not parent.mc_data['hip_objects']:
        if get_hip_objects(parent):        # Заполняем parent.mc_data['hip_objects']
            parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте HIP объектов.')
            return
    hip_objects = parent.mc_data['hip_objects']

    for item in data:
        if item['name'] in hip_objects:
            if parent.template_id == hip_objects[item['name']].template_id:
                parent.stepChanged.emit(f'uGRAY|    HIP объект "{item["name"]}" уже существует в текущем шаблоне.')
                err, result = parent.utm.update_template_hip_object(parent.template_id, hip_objects[item['name']].id, item)
                if err:
                    parent.stepChanged.emit(f'RED|       {result}  [HIP объект "{item["name"]}"]')
                    error = 1
                else:
                    parent.stepChanged.emit(f'uGRAY|       HIP объект "{item["name"]}" обновлён.')
            else:
                parent.stepChanged.emit(f'sGREEN|    HIP объект "{item["name"]}" уже существует в шаблоне "{hip_objects[item["name"]].template_name}".')
        else:
            err, result = parent.utm.add_template_hip_object(parent.template_id, item)
            if err:
                parent.stepChanged.emit(f'RED|    {result}  [HIP объект "{item["name"]}" не импортирован]')
                error = 1
            else:
                hip_objects[item['name']] = BaseObject(id=result, template_id=parent.template_id, template_name=parent.templates[parent.template_id])
                parent.stepChanged.emit(f'BLACK|    HIP объект "{item["name"]}" импортирован.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте HIP объектов.')
    else:
        parent.stepChanged.emit('GREEN|    Импорт HIP объектов завершён.')


def import_hip_profiles(parent, path):
    """Импортируем HIP профили"""
    json_file = os.path.join(path, 'config_hip_profiles.json')
    err, data = func.read_json_file(parent, json_file, mode=2)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт HIP профилей в раздел "Библиотеки/HIP профили".')
    error = 0

    if not parent.mc_data['hip_objects']:
        if get_hip_objects(parent):        # Заполняем parent.mc_data['hip_objects']
            parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте HIP профилей.')
            return
    hip_objects = parent.mc_data['hip_objects']

    if not parent.mc_data['hip_profiles']:
        if get_hip_profiles(parent):        # Заполняем parent.mc_data['hip_profiles']
            parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте HIP профилей.')
            return
    hip_profiles = parent.mc_data['hip_profiles']

    for item in data:
        for obj in item['hip_objects']:
            obj['id'] = hip_objects[obj['id']].id
        if item['name'] in hip_profiles:
            if parent.template_id == hip_profiles[item['name']].template_id:
                parent.stepChanged.emit(f'uGRAY|    HIP профиль "{item["name"]}" уже существует в текущем шаблоне.')
                err, result = parent.utm.update_template_hip_profile(parent.template_id, hip_profiles[item['name']].id, item)
                if err:
                    parent.stepChanged.emit(f'RED|       {result}  [HIP профиль "{item["name"]}"]')
                    error = 1
                else:
                    parent.stepChanged.emit(f'uGRAY|       HIP профиль "{item["name"]}" updated.')
            else:
                parent.stepChanged.emit(f'sGREEN|    HIP профиль "{item["name"]}" уже существует в шаблоне "{hip_profiles[item["name"]].template_name}".')
        else:
            err, result = parent.utm.add_template_hip_profile(parent.template_id, item)
            if err:
                parent.stepChanged.emit(f'RED|    {result}  [HIP профиль "{item["name"]}" не импортирован]')
                error = 1
            else:
                hip_profiles[item['name']] = BaseObject(id=result, template_id=parent.template_id, template_name=parent.templates[parent.template_id])
                parent.stepChanged.emit(f'BLACK|    HIP профиль "{item["name"]}" импортирован.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте HIP профилей.')
    else:
        parent.stepChanged.emit('GREEN|    Импорт HIP профилей завершён.')


def import_bfd_profiles(parent, path):
    """Импортируем профили BFD"""
    json_file = os.path.join(path, 'config_bfd_profiles.json')
    err, data = func.read_json_file(parent, json_file, mode=2)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт профилей BFD в раздел "Библиотеки/Профили BFD".')
    error = 0

    if not parent.mc_data['bfd_profiles']:
        if get_bfd_profiles(parent):        # Заполняем parent.mc_data['bfd_profiles']
            parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте BFD профилей.')
            return
    bfd_profiles = parent.mc_data['bfd_profiles']

    for item in data:
        if item['name'] in bfd_profiles:
            if parent.template_id == bfd_profiles[item['name']].template_id:
                parent.stepChanged.emit(f'uGRAY|    Профиль BFD "{item["name"]}" уже существует в текущем шаблоне.')
                err, result = parent.utm.update_template_bfd_profile(parent.template_id, bfd_profiles[item['name']].id, item)
                if err:
                    parent.stepChanged.emit(f'RED|       {result}  [Профиль BFD "{item["name"]}"]')
                    error = 1
                else:
                    parent.stepChanged.emit(f'uGRAY|       Профиль BFD "{item["name"]}" обновлён.')
            else:
                parent.stepChanged.emit(f'sGREEN|    Профиль BFD "{item["name"]}" уже существует в шаблоне "{bfd_profiles[item["name"]].template_name}".')
        else:
            err, result = parent.utm.add_template_bfd_profile(parent.template_id, item)
            if err:
                parent.stepChanged.emit(f'RED|    {result}  [Профиль BFD: "{item["name"]}" не импортирован]')
                error = 1
            else:
                bfd_profiles[item['name']] = BaseObject(id=result, template_id=parent.template_id, template_name=parent.templates[parent.template_id])
                parent.stepChanged.emit(f'BLACK|    Профиль BFD "{item["name"]}" импортирован.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей BFD.')
    else:
        parent.stepChanged.emit('GREEN|    Импорт профилей BFD завершён.')


def import_useridagent_syslog_filters(parent, path):
    """Импортируем syslog фильтры UserID агента"""
    json_file = os.path.join(path, 'config_useridagent_syslog_filters.json')
    err, data = func.read_json_file(parent, json_file, mode=2)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт syslog фильтров UserID агента в раздел "Библиотеки/Syslog фильтры UserID агента".')
    error = 0

    parent.stepChanged.emit('bRED|    Импорт syslog фильтров UserID агента в настоящее время не возможен, так как соответствующие API не работают.')
    return

    if not parent.mc_data['userid_filters']:
        if get_useridagent_filters(parent):        # Заполняем parent.mc_data['userid_filters']
            parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте syslog фильтров UserID агента.')
            return
    userid_filters = parent.mc_data['userid_filters']

    for item in data:
        if item['name'] in userid_filters:
            if parent.template_id == userid_filters[item['name']].template_id:
                parent.stepChanged.emit(f'uGRAY|    Фильтр агента UserID "{item["name"]}" уже существует в текущем шаблоне.')
                err, result = parent.utm.update_template_useridagent_filter(parent.template_id, userid_filters[item['name']].id, item)
                if err:
                    parent.stepChanged.emit(f'RED|       {result}  [Фильтр "{item["name"]}"]')
                    error = 1
                else:
                    parent.stepChanged.emit(f'uGRAY|       Фильтр "{item["name"]}" обновлён.')
            else:
                parent.stepChanged.emit(f'sGREEN|    Фильтр агента UserID "{item["name"]}" уже существует в шаблоне "{userid_filters[item["name"]].template_name}".')
        else:
            err, result = parent.utm.add_template_useridagent_filter(parent.template_id, item)
            if err:
                parent.stepChanged.emit(f'RED|    {result}  [Фильтр "{item["name"]}" не импортирован]')
                error = 1
            else:
                userid_filters[item['name']] = BaseObject(id=result, template_id=parent.template_id, template_name=parent.templates[parent.template_id])
                parent.stepChanged.emit(f'BLACK|    Фильтр "{item["name"]}" импортирован.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте syslog фильтров UserID агента.')
    else:
        parent.stepChanged.emit('GREEN|    Импорт Syslog фильтров UserID агента завершён.')


def import_scenarios(parent, path):
    """Импортируем список сценариев"""
    json_file = os.path.join(path, 'config_scenarios.json')
    err, data = func.read_json_file(parent, json_file, mode=2)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт списка сценариев в раздел "Библиотеки/Сценарии".')
    error = 0

    scenarios = parent.mc_data['scenarios']

    for item in data:
        item['name'] = func.get_restricted_name(item['name'])
        for condition in item['conditions']:
            if condition['kind'] == 'application':
                for x in condition['apps']:
                    try:
                        if x[0] == 'ro_group':
                            x[1] = 0 if x[1] == 'All' else parent.mc_data['l7_categories'][x[1]]
                        elif x[0] == 'group':
                            x[1] = parent.mc_data['apps_groups'][x[1]].id
                    except KeyError as err:
                        parent.stepChanged.emit(f'RED|    Error! Сценарий "{item["name"]}". Не найдена группа приложений {err}. Загрузите группы приложений и повторите попытку.')
                        item['description'] = f'{item["description"]}\nError: Не найдена группа приложений {err}.'
                        condition['apps'] = []
                        break
            elif condition['kind'] == 'mime_types':
                try:
                    condition['content_types'] = [parent.mc_data['mime'][x].id for x in condition['content_types']]
                except KeyError as err:
                    parent.stepChanged.emit(f'RED|    Error! Сценарий "{item["name"]}". Не найден тип контента {err}. Загрузите типы контента и повторите попытку.')
                    item['description'] = f'{item["description"]}\nError: Не найден тип контента {err}.'
                    condition['content_types'] = []
            elif condition['kind'] == 'url_category':
                for x in condition['url_categories']:
                    try:
                        if x[0] == 'list_id':
                            x[1] = parent.mc_data['url_categorygroups'][x[1]].id
                        elif x[0] == 'category_id':
                            x[1] = parent.mc_data['url_categories'][x[1]]
                    except KeyError as err:
                        parent.stepChanged.emit(f'RED|    Error! Сценарий "{item["name"]}". Не найдена группа URL категорий {err}. Загрузите категории URL и повторите попытку.')
                        item['description'] = f'{item["description"]}\nError: Не найдена группа URL категорий {err}.'
                        condition['url_categories'] = []
                        break

        if item['name'] in scenarios:
            if parent.template_id == scenarios[item['name']].template_id:
                parent.stepChanged.emit(f'uGRAY|    Сценарий "{item["name"]}" уже существует в текущем шаблоне.')
                err, result = parent.utm.update_template_scenarios_rule(parent.template_id, scenarios[item['name']].id, item)
                if err:
                    parent.stepChanged.emit(f'RED|       {result}  [Сценарий "{item["name"]}"]')
                    error = 1
                else:
                    parent.stepChanged.emit(f'uGRAY|       Сценарий "{item["name"]}" обновлён.')
            else:
                parent.stepChanged.emit(f'sGREEN|    Сценарий "{item["name"]}" уже существует в шаблоне "{scenarios[item["name"]].template_name}".')
        else:
            err, result = parent.utm.add_template_scenarios_rule(parent.template_id, item)
            if err:
                parent.stepChanged.emit(f'RED|    {result}  [Сценарий "{item["name"]}" не импортирован]')
                error = 1
            else:
                scenarios[item['name']] = BaseObject(id=result, template_id=parent.template_id, template_name=parent.templates[parent.template_id])
                parent.stepChanged.emit(f'BLACK|    Сценарий "{item["name"]}" импортирован.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте списка сценариев.')
    else:
        parent.stepChanged.emit('GREEN|    Импорт списка сценариев завершён.')


#-------------------------------------------- Сеть ------------------------------------------------------------
class Zone:
    def __init__(self, parent, zone):
        self.parent = parent
        self.name = zone['name']
        self.description = zone['description']
        self.services_access = zone['services_access']
        self.enable_antispoof = zone['enable_antispoof']
        self.antispoof_invert = zone['antispoof_invert']
        self.networks = zone['networks']
        self.sessions_limit_enabled = zone['sessions_limit_enabled']
        self.sessions_limit_exclusions = zone['sessions_limit_exclusions']
        self.service_ids = {
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
#           'SCADA': 'ffffff03-ffff-ffff-ffff-ffffff000017',
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
        self.error = 0
        self.check_services_access()
        self.check_networks()
        self.check_sessions_limit()


    def check_services_access(self):
        """Обрабатываем сервисы из контроля доступа"""
        new_services_access = []
        for service in self.services_access:
            if service['enabled']:
                service_name = service['service_id']
                # Проверяем что такой сервис существует в этой версии МС и получаем его ID.
                try:
                    service['service_id'] = self.service_ids[service['service_id']]
                except KeyError as err:
                    self.parent.stepChanged.emit(f'RED|    Error [Зона "{self.name}"]. Не корректный сервис "{service_name}" в контроле доступа. Сервис не импортирован.')
                    self.description = f'{self.description}\nError: Не импортирован сервис "{service_name}" в контроль доступа.'
                    self.error = 1
                    continue
                # Приводим список разрешённых адресов сервиса к спискам IP-листов.
                if service['allowed_ips'] and isinstance(service['allowed_ips'][0], list):
                    allowed_ips = []
                    for item in service['allowed_ips']:
                        if item[0] == 'list_id':
                            try:
                                item[1] = self.parent.mc_data['ip_lists'][item[1]].id
                            except KeyError as err:
                                self.parent.stepChanged.emit(f'RED|    Error [Зона "{self.name}"]. В контроле доступа "{service_name}" не найден список IP-адресов {err}.')
                                self.description = f'{self.description}\nError: В контроле доступа "{service_name}" не найден список IP-адресов {err}.'
                                self.error = 1
                                continue
                        allowed_ips.append(item)
                    service['allowed_ips'] = allowed_ips

                new_services_access.append(service)
        self.services_access = new_services_access


    def check_networks(self):
        """Обрабатываем защиту от IP-спуфинга"""
        if self.networks and isinstance(self.network[0], list):
            new_networks = []
            for item in self.networks:
                if item[0] == 'list_id':
                    try:
                        item[1] = self.parent.mc_data['ip_lists'][item[1]].id
                    except KeyError as err:
                        self.parent.stepChanged.emit(f'RED|    Error [Зона "{self.name}"]. В разделе "Защита от IP-спуфинга" не найден список IP-адресов {err}.')
                        self.description = f'{self.description}\nError: В разделе "Защита от IP-спуфинга" не найден список IP-адресов {err}.'
                        self.error = 1
                        continue
                new_networks.append(item)
            self.networks = new_networks


    def check_sessions_limit(self):
        """Обрабатываем ограничение сессий"""
        new_sessions_limit_exclusions = []
        for item in self.sessions_limit_exclusions:
            try:
                item[1] = self.parent.mc_data['ip_lists'][item[1]].id
                new_sessions_limit_exclusions.append(item)
            except KeyError as err:
                self.parent.stepChanged.emit(f'RED|    Error [Зона "{self.name}"]. В разделе "Ограничение сессий" не найден список IP-адресов {err}.')
                self.description = f'{self.description}\nError: В разделе "Ограничение сессий" не найден список IP-адресов {err}.'
                self.error = 1
        self.sessions_limit_exclusions = new_sessions_limit_exclusions
        if not self.sessions_limit_exclusions:
            self.sessions_limit_enabled = False


def import_zones(parent, path):
    """Импортируем зоны на NGFW, если они есть."""
    json_file = os.path.join(path, 'config_zones.json')
    err, data = func.read_json_file(parent, json_file, mode=2)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт зон в раздел "Сеть/Зоны".')
    mc_zones = parent.mc_data['zones']
    error = 0

    for zone in data:
        zone['name'] = func.get_restricted_name(zone['name'])
        if zone['name'] in mc_zones:
            if parent.template_id == mc_zones[zone['name']].template_id:
                parent.stepChanged.emit(f'uGRAY|    Зона "{zone["name"]}" уже существует в текущем шаблоне.')
            else:
                parent.stepChanged.emit(f'sGREEN|    Зона "{zone["name"]}" уже существует в шаблоне "{mc_zones[zone["name"]].template_name}".')
            continue

        current_zone = Zone(parent, zone)
        zone['services_access'] = current_zone.services_access
        zone['enable_antispoof'] = current_zone.enable_antispoof
        zone['antispoof_invert'] = current_zone.antispoof_invert
        zone['networks'] = current_zone.networks
        zone['sessions_limit_enabled'] = current_zone.sessions_limit_enabled
        zone['sessions_limit_exclusions'] = current_zone.sessions_limit_exclusions
        zone['description'] = current_zone.description
        error = current_zone.error

        err, result = parent.utm.add_template_zone(parent.template_id, zone)
        if err == 3:
            parent.stepChanged.emit(f'uGRAY|    {result}')
        elif err == 1:
            parent.stepChanged.emit(f'RED|    {result} [Зона "{zone["name"]}" не импортирована]')
            error = 1
        else:
            mc_zones[zone['name']] = BaseObject(id=result, template_id=parent.template_id, template_name=parent.templates[parent.template_id])
            parent.stepChanged.emit(f'BLACK|    Зона "{zone["name"]}" импортирована.')

    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте зон.')
    else:
        parent.stepChanged.emit('GREEN|    Импорт Зон завершён.')


def import_interfaces(parent, path):
    """Импортируем интерфесы Tunnel и Vlan."""
    json_file = os.path.join(path, 'config_interfaces.json')
    err, data = func.read_json_file(parent, json_file, mode=2)
    if err:
        return

    parent.stepChanged.emit(f'BLUE|Импорт интерфейсов на узел кластера "{parent.node_name}"')

    if not parent.mc_data['interfaces']:
        if get_interfaces_list(parent):        # Получаем все интерфейсы группы шаблонов и заполняем: parent.mc_data['interfaces']
            parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте интерфейсов.')
            return

    if not parent.mc_data['netflow_profiles']:
        if get_netflow_profiles(parent):        # Заполняем parent.mc_data['netflow_profiles']
            parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте интерфейсов.')
            return

    if not parent.mc_data['lldp_profiles']:
        if get_lldp_profiles(parent):        # Заполняем parent.mc_data['lldp_profiles']
            parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте интерфейсов.')
            return

    kinds = set()
    for item in data:
        kinds.add(item['kind'])

    if 'tunnel' in kinds:
        import_ipip_interfaces(parent, path, data)
    if 'vlan' in kinds:
        import_vlans(parent, path)


def import_ipip_interfaces(parent, path, data):
    """Импортируем интерфесы IP-IP."""
    # Проверяем что есть интерфейсы IP-IP для импорта.
    is_gre = False
    for item in data:
        if 'kind' in item and item['kind'] == 'tunnel' and item['name'][:3] == 'gre':
            is_gre = True
    if not is_gre:
        return

    parent.stepChanged.emit('BLUE|    Импорт интерфейсов GRE/IPIP/VXLAN в раздел "Сеть/Интерфейсы".')
    mc_ifaces = parent.mc_data['interfaces']
#    mc_gre = [int(x[3:].split(':')[0]) for x in mc_ifaces if x.startswith('gre') and x.split(':')[1] == parent.node_name]
    mc_gre = [int(aa[0][3:]) for x in mc_ifaces if (aa := x.split(':'))[0].startswith('gre') and aa[1] == parent.node_name]
    gre_num = max(mc_gre) if mc_gre else 0
    if gre_num:
        parent.stepChanged.emit(f'uGRAY|       Для интерфейсов GRE будут использованы номера начиная с {gre_num + 1} так как меньшие номера уже существует в этой группе шаблонов для узла кластера "{parent.node_name}".')
    error = 0

    for item in data:
        if 'kind' in item and item['kind'] == 'tunnel' and item['name'].startswith('gre'):
            gre_num += 1
            item['name'] = f'gre{gre_num}'
            item.pop('id', None)          # удаляем readonly поле
            item.pop('master', None)      # удаляем readonly поле
            item.pop('mac', None)
            if 'node_name' in item:
                 if item['node_name'] != parent.node_name:
                    continue
            else:
                item['node_name'] = parent.node_name

            iface_name = f'{item["name"]}:{parent.node_name}'
            if iface_name in mc_ifaces:
                if parent.template_id == mc_ifaces[iface_name].template_id:
                    parent.stepChanged.emit(f'uGRAY|       Интерфейс "{item["name"]}" уже существует в текущем шаблоне на узле кластера "{parent.node_name}".')
                else:
                    parent.stepChanged.emit(f'sGREEN|       Интерфейс "{item["name"]}" уже существует в шаблоне "{mc_ifaces[iface_name].template_name}" на узле кластера "{parent.node_name}".')
                continue

            if item['zone_id']:
                try:
                    item['zone_id'] = parent.mc_data['zones'][item['zone_id']].id
                except KeyError as err:
                    parent.stepChanged.emit(f'RED|       Error [Интерфейс "{item["name"]}"]. Не найдена зона {err}. Импортируйте зоны и повторите попытку.')
                    item['zone_id'] = 0
                    error = 1

            new_ipv4 = []
            for ip in item['ipv4']:
                err, result = func.unpack_ip_address(ip)
                if err:
                    parent.stepChanged.emit(f'RED|       Error [Интерфейс "{item["name"]}"]. Не удалось преобразовать IP: "{ip}". IP-адрес использован не будет. {result}')
                else:
                    new_ipv4.append(result)
            if not new_ipv4:
                item['config_on_device'] = True
            item['ipv4'] = new_ipv4

            err, result = parent.utm.add_template_interface(parent.template_id, item)
            if err:
                parent.stepChanged.emit(f'RED|       {result} [Интерфейс "{item["tunnel"]["mode"]} - {item["name"]}" не импортирован]')
                error = 1
            else:
                mc_ifaces[iface_name] = BaseObject(id=result, template_id=parent.template_id, template_name=parent.templates[parent.template_id])
                parent.stepChanged.emit(f'BLACK|       Интерфейс {item["tunnel"]["mode"]} - {item["name"]} импортирован на узел кластера "{parent.node_name}".')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|       Произошла ошибка при создании интерфейсов GRE/IPIP/VXLAN.')
    else:
        parent.stepChanged.emit('GREEN|       Импорт интерфейсов GRE/IPIP/VXLAN завершён.')


def import_vlans(parent, path):
    """Импортируем интерфесы VLAN. Нельзя использовать интерфейсы Management и slave."""
    parent.stepChanged.emit('BLUE|    Импорт VLAN в раздел "Сеть/Интерфейсы"')
    error = 0
    if isinstance(parent.ngfw_vlans, int):
        parent.stepChanged.emit(parent.new_vlans)
        if parent.ngfw_vlans == 1:
            parent.error = 1
        return
    mc_ifaces = parent.mc_data['interfaces']
    netflow_profiles = parent.mc_data['netflow_profiles']
    lldp_profiles = parent.mc_data['lldp_profiles']

    for item in parent.iface_settings:
        if 'kind' in item and item['kind'] == 'vlan':
            current_zone = parent.new_vlans[item['vlan_id']]['zone']
            current_port = parent.new_vlans[item['vlan_id']]['port']
            if current_port == "Undefined":
                parent.stepChanged.emit(f"rNOTE|       VLAN {item['vlan_id']} не импортирован так как для него не назначен порт.")
                continue

            item.pop('running', None)
            item.pop('master', None)
            item.pop('mac', None)
            item.pop('id', None)
            item['node_name'] = parent.node_name
            item['link'] = current_port
            item['name'] = f'{current_port}.{item["vlan_id"]}'

            iface_name = f'{item["name"]}:{parent.node_name}'
            if iface_name in mc_ifaces:
                if parent.template_id == mc_ifaces[iface_name].template_id:
                    parent.stepChanged.emit(f'uGRAY|       Интерфейс "{item["name"]}" уже существует в текущем шаблоне на узле кластера "{parent.node_name}".')
                else:
                    parent.stepChanged.emit(f'sGREEN|       Интерфейс "{item["name"]}" уже существует в шаблоне "{mc_ifaces[iface_name].template_name}" на узле кластера "{parent.node_name}".')
                continue

            if current_zone == "Undefined":
                item['zone_id'] = 0
            else:
                try:
                    item['zone_id'] = parent.mc_data['zones'][current_zone].id
                except KeyError as err:
                    parent.stepChanged.emit(f'RED|       Error [Интерфейс "{item["name"]}"]. Не найдена зона {err}. Импортируйте зоны и повторите попытку.')
                    item['zone_id'] = 0
                    error = 1

            new_ipv4 = []
            for ip in item['ipv4']:
                err, result = func.unpack_ip_address(ip)
                if err:
                    parent.stepChanged.emit(f'RED|       Error [Интерфейс "{item["name"]}"]. Не удалось преобразовать IP: "{ip}". IP-адрес использован не будет. {result}')
                    error = 1
                else:
                    new_ipv4.append(result)
            if not new_ipv4:
                item['mode'] = 'manual'
            item['ipv4'] = new_ipv4

            try:
                item['lldp_profile'] = lldp_profiles[item['lldp_profile']].id
            except KeyError:
                parent.stepChanged.emit(f'RED|       Error [Интерфейс "{item["name"]}"]. Не найден lldp profile "{item["lldp_profile"]}" . Импортируйте профили LLDP и повторите попытку.')
                item['lldp_profile'] = 'undefined'
            try:
                item['netflow_profile'] = netflow_profiles[item['netflow_profile']].id
            except KeyError:
                parent.stepChanged.emit(f'RED|       Error [Интерфейс "{item["name"]}"]. Не найден netflow profile "{item["netflow_profile"]}" . Импортируйте профили netflow и повторите попытку.')
                item['netflow_profile'] = 'undefined'

            err, result = parent.utm.add_template_interface(parent.template_id, item)
            if err:
                parent.stepChanged.emit(f'RED|       {result} [Интерфейс "{item["name"]}" не импортирован]')
                error = 1
            else:
                mc_ifaces[iface_name] = BaseObject(id=result, template_id=parent.template_id, template_name=parent.templates[parent.template_id])
                parent.stepChanged.emit(f'BLACK|       Интерфейс VLAN "{item["name"]}" импортирован на узел кластера "{parent.node_name}".')

    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|       Произошла ошибка при создания интерфейсов VLAN.')
    else:
        parent.stepChanged.emit('GREEN|       Импорт интерфейсов VLAN завершён.')


def import_gateways(parent, path):
    import_gateways_list(parent, path)
    import_gateway_failover(parent, path)

def import_gateways_list(parent, path):
    """Импортируем список шлюзов"""
    json_file = os.path.join(path, 'config_gateways.json')
    err, data = func.read_json_file(parent, json_file, mode=2)
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

    if not parent.mc_data['interfaces']:
        if get_interfaces_list(parent):        # Получаем все интерфейсы группы шаблонов и заполняем: parent.mc_data['interfaces']
            parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте шлюзов.')
            return
    mc_ifaces = parent.mc_data['interfaces'].keys()

    parent.mc_data['gateways'].clear()
    if get_gateways_list(parent):           # Получаем все шлюзы группы шаблонов и заполняем: parent.mc_data['gateways']
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте шлюзов.')
        return
    gateways = parent.mc_data['gateways']

    parent.mc_data['vrf'].clear()
    if get_vrf_list(parent):                # Получаем все VRF группы шаблонов и заполняем: parent.mc_data['vrf']
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте шлюзов.')
        return
    mc_vrf = parent.mc_data['vrf']

    gateways_vrf = {item['vrf']: [] for item in data}
    for item in data:
        if f'{item["iface"]}:{parent.node_name}' in mc_ifaces:
            gateways_vrf[item['vrf']].append(item['iface'])

    for item in data:
        item['is_automatic'] = False

        if 'node_name' in item:
            if item['node_name'] != parent.node_name:
                parent.stepChanged.emit(f'rNOTE|    Шлюз "{item["name"]}" не импортирован так как имя узла в настройках не совпало с указанным.')
                continue
        else:
            item['node_name'] = parent.node_name

        # Создаём новый VRF если такого ещё нет для этого узла кластера с интерфейсами, которые используются в шлюзах.
        vrf_name = f'{item["vrf"]}:{parent.node_name}'
        if vrf_name not in mc_vrf:
            err, result = add_empty_vrf(parent, item['vrf'], gateways_vrf[item['vrf']], parent.node_name)
            if err:
                parent.stepChanged.emit(f'RED|    {result}')
                parent.stepChanged.emit(f'RED|    Error: Для шлюза "{item["name"]}" не удалось добавить VRF "{item["vrf"]}". Установлен VRF по умолчанию.')
                item['vrf'] = 'default'
                item['default'] = False
                error = 1
            else:
                parent.stepChanged.emit(f'NOTE|    Для шлюза "{item["name"]}" создан VRF "{item["vrf"]}" на узле кластера "{parent.node_name}".')
                mc_vrf[vrf_name] = BaseObject(id=result, template_id=parent.template_id, template_name=parent.templates[parent.template_id])

        if item['iface'] not in gateways_vrf[item['vrf']]:
            item['iface'] = 'undefined'

        gateway_name = f'{item["name"]}:{parent.node_name}'
        if gateway_name in gateways:
            if parent.template_id == gateways[gateway_name].template_id:
                parent.stepChanged.emit(f'uGRAY|    Шлюз "{item["name"]}" уже существует в текущем шаблоне на узле кластера "{parent.node_name}".')
                err, result = parent.utm.update_template_gateway(parent.template_id, gateways[gateway_name].id, item)
                if err:
                    parent.stepChanged.emit(f'RED|    Error: Шлюз "{item["name"]}" не обновлён. {result}')
                    error = 1
                else:
                    parent.stepChanged.emit(f'uGRAY|    Шлюз "{item["name"]}" на узле кластера "{parent.node_name}" обновлён.')
            else:
                parent.stepChanged.emit(f'sGREEN|    Шлюз "{item["name"]}" уже существует в шаблоне "{gateways[gateway_name].template_name}" на узле кластера "{parent.node_name}".')
        else:
            err, result = parent.utm.add_template_gateway(parent.template_id, item)
            if err:
                parent.stepChanged.emit(f'RED|    {result}  [Шлюз "{item["name"]}" не импортирован]')
                error = 1
            else:
                gateways[gateway_name] = BaseObject(id=result, template_id=parent.template_id, template_name=parent.templates[parent.template_id])
                parent.stepChanged.emit(f'BLACK|    Шлюз "{item["name"]}" импортирован на узел кластера "{parent.node_name}".')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте шлюзов.')
    else:
        parent.stepChanged.emit('GREEN|    Импорт шлюзов завершён.')


def import_gateway_failover(parent, path):
    """Импортируем настройки проверки сети"""
    json_file = os.path.join(path, 'config_gateway_failover.json')
    err, data = func.read_json_file(parent, json_file, mode=2)
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

    if isinstance(parent.ngfw_ports, list) and not parent.dhcp_settings:
        json_file = os.path.join(path, 'config_dhcp_subnets.json')
        err, parent.dhcp_settings = func.read_json_file(parent, json_file)
        if err:
            return
        if not parent.mc_data['interfaces']:
            if get_interfaces_list(parent):        # Получаем все интерфейсы группы шаблонов и заполняем: parent.mc_data['interfaces']
                parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте интерфейсов.')
                return
        parent.ngfw_ports = [x.split(':')[0] for x in parent.mc_data['interfaces'] if x.split(':')[1] == parent.node_name]

    err, result = parent.utm.get_template_dhcp_list(parent.template_id)
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте настроек DHCP.')
        parent.error = 1
        return
    mc_dhcp_subnets = [x['name'] for x in result]
    error = 0

    for item in parent.dhcp_settings:
        if 'node_name' in item:
            if item['node_name'] != parent.node_name:
                parent.stepChanged.emit(f'rNOTE|    DHCP subnet "{item["name"]}" не импортирован так как имя узла в настройках не совпало с указанным.')
                continue
        else:
            item['node_name'] = parent.node_name

        if item['iface_id'] == 'Undefined':
            parent.stepChanged.emit(f'GRAY|    DHCP subnet "{item["name"]}" не добавлен так как для него не указан порт.')
            continue

        if item['iface_id'] not in parent.ngfw_ports:
            parent.stepChanged.emit(f'rNOTE|    DHCP subnet "{item["name"]}" не добавлен так как порт "{item["iface_id"]}" не существует для узла "{parent.node_name}" в группе шаблонов.')
            continue

        item['name'] = func.get_restricted_name(item['name'])
        if item['name'] in mc_dhcp_subnets:
            parent.stepChanged.emit(f'uGRAY|    DHCP subnet "{item["name"]}" уже существует в текущем шаблоне на узле кластера "{parent.node_name}".')
            continue

        err, result = parent.utm.add_template_dhcp_subnet(parent.template_id, item)
        if err == 1:
            parent.stepChanged.emit(f'RED|    {result}  [subnet "{item["name"]}" не импортирован]')
            error = 1
        elif err == 3:
            parent.stepChanged.emit(f'GRAY|    {result}.')
        else:
            parent.stepChanged.emit(f'BLACK|    DHCP subnet "{item["name"]}" импортирован на узел кластера "{parent.node_name}".')

    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте настроек DHCP.')
    else:
        parent.stepChanged.emit('GREEN|    Импорт настроек DHCP завершён.')


def import_dns_config(parent, path):
    """Импортируем раздел 'UserGate/DNS'."""
    import_dns_servers(parent, path)
    import_dns_proxy(parent, path)
    import_dns_rules(parent, path)
    import_dns_static(parent, path)

def import_dns_servers(parent, path):
    """Импортируем список системных DNS серверов"""
    json_file = os.path.join(path, 'config_dns_servers.json')
    err, data = func.read_json_file(parent, json_file, mode=2)
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
        parent.stepChanged.emit('GREEN|    Импорт системных DNS-серверов завершён.')

def import_dns_proxy(parent, path):
    """Импортируем настройки DNS прокси"""
    json_file = os.path.join(path, 'config_dns_proxy.json')
    err, result = func.read_json_file(parent, json_file, mode=2)
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

def import_dns_rules(parent, path):
    """Импортируем правила DNS-прокси"""
    json_file = os.path.join(path, 'config_dns_rules.json')
    err, data = func.read_json_file(parent, json_file, mode=2)
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
        parent.stepChanged.emit('GREEN|    Импорт правил DNS-прокси завершён.')

def import_dns_static(parent, path):
    """Импортируем статические записи DNS"""
    json_file = os.path.join(path, 'config_dns_static.json')
    err, data = func.read_json_file(parent, json_file, mode=2)
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
        parent.stepChanged.emit('GREEN|    Импорт статических записей DNS завершён.')


def import_vrf(parent, path):
    """Импортируем виртуальный маршрутизатор по умолчанию"""
    json_file = os.path.join(path, 'config_vrf.json')
    err, data = func.read_json_file(parent, json_file, mode=2)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт виртуальных маршрутизаторов в раздел "Сеть/Виртуальные маршрутизаторы".')
    parent.stepChanged.emit('LBLUE|    Если вы используете BGP, после импорта включите нужные фильтры in/out для BGP-соседей и Routemaps в свойствах соседей.')
    error = 0
    
    parent.mc_data['vrf'].clear()
    if get_vrf_list(parent):                # Получаем все VRF группы шаблонов и заполняем: parent.mc_data['vrf']
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте виртуальных маршрутизаторов.')
        return
    mc_vrf = parent.mc_data['vrf']

    if not parent.mc_data['interfaces']:
        if get_interfaces_list(parent):        # Получаем все интерфейсы группы шаблонов и заполняем: parent.mc_data['interfaces']
            parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте шлюзов.')
            return
    mc_ifaces = parent.mc_data['interfaces'].keys()

    if not parent.mc_data['bfd_profiles']:
        if get_bfd_profiles(parent):                # Получаем все профили BFD группы шаблонов и заполняем: parent.mc_data['bfd_profiles']
            parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте виртуальных маршрутизаторов.')
            return
    bfd_profiles = parent.mc_data['bfd_profiles']
    bfd_profiles[-1] = BaseObject(id=-1, template_id='', template_name='')

    vrfnames = []
    for item in data:
        if item['name'] in vrfnames:
            parent.stepChanged.emit(f'rNOTE|    VRF "{item["name"]}" не импортирован так как VRF с таким именем уже был импортирован выше.')
            continue
        else:
            vrfnames.append(item['name'])

        if 'node_name' in item:
            if item['node_name'] != parent.node_name:
                parent.stepChanged.emit(f'rNOTE|    VRF "{item["name"]}" не импортирован так как имя узла в настройках не совпало с указанным.')
                continue
        else:
            item['node_name'] = parent.node_name

        vrf_name = f'{item["name"]}:{parent.node_name}'
        if vrf_name in mc_vrf:
            if parent.template_id != mc_vrf[vrf_name].template_id:
                parent.stepChanged.emit(f'sGREEN|    VRF "{item["name"]}" уже существует в шаблоне "{mc_vrf[vrf_name].template_name}" на узле кластера "{parent.node_name}".')
                continue

        new_interfaces = []
        for x in item['interfaces']:
            if f'{x}:{parent.node_name}' in mc_ifaces:
                new_interfaces.append(x)
            else:
                parent.stepChanged.emit(f'RED|    Error [VRF "{item["name"]}"]. Из VRF удалён интерфейс "{x}" так как отсутствует на узле кластера "{parent.node_name}".')
                error = 1
        item['interfaces'] = new_interfaces

        for x in item['routes']:
            x['name'] = func.get_restricted_name(x['name'])
            if x['ifname'] != 'undefined':
                if f'{x["ifname"]}:{parent.node_name}' not in mc_ifaces:
                    if f'{x["ifname"]}:cluster' not in mc_ifaces:
                        parent.stepChanged.emit(f'RED|    Error [VRF "{item["name"]}"]. Интерфейс "{x["ifname"]}" удалён из статического маршрута "{x["name"]}" так как отсутствует на узле кластера "{parent.node_name}".')
                        x['ifname'] = 'undefined'
                        error = 1

        if item['ospf']:
            ids = set()
            new_interfaces = []
            for iface in item['ospf']['interfaces']:
                iface['network_type'] = iface.get('network_type', '')   # Добавляем поле, отсутствующее с старых версиях
                iface['is_passive'] = iface.get('is_passive', False)    # Добавляем поле, отсутствующее с старых версиях
                if item['name'] != 'default' and iface['iface_id'] not in item['interfaces']:
                    parent.stepChanged.emit(f'RED|    Error [VRF "{item["name"]}"]. Интерфейс OSPF "{iface["iface_id"]}" удалён из настроек OSPF так как отсутствует в этом VRF.')
                    ids.add(iface['id'])
                    error = 1
                else:
                    try:
                        iface['bfd_profile'] = bfd_profiles[iface['bfd_profile']].id
                    except KeyError as err:
                        parent.stepChanged.emit(f'RED|    Error [VRF "{item["name"]}"]. Для OSPF не найден профиль BFD {err}. Установлено значение по умолчанию.')
                        iface['bfd_profile'] = -1
                        error = 1
                    new_interfaces.append(iface)
            item['ospf']['interfaces'] = new_interfaces

            new_areas = []
            for area in item['ospf']['areas']:
                err, result = func.unpack_ip_address(area['area_id'])
                if err:
                    try:
                        area['area_id'] = int(area['area_id'])
                    except ValueError:
                        parent.stepChanged.emit(f'RED|    Error [VRF "{item["name"]}"]. Область OSPF "{area["name"]}" удалёна из настроек OSPF так как у неё не валидный идентификатор области.')
                        error = 1
                        continue
                tmp = set(area['interfaces'])
                if not (tmp - ids):
                    parent.stepChanged.emit(f'RED|    Error [VRF "{item["name"]}"]. Область OSPF "{area["name"]}" удалёна из настроек OSPF так как у неё отсутствуют интерфейсы.')
                    error = 1
                else:
                    new_areas.append(area)
            item['ospf']['areas'] = new_areas

        if item['bgp']:
            for x in item['bgp']['neighbors']:
                x['filter_in'] = []
                x['filter_out'] = []
                x['routemap_in'] = []
                x['routemap_out'] = []
                try:
                    x['bfd_profile'] = bfd_profiles[x['bfd_profile']].id
                except KeyError as err:
                    parent.stepChanged.emit(f'RED|    Error [VRF "{item["name"]}"]. Для BGP не найден профиль BFD {err}. Установлено значение по умолчанию.')
                    x['bfd_profile'] = -1
                    error = 1
        if item['rip']:
            # Проверяем сети RIP
            new_networks = []
            for net in item['rip']['networks']:
                if 'ifname' in net and net['ifname'] not in item['interfaces']:
                    parent.stepChanged.emit(f'RED|    Error [VRF "{item["name"]}"]. Сеть RIP "{net["ifname"]}" удалёна из настроек RIP так как этот интерфейс отсутствует в этом VRF.')
                    error = 1
                else:
                    new_networks.append(net)
            item['rip']['networks'] = new_networks
            # Проверяем интерфейсы RIP
            new_interfaces = []
            for iface in item['rip']['interfaces']:
                if iface['name'] not in item['interfaces']:
                    parent.stepChanged.emit(f'RED|    Error [VRF "{item["name"]}"]. Интерфейс RIP "{iface["name"]}" удалён из настроек RIP так как он отсутствует в этом VRF.')
                    error = 1
                else:
                    new_interfaces.append(iface)
            item['rip']['interfaces'] = new_interfaces

        try:
            if vrf_name in mc_vrf:
                parent.stepChanged.emit(f'uGRAY|    VRF "{item["name"]}" уже существует в текущем шаблоне на узле кластера "{parent.node_name}".')
                err, result = parent.utm.update_template_vrf(parent.template_id, mc_vrf[vrf_name].id, item)
                if err:
                    parent.stepChanged.emit(f'RED|       {result} [VRF "{item["name"]}"]')
                    error = 1
                else:
                    parent.stepChanged.emit(f'uGRAY|       VRF "{item["name"]}" обновлён.')
            else:
                err, result = parent.utm.add_template_vrf(parent.template_id, item)
                if err:
                    parent.stepChanged.emit(f'RED|    {result} [VRF "{item["name"]}" не импортирован]')
                    error = 1
                else:
                    mc_vrf[vrf_name] = BaseObject(id=result, template_id=parent.template_id, template_name=parent.templates[parent.template_id])
                    parent.stepChanged.emit(f'BLACK|    Создан виртуальный маршрутизатор "{item["name"]}" для узла кластера "{parent.node_name}".')
        except OverflowError as err:
            parent.stepChanged.emit(f'RED|    Произошла ошибка при импорте виртуального маршрутизатора "{item["name"]}" [{err}].')
            error = 1
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте виртуальных маршрутизаторов.')
    else:
        parent.stepChanged.emit('GREEN|    Импорт виртуальных маршрутизаторов завершён.')


def import_wccp_rules(parent, path):
    """Импортируем список правил WCCP"""
    json_file = os.path.join(path, 'config_wccp.json')
    err, data = func.read_json_file(parent, json_file, mode=2)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт правил WCCP в раздел "Сеть/WCCP".')
    error = 0

    wccp_rules = {}
    for uid, name in parent.templates.items():
        err, result = parent.utm.get_template_wccp_rules(uid)
        if err:
            parent.stepChanged.emit(f'RED|    {result}')
            parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил WCCP.')
            parent.error = 1
            return
        for x in result:
            if x['name'] in wccp_rules:
                parent.stepChanged.emit(f'RED|    Правило WCCP "{x["name"]}" обнаружено в нескольких шаблонах группы шаблонов. Правило из шаблона "{name}" не будет использовано.')
            else:
                wccp_rules[x['name']] = BaseObject(id=x['id'], template_id=uid, template_name=name)

    for item in data:
        item.pop('cc_network_devices', None)    # Если конфиг был экспортирован с МС.
        item.pop('cc_network_devices_negate', None)
        if item['routers']:
            routers = []
            for x in item['routers']:
                if x[0] == 'list_id':
                    try:
                        x[1] = parent.mc_data['ip_lists'][x[1]].id
                    except KeyError as err:
                        parent.stepChanged.emit(f'ORANGE|    Не найден список {err} для правила "{item["name"]}" в группе шаблонов. Загрузите списки IP-адресов и повторите попытку.')
                        continue
                routers.append(x)
            item['routers'] = routers

        if item['name'] in wccp_rules:
            if parent.template_id == wccp_rules[item['name']].template_id:
                parent.stepChanged.emit(f'uGRAY|    Правило WCCP "{item["name"]}" уже существует в текущем шаблоне.')
                err, result = parent.utm.update_template_wccp_rule(parent.template_id, wccp_rules[item['name']].id, item)
                if err:
                    parent.stepChanged.emit(f'RED|       {result} [Правило WCCP "{item["name"]}"]')
                    error = 1
                else:
                    parent.stepChanged.emit(f'uGRAY|       Правило WCCP "{item["name"]}" обновлено.')
            else:
                parent.stepChanged.emit(f'sGREEN|    Правило WCCP "{item["name"]}" уже существует в шаблоне "{wccp_rules[item["name"]].template_name}".')
        else:
            err, result = parent.utm.add_template_wccp_rule(parent.template_id, item)
            if err:
                parent.stepChanged.emit(f'RED|    {result} [Правило WCCP "{item["name"]}" не импортировано]')
                error = 1
            else:
                parent.stepChanged.emit(f'BLACK|    Правило WCCP "{item["name"]}" импортировано.')
                wccp_rules[item['name']] = BaseObject(id=result, template_id=parent.template_id, template_name=parent.templates[parent.template_id])
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил WCCP.')
    else:
        parent.stepChanged.emit('GREEN|    Импорт правил WCCP завершён.')

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
    mc_certs = parent.mc_data['certs']

    for cert_name, cert_path in certificates.items():
        files = [entry.name for entry in os.scandir(cert_path) if entry.is_file()]

        json_file = os.path.join(cert_path, 'certificate_list.json')
        err, data = func.read_json_file(parent, json_file)
        if err:
            continue

        if 'cert.pem' in files:
            with open(os.path.join(cert_path, 'cert.pem'), mode='rb') as fh:
                cert_data = fh.read()
        elif 'cert.der' in files:
            with open(os.path.join(cert_path, 'cert.der'), mode='rb') as fh:
                cert_data = fh.read()
        else:
            if data['name'] in mc_certs:
                if parent.template_id == mc_certs[data['name']].template_id:
                    parent.stepChanged.emit(f'uGRAY|    Сертификат "{cert_name}" уже существует в текущем шаблоне.')
                    parent.stepChanged.emit(f'uGRAY|       Cертификат "{cert_name}" не обновлён так как не найден файл сертификата "cert.pem" или "cert.der".')
                else:
                    parent.stepChanged.emit(f'sGREEN|    Cертификат "{cert_name}" уже существует в шаблоне "{mc_certs[data["name"]].template_name}".')
                continue
            else:
                parent.stepChanged.emit(f'BLACK|    Не найден файл сертификата "{cert_name}" для импорта. Будет сгенерирован новый сертификат "{cert_name}".')
                data.update(data['issuer'])
                err, result = parent.utm.new_template_certificate(parent.template_id, data)
                if err == 1:
                    parent.stepChanged.emit(f'RED|       {result}')
                    error = 1
                elif err == 3:
                    parent.stepChanged.emit(f'GRAY|       {result}')
                else:
                    parent.mc_data['certs'][cert_name] = result
                    parent.stepChanged.emit(f'BLACK|       Создан новый сертификат "{cert_name}".')
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

        if data['name'] in mc_certs:
            if parent.template_id == mc_certs[data['name']].template_id:
                parent.stepChanged.emit(f'uGRAY|    Сертификат "{cert_name}" уже существует в текущем шаблоне.')
                err, result = parent.utm.update_template_certificate(parent.template_id, mc_certs[data['name']].id, data, cert_data, private_key=key_data)
                if err:
                    parent.stepChanged.emit(f'RED|       {result} [Сертификат "{cert_name}"]')
                    error = 1
                else:
                    parent.stepChanged.emit(f'uGRAY|       Cертификат "{cert_name}" обновлён.')
            else:
                parent.stepChanged.emit(f'sGREEN|    Cертификат "{cert_name}" уже существует в шаблоне "{mc_certs[data["name"]].template_name}".')
        else:
            err, result = parent.utm.add_template_certificate(parent.template_id, data, cert_data, private_key=key_data)
            if err:
                parent.stepChanged.emit(f'RED|    {result} [Сертификат "{cert_name}" не импортирован]')
                error = 1
            else:
                mc_certs[cert_name] = BaseObject(id=result, template_id=parent.template_id, template_name=parent.templates[parent.template_id])
                parent.stepChanged.emit(f'BLACK|    Сертификат "{cert_name}" импортирован.')
        time.sleep(0.01)
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте сертификатов.')
    else:
        parent.stepChanged.emit('GREEN|    Импорт сертификатов завершён.')


def import_client_certificate_profiles(parent, path):
    """Импортируем профили пользовательских сертификатов в шаблон"""
    json_file = os.path.join(path, 'users_certificate_profiles.json')
    err, data = func.read_json_file(parent, json_file, mode=2)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт раздела "UserGate/Профили клиентских сертификатов".')

    if not parent.mc_data['client_certs_profiles']:
        if get_client_certificate_profiles(parent): # Заполняем parent.mc_data['client_certs_profiles']
            parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей клиентских сертификатов.')
            return

    error = 0
    client_certs_profiles = parent.mc_data['client_certs_profiles']

    for item in data:
        if item['name'] in client_certs_profiles:
            if parent.template_id == client_certs_profiles[item['name']].template_id:
                parent.stepChanged.emit(f'uGRAY|    Профиль клиентского сертификата "{item["name"]}" уже существует в текущем шаблоне.')
            else:
                parent.stepChanged.emit(f'sGREEN|    Профиль клиентского сертификата "{item["name"]}" уже существует в шаблоне "{client_certs_profiles[item["name"]].template_name}".')
        else:
            item['ca_certificates'] = [parent.mc_data['certs'][x].id for x in item['ca_certificates']]

            err, result = parent.utm.add_template_client_certificate_profile(parent.template_id, item)
            if err == 1:
                parent.stepChanged.emit(f'RED|    {result} [Профиль клиентского сертификата "{item["name"]}" не импортирован]')
                error = 1
            elif err == 3:
                parent.stepChanged.emit(f'GRAY|    {result}')
            else:
                client_certs_profiles[item['name']] = BaseObject(id=result, template_id=parent.template_id, template_name=parent.templates[parent.template_id])
                parent.stepChanged.emit(f'BLACK|    Профиль клиентского сертификата "{item["name"]}" импортирован.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей клиентских сертификатов.')
    else:
        parent.stepChanged.emit('GREEN|    Импорт профилей клиентских сертификатов завершён.')


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
    import_upstream_update_proxy_settings(parent, path)


def import_ui(parent, path):
    """Импортируем раздел UserGate/Настройки/Настройки интерфейса"""
    json_file = os.path.join(path, 'config_settings_ui.json')
    err, data = func.read_json_file(parent, json_file, mode=2)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт раздела "UserGate/Настройки/Настройки интерфейса".')

    if not parent.mc_data['client_certs_profiles']:
        if get_client_certificate_profiles(parent): # Заполняем parent.mc_data['client_certs_profiles']
            parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте настроек интерфейса.')
            return

    params = {
        'ui_timezone': 'Часовой пояс',
        'ui_language': 'Язык интерфейса по умолчанию',
        'web_console_ssl_profile_id': 'Профиль SSL для веб-консоли',
        'response_pages_ssl_profile_id': 'Профиль SSL для страниц блокировки/аутентификации',
        'endpoint_ssl_profile_id': 'Профиль SSL конечного устройства',
        'endpoint_certificate_id': 'Сертификат конечного устройства',
        'webui_auth_mode': 'Режим аутентификации веб-консоли'
    }
    error = 0

    for key in data:
        if key in params:
            value = data[key]
            if key == 'webui_auth_mode':
                if isinstance(value, dict):
                    if value['type'] == 'pki':
                        try:
                            value['client_certificate_profile_id'] = parent.mc_data['client_certs_profiles'][value['client_certificate_profile_id']].id
                        except KeyError as err:
                            parent.stepChanged.emit(f'RED|    Не найден профиль клиентского сертификата {err} для "{params[key]}". Загрузите профили клиентских сертификатов и повторите попытку.')
                            error = 1
                            continue
            if key == 'web_console_ssl_profile_id':
                try:
                    value = parent.mc_data['ssl_profiles'][data[key]].id
                except KeyError as err:
                    parent.stepChanged.emit(f'RED|    Не найден профиль SSL {err} для "{params[key]}". Загрузите профили SSL и повторите попытку.')
                    error = 1
                    continue
            if key == 'response_pages_ssl_profile_id':
                try:
                    value = parent.mc_data['ssl_profiles'][data[key]].id
                except KeyError as err:
                    parent.stepChanged.emit(f'RED|    Не найден профиль SSL {err} для "{params[key]}". Загрузите профили SSL и повторите попытку.')
                    error = 1
                    continue
            if key == 'endpoint_ssl_profile_id':
                try:
                    value = parent.mc_data['ssl_profiles'][data[key]].id
                except KeyError as err:
                    parent.stepChanged.emit(f'RED|    Не найден профиль SSL {err} для "{params[key]}". Загрузите профили SSL и повторите попытку.')
                    error = 1
                    continue
            if key == 'endpoint_certificate_id':
                try:
                    value = parent.mc_data['certs'][data[key]].id
                except KeyError as err:
                    parent.stepChanged.emit(f'RED|    Не найден сертификат {err} для "{params[key]}". Загрузите сертификаты и повторите попытку.')
                    error = 1
                    continue
            setting = {}
            setting[key] = {'value': value}
            err, result = parent.utm.set_template_settings(parent.template_id, setting)
            if err:
                parent.stepChanged.emit(f'RED|    {result} [Параметр "{params[key]}" не импортирован]')
                error = 1
            else:
                parent.stepChanged.emit(f'BLACK|    "{params[key]}" установлен в значение "{data[key]}".')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте настроек интерфейса.')
    else:
        parent.stepChanged.emit('GREEN|    Импорт настроек интерфейса завершён.')


def import_ntp_settings(parent, path):
    """Импортируем настройки NTP в шаблон"""
    json_file = os.path.join(path, 'config_ntp.json')
    err, data = func.read_json_file(parent, json_file, mode=2)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт настроек NTP раздела "UserGate/Настройки/Настройки времени сервера".')
    error = 0

    for i, ntp_server in enumerate(data['ntp_servers']):
        settings = {f'ntp_server{i+1}': {'value': ntp_server, 'enabled': True}}
        err, result = parent.utm.set_template_settings(parent.template_id, settings)
        if err:
            parent.stepChanged.emit(f'RED|    {result} [NTP-сервер "{ntp_server}" не импортирован]')
            error = 1
        else:
            parent.stepChanged.emit(f'BLACK|    NTP-сервер "{ntp_server}" добавлен.')
        if i >= 1:
            break

    settings = {
        'ntp_enabled': {
            'value': data['ntp_enabled'],
            'enabled': True if data['ntp_synced'] else False
        }
    }
    err, result = parent.utm.set_template_settings(parent.template_id, settings)
    if err:
        parent.stepChanged.emit(f'RED|    {result} [Параметр "Использовать NTP" не установлен]')
        error = 1
    else:
        parent.stepChanged.emit(f'BLACK|    Использование NTP {"включено" if data["ntp_enabled"] else "отключено"}.')

    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произоша ошибка при импорте настроек NTP.')
    else:
        parent.stepChanged.emit('GREEN|    Импорт серверов NTP завершён.')


def import_proxy_port(parent, path):
    """Импортируем HTTP(S)-прокси порт в шаблон"""
    json_file = os.path.join(path, 'config_proxy_port.json')
    err, data = func.read_json_file(parent, json_file, mode=2)
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
    err, data = func.read_json_file(parent, json_file, mode=2)
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
                    value['target_zone'] = parent.mc_data['zones'][value['target_zone']].id
                    value.pop('cc', None)
                    data[key].pop('cc', None)   # Удаляем для корректного вывода в лог.
                except KeyError as err:
                    parent.stepChanged.emit(f'RED|    Не найдена зона {err} для "{params[key]}". Загрузите зоны и повторите попытку.')
                    error = 1
                    continue
            setting = {}
            setting[key] = {'value': value}
            err, result = parent.utm.set_template_settings(parent.template_id, setting)
            if err:
                parent.stepChanged.emit(f'RED|    {result} [Параметр "{params[key]}" не установлен]')
                error = 1
            else:
                parent.stepChanged.emit(f'BLACK|    Параметр "{params[key]}" установлен в значение "{data[key]}".')

    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Импорт модулей прошёл с ошибками.')
    else:
        parent.stepChanged.emit('GREEN|    Импорт модулей завершён.')


def import_cache_settings(parent, path):
    """Импортируем раздел 'UserGate/Настройки/Настройки кэширования HTTP'"""
    json_file = os.path.join(path, 'config_proxy_settings.json')
    err, data = func.read_json_file(parent, json_file, mode=2)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт разделов "Расширенные настройки" и "Настройки кэширования HTTP" из "UserGate/Настройки".')
    error = 0
    settings = {
        'Настройки кэширования HTTP': {
            'http_cache': {
                'value': {},
                'enabled': False if data['http_cache_mode'] == 'off' else True
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
            parent.stepChanged.emit(f'RED|    {result} [{key} не импортированы]')
            error = 1
        else:
            parent.stepChanged.emit(f'BLACK|    {key} импортированы.')

    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте настроек.')
    else:
        parent.stepChanged.emit('GREEN|    Импортированы "Расширенные настройки" и "Настройки кэширования HTTP".')


def import_proxy_exceptions(parent, path):
    """Импортируем раздел UserGate/Настройки/Настройки кэширования HTTP/Исключения кэширования"""
    json_file = os.path.join(path, 'config_proxy_exceptions.json')
    err, exceptions = func.read_json_file(parent, json_file, mode=2)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт раздела "UserGate/Настройки/Настройки кэширования HTTP/Исключения кэширования".')
    error = 0

    err, result = parent.utm.get_template_nlists_list(parent.template_id, 'httpcwl')
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте исключений кэширования HTTP.')
        parent.error = 1
        return
    if result:
        list_id = result[0]['id']
    else:
        httpcwl_list = {'name': 'HTTP Cache Exceptions', 'type': 'httpcwl'}
        err, list_id = parent.utm.add_template_nlist(parent.template_id, httpcwl_list)
        if err:
            parent.stepChanged.emit(f'RED|    {list_id}')
            parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте исключений кэширования HTTP.')
            parent.error = 1
            return
    
    for item in exceptions:
        err, result = parent.utm.add_template_nlist_item(parent.template_id, list_id, item)
        if err == 1:
            parent.stepChanged.emit(f'RED|    {result} [URL "{item["value"]}" не импортирован]')
            error = 1
        elif err == 3:
            parent.stepChanged.emit(f'GRAY|    URL "{item["value"]}" уже существует в исключениях кэширования.')
        else:
            parent.stepChanged.emit(f'BLACK|    В исключения кэширования добавлен URL "{item["value"]}".')

    if exceptions:
        err, result = parent.utm.set_template_settings(parent.template_id, {'http_cache_exceptions': {'enabled': True}})
        if err:
            parent.stepChanged.emit(f'RED|    {result}')
            error = 1
            parent.stepChanged.emit('ORANGE|    Произошла ошибка при установке статуса исключения кэширования.')
        else:
            parent.stepChanged.emit(f'BLACK|    Исключения кэширования включено.')

    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте исключений кэширования HTTP.')
    else:
        parent.stepChanged.emit('GREEN|    Исключения кэширования HTTP импортированы".')


def import_web_portal_settings(parent, path):
    """Импортируем раздел 'UserGate/Настройки/Веб-портал'"""
    json_file = os.path.join(path, 'config_web_portal.json')
    err, data = func.read_json_file(parent, json_file, mode=2)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт раздела "UserGate/Настройки/Веб-портал".')
    error = 0

    if not parent.mc_data['response_pages']:
        if get_response_pages(parent):    # Устанавливаем parent.mc_data['response_pages']
            parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте настроек Веб-портала.')
            return
    response_pages = parent.mc_data['response_pages']

    if not parent.mc_data['client_certs_profiles']:
        if get_client_certificate_profiles(parent): # Устанавливаем parent.mc_data['client_certs_profiles']
            parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте настроек Веб-портала.')
            return
    client_certs_profiles = parent.mc_data['client_certs_profiles']

    try:
        data['user_auth_profile_id'] = parent.mc_data['auth_profiles'][data['user_auth_profile_id']].id
    except KeyError as err:
        parent.stepChanged.emit(f'RED|    Error: Не найден профиль аутентификации {err}. Загрузите профили аутентификации и повторите попытку.')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте настроек Веб-портала.')
        parent.error = 1
        return

    try:
        data['ssl_profile_id'] = parent.mc_data['ssl_profiles'][data['ssl_profile_id']].id
    except KeyError as err:
        parent.stepChanged.emit(f'RED|    Error: Не найден профиль SSL {err}. Загрузите профили SSL и повторите попытку.')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте настроек Веб-портала.')
        parent.error = 1
        return

    if data['client_certificate_profile_id']:
        try:
            data['client_certificate_profile_id'] = client_certs_profiles[data['client_certificate_profile_id']].id
        except KeyError as err:
            parent.stepChanged.emit(f'RED|    Error: Не найден профиль клиентского сертификата {err}. Укажите его вручную или загрузите профили клиентских сертификатов и повторите попытку.')
            data['client_certificate_profile_id'] = 0
            data['cert_auth_enabled'] = False
            error = 1

    if data['certificate_id']:
        try:
            data['certificate_id'] = parent.mc_data['certs'][data['certificate_id']].id
        except KeyError as err:
            parent.stepChanged.emit(f'RED|    Error: Не найден сертификат {err}. Укажите сертификат вручную или загрузите сертификаты и повторите попытку.')
            data['certificate_id'] = -1
            error = 1
    else:
        data['certificate_id'] = -1

    if data['proxy_portal_template_id'] != -1:
        try:
            data['proxy_portal_template_id'] = response_pages[data['proxy_portal_template_id']].id
        except KeyError as err:
            data['proxy_portal_template_id'] = -1
            parent.stepChanged.emit(f'RED|    Error: Не найден шаблон портала {err}. Укажите шаблон портала вручную или загрузите шаблоны страниц и повторите попытку.')
            error = 1

    if data['proxy_portal_login_template_id'] != -1:
        try:
            data['proxy_portal_login_template_id'] = response_pages[data['proxy_portal_login_template_id']].id
        except KeyError as err:
            data['proxy_portal_login_template_id'] = -1
            parent.stepChanged.emit(f'RED|    Error: Не найден шаблон страницы аутентификации {err}. Укажите её вручную или загрузите шаблоны страниц и повторите попытку.')
            error = 1

    settings = {
        'proxy_portal': {
            'value': data,
            'enabled': False if not data['enabled'] else True
        }
    }
    
    err, result = parent.utm.set_template_settings(parent.template_id, settings)
    if err:
        parent.stepChanged.emit(f'RED|    {result} [Настройки не импортированы]')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте настроек Веб-портала.')
        parent.error = 1
    else:
        parent.stepChanged.emit('GREEN|    Импорт настроек Веб-портала завершён.')


def import_upstream_proxy_settings(parent, path):
    """Импортируем настройки вышестоящего прокси"""
    json_file = os.path.join(path, 'upstream_proxy_settings.json')
    err, data = func.read_json_file(parent, json_file, mode=2)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт настроек раздела "UserGate/Настройки/Вышестоящий прокси".')

    settings = {
        'upstream_proxy': {
            'value': data,
            'enabled': False if not data['enabled'] else True
        }
    }
    
    err, result = parent.utm.set_template_settings(parent.template_id, settings)
    if err:
        parent.stepChanged.emit(f'RED|    {result} [Настройки не импортированы]')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте настроек вышестоящего прокси!')
        parent.error = 1
    else:
        parent.stepChanged.emit('GREEN|    Настройки вышестоящего прокси импортированы.')


def import_upstream_update_proxy_settings(parent, path):
    """Импортируем настройки вышестоящего прокси для проверки лицензий и обновлений"""
    json_file = os.path.join(path, 'upstream_update_proxy.json')
    err, data = func.read_json_file(parent, json_file, mode=2)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт настроек раздела "UserGate/Настройки/Вышестоящий прокси для проверки лицензий и обновлений".')

    settings = {
        'upstream_update_proxy': {
            'value': data,
            'enabled': False if not data['enabled'] else True
        }
    }
    
    err, result = parent.utm.set_template_settings(parent.template_id, settings)
    if err:
        parent.stepChanged.emit(f'RED|    {result} [Настройки не импортированы]')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте настроек вышестоящего прокси для проверки лицензий и обновлений')
        parent.error = 1
    else:
        parent.stepChanged.emit('GREEN|    Настройки вышестоящего прокси для проверки лицензий и обновлений импортированы.')


#---------------------------------------- Пользователи и устройства --------------------------------------------------------
def import_local_groups(parent, path):
    """Импортируем список локальных групп пользователей"""
    json_file = os.path.join(path, 'config_groups.json')
    err, groups = func.read_json_file(parent, json_file, mode=2)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт локальных групп пользователей в раздел "Пользователи и устройства/Группы".')
    parent.stepChanged.emit(f'LBLUE|    Если используются доменные пользователи, необходимы настроенные LDAP-коннекторы в "Управление областью/Каталоги пользователей"')
    error = 0

    local_groups = parent.mc_data['local_groups']

    for item in groups:
        users = item.pop('users')
        item['name'] = func.get_restricted_name(item['name'])
        if item['name'] in local_groups:
            if parent.template_id == local_groups[item['name']].template_id:
                parent.stepChanged.emit(f'uGRAY|    Группа пользователей "{item["name"]}" уже существует в текущем шаблоне.')
            else:
                parent.stepChanged.emit(f'sGREEN|    Группа пользователей "{item["name"]}" уже существует в шаблоне "{local_groups[item["name"]].template_name}".')
                continue
        else:
            err, result = parent.utm.add_template_group(parent.template_id, item)
            if err == 1:
                parent.stepChanged.emit(f'RED|    {result} [Группа пользователей "{item["name"]}" не импортирована]')
                error = 1
                continue
            elif err == 3:
                parent.stepChanged.emit(f'GRAY|    {result}') # В версиях 6 и выше проверяется что группа уже существует.
            else:
                local_groups[item['name']] = BaseObject(id=result, template_id=parent.template_id, template_name=parent.templates[parent.template_id])
                parent.stepChanged.emit(f'BLACK|    Группа пользователей "{item["name"]}" импортирована.')

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
                        parent.stepChanged.emit(f'bRED|       Нет пользователя "{user_name}" в домене "{domain}". Доменный пользователь не импортирован в группу "{item["name"]}".')
                        continue
                    err2, result2 = parent.utm.add_user_in_template_group(parent.template_id, local_groups[item['name']].id, result1)
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
        parent.stepChanged.emit('GREEN|    Импорт локальных групп пользователей завершён.')


def import_local_users(parent, path):
    """Импортируем локальных пользователей и добавляем их в группы"""
    json_file = os.path.join(path, 'config_users.json')
    err, users = func.read_json_file(parent, json_file, mode=2)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт локальных пользователей в раздел "Пользователи и устройства/Пользователи".')
    error = 0
    local_users = parent.mc_data['local_users']

    for item in users:
        user_groups = item.pop('groups', None)
        item['name'] = func.get_restricted_name(item['name'])
        item['auth_login'] = func.get_restricted_userlogin(item['auth_login'])

        if item['name'] in local_users:
            if parent.template_id == local_users[item['name']].template_id:
                parent.stepChanged.emit(f'uGRAY|    Пользователь "{item["name"]}" уже существует в текущем шаблоне.')
            else:
                parent.stepChanged.emit(f'sGREEN|    Пользователь "{item["name"]}" уже существует в шаблоне "{local_users[item["name"]].template_name}".')
                continue
        else:
            err, result = parent.utm.add_template_user(parent.template_id, item)
            if err == 1:
                parent.stepChanged.emit(f'RED|    {result} [Пользователь "{item["name"]}" не импортирован]')
                error = 1
                continue
            elif err == 3:
                parent.stepChanged.emit(f'GRAY|    {result}.') # В версиях 6 и выше проверяется что пользователь уже существует.
            else:
                local_users[item['name']] = BaseObject(id=result, template_id=parent.template_id, template_name=parent.templates[parent.template_id])
                parent.stepChanged.emit(f'BLACK|    Локальный пользователь "{item["name"]}" импортирован.')

        # Добавляем пользователя в группу.
        for group in user_groups:
            try:
                group_guid = parent.mc_data['local_groups'][group].id
            except KeyError as err:
                parent.stepChanged.emit(f'bRED|       Не найдена группа {err} для пользователя {item["name"]}. Импортируйте список групп и повторите импорт пользователей.')
            else:
                err2, result2 = parent.utm.add_user_in_template_group(parent.template_id, group_guid, local_users[item['name']].id)
                if err2:
                    parent.stepChanged.emit(f'RED|       {result2}  [User "{item["name"]}" не добавлен в группу "{group}"]')
                    error = 1
                else:
                    parent.stepChanged.emit(f'BLACK|       Пользователь "{item["name"]}" добавлен в группу "{group}".')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте локальных пользователей.')
    else:
        parent.stepChanged.emit('GREEN|    Импорт локальных пользователей завершён.')


def import_auth_servers(parent, path):
    """Импортируем список серверов аутентификации"""
    parent.stepChanged.emit('BLUE|Импорт раздела "Пользователи и устройства/Серверы аутентификации".')

    if not parent.mc_data['auth_servers']:
        if get_auth_servers(parent):    # Устанавливаем parent.mc_data['auth_servers']
            parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте серверов аутентификации.')
            return
    auth_servers = parent.mc_data['auth_servers']

    import_ldap_servers(parent, path, auth_servers['ldap'])
    import_ntlm_server(parent, path, auth_servers['ntlm'])
    import_radius_server(parent, path, auth_servers['radius'])
    import_tacacs_server(parent, path, auth_servers['tacacs_plus'])
    import_saml_server(parent, path, auth_servers['saml_idp'])
    

def import_ldap_servers(parent, path, ldap_servers):
    """Импортируем список серверов LDAP"""
    json_file = os.path.join(path, 'config_ldap_servers.json')
    err, data = func.read_json_file(parent, json_file, mode=2)
    if err:
        return

    parent.stepChanged.emit('BLUE|    Импорт серверов LDAP в раздел "Пользователи и устройства/Серверы аутентификации".')
    parent.stepChanged.emit(f'LBLUE|       После импорта необходимо ввести пароль и импортировать keytab файл в LDAP-коннекторы.')
    error = 0

    for item in data:
        item['name'] = func.get_restricted_name(item['name'])
        if item['name'] in ldap_servers:
            if parent.template_id == ldap_servers[item['name']].template_id:
                parent.stepChanged.emit(f'uGRAY|       LDAP-сервер "{item["name"]}" уже существует в текущем шаблоне.')
            else:
                parent.stepChanged.emit(f'sGREEN|       LDAP-сервер "{item["name"]}" уже существует в шаблоне "{ldap_servers[item["name"]].template_name}".')
        else:
            item['keytab_exists'] = False
            item['type'] = 'ldap'
            item.pop("cc", None)
            err, result = parent.utm.add_template_auth_server(parent.template_id, item)
            if err:
                parent.stepChanged.emit(f'RED|       {result} [LDAP-сервер "{item["name"]}" не импортирован]')
                error = 1
            else:
                ldap_servers[item['name']] = BaseObject(id=result, template_id=parent.template_id, template_name=parent.templates[parent.template_id])
                parent.stepChanged.emit(f'BLACK|       Сервер аутентификации LDAP "{item["name"]}" импортирован.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте серверов LDAP.')
    else:
        parent.stepChanged.emit('GREEN|    Импорт серверов LDAP завершён.')


def import_ntlm_server(parent, path, ntlm_servers):
    """Импортируем список серверов NTLM"""
    json_file = os.path.join(path, 'config_ntlm_servers.json')
    err, data = func.read_json_file(parent, json_file, mode=2)
    if err:
        return

    parent.stepChanged.emit('BLUE|    Импорт серверов NTLM в раздел "Пользователи и устройства/Серверы аутентификации".')
    error = 0

    for item in data:
        item['name'] = func.get_restricted_name(item['name'])
        if item['name'] in ntlm_servers:
            if parent.template_id == ntlm_servers[item['name']].template_id:
                parent.stepChanged.emit(f'uGRAY|       NTLM-сервер "{item["name"]}" уже существует в текущем шаблоне.')
            else:
                parent.stepChanged.emit(f'sGREEN|       NTLM-сервер "{item["name"]}" уже существует в шаблоне "{ntlm_servers[item["name"]].template_name}".')
        else:
            item['type'] = 'ntlm'
            item.pop("cc", None)
            err, result = parent.utm.add_template_auth_server(parent.template_id, item)
            if err:
                parent.stepChanged.emit(f'RED|       {result} [NTLM-сервер "{item["name"]}" не импортирован]')
                error = 1
            else:
                ntlm_servers[item['name']] = BaseObject(id=result, template_id=parent.template_id, template_name=parent.templates[parent.template_id])
                parent.stepChanged.emit(f'BLACK|       Сервер аутентификации NTLM "{item["name"]}" импортирован.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте серверов NTLM.')
    else:
        parent.stepChanged.emit('GREEN|    Импорт серверов NTLM завершён.')


def import_radius_server(parent, path, radius_servers):
    """Импортируем список серверов RADIUS"""
    json_file = os.path.join(path, 'config_radius_servers.json')
    err, data = func.read_json_file(parent, json_file, mode=2)
    if err:
        return

    parent.stepChanged.emit('BLUE|    Импорт серверов RADIUS в раздел "Пользователи и устройства/Серверы аутентификации".')
    parent.stepChanged.emit(f'LBLUE|       После импорта необходимо в каждом сервере RADIUS ввести пароль.')
    error = 0

    for item in data:
        item['name'] = func.get_restricted_name(item['name'])
        if item['name'] in radius_servers:
            if parent.template_id == radius_servers[item['name']].template_id:
                parent.stepChanged.emit(f'uGRAY|       RADIUS-сервер "{item["name"]}" уже существует в текущем шаблоне.')
            else:
                parent.stepChanged.emit(f'sGREEN|       RADIUS-сервер "{item["name"]}" уже существует в шаблоне "{radius_servers[item["name"]].template_name}".')
        else:
            item['type'] = 'radius'
            item.pop("cc", None)
            err, result = parent.utm.add_template_auth_server(parent.template_id, item)
            if err:
                parent.stepChanged.emit(f'RED|       {result} [RADIUS-сервер "{item["name"]}" не импортирован]')
                error = 1
            else:
                radius_servers[item['name']] = BaseObject(id=result, template_id=parent.template_id, template_name=parent.templates[parent.template_id])
                parent.stepChanged.emit(f'BLACK|       Сервер аутентификации RADIUS "{item["name"]}" импортирован.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте серверов RADIUS.')
    else:
        parent.stepChanged.emit('GREEN|    Импорт серверов RADIUS завершён.')


def import_tacacs_server(parent, path, tacacs_servers):
    """Импортируем список серверов TACACS+"""
    json_file = os.path.join(path, 'config_tacacs_servers.json')
    err, data = func.read_json_file(parent, json_file, mode=2)
    if err:
        return

    parent.stepChanged.emit('BLUE|    Импорт серверов TACACS+ в раздел "Пользователи и устройства/Серверы аутентификации".')
    parent.stepChanged.emit(f'LBLUE|       После импорта необходимо в каждом сервере TACACS+ ввести секретный ключ.')
    error = 0

    for item in data:
        item['name'] = func.get_restricted_name(item['name'])
        if item['name'] in tacacs_servers:
            if parent.template_id == tacacs_servers[item['name']].template_id:
                parent.stepChanged.emit(f'uGRAY|       TACACS-сервер "{item["name"]}" уже существует в текущем шаблоне.')
            else:
                parent.stepChanged.emit(f'sGREEN|       TACACS-сервер "{item["name"]}" уже существует в шаблоне "{tacacs_servers[item["name"]].template_name}".')
        else:
            item['type'] = 'tacacs_plus'
            item.pop("cc", None)
            err, result = parent.utm.add_template_auth_server(parent.template_id, item)
            if err:
                parent.stepChanged.emit(f'RED|       {result} [Сервер TACACS+ "{item["name"]}" не импортирован]')
                error = 1
            else:
                tacacs_servers[item['name']] = BaseObject(id=result, template_id=parent.template_id, template_name=parent.templates[parent.template_id])
                parent.stepChanged.emit(f'BLACK|       Сервер аутентификации TACACS+ "{item["name"]}" импортирован.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте серверов TACACS+.')
    else:
        parent.stepChanged.emit('GREEN|    Импорт серверов TACACS+ завершён.')


def import_saml_server(parent, path, saml_servers):
    """Импортируем список серверов SAML"""
    json_file = os.path.join(path, 'config_saml_servers.json')
    err, data = func.read_json_file(parent, json_file, mode=2)
    if err:
        return

    parent.stepChanged.emit('BLUE|    Импорт серверов SAML в раздел "Пользователи и устройства/Серверы аутентификации".')
    parent.stepChanged.emit(f'LBLUE|       После импорта необходимо в каждый сервер SAML загрузить SAML metadata.')
    error = 0

    for item in data:
        item['name'] = func.get_restricted_name(item['name'])
        if item['name'] in saml_servers:
            if parent.template_id == saml_servers[item['name']].template_id:
                parent.stepChanged.emit(f'uGRAY|       SAML-сервер "{item["name"]}" уже существует в текущем шаблоне.')
            else:
                parent.stepChanged.emit(f'sGREEN|       SAML-сервер "{item["name"]}" уже существует в шаблоне "{saml_servers[item["name"]].template_name}".')
        else:
            item['type'] = 'saml_idp'
            item.pop("cc", None)
            if item['certificate_id']:
                try:
                    item['certificate_id'] = parent.mc_data['certs'][item['certificate_id']].id
                except KeyError:
                    parent.stepChanged.emit(f'RED|       Error [Сервер SAML "{item["name"]}"]. Не найден сертификат "{item["certificate_id"]}".')
                    item['certificate_id'] = 0
                    error = 1
            err, result = parent.utm.add_template_auth_server(parent.template_id, item)
            if err:
                parent.stepChanged.emit(f'RED|       {result} [Сервер SAML "{item["name"]}" не импортирован]')
                error = 1
            else:
                saml_servers[item['name']] = BaseObject(id=result, template_id=parent.template_id, template_name=parent.templates[parent.template_id])
                parent.stepChanged.emit(f'BLACK|       Сервер аутентификации SAML "{item["name"]}" импортирован.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте серверов SAML.')
    else:
        parent.stepChanged.emit('GREEN|    Импорт серверов SAML завершён.')


def import_2fa_profiles(parent, path):
    """Импортируем список 2FA профилей"""
    json_file = os.path.join(path, 'config_2fa_profiles.json')
    err, data = func.read_json_file(parent, json_file, mode=2)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт профилей MFA в раздел "Пользователи и устройства/Профили MFA".')
    error = 0

    if not parent.mc_data['notification_profiles']:
        if get_notification_profiles(parent):      # Устанавливаем parent.mc_data['notification_profiles']
            parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей MFA.')
            return
    notification_profiles = parent.mc_data['notification_profiles']

    if not parent.mc_data['profiles_2fa']:
        if get_profiles_2fa(parent):      # Устанавливаем parent.mc_data['profiles_2fa']
            parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей MFA.')
            return
    profiles_2fa = parent.mc_data['profiles_2fa']

    for item in data:
        item['name'] = func.get_restricted_name(item['name'])
        if item['name'] in profiles_2fa:
            if parent.template_id == profiles_2fa[item['name']].template_id:
                parent.stepChanged.emit(f'uGRAY|    Профиль MFA "{item["name"]}" уже существует в текущем шаблоне.')
            else:
                parent.stepChanged.emit(f'sGREEN|    Профиль MFA "{item["name"]}" уже существует в шаблоне "{profiles_2fa[item["name"]].template_name}".')
        else:
            if item['type'] == 'totp':
                if item['init_notification_profile_id'] not in notification_profiles:
                    parent.stepChanged.emit(f'RED|    Error: Профиль MFA "{item["name"]}" не добавлен. Не найден профиль оповещения "{item["init_notification_profile_id"]}". Загрузите профили оповещения и повторите попытку.')
                    error = 1
                    continue
                item['init_notification_profile_id'] = notification_profiles[item['init_notification_profile_id']].id
            else:
                if item['auth_notification_profile_id'] not in notification_profiles:
                    parent.stepChanged.emit(f'RED|    Error: Профиль MFA "{item["name"]}" не добавлен. Не найден профиль оповещения "{item["auth_notification_profile_id"]}". Загрузите профили оповещения и повторите попытку.')
                    error = 1
                    continue
                item['auth_notification_profile_id'] = notification_profiles[item['auth_notification_profile_id']].id

            err, result = parent.utm.add_template_2fa_profile(parent.template_id, item)
            if err:
                parent.stepChanged.emit(f'RED|    {result}  [Профиль MFA "{item["name"]}" не импортирован]')
                error = 1
            else:
                profiles_2fa[item['name']] = BaseObject(id=result, template_id=parent.template_id, template_name=parent.templates[parent.template_id])
                parent.stepChanged.emit(f'BLACK|    Профиль MFA "{item["name"]}" импортирован.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей MFA.')
    else:
        parent.stepChanged.emit('GREEN|    Импорт профилей MFA завершён.')


def import_auth_profiles(parent, path):
    """Импортируем список профилей аутентификации"""
    json_file = os.path.join(path, 'config_auth_profiles.json')
    err, data = func.read_json_file(parent, json_file, mode=2)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт профилей аутентификации в раздел "Пользователи и устройства/Профили аутентификации".')
    error = 0

    if not parent.mc_data['auth_servers']:
        if get_auth_servers(parent):    # Устанавливаем parent.mc_data['auth_servers']
            parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей аутентификации.')
            return
    auth_servers = parent.mc_data['auth_servers']

    if not parent.mc_data['profiles_2fa']:
        if get_profiles_2fa(parent):      # Устанавливаем parent.mc_data['profiles_2fa']
            parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей аутентификации.')
            return
    profiles_2fa = parent.mc_data['profiles_2fa']

    auth_profiles = parent.mc_data['auth_profiles']
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
                item['2fa_profile_id'] = profiles_2fa[item['2fa_profile_id']].id
            except KeyError:
                parent.stepChanged.emit(f'RED|    Error [Профиль аутентификации "{item["name"]}"]. Не найден профиль MFA "{item["2fa_profile_id"]}". Загрузите профили MFA и повторите попытку.')
                item['2fa_profile_id'] = False
                error = 1

        for auth_method in item['allowed_auth_methods']:
            if len(auth_method) == 2:
                method_type = auth_method['type']
                method_server_id = auth_type[method_type]
                try:
                    auth_method[method_server_id] = auth_servers[method_type][auth_method[method_server_id]].id
                except KeyError:
                    parent.stepChanged.emit(f'RED|    Error [Профиль аутентификации "{item["name"]}"]. Не найден сервер аутентификации "{auth_method[method_server_id]}". Загрузите серверы аутентификации и повторите попытку.')
                    auth_method.clear()
                    error = 1
        item['allowed_auth_methods'] = [x for x in item['allowed_auth_methods'] if x]

        if item['name'] in auth_profiles:
            if parent.template_id == auth_profiles[item['name']].template_id:
                parent.stepChanged.emit(f'uGRAY|    Профиль аутентификации "{item["name"]}" уже существует в текущем шаблоне.')
                err, result = parent.utm.update_template_auth_profile(parent.template_id, auth_profiles[item['name']].id, item)
                if err:
                    parent.stepChanged.emit(f'RED|       {result}  [Profile: "{item["name"]}"]')
                    error = 1
                else:
                    parent.stepChanged.emit(f'uGRAY|       Профиль аутентификации "{item["name"]}" обновлён.')
            else:
                parent.stepChanged.emit(f'sGREEN|    Профиль аутентификации "{item["name"]}" уже существует в шаблоне "{auth_profiles[item["name"]].template_name}".')
        else:
            err, result = parent.utm.add_template_auth_profile(parent.template_id, item)
            if err:
                parent.stepChanged.emit(f'RED|    {result} [Профиль аутентификации "{item["name"]}" не импортирован]')
                error = 1
            else:
                auth_profiles[item['name']] = BaseObject(id=result, template_id=parent.template_id, template_name=parent.templates[parent.template_id])
                parent.stepChanged.emit(f'BLACK|    Профиль аутентификации "{item["name"]}" импортирован.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей аутентификации.')
    else:
        parent.stepChanged.emit('GREEN|    Импорт профилей аутентификации завершён.')


def import_captive_profiles(parent, path):
    """Импортируем список Captive-профилей"""
    json_file = os.path.join(path, 'config_captive_profiles.json')
    err, data = func.read_json_file(parent, json_file, mode=2)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт Captive-профилей в раздел "Пользователи и устройства/Captive-профили".')
    error = 0

    if not parent.mc_data['response_pages']:
        if get_response_pages(parent):              # Устанавливаем parent.mc_data['response_pages']
            parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте Captive-профилей.')
            return
    response_pages = parent.mc_data['response_pages']

    if not parent.mc_data['notification_profiles']:
        if get_notification_profiles(parent):       # Устанавливаем parent.mc_data['notification_profiles']
            parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте Captive-профилей.')
            return
    notification_profiles = parent.mc_data['notification_profiles']

    if not parent.mc_data['client_certs_profiles']:
        if get_client_certificate_profiles(parent): # Устанавливаем parent.mc_data['client_certs_profiles']
            parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте Captive-профилей.')
            return
    client_certs_profiles = parent.mc_data['client_certs_profiles']

    if not parent.mc_data['captive_profiles']:
        if get_captive_profiles(parent):            # Устанавливаем parent.mc_data['captive_profiles']
            parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте Captive-профилей.')
            return
    captive_profiles = parent.mc_data['captive_profiles']

    for item in data:
        item['name'] = func.get_restricted_name(item['name'])
        item['captive_template_id'] = response_pages[item['captive_template_id']].id
        try:
            item['user_auth_profile_id'] = parent.mc_data['auth_profiles'][item['user_auth_profile_id']].id
        except KeyError:
            parent.stepChanged.emit(f'RED|    Error [Captive-profile "{item["name"]}"]. Не найден профиль аутентификации "{item["user_auth_profile_id"]}". Загрузите профили аутентификации и повторите попытку.')
            item['description'] = f'{item["description"]}\nError: Не найден профиль аутентификации "{item["user_auth_profile_id"]}".'
            item['user_auth_profile_id'] = 1
            error = 1

        if item['notification_profile_id'] != -1:
            try:
                item['notification_profile_id'] = notification_profiles[item['notification_profile_id']].id
            except KeyError:
                parent.stepChanged.emit(f'RED|    Error [Captive-profile "{item["name"]}"]. Не найден профиль оповещения "{item["notification_profile_id"]}". Загрузите профили оповещения и повторите попытку.')
                item['description'] = f'{item["description"]}\nError: Не найден профиль оповещения "{item["notification_profile_id"]}".'
                item['notification_profile_id'] = -1
                error = 1
        try:
            item['ta_groups'] = [parent.mc_data['local_groups'][name].id for name in item['ta_groups']]
        except KeyError as err:
            parent.stepChanged.emit(f'RED|    Error [Captive-profile "{item["name"]}"]. Группа гостевых пользователей {err} не найдена в группе шаблонов. Загрузите локальные группы и повторите попытку.')
            item['description'] = f'{item["description"]}\nError: Не найдена группа гостевых пользователей {err}.'
            item['ta_groups'] = []
            error = 1

        if item['ta_expiration_date']:
            item['ta_expiration_date'] = item['ta_expiration_date'].replace(' ', 'T')
        else:
            item.pop('ta_expiration_date', None)

        item.pop('use_https_auth', None)
        if item['captive_auth_mode'] != 'aaa':
            try:
                item['client_certificate_profile_id'] = client_certs_profiles[item['client_certificate_profile_id']].id
            except KeyError as err:
                parent.stepChanged.emit(f'RED|    Error [Captive-profile "{item["name"]}"]. Не найден профиль сертификата пользователя {err}. Загрузите профили сертификата пользователя и повторите попытку.')
                item['description'] = f'{item["description"]}\nError: Не найден профиль сертификата пользователя "{item["client_certificate_profile_id"]}".'
                item['captive_auth_mode'] = 'aaa'
                item['client_certificate_profile_id'] = 0
                error = 1

        if item['name'] in captive_profiles:
            if parent.template_id == captive_profiles[item['name']].template_id:
                parent.stepChanged.emit(f'uGRAY|    Captive-профиль "{item["name"]}" уже существует в текущем шаблоне.')
                err, result = parent.utm.update_template_captive_profile(parent.template_id, captive_profiles[item['name']].id, item)
                if err:
                    parent.stepChanged.emit(f'RED|       {result}  [Captive-profile "{item["name"]}"]')
                    error = 1
                else:
                    parent.stepChanged.emit(f'uGRAY|       Captive-профиль "{item["name"]}" обновлён.')
            else:
                parent.stepChanged.emit(f'sGREEN|    Captive-профиль "{item["name"]}" уже существует в шаблоне "{captive_profiles[item["name"]].template_name}".')
        else:
            err, result = parent.utm.add_template_captive_profile(parent.template_id, item)
            if err:
                parent.stepChanged.emit(f'RED|    {result}  [Captive-profile "{item["name"]}" не импортирован]')
                error = 1
            else:
                captive_profiles[item['name']] = BaseObject(id=result, template_id=parent.template_id, template_name=parent.templates[parent.template_id])
                parent.stepChanged.emit(f'BLACK|    Captive-профиль "{item["name"]}" импортирован.')

    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте Captive-профилей.')
    else:
        parent.stepChanged.emit('GREEN|    Импорт Captive-профилей завершён.')


def import_captive_portal_rules(parent, path):
    """Импортируем список правил Captive-портала"""
    json_file = os.path.join(path, 'config_captive_portal_rules.json')
    err, data = func.read_json_file(parent, json_file, mode=2)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт правил Captive-портала в раздел "Пользователи и устройства/Captive-портал".')
    error = 0

    if not parent.mc_data['captive_profiles']:
        if get_captive_profiles(parent):            # Устанавливаем parent.mc_data['captive_profiles']
            parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил Captive-портала.')
            return
    captive_profiles = parent.mc_data['captive_profiles']

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
                item['profile_id'] = captive_profiles[item['profile_id']].id
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

        if item.pop('error', False):
            item['enabled'] = False
            error = 1

        if item['name'] in captive_portal_rules:
            parent.stepChanged.emit(f'uGRAY|    Правило Captive-портала "{item["name"]}" уже существует в текущем шаблоне.')
            err, result = parent.utm.update_template_captive_portal_rule(parent.template_id, captive_portal_rules[item['name']], item)
            if err:
                parent.stepChanged.emit(f'RED|       {result}  [Captive-portal "{item["name"]}"]')
                error = 1
            else:
                parent.stepChanged.emit(f'uGRAY|       Правило Captive-портала "{item["name"]}" обновлено.')
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
        parent.stepChanged.emit('GREEN|    Импорт правил Captive-портала завершён.')


def import_terminal_servers(parent, path):
    """Импортируем список терминальных серверов"""
    json_file = os.path.join(path, 'config_terminal_servers.json')
    err, data = func.read_json_file(parent, json_file, mode=2)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт списка терминальных серверов в раздел "Пользователи и устройства/Терминальные серверы".')
    error = 0
    terminal_servers = {}
    for uid, name in parent.templates.items():
        err, result = parent.utm.get_template_terminal_servers(uid)
        if err:
            parent.stepChanged.emit(f'RED|    {result}')
            parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте списка терминальных серверов.')
            parent.error = 1
            return
        for x in result:
            if x['name'] in terminal_servers:
                parent.stepChanged.emit('ORANGE|    Терминальный сервер обнаружен в нескольких шаблонах группы. Сервер из шаблона "{name}" не будет использован.')
            else:
                terminal_servers[x['name']] = BaseObject(id=x['id'], template_id=uid, template_name=name)

    for item in data:
        item['name'] = func.get_restricted_name(item['name'])
        if item['name'] in terminal_servers:
            if parent.template_id == terminal_servers[item['name']].template_id:
                parent.stepChanged.emit(f'uGRAY|    Терминальный сервер "{item["name"]}" уже существует в текущем шаблоне.')
                err, result = parent.utm.update_template_terminal_server(parent.template_id, terminal_servers[item['name']].id, item)
                if err:
                    parent.stepChanged.emit(f'RED|       {result}  [Terminal Server "{item["name"]}"]')
                    error = 1
                else:
                    parent.stepChanged.emit(f'uGRAY|       Терминальный сервер "{item["name"]}" обновлён.')
            else:
                parent.stepChanged.emit(f'sGREEN|    Терминальный сервер "{item["name"]}" уже существует в шаблоне "{terminal_servers[item["name"]].template_name}".')
        else:
            err, result = parent.utm.add_template_terminal_server(parent.template_id, item)
            if err:
                parent.stepChanged.emit(f'RED|    {result}  [Terminal Server "{item["name"]}" не импортирован]')
                error = 1
            else:
                terminal_servers[item['name']] = BaseObject(id=result, template_id=parent.template_id, template_name=parent.templates[parent.template_id])
                parent.stepChanged.emit(f'BLACK|    Терминальный сервер "{item["name"]}" импортирован.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте терминальных серверов.')
    else:
        parent.stepChanged.emit('GREEN|    Импорт терминальных серверов завершён.')


def import_userid_agent(parent, path):
    """Импортируем настройки UserID агент"""
    if parent.utm.float_version in (7.1, 8.0):
        import_agent_config_old_version(parent, path)
        import_agent_servers_old(parent, path)
    else:
        import_agent_config(parent, path)
        import_agent_servers(parent, path)


def import_agent_config_old_version(parent, path):
    """Импортируем настройки UserID агент (для версий МС 7.1 и 8.0)"""
    json_file = os.path.join(path, 'userid_agent_config.json')
    err, result = func.read_json_file(parent, json_file, mode=2)
    if err:
        return

    error = 0
    parent.stepChanged.emit('BLUE|Импорт свойств агента UserID в раздел "Пользователи и устройства/Агент UserID".')
    parent.stepChanged.emit(f'NOTE|    В МС версии {parent.utm.float_version} не возможно указать сертификаты для TCP.')

    try:
        data = result[0]
    except Exception:
        parent.stepChanged.emit(f'RED|    Error: Произошла ошибка при импорте свойств агента UserID. Ошибка формата файла конфигурации.')
        parent.error = 1
        return

    data.pop('tcp_ca_certificate_id', None)
    data.pop('tcp_server_certificate_id', None)
    data.pop('radius_monitoring_interval', None)
    data['tcp_secure'] = False
    data['expiration_time'] = 2700

    new_networks = []
    for x in data['ignore_networks']:
        try:
            new_networks.append(['list_id', parent.mc_data['ip_lists'][x[1]].id])
        except KeyError as err:
            parent.stepChanged.emit(f'RED|    Error: Не найден список IP-адресов {err} для Ignore Networks. Загрузите списки IP-адресов и повторите попытку.')
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


def import_agent_config(parent, path):
    """Импортируем настройки UserID агент"""
    json_file = os.path.join(path, 'userid_agent_config.json')
    err, config_data = func.read_json_file(parent, json_file, mode=2)
    if err:
        return

    json_file = os.path.join(parent.config_path, 'version.json')
    err, source_version = func.read_json_file(parent, json_file, mode=2)
    if err:
        if err == 1:
            parent.stepChanged.emit(f'RED|Проблема с файлом {json_file} при импорте свойств агента UserID.')
            parent.stepChanged.emit(source_version)
            return
        source_version = {'device': 'NGFW', 'float_version': 7.1}

    parent.stepChanged.emit('BLUE|Импорт свойств агента UserID в раздел "Пользователи и устройства/Агент UserID".')
    error = 0
        
    useridagent_config = {}
    for uid, name in parent.templates.items():
        err, result = parent.utm.get_template_useridagent_config(uid)
        if err:
            parent.stepChanged.emit('RED|    {result}')
            parent.stepChanged.emit('ORANGE|       Произошла ошибка при импорте свойств агента UserID.')
            parent.error = 1
            return
        for x in result:
            if x['name'] in useridagent_config:
                parent.stepChanged.emit('ORANGE|    Свойство агента UserID для узла кластера "{x["name"]}" обнаружено в нескольких шаблонах группы шаблонов. Свойство из шаблона "{name}" не будет использовано.')
            else:
                useridagent_config[x['name']] = BaseObject(id=x['id'], template_id=uid, template_name=name)

    if source_version['device'] == 'MC' and source_version['float_version'] == 7.2:
        for data in config_data:
            error = set_useridagent_config(parent, data, useridagent_config)
    else:
        try:
            data = config_data[0]
        except Exception:
            parent.stepChanged.emit(f'RED|    Error: Произошла ошибка при импорте свойств агента UserID. Ошибка файла конфигурации.')
            parent.error = 1
            return
        data['name'] = parent.node_name
        error = set_useridagent_config(parent, data, useridagent_config)

    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте свойств агента UserID.')
    else:
        parent.stepChanged.emit('GREEN|    Импорт свойств агента UserID завершён.')


def set_useridagent_config(parent, data, useridagent_config):
    error = 0
    if data['tcp_ca_certificate_id']:
        try:
            data['tcp_ca_certificate_id'] = parent.mc_data['certs'][data['tcp_ca_certificate_id']].id
        except KeyError as err:
            parent.stepChanged.emit(f'RED|    Error: Не найден сертификат {err}. Загрузите сертификаты и повторите попытку.')
            data.pop('tcp_ca_certificate_id', None)
            error = 1
    else:
        data.pop('tcp_ca_certificate_id', None)

    if data['tcp_server_certificate_id']:
        try:
            data['tcp_server_certificate_id'] = parent.mc_data['certs'][data['tcp_server_certificate_id']].id
        except KeyError as err:
            parent.stepChanged.emit(f'RED|    Error: Не найден сертификат УЦ "{err}". Загрузите сертификаты и повторите попытку.')
            data.pop('tcp_server_certificate_id', None)
            error = 1
    else:
        data.pop('tcp_server_certificate_id', None)

    new_networks = []
    for x in data['ignore_networks']:
        try:
            new_networks.append(['list_id', parent.mc_data['ip_lists'][x[1]].id])
        except KeyError as err:
            parent.stepChanged.emit(f'RED|    Error: Не найден список IP-адресов {err} для Ignore Networks. Загрузите списки IP-адресов и повторите попытку.')
            error = 1
    data['ignore_networks'] = new_networks

    if parent.node_name in useridagent_config:
        if parent.template_id == useridagent_config[parent.node_name].template_id:
            parent.stepChanged.emit(f'uGRAY|    Свойства агента UserID для узла "{parent.node_name}" уже существуют в текущем шаблоне.')
            err, result = parent.utm.update_template_useridagent_config(parent.template_id, useridagent_config[data['name']].id, data)
            if err:
                parent.stepChanged.emit(f'RED|       {result} [Свойства агента UserID не обновлены]')
                error = 1
            else:
                parent.stepChanged.emit(f'uGRAY|       Свойства агента UserID для узла "{parent.node_name}" обновлены')
        else:
            parent.stepChanged.emit(f'sGREEN|    Свойства агента UserID для узла "{parent.node_name}" уже существует в шаблоне "{useridagent_config[parent.node_name].template_name}".')
    else:
        err, result = parent.utm.set_template_useridagent_config(parent.template_id, data)
        if err:
            parent.stepChanged.emit(f'RED|    {result} [Свойства агента UserID не установлены]')
            error = 1
        else:
            useridagent_config[data['name']] = BaseObject(id=result, template_id=parent.template_id, template_name=parent.templates[parent.template_id])
            parent.stepChanged.emit(f'BLACK|    Свойства агента UserID для узла "{parent.node_name}" импортированы')
    return error


def import_agent_servers_old(parent, path):
    """Импортируем настройки AD и свойств отправителя syslog UserID агент (для версий МС 7.1 и 8.0)"""
    json_file = os.path.join(path, 'userid_agent_servers.json')
    err, data = func.read_json_file(parent, json_file, mode=2)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт Агент UserID в раздел "Пользователи и устройства/Агент UserID".')
    parent.stepChanged.emit(f'LBLUE|    Фильтры для коннеторов Syslog Агентов UserID в этой версии МС не переносятся. Необходимо добавить их руками.')
    error = 0

    useridagent_servers = {}
    for uid, name in parent.templates.items():
        err, result = parent.utm.get_template_useridagent_servers(uid)
        if err:
            parent.stepChanged.emit(f'RED|    {result}')
            parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте агентов UserID.')
            parent.error = 1
            return
        for x in result:
            if x['name'] in useridagent_servers:
                parent.stepChanged.emit(f'ORANGE|    Коннектор UserID агента "{x["name"]}" для узла "{x["node_name"]}" обнаружен в нескольких шаблонах группы шаблонов. Коннектор из шаблона "{name}" не будет использован.')
            else:
                useridagent_servers[x['name']] = BaseObject(id=x['id'], template_id=uid, template_name=name)

    for item in data:
        if item['type'] == 'radius':
            parent.stepChanged.emit(f'NOTE|    Warning: Коннектор UserID агент "{item["name"]}" не импортирован так как RADIUS поддерживается тоько в версии МС-7.2 и выше.')
            continue
        item.pop('expiration_time', None)
        item['name'] = func.get_restricted_name(item['name'])

        if item['name'] in useridagent_servers:
            if parent.template_id == useridagent_servers[item['name']].template_id:
                parent.stepChanged.emit(f'uGRAY|    Коннектор UserID агент "{item["name"]}" для узла "{parent.node_name}" уже существует в текущем шаблоне.')
            else:
                parent.stepChanged.emit(f'sGREEN|    Коннектор UserID агент "{item["name"]}" для узла "{parent.node_name}" уже существует в шаблоне "{useridagent_servers[item["name"]].template_name}".')
                continue
        try:
            item['auth_profile_id'] = parent.mc_data['auth_profiles'][item['auth_profile_id']].id
        except KeyError:
            parent.stepChanged.emit(f'RED|    Error [UserID агент "{item["name"]}"]. Не найден профиль аутентификации "{item["auth_profile_id"]}". Загрузите профили аутентификации и повторите попытку.')
            item['description'] = f'{item["description"]}\nError: Не найден профиль аутентификации "{item["auth_profile_id"]}".'
            item['auth_profile_id'] = 1
            error = 1
        if 'filters' in item:
            parent.stepChanged.emit(f'rNOTE|    Warning [UserID агент "{item["name"]}"]. Не импортированы Syslog фильтры. В вашей версии МС API для этого не работают.')
            for filter_name in item['filters']:
                item['description'] = f'{item["description"]}\nError: Не найден Syslog фильтр UserID агента "{filter_name}".'
            item['filters'] = []

        if item['name'] in useridagent_servers:
            err, result = parent.utm.update_template_useridagent_server(parent.template_id, useridagent_servers[item['name']].id, item)
            if err:
                parent.stepChanged.emit(f'RED|       {result}  [UserID агент "{item["name"]}" не обновлён]')
                error = 1
            else:
                parent.stepChanged.emit(f'uGRAY|       Коннектор UserID агент "{item["name"]}" для узла "{parent.node_name}" обновлён.')
        else:
            err, result = parent.utm.add_template_useridagent_server(parent.template_id, item)
            if err:
                parent.stepChanged.emit(f'RED|    {result}  [Коннектор UserID агент "{item["name"]}" для узла "{parent.node_name}" не импортирован]')
                error = 1
            else:
                useridagent_servers[item['name']] = BaseObject(id=result, template_id=parent.template_id, template_name=parent.templates[parent.template_id])
                parent.stepChanged.emit(f'BLACK|    Коннектор UserID агент "{item["name"]}" для узла "{parent.node_name}" импортирован.')
        if item['type'] == 'ad':
            parent.stepChanged.emit(f'LBLUE|       Необходимо указать пароль для этого коннектора Microsoft AD.')
        elif item['type'] == 'radius':
            parent.stepChanged.emit(f'LBLUE|       Необходимо указать секретный код для этого коннектора RADIUS.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте агентов UserID.')
    else:
        parent.stepChanged.emit('GREEN|    Импорт Агентов UserID завершён.')


def import_agent_servers(parent, path):
    """Импортируем коннекторы UserID агент"""
    json_file = os.path.join(path, 'userid_agent_servers.json')
    err, data = func.read_json_file(parent, json_file, mode=2)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт Агент UserID в раздел "Пользователи и устройства/Агент UserID".')
    parent.stepChanged.emit(f'LBLUE|    Фильтры для коннеторов Syslog Агентов UserID в этой версии МС не переносятся. Необходимо добавить их руками.')
    error = 0

# В версии 7.1 это не работает!!!!!!
#    err, result = parent.utm.get_template_useridagent_filters_list(parent.template_id)
#    if err:
#        parent.stepChanged.emit(f'RED|    {result}')
#        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте агентов UserID.')
#        parent.error = 1
#        return
#    useridagent_filters = {x['name']: x['id'] for x in result}

    useridagent_servers = {}
    for uid, name in parent.templates.items():
        err, result = parent.utm.get_template_useridagent_servers(uid)
        if err:
            parent.stepChanged.emit(f'RED|    {result}')
            parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте агентов UserID.')
            parent.error = 1
            return
        for x in result:
            srv_name = f'{x["name"]}:{x["node_name"]}'
            if srv_name in useridagent_servers:
                parent.stepChanged.emit(f'ORANGE|    Коннектор UserID агента "{x["name"]}" для узла "{x["node_name"]}" обнаружен в нескольких шаблонах группы шаблонов. Коннектор из шаблона "{name}" не будет использован.')
            else:
                useridagent_servers[srv_name] = BaseObject(id=x['id'], template_id=uid, template_name=name)

    for item in data:
        item['name'] = func.get_restricted_name(item['name'])
        item['node_name'] = parent.node_name
        srv_name = f'{item["name"]}:{parent.node_name}'
        if srv_name in useridagent_servers:
            if parent.template_id == useridagent_servers[srv_name].template_id:
                parent.stepChanged.emit(f'uGRAY|    Коннектор UserID агент "{item["name"]}" для узла "{parent.node_name}" уже существует в текущем шаблоне.')
            else:
                parent.stepChanged.emit(f'sGREEN|    Коннектор UserID агент "{item["name"]}" для узла "{parent.node_name}" уже существует в шаблоне "{useridagent_servers[srv_name].template_name}".')
                continue
        try:
            item['auth_profile_id'] = parent.mc_data['auth_profiles'][item['auth_profile_id']].id
        except KeyError:
            parent.stepChanged.emit(f'RED|    Error [UserID агент "{item["name"]}"]. Не найден профиль аутентификации "{item["auth_profile_id"]}". Загрузите профили аутентификации и повторите попытку.')
            item['description'] = f'{item["description"]}\nError: Не найден профиль аутентификации "{item["auth_profile_id"]}".'
            item['auth_profile_id'] = 1
            error = 1
        if 'filters' in item:
            new_filters = []
            parent.stepChanged.emit(f'rNOTE|    Warning [UserID агент "{item["name"]}"]. Не импортированы Syslog фильтры. В вашей версии МС API для этого не работает.')
            for filter_name in item['filters']:
                item['description'] = f'{item["description"]}\nError: Не найден Syslog фильтр UserID агента "{filter_name}".'
#                try:
#                    new_filters.append(useridagent_filters[filter_name])
#                except KeyError:
#                    parent.stepChanged.emit(f'RED|    Error [UserID агент "{item["name"]}"]. Не найден Syslog фильтр "{filter_name}". Загрузите фильтры UserID агента и повторите попытку.')
#                    item['description'] = f'{item["description"]}\nError: Не найден Syslog фильтр UserID агента "{filter_name}".'
#                    error = 1
            item['filters'] = new_filters

        if srv_name in useridagent_servers:
            err, result = parent.utm.update_template_useridagent_server(parent.template_id, useridagent_servers[srv_name].id, item)
            if err:
                parent.stepChanged.emit(f'RED|       {result}  [UserID агент "{item["name"]}" не обновлён]')
                error = 1
            else:
                parent.stepChanged.emit(f'uGRAY|       Коннектор UserID агент "{item["name"]}" для узла "{parent.node_name}" обновлён.')
        else:
            err, result = parent.utm.add_template_useridagent_server(parent.template_id, item)
            if err:
                parent.stepChanged.emit(f'RED|    {result}  [Коннектор UserID агент "{item["name"]}" для узла "{parent.node_name}" не импортирован]')
                error = 1
            else:
                useridagent_servers[srv_name] = BaseObject(id=result, template_id=parent.template_id, template_name=parent.templates[parent.template_id])
                parent.stepChanged.emit(f'BLACK|    Коннектор UserID агент "{item["name"]}" для узла "{parent.node_name}" импортирован.')
        if item['type'] == 'ad':
            parent.stepChanged.emit(f'LBLUE|       Необходимо указать пароль для этого коннектора Microsoft AD.')
        elif item['type'] == 'radius':
            parent.stepChanged.emit(f'LBLUE|       Необходимо указать секретный код для этого коннектора RADIUS.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте агентов UserID.')
    else:
        parent.stepChanged.emit('GREEN|    Импорт Агентов UserID завершён.')


#-------------------------------------- Политики сети ---------------------------------------------------------
def import_firewall_rules(parent, path):
    """Импортируем правила межсетевого экрана"""
    json_file = os.path.join(path, 'config_firewall_rules.json')
    err, data = func.read_json_file(parent, json_file, mode=2)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт правил межсетевого экрана в раздел "Политики сети/Межсетевой экран".')

    if not parent.mc_data['idps_profiles']:
        if get_idps_profiles(parent):            # Устанавливаем parent.mc_data['idps_profiles']
            parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил межсетевого экрана.')
            return
    idps_profiles = parent.mc_data['idps_profiles']

    if not parent.mc_data['l7_profiles']:
        if get_l7_profiles(parent):            # Устанавливаем parent.mc_data['l7_profiles']
            parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил межсетевого экрана.')
            return
    l7_profiles = parent.mc_data['l7_profiles']

    if not parent.mc_data['hip_profiles']:
        if get_hip_profiles(parent):            # Устанавливаем parent.mc_data['hip_profiles']
            parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил межсетевого экрана.')
            return
    hip_profiles = parent.mc_data['hip_profiles']

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
                item['scenario_rule_id'] = parent.mc_data['scenarios'][item['scenario_rule_id']].id
            except KeyError as err:
                parent.stepChanged.emit(f'RED|    Error [Правило "{item["name"]}"]. Не найден сценарий {err}. Загрузите сценарии и повторите попытку.')
                item['description'] = f'{item["description"]}\nError: Не найден сценарий {err}.'
                item['scenario_rule_id'] = False
                item['error'] = True
        if 'ips_profile' in item and item['ips_profile']:
            try:
                item['ips_profile'] = idps_profiles[item['ips_profile']].id
            except KeyError as err:
                parent.stepChanged.emit(f'RED|    Error [Правило "{item["name"]}"]: Не найден профиль СОВ {err}. Загрузите профили СОВ и повторите попытку.')
                item['description'] = f'{item["description"]}\nError: Не найден профиль СОВ {err}.'
                item['ips_profile'] = False
                item['error'] = True
        else:
            item['ips_profile'] = False
        if 'l7_profile' in item and item['l7_profile']:
            try:
                item['l7_profile'] = l7_profiles[item['l7_profile']].id
            except KeyError as err:
                parent.stepChanged.emit(f'RED|    Error [Правило "{item["name"]}"]: Не найден профиль приложений {err}. Загрузите профили приложений и повторите попытку.')
                item['description'] = f'{item["description"]}\nError: Не найден профиль приложений {err}.'
                item['l7_profile'] = False
                item['error'] = True
        else:
            item['l7_profile'] = False
        if 'hip_profiles' in item:
            new_hip_profiles = []
            for hip in item['hip_profiles']:
                try:
                    new_hip_profiles.append(hip_profiles[hip].id)
                except KeyError as err:
                    parent.stepChanged.emit(f'RED|    Error [Правило "{item["name"]}"]: Не найден профиль HIP {err}. Загрузите профили HIP и повторите попытку.')
                    item['description'] = f'{item["description"]}\nError: Не найден профиль HIP {err}.'
                    item['error'] = True
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

        if item.pop('error', False):
            item['enabled'] = False
            error = 1

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
        parent.stepChanged.emit('GREEN|    Импорт правил межсетевого экрана завершён.')


def import_nat_rules(parent, path):
    """Импортируем список правил NAT"""
    json_file = os.path.join(path, 'config_nat_rules.json')
    err, data = func.read_json_file(parent, json_file, mode=2)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт правил NAT в раздел "Политики сети/NAT и маршрутизация".')
    error = 0

    if not parent.mc_data['gateways']:
        if get_gateways_list(parent):            # Устанавливаем parent.mc_data['gateways']
            parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил NAT.')
            return
    mc_gateways = parent.mc_data['gateways']

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
        item['users'] = get_guids_users_and_groups(parent, item) if parent.mc_data['ldap_servers'] else []

        gateway_exist = False
        if item['action'] == 'route':
            for key in mc_gateways:
                gateway_name, node_name = key.split(':')
                if gateway_name == item['gateway']:
                    item['gateway'] = mc_gateways[key].id
                    parent.stepChanged.emit(f'rNOTE|    Для правила ПБР "{item["name"]}" установлен шлюз "{gateway_name}" для узла "{node_name}". Если нужен шлюз для другого узла, установите его вручную.')
                    gateway_exist = True
                    break
            if not gateway_exist:
                parent.stepChanged.emit(f'RED|    Error [Правило "{item["name"]}"]. Не найден шлюз "{item["gateway"]}" для правила ПБР в группе шаблонов.')
                item['description'] = f'{item["description"]}\nError: Не найден шлюз "{item["gateway"]}" для правила ПБР в группе шаблонов.'
                item['gateway'] = ''
                error = 1

        if item['scenario_rule_id']:
            try:
                item['scenario_rule_id'] = parent.mc_data['scenarios'][item['scenario_rule_id']].id
            except KeyError as err:
                parent.stepChanged.emit(f'RED|    Error [Правило "{item["name"]}"]: Не найден сценарий {err}. Загрузите сценарии и повторите попытку.')
                item['description'] = f'{item["description"]}\nError: Не найден сценарий {err}.'
                item['scenario_rule_id'] = False
                item['error'] = True
            
        if item.pop('error', False):
            item['enabled'] = False
            error = 1

        if item['name'] in nat_rules:
            parent.stepChanged.emit(f'uGRAY|    Правило "{item["name"]}" уже существует.')
            item.pop('position', None)
            err, result = parent.utm.update_template_traffic_rule(parent.template_id, nat_rules[item['name']], item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|       {result}  [Правило "{item["name"]}"]')
            else:
                parent.stepChanged.emit(f'uGRAY|       Правило "{item["name"]}" обновлено.')
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
        parent.stepChanged.emit('GREEN|    Импорт правил NAT завершён.')


def import_loadbalancing_rules(parent, path):
    """Импортируем правила балансировки нагрузки"""
    parent.stepChanged.emit('BLUE|Импорт правил балансировки нагрузки в раздел "Политики сети/Балансировка нагрузки".')
    err, result = parent.utm.get_template_loadbalancing_rules(parent.template_id)
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил балансировки нагрузки.')
        parent.error = 1
        return

    import_loadbalancing_tcpudp(parent, path, result)
    import_loadbalancing_icap(parent, path, result)
    import_loadbalancing_reverse(parent, path, result)


def import_loadbalancing_tcpudp(parent, path, balansing_servers):
    """Импортируем балансировщики TCP/UDP"""
    parent.stepChanged.emit('BLUE|    Импорт балансировщиков TCP/UDP.')
    json_file = os.path.join(path, 'config_loadbalancing_tcpudp.json')
    err, data = func.read_json_file(parent, json_file, mode=2)
    if err in (2, 3):
        parent.stepChanged.emit(f'GRAY|    Нет балансировщиков TCP/UDP для импорта.')
        return
    elif err == 1:
        return

    tcpudp_rules = {x['name']: x['id'] for x in balansing_servers if x['type'] == 'ipvs'}
    error = 0

    for item in data:
        item['src_zones'] = get_zones_id(parent, 'src', item['src_zones'], item)
        item['src_ips'] = get_ips_id(parent, 'src', item['src_ips'], item)
        item['type'] = 'ipvs'

        if item.pop('error', False):
            item['enabled'] = False
            error = 1

        item['name'] = func.get_restricted_name(item['name'])
        if item['name'] in tcpudp_rules:
            parent.stepChanged.emit(f'uGRAY|       Правило балансировки TCP/UDP "{item["name"]}" уже существует.')
            err, result = parent.utm.update_template_loadbalancing_rule(parent.template_id, tcpudp_rules[item['name']], item)
            if err:
                parent.stepChanged.emit(f'RED|          {result}  [Правило "{item["name"]}"]')
                error = 1
            else:
                parent.stepChanged.emit(f'uGRAY|          Правило балансировки TCP/UDP "{item["name"]}" обновлено.')
        else:
            err, result = parent.utm.add_template_loadbalancing_rule(parent.template_id, item)
            if err:
                parent.stepChanged.emit(f'RED|       {result}  [Правило "{item["name"]}" не импортировано]')
                error = 1
            else:
                tcpudp_rules[item['name']] = result
                parent.stepChanged.emit(f'BLACK|       Правило балансировки TCP/UDP "{item["name"]}" импортировано.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил балансировки TCP/UDP.')
    else:
        parent.stepChanged.emit('GREEN|    Импорт правил балансировки TCP/UDP завершён.')


def import_loadbalancing_icap(parent, path, balansing_servers):
    """Импортируем балансировщики ICAP"""
    parent.stepChanged.emit('BLUE|    Импорт балансировщиков ICAP.')
    json_file = os.path.join(path, 'config_loadbalancing_icap.json')
    err, data = func.read_json_file(parent, json_file, mode=2)
    if err in (2, 3):
        parent.stepChanged.emit(f'GRAY|    Нет балансировщиков ICAP для импорта.')
        return
    elif err == 1:
        return

    error = 0

    if not parent.mc_data['icap_servers']:
        if get_icap_servers(parent):            # Устанавливаем parent.mc_data['icap_servers']
            parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил балансировки ICAP.')
            return
    icap_servers = parent.mc_data['icap_servers']

    icap_loadbalancing = {x['name']: x['id'] for x in balansing_servers if x['type'] == 'icap'}

    for item in data:
        item['type'] = 'icap'
        new_profiles = []
        for profile in item['profiles']:
            try:
                new_profiles.append(icap_servers[profile].id)
            except KeyError as err:
                parent.stepChanged.emit(f'RED|       Error [Правило "{item["name"]}"]: Не найден сервер ICAP "{profile}" в группе шаблонов. Импортируйте серверы ICAP и повторите попытку.')
                item['description'] = f'{item["description"]}\nError: Не найден сервер ICAP "{profile}".'
                item['enabled'] = False
                error = 1
        item['profiles'] = new_profiles

        item['name'] = func.get_restricted_name(item['name'])
        if item['name'] in icap_loadbalancing:
            parent.stepChanged.emit(f'uGRAY|       Правило балансировки ICAP "{item["name"]}" уже существует.')
            err, result = parent.utm.update_template_loadbalancing_rule(parent.template_id, icap_loadbalancing[item['name']], item)
            if err:
                parent.stepChanged.emit(f'RED|          {result}  [Правило "{item["name"]}"]')
                error = 1
            else:
                parent.stepChanged.emit(f'uGRAY|          Правило балансировки ICAP "{item["name"]}" обновлено.')
        else:
            err, result = parent.utm.add_template_loadbalancing_rule(parent.template_id, item)
            if err:
                parent.stepChanged.emit(f'RED|       {result}  [Правило "{item["name"]}" не импортировано]')
                error = 1
            else:
                icap_loadbalancing[item['name']] = result
                parent.stepChanged.emit(f'BLACK|       Правило балансировки ICAP "{item["name"]}" импортировано.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил балансировки ICAP.')
    else:
        parent.stepChanged.emit('GREEN|    Импорт правил балансировки ICAP завершён.')


def import_loadbalancing_reverse(parent, path, balansing_servers):
    """Импортируем балансировщики reverse-proxy"""
    parent.stepChanged.emit('BLUE|    Импорт балансировщиков Reverse-proxy.')
    json_file = os.path.join(path, 'config_loadbalancing_reverse.json')
    err, data = func.read_json_file(parent, json_file, mode=2)
    if err in (2, 3):
        parent.stepChanged.emit(f'GRAY|    Нет балансировщиков Reverse-proxy для импорта.')
        return
    elif err == 1:
        return

    error = 0

    if not parent.mc_data['reverseproxy_servers']:
        if get_reverseproxy_servers(parent):            # Устанавливаем parent.mc_data['reverseproxy_servers']
            parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил балансировки Reverse-proxy.')
            return
    reverseproxy_servers = parent.mc_data['reverseproxy_servers']

    reverse_rules = {x['name']: x['id'] for x in balansing_servers if x['type'] == 'rp'}

    for item in data:
        item['type'] = 'rp'
        new_profiles = []
        for profile in item['profiles']:
            try:
                new_profiles.append(reverseproxy_servers[profile].id)
            except KeyError as err:
                parent.stepChanged.emit(f'RED|       Error [Правило "{item["name"]}"]. Не найден сервер reverse-proxy {err} в группе шаблонов. Загрузите серверы reverse-proxy и повторите попытку.')
                item['description'] = f'{item["description"]}\nError: Не найден сервер reverse-proxy {err}.'
                item['enabled'] = False
                error = 1
        item['profiles'] = new_profiles

        item['name'] = func.get_restricted_name(item['name'])
        if item['name'] in reverse_rules:
            parent.stepChanged.emit(f'uGRAY|       Правило балансировки reverse-proxy "{item["name"]}" уже существует.')
            err, result = parent.utm.update_template_loadbalancing_rule(parent.template_id, reverse_rules[item['name']], item)
            if err:
                parent.stepChanged.emit(f'RED|          {result}  [Правило "{item["name"]}"]')
                error = 1
            else:
                parent.stepChanged.emit(f'uGRAY|          Правило балансировки reverse-proxy "{item["name"]}" обновлено.')
        else:
            err, result = parent.utm.add_template_loadbalancing_rule(parent.template_id, item)
            if err:
                parent.stepChanged.emit(f'RED|       {result}  [Правило "{item["name"]}" не импортировано]')
                error = 1
            else:
                reverse_rules[item['name']] = result
                parent.stepChanged.emit(f'BLACK|       Правило балансировки reverse-proxy "{item["name"]}" импортировано.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил балансировки Reverse-proxy.')
    else:
        parent.stepChanged.emit('GREEN|    Импорт правил балансировки Reverse-proxy завершён.')


def import_shaper_rules(parent, path):
    """Импортируем список правил пропускной способности"""
    json_file = os.path.join(path, 'config_shaper_rules.json')
    err, data = func.read_json_file(parent, json_file, mode=2)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт правил пропускной способности в раздел "Политики сети/Пропускная способность".')
    error = 0

    if not parent.mc_data['shapers']:
        if get_shapers_list(parent):            # Устанавливаем parent.mc_data['shapers']
            parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил пропускной способности.')
            return

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
                item['scenario_rule_id'] = parent.mc_data['scenarios'][item['scenario_rule_id']].id
            except KeyError as err:
                parent.stepChanged.emit(f'RED|    Error [Правило "{item["name"]}"]. Не найден сценарий {err}. Загрузите сценарии и повторите попытку.')
                item['description'] = f'{item["description"]}\nError: Не найден сценарий {err}.'
                item['scenario_rule_id'] = False
                item['error'] = True
        item['src_zones'] = get_zones_id(parent, 'src', item['src_zones'], item)
        item['dst_zones'] = get_zones_id(parent, 'dst', item['dst_zones'], item)
        item['src_ips'] = get_ips_id(parent, 'src', item['src_ips'], item)
        item['dst_ips'] = get_ips_id(parent, 'dst', item['dst_ips'], item)
        item['services'] = get_services(parent, item['services'], item)
        item['users'] = get_guids_users_and_groups(parent, item) if parent.mc_data['ldap_servers'] else []
        item['apps'] = get_apps(parent, item)
        item['time_restrictions'] = get_time_restrictions(parent, item)
        try:
            item['pool'] = parent.mc_data['shapers'][item['pool']].id
        except KeyError as err:
            parent.stepChanged.emit(f'RED|    Error [Правило "{item["name"]}"]. Не найдена полоса пропускания "{item["pool"]}". Импортируйте полосы пропускания и повторите попытку.')
            item['description'] = f'{item["description"]}\nError: Не найдена полоса пропускания "{item["pool"]}".'
            item['error'] = True
            item['pool'] = 1

        if item.pop('error', False):
            item['enabled'] = False
            error = 1

        if item['name'] in shaper_rules:
            parent.stepChanged.emit(f'uGRAY|    Правило пропускной способности "{item["name"]}" уже существует.')
            item.pop('position', None)
            err, result = parent.utm.update_template_shaper_rule(parent.template_id, shaper_rules[item['name']], item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|       {result}  [Правило "{item["name"]}"]')
            else:
                parent.stepChanged.emit(f'uGRAY|       Правило пропускной способности "{item["name"]}" обновлено.')
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
        parent.stepChanged.emit('GREEN|    Импорт правил пропускной способности завершён.')

#-------------------------------------------- Политики безопасности --------------------------------------------------
def import_content_rules(parent, path):
    """Импортировать список правил фильтрации контента"""
    json_file = os.path.join(path, 'config_content_rules.json')
    err, data = func.read_json_file(parent, json_file, mode=2)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт правил фильтрации контента в раздел "Политики безопасности/Фильтрация контента".')
    error = 0

    if not parent.mc_data['response_pages']:
        if get_response_pages(parent):    # Устанавливаем parent.mc_data['response_pages']
            parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил контентной фильтрации.')
            return

    if not parent.mc_data['morphology']:
        if get_morphology_list(parent):    # Устанавливаем parent.mc_data['morphology']
            parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил контентной фильтрации.')
            return
    morphology_list = parent.mc_data['morphology']

    if not parent.mc_data['useragents']:
        if get_useragent_list(parent):    # Устанавливаем parent.mc_data['useragents']
            parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил контентной фильтрации.')
            return
    useragent_list = parent.mc_data['useragents']

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
            item['blockpage_template_id'] = parent.mc_data['response_pages'][item['blockpage_template_id']].id
        except KeyError as err:
            parent.stepChanged.emit(f'RED|    Error [Правило "{item["name"]}"]. Не найден шаблон страницы блокировки {err}. Импортируйте шаблоны страниц и повторите попытку.')
            item['description'] = f'{item["description"]}\nError: Не найден шаблон страницы блокировки {err}.'
            item['blockpage_template_id'] = -1
            item['error'] = True

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
                item['scenario_rule_id'] = parent.mc_data['scenarios'][item['scenario_rule_id']].id
            except KeyError as err:
                parent.stepChanged.emit(f'RED|    Error [Правило "{item["name"]}"]. Не найден сценарий {err}. Загрузите сценарии и повторите попытку.')
                item['description'] = f'{item["description"]}\nError: Не найден сценарий {err}.'
                item['scenario_rule_id'] = False
                item['error'] = True

        new_morph_categories = []
        for x in item['morph_categories']:
            if x in parent.mc_data['ug_morphology']:
                new_morph_categories.append(f'id-{x}')
            else:
                try:
                    new_morph_categories.append(morphology_list[x].id)
                except KeyError as err:
                    parent.stepChanged.emit(f'RED|    Error [Правило "{item["name"]}"]. Не найден список морфологии {err}. Загрузите списки морфологии и повторите попытку.')
                    item['description'] = f'{item["description"]}\nError: Не найден список морфологии {err}.'
                    item['error'] = True
        item['morph_categories'] = new_morph_categories

        new_user_agents = []
        for x in item['user_agents']:
            if x[1] in parent.mc_data['ug_useragents']:
                new_user_agents.append(['list_id', f'id-{x[1]}'])
            else:
                try:
                    new_user_agents.append(['list_id', useragent_list[x[1]].id])
                except KeyError as err:
                    parent.stepChanged.emit(f'RED|    Error [Правило "{item["name"]}"]. Не найден список UserAgent {err}. Загрузите списки UserAgent браузеров и повторите попытку.')
                    item['description'] = f'{item["description"]}\nError: Не найден список UserAgent {err}.'
                    item['error'] = True
        item['user_agents'] = new_user_agents

        new_content_types = []
        for x in item['content_types']:
            try:
                new_content_types.append(parent.mc_data['mime'][x].id)
            except KeyError as err:
                parent.stepChanged.emit(f'RED|    Error [Правило "{item["name"]}"]. Не найден список типов контента {err}. Загрузите списки типов контента и повторите попытку.')
                item['description'] = f'{item["description"]}\nError: Не найден список типов контента {err}.'
                item['error'] = True
        item['content_types'] = new_content_types

        if item.pop('error', False):
            item['enabled'] = False
            error = 1

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
                parent.stepChanged.emit(f'RED|    {result}  [Правило "{item["name"]}" не импортировано]')
            else:
                content_rules[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Правило контентной фильтрации "{item["name"]}" импортировано.')

    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил контентной фильтрации.')
    else:
        parent.stepChanged.emit('GREEN|    Импорт правил контентной фильтрации завершён.')


def import_safebrowsing_rules(parent, path):
    """Импортируем список правил веб-безопасности"""
    json_file = os.path.join(path, 'config_safebrowsing_rules.json')
    err, data = func.read_json_file(parent, json_file, mode=2)
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

        if item.pop('error', False):
            item['enabled'] = False
            error = 1

        if item['name'] in safebrowsing_rules:
            parent.stepChanged.emit(f'uGRAY|    Правило веб-безопасности "{item["name"]}" уже существует.')
            item.pop('position', None)
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
        parent.stepChanged.emit('GREEN|    Импорт правил веб-безопасности завершён.')


def import_tunnel_inspection_rules(parent, path):
    """Импортируем список правил инспектирования туннелей"""
    json_file = os.path.join(path, 'config_tunnelinspection_rules.json')
    err, data = func.read_json_file(parent, json_file, mode=2)
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

        if item.pop('error', False):
            item['enabled'] = False
            error = 1

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
        parent.stepChanged.emit('GREEN|    Импорт правил инспектирования туннелей завершён.')


def import_ssldecrypt_rules(parent, path):
    """Импортируем список правил инспектирования SSL"""
    json_file = os.path.join(path, 'config_ssldecrypt_rules.json')
    err, data = func.read_json_file(parent, json_file, mode=2)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт правил инспектирования SSL в раздел "Политики безопасности/Инспектирование SSL".')
    error = 0

    if not parent.mc_data['ssl_forward_profiles']:
        if get_ssl_forward_profiles(parent):    # Устанавливаем parent.mc_data['ssl_forward_profiles']
            parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил инспектирования SSL.')
            return
    ssl_forward_profiles = parent.mc_data['ssl_forward_profiles']

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
            item['ssl_profile_id'] = parent.mc_data['ssl_profiles'][item['ssl_profile_id']].id
        except KeyError as err:
            parent.stepChanged.emit(f'RED|    Error [Правило "{item["name"]}"]. Не найден профиль SSL {err}. Загрузите профили SSL и повторите импорт.')
            item['description'] = f'{item["description"]}\nError: Не найден профиль SSL {err}. Установлен Default SSL profile.'
            item['ssl_profile_id'] = parent.mc_data['ssl_profiles']['Default SSL profile'].id
            item['error'] = True
        try:
            item['ssl_forward_profile_id'] = ssl_forward_profiles[item['ssl_forward_profile_id']].id
        except KeyError as err:
            parent.stepChanged.emit(f'RED|    Error [Правило "{item["name"]}"]. Не найден профиль пересылки SSL {err}. Загрузите профили пересылки SSL и повторите импорт.')
            item['description'] = f'{item["description"]}\nError: Не найден профиль пересылки SSL {err}.'
            item['ssl_forward_profile_id'] = -1
            item['error'] = True

        if item.pop('error', False):
            item['enabled'] = False
            error = 1

        if item['name'] in ssldecrypt_rules:
            parent.stepChanged.emit(f'uGRAY|    Правило инспектирования SSL "{item["name"]}" уже существует.')
            err, result = parent.utm.update_template_ssldecrypt_rule(parent.template_id, ssldecrypt_rules[item['name']], item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|       {result}  [Правило инспектирования SSL "{item["name"]}"]')
            else:
                parent.stepChanged.emit(f'uGRAY|       Правило инспектирования SSL "{item["name"]}" обновлено.')
        else:
            item['position'] = 'last'
            err, result = parent.utm.add_template_ssldecrypt_rule(parent.template_id, item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Правило инспектирования SSL "{item["name"]}" не импортировано]')
            else:
                ssldecrypt_rules[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Правило инспектирования SSL "{item["name"]}" импортировано.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил инспектирования SSL.')
    else:
        parent.stepChanged.emit('GREEN|    Импорт правил инспектирования SSL завершён.')


def import_sshdecrypt_rules(parent, path):
    """Импортируем список правил инспектирования SSH"""
    json_file = os.path.join(path, 'config_sshdecrypt_rules.json')
    err, data = func.read_json_file(parent, json_file, mode=2)
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

        if item.pop('error', False):
            item['enabled'] = False
            error = 1

        if item['name'] in sshdecrypt_rules:
            parent.stepChanged.emit(f'uGRAY|    Правило инспектирования SSH "{item["name"]}" уже существует.')
            err, result = parent.utm.update_template_sshdecrypt_rule(parent.template_id, sshdecrypt_rules[item['name']], item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|       {result}  [Правило инспектирования SSH "{item["name"]}"]')
            else:
                parent.stepChanged.emit(f'uGRAY|       Правило инспектирования SSH "{item["name"]}" обновлено.')
        else:
            item['position'] = 'last'
            err, result = parent.utm.add_template_sshdecrypt_rule(parent.template_id, item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Правило инспектирования SSH "{item["name"]}" не импортировано]')
            else:
                sshdecrypt_rules[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Правило инспектирования SSH "{item["name"]}" импортировано.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил инспектирования SSH.')
    else:
        parent.stepChanged.emit('GREEN|    Импорт правил инспектирования SSH завершён.')


def import_mailsecurity(parent, path):
    import_mailsecurity_rules(parent, path)
    import_mailsecurity_antispam(parent, path)

def import_mailsecurity_rules(parent, path):
    """Импортируем список правил защиты почтового трафика"""
    json_file = os.path.join(path, 'config_mailsecurity_rules.json')
    err, data = func.read_json_file(parent, json_file, mode=2)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт правил защиты почтового трафика в раздел "Политики безопасности/Защита почтового трафика".')
    error = 0

    if not parent.mc_data['email_groups']:
        if get_email_groups(parent):    # Устанавливаем parent.mc_data['email_groups']
            parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил защиты почтового трафика.')
            return
    email = parent.mc_data['email_groups']

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
            item['envelope_from'] = [[x[0], email[x[1]].id] for x in item['envelope_from']]
        except KeyError as err:
            parent.stepChanged.emit(f'RED|    Error [Правило "{item["name"]}"]. Не найден список почтовых адресов {err}. Загрузите список почтовых адресов и повторите попытку.')
            item['description'] = f'{item["description"]}\nError: Не найден список почтовых адресов {err}.'
            item['envelope_from'] = []
            item['error'] = True

        try:
            item['envelope_to'] = [[x[0], email[x[1]].id] for x in item['envelope_to']]
        except KeyError as err:
            parent.stepChanged.emit(f'RED|    Error [Правило "{item["name"]}"]. Не найден список почтовых адресов {err}. Загрузите список почтовых адресов и повторите попытку.')
            item['description'] = f'{item["description"]}\nError: Не найден список почтовых адресов {err}.'
            item['envelope_to'] = []
            item['error'] = True

        if item.pop('error', False):
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
        parent.stepChanged.emit('GREEN|    Импорт правил защиты почтового трафика завершён.')


def import_mailsecurity_antispam(parent, path):
    """Импортируем dnsbl и batv защиты почтового трафика"""
    json_file = os.path.join(path, 'config_mailsecurity_dnsbl.json')
    err, data = func.read_json_file(parent, json_file, mode=2)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт настроек антиспама защиты почтового трафика в раздел "Политики безопасности/Защита почтового трафика".')

    json_file = os.path.join(path, 'config_mailsecurity_batv.json')
    err, batv = func.read_json_file(parent, json_file, mode=1)
    if err:
        data['enabled'] = False
        parent.stepChanged.emit('ORANGE|       В настройках антиспама BATV будет отключён.')
    else:
        data['enabled'] = batv['enabled']


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
    err, data = func.read_json_file(parent, json_file, mode=2)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт серверов ICAP в раздел "Политики безопасности/ICAP-серверы".')
    error = 0

    if not parent.mc_data['icap_servers']:
        if get_icap_servers(parent):      # Устанавливаем parent.mc_data['icap_servers']
            parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте серверов ICAP.')
            return
    icap_servers = parent.mc_data['icap_servers']

    for item in data:
        item['name'] = func.get_restricted_name(item['name'])
        if item['name'] in icap_servers:
            if parent.template_id == icap_servers[item['name']].template_id:
                parent.stepChanged.emit(f'uGRAY|    ICAP-сервер "{item["name"]}" уже существует в текущем шаблоне.')
                err, result = parent.utm.update_template_icap_server(parent.template_id, icap_servers[item['name']].id, item)
                if err:
                    parent.stepChanged.emit(f'RED|       {result}  [ICAP-сервер "{item["name"]}"]')
                    error = 1
                else:
                    parent.stepChanged.emit(f'uGRAY|       ICAP-сервер "{item["name"]}" обновлён.')
            else:
                parent.stepChanged.emit(f'sGREEN|    ICAP-сервер "{item["name"]}" уже существует в шаблоне "{icap_servers[item["name"]].template_name}".')
        else:
            item['position'] = 'last'
            err, result = parent.utm.add_template_icap_server(parent.template_id, item)
            if err:
                parent.stepChanged.emit(f'RED|    {result}  [ICAP-сервер "{item["name"]}" не импортирован]')
                error = 1
            else:
                icap_servers[item['name']] = BaseObject(id=result, template_id=parent.template_id, template_name=parent.templates[parent.template_id])
                parent.stepChanged.emit(f'BLACK|    ICAP-сервер "{item["name"]}" импортирован.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте серверов ICAP.')
    else:
        parent.stepChanged.emit('GREEN|    Импорт серверов ICAP завершён.')


def import_icap_rules(parent, path):
    """Импортируем список правил ICAP"""
    json_file = os.path.join(path, 'config_icap_rules.json')
    err, data = func.read_json_file(parent, json_file, mode=2)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт правил ICAP в раздел "Политики безопасности/ICAP-правила".')
    error = 0

    if not parent.mc_data['icap_servers']:
        if get_icap_servers(parent):      # Устанавливаем parent.mc_data['icap_servers']
            parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил ICAP.')
            return
    icap_servers = parent.mc_data['icap_servers']

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
                    item['error'] = True
            elif server[0] == 'profile':
                try:
                    new_servers.append(['profile', icap_servers[server[1]].id])
                except KeyError as err:
                    parent.stepChanged.emit(f'RED|    Error [Правило "{item["name"]}"]. Не найден сервер ICAP {err}. Импортируйте сервера ICAP и повторите попытку.')
                    item['description'] = f'{item["description"]}\nError: Не найден сервер ICAP {err}.'
                    item['error'] = True
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
                new_content_types.append(parent.mc_data['mime'][x].id)
            except KeyError as err:
                parent.stepChanged.emit(f'RED|    Error [Правило "{item["name"]}"]: Не найден список типов контента {err}. Загрузите списки типов контента и повторите попытку.')
                item['description'] = f'{item["description"]}\nError: Не найден список типов контента {err}.'
                item['error'] = True
        item['content_types'] = new_content_types

        if item.pop('error', False):
            item['enabled'] = False
            error = 1

        if item['name'] in icap_rules:
            parent.stepChanged.emit(f'uGRAY|    ICAP-правило "{item["name"]}" уже существует.')
            err, result = parent.utm.update_template_icap_rule(parent.template_id, icap_rules[item['name']], item)
            if err:
                parent.stepChanged.emit(f'RED|       {result}  [ICAP-правило "{item["name"]}"]')
                error = 1
            else:
                parent.stepChanged.emit(f'uGRAY|       ICAP-правило "{item["name"]}" обновлено.')
        else:
            item['position'] = 'last'
            err, result = parent.utm.add_template_icap_rule(parent.template_id, item)
            if err:
                parent.stepChanged.emit(f'RED|    {result}  [ICAP-правило "{item["name"]}" не импортировано]')
                error = 1
            else:
                icap_rules[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    ICAP-правило "{item["name"]}" импортировано.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил ICAP.')
    else:
        parent.stepChanged.emit('GREEN|    Импорт правил ICAP завершён.')


def import_dos_profiles(parent, path):
    """Импортируем список профилей DoS"""
    json_file = os.path.join(path, 'config_dos_profiles.json')
    err, data = func.read_json_file(parent, json_file, mode=2)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт профилей DoS в раздел "Политики безопасности/Профили DoS".')
    error = 0

    if not parent.mc_data['dos_profiles']:
        if get_dos_profiles(parent):      # Устанавливаем parent.mc_data['dos_profiles']
            parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей DoS.')
            return
    dos_profiles = parent.mc_data['dos_profiles']

    for item in data:
        item['name'] = func.get_restricted_name(item['name'])
        if item['name'] in dos_profiles:
            if parent.template_id == dos_profiles[item['name']].template_id:
                parent.stepChanged.emit(f'uGRAY|    Профиль DoS "{item["name"]}" уже существует в текущем шаблоне.')
                err, result = parent.utm.update_template_dos_profile(parent.template_id, dos_profiles[item['name']].id, item)
                if err:
                    parent.stepChanged.emit(f'RED|       {result}  [Профиль DoS "{item["name"]}"]')
                    error = 1
                else:
                    parent.stepChanged.emit(f'uGRAY|       Профиль DoS "{item["name"]}" обновлён.')
            else:
                parent.stepChanged.emit(f'sGREEN|    Профиль DoS "{item["name"]}" уже существует в шаблоне "{dos_profiles[item["name"]].template_name}".')
        else:
            err, result = parent.utm.add_template_dos_profile(parent.template_id, item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Профиль DoS "{item["name"]}" не импортирован]')
            else:
                dos_profiles[item['name']] = BaseObject(id=result, template_id=parent.template_id, template_name=parent.templates[parent.template_id])
                parent.stepChanged.emit(f'BLACK|    Профиль DoS "{item["name"]}" импортирован.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей DoS.')
    else:
        parent.stepChanged.emit('GREEN|    Импорт профилей DoS завершён.')


def import_dos_rules(parent, path):
    """Импортируем список правил защиты DoS"""
    json_file = os.path.join(path, 'config_dos_rules.json')
    err, data = func.read_json_file(parent, json_file, mode=2)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт правил защиты DoS в раздел "Политики безопасности/Правила защиты DoS".')
    error = 0

    if not parent.mc_data['dos_profiles']:
        if get_dos_profiles(parent):      # Устанавливаем parent.mc_data['dos_profiles']
            parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей DoS.')
            return
    dos_profiles = parent.mc_data['dos_profiles']

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
                item['dos_profile'] = dos_profiles[item['dos_profile']].id
            except KeyError as err:
                parent.stepChanged.emit(f'RED|    Error [Правило "{item["name"]}"]. Не найден профиль DoS {err}. Импортируйте профили DoS и повторите попытку.')
                item['description'] = f'{item["description"]}\nError: Не найден профиль DoS {err}.'
                item['dos_profile'] = False
                item['error'] = True
        if item['scenario_rule_id']:
            try:
                item['scenario_rule_id'] = parent.mc_data['scenarios'][item['scenario_rule_id']].id
            except KeyError as err:
                parent.stepChanged.emit(f'RED|    Error [Правило "{item["name"]}"]. Не найден сценарий {err}. Импортируйте сценарии и повторите попытку.')
                item['description'] = f'{item["description"]}\nError: Не найден сценарий {err}.'
                item['scenario_rule_id'] = False
                item['error'] = True

        if item.pop('error', False):
            item['enabled'] = False
            error = 1

        if item['name'] in dos_rules:
            parent.stepChanged.emit(f'uGRAY|    Правило защиты DoS "{item["name"]}" уже существует.')
            err, result = parent.utm.update_template_dos_rule(parent.template_id, dos_rules[item['name']], item)
            if err:
                parent.stepChanged.emit(f'RED|       {result}  [Правило защиты DoS "{item["name"]}"]')
                error = 1
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
        parent.stepChanged.emit('GREEN|    Импорт правил защиты DoS завершён.')


#-------------------------------------------------- WAF ----------------------------------------------------------
def import_waf_custom_layers(parent, path):
    """Импортируем Персональные слои WAF"""
    json_file = os.path.join(path, 'config_waf_custom_layers.json')
    err, data = func.read_json_file(parent, json_file, mode=2)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт персональных слоёв в раздел "WAF/Персональные слои".')
    error = 0

    if not parent.waf_custom_layers:
        if get_waf_custom_layers(parent):      # Устанавливаем атрибут parent.waf_custom_layers
            parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте персональных слоёв WAF.')
            return

    for item in data:
        item['name'] = func.get_restricted_name(item['name'])
        if item['name'] in parent.waf_custom_layers:
            parent.stepChanged.emit(f'uGRAY|    Персональный слой "{item["name"]}" уже существует в текущем шаблоне.')
            err, result = parent.utm.update_template_waf_custom_layer(parent.template_id, parent.waf_custom_layers[item['name']], item)
            if err:
                parent.stepChanged.emit(f'RED|       {result}  [Персональный слой "{item["name"]}"]')
                error = 1
            else:
                parent.stepChanged.emit(f'uGRAY|       Персональный слой "{item["name"]}" обновлён.')
        else:
            err, result = parent.utm.add_template_waf_custom_layer(parent.template_id, item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Персональный слой "{item["name"]}" не импортирован]')
            else:
                parent.waf_custom_layers[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Персональный слой "{item["name"]}" импортирован.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте персональных слоёв WAF.')
    else:
        parent.stepChanged.emit('GREEN|    Импорт персональных слоёв WAF завершён.')


def import_waf_profiles(parent, path):
    """Импортируем профили WAF"""
    json_file = os.path.join(path, 'config_waf_profiles.json')
    err, data = func.read_json_file(parent, json_file, mode=2)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт профилей WAF в раздел "WAF/Профили".')
    error = 0

    err, result = parent.utm.get_waf_technology_list()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей WAF.')
        parent.error = 1
        return
    waf_technology = {x['name']: x['id'] for x in result}

    if not parent.waf_custom_layers:
        if get_waf_custom_layers(parent):      # Устанавливаем атрибут parent.waf_custom_layers
            parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей WAF.')
            return

    err, result = parent.utm.get_template_waf_system_layers(parent.template_id)
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей WAF.')
        parent.error = 1
        return
    waf_system_layers = {x['name']: x['id'] for x in result}

    if not parent.mc_data['waf_profiles']:
        if get_waf_profiles(parent): # Устанавливаем parent.mc_data['waf_profiles']
            parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей WAF.')
            return
    waf_profiles = parent.mc_data['waf_profiles']

    for item in data:
        item['name'] = func.get_restricted_name(item['name'])
        if item['name'] in waf_profiles and parent.template_id != waf_profiles[item['name']].template_id:
            parent.stepChanged.emit(f'sGREEN|    Профиль WAF "{item["name"]}" уже существует в шаблоне "{waf_profiles[item["name"]].template_name}".')
            continue

        rule_layers = []
        for layer in item['layers']:
            if layer['type'] == 'custom_layer':
                try:
                    layer['id'] = parent.waf_custom_layers[layer['id']]
                    rule_layers.append(layer)
                except KeyError as err:
                    parent.stepChanged.emit(f'RED|    Error [Профиль "{item["name"]}"]. Не найден персональный слой "{layer["id"]}".')
                    item['description'] = f'{item["description"]}\nError: Не найден персональный слой "{layer["id"]}"'
                    error = 1
            else:
                protection_technologies = []
                for x in layer['protection_technologies']:
                    try:
                        protection_technologies.append(waf_technology[x])
                    except KeyError as err:
                        parent.stepChanged.emit(f'RED|    Error [Профиль "{item["name"]}"]. В слое "{layer["id"]}" обнаружена не существующая технология защиты {err}.')
                        item['description'] = f'{item["description"]}\nError: В слое "{layer["id"]}" обнаружена не существующая технология защиты {err}.'
                        error = 1
                layer['protection_technologies'] = protection_technologies
                layer['id'] = waf_system_layers[layer['id']]
                rule_layers.append(layer)
        item['layers'] = rule_layers

        if item['name'] in waf_profiles:
            if parent.template_id == waf_profiles[item['name']].template_id:
                parent.stepChanged.emit(f'uGRAY|    Профиль WAF "{item["name"]}" уже существует в текущем шаблоне.')
                err, result = parent.utm.update_template_waf_profile(parent.template_id, waf_profiles[item['name']].id, item)
                if err:
                    parent.stepChanged.emit(f'RED|       {result}  [Профиль WAF "{item["name"]}"]')
                    error = 1
                else:
                    parent.stepChanged.emit(f'uGRAY|       Профиль WAF "{item["name"]}" обновлён.')
        else:
            err, result = parent.utm.add_template_waf_profile(parent.template_id, item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Профиль WAF "{item["name"]}" не импортирован]')
            else:
                waf_profiles[item['name']] = BaseObject(id=result, template_id=parent.template_id, template_name=parent.templates[parent.template_id])
                parent.stepChanged.emit(f'BLACK|    Профиль WAF "{item["name"]}" импортирован.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей WAF.')
    else:
        parent.stepChanged.emit('GREEN|    Импорт профилей WAF завершён.')


#-------------------------------------------- Глобальный портал --------------------------------------------------
def import_proxyportal_rules(parent, path):
    """Импортируем список URL-ресурсов веб-портала"""
    json_file = os.path.join(path, 'config_web_portal.json')
    err, data = func.read_json_file(parent, json_file, mode=2)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт списка ресурсов веб-портала в раздел "Глобальный портал/Веб-портал".')
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
                item['mapping_url_ssl_profile_id'] = parent.mc_data['ssl_profiles'][item['mapping_url_ssl_profile_id']].id
        except KeyError as err:
            parent.stepChanged.emit(f'RED|    Error [Правило "{item["name"]}"]. Не найден профиль SSL {err}. Загрузите профили SSL и повторите попытку.')
            item['description'] = f'{item["description"]}\nError: Не найден профиль SSL {err}.'
            item['mapping_url_ssl_profile_id'] = 0
            item['enabled'] = False
            error = 1
        try:
            if item['mapping_url_certificate_id']:
                item['mapping_url_certificate_id'] = parent.mc_data['certs'][item['mapping_url_certificate_id']].id
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
                parent.stepChanged.emit(f'RED|       {result}  [Ресурс веб-портала "{item["name"]}"]')
                error = 1
            else:
                parent.stepChanged.emit(f'uGRAY|       Ресурс веб-портала "{item["name"]}" обновлён.')
        else:
            item['position'] = 'last'
            err, result = parent.utm.add_template_proxyportal_rule(parent.template_id, item)
            if err:
                parent.stepChanged.emit(f'RED|    {result}  [Ресурс веб-портала "{item["name"]}" не импортирован]')
                error = 1
            else:
                list_proxyportal[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Ресурс веб-портала "{item["name"]}" импортирован.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте ресурсов веб-портала.')
    else:
        parent.stepChanged.emit('GREEN|    Импорт списка ресурсов веб-портала завершён.')


def import_reverseproxy_servers(parent, path):
    """Импортируем список серверов reverse-прокси"""
    json_file = os.path.join(path, 'config_reverseproxy_servers.json')
    err, data = func.read_json_file(parent, json_file, mode=2)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт серверов reverse-прокси в раздел "Глобальный портал/Серверы reverse-прокси".')
    error = 0

    if not parent.mc_data['reverseproxy_servers']:
        if get_reverseproxy_servers(parent):      # Устанавливаем parent.mc_data['reverseproxy_servers']
            parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте серверов reverse-прокси.')
            return
    reverseproxy_servers = parent.mc_data['reverseproxy_servers']

    for item in data:
        item['name'] = func.get_restricted_name(item['name'])
        if item['name'] in reverseproxy_servers:
            if parent.template_id == reverseproxy_servers[item['name']].template_id:
                parent.stepChanged.emit(f'uGRAY|    Сервер reverse-прокси "{item["name"]}" уже существует в текущем шаблоне.')
                err, result = parent.utm.update_template_reverseproxy_server(parent.template_id, reverseproxy_servers[item['name']].id, item)
                if err:
                    parent.stepChanged.emit(f'RED|       {result}  [Сервер reverse-прокси "{item["name"]}"]')
                    error = 1
                else:
                    parent.stepChanged.emit(f'uGRAY|       Сервер reverse-прокси "{item["name"]}" обновлён.')
            else:
                parent.stepChanged.emit(f'sGREEN|    Сервер reverse-прокси "{item["name"]}" уже существует в шаблоне "{reverseproxy_servers[item["name"]].template_name}".')
        else:
            err, result = parent.utm.add_template_reverseproxy_server(parent.template_id, item)
            if err:
                parent.stepChanged.emit(f'RED|    {result}  [Сервер reverse-прокси "{item["name"]}" не импортирован]')
                error = 1
            else:
                reverseproxy_servers[item['name']] = BaseObject(id=result, template_id=parent.template_id, template_name=parent.templates[parent.template_id])
                parent.stepChanged.emit(f'BLACK|    Сервер reverse-прокси "{item["name"]}" импортирован.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте серверов reverse-прокси.')
    else:
        parent.stepChanged.emit('GREEN|    Импорт серверов reverse-прокси завершён.')


def import_reverseproxy_rules(parent, path):
    """Импортируем список правил reverse-прокси"""
    json_file = os.path.join(path, 'config_reverseproxy_rules.json')
    err, data = func.read_json_file(parent, json_file, mode=2)
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

    if not parent.mc_data['reverseproxy_servers']:
        if get_reverseproxy_servers(parent):      # Устанавливаем parent.mc_data['reverseproxy_servers']
            parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил reverse-прокси.')
            return
    reverseproxy_servers = parent.mc_data['reverseproxy_servers']

    if not parent.mc_data['useragents']:
        if get_useragent_list(parent):      # Устанавливаем parent.mc_data['useragents']
            parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил reverse-прокси.')
            return
    useragent_list = parent.mc_data['useragents']

    if not parent.mc_data['client_certs_profiles']:
        if get_client_certificate_profiles(parent): # Устанавливаем parent.mc_data['client_certs_profiles']
            parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил reverse-прокси.')
            return
    client_certs_profiles = parent.mc_data['client_certs_profiles']

    if parent.utm.waf_license:  # Проверяем что есть лицензия на WAF
        if not parent.mc_data['waf_profiles']:
            if get_waf_profiles(parent): # Устанавливаем parent.mc_data['waf_profiles']
                parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил reverse-прокси.')
                return
    else:
        parent.stepChanged.emit('NOTE|    Нет лицензии на WAF. Защита приложений WAF будет выключена в правилах.')
    waf_profiles = parent.mc_data['waf_profiles']

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
                x[1] = reverseproxy_servers[x[1]].id if x[0] == 'profile' else reverse_loadbalancing[x[1]]
        except KeyError as err:
            parent.stepChanged.emit(f'RED|    Error: Правило "{item["name"]}" не импортировано. Не найден сервер reverse-прокси или балансировщик {err}. Импортируйте reverse-прокси или балансировщик и повторите попытку.')
            continue

        if item['ssl_profile_id']:
            try:
                item['ssl_profile_id'] = parent.mc_data['ssl_profiles'][item['ssl_profile_id']].id
            except KeyError as err:
                parent.stepChanged.emit(f'RED|    Error [Правило "{item["name"]}"]. Не найден профиль SSL {err}. Загрузите профили SSL и повторите попытку.')
                item['description'] = f'{item["description"]}\nError: Не найден профиль SSL {err}.'
                item['ssl_profile_id'] = 0
                item['is_https'] = False
                item['error'] = True
        else:
            item['is_https'] = False

        if item['certificate_id']:
            try:
                item['certificate_id'] = parent.mc_data['certs'][item['certificate_id']].id
            except KeyError as err:
                parent.stepChanged.emit(f'RED|    Error [Правило "{item["name"]}"]. Не найден сертификат {err}. Создайте сертификат и повторите попытку.')
                item['description'] = f'{item["description"]}\nError: Не найден сертификат {err}.'
                item['certificate_id'] = -1
                item['is_https'] = False
                item['error'] = True
        else:
            item['certificate_id'] = -1
            item['is_https'] = False

        new_user_agents = []
        for x in item['user_agents']:
            if x[1] in parent.mc_data['ug_useragents']:
                new_user_agents.append(['list_id', f'id-{x[1]}'])
            else:
                try:
                    new_user_agents.append(['list_id', useragent_list[x[1]].id])
                except KeyError as err:
                    parent.stepChanged.emit(f'RED|    Error [Правило "{item["name"]}"]. Не найден список Useragent {err}. Импортируйте списки useragent браузеров и повторите попытку.')
                    item['description'] = f'{item["description"]}\nError: Не найден Useragent {err}.'
                    item['error'] = True
        item['user_agents'] = new_user_agents

        if item['client_certificate_profile_id']:
            try:
                item['client_certificate_profile_id'] = client_certs_profiles[item['client_certificate_profile_id']].id
            except KeyError as err:
                parent.stepChanged.emit(f'RED|    Error [Правило "{item["name"]}"]. Не найден профиль сертификата пользователя "{item["client_certificate_profile_id"]}". Импортируйте профили пользовательских сертификатов и повторите попытку.')
                item['description'] = f'{item["description"]}\nError: Не найден профиль сертификата пользователя "{item["client_certificate_profile_id"]}".'
                item['client_certificate_profile_id'] = 0
                item['error'] = True

        if item['waf_profile_id']:
            if parent.utm.waf_license:
                try:
                    item['waf_profile_id'] = waf_profiles[item['waf_profile_id']].id
                except KeyError as err:
                    parent.stepChanged.emit(f'RED|    Error [Правило "{item["name"]}"]. Не найден профиль WAF {err}. Импортируйте профили WAF и повторите попытку.')
                    item['description'] = f'{item["description"]}\nError: Не найден профиль WAF {err}.'
                    item['waf_profile_id'] = 0
                    item['error'] = True
            else:
                item['waf_profile_id'] = 0
                item['description'] = f'{item["description"]}\nError: Нет лицензии на модуль WAF. Профиль WAF "{item["waf_profile_id"]}" не импортирован в правило.'

        if item.pop('error', False):
            item['enabled'] = False
            error = 1

        if item['name'] in reverseproxy_rules:
            parent.stepChanged.emit(f'uGRAY|    Правило reverse-прокси "{item["name"]}" уже существует.')
            err, result = parent.utm.update_template_reverseproxy_rule(parent.template_id, reverseproxy_rules[item['name']], item)
            if err:
                parent.stepChanged.emit(f'RED|       {result}  [Правило reverse-прокси "{item["name"]}"]')
                error = 1
            else:
                parent.stepChanged.emit(f'uGRAY|       Правило reverse-прокси "{item["name"]}" обновлено.')
        else:
            item['position'] = 'last'
            err, result = parent.utm.add_template_reverseproxy_rule(parent.template_id, item)
            if err:
                parent.stepChanged.emit(f'RED|    {result}  [Правило reverse-прокси "{item["name"]}" не импортировано]')
                error = 1
            else:
                reverseproxy_rules[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Правило reverse-прокси "{item["name"]}" импортировано.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил reverse-прокси.')
    else:
        parent.stepChanged.emit('GREEN|    Импорт правил reverse-прокси завершён.')
    parent.stepChanged.emit('LBLUE|    Проверьте флаг "Использовать HTTPS" во всех импортированных правилах! Если не установлен профиль SSL, выберите нужный.')

#-------------------------------------------- VPN -----------------------------------------------------------------------
def import_vpnclient_security_profiles(parent, path):
    """Импортируем клиентские профилей безопасности VPN"""
    json_file = os.path.join(path, 'config_vpnclient_security_profiles.json')
    err, data = func.read_json_file(parent, json_file, mode=2)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт клиентских профилей безопасности VPN в раздел "VPN/Клиентские профили безопасности".')
    error = 0

    if not parent.mc_data['vpn_client_security_profiles']:
        if get_vpn_client_security_profiles(parent): # Устанавливаем parent.mc_data['vpn_client_security_profiles']
            parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте клиентских профилей безопасности VPN.')
            return
    security_profiles = parent.mc_data['vpn_client_security_profiles']

    for item in data:
        if item['certificate_id']:
            try:
                item['certificate_id'] = parent.mc_data['certs'][item['certificate_id']].id
            except KeyError as err:
                parent.stepChanged.emit(f'RED|    Error [Правило "{item["name"]}"]. Не найден сертификат {err}. Импортируйте сертификаты и повторите попытку.')
                item['description'] = f'{item["description"]}\nError: Не найден сертификат {err}.'
                item['certificate_id'] = 0
                error = 1

        if item['name'] in security_profiles:
            if parent.template_id == security_profiles[item['name']].template_id:
                parent.stepChanged.emit(f'uGRAY|    Профиль безопасности VPN "{item["name"]}" уже существует в текущем шаблоне.')
                err, result = parent.utm.update_template_vpn_client_security_profile(parent.template_id, security_profiles[item['name']].id, item)
                if err:
                    parent.stepChanged.emit(f'RED|       {result}  [Профиль безопасности VPN "{item["name"]}"]')
                    error = 1
                else:
                    parent.stepChanged.emit(f'uGRAY|       Профиль безопасности VPN "{item["name"]}" обновлён.')
            else:
                parent.stepChanged.emit(f'sGREEN|    Профиль безопасности VPN "{item["name"]}" уже существует в шаблоне "{security_profiles[item["name"]].template_name}".')
        else:
            err, result = parent.utm.add_template_vpn_client_security_profile(parent.template_id, item)
            if err:
                parent.stepChanged.emit(f'RED|    {result}  [Профиль безопасности VPN "{item["name"]}" не импортирован]')
                error = 1
            else:
                security_profiles[item['name']] = BaseObject(id=result, template_id=parent.template_id, template_name=parent.templates[parent.template_id])
                parent.stepChanged.emit(f'BLACK|    Профиль безопасности VPN "{item["name"]}" импортирован.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте клиентских профилей безопасности VPN.')
    else:
        parent.stepChanged.emit('GREEN|    Импорт клиентских профили безопасности завершён.')


def import_vpnserver_security_profiles(parent, path):
    """Импортируем серверные профилей безопасности VPN"""
    json_file = os.path.join(path, 'config_vpnserver_security_profiles.json')
    err, data = func.read_json_file(parent, json_file, mode=2)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт серверных профилей безопасности VPN в раздел "VPN/Серверные профили безопасности".')
    error = 0

    if not parent.mc_data['client_certs_profiles']:
        if get_client_certificate_profiles(parent): # Устанавливаем parent.mc_data['client_certs_profiles']
            parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте серверных профилей безопасности VPN.')
            return
    client_certs_profiles = parent.mc_data['client_certs_profiles']

    if not parent.mc_data['vpn_server_security_profiles']:
        if get_vpn_server_security_profiles(parent): # Устанавливаем parent.mc_data['vpn_server_security_profiles']
            parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте серверных профилей безопасности VPN.')
            return
    security_profiles = parent.mc_data['vpn_server_security_profiles']

    for item in data:
        if item['certificate_id']:
            try:
                item['certificate_id'] = parent.mc_data['certs'][item['certificate_id']].id
            except KeyError as err:
                parent.stepChanged.emit(f'RED|    Error [Правило "{item["name"]}"]. Не найден сертификат {err}. Импортируйте сертификаты и повторите попытку.')
                item['description'] = f'{item["description"]}\nError: Не найден сертификат {err}.'
                item['certificate_id'] = 0
                error = 1
        if item['client_certificate_profile_id']:
            try:
                item['client_certificate_profile_id'] = client_certs_profiles[item['client_certificate_profile_id']].id
            except KeyError as err:
                parent.stepChanged.emit(f'RED|    Error [Правило "{item["name"]}"]. Не найден профиль сертификата пользователя {err}. Импортируйте профили пользовательских сертификатов и повторите попытку.')
                item['description'] = f'{item["description"]}\nError: Не найден профиль сертификата пользователя {err}.'
                item['client_certificate_profile_id'] = 0
                error = 1

        if item['name'] in security_profiles:
            if parent.template_id == security_profiles[item['name']].template_id:
                parent.stepChanged.emit(f'uGRAY|    Профиль безопасности VPN "{item["name"]}" уже существует в текущем шаблоне.')
                err, result = parent.utm.update_template_vpn_server_security_profile(parent.template_id, security_profiles[item['name']].id, item)
                if err:
                    parent.stepChanged.emit(f'RED|       {result}  [Профиль безопасности VPN "{item["name"]}"]')
                    error = 1
                else:
                    parent.stepChanged.emit(f'uGRAY|       Профиль безопасности VPN "{item["name"]}" обновлён.')
            else:
                parent.stepChanged.emit(f'sGREEN|    Профиль безопасности VPN "{item["name"]}" уже существует в шаблоне "{security_profiles[item["name"]].template_name}".')
        else:
            err, result = parent.utm.add_template_vpn_server_security_profile(parent.template_id, item)
            if err:
                parent.stepChanged.emit(f'RED|    {result}  [Профиль безопасности VPN "{item["name"]}" не импортирован]')
                error = 1
            else:
                security_profiles[item['name']] = BaseObject(id=result, template_id=parent.template_id, template_name=parent.templates[parent.template_id])
                parent.stepChanged.emit(f'BLACK|    Профиль безопасности VPN "{item["name"]}" импортирован.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте серверных профилей безопасности VPN.')
    else:
        parent.stepChanged.emit('GREEN|    Импорт серверных профилей безопасности завершён.')


def import_vpn_networks(parent, path):
    """Импортируем список сетей VPN"""
    json_file = os.path.join(path, 'config_vpn_networks.json')
    err, data = func.read_json_file(parent, json_file, mode=2)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт списка сетей VPN в раздел "VPN/Сети VPN".')
    error = 0

    if not parent.mc_data['vpn_networks']:
        if get_vpn_networks(parent):        # Устанавливаем parent.mc_data['vpn_networks']
            parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте списка сетей VPN.')
            return
    vpn_networks = parent.mc_data['vpn_networks']

    for item in data:
        item['name'] = func.get_restricted_name(item['name'])
        item['networks'] = get_networks(parent, item['networks'], item)
        item['ep_routes_include'] = get_networks(parent, item['ep_routes_include'], item)
        item['ep_routes_exclude'] = get_networks(parent, item['ep_routes_exclude'], item)
        if 'error' in item:
            error = 1
            item.pop('error', None)

        if item['name'] in vpn_networks:
            if parent.template_id == vpn_networks[item['name']].template_id:
                parent.stepChanged.emit(f'uGRAY|    Сеть VPN "{item["name"]}" уже существует в текущем шаблоне.')
                err, result = parent.utm.update_template_vpn_network(parent.template_id, vpn_networks[item['name']].id, item)
                if err:
                    parent.stepChanged.emit(f'RED|       {result}  [Сеть VPN "{item["name"]}"]')
                    error = 1
                else:
                    parent.stepChanged.emit(f'uGRAY|       Сеть VPN "{item["name"]}" обновлена.')
            else:
                parent.stepChanged.emit(f'sGREEN|    Сеть VPN "{item["name"]}" уже существует в шаблоне "{vpn_networks[item["name"]].template_name}".')
        else:
            err, result = parent.utm.add_template_vpn_network(parent.template_id, item)
            if err:
                parent.stepChanged.emit(f'RED|    {result}  [Сеть VPN "{item["name"]}" не импортирована]')
                error = 1
            else:
                vpn_networks[item['name']] = BaseObject(id=result, template_id=parent.template_id, template_name=parent.templates[parent.template_id])
                parent.stepChanged.emit(f'BLACK|    Сеть VPN "{item["name"]}" импортирована.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте списка сетей VPN.')
    else:
        parent.stepChanged.emit('GREEN|    Импорт списка сетей VPN завершён.')


def get_networks(parent, networks, rule):
    new_networks = []
    for x in networks:
        try:
            new_networks.append(['list_id', parent.mc_data['ip_lists'][x[1]].id]  if x[0] == 'list_id' else x)
        except KeyError as err:
            parent.stepChanged.emit(f'RED|    Error [Правило "{rule["name"]}"]. Не найден список IP-адресов {err}. Импортируйте списки IP-адресов и повторите попытку.')
            rule['description'] = f'{rule["description"]}\nError: Не найден список IP-адресов {err}.'
            rule['error'] = 1
    return new_networks


def import_vpn_client_rules(parent, path):
    """Импортируем список клиентских правил VPN"""
    json_file = os.path.join(path, 'config_vpn_client_rules.json')
    err, data = func.read_json_file(parent, json_file, mode=2)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт клиентских правил VPN в раздел "VPN/Клиентские правила".')
    error = 0

    if not parent.mc_data['interfaces']:
        if get_interfaces_list(parent): # Устанавливаем parent.mc_data['interfaces']
            parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте клиентских правил VPN.')
            return

    if not parent.mc_data['vpn_client_security_profiles']:
        if get_vpn_client_security_profiles(parent): # Устанавливаем parent.mc_data['vpn_client_security_profiles']
            parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте клиентских правил VPN.')
            return
    security_profiles = parent.mc_data['vpn_client_security_profiles']

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
        if f'{item["iface_id"]}:cluster' not in parent.mc_data['interfaces']:
            parent.stepChanged.emit(f'ORANGE|    Warning [Правило "{item["name"]}"]. Не найден интерфейс VPN "{item["iface_id"]}" в группе шаблонов.')
        try:
            item['security_profile_id'] = security_profiles[item['security_profile_id']].id
        except KeyError as err:
            parent.stepChanged.emit(f'RED|    Error [Правило "{item["name"]}"]. Не найден профиль безопасности VPN {err}. Загрузите профили безопасности VPN и повторите попытку.')
            item['description'] = f'{item["description"]}\nError: Не найден профиль безопасности VPN {err}.'
            item['security_profile_id'] = ""
            item['enabled'] = False
            error = 1

        if item['name'] in vpn_client_rules:
            parent.stepChanged.emit(f'uGRAY|    Клиентское правило VPN "{item["name"]}" уже существует в текущем шаблоне.')
            err, result = parent.utm.update_template_vpn_client_rule(parent.template_id, vpn_client_rules[item['name']], item)
            if err:
                parent.stepChanged.emit(f'RED|       {result}  [Клиентское правило VPN "{item["name"]}"]')
                error = 1
            else:
                parent.stepChanged.emit(f'uGRAY|       Клиентское правило VPN "{item["name"]}" обновлено.')
        else:
            err, result = parent.utm.add_template_vpn_client_rule(parent.template_id, item)
            if err:
                parent.stepChanged.emit(f'RED|    {result}  [Клиентское правило VPN "{item["name"]}" не импортировано]')
                error = 1
            else:
                vpn_client_rules[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Клиентское правило VPN "{item["name"]}" импортировано.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте клиентских правил VPN.')
    else:
        parent.stepChanged.emit('GREEN|    Импорт клиентских правил VPN завершён.')


def import_vpn_server_rules(parent, path):
    """Импортируем список серверных правил VPN"""
    json_file = os.path.join(path, 'config_vpn_server_rules.json')
    err, data = func.read_json_file(parent, json_file, mode=2)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт серверных правил VPN в раздел "VPN/Серверные правила".')
    error = 0

    if not parent.mc_data['interfaces']:
        if get_interfaces_list(parent): # Устанавливаем parent.mc_data['interfaces']
            parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте клиентских правил VPN.')
            return

    if not parent.mc_data['vpn_server_security_profiles']:
        if get_vpn_server_security_profiles(parent): # Устанавливаем parent.mc_data['vpn_server_security_profiles']
            parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте серверных правил VPN.')
            return
    security_profiles = parent.mc_data['vpn_server_security_profiles']

    if not parent.mc_data['vpn_networks']:
        if get_vpn_networks(parent):        # Устанавливаем parent.mc_data['vpn_networks']
            parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте серверных правил VPN.')
            return
    vpn_networks = parent.mc_data['vpn_networks']

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
        if f'{item["iface_id"]}:cluster' not in parent.mc_data['interfaces']:
            parent.stepChanged.emit(f'RED|    Eror [Правило "{item["name"]}"]. Не найден интерфейс VPN "{item["iface_id"]}" в группе шаблонов.')
            parent.stepChanged.emit(f'RED|       Error: Правило "{item["name"]}" не импортировано.')
            error = 1
            continue
        try:
            item['security_profile_id'] = security_profiles[item['security_profile_id']].id
        except KeyError as err:
            parent.stepChanged.emit(f'RED|    Error [Правило "{item["name"]}"]. Не найден профиль безопасности VPN {err}. Загрузите профили безопасности VPN и повторите попытку.')
            parent.stepChanged.emit(f'RED|       Error: Правило "{item["name"]}" не импортировано.')
            error = 1
            continue
        try:
            item['tunnel_id'] = vpn_networks[item['tunnel_id']].id
        except KeyError as err:
            parent.stepChanged.emit(f'RED|    Error [Правило "{item["name"]}"]. Не найдена сеть VPN "{err}". Загрузите сети VPN и повторите попытку.')
            item['description'] = f'{item["description"]}\nError: Не найдена сеть VPN "{err}".'
            item['tunnel_id'] = False
            item['error'] = True
        try:
            item['auth_profile_id'] = parent.mc_data['auth_profiles'][item['auth_profile_id']].id
        except KeyError as err:
            parent.stepChanged.emit(f'RED|    Error [Правило "{item["name"]}"]. Не найден профиль авторизации {err}. Загрузите профили авторизации и повторите попытку.')
            item['description'] = f'{item["description"]}\nError: Не найден профиль авторизации {err}.'
            item['auth_profile_id'] = False
            item['error'] = True

        if item.pop('error', False):
            item['enabled'] = False
            error = 1

        if item['name'] in vpn_server_rules:
            parent.stepChanged.emit(f'uGRAY|    Серверное правило VPN "{item["name"]}" уже существует в текщем шаблоне.')
            err, result = parent.utm.update_template_vpn_server_rule(parent.template_id, vpn_server_rules[item['name']], item)
            if err:
                parent.stepChanged.emit(f'RED|       {result}  [Серверное правило VPN "{item["name"]}"]')
                error = 1
            else:
                parent.stepChanged.emit(f'uGRAY|       Серверное правило VPN "{item["name"]}" обновлено.')
        else:
            item['position'] = 'last'
            err, result = parent.utm.add_template_vpn_server_rule(parent.template_id, item)
            if err:
                parent.stepChanged.emit(f'RED|    {result}  [Серверное правило VPN "{item["name"]}" не импортировано]')
                error = 1
            else:
                vpn_server_rules[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Серверное правило VPN "{item["name"]}" импортировано.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте серверных правил VPN.')
    else:
        parent.stepChanged.emit('GREEN|    Импорт серверных правил VPN завершён.')


#--------------------------------------------------- Оповещения ---------------------------------------------------------
def import_notification_alert_rules(parent, path):
    """Импортируем список правил оповещений"""
    json_file = os.path.join(path, 'config_alert_rules.json')
    err, data = func.read_json_file(parent, json_file, mode=2)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт правил оповещений в раздел "Диагностика и мониторинг/Правила оповещений".')
    error = 0

    if not parent.mc_data['notification_profiles']:
        if get_notification_profiles(parent):      # Устанавливаем parent.mc_data['notification_profiles']
            parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил оповещений.')
            return

    if not parent.mc_data['email_groups']:
        if get_email_groups(parent):      # Устанавливаем parent.mc_data['email_groups']
            parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил оповещений.')
            return

    if not parent.mc_data['phone_groups']:
        if get_phone_groups(parent):      # Устанавливаем parent.mc_data['phone_groups']
            parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил оповещений.')
            return

    err, result = parent.utm.get_template_notification_alert_rules(parent.template_id)
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил оповещений.')
        parent.error = 1
        return
    alert_rules = {x['name']: x['id'] for x in result}

    for item in data:
        try:
            item['notification_profile_id'] = parent.mc_data['notification_profiles'][item['notification_profile_id']].id
        except KeyError as err:
            parent.stepChanged.emit(f'RED|    Error [Правило "{item["name"]}"]. Не найден профиль оповещений {err}. Импортируйте профили оповещений и повторите попытку.')
            parent.stepChanged.emit(f'RED|       Error: Правило "{item["name"]}" не импортировано.')
            error = 1
            continue

        new_emails = []
        for x in item['emails']:
            try:
                new_emails.append(['list_id', parent.mc_data['email_groups'][x[1]].id])
            except KeyError as err:
                parent.stepChanged.emit(f'RED|    Error [Правило "{item["name"]}"]. Не найдена группа почтовых адресов {err}. Загрузите почтовые адреса и повторите попытку.')
                item['description'] = f'{item["description"]}\nError: Не найдена группа почтовых адресов {err}.'
                item['enabled'] = False
                error = 1
        item['emails'] = new_emails

        new_phones = []
        for x in item['phones']:
            try:
                new_phones.append(['list_id', parent.mc_data['phone_groups'][x[1]].id])
            except KeyError as err:
                parent.stepChanged.emit(f'RED|    Error [Правило "{item["name"]}"]. Не найдена группа телефонных номеров {err}. Загрузите номера телефонов и повторите попытку.')
                item['description'] = f'{item["description"]}\nError: Не найдена группа телефонных номеров {err}.'
                item['enabled'] = False
                error = 1
        item['phones'] = new_phones

        if item['name'] in alert_rules:
            parent.stepChanged.emit(f'uGRAY|    Правило оповещения "{item["name"]}" уже существует в текущем шаблоне.')
            err, result = parent.utm.update_template_notification_alert_rule(parent.template_id, alert_rules[item['name']], item)
            if err:
                parent.stepChanged.emit(f'RED|       {result}  [Правило оповещения "{item["name"]}"]')
                error = 1
            else:
                parent.stepChanged.emit(f'uGRAY|       Правило оповещения "{item["name"]}" обновлено.')
        else:
            err, result = parent.utm.add_template_notification_alert_rule(parent.template_id, item)
            if err:
                parent.stepChanged.emit(f'RED|    {result}  [Правило оповещения "{item["name"]}" не импортировано]')
                error = 1
            else:
                alert_rules[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Правило оповещения "{item["name"]}" импортировано.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил оповещений.')
    else:
        parent.stepChanged.emit('GREEN|    Импорт правил оповещений завершён.')


def import_snmp_security_profiles(parent, path):
    """Импортируем профили безопасности SNMP"""
    json_file = os.path.join(path, 'config_snmp_profiles.json')
    err, data = func.read_json_file(parent, json_file, mode=2)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт профилей безопасности SNMP в раздел "Диагностика и мониторинг/Профили безопасности SNMP".')
    error = 0

    if not parent.mc_data['snmp_security_profiles']:
        if get_snmp_security_profiles(parent):      # Устанавливаем parent.mc_data['snmp_security_profiles']
            parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей безопасности SNMP.')
            return
    snmp_security_profiles = parent.mc_data['snmp_security_profiles']

    for item in data:
        if not isinstance(item['auth_password'], str):
            item['auth_password'] = ''
        if not isinstance(item['private_password'], str):
            item['private_password'] = ''

        if item['name'] in snmp_security_profiles:
            if parent.template_id == snmp_security_profiles[item['name']].template_id:
                parent.stepChanged.emit(f'uGRAY|    Профиль безопасности SNMP "{item["name"]}" уже существует в текущем шаблоне.')
                err, result = parent.utm.update_template_snmp_security_profile(parent.template_id, snmp_security_profiles[item['name']].id, item)
                if err:
                    parent.stepChanged.emit(f'RED|       {result}  [Профиль безопасности SNMP "{item["name"]}"]')
                    error = 1
                else:
                    parent.stepChanged.emit(f'uGRAY|       Профиль безопасности SNMP "{item["name"]}" обновлён.')
            else:
                parent.stepChanged.emit(f'sGREEN|    Профиль безопасности SNMP "{item["name"]}" уже существует в шаблоне "{snmp_security_profiles[item["name"]].template_name}".')
        else:
            err, result = parent.utm.add_template_snmp_security_profile(parent.template_id, item)
            if err:
                parent.stepChanged.emit(f'RED|    {result}  [Профиль безопасности SNMP: "{item["name"]}" не импортирован]')
                error = 1
            else:
                snmp_security_profiles[item['name']] = BaseObject(id=result, template_id=parent.template_id, template_name=parent.templates[parent.template_id])
                parent.stepChanged.emit(f'BLACK|    Профиль безопасности SNMP "{item["name"]}" импортирован.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей безопасности SNMP.')
    else:
        parent.stepChanged.emit('GREEN|    Импорт профилей безопасности SNMP завершён.')


def import_snmp_settings(parent, path):
    """Импортируем параметры SNMP"""
    json_file = os.path.join(path, 'config_snmp_engine.json')
    err, engine = func.read_json_file(parent, json_file, mode=2)
    if err:
        return
    json_file = os.path.join(path, 'config_snmp_sysname.json')
    err, sysname = func.read_json_file(parent, json_file, mode=2)
    if err:
        return
    json_file = os.path.join(path, 'config_snmp_syslocation.json')
    err, syslocation = func.read_json_file(parent, json_file, mode=2)
    if err:
        return
    json_file = os.path.join(path, 'config_snmp_sysdescription.json')
    err, sysdescription = func.read_json_file(parent, json_file, mode=2)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт параметров SNMP в раздел "Диагностика и мониторинг/Параметры SNMP".')

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
        parent.stepChanged.emit('GREEN|    Параметры SNMP импортированы.')


def import_snmp_rules(parent, path):
    """Импортируем список правил SNMP"""
    json_file = os.path.join(path, 'config_snmp_rules.json')
    err, data = func.read_json_file(parent, json_file, mode=2)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт списка правил SNMP в раздел "Диагностика и мониторинг/SNMP".')
    error = 0

    if not parent.mc_data['snmp_security_profiles']:
        if get_snmp_security_profiles(parent):      # Устанавливаем parent.mc_data['snmp_security_profiles']
            parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил SNMP.')
            return
    snmp_security_profiles = parent.mc_data['snmp_security_profiles']

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
                    item['snmp_security_profile'] = snmp_security_profiles[item['snmp_security_profile']].id
                except KeyError as err:
                    parent.stepChanged.emit(f'RED|    Error [Правило "{item["name"]}"]. Не найден профиль безопасности SNMP {err}. Импортируйте профили безопасности SNMP и повторите попытку.')
                    item['description'] = f'{item["description"]}\nError: Не найден профиль безопасности SNMP {err}.'
                    item['snmp_security_profile'] = 0
                    item['enabled'] = False
                    error = 1
        else:
            item['snmp_security_profile'] = 0
            item.pop('username', None)
            item.pop('auth_type', None)
            item.pop('auth_alg', None)
            item.pop('auth_password', None)
            item.pop('private_alg', None)
            item.pop('private_password', None)

        if item['name'] in snmp_rules:
            parent.stepChanged.emit(f'uGRAY|    Правило SNMP "{item["name"]}" уже существует в текущем шаблоне.')
            err, result = parent.utm.update_template_snmp_rule(parent.template_id, snmp_rules[item['name']], item)
            if err:
                parent.stepChanged.emit(f'RED|       {result}  [Правило SNMP "{item["name"]}"]')
                error = 1
            else:
                parent.stepChanged.emit(f'uGRAY|       Правило SNMP "{item["name"]}" обновлено.')
        else:
            err, result = parent.utm.add_template_snmp_rule(parent.template_id, item)
            if err:
                parent.stepChanged.emit(f'RED|    {result}  [Правило SNMP "{item["name"]}" не импортировано]')
                error = 1
            else:
                snmp_rules[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Правило SNMP "{item["name"]}" импортировано.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил SNMP.')
    else:
        parent.stepChanged.emit('GREEN|    Импорт правил SNMP завершён.')

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
    "UserIdAgentSyslogFilters": import_useridagent_syslog_filters,
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
    'MFAProfiles': import_2fa_profiles,
    'AuthServers': import_auth_servers,
    'AuthProfiles': import_auth_profiles,
    'GeneralSettings': import_general_settings,
#    'DeviceManagement': pass_function,
#    'Administrators': pass_function,
    'Groups': import_local_groups,
    'Users': import_local_users,
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
    "CustomWafLayers": import_waf_custom_layers,
    "SystemWafRules": pass_function,
    "WAFprofiles": import_waf_profiles,
    "WebPortal": import_proxyportal_rules,
    "ReverseProxyRules": import_reverseproxy_rules,
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
                new_rule_ips.append(['list_id', parent.mc_data['ip_lists'][ips[1]].id])
            elif ips[0] == 'urllist_id':
                new_rule_ips.append(['urllist_id', parent.mc_data['url_lists'][ips[1]].id])
        except KeyError as err:
            parent.stepChanged.emit(f'RED|    Error [Правило "{rule["name"]}"]: Не найден список {mode}-адресов "{ips[1]}". Загрузите списки в библиотеку и повторите импорт.')
            rule['description'] = f'{rule["description"]}\nError: Не найден список {mode}-адресов "{ips[1]}".'
            rule['error'] = True
    return new_rule_ips


def get_zones_id(parent, mode, zones, rule):
    """
    Получить UID-ы зон. Если зона не существует на MC, то она пропускается.
    mode - принимает значения: src | dst (для формирования сообщений)
    """
    new_zones = []
    for zone in zones:
        try:
            new_zones.append(parent.mc_data['zones'][zone].id)
        except KeyError as err:
            parent.stepChanged.emit(f'RED|    Error [Правило "{rule["name"]}"]: Не найдена {mode}-зона "{zone}" в группе шаблонов. Импортируйте зоны и повторите попытку.')
            rule['description'] = f'{rule["description"]}\nError: Не найдена {mode}-зона "{zone}".'
            rule['error'] = True
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
                        parent.stepChanged.emit(f'RED|    Error [Правило "{rule["name"]}"]: Пользователь "{item[1]}" не добавлен. Нет LDAP-коннектора для домена "{ldap_domain}".')
                        rule['description'] = f'{rule["description"]}\nError: Нет LDAP-коннектора для домена "{ldap_domain}".'
                        rule['error'] = True
                    else:
                        err, result = parent.utm.get_usercatalog_ldap_user_guid(ldap_id, user_name)
                        if err:
                            parent.stepChanged.emit(f'RED|    {result}  [Правило "{rule["name"]}"]')
                            rule['description'] = f'{rule["description"]}\nError: Не удалось получить ID пользователя "{user_name}" - {result}.'
                            rule['error'] = True
                        elif not result:
                            parent.stepChanged.emit(f'RED|    Error [Правило "{rule["name"]}"]: Нет пользователя "{user_name}" в домене "{ldap_domain}".')
                            rule['description'] = f'{rule["description"]}\nError: Нет пользователя "{user_name}" в домене "{ldap_domain}".'
                            rule['error'] = True
                        else:
                            new_users.append(['user', result])
                else:
                    try:
                        new_users.append(['user', parent.mc_data['local_users'][item[1]].id])
                    except KeyError as err:
                        parent.stepChanged.emit(f'RED|    Error [Правило "{rule["name"]}"]: Не найден локальный пользователь {err}. Импортируйте локальных пользователей.')
                        rule['description'] = f'{rule["description"]}\nError: Не найден локальный пользователь {err}.'
                        rule['error'] = True
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
                        parent.stepChanged.emit(f'RED|    Error [Правило "{rule["name"]}"]: Доменная группа "{item[1]}" не добавлена. Нет LDAP-коннектора для домена "{ldap_domain}"')
                        rule['description'] = f'{rule["description"]}\nError: Нет LDAP-коннектора для домена "{ldap_domain}".'
                        rule['error'] = True
                    else:
                        err, result = parent.utm.get_usercatalog_ldap_group_guid(ldap_id, group_name)
                        if err:
                            parent.stepChanged.emit(f'RED|    {result}  [Правило "{rule["name"]}"]')
                            rule['description'] = f'{rule["description"]}\nError: Не удалось получить ID группы "{group_name}" - {result}.'
                            rule['error'] = True
                        elif not result:
                            parent.stepChanged.emit(f'RED|    Error [Правило "{rule["name"]}"]: Нет группы "{group_name}" в домене "{ldap_domain}"!')
                            rule['description'] = f'{rule["description"]}\nError: Нет группы "{group_name}" в домене "{ldap_domain}".'
                            rule['error'] = True
                        else:
                            new_users.append(['group', result])
                else:
                    try:
                        new_users.append(['group', parent.mc_data['local_groups'][item[1]].id])
                    except KeyError as err:
                        parent.stepChanged.emit(f'RED|    Error [Правило "{rule["name"]}"]. Не найдена группа пользователей {err}. Импортируйте группы пользователей.')
                        rule['description'] = f'{rule["description"]}\nError: Не найдена группа пользователей {err}.'
                        rule['error'] = True
    return new_users


def get_services(parent, service_list, rule):
    """Получаем ID сервисов по из именам. Если сервис не найден, то он пропускается."""
    new_service_list = []
    for item in service_list:
        try:
            if item[0] == 'service':
                new_service_list.append(['service', parent.mc_data['services'][item[1]].id])
            elif item[0] == 'list_id':
                new_service_list.append(['list_id', parent.mc_data['service_groups'][item[1]].id])
        except KeyError as err:
            parent.stepChanged.emit(f'RED|    Error [Правило "{rule["name"]}"]. Не найден сервис или группа сервисов "{item[1]}" в группе шаблонов. Загрузите сервисы и группы сервисов и повторите импорт.')
            rule['description'] = f'{rule["description"]}\nError: Не найден сервис "{item[1]}".'
            rule['error'] = True
    return new_service_list


def get_url_categories_id(parent, rule, referer=0):
    """Получаем ID категорий URL и групп категорий URL. Если список не существует на MC, то он пропускается."""
    new_categories = []
    rule_data = rule['referer_categories'] if referer else rule['url_categories']
    for item in rule_data:
        try:
            if item[0] == 'list_id':
                new_categories.append(['list_id', parent.mc_data['url_categorygroups'][item[1]].id])
            elif item[0] == 'category_id':
                new_categories.append(['category_id', parent.mc_data['url_categories'][item[1]]])
        except KeyError as err:
            parent.stepChanged.emit(f'RED|    Error [Правило "{rule["name"]}"]. Не найдена категория URL "{item[1]}" в группе шаблонов. Загрузите категории URL и повторите импорт.')
            rule['description'] = f'{rule["description"]}\nError: Не найдена категория URL "{item[1]}".'
            rule['error'] = True
    return new_categories


def get_urls_id(parent, urls, rule):
    """Получаем ID списков URL. Если список не существует на MC, то он пропускается."""
    new_urls = []
    for item in urls:
        try:
            new_urls.append(parent.mc_data['url_lists'][item].id)
        except KeyError as err:
            parent.stepChanged.emit(f'RED|    Error [Правило "{rule["name"]}"]. Не найден список URL "{item}" в группе шаблонов. Загрузите списки URL и повторите импорт.')
            rule['description'] = f'{rule["description"]}\nError: Не найден список URL "{item}".'
            rule['error'] = True
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
                    rule['error'] = True
        elif app[0] == 'group':
            try:
                new_app_list.append(['group', parent.mc_data['apps_groups'][app[1]].id])
            except KeyError as err:
                parent.stepChanged.emit(f'RED|    Error [Правило "{rule["name"]}"]. Не найдена группа приложений l7 "{app[1]}".')
                rule['description'] = f'{rule["description"]}\nError: Не найдена группа приложений l7 "{app[1]}".'
                rule['error'] = True
    return new_app_list


def get_time_restrictions(parent, rule):
    """Получаем ID календарей шаблона по их именам. Если календарь не найден в шаблоне, то он пропускается."""
    new_schedules = []
    for name in rule['time_restrictions']:
        try:
            new_schedules.append(parent.mc_data['calendars'][name].id)
        except KeyError:
            parent.stepChanged.emit(f'RED|    Error [Правило "{rule["name"]}"]. Не найден календарь "{name}" в группе шаблонов.')
            rule['description'] = f'{rule["description"]}\nError: Не найден календарь "{name}".'
            rule['error'] = True
    return new_schedules


def get_icap_servers(parent):
    """Получаем список серверов ICAP и устанавливаем значение parent.mc_data['icap_servers']"""
    for uid, name in parent.templates.items():
        err, result = parent.utm.get_template_icap_servers(uid)
        if err:
            parent.stepChanged.emit(f'RED|    {result}')
            parent.error = 1
            return 1
        for x in result:
            if x['name'] in parent.mc_data['icap_servers']:
                parent.stepChanged.emit(f'ORANGE|    Сервер ICAP "{x["name"]}" обнаружен в нескольких шаблонах группы. Сервер из шаблона "{name}" не будет использован.')
            else:
                parent.mc_data['icap_servers'][x['name']] = BaseObject(id=x['id'], template_id=uid, template_name=name)
    return 0

def get_reverseproxy_servers(parent):
    """Получаем список серверов reverse-proxy и устанавливаем значение parent.mc_data['reverseproxy_servers']"""
    for uid, name in parent.templates.items():
        err, result = parent.utm.get_template_reverseproxy_servers(uid)
        if err:
            parent.stepChanged.emit(f'RED|    {result}')
            parent.error = 1
            return 1
        for x in result:
            if x['name'] in parent.mc_data['reverseproxy_servers']:
                parent.stepChanged.emit(f'ORANGE|    Сервер Reverse-прокси "{x["name"]}" обнаружен в нескольких шаблонах группы. Сервер из шаблона "{name}" не будет использован.')
            else:
                parent.mc_data['reverseproxy_servers'][x['name']] = BaseObject(id=x['id'], template_id=uid, template_name=name)
    return 0

def get_morphology_list(parent):
    """Получаем список морфологии и устанавливаем значение parent.mc_data['morphology']"""
    for uid, name in parent.templates.items():
        err, result = parent.utm.get_template_nlists_list(uid, 'morphology')
        if err:
            parent.stepChanged.emit(f'RED|    {result}')
            parent.error = 1
            return 1
        for x in result:
            if x['name'] in parent.mc_data['morphology']:
                parent.stepChanged.emit(f'ORANGE|    Список морфологии "{x["name"]}" обнаружен в нескольких шаблонах группы. Список из шаблона "{name}" не будет использован.')
            else:
                parent.mc_data['morphology'][x['name']] = BaseObject(id=x['id'], template_id=uid, template_name=name)
    return 0

def get_useragent_list(parent):
    """Получаем список UserAgents и устанавливаем значение parent.mc_data['useragents']"""
    for uid, name in parent.templates.items():
        err, result = parent.utm.get_template_nlists_list(uid, 'useragent')
        if err:
            parent.stepChanged.emit(f'RED|    {result}')
            parent.error = 1
            return 1
        for x in result:
            if x['name'] in parent.mc_data['useragents']:
                parent.stepChanged.emit(f'ORANGE|    Список UserAgents "{x["name"]}" обнаружен в нескольких шаблонах группы. Список из шаблона "{name}" не будет использован.')
            else:
                parent.mc_data['useragents'][x['name']] = BaseObject(id=x['id'], template_id=uid, template_name=name)
    return 0

def get_shapers_list(parent):
    """Получаем полосы пропускания и устанавливаем значение parent.mc_data['shapers']"""
    for uid, name in parent.templates.items():
        err, result = parent.utm.get_template_shapers_list(uid)
        if err:
            parent.stepChanged.emit(f'RED|    {result}')
            parent.error = 1
            return 1
        for x in result:
            if x['name'] in parent.mc_data['shapers']:
                parent.stepChanged.emit(f'ORANGE|    Полоса пропускания "{x["name"]}" обнаружена в нескольких шаблонах группы. Полоса из шаблона "{name}" не будет использована.')
            else:
                parent.mc_data['shapers'][x['name']] = BaseObject(id=x['id'], template_id=uid, template_name=name)
    return 0

def get_response_pages(parent):
    """Получаем список шаблонов страниц и устанавливаем значение parent.mc_data['response_pages']"""
    for uid, name in parent.templates.items():
        err, result = parent.utm.get_template_responsepages_list(uid)
        if err:
            parent.stepChanged.emit(f'RED|    {result}')
            parent.error = 1
            return 1
        for x in result:
            if x['name'] in parent.mc_data['response_pages']:
                parent.stepChanged.emit(f'ORANGE|    Шаблон страницы "{x["name"]}" обнаружен в нескольких шаблонах группы. Страница из шаблона "{name}" не будет использована.')
            else:
                parent.mc_data['response_pages'][x['name']] = BaseObject(id=x['id'], template_id=uid, template_name=name)
    parent.mc_data['response_pages'][-1] = BaseObject(id=-1, template_id=uid, template_name=name)
    return 0

def get_app_signatures(parent):
    """Получаем список приложений l7 MC и устанавливаем значение parent.mc_data['l7_apps']"""
    err, result = parent.utm.get_template_app_signatures(parent.template_id)
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return 1
    for x in result:
        parent.mc_data['l7_apps'][x['name']] = BaseAppObject(id=x['id'], owner=x['attributes']['owner'], signature_id=x['signature_id'])
    return 0

def get_l7_profiles(parent):
    """Получаем список профилей приложений группы шаблонов и устанавливаем значение parent.mc_data['l7_profiles']"""
    for uid, name in parent.templates.items():
        err, result = parent.utm.get_template_l7_profiles_list(uid)
        if err:
            parent.stepChanged.emit(f'RED|    {result}')
            parent.error = 1
            return 1
        for x in result:
            if x['name'] in parent.mc_data['l7_profiles']:
                parent.stepChanged.emit(f'ORANGE|    Профиль приложений "{x["name"]}" обнаружен в нескольких шаблонах группы. Профиль из шаблона "{name}" не будет использован.')
            else:
                parent.mc_data['l7_profiles'][x['name']] = BaseObject(id=x['id'], template_id=uid, template_name=name)
    return 0

def get_email_groups(parent):
    """Получаем список групп почтовых адресов группы шаблонов и устанавливаем значение parent.mc_data['email_groups']"""
    for uid, name in parent.templates.items():
        err, result = parent.utm.get_template_nlists_list(uid, 'emailgroup')
        if err:
            parent.stepChanged.emit(f'RED|    {result}')
            parent.error = 1
            return 1
        for x in result:
            if x['name'] in parent.mc_data['email_groups']:
                parent.stepChanged.emit(f'ORANGE|    Группа почтовых адресов "{x["name"]}" обнаружена в нескольких шаблонах группы. Группа из шаблона "{name}" не будет использована.')
            else:
                parent.mc_data['email_groups'][x['name']] = BaseObject(id=x['id'], template_id=uid, template_name=name)
    return 0

def get_phone_groups(parent):
    """Получаем список групп телефонных номеров группы шаблонов и устанавливаем значение parent.mc_data['phone_groups']"""
    for uid, name in parent.templates.items():
        err, result = parent.utm.get_template_nlists_list(uid, 'phonegroup')
        if err:
            parent.stepChanged.emit(f'RED|    {result}')
            parent.error = 1
            return 1
        for x in result:
            if x['name'] in parent.mc_data['phone_groups']:
                parent.stepChanged.emit(f'ORANGE|    Группа почтовых адресов "{x["name"]}" обнаружена в нескольких шаблонах группы. Группа из шаблона "{name}" не будет использована.')
            else:
                parent.mc_data['phone_groups'][x['name']] = BaseObject(id=x['id'], template_id=uid, template_name=name)
    return 0

def get_idps_users_signatures(parent):
    """Получаем список пользовательских сигнатур СОВ группы шаблонов и устанавливаем значение parent.users_signatures"""
    for uid, name in parent.templates.items():
        err, result = parent.utm.get_template_idps_signatures_list(uid, query={'query': 'owner = You'})
        if err:
            parent.stepChanged.emit(f'RED|    {result}')
            parent.error = 1
            return 1
        for x in result:
            if x['msg'] in parent.users_signatures:
                parent.stepChanged.emit(f'ORANGE|    Пользовательская сигнатура "{x["msg"]}" обнаружена в нескольких шаблонах группы. Сигнатура из шаблона "{name}" не будет использована.')
            else:
                parent.users_signatures[x['msg']] = BaseObject(id=x['id'], template_id=uid, template_name=name)
    return 0

def get_idps_profiles(parent):
    """Получаем список профилей СОВ группы шаблонов и устанавливаем значение parent.mc_data['idps_profiles']"""
    for uid, name in parent.templates.items():
        err, result = parent.utm.get_template_idps_profiles_list(uid)
        if err:
            parent.stepChanged.emit(f'RED|    {result}')
            parent.error = 1
            return 1
        for x in result:
            if x['name'] in parent.mc_data['idps_profiles']:
                parent.stepChanged.emit(f'ORANGE|    Профиль СОВ "{x["name"]}" обнаружен в нескольких шаблонах группы. Профиль из шаблона "{name}" не будет использован.')
            else:
                parent.mc_data['idps_profiles'][x['name']] = BaseObject(id=x['id'], template_id=uid, template_name=name)
    return 0

def get_notification_profiles(parent):
    """
    Получаем список профилей оповещения и
    устанавливаем значение атрибута parent.notification_profiles
    """
    for uid, name in parent.templates.items():
        err, result = parent.utm.get_template_notification_profiles(uid)
        if err:
            parent.stepChanged.emit(f'RED|    {result}')
            parent.error = 1
            return 1
        for x in result:
            if x['name'] in parent.mc_data['notification_profiles']:
                parent.stepChanged.emit(f'ORANGE|    Профиль оповещения "{x["name"]}" обнаружен в нескольких шаблонах группы. Профиль из шаблона "{name}" не будет использован.')
            else:
                parent.mc_data['notification_profiles'][x['name']] = BaseObject(id=x['id'], template_id=uid, template_name=name)
    parent.mc_data['notification_profiles'][-5] = BaseObject(id=-5, template_id='', template_name='')
    return 0

def get_netflow_profiles(parent):
    """Получаем список профилей netflow группы шаблонов и устанавливаем значение parent.mc_data['netflow_profiles']"""
    parent.mc_data['netflow_profiles']['undefined'] = BaseObject(id='undefined', template_id='', template_name='')
    for uid, name in parent.templates.items():
        err, result = parent.utm.get_template_netflow_profiles(uid)
        if err:
            parent.stepChanged.emit(f'RED|    {result}')
            parent.error = 1
            return 1
        for x in result:
            if x['name'] in parent.mc_data['netflow_profiles']:
                parent.stepChanged.emit(f'ORANGE|    Профиль netflow "{x["name"]}" обнаружен в нескольких шаблонах группы. Профиль из шаблона "{name}" не будет использован.')
            else:
                parent.mc_data['netflow_profiles'][x['name']] = BaseObject(id=x['id'], template_id=uid, template_name=name)
    return 0

def get_lldp_profiles(parent):
    """Получаем список профилей lldp группы шаблонов и устанавливаем значение parent.mc_data['lldp_profiles']"""
    parent.mc_data['lldp_profiles']['undefined'] = BaseObject(id='undefined', template_id='', template_name='')
    for uid, name in parent.templates.items():
        err, result = parent.utm.get_template_lldp_profiles(uid)
        if err:
            parent.stepChanged.emit(f'RED|    {result}')
            parent.error = 1
            return 1
        for x in result:
            if x['name'] in parent.mc_data['lldp_profiles']:
                parent.stepChanged.emit(f'ORANGE|    Профиль lldp "{x["name"]}" обнаружен в нескольких шаблонах группы. Профиль из шаблона "{name}" не будет использован.')
            else:
                parent.mc_data['lldp_profiles'][x['name']] = BaseObject(id=x['id'], template_id=uid, template_name=name)
    return 0

def get_ssl_forward_profiles(parent):
    """Получаем список профилей пересылки SSL группы шаблонов и устанавливаем значение parent.mc_data['ssl_forward_profiles']"""
    for uid, name in parent.templates.items():
        err, result = parent.utm.get_template_ssl_forward_profiles(uid)
        if err:
            parent.stepChanged.emit(f'RED|    {result}')
            parent.error = 1
            return 1
        for x in result:
            if x['name'] in parent.mc_data['ssl_forward_profiles']:
                parent.stepChanged.emit(f'ORANGE|    Профиль пересылки SSL "{x["name"]}" обнаружен в нескольких шаблонах группы. Профиль из шаблона "{name}" не будет использован.')
            else:
                parent.mc_data['ssl_forward_profiles'][x['name']] = BaseObject(id=x['id'], template_id=uid, template_name=name)
    parent.mc_data['ssl_forward_profiles'][-1] = BaseObject(id=-1, template_id='', template_name='')
    return 0

def get_hip_objects(parent):
    """Получаем список HIP объектов группы шаблонов и устанавливаем значение parent.mc_data['hip_objects']"""
    for uid, name in parent.templates.items():
        err, result = parent.utm.get_template_hip_objects(uid)
        if err:
            parent.stepChanged.emit(f'RED|    {result}')
            parent.error = 1
            return 1
        for x in result:
            if x['name'] in parent.mc_data['hip_objects']:
                parent.stepChanged.emit(f'ORANGE|    HIP объект "{x["name"]}" обнаружен в нескольких шаблонах группы. HIP объект из шаблона "{name}" не будет использован.')
            else:
                parent.mc_data['hip_objects'][x['name']] = BaseObject(id=x['id'], template_id=uid, template_name=name)
    return 0

def get_hip_profiles(parent):
    """Получаем список HIP профилей группы шаблонов и устанавливаем значение parent.mc_data['hip_profiles']"""
    for uid, name in parent.templates.items():
        err, result = parent.utm.get_template_hip_profiles(uid)
        if err:
            parent.stepChanged.emit(f'RED|    {result}')
            parent.error = 1
            return 1
        for x in result:
            if x['name'] in parent.mc_data['hip_profiles']:
                parent.stepChanged.emit(f'ORANGE|    HIP профиль "{x["name"]}" обнаружен в нескольких шаблонах группы. HIP профиль из шаблона "{name}" не будет использован.')
            else:
                parent.mc_data['hip_profiles'][x['name']] = BaseObject(id=x['id'], template_id=uid, template_name=name)
    return 0

def get_bfd_profiles(parent):
    """Получаем список BFD профилей группы шаблонов и устанавливаем значение parent.mc_data['bfd_profiles']"""
    for uid, name in parent.templates.items():
        err, result = parent.utm.get_template_bfd_profiles(uid)
        if err:
            parent.stepChanged.emit(f'RED|    {result}')
            parent.error = 1
            return 1
        for x in result:
            if x['name'] in parent.mc_data['bfd_profiles']:
                parent.stepChanged.emit(f'ORANGE|    BFD профиль "{x["name"]}" обнаружен в нескольких шаблонах группы. BFD профиль из шаблона "{name}" не будет использован.')
            else:
                parent.mc_data['bfd_profiles'][x['name']] = BaseObject(id=x['id'], template_id=uid, template_name=name)
    return 0

def get_useridagent_filters(parent):
    """Получаем Syslog фильтры агента UserID группы шаблонов и устанавливаем значение parent.mc_data['userid_filters']"""
    for uid, name in parent.templates.items():
        err, result = parent.utm.get_template_useridagent_filters(uid)
        if err:
            parent.stepChanged.emit(f'RED|    {result}')
            parent.error = 1
            return 1
        for x in result:
            if x['name'] in parent.mc_data['userid_filters']:
                parent.stepChanged.emit(f'ORANGE|    Syslog фильтр агента UserID "{x["name"]}" обнаружен в нескольких шаблонах группы. Фильтр из шаблона "{name}" не будет использован.')
            else:
                parent.mc_data['userid_filters'][x['name']] = BaseObject(id=x['id'], template_id=uid, template_name=name)
    return 0

def get_gateways_list(parent):
    """Получаем список всех шлюзов в группе шаблонов и устанавливаем значение parent.mc_data['gateways']"""
    for uid, name in parent.templates.items():
        err, result = parent.utm.get_template_gateways(uid)
        if err:
            parent.stepChanged.emit(f'RED|    {result}')
            parent.error = 1
            return 1
        for x in result:
            xname = x.get("name", x["ipv4"])
            gateway_name = f'{xname}:{x["node_name"]}'
            if gateway_name in parent.mc_data['gateways']:
                parent.stepChanged.emit(f'ORANGE|    Шлюз "{xname}" для узла кластера "{x["node_name"]}" обнаружен в нескольких шаблонах группы. Шлюз из шаблона "{name}" не будет использован.')
            else:
                parent.mc_data['gateways'][gateway_name] = BaseObject(id=x['id'], template_id=uid, template_name=name)
    return 0

def get_interfaces_list(parent):
    """Получаем список всех интерфейсов в группе шаблонов и устанавливаем значение parent.mc_data['interfaces']"""
    for uid, name in parent.templates.items():
        err, result = parent.utm.get_template_interfaces_list(uid)
        if err:
            parent.stepChanged.emit(f'RED|    {result}')
            parent.error = 1
            return 1
        for x in result:
            if x['kind'] not in ('bridge', 'bond', 'adapter', 'vlan', 'tunnel', 'vpn') or x['master']:
                continue
            iface_name = f'{x["name"]}:{x["node_name"]}'
            if iface_name in parent.mc_data['interfaces'] and x['kind'] in ('vlan', 'tunnel'):
                parent.stepChanged.emit(f'ORANGE|    Интерфейс "{x["name"]}" для узла кластера "{x["node_name"]}" обнаружен в нескольких шаблонах группы. Интерфейс из шаблона "{name}" не будет использован.')
            else:
                parent.mc_data['interfaces'][iface_name] = BaseObject(id=x['id'], template_id=uid, template_name=name)
    return 0

def get_vrf_list(parent):
    """Получаем список всех VRF в группе шаблонов и устанавливаем значение parent.mc_data['vrf']"""
    for uid, name in parent.templates.items():
        err, result = parent.utm.get_template_vrf_list(uid)
        if err:
            parent.stepChanged.emit(f'RED|    {result}')
            parent.error = 1
            return 1
        for x in result:
            vrf_name = f'{x["name"]}:{x["node_name"]}'
            if vrf_name in parent.mc_data['vrf']:
                parent.stepChanged.emit(f'ORANGE|    VRF "{x["name"]}" для узла кластера "{x["node_name"]}" обнаружен в нескольких шаблонах группы. VRF из шаблона "{name}" не будет использован.')
            else:
                parent.mc_data['vrf'][vrf_name] = BaseObject(id=x['id'], template_id=uid, template_name=name)
    return 0

def get_client_certificate_profiles(parent):
    """
    Получаем список всех профилей клиентских сертификатов в группе шаблонов и
    устанавливаем значение атрибута parent.client_certificate_profiles
    """
    for uid, name in parent.templates.items():
        err, result = parent.utm.get_template_client_certificate_profiles(uid)
        if err:
            parent.stepChanged.emit(f'RED|    {result}')
            parent.error = 1
            return 1
        for x in result:
            if x['name'] in parent.mc_data['client_certs_profiles']:
                parent.stepChanged.emit(f'ORANGE|    Профиль клиентского сертификата "{x["name"]}" обнаружен в нескольких шаблонах группы. Профиль из шаблона "{name}" не будет использован.')
            else:
                parent.mc_data['client_certs_profiles'][x['name']] = BaseObject(id=x['id'], template_id=uid, template_name=name)
    return 0

def get_auth_servers(parent):
    """Получаем список всех серверов аутентификации в группе шаблонов и устанавливаем значение parent.mc_data['auth_servers']"""
    auth_servers = {'ldap': {}, 'ntlm': {}, 'radius': {}, 'tacacs_plus': {}, 'saml_idp': {}}
    for uid, name in parent.templates.items():
        err, result = parent.utm.get_template_auth_servers(uid)
        if err == 1:
            parent.stepChanged.emit(f'RED|    {result}')
            parent.error = 1
            return 1
        for x in result:
            if x['name'] in auth_servers[x['type']]:
                parent.stepChanged.emit(f'ORANGE|    Сервер аутентификации "{x["name"]}" обнаружен в нескольких шаблонах группы шаблонов. Сервер из шаблона "{name}" не будет использован.')
            else:
                auth_servers[x['type']][x['name']] = BaseObject(id=x['id'], template_id=uid, template_name=name)
    parent.mc_data['auth_servers'] = auth_servers
    return 0

def get_profiles_2fa(parent):
    """Получаем список профилей MFA в группе шаблонов и устанавливаем значение parent.mc_data['profiles_2fa']"""
    for uid, name in parent.templates.items():
        err, result = parent.utm.get_template_2fa_profiles(uid)
        if err:
            parent.stepChanged.emit(f'RED|    {result}')
            parent.error = 1
            return 1
        for x in result:
            if x['name'] in parent.mc_data['profiles_2fa']:
                parent.stepChanged.emit(f'ORANGE|    Профиль MFA "{x["name"]}" обнаружен в нескольких шаблонах группы шаблонов. Профиль из шаблона "{name}" не будет использован.')
            else:
                parent.mc_data['profiles_2fa'][x['name']] = BaseObject(id=x['id'], template_id=uid, template_name=name)
    return 0

def get_captive_profiles(parent):
    """Получаем список Captive-профилей и устанавливаем значение parent.mc_data['captive_profiles']"""
    for uid, name in parent.templates.items():
        err, result = parent.utm.get_template_captive_profiles(uid)
        if err:
            parent.stepChanged.emit(f'RED|    {result}')
            parent.error = 1
            return 1
        for x in result:
            if x['name'] in parent.mc_data['captive_profiles']:
                parent.stepChanged.emit(f'ORANGE|    Captive-профиль "{x["name"]}" обнаружен в нескольких шаблонах группы шаблонов. Профиль из шаблона "{name}" не будет использован.')
            else:
                parent.mc_data['captive_profiles'][x['name']] = BaseObject(id=x['id'], template_id=uid, template_name=name)
    return 0

def get_dos_profiles(parent):
    """Получаем список профилей DoS и устанавливаем значение parent.mc_data['dos_profiles']"""
    for uid, name in parent.templates.items():
        err, result = parent.utm.get_template_dos_profiles(uid)
        if err:
            parent.stepChanged.emit(f'RED|    {result}')
            parent.error = 1
            return 1
        for x in result:
            if x['name'] in parent.mc_data['dos_profiles']:
                parent.stepChanged.emit(f'ORANGE|    Профиль DoS "{x["name"]}" обнаружен в нескольких шаблонах группы шаблонов. Профиль DoS из шаблона "{name}" не будет использован.')
            else:
                parent.mc_data['dos_profiles'][x['name']] = BaseObject(id=x['id'], template_id=uid, template_name=name)
    return 0

def get_waf_custom_layers(parent):
    """Получаем список персональных слоёв WAF и устанавливаем значение parent.mc_data['waf_custom_layers']"""
    err, result = parent.utm.get_template_waf_custom_layers(parent.template_id)
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return 1
    parent.waf_custom_layers = {x['name']: x['id'] for x in result}
    return 0

def get_waf_profiles(parent):
    """Получаем список профилей WAF и устанавливаем значение parent.mc_data['waf_profiles']"""
    for uid, name in parent.templates.items():
        err, result = parent.utm.get_template_waf_profiles(uid)
        if err:
            parent.stepChanged.emit(f'RED|    {result}')
            parent.error = 1
            return 1
        for x in result:
            if x['name'] in parent.mc_data['waf_profiles']:
                parent.stepChanged.emit(f'ORANGE|    Профиль WAF "{x["name"]}" обнаружен в нескольких шаблонах группы шаблонов. Профиль из шаблона "{name}" не будет использован.')
            else:
                parent.mc_data['waf_profiles'][x['name']] = BaseObject(id=x['id'], template_id=uid, template_name=name)
    return 0

def get_vpn_client_security_profiles(parent):
    """Получаем клиентские профили безопасности VPN и устанавливаем значение parent.mc_data['vpn_client_security_profiles']"""
    for uid, name in parent.templates.items():
        err, result = parent.utm.get_template_vpn_client_security_profiles(uid)
        if err:
            parent.stepChanged.emit(f'RED|    {result}')
            parent.error = 1
            return 1
        for x in result:
            if x['name'] in parent.mc_data['vpn_client_security_profiles']:
                parent.stepChanged.emit(f'ORANGE|    Клиентский профиль безопасности VPN "{x["name"]}" обнаружен в нескольких шаблонах группы шаблонов. Профиль из шаблона "{name}" не будет использован.')
            else:
                parent.mc_data['vpn_client_security_profiles'][x['name']] = BaseObject(id=x['id'], template_id=uid, template_name=name)
    return 0

def get_vpn_server_security_profiles(parent):
    """Получаем серверные профили безопасности VPN и устанавливаем значение parent.mc_data['vpn_server_security_profiles']"""
    for uid, name in parent.templates.items():
        err, result = parent.utm.get_template_vpn_server_security_profiles(uid)
        if err:
            parent.stepChanged.emit(f'RED|    {result}')
            parent.error = 1
            return 1
        for x in result:
            if x['name'] in parent.mc_data['vpn_server_security_profiles']:
                parent.stepChanged.emit(f'ORANGE|    Серверный профиль безопасности VPN "{x["name"]}" обнаружен в нескольких шаблонах группы шаблонов. Профиль из шаблона "{name}" не будет использован.')
            else:
                parent.mc_data['vpn_server_security_profiles'][x['name']] = BaseObject(id=x['id'], template_id=uid, template_name=name)
    return 0

def get_vpn_networks(parent):
    """Получаем сети VPN и устанавливаем значение parent.mc_data['vpn_networks']"""
    for uid, name in parent.templates.items():
        err, result = parent.utm.get_template_vpn_networks(uid)
        if err:
            parent.stepChanged.emit(f'RED|    {result}')
            parent.error = 1
            return 1
        for x in result:
            if x['name'] in parent.mc_data['vpn_networks']:
                parent.stepChanged.emit(f'ORANGE|    Сеть VPN "{x["name"]}" обнаружена в нескольких шаблонах группы шаблонов. Сеть VPN из шаблона "{name}" не будет использована.')
            else:
                parent.mc_data['vpn_networks'][x['name']] = BaseObject(id=x['id'], template_id=uid, template_name=name)
    return 0

def get_snmp_security_profiles(parent):
    """Получаем сети VPN и устанавливаем значение parent.mc_data['snmp_security_profiles']"""
    for uid, name in parent.templates.items():
        err, result = parent.utm.get_template_snmp_security_profiles(uid)
        if err:
            parent.stepChanged.emit(f'RED|    {result}')
            parent.error = 1
            return 1
        for x in result:
            if x['name'] in parent.mc_data['snmp_security_profiles']:
                parent.stepChanged.emit(f'ORANGE|    Профиль безопасности SNMP "{x["name"]}" обнаружен в нескольких шаблонах группы шаблонов. Профиль из шаблона "{name}" не будет использован.')
            else:
                parent.mc_data['snmp_security_profiles'][x['name']] = BaseObject(id=x['id'], template_id=uid, template_name=name)
    return 0


def add_empty_vrf(parent, vrf_name, ports, node_name):
    """Добавляем пустой VRF"""
    vrf = {
        'name': vrf_name,
        'description': '',
        'node_name': node_name,
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


@dataclass(kw_only=True, slots=True, frozen=True)
class BaseObject:
    id: str
    template_id: str
    template_name: str


@dataclass(kw_only=True, slots=True, frozen=True)
class BaseAppObject:
    id: str
    owner: str
    signature_id: int

