#!/usr/bin/env python
#
#  common_func.py
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

import os, json, pickle
import ipaddress
from PyQt6.QtWidgets import QMessageBox
from services import trans_filename, trans_name


def create_dir(path, delete='yes'):
    if not os.path.isdir(path):
        try:
            os.makedirs(path)
        except Exception as err:
            return 1, f'Ошибка создания каталога: {path} [{err}]'
        return 0, f'Создан каталог {path}'
    else:
        if delete == 'yes':
            for file_name in os.listdir(path):
                os.remove(os.path.join(path, file_name))
        return 0, f'Каталог {path} уже существует.'


def read_bin_file(parent, bin_file_path='temporary_data.bin'):
    """Читаем bin-файл."""
    try:
        with open(bin_file_path, 'rb') as fh:
            data = pickle.load(fh)
    except pickle.UnpicklingError as err:
        parent.stepChanged.emit(f'RED|    Error: {err}. Файл со служебной информацией: "{bin_file_path}" повреждён!')
        parent.error = 1
        return 1, 'RED'
    except FileNotFoundError as err:
        parent.stepChanged.emit(f'RED|    Error: Не найден файл "{bin_file_path}" со служебной информацией!')
        parent.error = 1
        return 2, 'RED'
    except EOFError:
        parent.stepChanged.emit(f'RED|    Файл со служебной информацией "{bin_file_path}" пуст!')
        return 3, 'RED'
    return 0, data


def write_bin_file(parent, data, bin_file_path='temporary_data.bin'):
    """Записываем bin-файл."""
    try:
        with open(bin_file_path, 'wb') as fh:
            pickle.dump(data, fh)
    except pickle.PickleError as err:
        parent.stepChanged.emit(f'RED|    Error: {err}. Не удалось записать файл "{bin_file_path}" со служебной информацией.')
        parent.error = 1
        return 1
    except PermissionError as err:
        parent.stepChanged.emit(f'RED|    Error: Нет права доступа для записи файла "{bin_file_path}" со служебной информацией!')
        parent.error = 1
        return 2
    return 0


def read_json_file(parent, json_file_path, mode=0):
    """Читаем json-файл с конфигурацией."""
    try:
        with open(json_file_path, "r") as fh:
            data = json.load(fh)
    except ValueError as err:
        parent.stepChanged.emit(f'RED|    JSONDecodeError: {err} "{json_file_path}".')
        parent.error = 1
        return 1, f'RED|    JSONDecodeError: {err} "{json_file_path}".'
    except json.JSONDecodeError as err:
        parent.stepChanged.emit(f'RED|    JSONDecodeError: {err} "{json_file_path}".')
        parent.error = 1
        return 1, f'RED|    JSONDecodeError: {err} "{json_file_path}".'
    except FileNotFoundError as err:
        if not mode:
            parent.stepChanged.emit(f'RED|    Error: Не найден файл "{json_file_path}" с сохранённой конфигурацией!')
            parent.error = 1
        return 2, f'bRED|    Error: Не найден файл "{json_file_path}" с сохранённой конфигурацией!'
    if not data:
        if not mode:
            parent.stepChanged.emit(f'GRAY|    Файл "{json_file_path}" пуст.')
        return 3, f'GRAY|    Файл "{json_file_path}" пуст.'
    return 0, data


def create_ip_list(parent, path, ips=[], name=None):
    """
    Создаём IP-лист для правила. Возвращаем имя ip-листа.
    В вызываемом модуле должна быть структура: self.ip_lists = set()
    """
    iplist_name = name if name else ips[0]
    if iplist_name not in parent.ip_lists:
        section_path = os.path.join(path, 'Libraries')
        current_path = os.path.join(section_path, 'IPAddresses')
        err, msg = create_dir(current_path, delete='no')
        if err:
            parent.stepChanged.emit(f'RED|    {msg}.')
            parent.error = 1
            return 0

        ip_list = {
            'name': iplist_name,
            'description': 'Портировано...',
            'type': 'network',
            'url': '',
            'list_type_update': 'static',
            'schedule': 'disabled',
            'attributes': {'threat_level': 3},
            'content': [{'value': ip} for ip in ips]
        }

        json_file = os.path.join(current_path, f'{ip_list["name"].strip().translate(trans_filename)}.json')
        with open(json_file, 'w') as fh:
            json.dump(ip_list, fh, indent=4, ensure_ascii=False)
        parent.ip_lists.add(iplist_name)
        parent.stepChanged.emit(f'NOTE|    Создан список IP-адресов "{ip_list["name"]}" и выгружен в файл "{json_file}".')

    return iplist_name


def get_time_restrictions(parent, time_restrictions, rule_name):
    """Проверяем что календарь существует. Возвращаем список только существующих календарей."""
    new_schedule = []
    for item in time_restrictions:
        if item in parent.time_restrictions:
            new_schedule.append(item)
        else:
            parent.stepChanged.emit(f'bRED|    Error! Правило "{rule_name}": Не найден календарь "{item}".')
    return new_schedule


def pack_ip_address(ip, mask):
    if ip == '0':
        ip = '0.0.0.0'
    if mask == '0':
        mask = '0.0.0.0'
    try:
        interface = ipaddress.ip_interface(f'{ip}/{mask}')
    except ValueError as err:
        return '10.10.10.1/32'
    return f'{ip}/{interface.network.prefixlen}'

def unpack_ip_address(iface):
    """Получаем данные в виде ip/mask (пример: 192.168.10.1/29)"""
    try:
        interface = ipaddress.ip_interface(iface)
        ipv4 = {'ip': f'{interface.ip}', 'mask': f'{interface.netmask}'}
    except ValueError as err:
        return 1, err
    return 0, ipv4

def get_restricted_name(name):
    """
    Получить имя объекта без запрещённых спецсимволов.
    Удаляется первый символ если он является разрешённым спецсимволом, т.к. запрещается делать первый символ спецсимволом.
    """
    if isinstance(name, str):
        new_name = name.translate(trans_name)
        if new_name[0] in ('_', '(', ')', ' ', '+', '-', ':', '/', ',', '.', '@'):
            new_name = new_name[1:]
            if new_name[0] in ('_', '(', ')', ' ', '+', '-', ':', '/', ',', '.', '@'):
                new_name = new_name[1:]
        return new_name
    else:
        return 'Name not valid'

def check_auth(parent):
    """Проверяем что авторизация не протухла. Если протухла, логинимся заново."""
    err = 0; msg = ''
    match parent.utm.ping_session()[0]:
        case 1:
            err, msg = parent.utm.connect()
        case 2:
            err, msg = parent.utm.login()
    if err:
        message_alert(parent, msg, '')
        return False
    else:
        return True

def message_inform(parent, title, message):
    """Общее информационное окно. Принимает родителя, заголовок и текст сообщения"""
    QMessageBox.information(parent, title, message, defaultButton=QMessageBox.StandardButton.Ok)

def message_question(parent, title, message):
    """Общее окно подтверждения. Принимает родителя, заголовок и текст сообщения"""
    result = QMessageBox.question(parent, title, message, defaultButton=QMessageBox.StandardButton.No)
    return 'yes' if result == QMessageBox.StandardButton.Yes else 'no'

def message_alert(parent, message, err):
    """Алерт при любых ошибках"""
    QMessageBox.critical(parent, "Ошибка!", f"{message}\n\n{err}", buttons=QMessageBox.StandardButton.Cancel)


def main(args):
    return 0

if __name__ == '__main__':
    import sys
    sys.exit(main(sys.argv))
