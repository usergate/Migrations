#!/usr/bin/env python
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
#-----------------------------------------------------------------------------
# common_func.py
# Общие функции (идентично для ug_ngfw_converter и universal_converter)
# Версия 2.7  03.04.2025
#

import os, json
from PyQt6.QtWidgets import QMessageBox


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


def read_json_file(parent, json_file_path, mode=0):
    """
    Читаем json-файл с конфигурацией.
    mode = 0 - ничего не печатается
    mode = 1 - печатается всё
    mode = 2 - печатаются ошибки формата файла
    """
    try:
        with open(json_file_path, "r") as fh:
            data = json.load(fh)
    except ValueError as err:
        if mode:
            parent.stepChanged.emit(f'RED|    JSONDecodeError: {err} "{json_file_path}".')
            parent.error = 1
        return 1, f'RED|    JSONDecodeError: {err} "{json_file_path}".'
    except json.JSONDecodeError as err:
        if mode:
            parent.stepChanged.emit(f'RED|    JSONDecodeError: {err} "{json_file_path}".')
            parent.error = 1
        return 1, f'RED|    JSONDecodeError: {err} "{json_file_path}".'
    except FileNotFoundError as err:
        if mode == 1:
            parent.stepChanged.emit(f'RED|    Error: Не найден файл "{json_file_path}" с сохранённой конфигурацией!')
            parent.error = 1
        return 2, f'bRED|    Error: Не найден файл "{json_file_path}" с сохранённой конфигурацией!'
    if not data:
        if mode == 1:
            parent.stepChanged.emit(f'GRAY|    Файл "{json_file_path}" пуст.')
        return 3, f'GRAY|    Файл "{json_file_path}" пуст.'
    return 0, data


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
