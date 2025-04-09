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
# common_classes.py
# Общие функции (идентично для ug_ngfw_converter и universal_converter)
# Версия 1.1  09.04.2025
#

import os, json
import ipaddress, pickle, uuid
from string import punctuation
from dataclasses import dataclass


@dataclass(kw_only=True, slots=True, frozen=True)
class BaseObject:
    """Используется при импорте в шаблон МС."""
    id: str
    template_id: str
    template_name: str


@dataclass(kw_only=True, slots=True, frozen=True)
class BaseAppObject:
    """Используется при импорте в шаблон МС."""
    id: str
    owner: str
    signature_id: int


class WriteBinFile():
    """Содержит метод записи в bin-файл для модулей get_temporary_data и get_mc_temporary_data"""
    def write_bin_file(self, data, bin_file_path='temporary_data.bin'):
        """Записываем bin-файл."""
        try:
            with open(bin_file_path, 'wb') as fh:
                pickle.dump(data, fh)
        except pickle.PickleError as err:
            self.stepChanged.emit(f'RED|    Error: Не удалось записать файл "{bin_file_path}" со служебной информацией.\n    {err}')
            return 1
        except PermissionError as err:
            self.stepChanged.emit(f'RED|    Error: Нет права доступа для записи файла "{bin_file_path}" со служебной информацией.')
            return 2
        return 0


class ReadWriteBinFile(WriteBinFile):
    """Содержит методы работы с bin-файлами для модулей импорта на NGFW и MC"""
    def read_bin_file(self, bin_file_path='temporary_data.bin'):
        """Читаем bin-файл."""
        try:
            with open(bin_file_path, 'rb') as fh:
                data = pickle.load(fh)
        except pickle.UnpicklingError as err:
            self.stepChanged.emit(f'RED|    Error: {err}. Файл со служебной информацией: "{bin_file_path}" повреждён!')
            return 1, 'RED'
        except FileNotFoundError as err:
            self.stepChanged.emit(f'RED|    Error: Не найден файл "{bin_file_path}" со служебной информацией!')
            return 2, 'RED'
        except EOFError:
            self.stepChanged.emit(f'RED|    Файл со служебной информацией "{bin_file_path}" пуст!')
            return 3, 'RED'
        return 0, data


class TransformObjectName():
    """Содержит метод для проверки имени объекта"""
    trans_object_name = {
        ord('\n'): None,
        ord('\t'): None,
        ord('\r'): None,
        ord('#'): None,
        ord('"'): None,
        ord("'"): None,
        ord('!'): None,
        ord('$'): None,
        ord('%'): None,
        ord('^'): None,
        ord('['): None,
        ord(']'): None,
        ord('{'): None,
        ord('}'): None,
        ord('*'): None,
        ord('~'): None,
        ord('<'): None,
        ord('>'): None,
        ord('='): '-',
        ord('?'): '_',
        ord(';'): ' ',
        ord('&'): ' and ',
        ord('|'): '-',
        ord('\\'): '_',
        65533: 'X',
    }


    @staticmethod
    def get_new_uuid():
        """Получить уникальный идентификатор"""
        return str(uuid.uuid4()).split('-')[4]


    def get_transformed_name(self, name, err=0, descr='Имя объекта', default_name=f'{get_new_uuid()} (Original name not valid)', mode=1):
        """
        Получить имя объекта без запрещённых спецсимволов.
        Удаляется первый символ если он является символом пуектуации, т.к. запрещается делать первый символ спецсимволом.
        Так же проверяется длина имени. Если оно более 64 символов, то обрезается до длины 64.
        """
        message = ''
        if isinstance(name, str):
            error64 = 0
            errorX = 0
            new_name = name.lstrip(punctuation)
            if not new_name:
                if mode:
                    message = f'RED|    Error: {descr} "{name}" не конвертировано, так как содержит одни спец.символы.\n'
                    self.stepChanged.emit(f'{message}       Новое {descr.lower()}: "{default_name}".')
                return 1, default_name
            if chr(65533) in new_name:
                errorX = 1
            new_name = new_name.translate(self.trans_object_name).strip()
            if len(new_name) > 64:
                new_name = new_name[:64]
                error64 = 1
            if error64 or errorX:
                if mode:
                    message = f'RED|    Error: {descr} "{name}".\n'
                    if error64:
                        message = f'{message}       {descr} имеет длину более 64 символов. Имя обрезано до 64 символов.\n'
                    if errorX:
                        message = f'{message}       {descr} содержит символы отсутствующие в кодировке ascii. Они заменены на символ "X".\n'
                    self.stepChanged.emit(f'{message}       Новое {descr.lower()}: "{new_name}".')
                err = 1
            return err, new_name
        else:
            if mode:
                message = f'RED|    Error: {descr} "{name}". Имя имеет не корректный тип.\n'
                self.stepChanged.emit(f'{message}       Новое {descr.lower()}: "{default_name}".')
            return 1, default_name


class MyMixedService(TransformObjectName):
    trans_userlogin = {
        ord('#'): None,
        ord('"'): None,
        ord("'"): None,
        ord('!'): None,
        ord('?'): None,
        ord('@'): None,
        ord(';'): None,
        ord('$'): None,
        ord('%'): None,
        ord('&'): None,
        ord('^'): None,
        ord('['): None,
        ord(']'): None,
        ord('{'): None,
        ord('}'): None,
        ord('*'): None,
        ord('~'): None,
        ord('<'): None,
        ord('>'): None,
        ord('='): None,
        ord('+'): None,
        ord('-'): None,
        ord(' '): None,
        ord('.'): None,
        ord('|'): None,
        ord('/'): None,
        ord('\\'): None,
        65533: 'X',
    }


    @staticmethod
    def unpack_ip_address(iface):
        """Принимаем данные в виде ip/mask (пример: 192.168.10.1/29)"""
        try:
            interface = ipaddress.ip_interface(iface)
            return 0, {'ip': f'{interface.ip}', 'mask': f'{interface.netmask}'}
        except ValueError as err:
            return 1, err


    def read_json_file(self, json_file_path, mode=0):
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
                self.stepChanged.emit(f'RED|    JSONDecodeError: {err} "{json_file_path}".')
                self.error = 1
            return 1, f'RED|    JSONDecodeError: {err} "{json_file_path}".'
        except json.JSONDecodeError as err:
            if mode:
                self.stepChanged.emit(f'RED|    JSONDecodeError: {err} "{json_file_path}".')
                self.error = 1
            return 1, f'RED|    JSONDecodeError: {err} "{json_file_path}".'
        except FileNotFoundError as err:
            if mode == 1:
                self.stepChanged.emit(f'RED|    Error: Не найден файл "{json_file_path}" с сохранённой конфигурацией!')
                self.error = 1
            return 2, f'bRED|    Error: Не найден файл "{json_file_path}" с сохранённой конфигурацией!'
        if not data:
            if mode == 1:
                self.stepChanged.emit(f'GRAY|    Файл "{json_file_path}" пуст.')
            return 3, f'GRAY|    Файл "{json_file_path}" пуст.'
        return 0, data


    def get_transformed_userlogin(self, user_login):
        """
        Получить валидный логин пользователя без запрещённых спецсимволов.
        Удаляется первый символ если он является символом пуектуации, т.к. запрещается делать первый символ спецсимволом.
        """
        if isinstance(user_login, str):
            errorX = 0
            new_userlogin = user_login.lstrip(punctuation)
            if not new_userlogin:
                message = f'RED|    Error: Логин "{user_login}" не конвертирован, так как содержит одни спец.символы.\n'
                self.stepChanged.emit(f'{message}       Логин заменён на "Login_not_valid".')
                return 'Login_not_valid'
            if chr(65533) in new_userlogin:
                errorX = 1
            new_userlogin = new_userlogin.translate(self.trans_userlogin).strip()
            if errorX:
                message = f'RED|    Error: Логин "{user_login}" содержит символы'
                message = f'{message} отсутствующие в кодировке ascii. Они заменены на символ "X".\n'
                self.stepChanged.emit(f'{message}       Логин заменён на "{new_userlogin}".')
            return new_userlogin
        else:
            return 'Login_not_valid'


class MyConv(MyMixedService):
    """Содержит общие методы для конвертеров сторонних вендоров"""
    app_proto = {k: k for k in ('ipip', 'gre', 'ah', 'skip', 'esp', 'pim', 'ospf', 'ggp', 'igp', 'egp', 'igmp', 'vrrp', 'mobility-header')}

    trans_table = {
        ord('\n'): None,
        ord('\t'): None,
        ord('\r'): None,
    }

    trans_filename = {
        ord('\n'): None,
        ord('\t'): None,
        ord('\r'): None,
        ord('#'): None,
        ord('='): '_',
        ord(':'): '_',
        ord('"'): None,
        ord("'"): None,
        ord('!'): '_',
        ord('?'): '_',
        ord('@'): '_',
        ord(';'): None,
        ord('$'): None,
        ord('%'): None,
        ord('&'): None,
        ord('^'): None,
        ord('['): None,
        ord(']'): None,
        ord('{'): None,
        ord('}'): None,
        ord('<'): None,
        ord('>'): None,
        ord('|'): None,
        ord('/'): None,
        ord('\\'): None,
    }

    @staticmethod
    def create_dir(path, delete='yes'):
        if not os.path.isdir(path):
            try:
                os.makedirs(path)
            except Exception as err:
                return 1, f'Ошибка создания каталога: {path} [{err}].'
            return 0, f'Создан каталог "{path}".'
        else:
            if delete == 'yes':
                for file_name in os.listdir(path):
                    os.remove(os.path.join(path, file_name))
            return 0, f'Каталог "{path}" уже существует.'


    def create_ip_list(self, ips=[], name=None, descr=None):
        """
        Создаём IP-лист для правила. Возвращаем имя ip-листа.
        В вызываемом модуле должна быть структура: self.ip_lists = set()
        """
        iplist_name = name if name else ips[0]
        err, iplist_name = self.get_transformed_name(iplist_name, descr='Имя списка IP-адресов')
        if iplist_name not in self.ip_lists:
            current_path = os.path.join(self.current_ug_path, 'Libraries', 'IPAddresses')
            err, msg = self.create_dir(current_path, delete='no')
            if err:
                self.stepChanged.emit(f'RED|    {msg}.')
                self.error = 1
                return 0

            ip_list = {
                'name': iplist_name,
                'description': descr if descr else '',
                'type': 'network',
                'url': '',
                'list_type_update': 'static',
                'schedule': 'disabled',
                'attributes': {'threat_level': 3},
                'content': [{'value': ip} for ip in ips]
            }

            json_file = os.path.join(current_path, f'{ip_list["name"].translate(self.trans_filename)}.json')
            with open(json_file, 'w') as fh:
                json.dump(ip_list, fh, indent=4, ensure_ascii=False)
            self.ip_lists.add(iplist_name)
            self.stepChanged.emit(f'NOTE|    Создан список IP-адресов "{ip_list["name"]}" и выгружен в файл "{json_file}".')

        return iplist_name


    @staticmethod
    def check_ip(ip):
        """
        Получаем данные в виде ip или ip/mask и проверяем что адрес действителен.
        Если нет ошибки, возвращаем 'ip/mask'. Если получили не валидный IP, возвращаем False.
        """
        try:
            interface = ipaddress.ip_interface(ip)
            return f'{ip}/{interface.network.prefixlen}'
        except ValueError as err:
            return False


    @staticmethod
    def pack_ip_address(ip, mask):
        """Получаем ip и маску (24, 255.255.255.0). Выдаём упакованный IP-адрес."""
        if ip == '0':
            ip = '0.0.0.0'
        if mask == '0':
            mask = '0.0.0.0'
        try:
            interface = ipaddress.ip_interface(f'{ip}/{mask}')
        except ValueError as err:
            return 1, err
        return 0, f'{ip}/{interface.network.prefixlen}'


    @staticmethod
    def ip_isglobal(ip):
        """
        Получаем ip-адрес и проверяем что он в глобальном адресном пространстве.
        Если нет ошибки, возвращаем True или False. Если получили не валидный IP, возвращаем ошибку.
        """
        try:
            ip_addr = ipaddress.ip_address(ip)
            return 0, ip_addr.is_global
        except ValueError as err:
            return 1, err


    @staticmethod
    def create_ug_services():
        ug_services = [
            {'name': 'DNS', 'description': 'Domain Name Service', 'protocols': [
                {'proto': 'udp', 'port': '53', 'app_proto': '', 'source_port': '', 'alg': ''},
                {'proto': 'tcp', 'port': '53', 'app_proto': '', 'source_port': '', 'alg': ''}]},
            {'name': 'HTTP', 'description': 'Hypertext Transport Protocol', 'protocols': [
                {'proto': 'tcp', 'port': '80', 'app_proto': '', 'source_port': '', 'alg': ''}]},
            {'name': 'HTTPS', 'description': 'Hypertext Transport Protocol over SSL', 'protocols': [
                {'proto': 'tcp', 'port': '443', 'app_proto': '', 'source_port': '', 'alg': ''}]},
            {'name': 'FTP', 'description': 'File Transfer Protocol', 'protocols': [
                {'proto': 'tcp', 'port': '20', 'app_proto': '', 'source_port': '', 'alg': ''},
                {'proto': 'tcp', 'port': '21', 'app_proto': '', 'source_port': '', 'alg': ''}]},
            {'name': 'IMAP', 'description': 'Internet Mail Access Protocol', 'protocols': [
                {'proto': 'tcp', 'port': '143', 'app_proto': '', 'source_port': '', 'alg': ''}]},
            {'name': 'IMAPS', 'description': 'Internet Mail Access Protocol over SSL', 'protocols': [
                {'proto': 'tcp', 'port': '993', 'app_proto': '', 'source_port': '', 'alg': ''}]},
            {'name': 'NTP', 'description': 'Network Time Protocol', 'protocols': [
                {'proto': 'udp', 'port': '123', 'app_proto': '', 'source_port': '', 'alg': ''}]},
            {'name': 'POP3', 'description': 'Post Office Protocol', 'protocols': [
                {'proto': 'pop3', 'port': '110', 'app_proto': 'pop3', 'source_port': '', 'alg': ''}]},
            {'name': 'POP3S', 'description': 'Post Office Protocol over SSL', 'protocols': [
                {'proto': 'pop3s', 'port': '995', 'app_proto': 'pop3s', 'source_port': '', 'alg': ''}]},
            {'name': 'Postgres SQL', 'description': '', 'protocols': [
                {'proto': 'tcp', 'port': '5432', 'app_proto': '', 'source_port': '', 'alg': ''}]},
            {'name': 'RDP', 'description': 'Remote Desktop Protocol', 'protocols': [
                {'proto': 'tcp', 'port': '3389', 'app_proto': '', 'source_port': '', 'alg': ''}]},
            {'name': 'SIP', 'description': 'Session Initiation Protocol', 'protocols': [
                {'proto': 'tcp', 'port': '5060-5061', 'app_proto': '', 'source_port': '', 'alg': ''},
                {'proto': 'udp', 'port': '5060', 'app_proto': '', 'source_port': '', 'alg': ''}]},
            {'name': 'SMTP', 'description': 'Simple Mail Transfer Protocol', 'protocols': [
                {'proto': 'smtp', 'port': '25', 'app_proto': 'smtp', 'source_port': '', 'alg': ''}]},
            {'name': 'SMTPS', 'description': 'Simple Mail Transfer Protocol over SSL', 'protocols': [
                {'proto': 'smtps', 'port': '465', 'app_proto': 'smtps', 'source_port': '', 'alg': ''}]},
            {'name': 'SNMP', 'description': 'Simple Network Management Protocol', 'protocols': [
                {'proto': 'tcp', 'port': '161', 'app_proto': '', 'source_port': '', 'alg': ''},
                {'proto': 'udp', 'port': '161', 'app_proto': '', 'source_port': '', 'alg': ''}]},
            {'name': 'SSH', 'description': 'Secure Shell', 'protocols': [
                {'proto': 'tcp', 'port': '22', 'app_proto': '', 'source_port': '', 'alg': ''}]},
            {'name': 'TFTP', 'description': 'Trivial File Transfer Protocol', 'protocols': [
                {'proto': 'udp', 'port': '69', 'app_proto': '', 'source_port': '', 'alg': ''}]},
            {'name': 'Rsync', 'description': '', 'protocols': [
                {'proto': 'tcp', 'port': '873', 'app_proto': '', 'source_port': '', 'alg': ''}]},
            {'name': 'pptp', 'description': 'Point-to-Point Tunneling Protocol, extension of PPP', 'protocols': [
                {'proto': 'tcp', 'port': '1723', 'app_proto': '', 'source_port': '', 'alg': ''}]},
        ]
        for item in {'tcp', 'udp', 'sctp', 'icmp', 'ipv6-icmp', 'gre', 'ipip'}:
            ug_services.append({
                'name': f'Any {item.upper()}',
                'description': f'Any {item.upper()} packet',
                'protocols': [{'proto': item, 'port': '', 'app_proto': '', 'source_port': '', 'alg': ''}]
            })
        return ug_services

