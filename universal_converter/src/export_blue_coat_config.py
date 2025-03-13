#!/usr/bin/python3
#
# export_cisco_fpr_config.py (convert configuration from Cisco FPR to NGFW UserGate).
#
# Copyright @ 2021-2022 UserGate Corporation. All rights reserved.
# Author: Aleksei Remnev <ran1024@yandex.ru>
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
#--------------------------------------------------------------------------------------------------- 
# Модуль предназначен для выгрузки конфигурации Blue Coat в формат json NGFW UserGate.
# Версия 1.2  12.03.2025
#

import os, sys, json, re, time
import common_func as func
from PyQt6.QtCore import QThread, pyqtSignal
from services import trans_table, trans_filename, ug_services, ServicePorts, service_ports

pattern_proxy = re.compile(r"<[Pp][Rr][Oo][Xx][Yy] +'(.+)'>(?: +condition=(.+)){0,1}")
pattern_rule = re.compile(r"ALLOW|;ALLOW|DENY|;DENY", flags=re.IGNORECASE)

trans_foo = str.maketrans({'(': None, ')': None, ' ': None, '"': None, "'": None})

class ConvertBlueCoatConfig(QThread):
    """Преобразуем файл конфигурации BlueCoat в формат UserGate NGFW."""
    stepChanged = pyqtSignal(str)
    
    def __init__(self, current_bluecoat_path, current_ug_path):
        super().__init__()
        self.current_vendor_path = current_bluecoat_path
        self.current_ug_path = current_ug_path
        self.ip_lists = set()
        self.url_lists = set()
        self.services = set()
        self.error = 0

    def run(self):
        self.stepChanged.emit(f'GREEN|{"Конвертация конфигурации BlueCoat в формат UserGate NGFW.":>110}')
        self.stepChanged.emit(f'ORANGE|{"="*110}')

        convert_config_file(self, self.current_vendor_path)
        
        json_file = os.path.join(self.current_vendor_path, 'config.json')
        err, data = func.read_json_file(self, json_file)
        if err:
            self.error = 1
        else:
            convert_ip_lists(self, self.current_ug_path, data)
            convert_url_lists(self, self.current_ug_path, data)
            convert_services_list(self, self.current_ug_path, data)
            convert_time_restrictions(self, self.current_ug_path, data)
            convert_firewall_rules(self, self.current_ug_path, data)

        if self.error:
            self.stepChanged.emit('iORANGE|Конвертация конфигурации BlueCoat в формат UserGate NGFW прошла с ошибками.\n')
        else:
            self.stepChanged.emit('iGREEN|Конвертация конфигурации BlueCoat в формат UserGate NGFW прошла успешно.\n')


def parse_rule(block):
    """Парсинг rule"""
    new_block = []
    for item in block:
        pass
    return new_block


def parse_condition_block(block):
    new_block = {'description': set(), 'ip_list': [], 'url_list': []}
    for item in block:
        x, _, description = item.partition(';')
        if description:
            new_block['description'].add(description)
        key, value = x.split('=')
        if key == 'client.address':
            new_block['ip_list'].append(value.strip())
        elif key == 'url.domain':
            new_block['url_list'].append(value.strip())
    new_block['description'] = ', '.join(new_block['description'])
    return new_block


def convert_config_file(parent, path):
    """Преобразуем файл конфигурации BlueCoat в json."""
    parent.stepChanged.emit('BLUE|Преобразование файла конфигурации BlueCoat в json.')
    if not os.path.isdir(path):
        parent.stepChanged.emit('RED|    Не найден каталог с конфигурацией BlueCoat.')
        parent.error = 1
        return
    error = 0
    config_file_path = os.path.join(path, 'bluecoat.cfg')

    config_data = []
    try:
        with open(config_file_path, "r") as fh:
            line = fh.readline()
            while line:
                line = line.translate(trans_table).strip().replace('"', "'")
                if line:
                    config_data.append(line)
                line = fh.readline()
            config_data.append('')
    except FileNotFoundError:
        parent.stepChanged.emit(f'RED|    Не найден файл "{config_file_path}" с конфигурацией BlueCoat.')
        parent.error = 1
        return

    # удалить по итогу
#    json_file = os.path.join(path, 'tmp_config.json')
#    with open(json_file, "w") as fh:
#        json.dump(config_data, fh, indent=4, ensure_ascii=False)

    data = {'conditions': {},}
    key = None
    num = 0
    while (len(config_data) - num):
        line = config_data[num]
        if line[:6].lower() == '<proxy':
            result = pattern_proxy.findall(line)
            key = result[0][0]
            data[key] = {'condition': result[0][1]}
            rule_block = []
            num += 1
            line = config_data[num]
            while (line.startswith(';') or pattern_rule.match(line)):
                if pattern_rule.match(line):
                    rule_block.append(line)
                num += 1
                line = config_data[num]
            data[key]['rules'] = rule_block
            num -= 1
        elif line.startswith('define'):
            _, _, def_name = line.split(' ')
            def_block = []
            while config_data[num] != 'end':
                num += 1
                def_block.append(config_data[num])
            data['conditions'][def_name] = parse_condition_block(def_block[:-1])
        num += 1

    make_firewall_rules(parent, data)

    json_file = os.path.join(path, 'config.json')
    with open(json_file, "w") as fh:
        json.dump(data, fh, indent=4, ensure_ascii=False)

    if error:
        parent.stepChanged.emit('ORANGE|    Ошибка экспорта конфигурации BlueCoat в формат json.')
    else:
        parent.stepChanged.emit(f'BLACK|    Конфигурация BlueCoat в формате json выгружена в файл "{json_file}".')


def make_firewall_rules(parent, data):
    pattern_action = re.compile(r'(ALLOW|;ALLOW|DENY|;DENY)', flags=re.IGNORECASE)
    pattern_srcips = re.compile(r"(?<=client\.address=)\([\d, \.\/]+\)|(?<=client\.address=)[^ ]+")
    pattern_dstips = re.compile(r"(?<=url\.address=)\([\d, \.//]+\)|(?<=url\.address=)\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")
    pattern_dsturl = re.compile(r"(?<=url\.domain=)(\([\w, \.-]+\))|(?<=url\.domain=) ?[^ ]+")
    pattern_timeset = re.compile(r"(?<=date=)[^ ]+")
    pattern_condition = re.compile(r"(?<=condition=)[^ ]+")
    pattern_user = re.compile(r"(?<=user=)(\([\w, \"\'\\]+\))|(?<=user=)[^ ]+")
    pattern_descr = re.compile(r"(?<=;\[)[^;]+")
    pattern_proxy_port = re.compile(r"(?<=proxy\.port=)(\([\w, ]+\))|(?<=proxy\.port=)\d+")
    pattern_url_port = re.compile(r"(?<=url\.port=)\d+")
    pattern_proto = re.compile(r"(?<=client\.protocol=)(\([\w, ]+\))|(?<=client\.protocol=)[^ ]+")
    pattern_category = re.compile(r"(?<=category=)(\([\w, \.-//]+\))|(?<=category=)[^ ]+")

    rules = []
    rule_keys = []
    for key, value in data.items():
        n = 0
        if key != 'conditions':
            rule_keys.append(key)
            ext_ips = value['condition'] if value['condition'] else ''
            for item in value['rules']:
                n += 1
                descr = pattern_descr.search(item)
                rule = {'name': f'{key}-{n}', 'description': descr.group().replace(']', '') if descr else '', 'ext_ips': ext_ips}
                action = pattern_action.match(item).group().lower()
                if action.startswith(';'):
                    action = action[1:]
                    rule['enabled'] = False
                else:
                    rule['enabled'] = True
                
                if (category := pattern_category.search(item)):
                    rule['description'] = f'{rule["description"]}\nНе конвертированы категории: {category.group()}.'
                    rule['enabled'] = False

                rule['action'] = 'accept' if action == 'allow' else 'drop'
                rule['src_ips'] = srcips.group().translate(trans_foo).split(',') if (srcips := pattern_srcips.search(item)) else []
                rule['dst_ips'] = dstips.group().translate(trans_foo).split(',') if (dstips := pattern_dstips.search(item)) else []
                rule['dst_url'] = dsturl.group().translate(trans_foo).split(',') if (dsturl := pattern_dsturl.search(item)) else []
                rule['ext_url'] = exturl.group() if (exturl := pattern_condition.search(item)) else ''
                rule['users'] = user.group().translate(trans_foo).split(',') if (user := pattern_user.search(item)) else []
                rule['time_restrictions'] = timeset.group() if (timeset := pattern_timeset.search(item)) else ''
                proxy_port = port.group().translate(trans_foo).split(',') if (port := pattern_proxy_port.search(item)) else []
                url_port = port.group().translate(trans_foo).split(',') if (port := pattern_url_port.search(item)) else []
                rule['services'] = url_port if url_port else proxy_port
                rule['service_proto'] = proto.group().translate(trans_foo).split(',') if (proto := pattern_proto.search(item)) else []
                rules.append(rule)
    for key in rule_keys:
        data.pop(key)
    data['rules'] = rules


def convert_ip_lists(parent, path, data):
    """Конвертируем списки IP-адресов"""
    parent.stepChanged.emit('BLUE|Конвертация списков IP-адресов.')
    section_path = os.path.join(path, 'Libraries')
    current_path = os.path.join(section_path, 'IPAddresses')
    err, msg = func.create_dir(current_path)
    if err:
        parent.stepChanged.emit('RED|    {msg}.')
        parent.error = 1
        return
    error = 0

    if (conditions := data.get('conditions', None)):
        error += convert_ip_lists_from_conditions(parent, current_path, conditions)
    if (rules := data.get('rules', None)):
        error += convert_ip_lists_from_rules(parent, current_path, rules)

    if parent.ip_lists:
        if error:
            parent.error = 1
            parent.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте списков IP-адресов.')
        else:
            parent.stepChanged.emit(f'GREEN|    Списки IP-адресов выгружены в каталог "{current_path}".')
    else:
        parent.stepChanged.emit('GRAY|    Нет списков IP-адресов для экспорта.')


def convert_ip_lists_from_conditions(parent, current_path, conditions):
    """Конвертируем списки IP-адресов из conditions"""
    error = 0
    for key, value in conditions.items():
        if value['ip_list']:
            error, iplist_name = func.get_transformed_name(parent, key, err=error, descr='Имя списка IP-адресов')
            ip_list = {
                'name': iplist_name,
                'description': f"Портировано с BlueCoat.\n{value.get('description', '')}",
                'type': 'network',
                'url': '',
                'list_type_update': 'static',
                'schedule': 'disabled',
                'attributes': {
                    'threat_level': 3
                },
                'content': [{'value': ip} for ip in value['ip_list']]
            }
            parent.ip_lists.add(ip_list['name'])
            json_file = os.path.join(current_path, f'{ip_list["name"].translate(trans_filename)}.json')
            with open(json_file, "w") as fh:
                json.dump(ip_list, fh, indent=4, ensure_ascii=False)
            parent.stepChanged.emit(f'BLACK|    Список IP-адресов "{ip_list["name"]}" выгружен в файл "{json_file}".')
            time.sleep(0.01)
    return error


def convert_ip_lists_from_rules(parent, current_path, rules):
    """Конвертируем списки IP-адресов из data[rules]"""
    error = 0
    hash_dict = {}

    for rule in rules:
        indicators = []
        if rule['src_ips']:
            indicators.append('src_ips')
        if rule['dst_ips']:
            indicators.append('dst_ips')

        for mode in indicators:
            hash_value = hash(tuple(rule[mode]))
            if len(rule[mode]) == 1:
                iplist_name = rule[mode][0]
            else:
                error, iplist_name = func.get_transformed_name(parent, rule['name'], err=error, descr='Имя списка IP-адресов')
            if iplist_name in parent.ip_lists:
                rule[mode] = [['list_id', iplist_name]]
            elif hash_value in hash_dict:
                rule[mode] = [['list_id', hash_dict[hash_value]]]
            else:
                hash_dict[hash_value] = iplist_name
                ip_list = {
                    'name': iplist_name,
                    'description': 'Портировано с BlueCoat.',
                    'type': 'network',
                    'url': '',
                    'list_type_update': 'static',
                    'schedule': 'disabled',
                    'attributes': {
                        'threat_level': 3
                    },
                    'content': [{'value': ip} for ip in rule[mode]]
                }
                parent.ip_lists.add(iplist_name)
                rule[mode] = [['list_id', iplist_name]]

                json_file = os.path.join(current_path, f'{iplist_name.translate(trans_filename)}.json')
                with open(json_file, "w") as fh:
                    json.dump(ip_list, fh, indent=4, ensure_ascii=False)
                parent.stepChanged.emit(f'BLACK|    Список IP-адресов "{ip_list["name"]}" выгружен в файл "{json_file}".')
                time.sleep(0.01)
    return error


def convert_url_lists(parent, path, data):
    """Конвертируем списки URL"""
    parent.stepChanged.emit('BLUE|Конвертация списков URL.')
    section_path = os.path.join(path, 'Libraries')
    current_path = os.path.join(section_path, 'URLLists')
    err, msg = func.create_dir(current_path)
    if err:
        parent.stepChanged.emit('RED|    {msg}.')
        parent.error = 1
        return
    error = 0

    if (conditions := data.get('conditions', None)):
        error += convert_url_lists_from_conditions(parent, current_path, conditions)
    if (rules := data.get('rules', None)):
        error += convert_url_lists_from_rules(parent, current_path, rules)

    if parent.url_lists:
        if error:
            parent.error = 1
            parent.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте списков URL.')
        else:
            parent.stepChanged.emit(f'GREEN|    Списки URL выгружены в каталог "{current_path}".')
    else:
        parent.stepChanged.emit('GRAY|    Нет списков URL для экспорта.')


def convert_url_lists_from_conditions(parent, current_path, conditions):
    """Конвертируем списки URL из conditions"""
    error = 0
    for key, value in conditions.items():
        if value['url_list']:
            error, urllist_name = func.get_transformed_name(parent, key, err=error, descr='Имя списка URL')
            url_list = {
                'name': urllist_name,
                'description': f"Портировано с BlueCoat.\n{value.get('description', '')}",
                'type': 'url',
                'url': '',
                'list_type_update': 'static',
                'schedule': 'disabled',
                'attributes': {
                    'list_complile_type': 'case_insensitive'
                },
                'content': [{'value': url} for url in value['url_list']]
            }
            parent.url_lists.add(url_list['name'])
            json_file = os.path.join(current_path, f'{url_list["name"].translate(trans_filename)}.json')
            with open(json_file, "w") as fh:
                json.dump(url_list, fh, indent=4, ensure_ascii=False)
            parent.stepChanged.emit(f'BLACK|    Список URL "{url_list["name"]}" выгружен в файл "{json_file}".')
            time.sleep(0.01)
    return error


def convert_url_lists_from_rules(parent, current_path, rules):
    """Конвертируем списки URL из data[rules]"""
    error = 0
    hash_dict = {}

    for rule in rules:
        if rule['dst_url']:
            hash_value = hash(tuple(rule['dst_url']))
            if len(rule['dst_url']) == 1:
                error, urllist_name = func.get_transformed_name(parent, rule['dst_url'][0], err=error, descr='Имя списка URL')
            else:
                error, urllist_name = func.get_transformed_name(parent, rule['name'], err=error, descr='Имя списка URL')
            if urllist_name in parent.url_lists:
                rule['dst_url'] = [['urllist_id', urllist_name]]
            elif hash_value in hash_dict:
                rule['dst_url'] = [['urllist_id', hash_dict[hash_value]]]
            else:
                url_list = {
                    'name': urllist_name,
                    'description': 'Портировано с BlueCoat.',
                    'type': 'url',
                    'url': '',
                    'list_type_update': 'static',
                    'schedule': 'disabled',
                    'attributes': {
                        'list_complile_type': 'case_insensitive'
                    },
                    'content': [{'value': url} for url in rule['dst_url']]
                }
                hash_dict[hash_value] = urllist_name
                parent.url_lists.add(urllist_name)
                rule['dst_url'] = [['urllist_id', urllist_name]]

                json_file = os.path.join(current_path, f'{urllist_name.translate(trans_filename)}.json')
                with open(json_file, "w") as fh:
                    json.dump(url_list, fh, indent=4, ensure_ascii=False)
                parent.stepChanged.emit(f'BLACK|    Список URL "{url_list["name"]}" выгружен в файл "{json_file}".')
                time.sleep(0.01)
    return error


def convert_services_list(parent, path, data):
    """Конвертируем список сервисов"""
    parent.stepChanged.emit('BLUE|Конвертация списка сервисов.')
    services_list = func.create_ug_services()

    if (rules := data.get('rules', None)):
        services_list.extend(convert_services_from_rules(parent, rules))

    if services_list:
        section_path = os.path.join(path, 'Libraries')
        current_path = os.path.join(section_path, 'Services')
        err, msg = func.create_dir(current_path)
        if err:
            parent.stepChanged.emit('RED|    {msg}.')
            parent.error = 1
            return

        json_file = os.path.join(current_path, 'config_services_list.json')
        with open(json_file, "w") as fh:
            json.dump(services_list, fh, indent=4, ensure_ascii=False)
        parent.stepChanged.emit(f'GREEN|    Список сервисов выгружен в файл "{json_file}".')
    else:
        parent.stepChanged.emit('GRAY|    Нет сервисов для экспорта.')


def convert_services_from_rules(parent, rules):
    """Конвертируем список сервисов из правил firewall"""
    services_list = []

    for rule in rules:
        if rule['services']:
            new_services = []
            for service_port in rule['services']:
                if service_port in ug_services:
                    service_name = ug_services[service_port]
                    new_services.append(service_name)
                else:
                    service_name = ServicePorts.get_name_by_port('tcp', service_port, service_port)
                    if service_name in parent.services:
                        new_services.append(service_name)
                    else:
                        services_list.append({
                            'name': service_name,
                            'description': 'Портировано с BlueCoat.',
                            'protocols': [
                                {
                                    'proto': 'tcp',
                                    'port': service_port,
                                    'app_proto': '',
                                    'source_port': '',
                                    'alg': ''
                                }
                            ]
                        })
                        new_services.append(service_name)
                        parent.services.add(service_name)
                        parent.stepChanged.emit(f'BLACK|    Создан сервис {service_name}".')
            rule['services'] = [['service', x] for x in new_services]
        if rule['service_proto']:
            new_services = []
            for item in rule['service_proto']:
                item = item.lower()
                if item in ug_services:
                    service_name = ug_services[item]
                    new_services.append(service_name)
                elif item in parent.services:
                    new_services.append(item)
                else:
                    try:
                        service_port = service_ports[item]
                    except KeyError as err:
                        parent.stepChanged.emit(f'RED|    Error: [Правило "{rule["name"]}"]. Не создан сервис "{item}" так как для него неизвестен порт.')
                        continue

                    services_list.append({
                        'name': item,
                        'description': 'Портировано с BlueCoat.',
                        'protocols': [
                            {
                                'proto': 'tcp',
                                'port': service_port,
                                'app_proto': '',
                                'source_port': '',
                                'alg': ''
                            }
                        ]
                    })
                    new_services.append(item)
                    parent.services.add(item)
                    parent.stepChanged.emit(f'BLACK|    Создан сервис {item}".')
            rule['services'] = [['service', x] for x in new_services]
        rule.pop('service_proto', None)
        time.sleep(0.01)
    return services_list


def convert_time_restrictions(parent, path, data):
    """Конвертируем календари"""
    parent.stepChanged.emit('BLUE|Конвертация календарей.')
    calendars = []
    time_set_names = set()

    if (rules := data.get('rules', None)):
        for rule in rules:
            if rule['time_restrictions']:
                schedule = rule['time_restrictions'].replace('..', '-')
                if schedule not in time_set_names:
                    start, end = schedule.split('-')
                    time_set = {
                        'name': schedule,
                        'description': 'Портировано с BlueCoat.',
                        'type': 'timerestrictiongroup',
                        'url': '',
                        'list_type_update': 'static',
                        'schedule': 'disabled',
                        'attributes': {},
                        'content': [
                            {
                                'name': schedule,
                                'type': 'span',
                                'time_from': '00:00',
                                'time_to': '24:00',
                                'fixed_date_from': f'{start[:4]}-{start[4:6]}-{start[6:]}T00:00:00',
                                'fixed_date_to': f'{end[:4]}-{end[4:6]}-{end[6:]}T00:00:00'
                            }
                        ]
                    }
                    calendars.append(time_set)
                    time_set_names.add(schedule)
                rule['time_restrictions'] = [schedule]

    if calendars:
        section_path = os.path.join(path, 'Libraries')
        current_path = os.path.join(section_path, 'TimeSets')
        err, msg = func.create_dir(current_path)
        if err:
            parent.stepChanged.emit('RED|    {msg}.')
            parent.error = 1
            return

        json_file = os.path.join(current_path, 'config_calendars.json')
        with open(json_file, "w") as fh:
            json.dump(calendars, fh, indent=4, ensure_ascii=False)
        parent.stepChanged.emit(f'GREEN|    Список календарей выгружен в файл "{json_file}".')
    else:
        parent.stepChanged.emit('GRAY|    Нет календарей для экспорта.')


def convert_firewall_rules(parent, path, data):
    """Конвертируем правила межсетевого экрана"""
    parent.stepChanged.emit('BLUE|Конвертация правил межсетевого экрана.')
    if not data.get('rules', None):
        parent.stepChanged.emit('GRAY|    Нет правил межсетевого экрана для экспорта.')
        return

    error = 0
    n = 0
    for item in data['rules']:
        error, item['name'] = func.get_transformed_name(parent, item['name'], err=error, descr='Имя правила МЭ')
        item['description'] = f'Портировано с BlueCoat.\n{item["description"]}'
        item['scenario_rule_id'] = False
        item['src_zones'] = []
        item['dst_zones'] = []
        if item['ext_ips']:
            item['src_ips'].append(['list_id', item['ext_ips']])
        if item['dst_url']:
            item['dst_ips'].extend(item['dst_url'])
        if item['ext_url']:
            item['dst_ips'].append(['urllist_id', item['ext_url']])
        item['users'] = [['user', x] for x in item['users']]
        item['limit'] = True
        item['limit_value'] = '3/h'
        item['limit_burst'] = 5
        item['log'] = True
        item['log_session_start'] = True
        item['src_zones_nagate'] = False
        item['dst_zones_nagate'] = False
        item['src_ips_nagate'] = False
        item['dst_ips_nagate'] = False
        item['services_nagate'] = False
        item['fragmented'] = 'ignore'
        item['send_host_icmp'] = 'tcp-rst'
        item['position_layer'] = 'local'
        item['ips_profile'] = False
        item['l7_profile'] = False
        item['hip_profiles'] = []

        item.pop('ext_ips')
        item.pop('dst_url')
        item.pop('ext_url')
        n += 1
        parent.stepChanged.emit(f'BLACK|    {n} - Создано правило межсетевого экрана "{item["name"]}".')
        time.sleep(0.01)

        if not item['dst_ips'] and not item['src_ips'] and not item['services'] and not item['users'] and item['action'] == 'accept':
            rule['enabled'] = False
            item['description'] = f'{item["description"]}\nОтключено так как в разрешающем правиле все поля пустые (нет адресов источника и назначения трафика).'
            parent.stepChanged.emit(f'NOTE|       Warning: Правило "{item["name"]}" отключено так как в разрешающем правиле все поля пустые (нет адресов источника и назначения трафика).')

    section_path = os.path.join(path, 'NetworkPolicies')
    current_path = os.path.join(section_path, 'Firewall')
    err, msg = func.create_dir(current_path)
    if err:
        parent.stepChanged.emit('RED|    {msg}.')
        parent.error = 1
        return

    json_file = os.path.join(current_path, 'config_firewall_rules.json')
    with open(json_file, "w") as fh:
        json.dump(data['rules'], fh, indent=4, ensure_ascii=False)

    if error:
        parent.error = 1
        parent.stepChanged.emit(f'ORANGE|    Конвертация правил МЭ прошла с ошибками. Список правил межсетевого экрана выгружен в файл "{json_file}".')
    else:
        parent.stepChanged.emit(f'GREEN|    Список правил межсетевого экрана выгружен в файл "{json_file}".')

#####################################################################################################

def main(args):
    return 0

if __name__ == '__main__':
    import sys
    sys.exit(main(sys.argv))
