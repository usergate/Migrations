#!/usr/bin/python3
#
# dhcp_subnet (migrating DHCP configuration from one NGFW UserGate to another).
#
# Copyright @ 2020-2022 UserGate Corporation. All rights reserved.
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
# Программа предназначена для переноса конфигурации DHCP с одного NGFW UserGate на другой.
# Версия 1.0
#
import sys
import os
import stdiomask
import json
from utm import UtmXmlRpc, UtmError


class UTM(UtmXmlRpc):
    def __init__(self, server_ip, login, password):
        super().__init__(server_ip, login, password)
        self._connect()

    def export_dhcp_subnets(self):
        """Выгрузить список DHCP"""
        print('Выгружаются настройки "DHCP":')
        if not os.path.isdir('data'):
            os.makedirs('data')

        _, data = self.get_dhcp_list()

        with open("data/config_dhcp_subnets.json", "w") as fd:
            json.dump(data, fd, indent=4, ensure_ascii=False)
        print(f"\tСписок подсетей DHCP выгружен в файл 'config_dhcp_subnets.json'.")

    def import_dhcp_subnet(self):
        """Добавить DHCP subnet на UTM"""
        print("Импорт DHCP subnets:")
        try:
            with open("data/config_dhcp_subnets.json", "r") as fd:
                subnets = json.load(fd)
        except FileNotFoundError as err:
            raise UtmError(f"\nОшибка: [FileNotFoundError] Не найден файл 'config_dhcp_subnets.json' с сохранённой конфигурацией!")

        _, data = self.get_interfaces_list()
        dst_ports = [x['name'] for x in data if not x['name'].startswith('tunnel')]

        _, data = self.get_dhcp_list()
        old_dhcp_subnets = [x['name'] for x in data]

        for item in subnets:
            if item['name'] in old_dhcp_subnets:
                print(f'\tDHCP subnet "{item["name"]}" уже существует!')
                continue
            elif item['name'] == "":
                item['name'] = "No Name subnet" 
            if item['iface_id'] not in dst_ports:
                print(f'\n\033[36mВы добавляете DHCP subnet\033[0m "{item["name"]}" \033[36mна несуществующий порт: \033[33m{item["iface_id"]}\033[0m')
                print(f'\033[36mСуществуют следующие порты:\033[0m {sorted(dst_ports)}')
                while True:
                    port = input("\n\033[36mВведите имя порта: \033[0m")
                    if port not in dst_ports:
                        print("\033[31mВы ввели несуществующий порт.\033[0m")
                    else:
                        break
                item['iface_id'] = port
            if "cc" in item.keys():
                item.pop("cc")
                item.pop("node_name")

            err, result = self.add_dhcp_subnet(item)
            print(f'\033[31m{result}\033[0m') if err else print(f'\tSubnet "{item["name"]}" добавлен.')


def main():
    try:
        print("\033c")
        print(f"\033[1;36;43mUserGate\033[1;37;43m                          Экспорт / Импорт настроек DHCP                   \033[1;36;43mUserGate\033[0m\n")
        print("\033[32mПрограмма экспортирует настройки DHCP UTM в файл json в каталог 'data' в текущей директории.")
        print("Вы можете изменить содержимое данного файла и импортировать в другое устройство UTM.\033[0m\n")
        print("1  - Экспортировать список подсетей DHCP.")
        print("2  - Импортировать список подсетей DHCP.")
        print("0  - Выход.")

        command = 0
        while True:
            try:
                command = int(input("\nВведите номер нужной операции: "))
                if command not in [0, 1, 2]:
                    print("Вы ввели несуществующую команду.")
                elif command == 0:
                    sys.exit()
                else:
                    break
            except ValueError:
                print("Ошибка! Введите число.")

        server_ip = input("Введите IP-адрес UTM: ")
        login = input("Введите логин администратора UTM: ")
        password = stdiomask.getpass("Введите пароль: ")

        utm = UTM(server_ip, login, password)
        try:
            if command == 1:
                utm.export_dhcp_subnets()
            elif command == 2:
                utm.import_dhcp_subnet()
        except UtmError as err:
            print(err)
        except Exception as err:
            print(f'\nОшибка: {err} (Node: {server_ip}).')
        finally:
            utm.logout()
    except KeyboardInterrupt:
        print("\nПрограмма принудительно завершена пользователем.")

if __name__ == '__main__':
    main()
