#!/usr/bin/python3
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
# universal_converter.py
# Version 8.11    11.04.2025
#--------------------------------------------------------------------------------------------------- 
#
import os, sys
from PyQt6.QtGui import QIcon
from PyQt6.QtWidgets import QApplication, QMainWindow, QWidget, QStackedLayout
import vizard_classes as vc
from common_func import create_dir, message_alert


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Перенос конфигурации сторонних вендоров на UserGate (version 8.11)")
        ico = QIcon("favicon.png")
#        ico = QIcon(os.path.join(sys._MEIPASS, "favicon.png")) # для PyInstaller
        self.setWindowIcon(ico)
        self._base_bluecoat_path = 'data_blue_coat'
        self._base_asa_path = 'data_cisco_asa'
        self._base_fpr_path = 'data_cisco_fpr'
        self._base_cp_path = 'data_checkpoint'
        self._base_fort_path = 'data_fortigate'
        self._base_huawei_path = 'data_huawei'
        self._base_mikrotik_path = 'data_mikrotik'
        self._current_ug_path = None    # Полный путь к каталогу с конфигурацией узла UG NGFW

        self.stacklayout = QStackedLayout()
        self.stacklayout.addWidget(vc.SelectAction(self))
        self.stacklayout.addWidget(vc.SelectExportMode(self))
        self.stacklayout.addWidget(vc.SelectImportMode(self))
        self.stacklayout.addWidget(vc.SelectMcImportMode(self))

        main_widget = QWidget()
        main_widget.setLayout(self.stacklayout)
        self.setCentralWidget(main_widget)

        # Создаём базовые каталоги вендоров и UG в текущей директории. Если успешно, активируем кнопки экспорта/импорта.
        err, msg = create_dir(self.base_ug_path, delete='no')
        if err:
            message_alert(self, msg, '')
        else:
            create_dir(self._base_bluecoat_path, delete='no')
            create_dir(self._base_asa_path, delete='no')
            create_dir(self._base_fpr_path, delete='no')
            create_dir(self._base_cp_path, delete='no')
            create_dir(self._base_fort_path, delete='no')
            create_dir(self._base_huawei_path, delete='no')
            create_dir(self._base_mikrotik_path, delete='no')
            self.stacklayout.widget(0).enable_buttons()

    @property
    def base_ug_path(self):
        """Получаем имя базового каталога конфигураций UG NGFW"""
        return 'data_usergate'

    def get_vendor_base_path(self, vendor):
        """Получаем имя базового каталога конфигураций выбранного вендора"""
        match vendor:
            case 'Blue Coat':
                return self._base_bluecoat_path
            case 'Cisco ASA':
                return self._base_asa_path
            case 'Cisco FPR':
                return self._base_fpr_path
            case 'Check Point':
                return self._base_cp_path
            case 'Fortigate':
                return self._base_fort_path
            case 'Huawei':
                return self._base_huawei_path
            case 'MikroTik':
                return self._base_mikrotik_path

    def get_ug_config_path(self):
        """Получаем путь к каталогу с конфигурацией выбранного устройсва UG NGFW"""
        return self._current_ug_path

    def set_ug_config_path(self, directory):
        """Запоминаем путь к каталогу с конфигурацией выбранного устройсва UG NGFW"""
        self._current_ug_path = os.path.join(self.base_ug_path, directory)

    def del_ug_config_path(self):
        """Удаляем путь к каталогу с конфигурацией выбранного устройсва UG NGFW"""
        self._current_ug_path = None

    def closeEvent(self, event):
        """
        При закрытии программы:
        1. Удаляем временный файл: temporary_data.bin
        2. Делаем logout с NGFW или МС если ранее был login
        """
        if os.path.isfile('temporary_data.bin'):
            os.remove('temporary_data.bin')
        for i in (2, 3):
            if self.stacklayout.widget(i).utm:
                self.stacklayout.widget(i).utm.logout()
                break

def main():
    app = QApplication([])
    window = MainWindow()
    window.show()
    app.exec()

if __name__ == '__main__':
    main()
