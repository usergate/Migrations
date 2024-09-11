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
# ug_universal_converter.py
# Version 2.5
#--------------------------------------------------------------------------------------------------- 
#
import os, sys, json
from PyQt6.QtGui import QIcon
from PyQt6.QtCore import QSize, Qt, QObject
from PyQt6.QtWidgets import QApplication, QMainWindow, QWidget, QStackedLayout
import vizard_classes as vc
import common_func as func


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Экспорт/Импорт конфигурации UG NGFW (version 2.5)")
        ico = QIcon("favicon.png")
        self.setWindowIcon(ico)
        self._base_path = os.getcwd()
        self._base_config_path = 'data'
        self._current_config_path = None    # Полный путь к каталогу с конфигурацией данного узла

        self.stacklayout = QStackedLayout()
        self.stacklayout.addWidget(vc.SelectAction(self))
        self.stacklayout.addWidget(vc.SelectExportMode(self))
        self.stacklayout.addWidget(vc.SelectImportMode(self))
        self.stacklayout.addWidget(vc.SelectMcImportMode(self))

        main_widget = QWidget()
        main_widget.setLayout(self.stacklayout)
        self.setCentralWidget(main_widget)

        # Создаём каталог data в текущей директории. Если успешно, активируем кнопки экспорта/импорта.
        err, msg = func.create_dir(self._base_config_path, delete='no')
        if err:
            func.message_alert(self, msg, '')
        else:
            self.stacklayout.widget(0).enable_buttons()

    def get_base_config_path(self):
        """Получаем имя базового каталога конфигураций"""
        return self._base_config_path

    def get_config_path(self):
        """Получаем путь к каталогу с конфигурацией данного узла"""
        return self._current_config_path

    def set_config_path(self, directory):
        """Запоминаем путь к каталогу с конфигурацией данного узла"""
        self._current_config_path = os.path.join(self._base_config_path, directory)

    def del_config_path(self):
        """Удаляем путь к каталогу с конфигурацией данного узла"""
        self._current_config_path = None

    def closeEvent(self, event):
        """
        При закрытии программы:
        1. Удаляем временный файл temporary_data.bin
        2. Делаем logout с NGFW если ранее был login
        """
        if os.path.isfile('temporary_data.bin'):
            os.remove('temporary_data.bin')
        for i in (1, 2, 3):
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
