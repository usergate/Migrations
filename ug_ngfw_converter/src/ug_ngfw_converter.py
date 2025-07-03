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
# ug_ngfw_converter.py
# Version 4.21  03.07.2025
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
        self.setWindowTitle("Экспорт/Импорт конфигурации продуктов UserGate (version 4.21)")
        ico = QIcon("favicon.png")
#        ico = QIcon(os.path.join(sys._MEIPASS, "favicon.png"))  # Для PyInstaller
        self.setWindowIcon(ico)
        self._current_config_path = None    # Полный путь к каталогу с конфигурацией данного узла

        self.stacklayout = QStackedLayout()
        self.stacklayout.addWidget(vc.SelectAction(self))
        self.stacklayout.addWidget(vc.SelectExportMode(self))
        self.stacklayout.addWidget(vc.SelectMcExportMode(self))
        self.stacklayout.addWidget(vc.SelectImportMode(self))
        self.stacklayout.addWidget(vc.SelectMcImportMode(self))
        self.stacklayout.addWidget(vc.SelectMcTemplateGroupImport(self))

        main_widget = QWidget()
        main_widget.setLayout(self.stacklayout)
        self.setCentralWidget(main_widget)

        # Создаём базовые каталоги в текущей директории. Если успешно, активируем кнопки экспорта/импорта.
        err, msg = create_dir(self.ngfw_base_path, delete='no')
        if err:
            message_alert(self, msg, '')
        else:
            err, msg = create_dir(self.mc_base_path, delete='no')
            if err:
                message_alert(self, msg, '')
            else:
                self.stacklayout.widget(0).enable_buttons()

    @property
    def ngfw_base_path(self):
        """Получаем имя базового каталога конфигураций для NGFW, DCFW"""
        return 'data'

    @property
    def mc_base_path(self):
        """Получаем имя базового каталога шаблонов МС"""
        return 'mc_templates'

    def get_config_path(self):
        """Получаем путь к каталогу с конфигурацией данного узла"""
        return self._current_config_path

    def set_config_path(self, base_path, directory):
        """Запоминаем путь к каталогу с конфигурацией данного узла"""
        self._current_config_path = os.path.join(base_path, directory)

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
        for i in (1, 2, 3, 4, 5):
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
