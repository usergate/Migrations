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
# cp-mc7_convert_config.py
# Version 1.2
#--------------------------------------------------------------------------------------------------- 
#
import os, sys, json
import vizard_classes as vc
from PyQt6.QtGui import QIcon, QFont, QPalette
from PyQt6.QtCore import QSize, Qt, QObject
from PyQt6.QtWidgets import QApplication, QMainWindow, QHBoxLayout, QVBoxLayout, QWidget, QStackedLayout, QFileDialog, QFrame


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Конвертация конфигурации с CheckPoint на UG Management Server")
        ico = QIcon("favicon.png")
        self.setWindowIcon(ico)
        self.base_path = os.getcwd()
        self.cp_path = os.path.join(self.base_path, 'data_cp')
        self.ug_path = os.path.join(self.base_path, 'data_ug')
        self.cp_data_json = os.path.join(self.cp_path, 'data_json')
        self.utm = None
        self.dest_templates = {}
        self.current_dest_template = None
        self.sg_name = None
        self.sg_index = {}

        self.stacklayout = QStackedLayout()
        self.stacklayout.addWidget(vc.SelectAction(self))
        self.stacklayout.addWidget(vc.SelectSecureGateway(self))
        self.stacklayout.addWidget(vc.SelectDestinationTemplate(self))
        self.stacklayout.addWidget(vc.SelectImportMode(self))

        main_widget = QWidget()
        main_widget.setLayout(self.stacklayout)
        self.setCentralWidget(main_widget)

        if vc.create_dir(self, self.ug_path):
            """Создаём каталог data_ug. Если успешно, активируем кнопку импорта конфигурации."""
            self.stacklayout.widget(0).btn_import.setEnabled(True)
            self.stacklayout.widget(0).btn_import.setStyleSheet('color: steelblue; background: white;')

    def check_auth(self):
        """Проверяем что авторизация не протухла. Если протухла, логинимся заново."""
        err = None; result = None
        match self.utm.ping_session()[0]:
            case 1:
                err, result = self.utm.connect()
            case 2:
                err, result = self.utm.login()
        if err:
            message_alert(self, result, 'Ошибка подключения к Management Center!')
            return False
        else:
            return True

    def closeEvent(self, event):
        """Делаем logout с UTM при закрытии программы если ранее был login."""
        if self.utm:
            self.utm.logout()


def main():
    app = QApplication([])
#    app.setStyle("Fusion")
#    app.setStyleSheet(cs.Style.app)
    window = MainWindow()
#    window.resize(500, 300)
    window.show()
    app.exec()


if __name__ == '__main__':
    main()
