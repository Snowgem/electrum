#!/usr/bin/env python
#
# Electrum - lightweight Bitcoin client
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
import webbrowser

import locale
import platform
import traceback
import os
import sys
import subprocess

from PyQt5.QtCore import QObject
import PyQt5.QtCore as QtCore
from PyQt5.QtWidgets import *

from electrum.i18n import _
from electrum import ELECTRUM_VERSION, bitcoin, constants

from .util import MessageBoxMixin

issue_template = """<h2>Traceback</h2>
<pre>
{traceback}
</pre>

<h2>Additional information</h2>
<ul>
  <li>ElectrumG version: {app_version}</li>
  <li>Operating system: {os}</li>
  <li>Wallet type: {wallet_type}</li>
  <li>Locale: {locale}</li>
  <li>Testnet: {testnet}</li>
  <li>Regtest: {regtest}</li>
</ul>
"""


class Exception_Window(QWidget, MessageBoxMixin):
    _active_window = None

    def __init__(self, main_window, exctype, value, tb):
        self.exc_args = (exctype, value, tb)
        self.main_window = main_window
        QWidget.__init__(self)
        self.setWindowTitle('ElectrumG - ' + _('An Error Occurred'))
        self.setMinimumSize(600, 300)

        main_box = QVBoxLayout()

        heading = QLabel('<h2>' + _('Sorry!') + '</h2>')
        main_box.addWidget(heading)
        main_box.addWidget(QLabel(_('Something went wrong while executing ElectrumG.')))

        main_box.addWidget(QLabel(_('Please create a bug report with the following content to help us diagnose and fix the problem:')))

        description_textfield = QTextEdit()
        description_textfield.setFixedHeight(250)
        description_textfield.setReadOnly(True)
        description_textfield.setText(self.get_report_string())
        main_box.addWidget(description_textfield)

        main_box.addWidget(QLabel(_("Do you want to report this?")))

        buttons = QHBoxLayout()

        report_button = QPushButton(_('Report Bug'))
        report_button.clicked.connect(self.file_report)
        buttons.addWidget(report_button)

        never_button = QPushButton(_('Never'))
        never_button.clicked.connect(self.show_never)
        buttons.addWidget(never_button)

        close_button = QPushButton(_('Not Now'))
        close_button.clicked.connect(self.close)
        buttons.addWidget(close_button)

        main_box.addLayout(buttons)

        self.setLayout(main_box)
        self.show()

    def file_report(self):
        self.main_window.app.clipboard().setText(self.get_report_string())
        self.show_message(_("Text copied to clipboard"))
        webbrowser.open(constants.GIT_ISSUE_URL, new=2)

    def show_never(self):
        self.main_window.config.set_key("show_crash_reporter", False)
        self.close()

    def closeEvent(self, event):
        self.on_close()
        event.accept()

    def get_additional_info(self):
        args = {
            "app_version": ELECTRUM_VERSION,
            "os": platform.platform(),
            "wallet_type": "unknown",
            "locale": locale.getdefaultlocale()[0],
            "testnet": constants.net.TESTNET,
            "regtest": constants.net.REGTEST
        }
        try:
            args["wallet_type"] = self.main_window.wallet.wallet_type
        except:
            # Maybe the wallet isn't loaded yet
            pass
        try:
            args["app_version"] = self.get_git_version()
        except:
            # This is probably not running from source
            pass
        return args

    def get_report_string(self):
        info = self.get_additional_info()
        info["traceback"] = "".join(traceback.format_exception(*self.exc_args))
        return issue_template.format(**info)

    @staticmethod
    def get_git_version():
        dir = os.path.dirname(os.path.realpath(sys.argv[0]))
        version = subprocess.check_output(
            ['git', 'describe', '--always', '--dirty'], cwd=dir)
        return str(version, "utf8").strip()


def _show_window(*args):
    if not Exception_Window._active_window:
        Exception_Window._active_window = Exception_Window(*args)


class Exception_Hook(QObject):
    _report_exception = QtCore.pyqtSignal(object, object, object, object)

    def __init__(self, main_window, *args, **kwargs):
        super(Exception_Hook, self).__init__(*args, **kwargs)
        if not main_window.config.get("show_crash_reporter", default=True):
            return
        self.main_window = main_window
        sys.excepthook = self.handler
        self._report_exception.connect(_show_window)

    def handler(self, *args):
        self._report_exception.emit(self.main_window, *args)
