import os
import sys
import pkg_resources


def get_version():
    """ Get absolute path to resource, works for dev and for PyInstaller """
    try:
        # PyInstaller creates a temp folder and stores path in _MEIPASS
        base_path = sys._MEIPASS
        with open(os.path.join(base_path, 'VERSION')) as f:
            return f.read()

    except Exception:
        # Exception is triggered if linux system, because _MEIPASS
        # is not defined
        version = pkg_resources.require("gvm-tools")[0].version
        return version
