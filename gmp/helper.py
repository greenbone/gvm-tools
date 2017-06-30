import os
import sys
import pkg_resources


def resource_path(file):
    """ Get absolute path to resource, works for dev and for PyInstaller """
    try:
        # PyInstaller creates a temp folder and stores path in _MEIPASS
        base_path = sys._MEIPASS
    except Exception:
        return pkg_resources.resource_filename(
            pkg_resources.Requirement.parse("gvm-tools"), file)

    return os.path.join(base_path, file)
