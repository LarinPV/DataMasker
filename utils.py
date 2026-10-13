import os
import sys

def get_resource_path(relative_path: str) -> str:
    """
    Возвращает абсолютный путь к ресурсу, поддерживая как режим разработки,
    так и режим упакованного исполняемого файла PyInstaller (через sys._MEIPASS).
    """
    if hasattr(sys, '_MEIPASS'):
        base_path = getattr(sys, '_MEIPASS')
    else:
        base_path = os.path.dirname(os.path.abspath(__file__))
    return os.path.normpath(os.path.join(base_path, relative_path))

def ensure_dir(path: str) -> None:
    """Создает директорию, если она не существует."""
    os.makedirs(path, exist_ok=True)
