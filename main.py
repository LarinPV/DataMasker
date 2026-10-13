"""
Точка входа настольного приложения DataMasker.
Запускает графический интерфейс пользователя (GUI) на базе CustomTkinter.
Обеспечивает поддержку High-DPI экранов Windows и корректную работу путей PyInstaller.
"""

import os
import sys

# Настройка DPI Awareness для четкого отображения шрифтов на Windows
if sys.platform == "win32":
    try:
        import ctypes
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        pass

from gui.app import DataMaskerApp


def main():
    """Главная функция запуска приложения."""
    try:
        app = DataMaskerApp()
        app.mainloop()
    except Exception as e:
        print(f"Ошибка запуска приложения: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
