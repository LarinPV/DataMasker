"""
Графический интерфейс приложения DataMasker на CustomTkinter.
Включает:
- Вкладку «Обезличить» с выбором папок, настройками типов данных, мастер-паролем, списком исключений.
- Вкладку «Восстановить» с выбором папки с токенами, ключа .vault, пароля и целевой папки.
- Асинхронное выполнение в фоновом потоке со 100% потокобезопасным чтением параметров UI.
- Прогресс-бар, счетчик обработанных файлов, найденных сущностей.
- Детальный журнал операций (лог) в реальном времени.
- Быстрый переход к папкам с результатами.
"""

import os
import sys
import threading
import tkinter as tk
from tkinter import filedialog, messagebox
import customtkinter as ctk

from core.detector import EntityDetector
from core.anonymizer import Anonymizer
from core.doc_handlers import DocumentProcessor
from core.vault import InvalidPasswordError, VaultError


ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")


class DataMaskerApp(ctk.CTk):
    """Главное окно приложения DataMasker."""

    def __init__(self):
        super().__init__()

        self.title("DataMasker — Автономное обезличивание документов")
        self.geometry("960, 720")
        self.minsize(860, 600)

        # Переменные состояния
        self.is_processing = False

        # Создание вкладок
        self.tabview = ctk.CTkTabview(self)
        self.tabview.pack(padx=20, pady=(10, 5), fill="both", expand=True)

        self.tab_mask = self.tabview.add("  Обезличить документы  ")
        self.tab_restore = self.tabview.add("  Восстановить документы  ")
        self.tab_settings = self.tabview.add("  Форматы и исключения  ")

        self._build_mask_tab()
        self._build_restore_tab()
        self._build_settings_tab()
        self._build_footer()

    def _build_footer(self):
        """Нижняя панель (футер) с информацией и ссылкой на GitHub разработчика."""
        footer = ctk.CTkFrame(self, fg_color="transparent")
        footer.pack(fill="x", padx=20, pady=(0, 8))

        ctk.CTkLabel(
            footer,
            text="DataMasker • 100% Offline",
            font=ctk.CTkFont(size=11),
            text_color="gray60"
        ).pack(side="left")

        github_btn = ctk.CTkLabel(
            footer,
            text="GitHub: LarinPV",
            font=ctk.CTkFont(size=11, underline=True),
            text_color=("#1f6aa5", "#4da8da"),
            cursor="hand2"
        )
        github_btn.pack(side="right")
        github_btn.bind("<Button-1>", lambda e: self._open_github())

    def _open_github(self):
        """Открывает страницу GitHub в браузере по умолчанию."""
        import webbrowser
        try:
            webbrowser.open_new_tab("https://github.com/LarinPV")
        except Exception:
            pass

    # =========================================================================
    # ВКЛАДКА 1: ОБЕЗЛИЧИВАНИЕ
    # =========================================================================

    def _build_mask_tab(self):
        tab = self.tab_mask

        # Блок выбора директорий
        folder_frame = ctk.CTkFrame(tab)
        folder_frame.pack(fill="x", padx=10, pady=10)

        # Исходная папка
        ctk.CTkLabel(folder_frame, text="Исходная папка с документами:", font=ctk.CTkFont(weight="bold")).grid(row=0, column=0, sticky="w", padx=10, pady=5)
        self.mask_src_entry = ctk.CTkEntry(folder_frame, placeholder_text="Выберите папку с файлами...")
        self.mask_src_entry.grid(row=0, column=1, sticky="ew", padx=10, pady=5)
        ctk.CTkButton(folder_frame, text="Обзор...", width=100, command=self._browse_mask_src).grid(row=0, column=2, padx=10, pady=5)

        # Папка назначения
        ctk.CTkLabel(folder_frame, text="Папка для обезличенных файлов:", font=ctk.CTkFont(weight="bold")).grid(row=1, column=0, sticky="w", padx=10, pady=5)
        self.mask_dst_entry = ctk.CTkEntry(folder_frame, placeholder_text="Выберите папку для сохранения...")
        self.mask_dst_entry.grid(row=1, column=1, sticky="ew", padx=10, pady=5)
        ctk.CTkButton(folder_frame, text="Обзор...", width=100, command=self._browse_mask_dst).grid(row=1, column=2, padx=10, pady=5)

        # Файл ключа .vault
        ctk.CTkLabel(folder_frame, text="Файл ключа маппинга (.vault):", font=ctk.CTkFont(weight="bold")).grid(row=2, column=0, sticky="w", padx=10, pady=5)
        self.mask_vault_entry = ctk.CTkEntry(folder_frame, placeholder_text="Путь к сохраняемому ключу .vault...")
        self.mask_vault_entry.grid(row=2, column=1, sticky="ew", padx=10, pady=5)
        ctk.CTkButton(folder_frame, text="Обзор...", width=100, command=self._browse_mask_vault).grid(row=2, column=2, padx=10, pady=5)

        # Мастер-пароль
        ctk.CTkLabel(folder_frame, text="Мастер-пароль шифрования:", font=ctk.CTkFont(weight="bold")).grid(row=3, column=0, sticky="w", padx=10, pady=5)
        self.mask_pwd_entry = ctk.CTkEntry(folder_frame, placeholder_text="Необязательно (если пусто, создается .key файл)", show="*")
        self.mask_pwd_entry.grid(row=3, column=1, sticky="ew", padx=10, pady=5)

        folder_frame.columnconfigure(1, weight=1)

        # Блок типов сущностей для маскирования
        types_frame = ctk.CTkFrame(tab)
        types_frame.pack(fill="x", padx=10, pady=5)

        ctk.CTkLabel(types_frame, text="Обнаруживать и обезличивать сущности:", font=ctk.CTkFont(weight="bold")).pack(anchor="w", padx=10, pady=(5, 5))

        chk_container = ctk.CTkFrame(types_frame, fg_color="transparent")
        chk_container.pack(fill="x", padx=10, pady=5)

        self.type_vars = {}
        entity_defs = [
            ("ФИО", "ФИО (Фамилия Имя / Инициалы)"),
            ("ОРГ", "Организации (ООО, АО, ИП...)"),
            ("ИНН", "ИНН (ЮЛ / ФЛ с валидацией)"),
            ("ОГРН", "ОГРН / ОГРНИП"),
            ("КПП", "КПП"),
            ("БИК", "БИК банка"),
            ("РСЧЕТ", "Банковские счета (Р/С, К/С)"),
            ("КАРТА", "Банковские карты"),
            ("ТЕЛ", "Номера телефонов"),
            ("EMAIL", "Email адреса"),
            ("ПАСПОРТ", "Паспорта РФ"),
            ("СНИЛС", "СНИЛС"),
            ("АДРЕС", "Адреса, улицы, квартиры"),
        ]

        for idx, (code, label_txt) in enumerate(entity_defs):
            var = ctk.BooleanVar(value=True)
            self.type_vars[code] = var
            r = idx // 4
            c = idx % 4
            chk = ctk.CTkCheckBox(chk_container, text=label_txt, variable=var)
            chk.grid(row=r, column=c, padx=8, pady=4, sticky="w")

        # Прогресс и статус
        status_frame = ctk.CTkFrame(tab)
        status_frame.pack(fill="x", padx=10, pady=5)

        self.mask_status_lbl = ctk.CTkLabel(status_frame, text="Готов к работе.", font=ctk.CTkFont(size=13))
        self.mask_status_lbl.pack(anchor="w", padx=10, pady=(5, 2))

        self.mask_progressbar = ctk.CTkProgressBar(status_frame)
        self.mask_progressbar.pack(fill="x", padx=10, pady=(2, 5))
        self.mask_progressbar.set(0.0)

        # Кнопки управления (закреплены внизу окна)
        btn_frame = ctk.CTkFrame(tab, fg_color="transparent")
        btn_frame.pack(side="bottom", fill="x", padx=10, pady=(5, 10))

        self.btn_open_mask_folder = ctk.CTkButton(
            btn_frame,
            text="Открыть папку с результатом",
            height=38,
            width=220,
            command=self._open_mask_dst
        )
        self.btn_open_mask_folder.pack(side="right", padx=5)

        self.btn_start_mask = ctk.CTkButton(
            btn_frame,
            text="▶ НАЧАТЬ ОБЕЗЛИЧИВАНИЕ",
            height=38,
            font=ctk.CTkFont(size=14, weight="bold"),
            fg_color="#1f6aa5",
            hover_color="#144870",
            command=self._start_mask_thread
        )
        self.btn_start_mask.pack(side="left", padx=5, expand=True, fill="x")

        # Лог работы (занимает доступное пространство)
        self.mask_log = ctk.CTkTextbox(tab, height=80, font=ctk.CTkFont(family="Consolas", size=11))
        self.mask_log.pack(fill="both", expand=True, padx=10, pady=5)

    # =========================================================================
    # ВКЛАДКА 2: ВОССТАНОВЛЕНИЕ
    # =========================================================================

    def _build_restore_tab(self):
        tab = self.tab_restore

        folder_frame = ctk.CTkFrame(tab)
        folder_frame.pack(fill="x", padx=10, pady=10)

        # Папка с обезличенными документами
        ctk.CTkLabel(folder_frame, text="Папка с обезличенными файлами:", font=ctk.CTkFont(weight="bold")).grid(row=0, column=0, sticky="w", padx=10, pady=5)
        self.restore_src_entry = ctk.CTkEntry(folder_frame, placeholder_text="Папка с токенами {{ТЕГ_XXX}}...")
        self.restore_src_entry.grid(row=0, column=1, sticky="ew", padx=10, pady=5)
        ctk.CTkButton(folder_frame, text="Обзор...", width=100, command=self._browse_restore_src).grid(row=0, column=2, padx=10, pady=5)

        # Файл ключа .vault
        ctk.CTkLabel(folder_frame, text="Файл ключа маппинга (.vault):", font=ctk.CTkFont(weight="bold")).grid(row=1, column=0, sticky="w", padx=10, pady=5)
        self.restore_vault_entry = ctk.CTkEntry(folder_frame, placeholder_text="Выберите файл .vault...")
        self.restore_vault_entry.grid(row=1, column=1, sticky="ew", padx=10, pady=5)
        ctk.CTkButton(folder_frame, text="Обзор...", width=100, command=self._browse_restore_vault).grid(row=1, column=2, padx=10, pady=5)

        # Файл секретного ключа .key (если без пароля)
        ctk.CTkLabel(folder_frame, text="Файл-ключ (.key) [если без пароля]:", font=ctk.CTkFont(weight="bold")).grid(row=2, column=0, sticky="w", padx=10, pady=5)
        self.restore_key_entry = ctk.CTkEntry(folder_frame, placeholder_text="Опционально (если ключ сохранен отдельно)...")
        self.restore_key_entry.grid(row=2, column=1, sticky="ew", padx=10, pady=5)
        ctk.CTkButton(folder_frame, text="Обзор...", width=100, command=self._browse_restore_key).grid(row=2, column=2, padx=10, pady=5)

        # Мастер-пароль
        ctk.CTkLabel(folder_frame, text="Мастер-пароль:", font=ctk.CTkFont(weight="bold")).grid(row=3, column=0, sticky="w", padx=10, pady=5)
        self.restore_pwd_entry = ctk.CTkEntry(folder_frame, placeholder_text="Введите пароль к хранилищу...", show="*")
        self.restore_pwd_entry.grid(row=3, column=1, sticky="ew", padx=10, pady=5)

        # Целевая папка для восстановленных документов
        ctk.CTkLabel(folder_frame, text="Папка для восстановленных файлов:", font=ctk.CTkFont(weight="bold")).grid(row=4, column=0, sticky="w", padx=10, pady=5)
        self.restore_dst_entry = ctk.CTkEntry(folder_frame, placeholder_text="Папка для готовых оригинальных документов...")
        self.restore_dst_entry.grid(row=4, column=1, sticky="ew", padx=10, pady=5)
        ctk.CTkButton(folder_frame, text="Обзор...", width=100, command=self._browse_restore_dst).grid(row=4, column=2, padx=10, pady=5)

        folder_frame.columnconfigure(1, weight=1)

        # Прогресс и статус
        status_frame = ctk.CTkFrame(tab)
        status_frame.pack(fill="x", padx=10, pady=5)

        self.restore_status_lbl = ctk.CTkLabel(status_frame, text="Готов к восстановлению.", font=ctk.CTkFont(size=13))
        self.restore_status_lbl.pack(anchor="w", padx=10, pady=(5, 2))

        self.restore_progressbar = ctk.CTkProgressBar(status_frame)
        self.restore_progressbar.pack(fill="x", padx=10, pady=(2, 5))
        self.restore_progressbar.set(0.0)

        # Кнопки (закреплены внизу окна)
        btn_frame = ctk.CTkFrame(tab, fg_color="transparent")
        btn_frame.pack(side="bottom", fill="x", padx=10, pady=(5, 10))

        self.btn_open_restore_folder = ctk.CTkButton(
            btn_frame,
            text="Открыть папку с результатом",
            height=38,
            width=220,
            command=self._open_restore_dst
        )
        self.btn_open_restore_folder.pack(side="right", padx=5)

        self.btn_start_restore = ctk.CTkButton(
            btn_frame,
            text="↺ ВОССТАНОВИТЬ ДОКУМЕНТЫ",
            height=38,
            font=ctk.CTkFont(size=14, weight="bold"),
            fg_color="#2b8a3e",
            hover_color="#1f662e",
            command=self._start_restore_thread
        )
        self.btn_start_restore.pack(side="left", padx=5, expand=True, fill="x")

        # Лог (занимает доступное пространство)
        self.restore_log = ctk.CTkTextbox(tab, height=80, font=ctk.CTkFont(family="Consolas", size=11))
        self.restore_log.pack(fill="both", expand=True, padx=10, pady=5)

    # =========================================================================
    # ВКЛАДКА 3: НАСТРОЙКИ ФОРМАТОВ И ИСКЛЮЧЕНИЙ
    # =========================================================================

    def _build_settings_tab(self):
        tab = self.tab_settings

        fmt_frame = ctk.CTkFrame(tab)
        fmt_frame.pack(fill="x", padx=10, pady=10)

        ctk.CTkLabel(fmt_frame, text="Поддерживаемые форматы файлов для обработки:", font=ctk.CTkFont(weight="bold")).pack(anchor="w", padx=10, pady=5)

        fmt_box = ctk.CTkFrame(fmt_frame, fg_color="transparent")
        fmt_box.pack(fill="x", padx=10, pady=5)

        self.format_vars = {
            ".docx": ctk.BooleanVar(value=True),
            ".doc":  ctk.BooleanVar(value=True),
            ".xlsx": ctk.BooleanVar(value=True),
            ".xls":  ctk.BooleanVar(value=True),
            ".txt":  ctk.BooleanVar(value=True),
            ".rtf":  ctk.BooleanVar(value=True),
            ".csv":  ctk.BooleanVar(value=True),
            ".tsv":  ctk.BooleanVar(value=True),
            ".pptx": ctk.BooleanVar(value=True),
            ".pdf":  ctk.BooleanVar(value=True),
            ".json": ctk.BooleanVar(value=True),
            ".xml":  ctk.BooleanVar(value=True),
            ".html": ctk.BooleanVar(value=True),
            ".odt":  ctk.BooleanVar(value=True),
            ".ods":  ctk.BooleanVar(value=True),
        }

        col = 0
        row = 0
        for ext, var in self.format_vars.items():
            chk = ctk.CTkCheckBox(fmt_box, text=ext, variable=var)
            chk.grid(row=row, column=col, padx=10, pady=5, sticky="w")
            col += 1
            if col > 4:
                col = 0
                row += 1

        # Белый список (Исключения)
        wl_frame = ctk.CTkFrame(tab)
        wl_frame.pack(fill="both", expand=True, padx=10, pady=10)

        ctk.CTkLabel(
            wl_frame,
            text="Белый список исключений (слова/названия, которые НЕ будут маскироваться):",
            font=ctk.CTkFont(weight="bold")
        ).pack(anchor="w", padx=10, pady=5)
        ctk.CTkLabel(
            wl_frame,
            text="Укажите по одному слову или словосочетанию на строку (например, название своей компании или ФИО руководителя):",
            font=ctk.CTkFont(size=11, slant="italic")
        ).pack(anchor="w", padx=10, pady=(0, 5))

        self.whitelist_textbox = ctk.CTkTextbox(wl_frame, font=ctk.CTkFont(family="Consolas", size=12))
        self.whitelist_textbox.pack(fill="both", expand=True, padx=10, pady=5)
        self.whitelist_textbox.insert("1.0", "# Пример исключений:\n# ООО Моя Компания\n# Иванов Иван Иванович\n")

    # =========================================================================
    # ЛОГИРОВАНИЕ И ВСПОМОГАТЕЛЬНЫЕ МЕТОДЫ
    # =========================================================================

    def _log_mask(self, message: str):
        def _append():
            self.mask_log.insert("end", message + "\n")
            self.mask_log.see("end")
        self.after(0, _append)

    def _log_restore(self, message: str):
        def _append():
            self.restore_log.insert("end", message + "\n")
            self.restore_log.see("end")
        self.after(0, _append)

    def _browse_mask_src(self):
        d = filedialog.askdirectory(title="Выберите исходную папку с документами")
        if d:
            self.mask_src_entry.delete(0, "end")
            self.mask_src_entry.insert(0, os.path.normpath(d))
            if not self.mask_dst_entry.get():
                self.mask_dst_entry.insert(0, os.path.normpath(d + "_masked"))
            if not self.mask_vault_entry.get():
                self.mask_vault_entry.insert(0, os.path.normpath(os.path.join(d + "_masked", "keys.vault")))

    def _browse_mask_dst(self):
        d = filedialog.askdirectory(title="Выберите папку для обезличенных документов")
        if d:
            self.mask_dst_entry.delete(0, "end")
            self.mask_dst_entry.insert(0, os.path.normpath(d))

    def _browse_mask_vault(self):
        f = filedialog.asksaveasfilename(
            title="Сохранить файл ключа сопоставлений",
            defaultextension=".vault",
            filetypes=[("Файл ключей маппинга", "*.vault"), ("Все файлы", "*.*")]
        )
        if f:
            self.mask_vault_entry.delete(0, "end")
            self.mask_vault_entry.insert(0, os.path.normpath(f))

    def _browse_restore_src(self):
        d = filedialog.askdirectory(title="Выберите папку с обезличенными документами")
        if d:
            self.restore_src_entry.delete(0, "end")
            self.restore_src_entry.insert(0, os.path.normpath(d))
            if not self.restore_dst_entry.get():
                self.restore_dst_entry.insert(0, os.path.normpath(d + "_restored"))

    def _browse_restore_vault(self):
        f = filedialog.askopenfilename(
            title="Выберите файл сопоставлений",
            filetypes=[("Файл ключей маппинга", "*.vault"), ("Все файлы", "*.*")]
        )
        if f:
            self.restore_vault_entry.delete(0, "end")
            self.restore_vault_entry.insert(0, os.path.normpath(f))

    def _browse_restore_key(self):
        f = filedialog.askopenfilename(
            title="Выберите файл-ключ (.key)",
            filetypes=[("Файл секретного ключа", "*.key"), ("Все файлы", "*.*")]
        )
        if f:
            self.restore_key_entry.delete(0, "end")
            self.restore_key_entry.insert(0, os.path.normpath(f))

    def _browse_restore_dst(self):
        d = filedialog.askdirectory(title="Выберите папку для восстановления документов")
        if d:
            self.restore_dst_entry.delete(0, "end")
            self.restore_dst_entry.insert(0, os.path.normpath(d))

    def _open_mask_dst(self):
        p = self.mask_dst_entry.get().strip()
        if p and os.path.exists(p):
            os.startfile(p)
        else:
            messagebox.showinfo("Папка не найдена", "Указанная папка еще не создана.")

    def _open_restore_dst(self):
        p = self.restore_dst_entry.get().strip()
        if p and os.path.exists(p):
            os.startfile(p)
        else:
            messagebox.showinfo("Папка не найдена", "Указанная папка еще не создана.")

    def _get_whitelist_items(self) -> list:
        raw = self.whitelist_textbox.get("1.0", "end")
        items = []
        for line in raw.splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                items.append(line)
        return items

    # =========================================================================
    # ПРОЦЕСС ОБЕЗЛИЧИВАНИЯ
    # =========================================================================

    def _start_mask_thread(self):
        if self.is_processing:
            return

        src = self.mask_src_entry.get().strip()
        dst = self.mask_dst_entry.get().strip()
        vault_path = self.mask_vault_entry.get().strip()
        password = self.mask_pwd_entry.get().strip() or None

        if not src or not os.path.exists(src):
            messagebox.showerror("Ошибка", "Укажите существующую исходную папку!")
            return
        if not dst:
            messagebox.showerror("Ошибка", "Укажите целевую папку для сохранения!")
            return
        if not vault_path:
            messagebox.showerror("Ошибка", "Укажите путь для сохранения файла ключа (.vault)!")
            return

        # ВАЖНО: считываем ВСЕ значения UI строго в главном потоке!
        enabled_types = {code: bool(var.get()) for code, var in self.type_vars.items()}
        allowed_exts = {ext for ext, var in self.format_vars.items() if var.get()}
        whitelist = self._get_whitelist_items()

        self.is_processing = True
        self.btn_start_mask.configure(state="disabled", text="⏳ ИДЕТ ОБРАБОТКА...")
        self.mask_progressbar.set(0.0)
        self.mask_log.delete("1.0", "end")

        thread = threading.Thread(
            target=self._run_masking,
            args=(src, dst, vault_path, password, enabled_types, allowed_exts, whitelist),
            daemon=True
        )
        thread.start()

    def _run_masking(self, src_dir: str, dst_dir: str, vault_path: str, password: str,
                     enabled_types: dict, allowed_exts: set, whitelist: list):
        try:
            self._log_mask("=" * 60)
            self._log_mask("ЗАПУСК ПРОЦЕССА ОБЕЗЛИЧИВАНИЯ (ПСЕВДОНИМИЗАЦИИ)")
            self._log_mask(f"Исходная папка: {src_dir}")
            self._log_mask(f"Целевая папка:  {dst_dir}")
            self._log_mask(f"Файл ключа:     {vault_path}")
            self._log_mask("=" * 60)

            self._log_mask(f"Включено категорий данных: {sum(enabled_types.values())} из {len(enabled_types)}")
            if whitelist:
                self._log_mask(f"Исключений в белом списке: {len(whitelist)}")

            detector = EntityDetector(enabled_types=enabled_types, whitelist=whitelist)
            anonymizer = Anonymizer()
            processor = DocumentProcessor(detector, anonymizer)

            # Поиск всех файлов
            files_to_process = []
            for root, _, files in os.walk(src_dir):
                for f in files:
                    if f.startswith("~$") or f.startswith("."):
                        continue
                    ext = os.path.splitext(f)[1].lower()
                    if ext in allowed_exts:
                        full_in = os.path.join(root, f)
                        rel = os.path.relpath(full_in, src_dir)
                        full_out = os.path.join(dst_dir, rel)
                        files_to_process.append((full_in, full_out, rel))

            total_files = len(files_to_process)
            self._log_mask(f"Найдено файлов для обработки: {total_files}")

            if total_files == 0:
                self._log_mask("⚠ В исходной папке нет файлов поддерживаемых форматов.")
                self.after(0, lambda: messagebox.showwarning("Внимание", "Не найдено файлов выбранных форматов!"))
                return

            processed_count = 0
            total_replacements = 0

            for in_path, out_path, rel_name in files_to_process:
                self._log_mask(f"\n[Файл {processed_count + 1}/{total_files}] Обработка: {rel_name}")
                self.after(0, lambda r=rel_name, i=processed_count: self.mask_status_lbl.configure(
                    text=f"Обработка ({i+1}/{total_files}): {r}"
                ))

                try:
                    changes = processor.process_file(in_path, out_path, mode="mask")
                    total_replacements += changes
                    extra_note = ""
                    if out_path.lower().endswith((".doc", ".xls")) and os.path.exists(out_path + "x"):
                        extra_note = f" (и копия {os.path.basename(out_path)}x для быстрого открытия в Office)"
                    self._log_mask(f"  ✓ Готово. Заменено сущностей: {changes}{extra_note}")
                except Exception as ex:
                    self._log_mask(f"  ❌ Ошибка обработки файла: {ex}")

                processed_count += 1
                progress = processed_count / total_files
                self.after(0, lambda p=progress: self.mask_progressbar.set(p))

            # Сохранение ключа .vault
            self._log_mask("\n" + "-" * 60)
            self._log_mask("Экспорт и шифрование файла соответствий...")
            os.makedirs(os.path.dirname(vault_path), exist_ok=True)

            meta = {
                "source_dir": src_dir,
                "target_dir": dst_dir,
                "total_files": total_files,
                "processed_files": processed_count,
            }
            saved_key_file = anonymizer.save_vault(vault_path, password=password, metadata=meta)

            self._log_mask(f"✓ Защищенный файл сопоставлений сохранен: {vault_path}")
            if saved_key_file:
                self._log_mask(f"🔑 Сгенерирован файл секретного ключа: {saved_key_file}")
                self._log_mask("   (Сохраните этот файл в надежном месте для расшифровки!)")
            else:
                self._log_mask("🔒 Хранилище защищено указанным мастер-паролем.")

            self._log_mask("\n" + "=" * 60)
            self._log_mask("ОБЕЗЛИЧИВАНИЕ УСПЕШНО ЗАВЕРШЕНО!")
            self._log_mask(f"Всего файлов обработано: {processed_count}")
            self._log_mask(f"Всего замен произведено: {total_replacements}")
            self._log_mask(f"Уникальных сущностей в базе токенов: {len(anonymizer.forward_map)}")
            if anonymizer.stats:
                self._log_mask("Статистика по типам:")
                for tag, cnt in sorted(anonymizer.stats.items()):
                    self._log_mask(f"  • {tag}: {cnt}")
            self._log_mask("=" * 60)

            self.after(0, lambda: self.mask_status_lbl.configure(text=f"Готово! Обработано файлов: {processed_count}"))
            self.after(0, lambda: messagebox.showinfo(
                "Успех",
                f"Обезличивание успешно завершено!\n\n"
                f"Обработано файлов: {processed_count}\n"
                f"Найдено сущностей: {len(anonymizer.forward_map)}\n"
                f"Произведено замен: {total_replacements}\n"
                f"Файл ключа: {vault_path}"
            ))

        except Exception as e:
            self._log_mask(f"\n❌ Критическая ошибка: {e}")
            self.after(0, lambda err=str(e): messagebox.showerror("Ошибка", f"Произошла ошибка:\n{err}"))
        finally:
            self.is_processing = False
            self.after(0, lambda: self.btn_start_mask.configure(state="normal", text="▶ НАЧАТЬ ОБЕЗЛИЧИВАНИЕ"))

    # =========================================================================
    # ПРОЦЕСС ВОССТАНОВЛЕНИЯ
    # =========================================================================

    def _start_restore_thread(self):
        if self.is_processing:
            return

        src = self.restore_src_entry.get().strip()
        dst = self.restore_dst_entry.get().strip()
        vault_path = self.restore_vault_entry.get().strip()
        key_file = self.restore_key_entry.get().strip() or None
        password = self.restore_pwd_entry.get().strip() or None

        if not src or not os.path.exists(src):
            messagebox.showerror("Ошибка", "Укажите существующую папку с обезличенными файлами!")
            return
        if not dst:
            messagebox.showerror("Ошибка", "Укажите папку для сохранения восстановленных файлов!")
            return
        if not vault_path or not os.path.exists(vault_path):
            messagebox.showerror("Ошибка", "Укажите существующий файл сопоставлений (.vault)!")
            return

        allowed_exts = {ext for ext, var in self.format_vars.items() if var.get()}

        self.is_processing = True
        self.btn_start_restore.configure(state="disabled", text="⏳ ИДЕТ ВОССТАНОВЛЕНИЕ...")
        self.restore_progressbar.set(0.0)
        self.restore_log.delete("1.0", "end")

        thread = threading.Thread(
            target=self._run_restoring,
            args=(src, dst, vault_path, password, key_file, allowed_exts),
            daemon=True
        )
        thread.start()

    def _run_restoring(self, src_dir: str, dst_dir: str, vault_path: str, password: str, key_filepath: str, allowed_exts: set):
        try:
            self._log_restore("=" * 60)
            self._log_restore("ЗАПУСК ПРОЦЕССА ОБРАТНОГО ВОССТАНОВЛЕНИЯ ДАННЫХ")
            self._log_restore(f"Папка с токенами:  {src_dir}")
            self._log_restore(f"Файл ключа:        {vault_path}")
            self._log_restore(f"Целевая папка:     {dst_dir}")
            self._log_restore("=" * 60)

            anonymizer = Anonymizer()
            self._log_restore("Расшифровка хранилища ключей...")

            try:
                meta = anonymizer.load_vault(vault_path, password=password, key_filepath=key_filepath)
            except InvalidPasswordError as pe:
                self._log_restore(f"❌ Ошибка доступа: {pe}")
                self.after(0, lambda: messagebox.showerror("Ошибка доступа", f"{pe}"))
                return

            total_tokens = len(anonymizer.reverse_map)
            self._log_restore(f"✓ Хранилище успешно расшифровано. Загружено токенов: {total_tokens}")

            detector = EntityDetector(enabled_types={})
            processor = DocumentProcessor(detector, anonymizer)

            # Поиск всех файлов
            files_to_process = []
            for root, _, files in os.walk(src_dir):
                for f in files:
                    if f.startswith("~$") or f.startswith("."):
                        continue
                    ext = os.path.splitext(f)[1].lower()
                    if ext in allowed_exts:
                        full_in = os.path.join(root, f)
                        rel = os.path.relpath(full_in, src_dir)
                        full_out = os.path.join(dst_dir, rel)
                        files_to_process.append((full_in, full_out, rel))

            total_files = len(files_to_process)
            self._log_restore(f"Найдено файлов для восстановления: {total_files}")

            if total_files == 0:
                self._log_restore("⚠ В папке не найдено файлов поддерживаемых форматов.")
                self.after(0, lambda: messagebox.showwarning("Внимание", "Не найдено файлов выбранных форматов!"))
                return

            processed_count = 0
            for in_path, out_path, rel_name in files_to_process:
                self._log_restore(f"\n[Файл {processed_count + 1}/{total_files}] Восстановление: {rel_name}")
                self.after(0, lambda r=rel_name, i=processed_count: self.restore_status_lbl.configure(
                    text=f"Восстановление ({i+1}/{total_files}): {r}"
                ))

                try:
                    processor.process_file(in_path, out_path, mode="restore")
                    extra_note = ""
                    if out_path.lower().endswith((".doc", ".xls")) and os.path.exists(out_path + "x"):
                        extra_note = f" (и копия {os.path.basename(out_path)}x для быстрого открытия в Office)"
                    self._log_restore(f"  ✓ Успешно восстановлен.{extra_note}")
                except Exception as ex:
                    self._log_restore(f"  ❌ Ошибка при восстановлении: {ex}")

                processed_count += 1
                progress = processed_count / total_files
                self.after(0, lambda p=progress: self.restore_progressbar.set(p))

            self._log_restore("\n" + "=" * 60)
            self._log_restore("ВОССТАНОВЛЕНИЕ УСПЕШНО ЗАВЕРШЕНО!")
            self._log_restore(f"Восстановлено файлов: {processed_count} из {total_files}")
            self._log_restore("=" * 60)

            self.after(0, lambda: self.restore_status_lbl.configure(text=f"Готово! Восстановлено файлов: {processed_count}"))
            self.after(0, lambda: messagebox.showinfo(
                "Успех",
                f"Восстановление успешно завершено!\n\n"
                f"Восстановлено файлов: {processed_count}\n"
                f"Папка с результатом: {dst_dir}"
            ))

        except Exception as e:
            self._log_restore(f"\n❌ Критическая ошибка: {e}")
            self.after(0, lambda err=str(e): messagebox.showerror("Ошибка", f"Произошла ошибка:\n{err}"))
        finally:
            self.is_processing = False
            self.after(0, lambda: self.btn_start_restore.configure(state="normal", text="↺ ВОССТАНОВИТЬ ДОКУМЕНТЫ"))
