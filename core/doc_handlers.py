"""
Обработчики различных форматов документов:
- Microsoft Word (.docx, .doc, .docm, .dotx) — поддержка современных и переименованных .doc
- Microsoft Excel (.xlsx, .xls, .xlsm) — пропуск формул (=), обработка строк и чисел
- Текстовые файлы (.txt, .md, .log, .sql, .ini, .rtf) — автоопределение кодировок
- CSV/TSV таблицы (.csv, .tsv) — автоопределение разделителей и кодировки
- Microsoft PowerPoint (.pptx, .ppt) — слайды, блоки текста, таблицы
- JSON файлы (.json) — рекурсивная обработка строковых полей с сохранением схемы
- XML / HTML (.xml, .html, .htm) — обработка текста без нарушения разметки тегов
- PDF файлы (.pdf) — извлечение и создание маскированной текстовой версии
"""

import os
import re
import csv
import json
import struct
import shutil
from typing import List, Tuple, Dict, Any, Optional
from .detector import EntityDetector
from .anonymizer import Anonymizer

# docx
try:
    import docx
    _DOCX_AVAILABLE = True
except ImportError:
    _DOCX_AVAILABLE = False

# openpyxl
try:
    import openpyxl
    _OPENPYXL_AVAILABLE = True
except ImportError:
    _OPENPYXL_AVAILABLE = False

# xlrd & xlwt & xlutils для legacy .xls
try:
    import xlrd
    import xlwt
    from xlutils.copy import copy as xlutils_copy
    _XLS_LEGACY_AVAILABLE = True
except ImportError:
    _XLS_LEGACY_AVAILABLE = False

# olefile для .doc 97-2003
try:
    import olefile
    _OLEFILE_AVAILABLE = True
except ImportError:
    _OLEFILE_AVAILABLE = False

# python-pptx
try:
    from pptx import Presentation
    _PPTX_AVAILABLE = True
except ImportError:
    _PPTX_AVAILABLE = False

# pypdf
try:
    import pypdf
    _PYPDF_AVAILABLE = True
except ImportError:
    _PYPDF_AVAILABLE = False


def safe_makedirs(file_path: str) -> None:
    """Безопасное создание родительских директорий для файла."""
    d = os.path.dirname(file_path)
    if d:
        os.makedirs(d, exist_ok=True)


def detect_file_encoding(file_path: str) -> str:
    """
    Надежное определение кодировки текстового файла для предотвращения сбоя кодировок:
    - Проверка сигнатур BOM: UTF-8-SIG (\xef\xbb\xbf), UTF-16-LE (\xff\xfe), UTF-16-BE (\xfe\xff)
    - Проверка строгой валидности UTF-8 (чтение до 1 МБ с проверкой декодирования без ошибок)
    - Проверка Windows-1251 (CP1251 — корпоративный стандарт РФ) с подтверждением кириллицы
    - Проверка CP866 (DOS)
    """
    try:
        with open(file_path, "rb") as f:
            raw = f.read(1000000)
        if not raw:
            return "utf-8"

        # 1. Проверка сигнатур BOM
        if raw.startswith(b"\xef\xbb\xbf"):
            return "utf-8-sig"
        if raw.startswith(b"\xff\xfe"):
            return "utf-16-le"
        if raw.startswith(b"\xfe\xff"):
            return "utf-16-be"

        # 2. Строгая проверка на UTF-8
        try:
            raw.decode("utf-8")
            return "utf-8"
        except UnicodeDecodeError:
            pass

        # 3. Проверка на CP1251 (Windows-1251)
        try:
            decoded_1251 = raw.decode("cp1251")
            has_cyrillic = any('\u0400' <= c <= '\u04ff' for c in decoded_1251)
            if has_cyrillic:
                return "cp1251"
        except UnicodeDecodeError:
            pass

        # 4. Проверка на CP866 (DOS)
        try:
            decoded_866 = raw.decode("cp866")
            has_cyrillic_866 = any('\u0400' <= c <= '\u04ff' for c in decoded_866)
            if has_cyrillic_866:
                return "cp866"
        except UnicodeDecodeError:
            pass

        # По умолчанию для русскоязычной Windows, если не UTF-8: CP1251
        return "cp1251"
    except Exception:
        return "utf-8"


def replace_matches_in_runs(runs, replacements):
    """
    Хирургическая замена совпадений внутри отдельных run'ов параграфа.
    Полностью сохраняет стили форматирования: полужирный, курсив, размер шрифта,
    цвет, подчёркивание, выравнивание и ссылки.
    replacements: список кортежей (start, end, replacement_text), non-overlapping, sorted by start.
    """
    if not runs or not replacements:
        return

    # Вычисляем диапазон [start, end) для каждого run в координатах параграфа
    run_spans = []
    offset = 0
    for r in runs:
        txt = r.text or ""
        length = len(txt)
        run_spans.append((offset, offset + length, r, txt))
        offset += length

    for r_start, r_end, run_obj, r_text in run_spans:
        if r_start == r_end:
            continue

        # Совпадения, пересекающие текущий run: m_s < r_end and m_e > r_start
        intersecting = [
            (m_s, m_e, token) for (m_s, m_e, token) in replacements
            if m_s < r_end and m_e > r_start
        ]

        if not intersecting:
            continue

        pieces = []
        curr_pos = r_start

        for m_s, m_e, token in intersecting:
            # 1. Текст до текущего совпадения в этом run
            prefix_end = min(r_end, m_s)
            if prefix_end > curr_pos:
                pieces.append(r_text[curr_pos - r_start : prefix_end - r_start])
                curr_pos = prefix_end

            # 2. Подставляем токен ТОЛЬКО в первый run, содержащий начало совпадения
            if m_s >= r_start:
                pieces.append(token)

            # 3. Пропускаем заменяемую часть
            curr_pos = max(curr_pos, min(r_end, m_e))

        # 4. Текст после последнего совпадения в этом run
        if curr_pos < r_end:
            pieces.append(r_text[curr_pos - r_start : r_end - r_start])

        run_obj.text = "".join(pieces)


class DocumentProcessor:
    """Универсальный процессор для маскирования и восстановления документов различных форматов."""

    SUPPORTED_EXTENSIONS = {
        ".docx", ".doc", ".docm", ".dotx", ".dot",
        ".xlsx", ".xls", ".xlsm",
        ".txt", ".md", ".log", ".sql", ".ini", ".yaml", ".yml",
        ".csv", ".tsv",
        ".json",
        ".xml", ".html", ".htm",
        ".pptx", ".ppt",
        ".pdf",
        ".rtf", ".odt", ".ods"
    }

    def __init__(self, detector: EntityDetector, anonymizer: Anonymizer):
        self.detector = detector
        self.anonymizer = anonymizer

    # =========================================================================
    # WORD (.DOCX / .DOC)
    # =========================================================================

    def _mask_paragraph(self, paragraph) -> int:
        """Маскирует сущности в параграфе Word без повреждения стилей и структуры."""
        full_text = paragraph.text
        if not full_text.strip():
            return 0

        matches = self.detector.find_all(full_text)
        if not matches:
            return 0

        # Получаем все runs параграфа (включая ссылки и вложенные контейнеры)
        if hasattr(paragraph, "_element") and _DOCX_AVAILABLE:
            runs = [docx.text.run.Run(r, paragraph) for r in paragraph._element.xpath('.//w:r')]
        else:
            runs = paragraph.runs

        if not runs or "".join(r.text or "" for r in runs) != full_text:
            masked_text = self.anonymizer.mask_text(full_text, matches)
            if masked_text != full_text:
                paragraph.text = masked_text
                return len(matches)
            return 0

        replacements = []
        for s, e, tag, orig_val in matches:
            token = self.anonymizer.get_or_create_token(tag, orig_val)
            replacements.append((s, e, token))

        replace_matches_in_runs(runs, replacements)
        return len(matches)

    def _unmask_paragraph(self, paragraph) -> int:
        """Восстановление исходного текста в параграфе Word без повреждения стилей и структуры."""
        full_text = paragraph.text
        if not full_text.strip() or "{{" not in full_text or not self.anonymizer.reverse_map:
            return 0

        sorted_tokens = sorted(self.anonymizer.reverse_map.keys(), key=lambda t: len(t), reverse=True)
        escaped_tokens = [re.escape(t) for t in sorted_tokens if t in full_text]
        if not escaped_tokens:
            return 0

        pattern = re.compile("|".join(escaped_tokens))
        replacements = []
        for m in pattern.finditer(full_text):
            token = m.group()
            orig_val = self.anonymizer.reverse_map[token]
            replacements.append((m.start(), m.end(), orig_val))

        if not replacements:
            return 0

        if hasattr(paragraph, "_element") and _DOCX_AVAILABLE:
            runs = [docx.text.run.Run(r, paragraph) for r in paragraph._element.xpath('.//w:r')]
        else:
            runs = paragraph.runs

        if not runs or "".join(r.text or "" for r in runs) != full_text:
            paragraph.text = self.anonymizer.unmask_text(full_text)
            return len(replacements)

        replace_matches_in_runs(runs, replacements)
        return len(replacements)

    def process_docx(self, input_path: str, output_path: str, mode: str = "mask") -> int:
        """Обработка документа Word: параграфы, таблицы (в т.ч. вложенные), колонтитулы, текстбоксы."""
        if not _DOCX_AVAILABLE:
            raise RuntimeError("Библиотека python-docx недоступна.")

        doc = docx.Document(input_path)
        total_changes = 0
        seen_elements = set()

        def _handle_p(p) -> int:
            if hasattr(p, "_element") and p._element in seen_elements:
                return 0
            if hasattr(p, "_element"):
                seen_elements.add(p._element)
            if mode == "mask":
                return self._mask_paragraph(p)
            else:
                return self._unmask_paragraph(p)

        def _handle_table(tbl) -> int:
            changes = 0
            for row in tbl.rows:
                for cell in row.cells:
                    for p in cell.paragraphs:
                        changes += _handle_p(p)
                    for nested_tbl in cell.tables:
                        changes += _handle_table(nested_tbl)
            return changes

        # 1. Параграфы основного документа
        for p in doc.paragraphs:
            total_changes += _handle_p(p)

        # 2. Таблицы (включая вложенные таблицы)
        for table in doc.tables:
            total_changes += _handle_table(table)

        # 3. Колонтитулы (все секции: основные, титульные, четные)
        for section in doc.sections:
            for header_obj in (getattr(section, "header", None),
                               getattr(section, "first_page_header", None),
                               getattr(section, "even_page_header", None)):
                if header_obj is not None:
                    for p in header_obj.paragraphs:
                        total_changes += _handle_p(p)
                    for tbl in header_obj.tables:
                        total_changes += _handle_table(tbl)

            for footer_obj in (getattr(section, "footer", None),
                               getattr(section, "first_page_footer", None),
                               getattr(section, "even_page_footer", None)):
                if footer_obj is not None:
                    for p in footer_obj.paragraphs:
                        total_changes += _handle_p(p)
                    for tbl in footer_obj.tables:
                        total_changes += _handle_table(tbl)

        # 4. Текстбоксы (Shape textboxes: <w:txbxContent>)
        for txbx_p_el in doc._element.xpath('.//w:txbxContent//w:p'):
            txbx_p = docx.text.paragraph.Paragraph(txbx_p_el, doc)
            total_changes += _handle_p(txbx_p)

        safe_makedirs(output_path)
        doc.save(output_path)
        return total_changes

    def _get_doc_pieces(self, ole_file):
        """
        Извлекает сегменты текста (Piece Table, Plcfpcd) из бинарного файла Word 97-2003 (.doc).
        Возвращает список словарей со смещениями в потоке WordDocument и кодировками.
        """
        w_stream = ole_file.openstream('WordDocument').read()
        flags = struct.unpack('<H', w_stream[10:12])[0]
        tbl_name = '1Table' if (flags & 0x0200) else '0Table'
        t_stream = ole_file.openstream(tbl_name).read()

        fcClx, lcbClx = struct.unpack('<II', w_stream[418:426])
        clx = t_stream[fcClx:fcClx + lcbClx]

        pieces = []
        pos = 0
        while pos < len(clx):
            clxt = clx[pos]
            if clxt == 1:
                pos += 1
                cbGrpprl = struct.unpack('<H', clx[pos:pos + 2])[0]
                pos += 2 + cbGrpprl
            elif clxt == 2:
                pos += 1
                lcb = struct.unpack('<I', clx[pos:pos + 4])[0]
                pos += 4
                pcd_data = clx[pos:pos + lcb]
                n = (lcb - 4) // 12
                cps = struct.unpack(f'<{n + 1}I', pcd_data[:(n + 1) * 4])
                pcds_offset = (n + 1) * 4
                for i in range(n):
                    pcd = pcd_data[pcds_offset + i * 8: pcds_offset + (i + 1) * 8]
                    fc = struct.unpack('<I', pcd[2:6])[0]
                    is_compressed = (fc & (1 << 30)) != 0
                    real_fc = (fc & ~(1 << 30)) // 2 if is_compressed else (fc & ~(1 << 30))
                    enc = 'cp1251' if is_compressed else 'utf-16le'
                    char_count = cps[i + 1] - cps[i]
                    byte_count = char_count if is_compressed else char_count * 2
                    raw_bytes = w_stream[real_fc:real_fc + byte_count]
                    txt = raw_bytes.decode(enc, errors='replace')
                    pieces.append({
                        'cp_start': cps[i],
                        'cp_end': cps[i + 1],
                        'fc': real_fc,
                        'is_compressed': is_compressed,
                        'encoding': enc,
                        'raw_bytes': raw_bytes,
                        'text': txt
                    })
                break
            else:
                pos += 1

        return pieces, tbl_name

    def process_doc_ole2(self, input_path: str, output_path: str, mode: str = "mask") -> int:
        """
        Прецизионная обработка бинарных файлов Word 97-2003 (.doc, OLE2) in-place:
        Модифицирует поток WordDocument напрямую на основе Piece Table (Plcfpcd).
        Полностью сохраняет 100% структуры: таблицы, рамки, штампы, рисунки, шрифты, стили,
        без изменения общего размера файла и смещений структур OLE2.
        """
        safe_makedirs(output_path)
        shutil.copyfile(input_path, output_path)

        if not (_OLEFILE_AVAILABLE and olefile.isOleFile(output_path)):
            return self.process_txt(input_path, output_path, mode=mode)

        try:
            ole = olefile.OleFileIO(output_path, write_mode=True)
            if not ole.exists('WordDocument'):
                ole.close()
                return self.process_txt(input_path, output_path, mode=mode)

            pieces, tbl_name = self._get_doc_pieces(ole)
            if not pieces:
                ole.close()
                return 0

            w_stream = bytearray(ole.openstream('WordDocument').read())
            full_text = "".join(p['text'] for p in pieces)
            total_changes = 0

            if mode == "mask":
                matches = self.detector.find_all(full_text)
                if not matches:
                    ole.close()
                    return 0

                replacements = []
                for s, e, tag, orig_val in matches:
                    needed_len = e - s
                    token = self.anonymizer.get_or_create_exact_token(tag, orig_val, needed_len)
                    assert len(token) == needed_len == len(orig_val), f"Token length mismatch: {len(token)} != {needed_len}"
                    replacements.append((s, e, token))
                    total_changes += 1

                for p in pieces:
                    p_s = p['cp_start']
                    p_e = p['cp_end']
                    p_text = list(p['text'])
                    modified = False

                    for m_s, m_e, token in replacements:
                        if m_s < p_e and m_e > p_s:
                            inter_s = max(m_s, p_s)
                            inter_e = min(m_e, p_e)
                            tok_start = inter_s - m_s
                            tok_end = tok_start + (inter_e - inter_s)
                            p_text[inter_s - p_s : inter_e - p_s] = list(token[tok_start:tok_end])
                            modified = True

                    if modified:
                        new_str = "".join(p_text)
                        new_bytes = new_str.encode(p['encoding'])
                        assert len(new_bytes) == len(p['raw_bytes']), "Byte count mismatch in doc piece"
                        w_stream[p['fc'] : p['fc'] + len(new_bytes)] = new_bytes

            else:
                # UNMASK MODE
                if not self.anonymizer.reverse_map:
                    ole.close()
                    return 0

                sorted_tokens = sorted(self.anonymizer.reverse_map.keys(), key=lambda t: len(t), reverse=True)
                escaped = [re.escape(t) for t in sorted_tokens if t in full_text]
                if not escaped:
                    ole.close()
                    return 0

                pattern = re.compile("|".join(escaped))
                replacements = []
                for m in pattern.finditer(full_text):
                    token = m.group()
                    orig_val = self.anonymizer.reverse_map[token]
                    replacements.append((m.start(), m.end(), orig_val))
                    total_changes += 1

                for p in pieces:
                    p_s = p['cp_start']
                    p_e = p['cp_end']
                    p_text = list(p['text'])
                    modified = False

                    for m_s, m_e, orig_val in replacements:
                        if m_s < p_e and m_e > p_s:
                            inter_s = max(m_s, p_s)
                            inter_e = min(m_e, p_e)
                            orig_start = inter_s - m_s
                            orig_end = orig_start + (inter_e - inter_s)
                            p_text[inter_s - p_s : inter_e - p_s] = list(orig_val[orig_start:orig_end])
                            modified = True

                    if modified:
                        new_str = "".join(p_text)
                        new_bytes = new_str.encode(p['encoding'])
                        assert len(new_bytes) == len(p['raw_bytes']), "Byte count mismatch in doc piece unmask"
                        w_stream[p['fc'] : p['fc'] + len(new_bytes)] = new_bytes

            ole.write_stream('WordDocument', bytes(w_stream))
            ole.close()
            return total_changes

        except Exception:
            return self.process_txt(input_path, output_path, mode=mode)

    def process_doc_or_docx(self, input_path: str, output_path: str, mode: str = "mask") -> int:
        """Универсальная обработка файлов .doc и .docx."""
        try:
            with open(input_path, "rb") as f:
                header = f.read(8)
        except Exception:
            header = b""

        # 1. Если файл в формате OpenXML (начинается с PK\x03\x04), даже если расширение .doc
        if header.startswith(b"PK\x03\x04") or (input_path.lower().endswith(".docx") and not header.startswith(b"\xd0\xcf\x11\xe0")):
            changes = self.process_docx(input_path, output_path, mode=mode)
            if output_path.lower().endswith(".doc"):
                docx_alt = output_path + "x"
                try:
                    shutil.copyfile(output_path, docx_alt)
                except Exception:
                    pass
            return changes

        # 2. Если файл RTF (начинается с {\rtf)
        elif header.startswith(b"{\\rtf"):
            return self.process_txt(input_path, output_path, mode=mode)

        # 3. Бинарный OLE2 формат (.doc 97-2003)
        else:
            return self.process_doc_ole2(input_path, output_path, mode=mode)

    # =========================================================================
    # EXCEL (.XLSX / .XLS)
    # =========================================================================

    def process_xlsx(self, input_path: str, output_path: str, mode: str = "mask") -> int:
        """
        Обработка книги Excel (.xlsx):
        - пропуск формул (начинающихся с '=')
        - обработка строковых ячеек (ФИО, адреса, реквизиты)
        - обработка числовых ячеек (телефоны, ИНН, карты, записанные как int)
        """
        if not _OPENPYXL_AVAILABLE:
            raise RuntimeError("Библиотека openpyxl недоступна.")

        wb = openpyxl.load_workbook(input_path)
        total_changes = 0

        for sheet in wb.worksheets:
            for row in sheet.iter_rows():
                for cell in row:
                    val = cell.value
                    if val is None:
                        continue

                    # Пропуск формул
                    if isinstance(val, str) and val.startswith("="):
                        continue

                    # Режим маскирования
                    if mode == "mask":
                        if isinstance(val, str) and val.strip():
                            matches = self.detector.find_all(val)
                            if matches:
                                cell.value = self.anonymizer.mask_text(val, matches)
                                total_changes += len(matches)
                        elif isinstance(val, int):
                            val_str = str(val)
                            if len(val_str) in (10, 11, 12, 13, 15, 16, 20):
                                matches = self.detector.find_all(val_str)
                                if matches:
                                    cell.value = self.anonymizer.mask_text(val_str, matches)
                                    total_changes += len(matches)

                    # Режим восстановления
                    else:
                        if isinstance(val, str) and "{{" in val:
                            restored = self.anonymizer.unmask_text(val)
                            if restored != val:
                                if restored.isdigit() and len(restored) <= 15:
                                    try:
                                        cell.value = int(restored)
                                    except Exception:
                                        cell.value = restored
                                else:
                                    cell.value = restored
                                total_changes += 1

        safe_makedirs(output_path)
        wb.save(output_path)
        return total_changes

    def process_xls_legacy(self, input_path: str, output_path: str, mode: str = "mask") -> int:
        """
        Обработка бинарных книг Excel 97-2003 (.xls, BIFF8) через xlrd и xlutils:
        Не повреждает структуру книги и формулы.
        """
        if not _XLS_LEGACY_AVAILABLE:
            raise RuntimeError("Библиотеки xlrd/xlwt/xlutils недоступны для старого формата .xls")

        try:
            rb = xlrd.open_workbook(input_path, formatting_info=True)
        except Exception:
            rb = xlrd.open_workbook(input_path, formatting_info=False)
        wb = xlutils_copy(rb)
        total_changes = 0

        for sheet_idx in range(rb.nsheets):
            sheet = rb.sheet_by_index(sheet_idx)
            ws = wb.get_sheet(sheet_idx)
            for row_idx in range(sheet.nrows):
                for col_idx in range(sheet.ncols):
                    val = sheet.cell_value(row_idx, col_idx)
                    if isinstance(val, str) and val.strip():
                        if mode == "mask":
                            matches = self.detector.find_all(val)
                            if matches:
                                ws.write(row_idx, col_idx, self.anonymizer.mask_text(val, matches))
                                total_changes += len(matches)
                        else:
                            if "{{" in val:
                                restored = self.anonymizer.unmask_text(val)
                                if restored != val:
                                    ws.write(row_idx, col_idx, restored)
                                    total_changes += 1
                    elif isinstance(val, (int, float)) and mode == "mask":
                        if isinstance(val, float) and val.is_integer():
                            val_int = int(val)
                            val_str = str(val_int)
                        elif isinstance(val, int):
                            val_str = str(val)
                        else:
                            val_str = ""
                        if len(val_str) in (10, 11, 12, 13, 15, 16, 20):
                            matches = self.detector.find_all(val_str)
                            if matches:
                                ws.write(row_idx, col_idx, self.anonymizer.mask_text(val_str, matches))
                                total_changes += len(matches)

        safe_makedirs(output_path)
        wb.save(output_path)
        return total_changes

    def process_excel(self, input_path: str, output_path: str, mode: str = "mask") -> int:
        """Универсальная обработка Excel (.xlsx, .xls, .xlsm)."""
        try:
            with open(input_path, "rb") as f:
                header = f.read(8)
        except Exception:
            header = b""

        # Если это OpenXML (PK\x03\x04), даже названный .xls
        if header.startswith(b"PK\x03\x04") or input_path.lower().endswith((".xlsx", ".xlsm")):
            changes = self.process_xlsx(input_path, output_path, mode=mode)
            # Дублируем как .xlsx, если файл был назван .xls, чтобы Excel не ругался на расширение
            if output_path.lower().endswith(".xls"):
                try:
                    shutil.copyfile(output_path, output_path + "x")
                except Exception:
                    pass
            return changes
        else:
            try:
                return self.process_xls_legacy(input_path, output_path, mode=mode)
            except Exception:
                try:
                    return self.process_xlsx(input_path, output_path, mode=mode)
                except Exception:
                    return self.process_txt(input_path, output_path, mode=mode)

    # =========================================================================
    # TEXT (.TXT, .MD, .LOG, .RTF, etc.)
    # =========================================================================

    def process_txt(self, input_path: str, output_path: str, mode: str = "mask") -> int:
        """Обработка текстовых файлов с точным сохранением исходной кодировки."""
        encoding = detect_file_encoding(input_path)
        with open(input_path, "r", encoding=encoding, errors="replace") as f:
            content = f.read()

        total_changes = 0
        if mode == "mask":
            matches = self.detector.find_all(content)
            if matches:
                new_content = self.anonymizer.mask_text(content, matches)
                total_changes = len(matches)
            else:
                new_content = content
        else:
            new_content = self.anonymizer.unmask_text(content)
            if new_content != content:
                total_changes = 1

        safe_makedirs(output_path)
        # Сохраняем файл строго в той же кодировке (CP1251, UTF-8, CP866), в которой он был открыт
        with open(output_path, "w", encoding=encoding, errors="replace") as f:
            f.write(new_content)

        return total_changes

    # =========================================================================
    # CSV (.CSV, .TSV)
    # =========================================================================

    def process_csv(self, input_path: str, output_path: str, mode: str = "mask") -> int:
        """Обработка CSV/TSV файлов с автоопределением разделителя и сохранением кодировки."""
        encoding = detect_file_encoding(input_path)
        with open(input_path, "r", encoding=encoding, errors="replace", newline="") as f:
            sample = f.read(8192)
            f.seek(0)
            delimiter = ","
            try:
                dialect = csv.Sniffer().sniff(sample)
                delimiter = dialect.delimiter
            except Exception:
                if ";" in sample:
                    delimiter = ";"
                elif "\t" in sample:
                    delimiter = "\t"

            reader = csv.reader(f, delimiter=delimiter)
            rows = list(reader)

        total_changes = 0
        new_rows = []
        for row in rows:
            new_row = []
            for cell in row:
                if cell.strip():
                    if mode == "mask":
                        matches = self.detector.find_all(cell)
                        if matches:
                            cell = self.anonymizer.mask_text(cell, matches)
                            total_changes += len(matches)
                    else:
                        restored = self.anonymizer.unmask_text(cell)
                        if restored != cell:
                            cell = restored
                            total_changes += 1
                new_row.append(cell)
            new_rows.append(new_row)

        safe_makedirs(output_path)
        # Если исходный файл был UTF-8 или UTF-8-SIG — сохраняем с сигнатурой BOM (utf-8-sig),
        # чтобы Microsoft Excel на русской Windows открывал кириллицу корректно без кракозябр.
        # Если исходный файл был в CP1251 или CP866 — сохраняем строго в CP1251/CP866!
        if encoding in ("utf-8", "utf-8-sig"):
            write_encoding = "utf-8-sig"
        else:
            write_encoding = encoding

        with open(output_path, "w", encoding=write_encoding, errors="replace", newline="") as f:
            writer = csv.writer(f, delimiter=delimiter)
            writer.writerows(new_rows)

        return total_changes

    # =========================================================================
    # JSON (.JSON)
    # =========================================================================

    def process_json(self, input_path: str, output_path: str, mode: str = "mask") -> int:
        """Обработка JSON файлов со структурированными полями."""
        encoding = detect_file_encoding(input_path)
        with open(input_path, "r", encoding=encoding, errors="replace") as f:
            data = json.load(f)

        total_changes = [0]

        def transform_obj(obj):
            if isinstance(obj, dict):
                return {k: transform_obj(v) for k, v in obj.items()}
            elif isinstance(obj, list):
                return [transform_obj(item) for item in obj]
            elif isinstance(obj, str) and obj.strip():
                if mode == "mask":
                    matches = self.detector.find_all(obj)
                    if matches:
                        total_changes[0] += len(matches)
                        return self.anonymizer.mask_text(obj, matches)
                else:
                    restored = self.anonymizer.unmask_text(obj)
                    if restored != obj:
                        total_changes[0] += 1
                        return restored
            return obj

        transformed = transform_obj(data)

        safe_makedirs(output_path)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(transformed, f, ensure_ascii=False, indent=2)

        return total_changes[0]

    # =========================================================================
    # POWERPOINT (.PPTX, .PPT)
    # =========================================================================

    def process_pptx(self, input_path: str, output_path: str, mode: str = "mask") -> int:
        """Обработка презентаций PowerPoint (.pptx) с полным сохранением стилей runs."""
        if not _PPTX_AVAILABLE:
            raise RuntimeError("Библиотека python-pptx недоступна.")

        prs = Presentation(input_path)
        total_changes = 0

        def _process_paragraph(paragraph) -> int:
            full_text = paragraph.text
            if not full_text.strip():
                return 0

            if mode == "mask":
                matches = self.detector.find_all(full_text)
                if not matches:
                    return 0

                runs = paragraph.runs
                if not runs or "".join(r.text or "" for r in runs) != full_text:
                    masked = self.anonymizer.mask_text(full_text, matches)
                    if masked != full_text:
                        paragraph.text = masked
                        return len(matches)
                    return 0

                replacements = []
                for s, e, tag, orig_val in matches:
                    token = self.anonymizer.get_or_create_token(tag, orig_val)
                    replacements.append((s, e, token))

                replace_matches_in_runs(runs, replacements)
                return len(matches)
            else:
                if "{{" not in full_text or not self.anonymizer.reverse_map:
                    return 0

                sorted_tokens = sorted(self.anonymizer.reverse_map.keys(), key=lambda t: len(t), reverse=True)
                escaped_tokens = [re.escape(t) for t in sorted_tokens if t in full_text]
                if not escaped_tokens:
                    return 0

                pattern = re.compile("|".join(escaped_tokens))
                replacements = []
                for m in pattern.finditer(full_text):
                    token = m.group()
                    orig_val = self.anonymizer.reverse_map[token]
                    replacements.append((m.start(), m.end(), orig_val))

                if not replacements:
                    return 0

                runs = paragraph.runs
                if not runs or "".join(r.text or "" for r in runs) != full_text:
                    paragraph.text = self.anonymizer.unmask_text(full_text)
                    return len(replacements)

                replace_matches_in_runs(runs, replacements)
                return len(replacements)

        def _iter_shape_paragraphs(shape):
            if shape.has_text_frame:
                for p in shape.text_frame.paragraphs:
                    yield p
            if shape.has_table:
                for row in shape.table.rows:
                    for cell in row.cells:
                        for p in cell.text_frame.paragraphs:
                            yield p
            if hasattr(shape, "shapes"):
                for sub_shape in shape.shapes:
                    yield from _iter_shape_paragraphs(sub_shape)

        for slide in prs.slides:
            for shape in slide.shapes:
                for p in _iter_shape_paragraphs(shape):
                    total_changes += _process_paragraph(p)

        safe_makedirs(output_path)
        prs.save(output_path)
        return total_changes

    # =========================================================================
    # PDF (.PDF)
    # =========================================================================

    def process_pdf(self, input_path: str, output_path: str, mode: str = "mask") -> int:
        """Обработка PDF: извлечение и создание маскированной текстовой версии."""
        if not _PYPDF_AVAILABLE:
            raise RuntimeError("Библиотека pypdf недоступна.")

        reader = pypdf.PdfReader(input_path)
        text_pages = []
        total_changes = 0

        for page in reader.pages:
            page_text = page.extract_text() or ""
            if mode == "mask":
                matches = self.detector.find_all(page_text)
                if matches:
                    page_text = self.anonymizer.mask_text(page_text, matches)
                    total_changes += len(matches)
            else:
                restored = self.anonymizer.unmask_text(page_text)
                if restored != page_text:
                    page_text = restored
                    total_changes += 1
            text_pages.append(page_text)

        full_doc = "\n\n--- СТРАНИЦА ---\n\n".join(text_pages)

        txt_output = os.path.splitext(output_path)[0] + "_processed.txt"
        safe_makedirs(txt_output)
        with open(txt_output, "w", encoding="utf-8") as f:
            f.write(full_doc)

        return total_changes

    # =========================================================================
    # ДИСПЕТЧЕР ФОРМАТОВ
    # =========================================================================

    def process_file(self, input_path: str, output_path: str, mode: str = "mask") -> int:
        """Единая точка входа для обработки файла любого поддерживаемого формата."""
        ext = os.path.splitext(input_path)[1].lower()

        if ext in {".docx", ".doc", ".docm", ".dotx", ".dot"}:
            return self.process_doc_or_docx(input_path, output_path, mode=mode)
        elif ext in {".xlsx", ".xls", ".xlsm", ".xltx"}:
            return self.process_excel(input_path, output_path, mode=mode)
        elif ext in {".txt", ".md", ".log", ".sql", ".ini", ".yaml", ".yml", ".rtf", ".odt", ".ods"}:
            return self.process_txt(input_path, output_path, mode=mode)
        elif ext in {".csv", ".tsv"}:
            return self.process_csv(input_path, output_path, mode=mode)
        elif ext == ".json":
            return self.process_json(input_path, output_path, mode=mode)
        elif ext in {".xml", ".html", ".htm"}:
            return self.process_txt(input_path, output_path, mode=mode)
        elif ext in {".pptx", ".ppt"}:
            return self.process_pptx(input_path, output_path, mode=mode)
        elif ext == ".pdf":
            return self.process_pdf(input_path, output_path, mode=mode)
        else:
            # Для любых других файлов пробуем обработать как текст
            return self.process_txt(input_path, output_path, mode=mode)
