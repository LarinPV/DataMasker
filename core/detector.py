"""
Высокоточный модуль поиска и распознавания персональных и конфиденциальных данных (Entity Detector).
Объединяет:
- Алгоритмический поиск и строгую валидацию контрольных сумм РФ (ИНН, ОГРН, СНИЛС, БИК, Счета, Карты)
- Регулярные выражения высокой точности (Телефоны, Email, Паспорта, КПП, Орг. структуры, Адреса, ФИО)
- Локальный NLP-анализ через Natasha (NamesExtractor, AddrExtractor, MorphVocab) с интеллектуальной фильтрацией
- Поддержку пользовательских исключений (White-list) и собственных правил (Custom Regex)
- Безотказную работу в 100% офлайн-режиме
"""

import re
from typing import List, Tuple, Dict, Set, Optional
from .checksums import (
    validate_inn,
    validate_ogrn,
    validate_snils,
    validate_kpp,
    validate_bik,
    validate_bank_account,
    validate_luhn
)
from .patterns import (
    EMAIL_PATTERN,
    STRICT_PHONE_PATTERN,
    PHONE_PATTERN,
    SNILS_PATTERN,
    PASSPORT_PATTERN,
    CONTEXT_PASSPORT_SERIES,
    CONTEXT_PASSPORT_NUMBER,
    INN_PATTERN,
    OGRN_PATTERN,
    KPP_PATTERN,
    CONTEXT_KPP_PATTERN,
    BIK_PATTERN,
    BANK_ACCOUNT_PATTERN,
    CREDIT_CARD_PATTERN,
    ORG_PATTERN_QUOTED,
    ORG_PATTERN_UNQUOTED,
    FIO_FULL_PATTERN,
    FIO_2_WORDS_PATTERN,
    FIO_SURNAME_INITIALS,
    FIO_INITIALS_SURNAME,
    FIO_NAME_INITIALS,
    FIO_INITIALS_MIDDLE,
    FIO_SURNAME_INIT_PATR,
    DOUBLE_SURNAME_PATTERN,
    SHORT_SURNAMES_PATTERN,
    PATRONYMIC_PATTERN,
    CONTEXT_SURNAME_PATTERN,
    SIGNATURE_SURNAME_PATTERN,
    SURNAME_MORPH_PATTERN,
    POSTAL_CODE_PATTERN,
    ADDRESS_PATTERN
)

# Стоп-слова для исключения ложных срабатываний ФИО (должности, роли, термины актов и смет)
FIO_STOP_WORDS = {
    # Приветствия и общие
    "добрый", "день", "утро", "вечер", "привет", "здравствуйте",
    # Должности и роли (не должны маскироваться отдельно от фамилий!)
    "заявитель", "заявителя", "заявителю", "заявителем",
    "собственник", "собственника", "собственнику", "собственником",
    "представитель", "представителя", "представителю", "представителем",
    "инженер", "инженера", "инженеру", "инженером",
    "прораб", "прораба", "прорабу", "прорабом",
    "мастер", "мастера", "мастеру", "мастером",
    "директор", "директора", "директору", "директором", "гендиректор",
    "начальник", "начальника", "начальнику", "начальником",
    "руководитель", "руководителя", "руководителю", "руководителем",
    "заказчик", "заказчика", "заказчику", "заказчиком",
    "подрядчик", "подрядчика", "подрядчику", "подрядчиком", "генподрядчик",
    "застройщик", "застройщика", "застройщику", "застройщиком",
    "исполнитель", "исполнителя", "исполнителю", "исполнителем",
    "техник", "техника", "технику", "техником",
    "бригадир", "монтажник", "слесарь", "электрик", "сантехник",
    "специалист", "эксперт", "бухгалтер", "юрист", "секретарь", "председатель",
    "гражданин", "гражданка", "сторона", "стороны", "стороной",
    # Виды документов
    "акт", "акта", "акту", "актом", "акте",
    "договор", "договора", "договору", "договором", "договоре",
    "смета", "сметы", "смете", "сметой", "ведомость", "ведомости",
    "заявление", "заявления", "заявлению", "заявлением",
    "претензия", "претензии", "претензию", "соглашение", "соглашения",
    "приложение", "приложения", "протокол", "протокола", "паспорт", "паспорта",
    "расписка", "счет", "счета", "фактура", "квитанция", "чек",
    "обязательства", "гарантия", "гарантии", "гарантийных", "гарантийным",
    "замечания", "замечаний", "устранение", "устранения", "устранению",
    # Термины работ и строительства
    "работа", "работы", "работу", "работам", "работой",
    "услуга", "услуги", "услуг", "товар", "товара", "товаров",
    "объект", "объекта", "объекту", "объектом", "объекте",
    "помещение", "помещения", "помещению", "помещением",
    "квартира", "квартиры", "квартире", "квартиру", "квартирой",
    "дом", "дома", "дому", "домом", "доме", "этаж", "этажа", "подъезд",
    "стена", "стены", "стен", "потолок", "потолка", "пол", "пола",
    "дверь", "двери", "окно", "окна", "шов", "стык", "дефект",
    "монтаж", "монтажа", "демонтаж", "установка", "замена", "ремонт",
    "плитка", "кабель", "розетка", "штукатурка", "клей", "труба", "кран",
    # Глаголы и служебные слова актов
    "составил", "составили", "сдал", "сдали", "принял", "приняли",
    "устранил", "устранили", "подписал", "подписали", "проверил",
    "настоящий", "настоящего", "указанный", "вышеуказанный", "соответствующий",
    "цена", "сумма", "итого", "всего", "руб", "рублей", "коп",
    "пункт", "раздел", "лист", "номер", "дата", "подпись",
    # Технические и документные аббревиатуры (не должны быть ФИО!)
    "зр", "тз", "пр", "рф", "ук", "тс", "гк", "сз", "смет", "ведом", "пом",
    # Города, регионы и органы выдачи документов
    "омск", "омска", "омску", "омском", "омске", "омская", "омской", "омскую", "омское",
    "кировский", "кировском", "кировского", "кировскому", "кировским",
    "округ", "округе", "округа", "округом", "гор", "город", "города",
    "отдел", "отделом", "отдела", "отделе", "уфмс", "мвд", "гувм", "россии",
    "банк", "банка", "банке", "банку", "банком",
    "информация", "информации", "информацию", "контактный", "контактная", "контактные",
    "вид", "вида", "виду", "видом", "виде", "тип", "типа", "типу", "типом", "типе",
    "том", "тома", "тому", "томом", "томе", "код", "кода", "коду", "кодом", "коде",
    # Термины чертежей, штампов ГОСТ и таблиц
    "кол", "кол-во", "величина", "величины", "величинам", "величиной",
    "объем", "объема", "объему", "объемом", "объеме",
    "участок", "участка", "участку", "участком", "участке", "участков",
    "лист", "листа", "листу", "листом", "листе", "листов",
    "масштаб", "масштаба", "стадия", "стадии", "раздел", "раздела", "шифр", "шифра",
    "согласовал", "утвердил", "гип", "гап", "нконтр", "изм", "подп",
    # Предлоги и союзы
    "по", "в", "на", "от", "для", "при", "до", "из", "под", "над", "без", "через", "со", "ко", "во"
}

# Якорные адресные слова
ADDRESS_ANCHORS = re.compile(
    r'\b(?:ул\b|улица|пер\b|переулок|пр-кт|проспект|проезд|ш\b|шоссе|бул\b|бульвар|наб\b|набережная|'
    r'г\b|город|пос\b|поселок|пгт|село|дер\b|деревня|обл\b|область|край|район|'
    r'д\b|дом|кв\b|квартира|оф\b|офис|корп\b|корпус|стр\b|строение)\b',
    re.IGNORECASE
)

# Стоп-фразы строительных и технических локаций
CONSTRUCTION_LOC_STOP = re.compile(
    r'\b(?:в штробе|в коробе|в стене|в полу|на стену|на пол|в санузле|в ванной|'
    r'на потолок|в потолке|к розетке|к распределительной коробке|в распределительной коробке|'
    r'в кабель-канале|по стене|по полу|в зоне душевой|в стяжке|под плитку|в штробу)\b',
    re.IGNORECASE
)

# Кэширование синглтонов Natasha
_NATASHA_INITED = False
_NAMES_EXTRACTOR = None
_ADDR_EXTRACTOR = None

try:
    from natasha import (
        Segmenter,
        MorphVocab,
        NamesExtractor,
        AddrExtractor
    )
    _morph_vocab = MorphVocab()
    _NAMES_EXTRACTOR = NamesExtractor(_morph_vocab)
    _ADDR_EXTRACTOR = AddrExtractor(_morph_vocab)
    _NATASHA_INITED = True
except Exception:
    _NATASHA_INITED = False


class EntityDetector:
    """Класс для обнаружения сущностей в тексте."""

    DEFAULT_TYPES = {
        "ФИО": True,
        "ОРГ": True,
        "ИНН": True,
        "ОГРН": True,
        "КПП": True,
        "БИК": True,
        "РСЧЕТ": True,
        "ТЕЛ": True,
        "EMAIL": True,
        "ПАСПОРТ": True,
        "СНИЛС": True,
        "АДРЕС": True,
        "КАРТА": True,
    }

    def __init__(self, enabled_types: Optional[Dict[str, bool]] = None, whitelist: Optional[List[str]] = None):
        self.enabled_types = dict(self.DEFAULT_TYPES)
        if enabled_types:
            self.enabled_types.update(enabled_types)

        self.whitelist: Set[str] = set()
        if whitelist:
            for item in whitelist:
                s = item.strip()
                if s:
                    self.whitelist.add(s.lower())

        self.custom_patterns: List[Tuple[re.Pattern, str]] = []

    def add_custom_rule(self, pattern_str: str, tag: str) -> bool:
        """Добавить пользовательское регулярное выражение."""
        try:
            compiled = re.compile(pattern_str, re.IGNORECASE)
            self.custom_patterns.append((compiled, tag))
            return True
        except Exception:
            return False

    def is_whitelisted(self, text: str) -> bool:
        """Проверка, входит ли строка в белый список исключений."""
        clean = text.strip().lower()
        return clean in self.whitelist

    def find_all(self, text: str) -> List[Tuple[int, int, str, str]]:
        """
        Ищет все сущности в тексте.
        Возвращает список: (start_index, end_index, tag_name, matched_substring).
        """
        if not text or not isinstance(text, str):
            return []

        # Быстрый фильтр: строки короче 4 символов не содержат сущностей
        if len(text.strip()) < 4:
            return []

        raw_matches: List[Tuple[int, int, str, str]] = []

        # 1. Email
        if self.enabled_types.get("EMAIL", True) and "@" in text:
            for m in EMAIL_PATTERN.finditer(text):
                val = m.group()
                if not self.is_whitelisted(val):
                    raw_matches.append((m.start(), m.end(), "EMAIL", val))

        # 2. Банковские карты (с проверкой алгоритма Луна)
        if self.enabled_types.get("КАРТА", True) and any(c.isdigit() for c in text):
            for m in CREDIT_CARD_PATTERN.finditer(text):
                val = m.group()
                clean_digits = re.sub(r'\D', '', val)
                if validate_luhn(clean_digits) and not self.is_whitelisted(val):
                    raw_matches.append((m.start(), m.end(), "КАРТА", val))

        # 3. ИНН (10 и 12 цифр с валидацией контрольных сумм)
        if self.enabled_types.get("ИНН", True) and any(c.isdigit() for c in text):
            for m in INN_PATTERN.finditer(text):
                val = m.group()
                if validate_inn(val) and not self.is_whitelisted(val):
                    raw_matches.append((m.start(), m.end(), "ИНН", val))

        # 4. ОГРН и ОГРНИП (13 и 15 цифр с проверкой деления)
        if self.enabled_types.get("ОГРН", True) and any(c.isdigit() for c in text):
            for m in OGRN_PATTERN.finditer(text):
                val = m.group()
                if validate_ogrn(val) and not self.is_whitelisted(val):
                    raw_matches.append((m.start(), m.end(), "ОГРН", val))

        # 5. СНИЛС (с алгоритмом ПФР)
        if self.enabled_types.get("СНИЛС", True) and any(c.isdigit() for c in text):
            for m in SNILS_PATTERN.finditer(text):
                val = m.group()
                clean_snils = re.sub(r'\D', '', val)
                if validate_snils(clean_snils) and not self.is_whitelisted(val):
                    raw_matches.append((m.start(), m.end(), "СНИЛС", val))

        # 6. БИК
        if self.enabled_types.get("БИК", True) and "04" in text:
            for m in BIK_PATTERN.finditer(text):
                val = m.group()
                if validate_bik(val) and not self.is_whitelisted(val):
                    raw_matches.append((m.start(), m.end(), "БИК", val))

        # 7. Расчетные и корр. счета (20 цифр)
        if self.enabled_types.get("РСЧЕТ", True) and any(c.isdigit() for c in text):
            for m in BANK_ACCOUNT_PATTERN.finditer(text):
                val = m.group()
                if validate_bank_account(val) and not self.is_whitelisted(val):
                    raw_matches.append((m.start(), m.end(), "РСЧЕТ", val))

        # 8. КПП (в контексте)
        if self.enabled_types.get("КПП", True):
            for m in CONTEXT_KPP_PATTERN.finditer(text):
                val = m.group(1)
                if validate_kpp(val) and not self.is_whitelisted(val):
                    raw_matches.append((m.start(1), m.end(1), "КПП", val))

        # 9. Паспорта РФ
        if self.enabled_types.get("ПАСПОРТ", True) and any(c.isdigit() for c in text):
            for m in PASSPORT_PATTERN.finditer(text):
                val = m.group()
                digits_only = re.sub(r'\D', '', val)
                if len(digits_only) == 10 and not self.is_whitelisted(val):
                    raw_matches.append((m.start(), m.end(), "ПАСПОРТ", val))
            for m in CONTEXT_PASSPORT_SERIES.finditer(text):
                val = m.group(1)
                digits_only = re.sub(r'\D', '', val)
                if len(digits_only) == 4 and not self.is_whitelisted(val):
                    raw_matches.append((m.start(1), m.end(1), "ПАСПОРТ", val))
            for m in CONTEXT_PASSPORT_NUMBER.finditer(text):
                val = m.group(1)
                digits_only = re.sub(r'\D', '', val)
                if len(digits_only) == 6 and not self.is_whitelisted(val):
                    raw_matches.append((m.start(1), m.end(1), "ПАСПОРТ", val))

        # 10. Телефоны (строгие российские форматы 10-11 цифр)
        if self.enabled_types.get("ТЕЛ", True) and any(c.isdigit() for c in text):
            for m in STRICT_PHONE_PATTERN.finditer(text):
                val = m.group()
                clean_digits = re.sub(r'\D', '', val)
                if 10 <= len(clean_digits) <= 11 and not self.is_whitelisted(val):
                    raw_matches.append((m.start(), m.end(), "ТЕЛ", val))

        # 11. Организации (ООО, АО, ИП и др.)
        if self.enabled_types.get("ОРГ", True):
            for m in ORG_PATTERN_QUOTED.finditer(text):
                val = m.group()
                if not self.is_whitelisted(val):
                    raw_matches.append((m.start(), m.end(), "ОРГ", val))
            for m in ORG_PATTERN_UNQUOTED.finditer(text):
                val = m.group()
                if not self.is_whitelisted(val):
                    raw_matches.append((m.start(), m.end(), "ОРГ", val))

        # 12. Адреса (улицы, дома, квартиры)
        if self.enabled_types.get("АДРЕС", True):
            # Шаблоны адресов
            for m in ADDRESS_PATTERN.finditer(text):
                val = m.group().strip()
                if not CONSTRUCTION_LOC_STOP.search(val) and not self.is_whitelisted(val):
                    raw_matches.append((m.start(), m.end(), "АДРЕС", val))

            # Почтовые индексы (6 цифр) в адресном контексте
            if any(c.isdigit() for c in text) and ADDRESS_ANCHORS.search(text):
                for m in POSTAL_CODE_PATTERN.finditer(text):
                    val = m.group(1)
                    if not self.is_whitelisted(val):
                        raw_matches.append((m.start(1), m.end(1), "АДРЕС", val))

            # Natasha AddrExtractor с обязательной проверкой адресных якорей
            if _ADDR_EXTRACTOR and ADDRESS_ANCHORS.search(text):
                try:
                    for match in _ADDR_EXTRACTOR(text):
                        val = text[match.start:match.stop].strip()
                        if (len(val) >= 5 and
                            not re.match(r'^стр\.?\s*\d+$', val, re.IGNORECASE) and
                            ADDRESS_ANCHORS.search(val) and
                            not CONSTRUCTION_LOC_STOP.search(val) and
                            not self.is_whitelisted(val)):
                            raw_matches.append((match.start, match.stop, "АДРЕС", val))
                except Exception:
                    pass

        # 13. ФИО (NLP Natasha + Регулярные выражения)
        if self.enabled_types.get("ФИО", True):
            # 1. Natasha NamesExtractor с фильтрацией стоп-слов
            if _NAMES_EXTRACTOR:
                try:
                    for match in _NAMES_EXTRACTOR(text):
                        val = text[match.start:match.stop].strip()
                        if "\n" in val or "\r" in val:
                            continue
                        fact = match.fact
                        has_multiple_parts = (
                            (fact.first and fact.last) or
                            (fact.first and fact.middle) or
                            (fact.last and fact.middle)
                        )
                        is_valid_single = (
                            len(val) >= 4 and
                            val.istitle() and
                            val.lower() not in FIO_STOP_WORDS and
                            val.replace('-', '').isalpha()
                        )
                        if (has_multiple_parts or is_valid_single) and not self.is_whitelisted(val):
                            if val.lower() not in FIO_STOP_WORDS:
                                raw_matches.append((match.start, match.stop, "ФИО", val))
                except Exception:
                    pass

            # 2. ФИО из 3 слов (Иванов Иван Иванович, Петров Петр Петрович)
            for m in FIO_FULL_PATTERN.finditer(text):
                val = m.group().strip()
                w1 = m.group(1).lower()
                w2 = m.group(2).lower()
                if w1 not in FIO_STOP_WORDS and w2 not in FIO_STOP_WORDS and not self.is_whitelisted(val):
                    raw_matches.append((m.start(), m.end(), "ФИО", val))

            # 3. Имя/Фамилия + инициалы (Иванов Иван И., Иванов Иван И.И., Иван И. Иванов)
            for m in FIO_NAME_INITIALS.finditer(text):
                val = m.group().strip()
                w1 = m.group(1).lower()
                w2 = m.group(2).lower()
                if w1 not in FIO_STOP_WORDS and w2 not in FIO_STOP_WORDS and not self.is_whitelisted(val):
                    raw_matches.append((m.start(), m.end(), "ФИО", val))
            for m in FIO_INITIALS_MIDDLE.finditer(text):
                val = m.group().strip()
                w1 = m.group(1).lower()
                w3 = m.group(3).lower()
                if w1 not in FIO_STOP_WORDS and w3 not in FIO_STOP_WORDS and not self.is_whitelisted(val):
                    raw_matches.append((m.start(), m.end(), "ФИО", val))
            for m in FIO_SURNAME_INIT_PATR.finditer(text):
                val = m.group().strip()
                w1 = m.group(1).lower()
                w3 = m.group(3).lower()
                if w1 not in FIO_STOP_WORDS and w3 not in FIO_STOP_WORDS and not self.is_whitelisted(val):
                    raw_matches.append((m.start(), m.end(), "ФИО", val))

            # 4. Фамилия с инициалами (Иванов И.И., Иванов И. И., Иванов И.) и наоборот (И.И. Иванов, И. Иванов)
            for m in FIO_SURNAME_INITIALS.finditer(text):
                val = m.group().strip()
                w1 = m.group(1).lower()
                if w1 not in FIO_STOP_WORDS and not self.is_whitelisted(val):
                    raw_matches.append((m.start(), m.end(), "ФИО", val))
            for m in FIO_INITIALS_SURNAME.finditer(text):
                val = m.group().strip()
                w2 = m.group(2).lower()
                if w2 not in FIO_STOP_WORDS and not self.is_whitelisted(val):
                    raw_matches.append((m.start(), m.end(), "ФИО", val))

            # 5. ФИО из 2 слов (Иванов Иван, Иван Иванов)
            for m in FIO_2_WORDS_PATTERN.finditer(text):
                val = m.group().strip()
                w1 = m.group(1).lower()
                w2 = m.group(2).lower()
                if (w1 not in FIO_STOP_WORDS and
                    w2 not in FIO_STOP_WORDS and
                    not self.is_whitelisted(val)):
                    raw_matches.append((m.start(), m.end(), "ФИО", val))

            # 6. Двойные/составные фамилии через дефис (Мамин-Сибиряк, Салтыков-Щедрин)
            for m in DOUBLE_SURNAME_PATTERN.finditer(text):
                val = m.group().strip()
                p1, p2 = val.split('-', 1)
                if (p1.lower() not in FIO_STOP_WORDS and
                    p2.lower() not in FIO_STOP_WORDS and
                    not self.is_whitelisted(val)):
                    raw_matches.append((m.start(), m.end(), "ФИО", val))

            # 7. Отдельные отчества (Иванович, Сергеевна, Ивановичу и др.)
            for m in PATRONYMIC_PATTERN.finditer(text):
                val = m.group().strip()
                if val.lower() not in FIO_STOP_WORDS and not self.is_whitelisted(val):
                    raw_matches.append((m.start(), m.end(), "ФИО", val))

            # 8. Фамилии в контексте должностей и реквизитов (Заявитель: Иванов, Собственник: Козлов и т.д.)
            for m in CONTEXT_SURNAME_PATTERN.finditer(text):
                val = m.group(1).strip()
                if val.lower() not in FIO_STOP_WORDS and not self.is_whitelisted(val):
                    raw_matches.append((m.start(1), m.end(1), "ФИО", val))

            # 9. Фамилии в подписях (Подпись: / Иванов / или Подпись: Иванов)
            for m in SIGNATURE_SURNAME_PATTERN.finditer(text):
                val = m.group(1).strip()
                if val.lower() not in FIO_STOP_WORDS and not self.is_whitelisted(val):
                    raw_matches.append((m.start(1), m.end(1), "ФИО", val))

            # 10. Морфологические русские фамилии на -ов/-ев/-ин/-ын/-ский/-цкий
            for m in SURNAME_MORPH_PATTERN.finditer(text):
                val = m.group().strip()
                if len(val) >= 4 and val.lower() not in FIO_STOP_WORDS and not self.is_whitelisted(val):
                    raw_matches.append((m.start(), m.end(), "ФИО", val))

            # 11. Короткие фамилии (Ким, Пак, Ли, Цой, Ван и др.)
            for m in SHORT_SURNAMES_PATTERN.finditer(text):
                val = m.group().strip()
                if not self.is_whitelisted(val):
                    raw_matches.append((m.start(), m.end(), "ФИО", val))

        # 14. Пользовательские правила
        for pattern, tag in self.custom_patterns:
            for m in pattern.finditer(text):
                val = m.group()
                if not self.is_whitelisted(val):
                    raw_matches.append((m.start(), m.end(), tag, val))

        # Фильтрация и дедупликация совпадений
        PRIORITY = {
            "КАРТА": 100,
            "СНИЛС": 95,
            "ИНН": 90,
            "ОГРН": 90,
            "БИК": 85,
            "РСЧЕТ": 85,
            "КПП": 80,
            "EMAIL": 80,
            "ПАСПОРТ": 75,
            "ТЕЛ": 70,
            "АДРЕС": 65,
            "ОРГ": 60,
            "ФИО": 50,
        }

        # Сортировка: сначала левее, при равенстве — более длинные и приоритетные
        sorted_candidates = sorted(
            raw_matches,
            key=lambda x: (x[0], -len(x[3]), -PRIORITY.get(x[2], 50))
        )

        filtered: List[Tuple[int, int, str, str]] = []
        last_end = -1
        for start, end, tag, val in sorted_candidates:
            if start >= last_end:
                filtered.append((start, end, tag, val))
                last_end = end

        trimmed_filtered: List[Tuple[int, int, str, str]] = []
        for s, e, tag, val in filtered:
            while s < e and text[s] in ' \t\r\n\x00\x07\x0b\x0c':
                s += 1
            while e > s and text[e - 1] in ' \t\r\n\x00\x07\x0b\x0c':
                e -= 1
            clean_val = text[s:e]
            if clean_val and len(clean_val) >= 2:
                trimmed_filtered.append((s, e, tag, clean_val))

        return trimmed_filtered
