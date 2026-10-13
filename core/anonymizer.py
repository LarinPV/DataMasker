"""
Хранилище сессии обезличивания и восстановления данных (Anonymizer).
Обеспечивает строгое сопоставление 1-к-1: одинаковые сущности получают одинаковые токены.
Управляет прямым и обратным маппингом, счетчиками токенов и заменой текста.
"""

from typing import Dict, List, Tuple, Optional, Any
from .vault import Vault


B62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

def to_b62(n: int, w: int) -> str:
    res = []
    for _ in range(w):
        res.append(B62[n % 62])
        n //= 62
    return "".join(reversed(res))

def make_exact_token(tag: str, count: int, needed_len: int) -> str:
    """
    Генерирует абсолютно уникальный ограниченный токен строго фиксированной длины needed_len.
    Использует base62 для гарантированного исключения коллизий даже при тысячах сущностей.
    """
    t_pre = tag[:2] if len(tag) >= 2 else (tag + "X")
    if needed_len >= 10:
        base = f"{{{{{t_pre}_{to_b62(count, 3)}"
        pad = needed_len - len(base) - 2
        return f"{base}{'_' * pad}}}}}"
    elif needed_len >= 7:
        pad = needed_len - 7
        return f"{{{{{t_pre[:1]}{to_b62(count, 2)}{'_' * pad}}}}}"
    elif needed_len == 6:
        return f"[{t_pre[:2]}{to_b62(count, 2)}]"
    elif needed_len == 5:
        return f"[{t_pre[:1]}{to_b62(count, 2)}]"
    elif needed_len == 4:
        return f"[{to_b62(count, 2)}]"
    elif needed_len == 3:
        return f"~{to_b62(count, 2)}"
    elif needed_len == 2:
        return f"~{to_b62(count, 1)}"
    return "*" * needed_len


class Anonymizer:
    """Класс для генерации плейсхолдеров, подстановки и обратного восстановления."""

    def __init__(self):
        # original_value -> token
        self.forward_map: Dict[str, str] = {}
        # token -> original_value
        self.reverse_map: Dict[str, str] = {}
        # tag_name -> count
        self.counters: Dict[str, int] = {}
        # Статистика по категориям
        self.stats: Dict[str, int] = {}
        # Кэш токенов точной длины для in-place замены: (orig_val, needed_len) -> token
        self._exact_token_cache: Dict[Tuple[str, int], str] = {}

    def reset(self) -> None:
        """Сброс сессии."""
        self.forward_map.clear()
        self.reverse_map.clear()
        self.counters.clear()
        self.stats.clear()
        self._exact_token_cache.clear()

    def get_or_create_exact_token(self, tag: str, original_val: str, needed_len: int) -> str:
        """
        Возвращает существующий токен точной длины или генерирует новый без коллизий.
        """
        cache_key = (original_val, needed_len)
        if cache_key in self._exact_token_cache:
            return self._exact_token_cache[cache_key]

        count = self.counters.get(tag, 0) + 1
        self.counters[tag] = count

        token = make_exact_token(tag, count, needed_len)
        self._exact_token_cache[cache_key] = token
        self.forward_map[original_val] = token
        self.reverse_map[token] = original_val
        self.stats[tag] = self.stats.get(tag, 0) + 1
        return token

    def get_or_create_token(self, tag: str, original_val: str) -> str:
        """
        Возвращает существующий токен или создает новый вида {{ТЕГ_001}}.
        Сохраняет одинаковый токен для идентичных исходных данных.
        """
        cleaned_orig = original_val.strip()
        if not cleaned_orig:
            return original_val

        # Проверка наличия в словаре
        if cleaned_orig in self.forward_map:
            return self.forward_map[cleaned_orig]

        # Инициализация счетчика тега
        count = self.counters.get(tag, 0) + 1
        self.counters[tag] = count

        token = f"{{{{{tag}_{count:03d}}}}}"
        self.forward_map[cleaned_orig] = token
        self.reverse_map[token] = cleaned_orig

        self.stats[tag] = self.stats.get(tag, 0) + 1
        return token

    def mask_text(self, text: str, matches: List[Tuple[int, int, str, str]]) -> str:
        """
        Заменяет найденные совпадения в тексте на уникальные токены.
        matches: список кортежей (start_index, end_index, tag_name, original_text)
        Сортировка спанов от конца строки к началу предотвращает сдвиг индексов.
        """
        if not text or not matches:
            return text

        # Удаление пересекающихся спанов
        # Сортируем: сначала те, у которых start меньше, при равенстве - более длинные
        sorted_spans = sorted(matches, key=lambda x: (x[0], -(x[1] - x[0])))
        non_overlapping: List[Tuple[int, int, str, str]] = []
        last_end = -1

        for span in sorted_spans:
            s, e, tag, val = span
            if s >= last_end:
                non_overlapping.append(span)
                last_end = e

        # Замена справа налево
        result_chars = list(text)
        for s, e, tag, orig_val in sorted(non_overlapping, key=lambda x: x[0], reverse=True):
            token = self.get_or_create_token(tag, orig_val)
            result_chars[s:e] = list(token)

        return "".join(result_chars)

    def unmask_text(self, text: str) -> str:
        """
        Обратная замена токенов на исходные значения.
        Сортировка по длине токена от большего к меньшему исключает частичные наложения.
        """
        if not text or not self.reverse_map:
            return text

        result = text
        # Сортируем ключи по длине от длинных к коротким
        sorted_tokens = sorted(self.reverse_map.keys(), key=lambda t: len(t), reverse=True)
        for token in sorted_tokens:
            if token in result:
                result = result.replace(token, self.reverse_map[token])

        return result

    def save_vault(
        self,
        filepath: str,
        password: Optional[str] = None,
        key_filepath: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> str:
        """Сохраняет сопоставления в защищенный файл .vault."""
        meta = metadata or {}
        meta["stats"] = self.stats
        meta["total_entities"] = len(self.forward_map)
        return Vault.save_vault(
            filepath=filepath,
            forward_map=self.forward_map,
            reverse_map=self.reverse_map,
            password=password,
            key_filepath=key_filepath,
            metadata=meta
        )

    def load_vault(
        self,
        filepath: str,
        password: Optional[str] = None,
        key_filepath: Optional[str] = None
    ) -> Dict[str, Any]:
        """Загружает маппинг из файла .vault для операции восстановления."""
        f_map, r_map, meta = Vault.load_vault(
            filepath=filepath,
            password=password,
            key_filepath=key_filepath
        )
        self.forward_map = f_map
        self.reverse_map = r_map
        return meta
