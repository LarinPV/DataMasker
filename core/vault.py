"""
Модуль безопасного хранения и шифрования таблицы сопоставлений (Vault).
Использует AES-128-CBC + HMAC-SHA256 через Fernet с выводом ключа через PBKDF2HMAC.
Позволяет защитить обратимый ключ псевдонимизации мастер-паролем или файл-ключом.
"""

import os
import json
import base64
from typing import Dict, Any, Tuple, Optional
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


class VaultError(Exception):
    """Базовое исключение для ошибок хранилища ключей."""
    pass


class InvalidPasswordError(VaultError):
    """Исключение при неверном пароле или поврежденном ключе."""
    pass


class Vault:
    """Управление зашифрованным файлом сопоставлений токенов."""

    MAGIC_HEADER = b"DMVAULT1"  # Заголовок формата (DataMasker Vault v1)
    SALT_SIZE = 16

    @classmethod
    def derive_key_from_password(cls, password: str, salt: bytes) -> bytes:
        """Генерация ключа Fernet из мастер-пароля с помощью PBKDF2."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100_000,
            backend=default_backend()
        )
        derived = kdf.derive(password.encode("utf-8"))
        return base64.urlsafe_b64encode(derived)

    @classmethod
    def save_vault(
        cls,
        filepath: str,
        forward_map: Dict[str, str],
        reverse_map: Dict[str, str],
        password: Optional[str] = None,
        key_filepath: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Сохраняет файл маппинга в зашифрованном виде.
        Если указан password, шифрует паролем.
        Если пароль не указан, генерирует случайный ключ Fernet и сохраняет его в key_filepath.
        Возвращает путь к сохраненному ключу (если ключ сохранялся отдельно).
        """
        payload = {
            "forward_map": forward_map,
            "reverse_map": reverse_map,
            "metadata": metadata or {}
        }
        json_bytes = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")

        if password:
            salt = os.urandom(cls.SALT_SIZE)
            key = cls.derive_key_from_password(password, salt)
            fernet = Fernet(key)
            encrypted_data = fernet.encrypt(json_bytes)
            # Формат: MAGIC_HEADER (8 байт) + SALT (16 байт) + ENCRYPTED_DATA
            output_bytes = cls.MAGIC_HEADER + salt + encrypted_data
            saved_key_path = ""
        else:
            # Генерация ключа Fernet
            key = Fernet.generate_key()
            fernet = Fernet(key)
            encrypted_data = fernet.encrypt(json_bytes)
            # Без соли: заголовок MAGIC_HEADER + 16 нулевых байт + данные
            salt = b"\x00" * cls.SALT_SIZE
            output_bytes = cls.MAGIC_HEADER + salt + encrypted_data
            
            # Сохранение ключа в отдельный файл
            if not key_filepath:
                key_filepath = filepath + ".key"
            with open(key_filepath, "wb") as kf:
                kf.write(key)
            saved_key_path = key_filepath

        with open(filepath, "wb") as f:
            f.write(output_bytes)

        return saved_key_path

    @classmethod
    def load_vault(
        cls,
        filepath: str,
        password: Optional[str] = None,
        key_filepath: Optional[str] = None
    ) -> Tuple[Dict[str, str], Dict[str, str], Dict[str, Any]]:
        """
        Загружает и расшифровывает файл сопоставлений.
        Возвращает кортеж: (forward_map, reverse_map, metadata).
        """
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Файл ключей не найден: {filepath}")

        with open(filepath, "rb") as f:
            data = f.read()

        if len(data) < len(cls.MAGIC_HEADER) + cls.SALT_SIZE:
            raise VaultError("Некорректный или поврежденный файл хранилища ключей.")

        header = data[:len(cls.MAGIC_HEADER)]
        if header != cls.MAGIC_HEADER:
            # Попытка прочитать как открытый JSON (на случай обратной совместимости)
            try:
                raw_json = json.loads(data.decode("utf-8"))
                return (
                    raw_json.get("forward_map", {}),
                    raw_json.get("reverse_map", {}),
                    raw_json.get("metadata", {})
                )
            except Exception:
                raise VaultError("Неверный формат заголовка файла .vault")

        salt = data[len(cls.MAGIC_HEADER):len(cls.MAGIC_HEADER) + cls.SALT_SIZE]
        encrypted_data = data[len(cls.MAGIC_HEADER) + cls.SALT_SIZE:]

        # Определение ключа шифрования
        if salt == b"\x00" * cls.SALT_SIZE:
            # Шифрование производилось файловым ключом
            key_to_use = None
            if key_filepath and os.path.exists(key_filepath):
                with open(key_filepath, "rb") as kf:
                    key_to_use = kf.read().strip()
            elif os.path.exists(filepath + ".key"):
                with open(filepath + ".key", "rb") as kf:
                    key_to_use = kf.read().strip()
            elif password:
                # На случай, если пользователь все же ввел строку
                key_to_use = password.encode("utf-8").strip()
            
            if not key_to_use:
                raise InvalidPasswordError("Требуется файл-ключ (.key) для расшифровки данного хранилища.")
        else:
            # Шифрование производилось паролем
            if not password:
                raise InvalidPasswordError("Для открытия этого хранилища требуется ввести мастер-пароль.")
            key_to_use = cls.derive_key_from_password(password, salt)

        try:
            fernet = Fernet(key_to_use)
            decrypted_bytes = fernet.decrypt(encrypted_data)
            payload = json.loads(decrypted_bytes.decode("utf-8"))
            return (
                payload.get("forward_map", {}),
                payload.get("reverse_map", {}),
                payload.get("metadata", {})
            )
        except InvalidToken:
            raise InvalidPasswordError("Неверный пароль или поврежденный файл ключей!")
        except Exception as e:
            raise VaultError(f"Ошибка при чтении данных хранилища: {e}")
