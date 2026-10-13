"""
Модуль математической и алгоритмической валидации реквизитов РФ:
- ИНН (10 и 12 цифр) по алгоритму ФНС РФ
- ОГРН (13 цифр) и ОГРНИП (15 цифр)
- СНИЛС (11 цифр) по правилам ПФР
- КПП (9 знаков)
- БИК (9 знаков)
- Расчетные и корреспондентские счета (20 знаков, валидация ключа по положению ЦБ РФ)
- Банковские карты (алгоритм Луна)
"""

def validate_inn(inn: str) -> bool:
    """Валидация ИНН юридического (10 цифр) или физического лица / ИП (12 цифр)."""
    if not isinstance(inn, str) or not inn.isdigit():
        return False
    
    if len(inn) == 10:
        coeffs = [2, 4, 10, 3, 5, 9, 4, 6, 8, 0]
        check_sum = sum(int(digit) * coeff for digit, coeff in zip(inn, coeffs)) % 11 % 10
        return check_sum == int(inn[9])
    
    elif len(inn) == 12:
        coeffs_11 = [7, 2, 4, 10, 3, 5, 9, 4, 6, 8, 0, 0]
        coeffs_12 = [3, 7, 2, 4, 10, 3, 5, 9, 4, 6, 8, 0]
        check_11 = sum(int(digit) * coeff for digit, coeff in zip(inn, coeffs_11)) % 11 % 10
        check_12 = sum(int(digit) * coeff for digit, coeff in zip(inn, coeffs_12)) % 11 % 10
        return check_11 == int(inn[10]) and check_12 == int(inn[11])
    
    return False


def validate_ogrn(ogrn: str) -> bool:
    """Валидация ОГРН (13 цифр) и ОГРНИП (15 цифр)."""
    if not isinstance(ogrn, str) or not ogrn.isdigit():
        return False
    
    if len(ogrn) == 13:
        num = int(ogrn[:12])
        check_digit = (num % 11) % 10
        return check_digit == int(ogrn[12])
    
    elif len(ogrn) == 15:
        num = int(ogrn[:14])
        check_digit = (num % 13) % 10
        return check_digit == int(ogrn[14])
    
    return False


def validate_snils(snils_str: str) -> bool:
    """Валидация страхового номера СНИЛС (11 цифр)."""
    digits = [c for c in snils_str if c.isdigit()]
    if len(digits) != 11:
        return False
    
    snils_digits = [int(c) for c in digits]
    # Номера меньше 001-001-998 проверке не подлежат
    if int("".join(digits[:9])) <= 1001998:
        return True
    
    total = sum(snils_digits[i] * (9 - i) for i in range(9))
    control_num = int("".join(digits[9:]))
    
    if total < 100:
        check = total
    elif total in (100, 101):
        check = 0
    else:
        rem = total % 101
        if rem < 100:
            check = rem
        elif rem in (100, 101):
            check = 0
        else:
            check = 0
            
    return check == control_num


def validate_kpp(kpp: str) -> bool:
    """Валидация КПП (9 символов: первые 4 цифры - код ИФНС, затем 2 символа причины, 3 цифры номера)."""
    if not isinstance(kpp, str) or len(kpp) != 9:
        return False
    # Первые 4 - цифры ИФНС
    if not kpp[:4].isdigit() or kpp[:4] == "0000":
        return False
    # Последние 3 - цифры
    if not kpp[6:].isdigit() or kpp[6:] == "000":
        return False
    # 5-6 символы: цифры или заглавные латинские буквы
    mid = kpp[4:6]
    if not (mid.isdigit() or (mid.isalnum() and mid.isupper())):
        return False
    return True


def validate_bik(bik: str) -> bool:
    """Валидация БИК (9 цифр, начинается с 04 для РФ)."""
    return isinstance(bik, str) and len(bik) == 9 and bik.isdigit() and bik.startswith("04")


def validate_bank_account(account: str, bik: str = "") -> bool:
    """
    Валидация расчетного или корреспондентского счета (20 цифр).
    Если передан БИК (9 цифр), выполняется строгая проверка контрольного ключа ЦБ РФ.
    """
    if not isinstance(account, str) or len(account) != 20 or not account.isdigit():
        return False
    
    # Известные префиксы банковских счетов РФ
    valid_prefixes = (
        "40701", "40702", "40703", "40802", "40817", "40820",
        "30101", "30102", "40502", "40602", "42301", "42302",
        "42303", "42304", "42305", "42306", "42307", "40807",
        "40911", "30232", "30301", "47422", "47423", "40101",
        "40102", "40201", "40302", "40401"
    )
    
    if bik and len(bik) == 9 and bik.isdigit():
        # Расчет весового коэффициента по правилам Банка России
        if account.startswith(("30101", "30102")):
            bik_part = "0" + bik[4:6]
        else:
            bik_part = bik[6:9]
            
        full_num = bik_part + account
        weights = [7, 1, 3] * 7 + [7, 1]
        weighted_sum = sum(int(d) * w for d, w in zip(full_num, weights))
        return weighted_sum % 10 == 0
        
    # Если БИК не указан, проверяем по префиксам балансовых счетов
    return account.startswith(valid_prefixes)


def validate_luhn(card_number: str) -> bool:
    """Валидация номера банковской карты (13-19 цифр) по алгоритму Луна."""
    clean = "".join(c for c in card_number if c.isdigit())
    if not (13 <= len(clean) <= 19):
        return False
    
    digits = [int(c) for c in clean]
    checksum = 0
    reverse_digits = digits[::-1]
    
    for i, d in enumerate(reverse_digits):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
        
    return checksum % 10 == 0
