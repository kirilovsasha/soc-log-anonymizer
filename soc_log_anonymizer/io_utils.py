"""Утилиты файлового ввода-вывода (только стандартная библиотека):
автоопределение кодировки, построчное чтение больших файлов через mmap,
прозрачная поддержка gzip-архивов, проверка прав доступа к чувствительным
файлам."""

import gzip
import logging
import mmap
import os
import stat
from typing import BinaryIO, Iterator, Optional

logger = logging.getLogger("soc_log_anonymizer")

_ENCODING_CANDIDATES = ['utf-8', 'utf-8-sig', 'windows-1251', 'cp1252', 'latin-1']
_GZIP_MAGIC = b'\x1f\x8b'


def is_gzip_file(file_path: str) -> bool:
    """Определяет gzip-архив по магическим байтам заголовка (а не только
    по расширению `.gz`) — работает и для файлов без характерного
    расширения. SOC-логи часто архивируются (`app.log.gz`), эта функция
    позволяет анонимизатору принимать такие файлы без ручной распаковки."""
    try:
        with open(file_path, 'rb') as f:
            return f.read(2) == _GZIP_MAGIC
    except OSError:
        return False


def _open_binary(file_path: str) -> BinaryIO:
    """Открывает файл в бинарном режиме, прозрачно распаковывая gzip."""
    if is_gzip_file(file_path):
        return gzip.open(file_path, 'rb')
    return open(file_path, 'rb')


def _text_quality_score(text: str) -> float:
    """Грубая эвристика качества декодирования: доля "нормальных" символов.
    Нужна, чтобы выбрать лучший вариант из нескольких кодировок, для
    которых декодирование не вызвало исключения — что типично для
    однобайтовых кодировок вроде cp1252/latin-1, которые "успешно"
    декодируют почти любые байты, даже если результат — моджибейк."""
    if not text:
        return 0.0
    sample = text[:20000]
    total = len(sample)
    if total == 0:
        return 0.0
    bad = sum(1 for ch in sample if ch == '\ufffd')
    control = sum(1 for ch in sample if ord(ch) < 32 and ch not in '\n\r\t')
    return 1.0 - (bad + control) / total


def _decode_bytes_auto(raw: bytes) -> str:
    """Декодирует байтовую строку, перебирая кандидатов кодировок и
    выбирая лучший результат по _text_quality_score. windows-1251
    проверяется раньше cp1252/latin-1, т.к. эти однобайтовые кодировки
    почти всегда "успешно" декодируют произвольные байты, но для
    кириллицы дадут моджибейк вместо явной ошибки."""
    encodings = ['utf-8', 'utf-8-sig', 'utf-16', 'utf-16-le', 'utf-16-be'] + _ENCODING_CANDIDATES[2:]
    candidates = []
    for enc in encodings:
        try:
            text = raw.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
        if enc in ('utf-8', 'utf-8-sig'):
            return text
        candidates.append((_text_quality_score(text), enc, text))

    if candidates:
        candidates.sort(key=lambda x: x[0], reverse=True)
        return candidates[0][2]

    return raw.decode('utf-8', errors='ignore')


def _detect_encoding_from_bytes(sample: bytes) -> str:
    """Определяет кодировку по бинарному сэмплу (без чтения всего файла).
    Используется для потокового чтения больших файлов, где полная
    загрузка для детекции кодировки свела бы на нет экономию памяти.
    Не включает utf-16: на произвольно обрезанном сэмплe без BOM в начале
    файла двухбайтовая кодировка ненадёжно определяется по фрагменту."""
    best_enc, best_score = "utf-8", -1.0
    for enc in _ENCODING_CANDIDATES:
        try:
            text = sample.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
        if enc in ("utf-8", "utf-8-sig"):
            return enc
        score = _text_quality_score(text)
        if score > best_score:
            best_enc, best_score = enc, score
    return best_enc


def read_file_auto_encoding(file_path: str) -> str:
    """Чтение файла ЦЕЛИКОМ с автоопределением кодировки. Прозрачно
    распаковывает gzip (по магическим байтам, не по расширению). Для
    больших файлов предпочтительнее detect_file_encoding() +
    iter_lines_stream()."""
    with _open_binary(file_path) as f:
        raw = f.read()
    return _decode_bytes_auto(raw)


def detect_file_encoding(file_path: str, sample_size: int = 65536) -> str:
    """Определяет кодировку файла по первым `sample_size` байт
    (распакованного содержимого, если файл — gzip), не читая файл
    целиком — для потоковой обработки больших логов."""
    with _open_binary(file_path) as f:
        sample = f.read(sample_size)
    return _detect_encoding_from_bytes(sample)


def iter_lines_mmap(file_path: str, encoding: Optional[str] = None) -> Iterator[str]:
    """Построчный итератор по файлу через mmap — файл не загружается в
    память целиком (ОС подкачивает страницы по требованию), что даёт
    преимущество над обычным построчным чтением на очень больших файлах
    (десятки ГБ) на файловых системах с быстрым произвольным доступом.

    Не подходит для gzip-архивов (mmap работает с исходными байтами на
    диске, а для .gz это сжатые данные, а не текст) — для них
    iter_lines_stream() автоматически использует gzip-поток вместо mmap.

    Ограничение: кодировка определяется по первому сэмплу файла (не
    учитывает utf-16 без BOM в начале — см. _detect_encoding_from_bytes),
    и предполагается, что вся оставшаяся часть файла в той же кодировке.
    Пустой файл возвращает пустой итератор."""
    if encoding is None:
        encoding = detect_file_encoding(file_path)

    with open(file_path, 'rb') as f:
        size = os.fstat(f.fileno()).st_size
        if size == 0:
            return
        with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
            while True:
                line = mm.readline()
                if not line:
                    break
                yield line.decode(encoding, errors='replace')


def iter_lines_stream(file_path: str, encoding: Optional[str] = None,
                       use_mmap: bool = False) -> Iterator[str]:
    """Единая точка входа для построчного потокового чтения файла —
    используется CLI-командой `anonymize --stream`. Автоматически
    выбирает правильную стратегию:

    - gzip-архив -> построчное чтение через `gzip.open(..., 'rt')`
      (mmap здесь неприменим — на диске лежат сжатые байты, не текст);
    - обычный файл + `use_mmap=True` -> `iter_lines_mmap()`;
    - обычный файл иначе -> обычное ленивое построчное чтение через
      `open()` с заранее определённой кодировкой (константный объём
      памяти, без сторонних средств)."""
    if is_gzip_file(file_path):
        if encoding is None:
            encoding = detect_file_encoding(file_path)
        with gzip.open(file_path, 'rt', encoding=encoding, errors='replace') as f:
            yield from f
        return

    if use_mmap:
        yield from iter_lines_mmap(file_path, encoding=encoding)
        return

    if encoding is None:
        encoding = detect_file_encoding(file_path)
    with open(file_path, 'r', encoding=encoding, errors='replace') as f:
        yield from f


def format_size_mb(size_bytes: int) -> float:
    return size_bytes / (1024 * 1024)


def check_world_readable(file_path: str) -> Optional[str]:
    """Проверяет права доступа к чувствительному файлу (соль, mapping) на
    POSIX-системах и возвращает текст предупреждения, если файл доступен
    на чтение группе/остальным пользователям. На Windows права доступа
    устроены иначе (ACL, не биты rwx), проверка пропускается — возвращает
    None. Не блокирует чтение, только информирует (гигиена, а не гейт)."""
    if os.name != "posix":
        return None
    try:
        mode = os.stat(file_path).st_mode
    except OSError:
        return None
    if mode & (stat.S_IRGRP | stat.S_IROTH):
        return (f"Файл {file_path} доступен на чтение другим пользователям системы "
                f"(рекомендуется chmod 600 {file_path}) — он может содержать соль "
                f"или таблицу деанонимизации.")
    return None
