"""
SOC Log Anonymizer — анонимизация логов для SOC-аналитиков перед
отправкой во внешнюю LLM. Только стандартная библиотека Python.

Публичный API:
    from soc_log_anonymizer import SOCLogAnonymizer, AnonymizerConfig
"""

from .anonymizer import SOCLogAnonymizer
from .config import AnonymizerConfig
from .io_utils import read_file_auto_encoding

__version__ = "2.1.0"

__all__ = [
    "SOCLogAnonymizer",
    "AnonymizerConfig",
    "read_file_auto_encoding",
    "__version__",
]
