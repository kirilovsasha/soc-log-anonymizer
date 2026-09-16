"""
SOC Log Anonymizer — анонимизация логов для SOC-аналитиков перед
отправкой во внешнюю LLM. Только стандартная библиотека Python.

Публичный API:
    from soc_log_anonymizer import SOCLogAnonymizer, AnonymizerConfig, AnonymizeResult
"""

from .anonymizer import SOCLogAnonymizer
from .config import AnonymizerConfig
from .io_utils import read_file_auto_encoding
from .result import AnonymizeResult

__version__ = "2.4.0"

__all__ = [
    "AnonymizeResult",
    "AnonymizerConfig",
    "SOCLogAnonymizer",
    "__version__",
    "read_file_auto_encoding",
]
