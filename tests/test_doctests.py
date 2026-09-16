"""Прогоняет doctest-примеры из docstring'ов как часть unittest discovery.

    python -m unittest discover -s tests -v

подхватит и обычные TestCase, и doctest-примеры из этого файла.
"""

import doctest
import unittest

import soc_log_anonymizer.anonymizer as anonymizer_module


def load_tests(loader, tests, ignore):
    """Стандартный protocol unittest для расширения набора тестов —
    вызывается автоматически discovery-механизмом unittest."""
    tests.addTests(doctest.DocTestSuite(anonymizer_module))
    return tests


if __name__ == "__main__":
    unittest.main()
