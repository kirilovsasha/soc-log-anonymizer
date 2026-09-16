"""
Точка входа пакета.

    python -m soc_log_anonymizer            -> запуск GUI
    python -m soc_log_anonymizer gui         -> запуск GUI
    python -m soc_log_anonymizer anonymize ... -> делегирование в CLI
    python -m soc_log_anonymizer deanonymize ...
    python -m soc_log_anonymizer batch ...

Также используется как entry point при упаковке в zipapp:
    python -m zipapp soc_log_anonymizer -o anonymizer.pyz
    ./anonymizer.pyz              # GUI
    ./anonymizer.pyz anonymize -i raw.log -o clean.log --salt-file salt.txt
"""

import sys


def main() -> int:
    if len(sys.argv) <= 1 or sys.argv[1] == "gui":
        from .gui import main as gui_main
        gui_main()
        return 0

    from .cli import main as cli_main
    return cli_main(sys.argv[1:])


if __name__ == "__main__":
    sys.exit(main())
