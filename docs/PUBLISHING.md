# Публикация: GitHub Releases, подпись кода, PyPI

## GitHub Releases

По тегу версии (например `v2.5.0`) workflow `.github/workflows/release.yml`:

1. Запускает набор тестов
2. Собирает Windows GUI/CLI onefile-артефакты
3. Загружает их в GitHub Release

Создание релиза:

```bash
git tag v2.5.0
git push origin v2.5.0
```

## Подпись кода (Windows)

CI загружает **неподписанные** бинарники. Для боевой раздачи в SOC
подписывайте локально или на защищённом раннере корпоративным
сертификатом:

```bat
signtool sign /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 ^
  /a dist\soc-log-anonymizer-gui.exe
signtool sign /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 ^
  /a dist\soc-log-anonymizer-cli.exe
```

См. также [WINDOWS_EXE.md](WINDOWS_EXE.md) (заметки про SmartScreen).

## PyPI

Workflow `.github/workflows/publish-pypi.yml` публикует пакет по тегам,
если в секретах репозитория настроен `PYPI_API_TOKEN` (или Trusted
Publishing).

Вручную:

```bash
pip install -e ".[dev]"
python -m build
python -m twine upload dist/*
```

Имя пакета: `soc-log-anonymizer` (runtime только на стандартной
библиотеке; extras `dev` / `publish` опциональны).
