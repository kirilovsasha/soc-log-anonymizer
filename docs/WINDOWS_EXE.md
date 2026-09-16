# Windows EXE (PyInstaller) — один автономный файл

Раздача **SOC Log Anonymizer** аналитикам как **одного `.exe`** без
установленного Python.

## Основная сборка: `--onefile`

| Артефакт | Spec | Назначение |
|---|---|---|
| `dist/soc-log-anonymizer-gui.exe` | `packaging/soc_log_anonymizer_gui_onefile.spec` | GUI, без консольного окна |
| `dist/soc-log-anonymizer-cli.exe` | `packaging/soc_log_anonymizer_cli_onefile.spec` | CLI с консолью |

### Сборка

```bat
packaging\build_windows.bat
```

Или вручную:

```bat
pip install pyinstaller
pyinstaller packaging\soc_log_anonymizer_gui_onefile.spec
pyinstaller packaging\soc_log_anonymizer_cli_onefile.spec
```

В свойствах файла Windows: **версия**, описание и **иконка**.

Рядом с exe можно положить `soc_log_anonymizer.json` (скрипт копирует
образец в `dist\`). При первом запуске конфиг также может быть извлечён
изнутри exe во временный `_MEIPASS` и скопирован рядом с бинарником.

Опционально (папка с DLL, быстрее старт):  
`packaging/soc_log_anonymizer_gui.spec` / `*_cli.spec` (`--onedir`).

## SmartScreen / Defender

Onefile-бинарники без подписи часто помечаются SmartScreen — это нормально
для PyInstaller.

1. **Authenticode** — подпишите exe корпоративным сертификатом
   (`signtool sign /fd SHA256 ...`).
2. **UPX отключён** в spec намеренно (меньше ложных срабатываний AV).
3. При внутреннем распространении добавьте hash/версию в каталог ПО SOC.

Первый запуск onefile чуть медленнее: архив распаковывается во временную
папку. Конфиг/соль/mapping храните **рядом с exe** или в AppData — не во
временном `_MEIPASS`.

## Куда класть конфиг и соль

- Рядом с exe: `soc_log_anonymizer.json` (подхватывается автоматически).
- **Соль** и **mapping** — только в профиле пользователя или на
  зашифрованном носителе. Не синхронизируйте их в OneDrive/общий диск
  без шифрования контейнера.
- На Windows при сохранении salt/mapping/черновика выставляется ACL
  текущего пользователя (`icacls`); на POSIX — `chmod 600`.

## Portable vs installed

| Режим | Как включить | Где данные |
|---|---|---|
| Installed (по умолчанию) | нет маркера | `%APPDATA%\SOC Log Anonymizer\` (state, crash log), `%LOCALAPPDATA%\...\drafts\` |
| Portable | файл `portable.flag` рядом с exe, или `SOC_ANON_PORTABLE=1`, или меню «Настройки» | рядом с exe / `data\` |

Меню GUI: **Файл → Открыть папку приложения / данных / журнал ошибок**.

## Журнал ошибок (windowed GUI)

При `console=False` traceback пишется в:

`%APPDATA%\SOC Log Anonymizer\gui_error.log`

(в portable — рядом с exe). MessageBox показывает путь к файлу.

## Большие логи в GUI

При файлах ≳ 50 МБ GUI предлагает режим **превью + sidecar** (`*.anon.log`).
Для массовой обработки используйте CLI-exe:

```bat
soc-log-anonymizer-cli.exe anonymize -i huge.log -o clean.log --salt-file salt.txt --stream --stats
```

## Обновление версии

1. Замените `soc-log-anonymizer-gui.exe` новой сборкой.
2. Сохраните локальный `soc_log_anonymizer.json` / `portable.flag` / соль.
3. Mapping от старой версии обычно совместим (`schema_version`).

## CI

GitHub Actions job `pyinstaller-windows` собирает **onefile** GUI+CLI и
публикует zip-артефакты.
