# emudhra_scan.py

Поиск и исправление хранилищ доверия, затронутых компрометацией промежуточных CA eMudhra (октябрь 2026, [Mozilla bug 2083449](https://bugzilla.mozilla.org/show_bug.cgi?id=2083449)).

Один файл, только стандартная библиотека Python. Linux. Проверено на Python 3.12, рассчитано на 3.6+.

## Контекст

- У 8 промежуточных сертификатов eMudhra (6 TLS, 2 для подписи кода) приватные ключи P-384 оказались меньше 256 и публично восстановлены.
- Те же ключи кросс-подписаны Sectigo от корня AAA Certificate Services, который ещё доверен у Microsoft и Apple.
- Mozilla и Chrome экстренно сняли доверие с корня **emSign ECC Root CA - G3**.
- Большинство небраузерных клиентов (OpenSSL, Go, Java по умолчанию, Node, Python) отзыв не проверяют. Поэтому защищает только удаление корня из хранилищ, а не отзыв.

## Быстрый старт

```sh
sudo python3 emudhra_scan.py                              # скан всего хоста
sudo python3 emudhra_scan.py --fix --dry-run              # план исправлений, ничего не меняет
sudo python3 emudhra_scan.py --fix                        # бэкап, затем вопрос по каждому действию
sudo python3 emudhra_scan.py --fix --force                # бэкап и все автоматические исправления
sudo python3 emudhra_scan.py --manual-list manual.tsv     # список того, что придётся делать руками
python3 emudhra_scan.py --root /tmp/rootfs                # распакованный образ контейнера
```

Полный скан хоста занимает около минуты. `--no-fs` (только конфиги и процессы) — несколько секунд.

## Что ищется

| Источник | Что именно |
|---|---|
| Файловая система | `*.pem`, `*.crt`, `*.cer`, `*.der`, `*.jks`, `*.p12`, `cacerts`, `ca-bundle*`, `cert9.db` и т. п.; бинарники `node`/`nodejs` |
| Java | `cacerts` и keystore через `keytool` хоста, с alias; `-Djavax.net.ssl.trustStore` в юнитах и процессах; `cacerts` по умолчанию у запущенных JVM |
| Node.js | корни, вшитые в бинарник (читаются без запуска) |
| Python | `certifi/cacert.pem` во всех venv и `pip/_vendor` |
| PHP | `openssl.cafile`, `openssl.capath`, `curl.cainfo` |
| Конфиги | nginx/angie/openresty, Apache, HAProxy, Postfix, Squid, Envoy, Kafka, Elasticsearch/OpenSearch, systemd, `/etc/environment`, `/etc/default` |
| Переменные | `SSL_CERT_FILE`, `SSL_CERT_DIR`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`, `NODE_EXTRA_CA_CERTS`, `GIT_SSL_CAINFO`, `AWS_CA_BUNDLE`, `PIP_CERT` |
| Процессы | environ и cmdline; файлы внутри контейнеров читаются через `/proc/PID/root` |
| NSS | `cert9.db` через sqlite, с nickname |

Каждый сертификат разбирается (отпечаток, серийный номер, CN субъекта и издателя). Если формат не разбирается, используется поиск имён и серийных номеров в сырых байтах. Бинарники из сканируемого дерева никогда не исполняются.

## Классы находок

Требуют действий (код возврата 1):

| Класс | Значение |
|---|---|
| `IOC_INTERMEDIATE` | скомпрометированный промежуточный, совпадение SHA-256 (16 отпечатков: 8 eMudhra + 8 кросс-подписей Sectigo) |
| `IOC_SERIAL` | серийный номер из IOC без совпадения отпечатка или в неразобранном хранилище |
| `ROOT_DISTRUST` | `emSign ECC Root CA - G3` / `emSign Root TLS CA - G3` — удалить |
| `ROOT_CS` | `emSign Root CS CA - G3` (подпись кода) |
| `CROSS_PATH` | доверен `AAA Certificate Services`: через него проходят кросс-подписи Sectigo |
| `MTLS_PUBLIC_TRUST` | сервер проверяет клиентские сертификаты по публичному бандлу (30+ сертификатов) |

Информационные:

| Класс | Значение |
|---|---|
| `EMUDHRA_OTHER` | прочие корни eMudhra (G1, C1, ECC C3): на 21.10.2026 не отозваны |
| `INACTIVE_SOURCE` | исходник Debian в `/usr/share/ca-certificates`, не выбранный в `/etc/ca-certificates.conf` |
| `BLOCKLIST_ENTRY` | сертификат в p11-kit blocklist (RHEL), то есть уже недоверенный |
| `UNPARSED_KEYSTORE` | keystore не разобран: нет `keytool` или неверный пароль (`--storepass`) |

## Вывод

- **stdout** — таблицы: находки, план, результаты, Manual actions, сводка. Цвет только на терминале; отключается `--no-color` или `NO_COLOR`.
- **`-o FILE`** — дополнительно JSON Lines. У каждой записи есть `type`: `finding`, `plan`, `manual`, `backup`, `fix`, `summary`. Последней всегда идёт `summary` с `exit_code`.
- **`-o -`** — JSONL в stdout, таблицы в stderr.

```sh
sudo python3 emudhra_scan.py -o - 2>/dev/null \
  | jq -r 'select(.type=="finding" and (.class|IN("ROOT_DISTRUST","IOC_INTERMEDIATE","CROSS_PATH"))) | [.class,.path,.alias // "-"] | @tsv'
```

## Исправление (`--fix`)

Работает только на живой системе (`--root /`). Образы исправляются пересборкой.

Порядок: скан → план → **бэкап до любых изменений** → решения → применение → повторная проверка каждого затронутого хранилища.

| Хранилище | Действие |
|---|---|
| Системный бандл Debian/Ubuntu/Alpine | `!` перед строкой в `/etc/ca-certificates.conf`, затем `update-ca-certificates --fresh`. Переживает обновления пакетов |
| Системный бандл RHEL/Fedora | PEM в `/etc/pki/ca-trust/source/blocklist/`, затем `update-ca-trust extract` |
| PEM-бандл (certifi, приложения) | вырезание блоков вместе с заголовком-комментарием; атомарная запись, права и владелец сохраняются |
| Java keystore | `keytool -delete` по alias |
| NSS | `certutil -D` |
| Файл в каталоге-CApath | удаление файла (копия в бэкапе) |

Флаги:

- `--dry-run` — только план.
- `--force` — без вопросов. Без него для каждого действия спрашивается `y` / `n` / `a` (все неопасные) / `q`. Нужен терминал; без терминала — код 2, ничего не меняется.
- `--fix-cross` — разрешить удаление `AAA Certificate Services`. Без этого флага AAA не удаляется даже с `--force`: это может сломать легитимные старые цепочки Sectigo. Если в одном файле есть и G3, и AAA, это два отдельных решения.

Тонкость Debian: `update-ca-certificates` сначала снимает строки с `!`, потом добавляет все обычные. Обычная строка побеждает `!` независимо от порядка, поэтому скрипт заменяет **все** вхождения.

## Бэкап и откат

`--backup-dir BASE` задаёт базовый каталог (по умолчанию `/var/backups/emudhra-scan`). Каждый запуск создаёт новый `BASE/<UTC>-<host>[-N]` с правами 0700; существующие бэкапы не перезаписываются.

```
BASE/20261021T175421Z-host/
├── .emudhra-backup        маркер: сканер не обходит этот каталог
├── files/<исходный путь>  копии, сверенные по sha256
├── manifest.json          пути, sha256, режим, владелец, решения, статусы, команды (пароли замаскированы)
├── manual-actions.tsv     список ручных действий
└── restore.sh             откат
```

```sh
sudo sh /var/backups/emudhra-scan/20261021T175421Z-host/restore.sh
```

`restore.sh` возвращает файлы, удаляет созданные (blocklist), перезапускает обновление хранилища и восстанавливает файлы ещё раз. Результат байт в байт совпадает с бэкапом, включая Java `cacerts`, который хуки пересобирают.

Копии keystore могут содержать приватные ключи. Удаляй бэкапы после проверки.

Если бэкап не удался (нет места, нет прав, база — файл), выводится `Backup failed`, ничего не меняется, код 3.

## Manual actions

Итоговый список того, что скрипт не может или не должен менять сам. Список сгруппирован по причине, совет даётся на группу. `--manual-list FILE` пишет его в TSV (`category`, `path`, `certificates`, `classes`, `detail`, `what_to_do`); работает и без `--fix`.

| Категория | Что делать |
|---|---|
| `snap` | squashfs только на чтение: `snap refresh <snap>`; неактивные ревизии — `snap remove <snap> --revision=<rev>` |
| `image-layer` | слои в `/var/lib/docker`, containerd, podman: пересобрать образ от исправленной базы |
| `container` | файлы запущенных контейнеров: пересобрать образ и перезапустить |
| `flatpak` | `flatpak update` |
| `readonly` | ФС только на чтение: исправить в источнике или перемонтировать на запись |
| `permission` | нет прав или `chattr +i`: запустить от root или снять атрибут |
| `node` | корни вшиты в Node.js: обновить Node или запускать с `--use-openssl-ca` |
| `binary` | хранилище вшито в бинарник или формат не распознан: обновить ПО |
| `chain` | отдаваемая цепочка (`ssl_certificate` и т. п.): перевыпустить серверный сертификат у другого CA |
| `empty` | файл стал бы пустым: решить, чему должен доверять потребитель |
| `keystore` | нужен `--storepass` или `certutil` |
| `cross` | AAA без `--fix-cross` |
| `mtls` | перенастроить проверку клиентов на внутренний CA |
| `apply-error` | упало при применении: см. ошибку |

Права, ФС только на чтение и immutable проверяются **до** применения. Такие действия сразу уходят в список и не ломают прогон. Ошибки, возникшие при применении (SELinux, AppArmor), тоже попадают сюда с текстом ошибки.

## Коды возврата

| Код | Значение |
|---|---|
| 0 | ничего не найдено, или всё исправлено и проверено |
| 1 | есть находки, ручные пункты, отклонённые или неисправленные действия |
| 2 | `--fix` без терминала и без `--force` / `--dry-run`; ничего не изменено |
| 3 | ошибка бэкапа (ничего не изменено) или ошибки при применении |

## Флот (Ansible)

```yaml
- hosts: all
  become: true
  tasks:
    - name: Copy scanner
      ansible.builtin.copy:
        src: emudhra_scan.py
        dest: /usr/local/sbin/emudhra_scan.py
        mode: "0700"

    - name: Scan
      ansible.builtin.command: >
        python3 /usr/local/sbin/emudhra_scan.py --xdev --no-color
        -o /var/tmp/emudhra.jsonl --manual-list /var/tmp/emudhra-manual.tsv
      register: scan
      changed_when: false
      failed_when: scan.rc not in [0, 1]

    - name: Fetch reports
      ansible.builtin.fetch:
        src: "/var/tmp/{{ item }}"
        dest: "reports/{{ inventory_hostname }}/"
        flat: true
      loop: [emudhra.jsonl, emudhra-manual.tsv]
```

Сводка по флоту:

```sh
cat reports/*/emudhra.jsonl \
  | jq -r 'select(.type=="finding" and .class=="ROOT_DISTRUST") | [.host,.path] | @tsv' | sort -u
```

Для исправления на флоте — тот же плейбук с `--fix --force` (и `failed_when: scan.rc not in [0, 1]`). Сначала прогони `--fix --dry-run` и по одному хосту каждого семейства ОС.

## Параметры

| Параметр | Назначение |
|---|---|
| `--root DIR` | сканировать дерево вместо `/` (образ, chroot). Процессы при этом не сканируются |
| `--xdev` | не переходить на другие файловые системы при обходе |
| `--no-fs` | без обхода ФС: только конфиги и процессы |
| `--no-proc` | без процессов |
| `--scan-binaries` | искать хранилища во всех исполняемых и `.so` (Go `x509roots/fallback`, Rust `webpki-roots`), только по сырым байтам |
| `--keytool PATH` | `keytool` хоста; из `--root` никогда не берётся |
| `--storepass PW` | пароль keystore, можно указывать несколько раз; по умолчанию `changeit` |
| `--quiet-other` | скрыть `EMUDHRA_OTHER` |

## Ограничения

- RHEL (`update-ca-trust`, blocklist) и Alpine вживую не тестировались, только Debian/Ubuntu. Начинай с `--dry-run`.
- PKCS12 с паролем без `keytool` и верного `--storepass` не читается: сертификаты внутри зашифрованы.
- Относительные пути в конфигах nginx и Apache разрешаются от каталога конфига, а не от `prefix` / `ServerRoot`.
- Вшитые хранилища Go и Rust находятся только с `--scan-binaries` и только по сырым байтам.
- Процессы сканируются только при `--root /` и под root.
- Windows и macOS не поддерживаются. Там нужны `Cert:\…\Disallowed` (GPO) и `security add-trusted-cert -d -r deny`.
- Список IOC зашит в скрипт по состоянию бага на 21.10.2026. Если появятся новые затронутые сертификаты, его нужно обновить.
