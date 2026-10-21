#!/usr/bin/env python3
"""
emudhra_scan.py — поиск в trust store'ах сертификатов, связанных с инцидентом eMudhra (Oct 2026,
Mozilla bug 2083449). Только stdlib, Python 3.6+, Linux.

Вывод: человекочитаемые таблицы в stdout (цвет только на терминале; --no-color или NO_COLOR отключают).
  -o FILE  — дополнительно JSON Lines в FILE: записи type=finding|plan|manual|backup|fix|summary.
  -o -     — JSON Lines в stdout, таблицы в stderr (удобно для `| jq`).

Источники:
  fs      — обход ФС: файлы с «сертификатными» именами (*.pem, *.crt, cacerts, cert9.db, ...),
            бинарники node/nodejs (корни Node вшиты в PEM-виде).
  conf    — ссылки из конфигов: nginx/angie/openresty, Apache, HAProxy, PHP (openssl.cafile, curl.cainfo),
            Postfix, Envoy, Squid, Kafka/Elasticsearch, systemd-юниты, /etc/environment, /etc/default.
  proc    — запущенные процессы (только --root /): SSL_CERT_FILE, NODE_EXTRA_CA_CERTS, REQUESTS_CA_BUNDLE и др.
            из environ, -Djavax.net.ssl.trustStore, cacerts по умолчанию у JVM, бинарник node.
            Пути внутри контейнеров читаются через /proc/PID/root.

Форматы: PEM/DER (в т. ч. TRUSTED CERTIFICATE), JKS/PKCS12 через keytool хоста (с alias),
NSS cert9.db через sqlite3, всё прочее — поиск имён и серийников в сырых байтах.
Бинарники из сканируемого дерева никогда не исполняются.

Классы находок (exit code 1, если есть хоть один из них):
  IOC_INTERMEDIATE  — скомпрометированный промежуточный (точное совпадение SHA-256)
  IOC_SERIAL        — серийный номер из IOC (без совпадения отпечатка или в нераспарсенном хранилище)
  ROOT_DISTRUST     — корень emSign ECC Root CA - G3 / emSign Root TLS CA - G3: удалить
  ROOT_CS           — корень emSign Root CS CA - G3
  CROSS_PATH        — доверен AAA Certificate Services: путь для кросс-подписей Sectigo
  MTLS_PUBLIC_TRUST — сервер проверяет клиентские сертификаты по публичному бандлу
Информационные (на exit code не влияют):
  EMUDHRA_OTHER     — прочие корни eMudhra (G1, C1, ...)
  INACTIVE_SOURCE   — исходник Debian в /usr/share/ca-certificates, не выбранный в /etc/ca-certificates.conf
  BLOCKLIST_ENTRY   — сертификат лежит в p11-kit blocklist (RHEL), то есть уже недоверенный
  UNPARSED_KEYSTORE — хранилище Java не разобрано (нет keytool или неверный пароль); PKCS12 с паролем
                      шифрует сертификаты, сырой поиск их не видит — перезапустить с --storepass

Примеры:
  sudo python3 emudhra_scan.py                      # весь хост
  sudo python3 emudhra_scan.py --no-fs              # быстро: только конфиги и процессы
  python3 emudhra_scan.py --root /tmp/img-rootfs    # распакованный образ контейнера
  sudo python3 emudhra_scan.py --scan-binaries      # + все исполняемые/.so (вшитые webpki-roots и т. п.)

Исправление (только живая система, --root /):
  sudo python3 emudhra_scan.py --fix --dry-run      # показать план, ничего не трогать
  sudo python3 emudhra_scan.py --fix                # бэкап, затем вопрос по каждому действию (y/n/a/q)
  sudo python3 emudhra_scan.py --fix --force        # бэкап и все автоматические действия без вопросов
  ... --fix-cross                                   # разрешить удаление AAA Certificate Services (по умолчанию нет)
  ... --backup-dir BASE                             # каждый запуск создаёт новый BASE/<UTC>-<host>[-N];
                                                    # по умолчанию BASE=/var/backups/emudhra-scan

  Действия: системные бандлы — штатно ('!' в /etc/ca-certificates.conf + update-ca-certificates --fresh;
  RHEL: p11-kit blocklist + update-ca-trust extract); PEM — вырезание блоков (атомарно, права и владелец
  сохраняются); Java — keytool -delete; NSS — certutil -D; файл в каталоге-CApath — удаление.
  Только вручную: вшитые в Node и бинарники, отдаваемые цепочки (ssl_certificate), MTLS_PUBLIC_TRUST,
  файлы, которые стали бы пустыми, файлы в запущенных контейнерах (/proc/PID/root).

  Manual actions: итоговый список файлов для ручной обработки, сгруппированный по причине, с советом на группу:
  snap (squashfs, только `snap refresh`), слои образов (/var/lib/docker, containerd, podman), flatpak, ФС только
  на чтение, нет прав/immutable (проверяется ДО применения), Node и бинарники, отдаваемые цепочки, файлы, которые
  стали бы пустыми, keystore без пароля, AAA без --fix-cross, mTLS, а также всё, что упало при применении.
  --manual-list FILE пишет его в TSV (category, path, certificates, classes, detail, what_to_do) — с --fix или
  без него; при --fix копия сохраняется в каталоге бэкапа как manual-actions.tsv.
  Бэкап: каталог 0700 с копиями (могут содержать приватные ключи из keystore), manifest.json (исходный
  путь, sha256, режим, владелец, решения, статусы, команды) и restore.sh (байт в байт). Каталог бэкапа
  помечается .emudhra-backup и не сканируется.
  Коды выхода: 0 — всё исправлено и проверено; 1 — остались ручные/отклонённые/неисправленные;
  2 — нет терминала для вопросов (нужен --force или --dry-run), ничего не изменено; 3 — ошибки применения.
"""
import argparse, base64, hashlib, json, os, re, shutil, socket, sqlite3, stat, subprocess, sys
from collections import Counter

# --- IOC: Mozilla bugzilla 2083449, comments 0 and 2 ---
IOC = {
    # eMudhra-issued (revoked by eMudhra 2026-10-18, caCompromise)
    "E7568FE6E12331F4FD7DE61DA4C7559D0F8EB192A218D4741A3BA75184333838": ("EM EV TLS CA - G3B", "c7c41efe92d825f05eae841a4a82c1"),
    "98B896625C0C230ADEEC3EB2CF6AAD5001ECF9156A68644E82374CE5833BC25B": ("EM OV TLS CA - G3B", "6cada367fb1c100088120ea202d568"),
    "42C4ACCD12C4F59597925E1A08A7A90102608543809308D50EC427E118BA1493": ("EM DV TLS CA - G3B", "a4aee678f23362b4c0e460b772f214"),
    "432EC25F0D28DE9006D97BF752F17BBB2CD41F669933FCB072D9A1148D0261F3": ("EM EV TLS CA - G3C", "8009928a64107601af05fa2f19f109"),
    "CB6E15165AC802E9B3F993F16C25D41F4E81C21EBDE71AE1B012AC00BF9C7C3F": ("EM OV TLS CA - G3C", "296926c227a3a1526392b19482a504"),
    "0164D7CEAE5BB909C272AF151FF44B1177AE9B47D9424B94F1D9558C30934D19": ("EM DV TLS CA - G3C", "588b2e3c2bb8cda13e1a1209254321"),
    "9E39DE2881273ACC225A149C72BA3E0F51424963669AB633EE1DC7DF5DB067B4": ("EM OV CS CA - G3B",  "7818933f8f85b4619a2b35fba83d0a"),
    "4B2460A466F95FD40113BCDCCA2CEB29B3B093921DE45474DA7DF48874C630B1": ("EM OV CS CA - G3C",  "544b7f922c31ae220a4a922916f6e6"),
    # Sectigo cross-signed (same keys; chain to AAA Certificate Services, still trusted by Microsoft/Apple)
    "579480AEA166290BD3C643589E795FC0D0E54E86505D180F1DFF99EFD3199512": ("EM EV TLS CA - G3B (Sectigo cross)", "d8f8685e4f2bd9d82402a85a1c1eb731"),
    "5F1DED4DD590AF74631290CF073B122A2AAC6A1FA479778A0BD43579BD832699": ("EM OV TLS CA - G3B (Sectigo cross)", "e94223bde92f914e5ab9acabfdac3710"),
    "45A883F349AEDFD5F3A649B5498FFB121712BA8B448F3F2A91DBC5A766FCDDBE": ("EM DV TLS CA - G3B (Sectigo cross)", "a024fdf4ba665c785ce4a020483858b7"),
    "FD9D5C2DBBD4995AB69B8D50C439D9527B00529199C2FD01B2174EB58F07021F": ("EM EV TLS CA - G3C (Sectigo cross)", "05f078752dece7a1bb8595d303167171"),
    "7485B51C0ED192878FA1D2F948FB529AE1842CC5086C4B67F7BE5B2039DE9489": ("EM OV TLS CA - G3C (Sectigo cross)", "8d5a4811939ef447d77111cdd9849ae9"),
    "62B7F9868263F72F6911FC78CEAF72C1979158B7368BF648683BB2AA39B02E72": ("EM DV TLS CA - G3C (Sectigo cross)", "91f347f1a5b7d39962b95e0ee4e299d1"),
    "A496E23AC0CAB8155FC9B117B97EAE368EFCBB9041AEC8804D5A308D2D01C2D8": ("EM OV CS CA - G3B (Sectigo cross)",  "41e32b73ac185d6ce0d7480bacf84e69"),
    "84112972B8E59D14560AE7E7119654474AAD119990CF3722BFC1E3B91615E1FD": ("EM OV CS CA - G3C (Sectigo cross)",  "d6a5ef613b390f32ef9cdf349f772841"),
}
SERIAL_HEX = {s: n for (n, s) in IOC.values()}
SERIAL_BYTES = {bytes.fromhex(s): n for (n, s) in IOC.values()}

ROOT_CLASSES = {
    "emSign ECC Root CA - G3": "ROOT_DISTRUST",   # Mozilla/Chrome emergency distrust
    "emSign Root TLS CA - G3": "ROOT_DISTRUST",   # CCADB name of the issuer in the bug
    "emSign Root CS CA - G3":  "ROOT_CS",
    "AAA Certificate Services": "CROSS_PATH",
}
ACTIONABLE = {"IOC_INTERMEDIATE", "IOC_SERIAL", "ROOT_DISTRUST", "ROOT_CS", "CROSS_PATH", "MTLS_PUBLIC_TRUST"}

CERTISH_NAME = re.compile(
    r"(\.(pem|crt|cer|der|jks|p12|pfx|keystore|truststore)$)|"
    r"^(cacerts|ca-bundle.*|ca-certificates.*|cacert\.pem|tls-ca-bundle\.pem|cert[89]\.db|"
    r"email-ca-bundle\.pem|objsign-ca-bundle\.pem|trusted\.pem)$", re.I)
NODE_NAME = re.compile(r"^(node|nodejs)$")
KEYSTORE_NAME = re.compile(r"(\.(jks|p12|pfx|keystore|truststore)$)|^cacerts$", re.I)
PEM_RE = re.compile(rb"-----BEGIN (?:TRUSTED )?CERTIFICATE-----(.+?)-----END (?:TRUSTED )?CERTIFICATE-----", re.S)
SKIP_TOP = {"proc", "sys", "dev", "run"}
MAX_SIZE = 256 * 1024 * 1024
PUBLIC_BUNDLE_MIN = 30          # >= this many certs in a client-trust file => looks like a public bundle
PUBLIC_BUNDLE_NAMES = {"ca-certificates.crt", "tls-ca-bundle.pem", "ca-bundle.crt", "ca-bundle.pem",
                       "cacert.pem", "ca-bundle.trust.crt", "cacerts"}
BACKUP_MARKER = ".emudhra-backup"


def debian_selected(root):
    """Certificates update-ca-certificates actually installs: it first drops '!' lines, then adds every plain
    line, so a plain line wins over '!' regardless of order. -> set of paths relative to /usr/share/ca-certificates,
    or None if the conf does not exist."""
    p = os.path.join(root, "etc/ca-certificates.conf")
    try:
        with open(p, encoding="utf-8", errors="replace") as fh:
            lines = [l.strip() for l in fh]
    except OSError:
        return None
    return {l for l in lines if l and not l.startswith(("#", "!"))}


def informational_override(shown_path, deb_sel):
    """Some files hold affected certificates by design and are not trusted: report them, but not as actionable."""
    if deb_sel is not None and shown_path.startswith("/usr/share/ca-certificates/"):
        rel = shown_path[len("/usr/share/ca-certificates/"):]
        if rel not in deb_sel:
            return "INACTIVE_SOURCE", "not selected in /etc/ca-certificates.conf: not installed into the bundle"
    if "/ca-trust/source/blocklist/" in shown_path or "/ca-trust/source/blacklist/" in shown_path:
        return "BLOCKLIST_ENTRY", "p11-kit blocklist entry: this certificate is distrusted"
    return None


# ---------------------------------------------------------------- DER

def tlv(b, off):
    """-> (tag, value_start, end) or None."""
    if off + 2 > len(b):
        return None
    tag, l, p = b[off], b[off + 1], off + 2
    if l & 0x80:
        n = l & 0x7F
        if n == 0 or n > 4 or p + n > len(b):
            return None
        l, p = int.from_bytes(b[p:p + n], "big"), p + n
    return (tag, p, p + l) if p + l <= len(b) else None


DER_CN_RE = re.compile(rb"\x06\x03\x55\x04\x03[\x0c\x13\x14\x16]([\x01-\x7f])", re.S)


def cn_values(name_der):
    out = []
    for m in DER_CN_RE.finditer(name_der):
        n = m.group(1)[0]
        v = name_der[m.end():m.end() + n]
        try:
            t = v.decode("utf-8")
        except UnicodeDecodeError:
            continue
        if len(v) == n and t.isprintable():
            out.append(t)
    return out


def parse_cert(der):
    """Minimal X.509 parse -> dict or None. Accepts a TRUSTED CERTIFICATE blob (cert is the first TLV)."""
    t = tlv(der, 0)
    if not t or t[0] != 0x30:
        return None
    cert = der[:t[2]]
    tbs = tlv(cert, t[1])
    if not tbs or tbs[0] != 0x30:
        return None
    fields, p = [], tbs[1]
    while p < tbs[2] and len(fields) < 7:
        f = tlv(cert, p)
        if not f:
            return None
        fields.append(f)
        p = f[2]
    if fields and fields[0][0] == 0xA0:          # [0] version
        fields = fields[1:]
    # serial, signature, issuer, validity, subject
    if len(fields) < 5 or fields[0][0] != 0x02 or fields[2][0] != 0x30 or fields[4][0] != 0x30:
        return None
    serial = cert[fields[0][1]:fields[0][2]].lstrip(b"\x00")
    iss, sub = cn_values(cert[fields[2][1]:fields[2][2]]), cn_values(cert[fields[4][1]:fields[4][2]])
    return {"sha256": hashlib.sha256(cert).hexdigest().upper(), "serial": serial.hex(),
            "issuer": iss[-1] if iss else "", "subject": sub[-1] if sub else ""}


def classify(c):
    out = []
    if c["sha256"] in IOC:
        out.append(("IOC_INTERMEDIATE", IOC[c["sha256"]][0]))
    elif c["serial"] in SERIAL_HEX:
        out.append(("IOC_SERIAL", SERIAL_HEX[c["serial"]]))
    cls = ROOT_CLASSES.get(c["subject"])
    if cls:
        out.append((cls, c["subject"]))
    elif not out and ("emSign" in c["subject"] or "eMudhra" in c["subject"]):
        out.append(("EMUDHRA_OTHER", c["subject"]))
    return out


# ---------------------------------------------------------------- store readers
# each returns (store_type, [(der, alias)]); empty list => caller falls back to raw scan

def pem_ders(data):
    out = []
    for m in PEM_RE.finditer(data):
        try:
            out.append(base64.b64decode(re.sub(rb"\s+", b"", m.group(1))))
        except Exception:
            pass
    return out


STOREPASS_USED = {}   # keystore path -> password that opened it (None: listed without password)
JAVA_ENV = {k: v for k, v in os.environ.items() if k not in ("JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "_JAVA_OPTIONS")}


def read_keytool(path, keytool, passwords):
    if not keytool:
        return []
    env = JAVA_ENV
    attempts = [["-storepass", p] for p in passwords] + [[]]
    for extra in attempts:
        try:
            r = subprocess.run([keytool, "-list", "-rfc", "-keystore", path] + extra, input=b"\n",
                               stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=env, timeout=60)
        except (OSError, subprocess.TimeoutExpired):
            return []
        out, certs = r.stdout, []
        for chunk in re.split(rb"\n(?=Alias name: )", out):
            m = re.match(rb"Alias name: (.*)", chunk)
            alias = m.group(1).decode("utf-8", "replace").strip() if m else None
            certs += [(d, alias) for d in pem_ders(chunk)]
        if certs:
            STOREPASS_USED[path] = extra[1] if extra else None
            return certs
    return []


def read_nss(path):
    try:
        con = sqlite3.connect("file:%s?mode=ro&immutable=1" % path, uri=True)
        rows = con.execute("SELECT a11, a3 FROM nssPublic WHERE a11 IS NOT NULL").fetchall()
        con.close()
    except Exception:
        return []
    out = []
    for val, label in rows:
        if isinstance(val, bytes) and val[:1] == b"\x30":
            alias = label.decode("utf-8", "replace").rstrip("\x00") if isinstance(label, bytes) else None
            out.append((val, alias))
    return out


def read_store(path, data, keytool, passwords):
    name = os.path.basename(path)
    if name in ("cert9.db",):
        certs = read_nss(path)
        if certs:
            return "nss", certs
    ders = pem_ders(data)
    if ders:
        return ("node-binary" if NODE_NAME.match(name) else "pem"), [(d, None) for d in ders]
    if KEYSTORE_NAME.search(name) or data[:4] == b"\xfe\xed\xfe\xed":
        certs = read_keytool(path, keytool, passwords)
        if certs:
            return "keytool", certs
    if data[:1] == b"\x30" and parse_cert(data):
        return "der", [(data, None)]
    return "raw", []


def raw_hits(data):
    """Fallback for stores we cannot parse (JKS without keytool, cert8.db, binaries)."""
    out = []
    for name, cls in ROOT_CLASSES.items():
        if name.encode() in data:
            out.append((cls, name))
    for ser, name in SERIAL_BYTES.items():
        if ser in data:
            out.append(("IOC_SERIAL", name))
    if b"emSign" in data and not any(c in ("ROOT_DISTRUST", "ROOT_CS") for c, _ in out):
        for n in sorted(set(cn_values(data))):
            if "emSign" in n and n not in ROOT_CLASSES:
                out.append(("EMUDHRA_OTHER", n))
    return out


# ---------------------------------------------------------------- path resolution

def resolve_in_root(root, path, hops=40):
    """Resolve absolute `path` inside `root`, following symlinks without escaping root. -> host path or None."""
    parts = [p for p in path.split("/") if p not in ("", ".")]
    cur = []
    while parts:
        p = parts.pop(0)
        if p == "..":
            if cur:
                cur.pop()
            continue
        host = os.path.join(root, *cur, p)
        try:
            st = os.lstat(host)
        except OSError:
            return None
        if stat.S_ISLNK(st.st_mode):
            hops -= 1
            if hops < 0:
                return None
            t = os.readlink(host)
            if t.startswith("/"):
                cur = []
            parts = [x for x in t.split("/") if x not in ("", ".")] + parts
        else:
            cur.append(p)
    return os.path.join(root, *cur) if cur else root


def display(root, host_path):
    if root != "/" and host_path.startswith(root.rstrip("/") + "/"):
        return host_path[len(root.rstrip("/")):]
    return host_path


# ---------------------------------------------------------------- config references

ENV_KEYS = ("SSL_CERT_FILE", "SSL_CERT_DIR", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "NODE_EXTRA_CA_CERTS",
            "GIT_SSL_CAINFO", "GIT_SSL_CAPATH", "AWS_CA_BUNDLE", "PIP_CERT", "GRPC_DEFAULT_SSL_ROOTS_FILE_PATH")
ENV_RE = re.compile(r"\b(%s)=\"?([^\"\s]+)" % "|".join(ENV_KEYS))
JAVA_TS_RE = re.compile(r"-Djavax\.net\.ssl\.trustStore=\"?([^\"\s]+)")

# (family, dirs relative to root, [(regex, directive_group, path_group, kind)])
# kind: client_trust (verifies client certs: mTLS), trust (upstream/outbound trust), chain (served chain)
LINE_RULES = [
    ("nginx", ["etc/nginx", "etc/angie", "etc/openresty", "usr/local/nginx/conf", "usr/local/openresty/nginx/conf",
               "usr/local/etc/nginx"],
     [(re.compile(r"(?:^|[;{])\s*(ssl_client_certificate|ssl_trusted_certificate)\s+\"?([^;\"\s]+)"), 1, 2, "client_trust"),
      (re.compile(r"(?:^|[;{])\s*((?:proxy|grpc|uwsgi)_ssl_trusted_certificate)\s+\"?([^;\"\s]+)"), 1, 2, "trust"),
      (re.compile(r"(?:^|[;{])\s*(ssl_certificate)\s+\"?([^;\"\s]+)"), 1, 2, "chain")]),
    ("apache", ["etc/apache2", "etc/httpd", "usr/local/apache2/conf", "usr/local/etc/apache24"],
     [(re.compile(r"^\s*(SSLCACertificate(?:File|Path))\s+\"?([^\"\s]+)", re.I), 1, 2, "client_trust"),
      (re.compile(r"^\s*(SSLProxyCACertificate(?:File|Path))\s+\"?([^\"\s]+)", re.I), 1, 2, "trust"),
      (re.compile(r"^\s*(SSLCertificateChainFile|SSLCertificateFile)\s+\"?([^\"\s]+)", re.I), 1, 2, "chain")]),
    ("haproxy", ["etc/haproxy", "usr/local/etc/haproxy"],
     [(re.compile(r"^\s*bind\b.*\bverify\s+(?:required|optional)\b.*\b(ca-file)\s+(\S+)"), 1, 2, "client_trust"),
      (re.compile(r"^\s*bind\b.*\b(ca-file)\s+(\S+).*\bverify\s+(?:required|optional)\b"), 1, 2, "client_trust"),
      (re.compile(r"^\s*(?:server|default-server)\b.*\b(ca-file)\s+(\S+)"), 1, 2, "trust"),
      (re.compile(r"^\s*bind\b.*\b(crt)\s+(\S+)"), 1, 2, "chain")]),
    ("php", ["etc/php", "etc/php5", "etc/php7", "etc/php8", "usr/local/etc/php", "etc/opt/remi", "opt/remi"],
     [(re.compile(r"^\s*(openssl\.cafile|openssl\.capath|curl\.cainfo)\s*=\s*\"?([^\";\s]+)"), 1, 2, "trust")]),
    ("postfix", ["etc/postfix"],
     [(re.compile(r"^\s*(smtpd_tls_CA(?:file|path))\s*=\s*(\S+)"), 1, 2, "client_trust"),
      (re.compile(r"^\s*(smtp_tls_CA(?:file|path))\s*=\s*(\S+)"), 1, 2, "trust")]),
    ("squid", ["etc/squid"],
     [(re.compile(r"\b(tls-cafile|sslcafile|sslproxy_cafile)[=\s]+(\S+)"), 1, 2, "trust")]),
    ("java", ["etc/kafka", "opt/kafka/config", "etc/elasticsearch", "etc/opensearch", "etc/default", "etc/sysconfig",
              "etc/systemd/system", "usr/lib/systemd/system", "lib/systemd/system", "etc/tomcat", "etc/tomcat9",
              "etc/tomcat10", "etc/jenkins", "opt"],
     [(re.compile(r"(-Djavax\.net\.ssl\.trustStore)=\"?([^\"\s]+)"), 1, 2, "trust"),
      (re.compile(r"^\s*((?:ssl|listener\.[\w.-]+\.ssl)\.truststore\.location)\s*=\s*(\S+)"), 1, 2, "client_trust"),
      (re.compile(r"^\s*(xpack\.security\.http\.ssl\.(?:truststore\.path|certificate_authorities))\s*:\s*\[?\s*\"?([^\"\s\],]+)"), 1, 2, "client_trust"),
      (re.compile(r"^\s*(xpack\.security\.transport\.ssl\.(?:truststore\.path|certificate_authorities))\s*:\s*\[?\s*\"?([^\"\s\],]+)"), 1, 2, "client_trust")]),
    ("env", ["etc/environment", "etc/default", "etc/sysconfig", "etc/systemd/system", "usr/lib/systemd/system",
             "lib/systemd/system", "etc/profile.d"],
     [(ENV_RE, 1, 2, "trust")]),
]
FILE_RULES = [  # whole-file regexes (multi-line YAML)
    ("envoy", ["etc/envoy"], re.compile(r"(trusted_ca):\s*(?:\{\s*)?filename:\s*\"?([^\"\s},]+)"), "trust"),
]
MTLS_ENABLE = {  # client_trust only matters if client verification is on somewhere in that family's config
    "nginx": re.compile(r"(?:^|[;{])\s*ssl_verify_client\s+(on|optional|optional_no_ca)\b", re.M),
    "apache": re.compile(r"^\s*SSLVerifyClient\s+(require|optional)\b", re.M | re.I),
    "postfix": re.compile(r"^\s*smtpd_tls_(ask_ccert|req_ccert)\s*=\s*yes\b", re.M),
    "java": re.compile(r"(ssl\.client\.auth\s*=\s*required|client_authentication\s*:\s*required)", re.M),
}
CONF_MAX = 4 * 1024 * 1024
CONF_SKIP_EXT = (".so", ".jar", ".gz", ".zip", ".png", ".jpg", ".pyc", ".class")


def iter_conf_files(root, rel_dir, deep):
    base = os.path.join(root, rel_dir)
    if os.path.isfile(base):
        yield base
        return
    if not os.path.isdir(base):
        return
    for dp, dn, fn in os.walk(base, followlinks=False):
        if not deep and dp.count(os.sep) - base.count(os.sep) >= 3:
            dn[:] = []
        for f in fn:
            p = os.path.join(dp, f)
            if f.endswith(CONF_SKIP_EXT):
                continue
            try:
                st = os.stat(p)
            except OSError:
                continue
            if stat.S_ISREG(st.st_mode) and 0 < st.st_size <= CONF_MAX:
                yield p


def read_text(p):
    try:
        with open(p, "rb") as fh:
            b = fh.read(CONF_MAX)
    except OSError:
        return None
    if b"\x00" in b[:4096]:
        return None
    return b.decode("utf-8", "replace")


def collect_conf_refs(root):
    """-> list of dict(family, directive, kind, conf, line, target, mtls_on)"""
    refs, mtls_on = [], {}
    for family, dirs, rules in LINE_RULES:
        for d in dirs:
            for cf in iter_conf_files(root, d, deep=(d != "opt")):
                if d == "opt" and not re.search(r"(jvm\.options|\.properties|\.conf|setenv\.sh|\.service)$", cf):
                    continue
                txt = read_text(cf)
                if not txt:
                    continue
                if family in MTLS_ENABLE and MTLS_ENABLE[family].search(txt):
                    mtls_on[family] = True
                for i, line in enumerate(txt.splitlines(), 1):
                    s = line.split("#", 1)[0] if family not in ("php",) else line.split(";", 1)[0]
                    for rx, gd, gp, kind in rules:
                        for m in rx.finditer(s):
                            target = m.group(gp)
                            if "$" in target or "%" in target:
                                continue
                            if not target.startswith("/"):
                                target = os.path.normpath(os.path.join("/" + os.path.relpath(os.path.dirname(cf), root), target))
                            refs.append({"family": family, "directive": m.group(gd), "kind": kind,
                                         "conf": display(root, cf), "line": i, "target": target})
    for family, dirs, rx, kind in FILE_RULES:
        for d in dirs:
            for cf in iter_conf_files(root, d, deep=True):
                txt = read_text(cf)
                for m in rx.finditer(txt or ""):
                    refs.append({"family": family, "directive": m.group(1), "kind": kind,
                                 "conf": display(root, cf), "line": txt[:m.start()].count("\n") + 1,
                                 "target": m.group(2)})
    for r in refs:
        r["mtls_on"] = bool(mtls_on.get(r["family"])) or r["family"] == "haproxy"
    return refs


# ---------------------------------------------------------------- processes

def collect_proc_refs():
    """-> list of dict(root, target, via) for running processes; paths resolved inside /proc/PID/root."""
    refs = []
    for pid in os.listdir("/proc"):
        if not pid.isdigit():
            continue
        base = "/proc/" + pid
        try:
            with open(base + "/cmdline", "rb") as fh:
                argv = [a.decode("utf-8", "replace") for a in fh.read().split(b"\0") if a]
            with open(base + "/environ", "rb") as fh:
                env = [a.decode("utf-8", "replace") for a in fh.read().split(b"\0") if a]
            exe = os.readlink(base + "/exe")
        except OSError:
            continue
        exe = exe.replace(" (deleted)", "")
        comm = os.path.basename(exe)
        proot = base + "/root"
        label = "proc:%s:%s" % (pid, comm)
        for kv in env:
            m = ENV_RE.match(kv)
            if m:
                refs.append({"root": proot, "target": m.group(2), "via": "%s env %s" % (label, m.group(1))})
        java_opts = " ".join(argv + [kv for kv in env if kv.split("=", 1)[0] in
                                     ("JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "_JAVA_OPTIONS", "JAVA_OPTS")])
        if comm == "java":
            m = JAVA_TS_RE.search(java_opts)
            if m:
                refs.append({"root": proot, "target": m.group(1), "via": "%s -Djavax.net.ssl.trustStore" % label})
            else:
                jhome = os.path.dirname(os.path.dirname(exe))
                for cand in ("lib/security/cacerts", "jre/lib/security/cacerts"):
                    refs.append({"root": proot, "target": os.path.join(jhome, cand),
                                 "via": "%s default cacerts" % label, "optional": True})
        if NODE_NAME.match(comm):
            # read the executable through /proc/PID/exe: works for containers and deleted binaries
            refs.append({"root": None, "target": base + "/exe", "via": "%s node built-in roots" % label,
                         "name_hint": "node"})
    return refs


# ---------------------------------------------------------------- fs walk

def is_binary_candidate(path, st):
    if st.st_mode & 0o111:
        return True
    n = os.path.basename(path)
    return n.endswith((".so", ".dll", ".node")) or ".so." in n


def walk(root, scan_binaries, xdev):
    root_dev = os.stat(root).st_dev
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        if BACKUP_MARKER in filenames:          # our own --fix backups: copies of stores, not live stores
            dirnames[:] = []
            continue
        if os.path.relpath(dirpath, root) == ".":
            dirnames[:] = [d for d in dirnames if d not in SKIP_TOP]
        if xdev:
            dirnames[:] = [d for d in dirnames if _same_dev(os.path.join(dirpath, d), root_dev)]
        for f in filenames:
            p = os.path.join(dirpath, f)
            try:
                st = os.lstat(p)
            except OSError:
                continue
            if not stat.S_ISREG(st.st_mode) or st.st_size == 0 or st.st_size > MAX_SIZE:
                continue
            if CERTISH_NAME.search(f) or NODE_NAME.match(f) or (scan_binaries and is_binary_candidate(p, st)):
                yield p


def _same_dev(p, dev):
    try:
        return os.lstat(p).st_dev == dev
    except OSError:
        return False


# ---------------------------------------------------------------- fix
#
# Flow: plan -> (dry-run stops here) -> backup every file an action may touch (+ manifest.json, restore.sh)
#       -> confirm each action (or --force) -> apply: system mechanisms first, then direct edits
#       -> verify by re-reading every touched store.

DEB_CONF = "/etc/ca-certificates.conf"
DEB_SRC = "/usr/share/ca-certificates"
DEB_LOCAL = "/usr/local/share/ca-certificates"
RH_TRUST = "/etc/pki/ca-trust"
RH_ANCHORS = ("/etc/pki/ca-trust/source/anchors", "/usr/share/pki/ca-trust-source/anchors")
FIX_DEFAULT = {"IOC_INTERMEDIATE", "IOC_SERIAL", "ROOT_DISTRUST", "ROOT_CS"}
CERT_FILE_EXT = (".pem", ".crt", ".cer", ".der")


class QuitFix(Exception):
    pass


def system_flavor():
    if os.path.isfile(DEB_CONF) and shutil.which("update-ca-certificates"):
        return "debian"
    if os.path.isdir(RH_TRUST) and shutil.which("update-ca-trust"):
        return "rhel"
    return None


def managed_by(path, flavor):
    """True if `path` is generated or sourced by the distro trust mechanism (direct edits would be reverted)."""
    rp = os.path.realpath(path)
    if flavor == "debian":
        if rp.startswith("/etc/ssl/certs/java/"):     # ca-certificates-java: verified and fixed via keytool
            return False
        return rp.startswith(("/etc/ssl/certs/", DEB_SRC + "/", DEB_LOCAL + "/"))
    if flavor == "rhel":
        return rp.startswith((RH_TRUST + "/extracted/", RH_TRUST + "/source/", "/usr/share/pki/ca-trust-source/"))
    return False


def certs_in_file(path, keytool=None, passwords=("changeit",)):
    """-> {sha256: (alias, der)} for a store, using the same readers as the scan."""
    try:
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError:
        return {}
    _, certs = read_store(path, data, keytool, list(passwords))
    out = {}
    for der, alias in certs:
        c = parse_cert(der)
        if c:
            out.setdefault(c["sha256"], (alias, der))
    return out


def index_sources(dirs):
    idx = {}
    for d in dirs:
        if not os.path.isdir(d):
            continue
        for dp, _, fn in os.walk(d):
            for f in fn:
                p = os.path.join(dp, f)
                if os.path.islink(p) or not os.path.isfile(p):
                    continue
                for fp in certs_in_file(p):
                    idx.setdefault(fp, []).append(p)
    return idx


def remove_pem_blocks(data, bad):
    """Cut PEM blocks whose SHA-256 is in `bad`, with their '#' header lines (certifi/Mozilla style)."""
    spans, removed = [], set()
    for m in PEM_RE.finditer(data):
        try:
            c = parse_cert(base64.b64decode(re.sub(rb"\s+", b"", m.group(1))))
        except Exception:
            continue
        if not c or c["sha256"] not in bad:
            continue
        s, e = m.start(), m.end()
        s = data.rfind(b"\n", 0, s) + 1
        while s > 0:
            prev = data.rfind(b"\n", 0, s - 1) + 1
            if data[prev:s - 1].lstrip().startswith(b"#"):
                s = prev
            else:
                break
        if data[e:e + 1] == b"\n":
            e += 1
        spans.append((s, e))
        removed.add(c["sha256"])
    out, pos = bytearray(), 0
    for s, e in spans:
        out += data[pos:s]
        pos = e
    out += data[pos:]
    return bytes(out), removed


def atomic_write(path, data):
    st = os.stat(path)
    import tempfile
    fd, tmp = tempfile.mkstemp(prefix=".emudhra-", dir=os.path.dirname(path))
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, stat.S_IMODE(st.st_mode))
        try:
            os.chown(tmp, st.st_uid, st.st_gid)
        except PermissionError:
            pass
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def run_cmd(cmd, log, env=None):
    try:
        r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env, timeout=300)
        rc, out = r.returncode, r.stdout.decode("utf-8", "replace")
    except (OSError, subprocess.TimeoutExpired) as ex:
        rc, out = -1, str(ex)
    log.append({"cmd": cmd, "rc": rc, "output": out[-2000:]})
    return rc, out


def path_notes(path):
    n = []
    if "/certifi/" in path or "/pip/_vendor/" in path:
        n.append("pip/certifi upgrade overwrites this file: also upgrade certifi")
    if path.startswith("/opt/gitlab/embedded/"):
        n.append("GitLab upgrade overwrites this file")
    if "/site-packages/" in path or "/dist-packages/" in path or "/node_modules/" in path:
        n.append("package-managed file: a reinstall restores it")
    return n


# Manual categories: (key, title, what to do). Order = display order.
MANUAL_CATEGORIES = [
    ("snap", "Snap packages (read-only squashfs, managed by snapd)",
     "fixed only by a new snap revision: `snap refresh <snap>`; inactive old revisions can be removed with "
     "`snap remove <snap> --revision=<rev>`"),
    ("image-layer", "Container image layers on disk",
     "do not edit layers: rebuild the image from a fixed base image and redeploy"),
    ("container", "Running containers / process images (/proc/PID/root)",
     "rebuild the image or upgrade the runtime, then restart the container"),
    ("flatpak", "Flatpak runtimes", "`flatpak update` once the runtime ships a fixed CA bundle"),
    ("readonly", "Read-only filesystems", "fix at the source (image, package) or remount read-write and re-run"),
    ("permission", "Not writable by this user", "re-run as root, or ask the owner of the file"),
    ("node", "Node.js built-in roots", "upgrade Node.js, or run it with --use-openssl-ca so it uses the fixed system store"),
    ("binary", "Embedded in binaries / unknown formats", "upgrade or rebuild the software that embeds the store"),
    ("chain", "Served certificate chains", "reissue the server certificate from another CA and replace the chain"),
    ("empty", "Files that would become empty",
     "decide what the consumer should trust instead, then edit or remove the file and its reference"),
    ("keystore", "Keystores needing a password or a tool", "re-run with --storepass (keytool), or install certutil (NSS)"),
    ("cross", "AAA Certificate Services (not removed by default)",
     "re-run with --fix-cross, or block the 8 Sectigo cross-signed intermediates instead"),
    ("mtls", "mTLS verified against a public CA bundle",
     "point client-certificate verification to your internal CA bundle"),
    ("apply-error", "Failed while applying", "see the error, fix the cause, re-run"),
]
MANUAL_INFO = {k: (t, w) for k, t, w in MANUAL_CATEGORIES}


def mount_point(p):
    """Longest mount point containing p (from /proc/self/mountinfo: also sees bind mounts, which ismount() misses)."""
    p = os.path.realpath(p)
    best = "/"
    try:
        with open("/proc/self/mountinfo") as fh:
            for line in fh:
                mp = re.sub(r"\\([0-7]{3})", lambda m: chr(int(m.group(1), 8)), line.split()[4])
                if (p == mp or p.startswith(mp.rstrip("/") + "/")) and len(mp) > len(best):
                    best = mp
    except OSError:
        pass
    return best


def is_immutable(p):
    """ext4/xfs/btrfs 'i' or 'a' attribute (chattr): even root cannot modify such files."""
    try:
        import fcntl, struct
        fd = os.open(p, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
        try:
            flags = struct.unpack("l", fcntl.ioctl(fd, 0x80086601, struct.pack("l", 0)))[0]   # FS_IOC_GETFLAGS
        finally:
            os.close(fd)
        return bool(flags & 0x30)            # FS_IMMUTABLE_FL | FS_APPEND_FL
    except Exception:
        return False


def path_context(path):
    """Locations that must never be edited in place. -> (category, detail) or None."""
    m = re.match(r"^/snap/([^/]+)/([^/]+)/", path)
    if m:
        name, rev = m.groups()
        try:
            cur = os.readlink("/snap/%s/current" % name)
        except OSError:
            cur = None
        state = "active revision" if cur == rev else ("inactive revision, current is %s" % cur if cur else "revision")
        return "snap", "snap %s rev %s (%s)" % (name, rev, state)
    if path.startswith("/proc/"):
        return "container", "process %s" % path.split("/")[2]
    if re.match(r"^/var/lib/(docker|containerd|containers/storage|rancher)/", path) or "/overlay2/" in path:
        return "image-layer", "image/layer storage"
    if "/flatpak/" in path:
        return "flatpak", "flatpak runtime"
    return None


def write_blocker(paths, dirs):
    """Can we modify these files and create/replace files in these directories? -> (category, detail) or None."""
    for p in list(paths) + list(dirs):
        if not os.path.exists(p):
            continue
        try:
            if os.statvfs(p).f_flag & os.ST_RDONLY:
                return "readonly", "read-only filesystem mounted at %s" % mount_point(p)
        except OSError:
            pass
    for p in list(paths) + list(dirs):
        if os.path.exists(p) and is_immutable(p):
            return "permission", "immutable attribute on %s (`lsattr`; remove with `chattr -i` if intended)" % p
    for d in dirs:
        if os.path.isdir(d) and not os.access(d, os.W_OK | os.X_OK):
            return "permission", "no write permission on directory %s (euid %d)" % (d, os.geteuid())
    for p in paths:
        if os.path.exists(p) and not os.access(p, os.W_OK):
            return "permission", "no write permission on %s (euid %d)" % (p, os.geteuid())
    return None


def action_blocker(a):
    t = a["type"]
    if t == "debian-deselect":
        return write_blocker([DEB_CONF] + a["quarantine"], ["/etc", "/etc/ssl/certs"] +
                             [os.path.dirname(q) for q in a["quarantine"]])
    if t == "rhel-blocklist":
        return write_blocker(a["quarantine"], [os.path.dirname(os.path.dirname(a["blocklist_file"])),
                                               RH_TRUST + "/extracted"] + [os.path.dirname(q) for q in a["quarantine"]])
    return write_blocker([a["path"]], [os.path.dirname(a["path"])])   # atomic replace / delete / keystore journal


def add_manual(manual, category, path, certs, detail=None):
    """certs: list of dicts with subject/class (findings or plan certs)."""
    manual.append({"category": category, "path": path, "detail": detail,
                   "certs": [{"subject": c.get("subject") or c.get("detail") or "-", "class": c["class"]} for c in certs]})


def merge_manual(manual):
    """One entry per (category, path); certificates and details merged."""
    out = {}
    for m in manual:
        k = (m["category"], m["path"])
        e = out.setdefault(k, {"category": m["category"], "path": m["path"], "certs": [], "details": []})
        for c in m["certs"]:
            if c not in e["certs"]:
                e["certs"].append(c)
        if m.get("detail") and m["detail"] not in e["details"]:
            e["details"].append(m["detail"])
    order = {k: i for i, (k, _, _) in enumerate(MANUAL_CATEGORIES)}
    return sorted(out.values(), key=lambda m: (order.get(m["category"], 99), m["path"]))


def build_plan(findings, reg, cert_counts, fix_classes, flavor, keytool, certutil):
    actions, manual = [], []
    by_file, sys_certs = {}, {}
    for f in findings:
        rec, cls = f["rec"], f["rec"]["class"]
        if cls not in ACTIONABLE:
            continue
        if cls == "MTLS_PUBLIC_TRUST":
            add_manual(manual, "mtls", rec["path"], [{"subject": "%d certs in client trust" % rec.get("certs", 0),
                                                      "class": cls}], rec["via"][0])
            continue
        if cls not in fix_classes:
            hp = rec["path"] if f["key"] is None else reg.files[f["key"]]["path"]
            # if the file cannot be changed anyway, say why (snap, read-only, permission) instead of "use --fix-cross"
            why = path_context(hp) or \
                {"node-binary": ("node", None), "raw": ("binary", "store type: raw")}.get(f["store"]) or \
                write_blocker([hp], [os.path.dirname(hp)])
            add_manual(manual, why[0] if why else "cross", rec["path"], [rec], why[1] if why else None)
            continue
        by_file.setdefault(f["key"], []).append(f)

    def manual_all(fs, category, detail=None):
        add_manual(manual, category, fs[0]["rec"]["path"], [f["rec"] for f in fs], detail)

    for key, fs in by_file.items():
        e, store = reg.files[key], fs[0]["store"]
        path = e["path"]
        ctx = path_context(path)
        if ctx:
            manual_all(fs, *ctx)
            continue
        if store == "node-binary":
            manual_all(fs, "node")
            continue
        if store == "raw" or any(f["der"] is None for f in fs):
            manual_all(fs, "binary", "store type: %s" % store)
            continue
        if "chain" in e["kinds"]:
            manual_all(fs, "chain", ", ".join(v for v in e["via"] if v != "fs"))
            continue
        risky = any(f["rec"]["class"] == "CROSS_PATH" for f in fs)
        certs = {}
        for f in fs:
            c = parse_cert(f["der"])
            certs[c["sha256"]] = {"sha256": c["sha256"], "subject": c["subject"], "class": f["rec"]["class"],
                                  "alias": f["alias"], "der": f["der"]}
        if flavor and store in ("pem", "der") and managed_by(path, flavor):
            for fp, c in certs.items():
                sys_certs.setdefault(fp, dict(c, files=set()))["files"].add(path)
            continue
        base = {"path": path, "shown": e["shown"], "certs": list(certs.values()), "backup": [path], "risky": risky,
                "notes": path_notes(path), "via": e["via"]}
        if store in ("pem", "keytool", "nss") and risky and len({c["class"] == "CROSS_PATH" for c in certs.values()}) == 2 \
                and (store != "pem" or cert_counts.get(key, 0) > len(certs)):
            # mixed file: keep the risky AAA removal a separate decision from the eMudhra removal
            safe = [c for c in certs.values() if c["class"] != "CROSS_PATH"]
            cross = [c for c in certs.values() if c["class"] == "CROSS_PATH"]
            kw = {"pem": {"type": "pem-remove"}, "nss": {"type": "nss-delete", "dir": os.path.dirname(path)},
                  "keytool": {"type": "keytool-delete", "storepass": STOREPASS_USED.get(path)}}[store]
            if store == "keytool" and (not keytool or kw["storepass"] is None):
                manual_all(fs, "keystore", "keystore password unknown: re-run with --storepass")
                continue
            if store == "nss" and not certutil:
                manual_all(fs, "keystore", "certutil not found: `certutil -D -d sql:DIR -n NICK`")
                continue
            actions.append(dict(base, certs=safe, risky=False, **kw))
            actions.append(dict(base, certs=cross, risky=True, **kw))
            continue
        if store in ("pem", "der"):
            if cert_counts.get(key, 0) > len(certs) and store == "pem":
                actions.append(dict(base, type="pem-remove"))
            else:
                d = os.path.dirname(path)
                siblings = [x for x in os.listdir(d) if x.lower().endswith(CERT_FILE_EXT)] if os.path.isdir(d) else []
                if len(siblings) > 2:
                    actions.append(dict(base, type="quarantine",
                                        notes=base["notes"] + ["directory store: run `openssl rehash %s` if it is "
                                                               "used as a CApath" % d]))
                else:
                    manual_all(fs, "empty", "referenced by: %s" % ", ".join(e["via"]))
        elif store == "keytool":
            pw = STOREPASS_USED.get(path)
            if keytool and pw is not None:
                actions.append(dict(base, type="keytool-delete", storepass=pw))
            else:
                manual_all(fs, "keystore", "keystore password unknown: re-run with --storepass")
        elif store == "nss":
            if certutil:
                actions.append(dict(base, type="nss-delete", path=path, dir=os.path.dirname(path)))
            else:
                manual_all(fs, "keystore", "certutil not found: `certutil -D -d sql:DIR -n NICK`")

    # one system action per certificate, covering every managed file it appears in
    if sys_certs:
        src = index_sources([DEB_SRC, DEB_LOCAL] if flavor == "debian" else list(RH_ANCHORS))
        for fp, c in sys_certs.items():
            files = sorted(c.pop("files"))
            sources = src.get(fp, [])
            a = {"path": files[0], "certs": [c], "risky": c["class"] == "CROSS_PATH", "covers": files, "notes": [],
                 "via": [], "update": flavor}
            if flavor == "debian":
                conf_lines = [os.path.relpath(s, DEB_SRC) for s in sources if s.startswith(DEB_SRC + "/")]
                local = [s for s in sources if s.startswith(DEB_LOCAL + "/")]
                a.update(type="debian-deselect", conf_lines=conf_lines, quarantine=local,
                         backup=[DEB_CONF] + local + files,
                         notes=["persistent: package upgrades keep '!' deselections in %s" % DEB_CONF])
                if not sources:
                    a["notes"].append("no source certificate found; `update-ca-certificates --fresh` will rebuild the bundle")
            else:
                bl = os.path.join(RH_TRUST, "source", "blocklist" if os.path.isdir(os.path.join(RH_TRUST, "source", "blocklist"))
                                  else "blacklist")
                anchors = [s for s in sources if s.startswith(RH_ANCHORS[0] + "/")]
                a.update(type="rhel-blocklist", blocklist_file=os.path.join(bl, "emudhra-%s.pem" % fp[:16].lower()),
                         quarantine=anchors, backup=anchors + files,
                         notes=["persistent: p11-kit blocklist survives package upgrades"])
            actions.insert(0, a)
    # actions we could not carry out anyway (read-only filesystem, no permission) become manual items now,
    # instead of failing half-way through the apply phase
    runnable = []
    for a in actions:
        b = action_blocker(a)
        if b:
            add_manual(manual, b[0], a.get("shown", a["path"]), a["certs"], b[1])
        else:
            runnable.append(a)
    for i, a in enumerate(runnable, 1):
        a["id"] = i
    return runnable, manual


def action_steps(a):
    """What the action will do, step by step (no certificates, no header)."""
    s = []
    if a["type"] == "debian-deselect":
        s += ["%s: %s -> !%s" % (DEB_CONF, l, l) for l in a["conf_lines"]]
        s += ["remove local source %s" % q for q in a["quarantine"]]
        s += ["covers: %s" % ", ".join(a["covers"]), "then: update-ca-certificates --fresh"]
    elif a["type"] == "rhel-blocklist":
        s += ["add %s" % a["blocklist_file"]] + ["remove anchor %s" % q for q in a["quarantine"]]
        s += ["covers: %s" % ", ".join(a["covers"]), "then: update-ca-trust extract"]
    elif a["type"] == "keytool-delete":
        s.append("keytool -delete -alias %s" % ", ".join(c["alias"] or "?" for c in a["certs"]))
    elif a["type"] == "nss-delete":
        s.append("certutil -D -d sql:%s -n %s" % (a["dir"], ", ".join(c["alias"] or "?" for c in a["certs"])))
    elif a["type"] == "quarantine":
        s.append("delete the file (a copy stays in the backup)")
    if a.get("via") and a["via"] != ["fs"]:
        s.append("via: %s" % "; ".join(v for v in a["via"] if v != "fs"))
    s += ["note: %s" % n for n in a["notes"]]
    return s


def describe(a):
    lines = ["[%d] %s%s  %s" % (a["id"], a["type"], " (RISKY)" if a["risky"] else "", a.get("shown", a["path"]))]
    for c in a["certs"]:
        lines.append("     - %s  [%s] sha256 %s…%s" % (c["subject"], c["class"], c["sha256"][:16],
                                                       ("  alias=" + c["alias"]) if c.get("alias") else ""))
    lines += ["     " + x for x in action_steps(a)]
    return "\n".join(lines)


# ---------------------------------------------------------------- output

SEVERITY = ["IOC_INTERMEDIATE", "IOC_SERIAL", "ROOT_DISTRUST", "ROOT_CS", "CROSS_PATH", "MTLS_PUBLIC_TRUST",
            "UNPARSED_KEYSTORE", "EMUDHRA_OTHER", "INACTIVE_SOURCE", "BLOCKLIST_ENTRY"]
COLORS = {"red": "31", "yellow": "33", "green": "32", "dim": "2", "bold": "1", "cyan": "36"}
CLASS_COLOR = {"IOC_INTERMEDIATE": "red", "IOC_SERIAL": "red", "ROOT_DISTRUST": "red", "ROOT_CS": "red",
               "CROSS_PATH": "yellow", "MTLS_PUBLIC_TRUST": "yellow"}
STATUS_COLOR = {"fixed": "green", "already-clean": "green", "declined": "dim", "still-present": "red",
                "error": "red", "unknown": "red"}


class Report:
    """Human tables to stdout (or stderr with `-o -`), JSONL records to the -o target."""

    def __init__(self, jsonl, color):
        self.jf, self.human = None, sys.stdout
        if jsonl == "-":
            self.jf, self.human = sys.stdout, sys.stderr
        elif jsonl:
            self.jf = open(jsonl, "w", encoding="utf-8")
        self.color = color and self.human.isatty() and not os.environ.get("NO_COLOR")

    def record(self, typ, rec):
        if self.jf:
            self.jf.write(json.dumps(dict({"type": typ}, **rec), ensure_ascii=False) + "\n")
            self.jf.flush()

    def c(self, text, color):
        return "\033[%sm%s\033[0m" % (COLORS[color], text) if self.color and color else text

    def say(self, text=""):
        print(text, file=self.human, flush=True)

    def heading(self, text):
        self.say()
        self.say(self.c(text, "bold"))

    def table(self, headers, rows, caps=None, colors=None, sub=None):
        """rows: lists of str; last column is never padded or truncated. caps: max width per column.
        colors: per-row list of (column index, color). sub: per-row list of continuation lines."""
        caps = caps or [None] * len(headers)

        def fit(v, cap):
            v = str(v)
            return v if cap is None or len(v) <= cap else v[:cap - 1] + "…"

        cells = [[fit(v, caps[i]) for i, v in enumerate(r)] for r in rows]
        widths = [max([len(headers[i])] + [len(r[i]) for r in cells]) for i in range(len(headers))]
        pad = lambda vals, i: vals[i] if i == len(vals) - 1 else vals[i].ljust(widths[i])
        self.say(self.c("  ".join(pad(headers, i) for i in range(len(headers))).rstrip(), "dim"))
        indent = " " * (sum(widths[:-1]) + 2 * (len(widths) - 1))
        for n, r in enumerate(cells):
            out = []
            for i in range(len(r)):
                v = pad(r, i)
                col = dict(colors[n]).get(i) if colors else None
                out.append(self.c(v, col) if col else v)
            self.say("  ".join(out).rstrip())
            for line in (sub[n] if sub else []):
                self.say(self.c(indent + "↳ " + line, "dim"))

    def close(self):
        if self.jf and self.jf is not sys.stdout:
            self.jf.close()


def render_findings(rep, findings, quiet_other):
    shown = [f["rec"] for f in findings if not (quiet_other and f["rec"]["class"] == "EMUDHRA_OTHER")]
    order = {c: i for i, c in enumerate(SEVERITY)}
    shown.sort(key=lambda r: (order.get(r["class"], 99), r["path"], r.get("subject") or r.get("detail") or ""))

    def rows_of(recs):
        rows, colors, sub = [], [], []
        for r in recs:
            cert = r.get("subject") or r.get("detail") or ""
            if r["class"] == "MTLS_PUBLIC_TRUST":
                cert = "%d certs in client trust" % r.get("certs", 0)
            rows.append([r["class"], r.get("store", "-"), cert, r.get("alias") or "-", r["path"]])
            colors.append([(0, CLASS_COLOR.get(r["class"], "dim"))])
            extra = [v for v in r.get("via", []) if v != "fs" and not v.startswith("WARN:")]
            if r.get("would_be"):
                extra.append("%s (would be %s)" % (r["detail"], r["would_be"]))
            sub.append(extra)
        return rows, colors, sub

    act = [r for r in shown if r["class"] in ACTIONABLE]
    info = [r for r in shown if r["class"] not in ACTIONABLE]
    hdr = ["CLASS", "STORE", "CERTIFICATE", "ALIAS", "PATH"]
    caps = [None, None, 36, 28, None]
    if act:
        rep.heading("Findings requiring action (%d)" % len(act))
        rows, colors, sub = rows_of(act)
        rep.table(hdr, rows, caps, colors, sub)
    if info:
        rep.heading("Informational (%d)" % len(info))
        rows, colors, sub = rows_of(info)
        rep.table(hdr, rows, caps, colors, sub)
    if not act and not info:
        rep.heading("No affected certificates found")


def render_manual(rep, merged):
    """Grouped list: one header per category with the advice once, then a table of files."""
    files = len({m["path"] for m in merged})
    rep.heading("Manual actions (%d file(s))" % files if merged else "Manual actions: none")
    for key, title, what in MANUAL_CATEGORIES:
        items = [m for m in merged if m["category"] == key]
        if not items:
            continue
        rep.say()
        rep.say("  " + rep.c("[%s] %s (%d)" % (key, title, len(items)), "yellow"))
        rep.say("  " + rep.c("what to do: " + what, "dim"))
        rows = [[m["path"], ", ".join(dict.fromkeys(c["subject"] for c in m["certs"])),
                 "; ".join(m["details"]) or "-"] for m in items]
        w0 = max(len(r[0]) for r in rows)
        w1 = min(max(len(r[1]) for r in rows), 64)
        for r in rows:
            cert = r[1] if len(r[1]) <= 64 else r[1][:63] + "…"
            rep.say(("    %s  %s  %s" % (r[0].ljust(w0), cert.ljust(w1), rep.c(r[2], "dim"))).rstrip())


def write_manual_tsv(path, merged):
    clean = lambda v: str(v).replace("\t", " ").replace("\n", " ")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("category\tpath\tcertificates\tclasses\tdetail\twhat_to_do\n")
        for m in merged:
            fh.write("\t".join(clean(v) for v in (
                m["category"], m["path"], "; ".join(c["subject"] for c in m["certs"]),
                ",".join(sorted({c["class"] for c in m["certs"]})), "; ".join(m["details"]),
                MANUAL_INFO.get(m["category"], ("", ""))[1])) + "\n")


def render_summary(rep, summary, exit_code):
    f = summary["findings"]
    act = ["%s=%d" % (k, f[k]) for k in SEVERITY if k in f and k in ACTIONABLE]
    inf = ["%s=%d" % (k, f[k]) for k in SEVERITY if k in f and k not in ACTIONABLE]
    rep.heading("Summary")
    rows = [["host", summary["host"]], ["files scanned", str(summary["files_scanned"])],
            ["requiring action", " ".join(act) or "none"], ["informational", " ".join(inf) or "none"],
            ["keytool", summary["keytool"] or "not found (Java keystores scanned raw)"]]
    st = summary["stats"]
    if st.get("conf_ref_missing"):
        rows.append(["config refs missing", "%d (paths referenced in configs that do not exist)" % st["conf_ref_missing"]])
    if st.get("keystore_unparsed"):
        rows.append(["keystores unparsed", "%d (need keytool / --storepass)" % st["keystore_unparsed"]])
    if "manual_files" in summary:
        rows.append(["manual actions", "%d file(s)" % summary["manual_files"]])
    rows.append(["exit code", str(exit_code)])
    w = max(len(r[0]) for r in rows)
    for k, v in rows:
        rep.say("  %s  %s" % (k.ljust(w), v))


class Asker:
    def __init__(self, force):
        self.force, self.all, self.tin, self.tout = force, False, None, None
        if not force:
            try:   # separate handles: a tty is not seekable, so text mode "r+" fails on it
                self.tin, self.tout = open("/dev/tty", "r"), open("/dev/tty", "w")
            except OSError:
                raise SystemExit("--fix needs a terminal for confirmations; use --force or --dry-run")

    def ask(self, a):
        if self.force or (self.all and not a["risky"]):
            return True
        self.tout.write("\n" + describe(a) + "\nApply? [y]es / [n]o / [a]ll non-risky / [q]uit: ")
        self.tout.flush()
        while True:
            line = self.tin.readline()
            if not line:                      # EOF on the terminal: treat as quit
                raise QuitFix()
            ans = line.strip().lower()
            if ans in ("y", "yes"):
                return True
            if ans in ("n", "no", ""):
                return False
            if ans in ("a", "all"):
                self.all = True
                return True
            if ans in ("q", "quit"):
                raise QuitFix()
            self.tout.write("y/n/a/q: ")
            self.tout.flush()


def sha256_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def make_backup_dir(base, host, now):
    """Create a fresh <base>/<UTC>-<host>[-N] directory (0700). Never reuses an existing one: an existing backup
    directory is somebody's restore point."""
    base = os.path.abspath(base)
    if os.path.exists(base) and not os.path.isdir(base):
        raise OSError("backup base %s exists and is not a directory" % base)
    os.makedirs(base, mode=0o700, exist_ok=True)
    name = now.strftime("%Y%m%dT%H%M%SZ") + "-" + host
    for i in range(1000):
        d = os.path.join(base, name if i == 0 else "%s-%d" % (name, i))
        try:
            os.mkdir(d, 0o700)
        except FileExistsError:
            continue
        os.chmod(d, 0o700)
        return d
    raise OSError("cannot create a unique backup directory under %s" % base)


def do_backup(actions, manual, bdir, meta):
    with open(os.path.join(bdir, BACKUP_MARKER), "w") as fh:   # makes the scanner skip this directory
        fh.write("emudhra_scan.py backup; see manifest.json\n")
    files = {}
    for a in actions:
        for p in a["backup"]:
            if p in files or not os.path.isfile(p):
                continue
            st = os.stat(p)
            rel = os.path.join("files", p.lstrip("/"))
            dst = os.path.join(bdir, rel)
            os.makedirs(os.path.dirname(dst), mode=0o700, exist_ok=True)
            shutil.copy2(p, dst)
            if sha256_file(dst) != sha256_file(p):
                raise OSError("backup verification failed for %s" % p)
            files[p] = {"original": p, "backup": rel, "sha256": sha256_file(p), "mode": "%04o" % stat.S_IMODE(st.st_mode),
                        "uid": st.st_uid, "gid": st.st_gid, "size": st.st_size}
    meta["files"] = list(files.values())
    meta["manual"] = manual
    write_manifest(bdir, meta, actions)
    return files


def write_manifest(bdir, meta, actions):
    pub = []
    for a in actions:
        x = {k: v for k, v in a.items() if k not in ("certs", "backup", "storepass")}
        x["certs"] = [{k: c[k] for k in ("sha256", "subject", "class") if k in c} for c in a["certs"]]
        pub.append(x)
    meta["actions"] = pub
    with open(os.path.join(bdir, "manifest.json"), "w") as fh:
        json.dump(meta, fh, ensure_ascii=False, indent=2)


def write_restore(bdir, meta):
    import shlex
    q = shlex.quote
    out = ["#!/bin/sh", "# restore script generated by emudhra_scan.py --fix at %s on %s" % (meta["created"], meta["host"]),
           "# puts back every backed-up file byte for byte, removes files the fix created, re-runs the trust update",
           "set -eu", 'B=$(cd "$(dirname "$0")" && pwd)',
           'restore() { mkdir -p "$(dirname "$2")"; cp -p "$B/$1" "$2"; chown "$3" "$2"; chmod "$4" "$2"; }']
    restores = ["restore %s %s %d:%d %s" % (q(f["backup"]), q(f["original"]), f["uid"], f["gid"], f["mode"])
                for f in meta["files"]]
    out += restores
    for c in meta.get("created_files", []):
        out.append("rm -f %s" % q(c))
    updates = sorted(set(meta.get("updates_run", [])))
    for u in updates:
        out.append({"debian": "update-ca-certificates --fresh", "rhel": "update-ca-trust extract"}[u])
    if updates:
        out.append("# the update re-runs hooks (symlinks, Java keystore) and regenerates outputs with new bytes;")
        out.append("# restore once more so every file is byte-identical to the backup")
        out += restores
    out.append('echo "restored %d file(s)"' % len(meta["files"]))
    p = os.path.join(bdir, "restore.sh")
    with open(p, "w") as fh:
        fh.write("\n".join(out) + "\n")
    os.chmod(p, 0o700)


def apply_action(a, keytool, certutil, meta, log):
    """-> (status, detail). Each action re-checks the current state first (a system update may already have
    removed the certificate)."""
    fps = {c["sha256"] for c in a["certs"]}
    t = a["type"]
    if t == "debian-deselect":
        with open(DEB_CONF, "rb") as fh:
            lines = fh.read().decode("utf-8", "replace").split("\n")
        # update-ca-certificates removes '!' entries first and then adds every plain entry, so a plain line wins
        # regardless of order: turn EVERY plain occurrence into '!', and make sure one '!' line exists.
        changed = False
        for rel in a["conf_lines"]:
            hits = [i for i, l in enumerate(lines) if l.strip() == rel]
            for i in hits:
                lines[i] = "!" + rel
                changed = True
            if not hits and "!" + rel not in (l.strip() for l in lines):
                lines.insert(len(lines) - 1 if lines and lines[-1] == "" else len(lines), "!" + rel)
                changed = True
        if changed:
            atomic_write(DEB_CONF, "\n".join(lines).encode())
        for q in a["quarantine"]:
            if os.path.exists(q):
                os.unlink(q)
        return "applied", "update pending"
    if t == "rhel-blocklist":
        pem = b"-----BEGIN CERTIFICATE-----\n" + base64.encodebytes(a["certs"][0]["der"]) + b"-----END CERTIFICATE-----\n"
        os.makedirs(os.path.dirname(a["blocklist_file"]), exist_ok=True)
        with open(a["blocklist_file"], "wb") as fh:
            fh.write(pem)
        os.chmod(a["blocklist_file"], 0o644)
        meta.setdefault("created_files", []).append(a["blocklist_file"])
        for q in a["quarantine"]:
            if os.path.exists(q):
                os.unlink(q)
        return "applied", "update pending"
    if t == "pem-remove":
        with open(a["path"], "rb") as fh:
            data = fh.read()
        new, removed = remove_pem_blocks(data, fps)
        if not removed:
            return "already-clean", "certificates no longer present"
        atomic_write(a["path"], new)
        return "applied", "removed %d certificate(s)" % len(removed)
    if t == "quarantine":
        if not os.path.exists(a["path"]):
            return "already-clean", "file no longer present"
        os.unlink(a["path"])
        return "applied", "file deleted (copy in backup)"
    if t == "keytool-delete":
        pw = a["storepass"]
        present = {fp: al for fp, (al, _) in certs_in_file(a["path"], keytool, [pw]).items() if fp in fps}
        if not present:
            return "already-clean", "aliases no longer present"
        for fp, alias in present.items():
            rc, out = run_cmd([keytool, "-delete", "-noprompt", "-alias", alias, "-keystore", a["path"],
                               "-storepass", pw], log, env=JAVA_ENV)
            log[-1]["cmd"] = [x if x != pw else "***" for x in log[-1]["cmd"]]
            if rc != 0:
                return "error", "keytool -delete %s failed: %s" % (alias, out.strip()[-300:])
        return "applied", "deleted alias(es): %s" % ", ".join(present.values())
    if t == "nss-delete":
        present = {fp: al for fp, (al, _) in certs_in_file(a["path"]).items() if fp in fps}
        if not present:
            return "already-clean", "certificates no longer present"
        for fp, nick in present.items():
            rc, out = run_cmd([certutil, "-D", "-d", "sql:" + a["dir"], "-n", nick], log)
            if rc != 0:
                return "error", "certutil -D %s failed: %s" % (nick, out.strip()[-300:])
        return "applied", "deleted nickname(s): %s" % ", ".join(present.values())
    return "error", "unknown action"


def verify_action(a, keytool):
    fps = {c["sha256"] for c in a["certs"]}
    # distro sources keep the certificate on disk by design ('!' in the conf / p11-kit blocklist): check outputs only
    files = [f for f in (a.get("covers") or [a["path"]])
             if not f.startswith((DEB_SRC + "/", "/usr/share/pki/ca-trust-source/", RH_TRUST + "/source/"))]
    pw = [a["storepass"]] if a.get("storepass") else ["changeit"]
    left = []
    for f in files:
        if not os.path.exists(f):
            continue
        found = set(certs_in_file(f, keytool, pw)) & fps
        if found:
            left.append(f)
    return left


def pub_certs(x):
    return [{k: c[k] for k in ("sha256", "subject", "class")} for c in x["certs"]]


def run_fix(a, actions, manual, flavor, certutil, host, keytool, rep):
    """Plan display, backup, confirmations, apply, verify. Appends apply-time failures to `manual`.
    -> (exit code, backup dir or None)"""
    rep.heading("Fix plan: %d action(s); trust mechanism: %s%s" %
                (len(actions), flavor or "none detected", "  [dry run]" if a.dry_run else ""))
    if actions:
        rep.table(["ID", "ACTION", "RISK", "CERTIFICATES", "PATH"],
                  [[str(x["id"]), x["type"], "RISKY" if x["risky"] else "-",
                    ", ".join(c["subject"] for c in x["certs"]), x.get("shown", x["path"])] for x in actions],
                  caps=[None, None, None, 48, None],
                  colors=[[(2, "yellow")] if x["risky"] else [] for x in actions],
                  sub=[action_steps(x) for x in actions])
    else:
        rep.say("nothing to fix automatically")
    if manual:
        rep.say(rep.c("  + %d file(s) to handle manually: see 'Manual actions' below" %
                      len({m["path"] for m in manual}), "dim"))
    for x in actions:
        rep.record("plan", {"id": x["id"], "action": x["type"], "path": x["path"], "host": host, "risky": x["risky"],
                            "steps": action_steps(x), "certs": pub_certs(x)})
    if a.dry_run or not actions:
        return (1 if (actions or manual) else 0), None

    asker = Asker(a.force)          # fail before touching anything if confirmations are impossible
    import datetime
    now = datetime.datetime.now(datetime.timezone.utc)
    base = a.backup_dir or "/var/backups/emudhra-scan"
    bdir = None
    try:
        bdir = make_backup_dir(base, host, now)
        meta = {"tool": "emudhra_scan.py", "created": now.isoformat(), "host": host, "argv": sys.argv,
                "backup_dir": bdir, "trust_mechanism": flavor, "commands": [], "created_files": [], "updates_run": []}
        do_backup(actions, merge_manual(manual), bdir, meta)
        write_restore(bdir, meta)
    except (OSError, shutil.Error) as ex:
        if bdir:
            shutil.rmtree(bdir, ignore_errors=True)     # incomplete backup is useless; nothing was changed yet
        rep.heading(rep.c("Backup failed: %s" % ex, "red"))
        rep.say("  nothing was changed; fix the backup location (--backup-dir) and re-run")
        rep.record("backup", {"host": host, "backup_dir": None, "error": str(ex)})
        return 3, None
    rep.heading("Backup")
    rep.say("  %s  (%d file(s), manifest.json, restore.sh)" % (bdir, len(meta["files"])))
    rep.record("backup", {"host": host, "backup_dir": bdir, "files": meta["files"]})

    try:
        for x in actions:
            x["decision"] = "accepted" if asker.ask(x) else "declined"
    except QuitFix:
        for x in actions:
            x.setdefault("decision", "declined")
        rep.say("quit: remaining actions declined")

    log = meta["commands"]
    accepted = [x for x in actions if x["decision"] == "accepted"]
    updates = set()
    for phase in ("system", "direct"):
        if phase == "direct":
            for u in sorted(updates):
                cmd = ["update-ca-certificates", "--fresh"] if u == "debian" else ["update-ca-trust", "extract"]
                rc, out = run_cmd(cmd, log)
                meta["updates_run"].append(u)
                rep.say("  ran %s: rc=%d" % (" ".join(cmd), rc))
                if rc != 0:
                    for x in accepted:
                        if x.get("update") == u:
                            x["status"], x["detail"] = "error", "%s failed: %s" % (cmd[0], out.strip()[-300:])
        for x in accepted:
            if (phase == "system") != bool(x.get("update")):
                continue
            try:
                st, det = apply_action(x, keytool, certutil, meta, log)
            except Exception as ex:
                st, det = "error", "%s: %s" % (type(ex).__name__, ex)
                x["errno"] = getattr(ex, "errno", None)
            x["status"], x["detail"] = st, det
            if x.get("update") and st == "applied":
                updates.add(x["update"])
        write_manifest(bdir, meta, actions)
        write_restore(bdir, meta)

    # verify
    for x in accepted:
        if x.get("status") == "error":
            continue
        left = verify_action(x, keytool)
        if left:
            x["status"], x["detail"] = "still-present", "still in: %s" % ", ".join(left)
        elif x["status"] == "applied":
            x["status"] = "fixed"
            if x.get("detail") == "update pending":
                x["detail"] = "conf/blocklist changed; trust update ran; verified absent"
    import errno as _errno
    for x in actions:
        x.setdefault("status", "declined" if x["decision"] == "declined" else "unknown")
        rep.record("fix", {"id": x["id"], "action": x["type"], "path": x["path"], "status": x["status"],
                           "detail": x.get("detail"), "host": host, "backup_dir": bdir, "certs": pub_certs(x)})
        if x["status"] in ("error", "still-present"):
            cat = {_errno.EROFS: "readonly", _errno.EACCES: "permission", _errno.EPERM: "permission"}.get(
                x.get("errno"), "apply-error")
            add_manual(manual, cat, x.get("shown", x["path"]), x["certs"], x.get("detail"))
    meta["manual"] = merge_manual(manual)
    write_manifest(bdir, meta, actions)
    write_restore(bdir, meta)
    st = Counter(x["status"] for x in actions)
    rep.heading("Fix results: %s" % ", ".join("%s=%d" % kv for kv in sorted(st.items())))
    rep.table(["ID", "ACTION", "STATUS", "PATH"],
              [[str(x["id"]), x["type"], x["status"], x.get("shown", x["path"])] for x in actions],
              colors=[[(2, STATUS_COLOR.get(x["status"]))] for x in actions],
              sub=[[x["detail"]] if x.get("detail") else [] for x in actions])
    rep.say("\n  restore: sh %s" % os.path.join(bdir, "restore.sh"))
    if st.get("error"):
        return 3, bdir
    if manual or st.get("still-present") or st.get("declined"):
        return 1, bdir
    return 0, bdir


# ---------------------------------------------------------------- main

class Registry:
    """Deduplicate files by (dev, inode); keep every reason a file is in scope."""

    def __init__(self):
        self.files = {}

    def add(self, host_path, via, shown=None, name_hint=None, kind=None):
        try:
            st = os.stat(host_path)
        except OSError:
            return None
        if stat.S_ISDIR(st.st_mode):
            n = 0
            for f in sorted(os.listdir(host_path)):
                p = os.path.join(host_path, f)
                if os.path.isfile(p):
                    self.add(p, via, (shown.rstrip("/") + "/" + f) if shown else None, kind=kind)
                    n += 1
            return n
        if not stat.S_ISREG(st.st_mode) or st.st_size == 0 or st.st_size > MAX_SIZE:
            return None
        key = (st.st_dev, st.st_ino)
        e = self.files.setdefault(key, {"path": host_path, "shown": shown or host_path, "via": [],
                                        "name_hint": name_hint, "kinds": set()})
        if via not in e["via"]:
            e["via"].append(via)
        e["kinds"].add(kind or ("proc" if via.startswith("proc:") else "fs"))
        return key


def main():
    ap = argparse.ArgumentParser(description="eMudhra/emSign trust store scanner")
    ap.add_argument("--root", default="/")
    ap.add_argument("--scan-binaries", action="store_true", help="also scan executables/.so for embedded stores")
    ap.add_argument("--xdev", action="store_true", help="do not cross filesystem boundaries in the fs walk")
    ap.add_argument("--no-fs", action="store_true", help="skip the fs walk; only config and process references")
    ap.add_argument("--no-proc", action="store_true", help="skip running processes")
    ap.add_argument("--keytool", default=shutil.which("keytool"), help="host keytool (never taken from --root)")
    ap.add_argument("--storepass", action="append", default=None, help="keystore password(s) to try; default changeit")
    ap.add_argument("--quiet-other", action="store_true", help="suppress EMUDHRA_OTHER")
    ap.add_argument("-o", "--output", metavar="FILE",
                    help="write JSON Lines to FILE ('-' = stdout; the human report then goes to stderr)")
    ap.add_argument("--no-color", action="store_true", help="no ANSI colors (also honours NO_COLOR)")
    fx = ap.add_argument_group("fix (live system only, --root /)")
    fx.add_argument("--fix", action="store_true", help="back up affected stores, then offer fixes one by one")
    fx.add_argument("--force", action="store_true", help="with --fix: apply every automatic fix without asking")
    fx.add_argument("--dry-run", action="store_true", help="with --fix: print the plan only; no backup, no changes")
    fx.add_argument("--fix-cross", action="store_true", help="with --fix: also remove AAA Certificate Services (risky)")
    fx.add_argument("--manual-list", metavar="FILE",
                    help="write the 'Manual actions' list as TSV to FILE (works with or without --fix; with --fix it "
                         "is also saved as manual-actions.tsv in the backup directory)")
    fx.add_argument("--backup-dir", metavar="BASE",
                    help="base directory for backups; every run creates a new BASE/<UTC>-<host> inside it "
                         "(default BASE: /var/backups/emudhra-scan)")
    a = ap.parse_args()
    if (a.force or a.dry_run or a.fix_cross or a.backup_dir) and not a.fix:
        ap.error("--force/--dry-run/--fix-cross/--backup-dir require --fix")
    if (a.fix or a.manual_list) and os.path.abspath(a.root) != "/":
        ap.error("--fix/--manual-list work on the live system only (--root /); for images fix the Dockerfile and rebuild")
    if a.fix and not a.dry_run and os.geteuid() != 0:
        print("warning: not running as root; most system stores will not be writable", file=sys.stderr)
    root = os.path.abspath(a.root)
    passwords = a.storepass or ["changeit"]
    host = socket.gethostname()
    try:
        rep = Report(a.output, not a.no_color)
    except OSError as ex:
        ap.error("cannot open --output: %s" % ex)
    reg, stats, classes, findings = Registry(), Counter(), Counter(), []
    progress_on = sys.stderr.isatty() and rep.human is not sys.stderr

    def progress(text):
        if progress_on:
            sys.stderr.write("\r\033[K" + text)
            sys.stderr.flush()

    def emit(rec, key=None, der=None, alias=None, store=None):
        rec["host"] = host
        if root != "/":
            rec["root"] = root
        findings.append({"rec": rec, "key": key, "der": der, "alias": alias, "store": store})
        if a.quiet_other and rec["class"] == "EMUDHRA_OTHER":
            return
        classes[rec["class"]] += 1
        rep.record("finding", rec)

    # 1. fs walk
    if not a.no_fs:
        for n, p in enumerate(walk(root, a.scan_binaries, a.xdev), 1):
            reg.add(p, "fs", display(root, p))
            if n % 200 == 0:
                progress("walking filesystem: %d candidate files" % n)

    # 2. config references
    conf_refs = collect_conf_refs(root)
    mtls_checks = []
    for r in conf_refs:
        hp = resolve_in_root(root, r["target"])
        via = "%s:%s:%d %s" % (r["family"], r["conf"], r["line"], r["directive"])
        if hp is None:
            stats["conf_ref_missing"] += 1
            continue
        reg.add(hp, via, r["target"], kind=r["kind"])
        if r["kind"] == "client_trust" and r["mtls_on"]:
            mtls_checks.append((r, hp, via))

    # 3. running processes
    if root == "/" and not a.no_proc:
        for r in collect_proc_refs():
            hp = r["target"] if r["root"] is None else resolve_in_root(r["root"], r["target"])
            if hp is None:
                if not r.get("optional"):
                    stats["proc_ref_missing"] += 1
                continue
            shown = r["target"] if r["root"] is None else r["root"] + r["target"]
            reg.add(hp, r["via"], shown, r.get("name_hint"))

    # 4. scan every registered file once
    cert_counts = {}
    deb_sel = debian_selected(root)
    total = len(reg.files)
    for n, (key, e) in enumerate(reg.files.items(), 1):
        if n % 25 == 0 or n == total:
            progress("scanning stores: %d/%d" % (n, total))
        try:
            with open(e["path"], "rb") as fh:
                data = fh.read()
        except OSError:
            stats["unreadable"] += 1
            continue
        if e["name_hint"] == "node":          # /proc/PID/exe of a node process
            store, certs = "node-binary", [(d, None) for d in pem_ders(data)]
        else:
            store, certs = read_store(e["path"], data, a.keytool, passwords)
        looks_keystore = data[:4] in (b"\xfe\xed\xfe\xed", b"\xce\xce\xce\xce") or data[:1] == b"\x30"  # JKS/JCEKS/PKCS12
        if store == "raw" and looks_keystore and (KEYSTORE_NAME.search(os.path.basename(e["path"]))
                                                  or any(v.startswith("java:") for v in e["via"])):
            stats["keystore_unparsed"] += 1
            e["via"].append("WARN: keystore not parsed; password-protected PKCS12 needs keytool and --storepass")
        stats["store:" + store] += 1
        base = {"path": e["shown"], "store": store, "via": e["via"]}
        parsed = 0
        for der, alias in certs:
            c = parse_cert(der)
            if not c:
                continue
            parsed += 1
            override = informational_override(e["shown"], deb_sel)
            for cls, detail in classify(c):
                rec = dict(base, **{"class": cls, "detail": detail, "subject": c["subject"],
                                    "issuer": c["issuer"], "sha256": c["sha256"], "serial": c["serial"]})
                if override and cls in ACTIONABLE:
                    rec.update({"class": override[0], "detail": override[1], "would_be": cls})
                if alias:
                    rec["alias"] = alias
                emit(rec, key, der, alias, store)
        cert_counts[key] = parsed
        if not certs:
            for cls, detail in raw_hits(data):
                emit(dict(base, **{"class": cls, "detail": detail, "layer": "raw"}), key, None, None, store)
            if stats["keystore_unparsed"] and e["via"][-1].startswith("WARN:"):
                emit(dict(base, **{"class": "UNPARSED_KEYSTORE",
                                   "detail": "not parsed: run with keytool and the right --storepass"}))

    # 5. mTLS against a public bundle
    for r, hp, via in mtls_checks:
        files = [hp] if os.path.isfile(hp) else \
            [os.path.join(hp, f) for f in os.listdir(hp) if os.path.isfile(os.path.join(hp, f))] if os.path.isdir(hp) else []
        n = 0
        for f in files:
            try:
                st = os.stat(f)
            except OSError:
                continue
            n += cert_counts.get((st.st_dev, st.st_ino), 0)
        public_name = os.path.basename(os.path.realpath(hp)) in PUBLIC_BUNDLE_NAMES
        if n >= PUBLIC_BUNDLE_MIN or public_name:
            emit({"class": "MTLS_PUBLIC_TRUST", "path": r["target"], "via": [via], "certs": n,
                  "detail": "client certificates verified against a public CA bundle"})

    progress("")
    if progress_on:
        sys.stderr.write("\r\033[K")
    summary = {"host": host, "root": root, "files_scanned": len(reg.files), "findings": dict(classes),
               "stats": dict(stats), "keytool": a.keytool or None}
    rep.say(rep.c("emudhra_scan", "bold") + "  host=%s  root=%s  files scanned=%d" % (host, root, len(reg.files)))
    render_findings(rep, findings, a.quiet_other)
    code = 1 if any(c in ACTIONABLE for c in classes) else 0
    if a.fix or a.manual_list:
        flavor, certutil = system_flavor(), shutil.which("certutil")
        fix_classes = FIX_DEFAULT | ({"CROSS_PATH"} if a.fix_cross else set())
        actions, manual = build_plan(findings, reg, cert_counts, fix_classes, flavor, a.keytool, certutil)
        bdir = None
        if a.fix:
            try:
                code, bdir = run_fix(a, actions, manual, flavor, certutil, host, a.keytool, rep)
            except SystemExit as ex:          # e.g. no terminal for confirmations: report it, keep the JSONL valid
                rep.say()
                rep.say(rep.c(str(ex.code), "red"))
                code = 2
        merged = merge_manual(manual)
        render_manual(rep, merged)
        for m in merged:
            rep.record("manual", dict(m, host=host, what_to_do=MANUAL_INFO.get(m["category"], ("", ""))[1]))
        for target in [a.manual_list, os.path.join(bdir, "manual-actions.tsv") if bdir else None]:
            if not target:
                continue
            try:
                write_manual_tsv(target, merged)
                rep.say(rep.c("  manual list saved: %s" % os.path.abspath(target), "dim"))
            except OSError as ex:
                rep.say(rep.c("  cannot write manual list %s: %s" % (target, ex), "red"))
        summary["manual_files"] = len({m["path"] for m in merged})
    summary["exit_code"] = code
    render_summary(rep, summary, code)
    rep.record("summary", summary)
    rep.close()
    sys.exit(code)


if __name__ == "__main__":
    main()
