# requires: requests cryptography aiohttp
# meta developer: @samsepi0l_ovf
# authors: @goy_ai
# Description: GoySecurity — продвинутый антивирусный сканер модулей, файлов и архивов с поддержкой Gemini AI.
# meta banner: https://raw.githubusercontent.com/sepiol026-wq/goypulse/main/banner.png

from __future__ import annotations

import ast
import asyncio
import base64
import binascii
import bz2
import gzip
import hashlib
import html
import io
import json
import lzma
import logging
import re
import tarfile
import time
import zipfile
from dataclasses import dataclass
from typing import Any, Dict, List, Sequence, Tuple, Optional

import aiohttp
import requests

from .. import loader, utils

log = logging.getLogger(__name__)

CODE_EXTS = (
    ".py", ".pyw", ".txt", ".md", ".json", ".cfg", ".ini", ".yml", ".yaml",
    ".toml", ".log", ".js", ".ts", ".sh", ".bat", ".ps1", ".env", ".pyc"
)

URL_RE = re.compile(r"https?://[^\s\'\"<>()]+", re.I)
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
B64_RE = re.compile(r"^[A-Za-z0-9+/=]+$")

SUS_DOMAINS = (
    "webhook", "pastebin", "discord.com/api/webhooks", "discordapp.com/api/webhooks", 
    "api.telegram.org/bot", "ngrok", "localtunnel", "requestbin", "hookbin", 
    "transfer.sh", "file.io", "anonfiles", "gofile", "0x0.st", "paste.ee", 
    "ghostbin", "catbox.moe", "t.me", "telegram.me", "rentry.co", "rentry.org", 
    "telegra.ph", "hastebin.com", "dpaste.com", "controlc.com", "iplogger.org", 
    "grabify.link", "api.ipify.org", "ident.me", "myexternalip.com", "ifconfig.me"
)

IMPORT_RISK = {
    "ctypes": ("warning", "Низкоуровневый доступ к ОС", 10, "sys"),
    "subprocess": ("warning", "Запуск внешних процессов", 10, "exec"),
    "pickle": ("warning", "Десериализация", 15, "deserialize"),
    "marshal": ("warning", "Десериализация", 15, "deserialize"),
    "socket": ("info", "Сеть", 0, "net"),
    "smtplib": ("warning", "Исходящая почта", 10, "exfil"),
    "paramiko": ("info", "SSH", 0, "exec"),
    "multiprocessing": ("info", "Процессы", 0, "process"),
    "sqlite3": ("info", "SQLite", 0, "storage"),
    "telethon.sessions": ("info", "Сессии Telegram", 0, "session"),
    "pyrogram.session": ("info", "Сессии Pyrogram", 0, "session"),
    "keyring": ("warning", "Секреты ОС", 14, "session"),
    "winreg": ("warning", "Реестр Windows", 20, "sys"),
}

CALL_RISK = {
    "eval": ("critical", "Динамическое выполнение кода", 50, "exec"),
    "exec": ("critical", "Динамическое выполнение кода", 50, "exec"),
    "compile": ("warning", "Генерация кода", 10, "exec"),
    "__import__": ("warning", "Динамический импорт", 10, "sandbox"),
    "getattr": ("info", "Доступ к атрибутам", 0, "sandbox"),
}

ATTR_RISK = {
    "os.system": ("critical", "Вызов shell", 50, "exec"),
    "os.popen": ("critical", "Вызов shell", 50, "exec"),
    "subprocess.Popen": ("warning", "Запуск процесса", 20, "exec"),
    "subprocess.run": ("info", "Запуск процесса", 0, "exec"),
    "asyncio.create_subprocess_shell": ("critical", "Shell-процесс", 50, "exec"),
    "pickle.loads": ("critical", "Опасная десериализация", 40, "deserialize"),
    "marshal.loads": ("critical", "Опасная десериализация", 40, "deserialize"),
    "ctypes.cdll.LoadLibrary": ("warning", "Нативная библиотека", 30, "sys"),
    "shutil.rmtree": ("warning", "Удаление дерева", 15, "storage"),
    "requests.post": ("info", "HTTP-отправка", 0, "net"),
    "urllib.request.urlopen": ("info", "HTTP-запрос", 0, "net"),
    "telethon.sessions.StringSession.save": ("warning", "Сохранение string session", 20, "session"),
    "pyrogram.Client.export_session_string": ("warning", "Pyrogram string session", 20, "session"),
    "os.environ.get": ("info", "Доступ к ENV", 0, "sys"),
}

STR_PAT = [
    (re.compile(r"(?i)\b(?:auth[_-]?key|session[_-]?string|api[_-]?hash|bot[_-]?token)\b"), "session", "Сессионный секрет", 15),
    (re.compile(r"(?i)\b(?:discord\s*token|token\s*grab|stealer|rat|keylogger|clipper|spyware|malware)\b"), "stealer", "Stealer-паттерн", 45),
    (re.compile(r"(?i)\b(?:webhook|pastebin|discord\.com/api/webhooks|api\.telegram\.org/bot|ngrok|localtunnel|webhook\.site)\b"), "exfil", "Канал вывода данных", 25),
    (re.compile(r"(?i)\b(?:powershell|cmd\.exe|/bin/sh|/bin/bash|nc\s+-e|/dev/tcp/|subprocess\.run|os\.system|pty\.spawn)\b"), "exec", "Shell-паттерн", 35),
    (re.compile(r"(?i)\b(?:anti[-_ ]?debug|anti[-_ ]?vm|is_debugger_present|check_sandbox|ptrace|sysctl|hw\.model|vmware|vbox|qemu)\b"), "sandbox", "Антианализ", 35),
    (re.compile(r"(?i)\b(?:tdata|D877F783D5D3EF8C|A7F324|key4\.db|logins\.json|cookies\.sqlite|history\.sqlite)\b"), "stealer", "Браузерные/TG данные", 40),
    (re.compile(r"(?i)\b(?:exodus|metamask|phantom|tronlink|atomicwallet|guarda|coinomi|trustwallet)\b"), "stealer", "Крипто-кошелек", 45),
]

PATH_PAT = [
    (re.compile(r"(?i)(?:/etc/passwd|/etc/shadow|/proc/self/environ|login data|web data|local state|cookies|wallet\.dat)"), "stealer", "Путь к секретам", 30),
    (re.compile(r"(?i)(?:Telegram[\\/]tdata|tdata[\\/]D877|AppData[\\/]Roaming[\\/]Telegram|Local[\\/]Google[\\/]Chrome|Local Storage[\\/]leveldb)"), "stealer", "Путь к данным приложения", 40),
    (re.compile(r"(?i)(?:\.config/autostart|\.bashrc|\.profile|/etc/systemd/system|crontab)"), "persistence", "Механизм автозагрузки", 30),
]

OBF_PAT = [
    (re.compile(r"(?i)\b(?:eval\(|exec\(|globals\(\)\[|locals\(\)\[|__import__\()"), 20),
    (re.compile(r"(?i)\b(?:marshal\.loads|zlib\.decompress|base64\.b64decode|binascii\.unhexlify|lzma\.decompress|getattr\(.*?['\"]__builtins__['\"])\b"), 25),
    (re.compile(r"(?i)\b(?:getattr|setattr|hasattr)\b.*\b(?:__builtins__|__dict__|__subclasses__|__class__|__mro__)\b"), 35),
]

RISK_STRONG = {"session", "exfil", "stealer", "spy", "clipper", "ransom", "loader", "trojan", "browser", "secret", "persistence", "crypto"}
RISK_WEAK = {"process", "net", "storage", "runtime", "crypto", "decode", "import", "sandbox"}

@dataclass
class Finding:
    sev: str
    title: str
    detail: str
    source: str
    line: int
    col: int
    conf: int
    family: str
    score: int

    def as_dict(self) -> Dict[str, Any]:
        return {
            "sev": self.sev, "title": self.title, "detail": self.detail, "source": self.source,
            "line": self.line, "col": self.col, "conf": self.conf, "family": self.family,
            "score": self.score,
        }

class SourceUnit:
    def __init__(self, name: str, text: str):
        self.name = name
        self.text = text or ""
        self.lines = self.text.splitlines() or [""]

class Analyzer:
    def __init__(self, depth: int = 5, mode: str = "strict", max_files: int = 40):
        self.depth = depth
        self.mode = mode
        self.max_files = max_files
        self.hits: List[Finding] = []
        self.parts: List[Tuple[str, str]] = []
        self.mode_chain: List[str] = []
        self.decoded: str = ""
        self.fp: str = ""

    def scan(self, parts: Sequence[Tuple[str, str]]) -> Dict[str, Any]:
        self.parts = list(parts)
        self.mode_chain = []
        self.hits = []
        self._ingest(parts)
        self._synergy()
        return self._render()

    def _ingest(self, parts: Sequence[Tuple[str, str]]) -> None:
        texts = []
        for name, raw in parts:
            txt = self._decode_candidate(name, raw)
            texts.append(f"# FILE: {name}\n{txt}")
        
        self.decoded = "\n\n".join(texts).strip()
        self.fp = hashlib.sha256(self.decoded.encode("utf-8", "ignore")).hexdigest()[:16]
        
        self._scan_text(self.decoded, "bundle")
        for name, raw in parts:
            txt = self._decode_candidate(name, raw)
            self._scan_single(name, txt)

    def _decode_candidate(self, name: str, raw: Any) -> str:
        if isinstance(raw, str):
            text = raw
        elif isinstance(raw, bytes):
            text = self._maybe_decode(name, raw)
        else:
            text = str(raw)
            
        text = text.replace("\r\n", "\n").replace("\r", "\n")
        current = text
        methods = []
        
        for _ in range(max(1, self.depth)):
            nxt, method_name = self._try_decode_layer(current)
            if not method_name or nxt == current:
                break
            methods.append(method_name)
            current = nxt
            
        self.mode_chain = methods if methods else ["Исходный код (Plaintext)"]
        return current

    def _maybe_decode(self, name: str, data: bytes) -> str:
        for enc in ("utf-8", "utf-8-sig", "cp1251", "latin-1"):
            try: return data.decode(enc)
            except: pass
        for fn in (gzip.decompress, bz2.decompress, lzma.decompress):
            try:
                data = fn(data)
                break
            except: pass
        return data.decode("utf-8", "ignore")

    def _entropy(self, data: str) -> float:
        if not data: return 0.0
        occ = {}
        for c in data: occ[c] = occ.get(c, 0) + 1
        import math
        ent = 0.0
        for count in occ.values():
            p = count / len(data)
            ent -= p * math.log2(p)
        return ent

    def _try_decode_layer(self, text: str) -> Tuple[str, str]:
        s = text.strip()
        if not s: return text, ""
        plain = s.replace("\n", "").replace(" ", "")
        if len(plain) > 60 and B64_RE.fullmatch(plain) and len(plain) % 4 == 0:
            try: return base64.b64decode(plain, validate=False).decode("utf-8", "ignore"), "Base64"
            except: pass
        if len(plain) > 80 and HEX_RE.fullmatch(plain):
            try: return binascii.unhexlify(plain).decode("utf-8", "ignore"), "Hex"
            except: pass
        for fn, m_name in ((gzip.decompress, "Gzip"), (bz2.decompress, "Bzip2"), (lzma.decompress, "Lzma")):
            try: return fn(s.encode("utf-8", "ignore")).decode("utf-8", "ignore"), m_name
            except: pass
        return text, ""

    def _scan_single(self, name: str, text: str) -> None:
        src = SourceUnit(name, text)
        self._scan_text(text, name)
        self._scan_ast(src)

    def _scan_text(self, text: str, source: str) -> None:
        if not text: return
        for rx, family, title, score in STR_PAT:
            for m in rx.finditer(text):
                sev = "warning" if score < 30 else "critical"
                self._add(sev, title, self._excerpt(text, m.start(), m.end()), source, self._pos(text, m.start()), score, family)
        for rx, family, title, score in PATH_PAT:
            for m in rx.finditer(text):
                sev = "warning" if score < 30 else "critical"
                self._add(sev, title, self._excerpt(text, m.start(), m.end()), source, self._pos(text, m.start()), score, family)
        for rx, score in OBF_PAT:
            for m in rx.finditer(text):
                sev = "warning" if score < 20 else "critical"
                self._add(sev, "Обфускация/Декодер", self._excerpt(text, m.start(), m.end()), source, self._pos(text, m.start()), score, "obf")
        for m in URL_RE.finditer(text):
            url = m.group(0)
            fam = "exfil" if any(d in url.lower() for d in SUS_DOMAINS) else "net"
            score = 35 if fam == "exfil" else 0
            if score > 0:
                sev = "critical" if fam == "exfil" else "warning"
                self._add(sev, "Подозрительный URL", url, source, self._pos(text, m.start()), score, fam)
        
        for m in re.finditer(r'["\']([A-Za-z0-9+/]{40,})["\']', text):
            token = m.group(1)
            ent = self._entropy(token)
            if ent > 4.5:
                self._add("warning", "Энтропия данных", f"Слишком высокая энтропия ({ent:.2f})", source, self._pos(text, m.start()), 20, "obf")

    def _scan_ast(self, src: SourceUnit) -> None:
        try:
            tree = ast.parse(src.text)
        except Exception:
            return
        visitor = _ASTVisitor(src, self)
        visitor.visit(tree)

    def _add(self, sev: str, title: str, detail: str, source: str, pos: Tuple[int, int], conf: int, family: str) -> None:
        if conf <= 0:
            return
        line, col = pos
        self.hits.append(Finding(sev, title, detail, source, line, col, conf, family, conf))

    def _pos(self, text: str, idx: int) -> Tuple[int, int]:
        pre = text[:idx]
        return pre.count("\n") + 1, len(pre.rsplit("\n", 1)[-1]) + 1

    def _excerpt(self, text: str, start: int, end: int, pad: int = 40) -> str:
        a = max(0, start - pad)
        b = min(len(text), end + pad)
        return text[a:b].replace("\n", " ").strip()

    def _family_rank(self) -> List[Tuple[str, int, int]]:
        fam: Dict[str, int] = {}
        conf: Dict[str, int] = {}
        for h in self.hits:
            fam[h.family] = fam.get(h.family, 0) + h.score
            conf[h.family] = max(conf.get(h.family, 0), h.conf)
            
        ranked = [(k, fam[k], conf.get(k, 0)) for k in fam]
        return sorted(ranked, key=lambda x: (-x[1], -x[2], x[0]))

    def _synergy(self) -> None:
        fams = {h.family for h in self.hits}
        crit_count = sum(1 for h in self.hits if h.sev == "critical")
        if "session" in fams and "exfil" in fams:
            self._add("critical", "Synergy: Кража сессии", "Сессионные признаки + вывод наружу", "bundle", (1, 1), 75, "stealer")
        if ("stealer" in fams or "crypto" in fams) and "exfil" in fams:
            self._add("critical", "Synergy: Stealer-активность", "Сбор данных + эксфильтрация", "bundle", (1, 1), 90, "stealer")
        if "sandbox" in fams and "exec" in fams and "obf" in fams:
            self._add("critical", "Synergy: Малварь", "Антианализ + обфускация + исполнение", "bundle", (1, 1), 95, "loader")
        if "persistence" in fams and ("net" in fams or "exec" in fams):
            self._add("critical", "Synergy: Бэкдор/Троян", "Автозагрузка + удаленный доступ", "bundle", (1, 1), 80, "trojan")
        if crit_count >= 3:
            self._add("critical", "Множественные угрозы", f"Найдено {crit_count} критических маркеров", "bundle", (1, 1), 65, "general")

    def _risk(self, s: int) -> str:
        if s >= 150: return "critical"
        if s >= 70: return "high"
        if s >= 30: return "medium"
        if s > 0: return "low"
        return "clean"

    def _render(self) -> Dict[str, Any]:
        fam = {}
        for h in self.hits:
            fam[h.family] = fam.get(h.family, 0) + 1
            
        score = sum(h.score for h in self.hits)
        ranked = self._family_rank()
        
        main_family = "clean"
        main_conf = 100
        
        if ranked:
            main_family = ranked[0][0]
            main_conf = ranked[0][2]
            
        if main_family in RISK_WEAK and not any(f in RISK_STRONG for f, _, _ in ranked):
            main_family = "capability-only"
            main_conf = max(10, main_conf)
            
        return {
            "decoded": self.decoded,
            "mode": self.mode_chain,
            "score": score,
            "risk": self._risk(score),
            "family": main_family,
            "family_conf": main_conf,
            "families": ranked,
            "critical": [h.as_dict() for h in self.hits if h.sev == "critical"],
            "warning": [h.as_dict() for h in self.hits if h.sev == "warning"],
            "info": [h.as_dict() for h in self.hits if h.sev == "info"],
            "total": len(self.hits),
            "fp": self.fp,
            "parts": len(self.parts),
            "capabilities": fam,
        }

class _ASTVisitor(ast.NodeVisitor):
    def __init__(self, src: SourceUnit, av: Analyzer):
        self.src = src
        self.av = av
        self.imports: Dict[str, str] = {}
        self.vars: Dict[str, str] = {}

    def _eval_binop_str(self, node: ast.BinOp) -> Optional[str]:
        if isinstance(node.op, ast.Add):
            left = self._eval_node_str(node.left)
            right = self._eval_node_str(node.right)
            if left and right:
                return left + right
        return None

    def _eval_node_str(self, node: ast.AST) -> Optional[str]:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        if isinstance(node, ast.BinOp):
            return self._eval_binop_str(node)
        return None

    def visit_Assign(self, node: ast.Assign):
        taint = None
        if isinstance(node.value, ast.Call):
            q = self._call_name(node.value)
            res = self._resolve(q)
            if "StringSession" in res or "export_session_string" in res:
                taint = "session_data"
            elif "environ" in res or "getenv" in res:
                taint = "env_data"
            elif "open" in res or "read" in res:
                taint = "file_data"
        elif isinstance(node.value, ast.Attribute):
            q = self._attr_name(node.value)
            if "environ" in q:
                taint = "env_data"
        
        if taint:
            for tgt in node.targets:
                if isinstance(tgt, ast.Name):
                    self.vars[tgt.id] = taint
                elif isinstance(tgt, ast.Tuple):
                    for elt in tgt.elts:
                        if isinstance(elt, ast.Name):
                            self.vars[elt.id] = taint
                            
        self.generic_visit(node)

    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            base = alias.name.split(".")[0]
            q = alias.asname or base
            self.imports[q] = alias.name
            self._check_module(alias.name, node.lineno, node.col_offset)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        mod = node.module or ""
        self._check_module(mod, node.lineno, node.col_offset)
        for alias in node.names:
            q = alias.asname or alias.name
            if mod:
                self.imports[q] = f"{mod}.{alias.name}"
            else:
                self.imports[q] = alias.name
            self._check_module(self.imports[q], node.lineno, node.col_offset)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        q = self._call_name(node.func)
        
        if q == "__import__":
            if node.args:
                arg_str = self._eval_node_str(node.args[0])
                if arg_str:
                    q = f"__import__({arg_str})"

        if q:
            q = self._resolve(q)
            self._check_call(q, node.lineno, node.col_offset)

            for arg in node.args:
                arg_name = None
                if isinstance(arg, ast.Name):
                    arg_name = arg.id
                elif isinstance(arg, ast.Call) and isinstance(arg.func, ast.Name):
                    arg_name = arg.func.id
                
                if arg_name and arg_name in self.vars:
                    vtype = self.vars[arg_name]
                    target_funcs = ("post", "send", "request", "upload", "write")
                    if vtype in ("session_data", "env_data", "file_data") and any(x in q.lower() for x in target_funcs):
                        msg = f"Переменная '{arg_name}' передана в '{q}'"
                        self.av._add("critical", "Утечка данных", msg, self.src.name, (node.lineno, node.col_offset), 100, "stealer")

        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute):
        q = self._attr_name(node)
        if q:
            q = self._resolve(q)
            self._check_attr(q, node.lineno, node.col_offset)
        self.generic_visit(node)

    def _resolve(self, q: str) -> str:
        root = q.split(".", 1)[0]
        if root in self.imports:
            return q.replace(root, self.imports[root], 1)
        return q

    def _call_name(self, n: ast.AST) -> str:
        if isinstance(n, ast.Name):
            return n.id
        if isinstance(n, ast.Attribute):
            return self._attr_name(n)
        return ""

    def _attr_name(self, n: ast.AST) -> str:
        parts = []
        cur = n
        while isinstance(cur, ast.Attribute):
            parts.append(cur.attr)
            cur = cur.value
            
        if isinstance(cur, ast.Name):
            parts.append(cur.id)
        elif isinstance(cur, ast.Call):
            parts.append(self._call_name(cur.func))
        else:
            return ""
            
        parts.reverse()
        return ".".join(parts)

    def _check_module(self, name: str, line: int, col: int) -> None:
        base = name.split(".")[0]
        if name in IMPORT_RISK:
            s, t, sc, f = IMPORT_RISK[name]
            self.av._add(s, t, name, self.src.name, (line, col), sc, f)
        elif base in IMPORT_RISK:
            s, t, sc, f = IMPORT_RISK[base]
            self.av._add(s, t, name, self.src.name, (line, col), sc, f)

    def _check_call(self, q: str, line: int, col: int) -> None:
        if q in CALL_RISK:
            s, t, sc, f = CALL_RISK[q]
            self.av._add(s, t, q, self.src.name, (line, col), sc, f)

    def _check_attr(self, q: str, line: int, col: int) -> None:
        if q in ATTR_RISK:
            s, t, sc, f = ATTR_RISK[q]
            self.av._add(s, t, q, self.src.name, (line, col), sc, f)

@loader.tds
class GoySecurity(loader.Module):
    """
    🛡 Продвинутый антивирусный сканер модулей с поддержкой Gemini AI.
    
    Для работы нейросети укажите токен в конфиге (gemini_token).
    Вы также можете указать нужную модель в конфиге (gemini_model), например: gemini-3-flash-preview.
    
    by @samsepi0l_ovf / @goy_ai
    """
    strings = {
        "name": "GoySecurity",
        "loading": "<b>🛡 GoySecurity Sandbox</b>",
        "stage_fetch": "📥 <code>Сбор данных...</code>",
        "stage_extract": "📦 <code>Анализ структуры...</code>",
        "stage_decode": "🧬 <code>Снятие защиты...</code>",
        "stage_parse": "🧠 <code>Когнитивный разбор...</code>",
        "stage_rules": "⚔️ <code>Сигнатурный поиск...</code>",
        "stage_ai": "🤖 <code>Мнение ИИ (Gemini)...</code>",
        "no_code": "⚠️ Код не найден. Убедитесь, что вы ответили на файл .py или прислали ссылку.",
        "header": "<b>🛡️ GoySecurity by Goy(@samsepi0l_ovf)</b>\n",
        "summary": (
            "<b>⚖️ Вердикт:</b> {verdict}\n"
            "<b>🦠 Семейство:</b> <code>{family}</code> (Уверенность: <code>{family_conf}%</code>)\n"
            "<b>⚠️ Опасность:</b> <code>{score} баллов</code> | <b>Флагов:</b> <code>{total}</code>\n"
        ),
        "mode_line": "<b>🔎 Извлечение:</b> <code>{mode}</code>",
        "caps": "<b>📋 Профиль поведения модуля:</b>\n{caps}",
        "why_head": "<b>Краткая сводка угроз (Статика):</b>\n",
        "empty": "✅ <b>Статических угроз не найдено.</b>\n",
        "section": "\n<b>{title}:</b>\n",
        "row": "🔻 <b>{title}</b> <i>(Стр: {line})</i>\n",
        "row_why": "🔻 <b>{title}</b>\n  └ <i>{detail} (Стр: {line})</i>\n",
        "footer": "\n<i>by Goy(@samsepi0l_ovf)</i>",
        "err": "❌ Ошибка: {err}",
        "mode_set": "✅ Уровень паранойи установлен на: <code>{mode}</code>",
        "wl_add": "✅ Добавлен в белый список: <code>{fp}</code>",
        "wl_del": "✅ Удалён из белого списка: <code>{fp}</code>",
        "hist_head": "<b>📋 Последние сканирования:</b>\n",
        "hist_row": "• <code>{fp}</code> | <b>{verdict}</b> | Баллов: <code>{score}</code>\n",
        "whitelisted": "✅ <b>Этот модуль находится в Белом Списке.</b>\n",
        "details_head": "<b>🔍 Детальный отчет сканирования:</b>\n",
    }

    def __init__(self) -> None:
        self.config = loader.ModuleConfig(
            loader.ConfigValue("gemini_token", "", "Токен Gemini API (из Google AI Studio) для нейро-анализа кода.", validator=loader.validators.Hidden()),
            loader.ConfigValue("gemini_model", "gemini-3-flash-preview", "Модель Gemini API (например: gemini-3-flash-preview)"),
            loader.ConfigValue("max_bytes", 2_000_000, "Максимум байт для анализа", validator=loader.validators.Integer(minimum=10_000, maximum=20_000_000)),
            loader.ConfigValue("timeout", 20, "Таймаут URL", validator=loader.validators.Integer(minimum=3, maximum=120)),
            loader.ConfigValue("decode_depth", 5, "Глубина декодирования", validator=loader.validators.Integer(minimum=1, maximum=10)),
            loader.ConfigValue("max_files", 40, "Максимум файлов в архиве", validator=loader.validators.Integer(minimum=1, maximum=250)),
            loader.ConfigValue("ui_updates", True, "Показывать пошаговый статус", validator=loader.validators.Boolean()),
        )
        self.av = Analyzer(depth=self.config["decode_depth"], mode="strict", max_files=self.config["max_files"])
        self._hist: List[Dict[str, Any]] = []
        self._wl: List[str] = []
        self._mode = "strict"
        self._cur = ""
        self._last_res = None

    def config_complete(self):
        self.av.depth = self.config["decode_depth"]
        self.av.max_files = self.config["max_files"]

    async def client_ready(self):
        self.av.depth = self.config["decode_depth"]
        self.av.max_files = self.config["max_files"]
        
        hist_data = self.db.get("GoySecurity", "gsec_hist")
        if hist_data:
            self._hist = list(hist_data)
        else:
            self._hist = []
            
        wl_data = self.db.get("GoySecurity", "gsec_wl")
        if wl_data:
            self._wl = list(wl_data)
        else:
            self._wl = []
            
        self._mode = self.db.get("GoySecurity", "gsec_mode", "strict")
        if self._mode not in {"normal", "strict", "paranoid"}:
            self._mode = "strict"
            
        self.av.mode = self._mode

    def _persist(self) -> None:
        self.db.set("GoySecurity", "gsec_hist", self._hist)
        self.db.set("GoySecurity", "gsec_wl", self._wl)
        self.db.set("GoySecurity", "gsec_mode", self._mode)

    async def _stage(self, message, text: str):
        if self.config["ui_updates"]:
            try:
                return await utils.answer(message, text)
            except Exception:
                return None
        return None

    def _get_verdict(self, risk: str) -> str:
        if risk == "critical": return "☠️ СТИЛЕР / МАЛВАРЬ"
        if risk == "high": return "🔴 ВЫСОКИЙ РИСК"
        if risk == "medium": return "🟡 ПОДОЗРИТЕЛЬНО"
        if risk == "low": return "🔵 НИЗКИЙ РИСК"
        return "✅ АБСОЛЮТНО ЧИСТО"

    async def _send_text_chunked(self, message, text: str):
        if len(text) <= 3900:
            await utils.answer(message, text)
            return

        chunks = []
        current_chunk = ""
        for line in text.splitlines():
            if len(current_chunk) + len(line) > 3900:
                chunks.append(current_chunk.strip())
                current_chunk = line + "\n"
            else:
                current_chunk += line + "\n"
                
        if current_chunk:
            chunks.append(current_chunk.strip())

        msg = await utils.answer(message, chunks[0])
        for chunk in chunks[1:]:
            await asyncio.sleep(0.3)
            msg = await msg.reply(chunk)

    async def _ask_gemini(self, token: str, code: str, model_name: str, static_res: Optional[Dict[str, Any]] = None) -> Optional[Dict[str, Any]]:
        for attempt in range(5):
            try:
                url = f"https://generativelanguage.googleapis.com/v1beta/models/{model_name}:generateContent?key={token}"
                analysis_summary = ""
                if static_res:
                    analysis_summary = (
                        f"Результаты статики: Риск {static_res['risk']}, "
                        f"Очков {static_res['score']}, "
                        f"Семейство {static_res['family']} ({static_res['family_conf']}%)\n"
                        f"Флаги: {', '.join([h['title'] for h in static_res.get('critical', [])])}\n"
                    )
                
                prompt = (
                    "Ты — эксперт Malware-аналитик. Проверь Python-код на вредоносную активность (сессии, стилеры, бэкдоры). "
                    "Игнорируй штатное использование библиотек для легитимных целей. "
                    "Мне не нужно твое упоминание статического анализа в ответе, используй его только как подсказку для себя. "
                    "Если статика совпадает с твоими выводами - это подтверждение. "
                    "Ответь СТРОГО в формате JSON без markdown: "
                    '{"verdict": "Безопасно"|"Подозрительно"|"Вредонос", "reason": "...", "threats": []}.'
                )
                
                payload = {
                    "contents": [{"parts": [{"text": f"{prompt}\n\n{analysis_summary}\n\nCODE:\n{code[:35000]}"}]}],
                    "generationConfig": {"temperature": 0.1, "responseMimeType": "application/json"}
                }
                
                async with aiohttp.ClientSession() as session:
                    async with session.post(url, json=payload, timeout=50) as resp:
                        if resp.status == 429:
                            await asyncio.sleep(2 ** attempt + 2)
                            continue
                        if resp.status != 200:
                            return {"error": True, "reason": f"API Error {resp.status}"}
                            
                        data = await resp.json()
                        text = data.get("candidates", [{}])[0].get("content", {}).get("parts", [{}])[0].get("text", "").strip()
                        
                        try:
                            clean_text = re.sub(r'^```json\s*|\s*```$', '', text, flags=re.MULTILINE|re.IGNORECASE).strip()
                            return json.loads(clean_text)
                        except:
                            match = re.search(r'\{.*\}', text, re.DOTALL)
                            if match:
                                try: return json.loads(match.group(0))
                                except: pass
                            return {"error": True, "reason": "JSON Parse Error"}
            except Exception as e:
                if attempt == 4: return {"error": True, "reason": str(e)}
                await asyncio.sleep(1)
        return None

    @loader.unrestricted
    @loader.ratelimit
    async def gscancmd(self, message):
        """<ответом на файл/ссылку/текст> — Проверить модуль на вирусы и стилеры"""
        args = utils.get_args_raw(message).strip()
        status_msg = await utils.answer(message, self.strings("loading"))
        
        try:
            srcs = await self._resolve(message, args)
            if not srcs:
                await utils.answer(message, self.strings("no_code"))
                return
            
            if self.config["ui_updates"]:
                await utils.answer(status_msg, f"{self.strings('loading')}\n{self.strings('stage_rules')}")
            
            self.av.mode = self._mode
            res = self.av.scan(srcs)
            self._cur = res["fp"]
            self._last_res = res
            
            ai_result = None
            api_error = None
            gemini_token = str(self.config.get("gemini_token", "")).strip()
            gemini_model = str(self.config.get("gemini_model", "gemini-3-flash-preview")).strip()
            
            if gemini_token:
                if self.config["ui_updates"]:
                    await utils.answer(status_msg, f"{self.strings('loading')}\n{self.strings('stage_rules')}\n{self.strings('stage_ai')}")
                ai_result = await self._ask_gemini(gemini_token, res["decoded"], gemini_model, res)
                if ai_result and ai_result.get("error"):
                    api_error = ai_result.get("reason")
                    ai_result = None

            if ai_result:
                final_text = self._fmt_ai(res, ai_result)
            else:
                final_text = ""
                if res["fp"] in self._wl:
                    final_text += self.strings("whitelisted") + self._fmt_static(res, api_error)
                else:
                    self._push(res["fp"], res["risk"], res["score"], res.get("mode", []))
                    self._persist()
                    final_text += self._fmt_static(res, api_error)
                
            await self._send_text_chunked(message, final_text)
            
        except Exception as e:
            log.exception("GoySecurity scan error")
            err_str = str(e)
            err_str = err_str[:497] + "..." if len(err_str) > 500 else err_str
            err_msg = self.strings("err").format(err=html.escape(err_str))
            await utils.answer(message, err_msg)

    @loader.unrestricted
    async def gmodecmd(self, message):
        """[normal|strict|paranoid] — Изменить уровень паранойи антивируса"""
        a = utils.get_args_raw(message).strip().lower()
        if not a:
            m = "normal" if self._mode == "strict" else "strict"
        else:
            m = a
            
        if m not in {"normal", "strict", "paranoid"}:
            err_msg = self.strings("err").format(err="use: normal, strict, paranoid")
            await utils.answer(message, err_msg)
            return
            
        self._mode = m
        self.av.mode = m
        self._persist()
        
        success_msg = self.strings("mode_set").format(mode=html.escape(m))
        await utils.answer(message, success_msg)

    @loader.unrestricted
    async def gwlcmd(self, message):
        """[fp] — Добавить хэш модуля в белый список (игнорировать детекты)"""
        fp = utils.get_args_raw(message).strip().lower()
        if not fp:
            fp = self._cur
            
        if not fp:
            err_msg = self.strings("err").format(err="no fingerprint")
            await utils.answer(message, err_msg)
            return
            
        if fp not in self._wl:
            self._wl.append(fp)
            self._persist()
            
        success_msg = self.strings("wl_add").format(fp=html.escape(fp))
        await utils.answer(message, success_msg)

    @loader.unrestricted
    async def gunwlcmd(self, message):
        """[fp] — Удалить хэш модуля из белого списка"""
        fp = utils.get_args_raw(message).strip().lower()
        if not fp:
            fp = self._cur
            
        if not fp:
            err_msg = self.strings("err").format(err="no fingerprint")
            await utils.answer(message, err_msg)
            return
            
        if fp in self._wl:
            self._wl.remove(fp)
            self._persist()
            
        success_msg = self.strings("wl_del").format(fp=html.escape(fp))
        await utils.answer(message, success_msg)

    @loader.unrestricted
    async def ghistcmd(self, message):
        """— Показать историю последних проверок"""
        hist = list(self._hist)[-10:]
        if not hist:
            empty_msg = self.strings("hist_head") + "<i>Пусто</i>"
            await utils.answer(message, empty_msg)
            return
            
        out = [self.strings("hist_head")]
        for it in reversed(hist):
            fp_str = html.escape(str(it.get("fp", "")))
            verdict_str = self._get_verdict(str(it.get("risk", "")))
            score_str = html.escape(str(it.get("score", "")))
            row_msg = self.strings("hist_row").format(fp=fp_str, verdict=verdict_str, score=score_str)
            out.append(row_msg)
            
        await utils.answer(message, "".join(out))

    @loader.unrestricted
    async def gwhycmd(self, message):
        """— Показать подробный отчет по последнему скану"""
        if not self._last_res:
            err_msg = self.strings("err").format(err="Сначала запустите .gscan")
            await utils.answer(message, err_msg)
            return
            
        gemini_token = str(self.config.get("gemini_token", "")).strip()
        gemini_model = str(self.config.get("gemini_model", "gemini-3-flash-preview")).strip()
        ai_result = None
        api_error = None
        
        if gemini_token and self._last_res.get("decoded"):
            status = self.strings("stage_ai")
            await self._stage(message, status)
            ai_result = await self._ask_gemini(gemini_token, self._last_res["decoded"], gemini_model)
            if ai_result and ai_result.get("error"):
                api_error = ai_result.get("reason")
                ai_result = None
                
        if ai_result:
            why_str = self._fmt_ai(self._last_res, ai_result)
        else:
            why_str = self._why_static(self._last_res, api_error)
            
        await self._send_text_chunked(message, why_str)

    def _push(self, fp: str, risk: str, score: int, mode: List[str]) -> None:
        mode_str = " -> ".join(mode)
        ts = int(time.time())
        item = {"fp": fp, "risk": risk, "score": score, "mode": mode_str, "ts": ts}
        
        self._hist.append(item)
        if len(self._hist) > 50:
            del self._hist[:-50]

    async def _resolve(self, message, args: str) -> List[Tuple[str, str]]:
        if args and (args.startswith("http://") or args.startswith("https://")):
            return await self._from_url(args)
            
        reply = await message.get_reply_message()
        if reply:
            xs = await self._from_msg(reply)
            if xs:
                return xs
                
        if getattr(message, "media", None):
            xs = await self._from_msg(message)
            if xs:
                return xs
                
        if args:
            return [("args", args)]
            
        return []

    async def _from_url(self, url: str) -> List[Tuple[str, str]]:
        try:
            resp = await utils.run_sync(requests.get, url, timeout=self.config["timeout"])
            resp.raise_for_status()
            data = resp.content[: self.config["max_bytes"]]
            return self._expand(url, data)
        except Exception:
            return []

    async def _from_msg(self, msg) -> List[Tuple[str, str]]:
        try:
            xs = []
            if getattr(msg, "media", None):
                data = await self.client.download_media(msg.media, bytes)
                if data:
                    f_name = "document.py"
                    if hasattr(msg, "file") and getattr(msg.file, "name"):
                        f_name = msg.file.name
                        
                    chopped_data = data[: self.config["max_bytes"]]
                    expanded = self._expand(f_name, chopped_data)
                    xs.extend(expanded)
                    
            txt = getattr(msg, "raw_text", None) or getattr(msg, "text", None)
            if txt and not xs:
                xs.append(("message", str(txt)))
                
            return xs
        except Exception as e:
            log.error(f"Media extraction failed: {e}")
            return []

    def _expand(self, name: str, data: bytes) -> List[Tuple[str, str]]:
        if not data:
            return []
            
        out = []
        bio = io.BytesIO(data)
        
        try:
            if zipfile.is_zipfile(bio):
                bio.seek(0)
                with zipfile.ZipFile(bio) as z:
                    for nm in z.namelist()[: self.config["max_files"]]:
                        if nm.endswith("/"):
                            continue
                        if not nm.lower().endswith(CODE_EXTS):
                            continue
                        try:
                            raw_file = z.read(nm)[: self.config["max_bytes"]]
                            decoded_str = self._maybe_decode(nm, raw_file)
                            out.append((nm, decoded_str))
                        except Exception:
                            pass
                if out:
                    return out
        except Exception:
            pass
            
        bio.seek(0)
        
        try:
            if tarfile.is_tarfile(bio):
                bio.seek(0)
                with tarfile.open(fileobj=bio, mode="r:*") as t:
                    count = 0
                    for it in t:
                        if count >= self.config["max_files"]:
                            break
                        if not it.isfile():
                            continue
                        if not it.name.lower().endswith(CODE_EXTS):
                            continue
                        try:
                            f = t.extractfile(it)
                            if f:
                                raw_file = f.read(self.config["max_bytes"])
                                decoded_str = self._maybe_decode(it.name, raw_file)
                                out.append((it.name, decoded_str))
                        except Exception:
                            pass
                        count += 1
                if out:
                    return out
        except Exception:
            pass
            
        decoded_str = self._maybe_decode(name, data)
        out.append((name, decoded_str))
        return out

    def _maybe_decode(self, name: str, data: bytes) -> str:
        if not data:
            return ""
            
        for enc in ("utf-8", "utf-8-sig", "cp1251", "latin-1"):
            try:
                s = data.decode(enc)
                if s:
                    return s.replace("\r\n", "\n").replace("\r", "\n")
            except Exception:
                pass
                
        lower_name = name.lower()
        
        if lower_name.endswith(".gz") or lower_name.endswith(".gzip"):
            try:
                decompressed = gzip.decompress(data)
                return self._dec_bytes(decompressed)
            except Exception:
                pass
                
        if lower_name.endswith(".bz2"):
            try:
                decompressed = bz2.decompress(data)
                return self._dec_bytes(decompressed)
            except Exception:
                pass
                
        if lower_name.endswith(".xz") or lower_name.endswith(".lzma"):
            try:
                decompressed = lzma.decompress(data)
                return self._dec_bytes(decompressed)
            except Exception:
                pass
                
        for fn in (gzip.decompress, bz2.decompress, lzma.decompress):
            try:
                decompressed = fn(data)
                return self._dec_bytes(decompressed)
            except Exception:
                pass
                
        return data.decode("utf-8", "ignore")

    def _dec_bytes(self, b: bytes) -> str:
        for enc in ("utf-8", "utf-8-sig", "cp1251", "latin-1"):
            try:
                s = b.decode(enc)
                return s.replace("\r\n", "\n").replace("\r", "\n")
            except Exception:
                pass
                
        return b.decode("utf-8", "ignore")

    def _fmt_ai(self, res: Dict[str, Any], ai_result: Dict[str, Any]) -> str:
        out = [self.strings("header")]
        out.append("<b>🤖 Нейро-анализ (Gemini):</b>\n")
        
        verdict = html.escape(str(ai_result.get("verdict", "Неизвестно")))
        out.append(f"<b>⚖️ Вердикт:</b> <code>{verdict}</code>")
        
        reason = str(ai_result.get("reason", "Нет данных"))
        if len(reason) > 2800:
            reason = reason[:2797] + "..."
        out.append(f"<b>🛡 Обоснование:</b> {html.escape(reason)}")
        
        threats = ai_result.get("threats", [])
        if threats:
            out.append("\n<b>⚠️ Главные угрозы:</b>")
            for t in threats:
                t_esc = html.escape(str(t))
                out.append(f"  └ <i>{t_esc}</i>")
        else:
            out.append("\n<b>⚠️ Главные угрозы:</b> <i>Не обнаружено</i>")
            
        r_fp = str(res.get("fp", ""))
        r_parts = str(res.get("parts", 1))
        out.append(f"\n<b>🔖 Хэш:</b> <code>{r_fp}</code> | <b>📦 Файлов:</b> <code>{r_parts}</code>")
        
        out.append(self.strings("footer"))
        return "\n".join(out)

    def _fmt_static(self, res: Dict[str, Any], api_err: Optional[str] = None) -> str:
        out = [self.strings("header")]
        
        if api_err:
            out.append(f"⚠️ <b>Нейро-анализ недоступен:</b> <i>{html.escape(api_err)}</i>\n<i>Использован статический анализ.</i>\n")
            
        r_risk = str(res.get("risk", ""))
        verdict = self._get_verdict(r_risk)
        
        r_fam = html.escape(str(res.get("family", "")))
        r_conf = str(res.get("family_conf", ""))
        r_score = str(res.get("score", ""))
        r_total = str(res.get("total", ""))
        r_fp = str(res.get("fp", ""))
        r_parts = str(res.get("parts", 1))
        
        summary_msg = self.strings("summary").format(
            verdict=verdict, family=r_fam, family_conf=r_conf, 
            score=r_score, total=r_total, fp=r_fp, parts=r_parts
        )
        out.append(summary_msg)
        
        modes = res.get("mode", [])
        if not modes:
            modes = ["Plaintext"]
            
        m_str = html.escape(" -> ".join(modes))
        mode_msg = self.strings("mode_line").format(mode=m_str)
        out.append(mode_msg)
            
        caps_str = html.escape(self._caps(res))
        caps_msg = self.strings("caps").format(caps=caps_str)
        out.append("\n" + caps_msg + "\n")
        
        if not res.get("total", 0):
            out.append(self.strings("empty"))
            out.append(self.strings("footer"))
            return "".join(out)
            
        out.append(self.strings("why_head"))
        
        sections = [
            ("Критичные", res.get("critical", [])),
            ("Предупреждения", res.get("warning", [])),
            ("Инфо", res.get("info", []))
        ]
        
        for head, arr in sections:
            if not arr:
                continue
                
            sec_msg = self.strings("section").format(title=html.escape(head))
            out.append(sec_msg)
            
            for h in arr[:5]:
                t_esc = html.escape(str(h.get("title", "")))
                row_msg = self.strings("row").format(
                    title=t_esc, line=h.get("line", 0)
                )
                out.append(row_msg)
                
        out.append("\n<i>Полный разбор кода — <code>.gwhy</code></i>")
        out.append(self.strings("footer"))
        return "".join(out)

    def _why_static(self, res: Dict[str, Any], api_err: Optional[str] = None) -> str:
        out = [self.strings("details_head")]
        
        if api_err:
            out.append(f"⚠️ <b>Нейро-анализ недоступен:</b> <i>{html.escape(api_err)}</i>\n<i>Детали статического анализа.</i>\n")
            
        r_risk = str(res.get("risk", ""))
        verdict = self._get_verdict(r_risk)
        
        summary_msg = self.strings("summary").format(
            verdict=verdict, 
            family=html.escape(str(res.get("family", ""))), 
            family_conf=str(res.get("family_conf", "")), 
            score=str(res.get("score", "")), 
            total=str(res.get("total", "")), 
            fp=str(res.get("fp", "")), 
            parts=str(res.get("parts", 1))
        )
        out.append(summary_msg)
        
        crit_issues = res.get("critical", [])
        warn_issues = res.get("warning", [])
        info_issues = res.get("info", [])
        all_issues = crit_issues + warn_issues + info_issues
        
        if not all_issues:
            out.append(self.strings("empty"))
            out.append(self.strings("footer"))
            return "".join(out)
            
        for h in all_issues:
            t_esc = html.escape(str(h.get("title", "")))
            
            d_str = str(h.get("detail", ""))
            d_str = d_str[:60] + "..." if len(d_str) > 60 else d_str
            d_esc = html.escape(d_str)
            
            row_msg = self.strings("row_why").format(
                title=t_esc, detail=d_esc, line=h.get("line", 0)
            )
            out.append(row_msg)
                
        out.append(self.strings("footer"))
        return "".join(out)

    def _caps(self, res: Dict[str, Any]) -> str:
        caps = res.get("capabilities", {})
        if not caps:
            return "✅ Подозрительной активности не выявлено"
            
        cap_names = {
            "stealer": "Стилер (кража данных)",
            "exfil": "Отправка данных в сеть",
            "session": "Угроза сессиям (Telegram/Pyrogram)",
            "exec": "Выполнение команд/Shell",
            "sandbox": "Анти-анализ/Песочница",
            "obf": "Обфускация/Скрытый код",
            "net": "Сетевые запросы",
            "sys": "Системные вызовы",
            "storage": "Работа с файловой системой",
            "process": "Управление процессами",
            "deserialize": "Опасная десериализация",
            "loader": "Малварь/Загрузчик"
        }
            
        items = []
        for k, v in sorted(caps.items(), key=lambda x: (-x[1], x[0])):
            name = cap_names.get(k, k.capitalize())
            items.append(f"├ {name} (совпадений: {v})")
            
        return "\n".join(items)
