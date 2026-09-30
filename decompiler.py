"""
Ravel v0.7 static decompiler / source-like rewriter.

Goals:
- Decode the Ravel P table without executing the uploaded program.
- Track register values as expressions instead of printing every VM register.
- Fold LOADK/MOVE/GETGLOBAL/GETTABLE/CALL chains.
- Recover common Luau forms such as game:GetService("Players").
- Remove VM-only temporaries when they are not semantically needed.
- Preserve uncertain control-flow as labelled blocks instead of inventing logic.

This is static analysis only. It never executes uploaded Lua/Luau.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any


OPS = {
    1: "LOADK", 2: "MOVE", 3: "GETGLOBAL", 4: "SETGLOBAL", 5: "NEWTABLE",
    6: "GETTABLE", 7: "SETTABLE", 8: "NEG", 9: "NOT", 10: "LEN",
    11: "ADD", 12: "SUB", 13: "MUL", 14: "DIV", 15: "IDIV", 16: "MOD",
    17: "POW", 18: "CONCAT", 19: "EQ", 20: "NE", 21: "LT", 22: "LE",
    23: "GT", 24: "GE", 25: "CALL", 26: "CLOSURE", 27: "JUMP",
    28: "JUMP_IF_FALSE", 29: "RETURN", 30: "NEWCELL", 31: "GETCELL",
    32: "SETCELL", 33: "GETUPVALUE", 34: "PACK", 35: "PACKGET",
    36: "VARARG", 37: "CALLPACK", 38: "TABLEEXTEND", 39: "NUMFORCHECK",
    40: "RETURNPACK", 41: "BRANCH", 42: "FUSED_LOADK_ADD",
    43: "FUSED_GET", 44: "FUSED_SET",
}

BINARY = {
    11: "+", 12: "-", 13: "*", 14: "/", 15: "//", 16: "%",
    17: "^", 18: "..", 19: "==", 20: "~=", 21: "<", 22: "<=",
    23: ">", 24: ">=",
}

SAFE_IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
KEYWORDS = {
    "and", "break", "do", "else", "elseif", "end", "false", "for", "function",
    "if", "in", "local", "nil", "not", "or", "repeat", "return", "then",
    "true", "until", "while",
}


class LuaTableParser:
    def __init__(self, s: str):
        self.s = s
        self.i = 0
        self.n = len(s)

    def ws(self):
        while self.i < self.n:
            if self.s[self.i].isspace():
                self.i += 1
            elif self.s.startswith("--", self.i):
                j = self.s.find("\n", self.i)
                self.i = self.n if j < 0 else j + 1
            else:
                break

    def expect(self, x: str):
        self.ws()
        if not self.s.startswith(x, self.i):
            raise ValueError(f"expected {x!r} at {self.i}")
        self.i += len(x)

    def number(self):
        self.ws()
        m = re.match(
            r"-?(?:\d+\.\d*|\d*\.\d+|\d+)(?:[eE][+-]?\d+)?",
            self.s[self.i:],
        )
        if not m:
            raise ValueError(f"number expected at {self.i}")
        t = m.group(0)
        self.i += len(t)
        return float(t) if any(c in t for c in ".eE") else int(t)

    def string(self):
        self.ws()
        q = self.s[self.i]
        self.i += 1
        out = []

        while self.i < self.n:
            c = self.s[self.i]
            self.i += 1

            if c == q:
                return "".join(out)

            if c == "\\" and self.i < self.n:
                if self.s[self.i].isdigit():
                    m = re.match(r"\d{1,3}", self.s[self.i:])
                    t = m.group(0)
                    self.i += len(t)
                    out.append(chr(int(t)))
                elif self.s[self.i] == "x" and self.i + 2 < self.n:
                    t = self.s[self.i + 1:self.i + 3]
                    if re.fullmatch(r"[0-9A-Fa-f]{2}", t):
                        self.i += 3
                        out.append(chr(int(t, 16)))
                    else:
                        out.append("x")
                        self.i += 1
                else:
                    c2 = self.s[self.i]
                    self.i += 1
                    out.append({
                        "n": "\n", "r": "\r", "t": "\t",
                        "\\": "\\", '"': '"', "'": "'",
                    }.get(c2, c2))
            else:
                out.append(c)

        raise ValueError("unterminated string")

    def value(self):
        self.ws()
        if self.i >= self.n:
            raise ValueError("unexpected end")

        c = self.s[self.i]

        if c in "'\"":
            return self.string()
        if c == "{":
            return self.table()
        if self.s.startswith("true", self.i):
            self.i += 4
            return True
        if self.s.startswith("false", self.i):
            self.i += 5
            return False
        if self.s.startswith("nil", self.i):
            self.i += 3
            return None

        return self.number()

    def table(self):
        self.expect("{")
        arr = []
        keyed = {}

        while True:
            self.ws()

            if self.i < self.n and self.s[self.i] == "}":
                self.i += 1
                break

            if self.i < self.n and self.s[self.i] == "[":
                self.i += 1
                key = self.number()
                self.expect("]")
                self.expect("=")
                keyed[int(key)] = self.value()
            else:
                arr.append(self.value())

            self.ws()

            if self.i < self.n and self.s[self.i] == ",":
                self.i += 1
                continue

            if self.i < self.n and self.s[self.i] == "}":
                self.i += 1
                break

            raise ValueError(f"expected comma/table end at {self.i}")

        return keyed if keyed else arr


def parse_ravel(source: str):
    m = re.search(r"\blocal\s+P\s*=\s*", source)
    if not m:
        raise ValueError("ไม่พบ local P ของ Ravel VM")

    p = LuaTableParser(source[m.end():]).value()

    if not isinstance(p, dict):
        raise ValueError("Ravel P table is not a keyed table")

    return p


def proto_parts(proto):
    if isinstance(proto, dict):
        params = proto.get(1, 0)
        consts = proto.get(2, [])
        words = proto.get(3, [])
    else:
        params, consts, words = proto[0], proto[1], proto[2]

    if isinstance(consts, list):
        constants = consts
    elif isinstance(consts, dict):
        constants = [consts[k] for k in sorted(consts)]
    else:
        constants = list(consts)

    return int(params), constants, words


def decode_words(words):
    rows = []
    i = 0

    while i < len(words):
        if i + 1 >= len(words):
            raise ValueError(f"truncated instruction header at word {i}")

        op = int(words[i])
        size = int(words[i + 1])

        if size < 2 or i + size > len(words):
            raise ValueError(f"invalid instruction size at word {i}")

        args = [int(x) for x in words[i + 2:i + size]]
        rows.append(IR(i + 1, op, args))
        i += size

    return rows


@dataclass
class IR:
    addr: int
    op: int
    args: list[int]


@dataclass(frozen=True)
class Expr:
    text: str
    precedence: int = 100
    pure: bool = True


def lit(v: Any) -> Expr:
    if isinstance(v, str):
        return Expr(
            '"' + v.replace("\\", "\\\\").replace('"', '\\"')
            .replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t") + '"'
        )
    if v is None:
        return Expr("nil")
    if v is True:
        return Expr("true")
    if v is False:
        return Expr("false")
    return Expr(repr(v))


def is_ident(s: str) -> bool:
    return bool(SAFE_IDENT.fullmatch(s)) and s not in KEYWORDS


def key_expr(key: Expr) -> str:
    # Convert t["Name"] to t.Name where that is valid Luau.
    if len(key.text) >= 2 and key.text[0] == '"' and key.text[-1] == '"':
        raw = key.text[1:-1]
        if is_ident(raw):
            return "." + raw
    return "[" + key.text + "]"


def parenthesize(e: Expr, minimum: int) -> str:
    if e.precedence < minimum:
        return "(" + e.text + ")"
    return e.text


def binary(a: Expr, op: str, b: Expr) -> Expr:
    prec = {
        "or": 10, "and": 20,
        "==": 30, "~=": 30, "<": 30, "<=": 30, ">": 30, ">=": 30,
        "..": 40,
        "+": 50, "-": 50,
        "*": 60, "/": 60, "//": 60, "%": 60,
        "^": 70,
    }.get(op, 50)

    return Expr(
        f"{parenthesize(a, prec)} {op} {parenthesize(b, prec + (0 if op == '^' else 1))}",
        prec,
        a.pure and b.pure,
    )


def unary(op: str, a: Expr) -> Expr:
    prec = 80
    return Expr(f"{op}{parenthesize(a, prec)}", prec, a.pure)


class Decompiler:
    def __init__(self, pid: int, proto: Any, all_protos: dict[int, Any]):
        self.pid = pid
        self.proto = proto
        self.all_protos = all_protos

        self.params, self.constants, words = proto_parts(proto)
        self.rows = decode_words(words)

        self.alias: dict[int, Expr] = {}
        self.names: dict[int, str] = {}
        self.cells: dict[int, Expr] = {}
        self.assigned: set[int] = set()
        self.used: dict[int, int] = {}

        self.lines: list[str] = []
        self.declared: set[str] = set()
        self.labels: dict[int, str] = {}

        self._count_uses()
        self._make_labels()
        self._init_params()

    def _count_uses(self):
        for row in self.rows:
            op, a = row.op, row.args

            def use(reg):
                self.used[reg] = self.used.get(reg, 0) + 1

            if op == 2 and len(a) >= 2:
                use(a[1])
            elif op in (6, 7):
                for x in a[1:]:
                    use(x)
            elif op in (8, 9, 10):
                if len(a) >= 2:
                    use(a[1])
            elif op in BINARY:
                for x in a[1:3]:
                    use(x)
            elif op == 25:
                if len(a) >= 2:
                    use(a[1])
                    count = a[2] if len(a) >= 3 else 0
                    for x in a[3:3 + count]:
                        use(x)
            elif op == 28 and a:
                use(a[0])
            elif op == 29:
                for x in a[1:]:
                    use(x)
            elif op == 30 and len(a) >= 2:
                use(a[1])
            elif op == 32 and len(a) >= 2:
                use(a[1])
            elif op == 34:
                for x in a[1:]:
                    use(x)
            elif op == 35 and len(a) >= 2:
                use(a[1])
            elif op == 37:
                if len(a) >= 2:
                    use(a[1])
                    count = a[2] if len(a) >= 3 else 0
                    for x in a[3:3 + count]:
                        use(x)
            elif op == 38:
                for x in a[1:]:
                    use(x)
            elif op == 39:
                for x in a[1:]:
                    use(x)
            elif op == 40 and a:
                use(a[0])
            elif op == 41 and a:
                use(a[0])
            elif op == 42 and len(a) >= 5:
                use(a[3]); use(a[4])
            elif op == 43 and len(a) >= 5:
                use(a[3]); use(a[4])
            elif op == 44 and len(a) >= 5:
                use(a[2]); use(a[3]); use(a[4])

    def _make_labels(self):
        targets = set()

        for row in self.rows:
            a = row.args
            if row.op == 27 and a:
                targets.add(a[0])
            elif row.op == 28 and len(a) >= 2:
                targets.add(a[1])
            elif row.op == 41 and len(a) >= 3:
                targets.update(a[1:3])

        for n, addr in enumerate(sorted(targets), 1):
            self.labels[addr] = f"L{n}"

    def _init_params(self):
        for r in range(self.params):
            self.alias[r] = Expr(f"arg{r + 1}")
            self.names[r] = f"arg{r + 1}"

    def constant(self, index: int) -> Expr:
        if 1 <= index <= len(self.constants):
            return lit(self.constants[index - 1])
        return Expr(f"/* const {index} */ nil")

    def reg(self, n: int) -> Expr:
        return self.alias.get(n, Expr(self.names.get(n, f"v{n}")))

    def set_reg(self, n: int, e: Expr):
        self.alias[n] = e
        self.assigned.add(n)

    def new_name(self, reg: int) -> str:
        if reg in self.names:
            return self.names[reg]

        name = f"v{reg}"
        self.names[reg] = name
        return name

    def target(self, addr: int) -> str:
        return self.labels.get(addr, f"PC_{addr}")

    def emit_assignment(self, reg: int, e: Expr, force=False):
        name = self.new_name(reg)

        # Keep pure one-use values inline. This is the main difference from
        # the old register-dump decompiler.
        if not force and self.used.get(reg, 0) <= 1 and e.pure:
            self.set_reg(reg, e)
            return

        prefix = "local " if name not in self.declared else ""
        self.declared.add(name)
        self.lines.append(f"{prefix}{name} = {e.text}")
        self.set_reg(reg, Expr(name))

    def env_expr(self, key: Expr) -> Expr:
        if key.text.startswith('"') and key.text.endswith('"'):
            raw = key.text[1:-1]
            if is_ident(raw):
                return Expr(raw)
        return Expr(f"_ENV[{key.text}]")

    def table_get(self, table: Expr, key: Expr) -> Expr:
        # Recognize method-looking table accesses.
        if key.text.startswith('"') and key.text.endswith('"'):
            raw = key.text[1:-1]
            if is_ident(raw):
                return Expr(table.text + "." + raw, 90, table.pure)
        return Expr(table.text + key_expr(key), 90, table.pure and key.pure)

    def call_expr(self, fn: Expr, args: list[Expr]) -> Expr:
        argtext = ", ".join(x.text for x in args)

        # game.GetService("Players") -> game:GetService("Players")
        m = re.fullmatch(r"(.+)\.([A-Za-z_][A-Za-z0-9_]*)", fn.text)
        if m and m.group(2) in {
            "GetService", "WaitForChild", "FindFirstChild", "FindFirstChildOfClass",
            "GetChildren", "GetPlayers", "Connect", "Destroy", "Clone",
        }:
            return Expr(f"{m.group(1)}:{m.group(2)}({argtext})", 90, fn.pure and all(a.pure for a in args))

        return Expr(f"{fn.text}({argtext})", 90, fn.pure and all(a.pure for a in args))

    def process(self):
        for row in self.rows:
            if row.addr in self.labels:
                self.lines.append(self.labels[row.addr] + ":")

            op, a = row.op, row.args

            try:
                self.op(row)
            except Exception as exc:
                self.lines.append(f"-- decode error: {OPS.get(op, op)} {a}: {exc}")

        return self.render()

    def op(self, row: IR):
        op, a = row.op, row.args

        if op == 1:  # LOADK
            self.emit_assignment(a[0], self.constant(a[1]))
            return

        if op == 2:  # MOVE
            self.set_reg(a[0], self.reg(a[1]))
            return

        if op == 3:  # GETGLOBAL
            self.set_reg(a[0], self.env_expr(self.constant(a[1])))
            return

        if op == 4:  # SETGLOBAL
            self.lines.append(f"_ENV[{self.constant(a[0]).text}] = {self.reg(a[1]).text}")
            return

        if op == 5:  # NEWTABLE
            self.emit_assignment(a[0], Expr("{}"), force=self.used.get(a[0], 0) > 0)
            return

        if op == 6:  # GETTABLE
            e = self.table_get(self.reg(a[1]), self.reg(a[2]))
            self.emit_assignment(a[0], e)
            return

        if op == 7:  # SETTABLE
            self.lines.append(
                f"{self.reg(a[0]).text}{key_expr(self.reg(a[1]))} = {self.reg(a[2]).text}"
            )
            return

        if op in (8, 9, 10):
            sym = {8: "-", 9: "not ", 10: "#"}[op]
            self.emit_assignment(a[0], unary(sym, self.reg(a[1])))
            return

        if op in BINARY:
            self.emit_assignment(a[0], binary(self.reg(a[1]), BINARY[op], self.reg(a[2])))
            return

        if op == 25:  # CALL
            dst, fnreg, count = a[:3]
            argv = [self.reg(x) for x in a[3:3 + count]]
            self.emit_assignment(dst, self.call_expr(self.reg(fnreg), argv), force=True)
            return

        if op == 26:  # CLOSURE
            dst, target = a[:2]
            self.emit_assignment(
                dst,
                Expr(f"__ravel_proto_{target}", 90),
                force=True,
            )
            return

        if op == 27:
            self.lines.append(f"goto {self.target(a[0])}")
            return

        if op == 28:
            self.lines.append(f"if not {self.reg(a[0]).text} then goto {self.target(a[1])} end")
            return

        if op == 29:
            if not a or a[0] == 0:
                self.lines.append("return")
            else:
                self.lines.append("return " + ", ".join(self.reg(x).text for x in a[1:]))
            return

        if op == 30:  # NEWCELL
            cellid, src = a[:2]
            self.cells[cellid] = self.reg(src)
            return

        if op == 31:  # GETCELL
            dst, cellid = a[:2]
            self.set_reg(dst, self.cells.get(cellid, Expr(f"cell_{cellid}")))
            return

        if op == 32:  # SETCELL
            cellid, src = a[:2]
            self.cells[cellid] = self.reg(src)
            return

        if op == 33:
            self.set_reg(a[0], Expr(f"upvalue_{a[1]}"))
            return

        if op == 34:
            self.emit_assignment(
                a[0],
                Expr("{" + ", ".join(self.reg(x).text for x in a[1:]) + "}"),
                force=True,
            )
            return

        if op == 35:
            self.emit_assignment(
                a[0],
                Expr(self.reg(a[1]).text + f"[{a[2]}]"),
            )
            return

        if op == 36:
            self.emit_assignment(a[0], Expr("..."), force=True)
            return

        if op == 37:
            dst, fnreg, count = a[:3]
            argv = [self.reg(x) for x in a[3:3 + count]]
            if len(argv) == 1:
                call = Expr(f"{self.reg(fnreg).text}(table.unpack({argv[0].text}))", 90, False)
            else:
                call = self.call_expr(self.reg(fnreg), argv)
            self.emit_assignment(dst, call, force=True)
            return

        if op == 38:
            self.lines.append(
                f"table.move({self.reg(a[1]).text}, 1, {self.reg(a[2]).text}, 1, {self.reg(a[0]).text})"
            )
            return

        if op == 39:
            self.emit_assignment(
                a[0],
                binary(self.reg(a[1]), "<=", self.reg(a[3])),
                force=True,
            )
            return

        if op == 40:
            self.lines.append(f"return table.unpack({self.reg(a[0]).text})")
            return

        if op == 41:
            # Keep the branch explicit until the CFG pass can prove a structured
            # if/else. This avoids generating incorrect source.
            cond, t, f = a[:3]
            self.lines.append(
                f"if {self.reg(cond).text} then goto {self.target(t)} else goto {self.target(f)} end"
            )
            return

        if op == 42:
            # Fused LOADK + ADD. Keep both effects but do not expose temporary
            # register names unless they survive later.
            dst, k, adddst, b, c = a[:5]
            self.set_reg(dst, self.constant(k))
            self.emit_assignment(adddst, binary(self.reg(b), "+", self.reg(c)))
            return

        if op == 43:
            dst, k, getdst, base, key = a[:5]
            self.set_reg(dst, self.constant(k))
            self.emit_assignment(getdst, self.table_get(self.reg(base), self.constant(k)))
            return

        if op == 44:
            dst, k, tbl, key, val = a[:5]
            self.set_reg(dst, self.constant(k))
            self.lines.append(
                f"{self.reg(tbl).text}[{self.reg(key).text}] = {self.reg(val).text}"
            )
            return

        self.lines.append(f"-- {OPS.get(op, 'OP' + str(op))} {a}")

    def render(self):
        params = ", ".join(self.names.get(i, f"arg{i + 1}") for i in range(self.params))

        out = [
            f"-- prototype {self.pid} | params={self.params} | constants={len(self.constants)}",
            f"local function __ravel_proto_{self.pid}({params})",
        ]

        out.extend("    " + line for line in self.lines)
        out.append("end")

        return "\n".join(out)


def decompile_proto(pid, proto, all_protos):
    return Decompiler(pid, proto, all_protos).process()


def deobfuscate(source: str):
    p = parse_ravel(source)

    keys = sorted(
        int(k) for k in p.keys()
        if str(k).lstrip("-").isdigit()
    )

    protos = {}
    for k in keys:
        protos[k] = p[k] if k in p else p[str(k)]

    out = [
        "-- Ravel v0.7 SOURCE-LIKE STATIC DECOMPILATION",
        "-- VM instructions are reconstructed into expressions where provable.",
        "-- Control-flow is kept explicit when it cannot be proven safely.",
        "",
    ]

    for pid in keys:
        try:
            out.append(decompile_proto(pid, protos[pid], protos))
        except Exception as exc:
            out.append(f"-- prototype {pid} failed: {exc}")
        out.append("")

    result = "\n".join(out)
    stats = {
        "prototypes": len(keys),
        "input_bytes": len(source.encode("utf-8", "replace")),
        "output_bytes": len(result.encode("utf-8")),
    }
    return result, stats
