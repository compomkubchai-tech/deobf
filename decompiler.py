"""
Ravel v0.7 static decompiler.

This is intentionally a non-executing decompiler: it parses the VM data,
reconstructs expressions/cells/prototypes and emits Luau-like source.
It never calls the uploaded script, Roblox APIs, loadstring, or an executor.
"""

import re
from dataclasses import dataclass
from typing import Any

OPS = {
    1:"LOADK", 2:"MOVE", 3:"GETGLOBAL", 4:"SETGLOBAL", 5:"NEWTABLE",
    6:"GETTABLE", 7:"SETTABLE", 8:"NEG", 9:"NOT", 10:"LEN",
    11:"ADD", 12:"SUB", 13:"MUL", 14:"DIV", 15:"IDIV", 16:"MOD", 17:"POW",
    18:"CONCAT", 19:"EQ", 20:"NE", 21:"LT", 22:"LE", 23:"GT", 24:"GE",
    25:"CALL", 26:"CLOSURE", 27:"JUMP", 28:"JUMP_IF_FALSE", 29:"RETURN",
    30:"NEWCELL", 31:"GETCELL", 32:"SETCELL", 33:"GETUPVALUE", 34:"PACK",
    35:"PACKGET", 36:"VARARG", 37:"CALLPACK", 38:"TABLEEXTEND",
    39:"NUMFORCHECK", 40:"RETURNPACK", 41:"BRANCH", 42:"FUSED_LOADK_ADD",
    43:"FUSED_GET", 44:"FUSED_SET",
}

class LuaTableParser:
    def __init__(self, s: str):
        self.s, self.i, self.n = s, 0, len(s)

    def ws(self):
        while self.i < self.n:
            if self.s[self.i].isspace():
                self.i += 1
            elif self.s.startswith("--", self.i):
                j = self.s.find("\n", self.i)
                self.i = self.n if j < 0 else j + 1
            else:
                break

    def expect(self, x):
        self.ws()
        if not self.s.startswith(x, self.i):
            raise ValueError(f"expected {x!r} at {self.i}")
        self.i += len(x)

    def number(self):
        self.ws()
        m = re.match(r'-?(?:\d+\.\d*|\d*\.\d+|\d+)(?:[eE][+-]?\d+)?', self.s[self.i:])
        if not m:
            raise ValueError(f"number expected at {self.i}")
        t = m.group(0); self.i += len(t)
        return float(t) if any(c in t for c in ".eE") else int(t)

    def string(self):
        self.ws()
        q = self.s[self.i]; self.i += 1; out = []
        while self.i < self.n:
            c = self.s[self.i]; self.i += 1
            if c == q:
                return "".join(out)
            if c == "\\" and self.i < self.n:
                if self.s[self.i].isdigit():
                    m = re.match(r'\d{1,3}', self.s[self.i:])
                    t = m.group(0); self.i += len(t); out.append(chr(int(t)))
                elif self.s[self.i] == "x" and self.i + 2 < self.n:
                    t = self.s[self.i+1:self.i+3]
                    if re.fullmatch(r"[0-9A-Fa-f]{2}", t):
                        self.i += 3; out.append(chr(int(t,16)))
                    else:
                        out.append("x"); self.i += 1
                else:
                    c2 = self.s[self.i]; self.i += 1
                    out.append({"n":"\n","r":"\r","t":"\t","\\":"\\",'"': '"', "'":"'"}.get(c2,c2))
            else:
                out.append(c)
        raise ValueError("unterminated string")

    def value(self):
        self.ws()
        if self.i >= self.n: raise ValueError("unexpected end")
        c = self.s[self.i]
        if c in "'\"": return self.string()
        if c == "{": return self.table()
        if self.s.startswith("true", self.i): self.i += 4; return True
        if self.s.startswith("false", self.i): self.i += 5; return False
        if self.s.startswith("nil", self.i): self.i += 3; return None
        return self.number()

    def table(self):
        self.expect("{"); arr=[]; keyed={}
        while True:
            self.ws()
            if self.i < self.n and self.s[self.i] == "}":
                self.i += 1; break
            if self.i < self.n and self.s[self.i] == "[":
                self.i += 1; key=self.number(); self.expect("]"); self.expect("=")
                keyed[int(key)] = self.value()
            else:
                arr.append(self.value())
            self.ws()
            if self.i < self.n and self.s[self.i] == ",":
                self.i += 1; continue
            if self.i < self.n and self.s[self.i] == "}":
                self.i += 1; break
            raise ValueError(f"expected comma/table end at {self.i}")
        return keyed if keyed else arr

def parse_ravel(source):
    m = re.search(r'\blocal\s+P\s*=\s*', source)
    if not m:
        raise ValueError("ไม่พบ local P ของ Ravel VM")
    p = LuaTableParser(source[m.end():]).value()
    if not isinstance(p, dict):
        raise ValueError("Ravel P table is not a keyed table")
    return p

def fmt(v):
    if isinstance(v, str):
        # Prefer escaped Luau string literals while preserving unicode.
        return '"' + v.replace("\\","\\\\").replace('"','\\"').replace("\n","\\n").replace("\r","\\r") + '"'
    if v is None: return "nil"
    if v is True: return "true"
    if v is False: return "false"
    return repr(v)

def decode_words(words):
    rows=[]; i=0
    while i < len(words):
        op=int(words[i]); size=int(words[i+1])
        if size < 2 or i+size > len(words):
            raise ValueError(f"invalid instruction size at word {i+1}")
        args=[int(x) for x in words[i+2:i+size]]
        rows.append((i+1,op,args))
        i += size
    if i != len(words): raise ValueError("truncated word stream")
    return rows

def proto_parts(proto):
    # Ravel P entries are [params, constants, word stream] in the v0.7 format.
    if isinstance(proto, dict):
        params = proto.get(1, 0)
        consts = proto.get(2, [])
        words = proto.get(3, [])
    else:
        params, consts, words = proto[0], proto[1], proto[2]
    return int(params), consts if isinstance(consts,list) else list(consts.values()), words

@dataclass
class IR:
    addr:int
    op:int
    args:list

def decompile_proto(pid, proto, all_protos):
    params, consts, words = proto_parts(proto)
    rows=[IR(*x) for x in decode_words(words)]
    reg={}
    cell={}
    aliases={}
    lines=[]
    labels={}
    targets=set()

    for x in rows:
        if x.op == 27 and x.args: targets.add(x.args[0])
        elif x.op == 28 and len(x.args)>=2: targets.add(x.args[1])
        elif x.op == 41 and len(x.args)>=3: targets.update(x.args[1:3])
    for n,a in enumerate(sorted(targets),1): labels[a]=f"L{n}"

    def rv(n):
        return aliases.get(n, f"r{n}")
    def setr(n, value):
        reg[n]=value
        # Do not alias through a mutable cell/table.
        aliases[n]=value if isinstance(value,str) and len(value)<120 else f"r{n}"
    def c(k):
        if k < 1 or k > len(consts): return f"<const:{k}>"
        return fmt(consts[k-1])

    # Parameters are kept stable instead of exposing r0/r1.
    for n in range(params):
        aliases[n] = f"arg{n+1}"

    out=[f"-- prototype {pid} | params={params} | constants={len(consts)}"]
    out.append(f"local function __ravel_proto_{pid}({', '.join(aliases.get(i, f'arg{i+1}') for i in range(params))}{', ' if params else ''}...)")
    indent="    "

    for x in rows:
        op,a=x.op,x.args
        if x.addr in labels: out.append(labels[x.addr]+":")

        def R(n): return rv(n)
        try:
            s=None
            if op==1:
                dst,k=a[0],a[1]; v=c(k); aliases[dst]=v; reg[dst]=v
                # Keep constant as a value; subsequent uses become readable.
                s=f"local r{dst} = {v}" if dst not in aliases or aliases[dst]==f"r{dst}" else f"r{dst} = {v}"
            elif op==2:
                dst,src=a[:2]; aliases[dst]=R(src); s=f"{R(dst)} = {R(src)}"
            elif op==3:
                dst,k=a[:2]; v=c(k); aliases[dst]=f"_ENV[{v}]"; s=f"{R(dst)} = _ENV[{v}]"
            elif op==4:
                k,src=a[:2]; s=f"_ENV[{c(k)}] = {R(src)}"
            elif op==5:
                dst=a[0]; aliases[dst]=f"{{}}"; s=f"{R(dst)} = {{}}"
            elif op==6:
                dst,tbl,key=a[:3]; s=f"{R(dst)} = {R(tbl)}[{R(key)}]"
            elif op==7:
                tbl,key,val=a[:3]; s=f"{R(tbl)}[{R(key)}] = {R(val)}"
            elif op in (8,9,10):
                dst,src=a[:2]; sym={8:"-",9:"not ",10:"#"}[op]; s=f"{R(dst)} = {sym}{R(src)}"
            elif 11<=op<=24:
                dst,b,c0=a[:3]
                sym={11:"+",12:"-",13:"*",14:"/",15:"//",16:"%",17:"^",18:"..",19:"==",20:"~=",21:"<",22:"<=",23:">",24:">="}[op]
                s=f"{R(dst)} = {R(b)} {sym} {R(c0)}"
            elif op==25:
                dst,fn,count,*argv=a; argv=argv[:count]
                s=f"{R(dst)} = {R(fn)}({', '.join(R(z) for z in argv)})"
            elif op==26:
                dst,target,*rest=a
                aliases[dst]=f"__ravel_proto_{target}"
                s=f"{R(dst)} = __ravel_proto_{target}"
            elif op==27:
                s=f"goto {labels.get(a[0], 'PC_'+str(a[0]))}"
            elif op==28:
                cond,t=a[:2]; s=f"if not {R(cond)} then goto {labels.get(t,'PC_'+str(t))} end"
            elif op==29:
                if not a or a[0]==0: s="return"
                else: s="return " + ", ".join(R(z) for z in a[1:])
            elif op==30:
                cellid,src=a[:2]; cell[cellid]=R(src); s=f"local cell_{cellid} = {R(src)}"
            elif op==31:
                dst,cellid=a[:2]; aliases[dst]=cell.get(cellid,f"cell_{cellid}"); s=f"{R(dst)} = cell_{cellid}"
            elif op==32:
                cellid,src=a[:2]; cell[cellid]=R(src); s=f"cell_{cellid} = {R(src)}"
            elif op==33:
                dst,u=a[:2]; aliases[dst]=f"upvalue_{u}"; s=f"{R(dst)} = upvalue_{u}"
            elif op==34:
                dst,*vals=a; s=f"{R(dst)} = table.pack({', '.join(R(z) for z in vals)})"
            elif op==35:
                dst,src,key=a[:3]; s=f"{R(dst)} = {R(src)}[{key}]"
            elif op==36:
                dst=a[0]; s=f"{R(dst)} = table.pack(...)"
            elif op==37:
                dst,fn,count,*argv=a; argv=argv[:count]
                s=f"{R(dst)} = {R(fn)}(table.unpack({R(argv[0])}) if {len(argv)==1} else {', '.join(R(z) for z in argv)})" if argv else f"{R(dst)} = {R(fn)}()"
            elif op==38:
                t,a0,b=a[:3]; s=f"table.move({R(a0)}, 1, {R(b)}, 1, {R(t)})"
            elif op==39:
                dst,start,step,limit=a[:4]; s=f"{R(dst)} = ({R(start)} <= {R(limit)})"
            elif op==40:
                s=f"return table.unpack({R(a[0])})"
            elif op==41:
                cond,t,f=a[:3]; s=f"if not {R(cond)} then goto {labels.get(t,'PC_'+str(t))} else goto {labels.get(f,'PC_'+str(f))} end"
            elif op==42:
                dst,k,adddst,b,c0=a[:5]; s=f"{R(dst)} = {c(k)}; {R(adddst)} = {R(b)} + {R(c0)}"
            elif op==43:
                dst,k,getdst,base,key=a[:5]; aliases[getdst]=f"{R(base)}[{c(k)}]"
                s=f"{R(dst)} = {c(k)}; {R(getdst)} = {R(base)}[{c(k)}]"
            elif op==44:
                dst,k,tbl,key,val=a[:5]; s=f"{R(dst)} = {c(k)}; {R(tbl)}[{R(key)}] = {R(val)}"
            else:
                s=f"-- {OPS.get(op,'OP'+str(op))} {a}"

            out.append(indent+s)
        except Exception as e:
            out.append(indent+f"-- decode error op={op} args={a}: {e}")

    out.append("end")
    return "\n".join(out)

def deobfuscate(source):
    p=parse_ravel(source)
    keys=sorted(int(k) for k in p.keys() if str(k).lstrip("-").isdigit())
    # Ravel v0.7 stores prototypes as numeric entries; ignore metadata entries.
    protos={}
    for k in keys:
        try:
            protos[k]=p[k]
        except KeyError:
            protos[k]=p[str(k)]
    out=[
        "-- Ravel v0.7 FULL STATIC DECOMPILATION",
        "-- Non-executing: VM bytecode is decoded, expressions/cells/prototypes are reconstructed.",
        "",
    ]
    for pid in keys:
        try:
            out.append(decompile_proto(pid, protos[pid], protos))
        except Exception as e:
            out.append(f"-- prototype {pid} failed: {e}")
        out.append("")
    stats={"prototypes":len(keys),"input_bytes":len(source.encode("utf-8","replace")),"output_bytes":0}
    result="\n".join(out)
    stats["output_bytes"]=len(result.encode("utf-8"))
    return result, stats
