import io, re, html
from flask import Flask, render_template, request, send_file

app = Flask(__name__)
MAX_BYTES = 8 * 1024 * 1024

class LuaTableParser:
    def __init__(self, s):
        self.s=s; self.i=0; self.n=len(s)
    def ws(self):
        while self.i<self.n:
            if self.s[self.i].isspace(): self.i+=1; continue
            if self.s.startswith("--",self.i):
                j=self.s.find("\n",self.i)
                self.i=self.n if j<0 else j+1
                continue
            break
    def expect(self,c):
        self.ws()
        if not self.s.startswith(c,self.i): raise ValueError(f"expected {c!r} at {self.i}")
        self.i+=len(c)
    def number(self):
        self.ws(); m=re.match(r'-?(?:\d+\.\d*|\d*\.\d+|\d+)(?:[eE][+-]?\d+)?',self.s[self.i:])
        if not m: raise ValueError(f"number expected at {self.i}")
        t=m.group(0); self.i+=len(t)
        x=float(t) if any(c in t for c in ".eE") else int(t)
        return x
    def string(self):
        self.ws(); q=self.s[self.i]; self.i+=1; out=[]
        while self.i<self.n:
            c=self.s[self.i]; self.i+=1
            if c==q: return "".join(out)
            if c=="\\" and self.i<self.n:
                if self.s[self.i].isdigit():
                    m=re.match(r'\d{1,3}',self.s[self.i:])
                    t=m.group(0); self.i+=len(t); out.append(chr(int(t)))
                else:
                    c2=self.s[self.i]; self.i+=1
                    out.append({"n":"\n","r":"\r","t":"\t","\\":"\\",'"':'"',"'":"'"}.get(c2,c2))
            else: out.append(c)
        raise ValueError("unterminated string")
    def value(self):
        self.ws()
        c=self.s[self.i]
        if c in "'\"": return self.string()
        if c=="{": return self.table()
        if self.s.startswith("true",self.i): self.i+=4; return True
        if self.s.startswith("false",self.i): self.i+=5; return False
        if self.s.startswith("nil",self.i): self.i+=3; return None
        return self.number()
    def table(self):
        self.expect("{"); arr=[]; keyed={}
        while True:
            self.ws()
            if self.i<self.n and self.s[self.i]=="}": self.i+=1; break
            if self.i<self.n and self.s[self.i]=="[":
                self.i+=1; key=self.number(); self.expect("]"); self.expect("="); val=self.value()
                keyed[int(key)]=val
            else:
                arr.append(self.value())
            self.ws()
            if self.i<self.n and self.s[self.i]==",": self.i+=1; continue
            if self.i<self.n and self.s[self.i]=="}": self.i+=1; break
            raise ValueError(f"expected comma/table end at {self.i}")
        return keyed if keyed else arr

def parse_ravel(source):
    m=re.search(r'\blocal\s+P\s*=\s*',source)
    if not m: raise ValueError("ไม่พบ local P ของ Ravel VM")
    p=LuaTableParser(source[m.end():]).value()
    if not isinstance(p,dict): raise ValueError("รูปแบบ P ไม่ถูกต้อง")
    return p

OPS={1:"LOADK",2:"MOVE",3:"GETGLOBAL",4:"SETGLOBAL",5:"NEWTABLE",6:"GETTABLE",7:"SETTABLE",
8:"NEG",9:"NOT",10:"LEN",11:"ADD",12:"SUB",13:"MUL",14:"DIV",15:"IDIV",16:"MOD",17:"POW",
18:"CONCAT",19:"EQ",20:"NE",21:"LT",22:"LE",23:"GT",24:"GE",25:"CALL",26:"CLOSURE",27:"JUMP",
28:"JUMP_IF_FALSE",29:"RETURN",30:"NEWCELL",31:"GETCELL",32:"SETCELL",33:"GETUPVALUE",34:"PACK",
35:"PACKGET",36:"VARARG",37:"CALLPACK",38:"TABLEEXTEND",39:"NUMFORCHECK",40:"RETURNPACK"}

def fmt(v):
    if isinstance(v,str): return repr(v)
    if v is None: return "nil"
    if v is True: return "true"
    if v is False: return "false"
    return str(v)

def decode_words(words):
    i=0; rows=[]
    while i<len(words):
        op=int(words[i]); size=int(words[i+1]); operands=[int(x) for x in words[i+2:i+size]]
        rows.append((i+1,op,operands))
        i += size
    if i!=len(words): raise ValueError("bytecode word stream เสียหาย")
    return rows

def decompile_proto(pid, proto):
    params, consts, words = proto
    rows=decode_words(words)
    labels={addr:f"L{n}" for n,addr in enumerate(sorted({a for a,op,args in rows if op in (27,28,41) for a in ([args[-1]] if op==27 else ([args[1]] if op==28 else [args[1],args[2]]))}),1)}
    # labels are approximate word addresses; branch targets are exact word PCs.
    lines=[f"-- prototype {pid}, params={params}, constants={len(consts)}"]
    for addr,op,args in rows:
        if addr in labels: lines.append(labels[addr]+":")
        def r(n): return f"r{n}"
        try:
            if op==1: s=f"{r(args[0])} = {fmt(consts[args[1]-1])}"
            elif op==2: s=f"{r(args[0])} = {r(args[1])}"
            elif op==3: s=f"{r(args[0])} = _ENV[{fmt(consts[args[1]-1])}]"
            elif op==4: s=f"_ENV[{fmt(consts[args[0]-1])}] = {r(args[1])}"
            elif op==5: s=f"{r(args[0])} = {{}}"
            elif op==6: s=f"{r(args[0])} = {r(args[1])}[{r(args[2])}]"
            elif op==7: s=f"{r(args[0])}[{r(args[1])}] = {r(args[2])}"
            elif op in (8,9,10):
                sym={8:"-",9:"not ",10:"#"}[op]
                s=f"{r(args[0])} = {sym}{r(args[1])}"
            elif 11<=op<=24:
                sym={11:"+",12:"-",13:"*",14:"/",15:"//",16:"%",17:"^",18:"..",19:"==",20:"~=",21:"<",22:"<=",23:">",24:">="}[op]
                s=f"{r(args[0])} = {r(args[1])} {sym} {r(args[2])}"
            elif op==25:
                dst,fn,count,spread,*argv=args
                s=f"{r(dst)} = {r(fn)}(" + ", ".join(r(x) for x in argv[:count]) + ")"
            elif op==37:
                dst,fn,count,spread,*argv=args
                s=f"{r(dst)} = {r(fn)}(/* packed call */ " + ", ".join(r(x) for x in argv[:count]) + ")"
            elif op==26:
                dst,target,count,*caps=args
                s=f"{r(dst)} = function(...) -- closure -> prototype {target}; captures {caps}"
            elif op==27: s=f"goto {labels.get(args[0], 'PC_'+str(args[0]))}"
            elif op==28: s=f"if not {r(args[0])} then goto {labels.get(args[1], 'PC_'+str(args[1]))} end"
            elif op==29: s="return" if args[0]==0 else f"return {r(args[1])}"
            elif op==30: s=f"cell_{args[0]} = {r(args[1])}"
            elif op==31: s=f"{r(args[0])} = cell_{args[1]}"
            elif op==32: s=f"cell_{args[0]} = {r(args[1])}"
            elif op==33: s=f"{r(args[0])} = upvalue_{args[1]}"
            elif op==34: s=f"{r(args[0])} = pack(" + ", ".join(r(x) for x in args[4:]) + ")"
            elif op==35: s=f"{r(args[0])} = {r(args[1])}[{args[2]}]"
            elif op==36: s=f"{r(args[0])} = varargs()"
            elif op==38: s=f"table_extend({r(args[0])}, {r(args[1])}, {r(args[2])})"
            elif op==39: s=f"{r(args[0])} = numeric_for_check({r(args[1])}, {r(args[2])}, {r(args[3])})"
            elif op==40: s=f"return unpack({r(args[0])})"
            elif op==41:
                cond,t,f=args; s=f"if not {r(cond)} then goto {labels.get(t,'PC_'+str(t))} else goto {labels.get(f,'PC_'+str(f))} end"
            elif op==42:
                dst,k,adddst,a,b=args; s=f"{r(dst)} = {fmt(consts[k-1])}; {r(adddst)} = {r(a)} + {r(b)}"
            elif op==43:
                dst,k,getdst,a,b=args; s=f"{r(dst)} = {fmt(consts[k-1])}; {r(getdst)} = {r(a)}[{r(b)}]"
            elif op==44:
                dst,k,settable,key,val=args; s=f"{r(dst)} = {fmt(consts[k-1])}; {r(settable)}[{r(key)}] = {r(val)}"
            else: s=f"-- {OPS.get(op,'OP'+str(op))} {args}"
        except Exception as e:
            s=f"-- {OPS.get(op,'OP'+str(op))} {args}  [decode error: {e}]"
        lines.append(f"  -- pc {addr:>6}  op {OPS.get(op,'OP'+str(op))}")
        lines.append("  "+s)
    return "\n".join(lines)

def deobfuscate(source):
    p=parse_ravel(source)
    out=[f"-- Ravel v0.7 static deobfuscation; prototypes={len(p)}", ""]
    for pid in sorted(p):
        out.append(decompile_proto(pid,p[pid])); out.append("")
    return "\n".join(out)

@app.get("/")
def index(): return render_template("index.html")

@app.post("/deobfuscate")
def api():
    f=request.files.get("file")
    src=request.form.get("source","")
    if f and f.filename:
        raw=f.read(MAX_BYTES+1)
        if len(raw)>MAX_BYTES: return "File too large (8 MB max).",413
        src=raw.decode("utf-8","replace"); name=f.filename
    else: name="input.lua"
    if not src.strip(): return "No source supplied.",400
    try: result=deobfuscate(src)
    except Exception as e: return f"Deobfuscation failed: {e}",400
    return send_file(io.BytesIO(result.encode()),mimetype="text/plain; charset=utf-8",
                     as_attachment=True,download_name="deobf_"+name.rsplit(".",1)[0]+".lua")

if __name__=="__main__": app.run(host="0.0.0.0",port=10000)
