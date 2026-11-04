"""Compares a sonda scan with what Clippy reported on the same sources: per rule,
how many findings agree, and what each side has alone. Only files Clippy
compiled count, and a struct field definition it flags (a derive macro's
span) is set aside. See tools/clippy-oracle/README.md."""
import json,collections,re,os,sys
# usage: compare.py SONDA_REPORT.json RESULTS.json SOURCES_DIR [DUMP_DIR]
# SONDA_REPORT is `sonda scan SOURCES_DIR --format json`; RESULTS.json is run.py's.
sonda=json.load(open(sys.argv[1]))
orc=json.load(open(sys.argv[2]))
P=sys.argv[3].rstrip('/')+'/'
compiled={c:set(v['compiled']) | {f for _, f, _ in v['findings']} for c,v in orc.items()}
# A file Clippy reported on was compiled, whatever the dependency info listed (example targets).
fielddef=re.compile(r'^\s*(?:pub(?:\([a-z]+\))?\s+)?([a-z_][a-z0-9_]*)\s*:\s*([^=]+?),?\s*(?://.*)?$')
def is_definition(line):
    # `x: u32,` defines a field; `x: x,` initializes one, which is what the lint is about.
    m=fielddef.match(line)
    return bool(m) and m.group(1)!=m.group(2).strip()
def src(c,f,l):
    try: return open(P+c+'/'+f,errors='replace').read().split('\n')[l-1]
    except Exception: return ''
mine=collections.defaultdict(set); unj=collections.Counter()
for i in sonda['issues']:
    if not i['rule'].startswith('rs/'): continue
    c,_,f=i['path'].partition('/')
    if c not in orc: continue
    if f in compiled[c]: mine[i['rule']].add((c,f,i['line']))
    else: unj[i['rule']]+=1
clip=collections.defaultdict(set); derive=collections.Counter()
for c,v in orc.items():
    for rule,f,l in v['findings']:
        if rule=='rs/redundant-field-name' and is_definition(src(c,f,l)): derive[rule]+=1; continue
        clip[rule].add((c,f,l))
near=lambda x,T:any((x[0],x[1],x[2]+d) in T for d in (-1,0,1))
tot=collections.Counter()
print(f"{'rule':28} {'sonda':>5} {'clippy':>6} {'agree':>5} {'sonda-only':>10} {'clippy-only':>11} {'precision':>9} {'recall':>6} {'(unjudged,derive)':>18}")
for rule in sorted(set(mine)|set(clip)|set(unj)):
    a,b=mine[rule],clip[rule]
    ta=sum(1 for x in a if near(x,b)); tb=sum(1 for y in b if near(y,a))
    p=f'{100*ta/len(a):.0f}%' if a else '-'; r=f'{100*tb/len(b):.0f}%' if b else '-'
    print(f"{rule:28} {len(a):5} {len(b):6} {ta:5} {len(a)-ta:10} {len(b)-tb:11} {p:>9} {r:>6} {unj[rule]:>9},{derive[rule]:>3}")
if len(sys.argv) > 4:
    # An optional directory to write each side's findings to, to read the differences.
    os.makedirs(sys.argv[4], exist_ok=True)
    json.dump({r: sorted(v) for r, v in mine.items()}, open(sys.argv[4] + '/sonda.json', 'w'))
    json.dump({r: sorted(v) for r, v in clip.items()}, open(sys.argv[4] + '/clippy.json', 'w'))
print('failed crates:',{c:v['err'][:50] for c,v in orc.items() if v['rc'] not in (0,101)})
