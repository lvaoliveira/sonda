"""Runs Clippy on each crate under /in, inside the oracle container, and writes
/out/results.json: per crate, its exit code, the files it compiled and each
finding of the lints below. tools/clippy-oracle/README.md has the command.
"""
import glob,json,os,shutil,subprocess,time
# sonda rule id -> the Clippy lint it follows. Add a rule's pair here when it lands.
LINTS={'rs/self-assignment':'self_assignment','rs/identical-operands':'eq_op','rs/same-condition-in-chain':'ifs_same_cond','rs/skip-zero':'iter_skip_zero','rs/step-by-zero':'iterator_step_by_zero','rs/splitn-limit':'suspicious_splitn','rs/modulo-one':'modulo_one','rs/resize-to-zero':'vec_resize_to_zero','rs/option-env-unwrap':'option_env_unwrap','rs/uninit-assumed-init':'uninit_assumed_init','rs/replace-with-uninit':'mem_replace_with_uninit','rs/null-pointer-from-zero':'zero_ptr','rs/redundant-field-name':'redundant_field_names','rs/let-and-return':'let_and_return','rs/match-on-bool':'match_bool','rs/else-if-without-else':'else_if_without_else',
 'rs/wildcard-import':'wildcard_imports','rs/unnecessary-semicolon':'unnecessary_semicolon','rs/invisible-characters':'invisible_characters','rs/approximate-constant':'approx_constant','rs/never-loop':'never_loop','rs/no-effect':'no_effect','rs/vec-init-then-push':'vec_init_then_push','rs/misnamed-getter':'misnamed_getters','rs/almost-swapped':'almost_swapped','rs/iter-next-loop':'iter_next_loop','rs/inline-without-body':'inline_fn_without_body','rs/mistyped-literal-suffix':'mistyped_literal_suffixes','rs/reversed-empty-range':'reversed_empty_ranges','rs/erasing-op':'erasing_op','rs/unreadable-literal':'unreadable_literal','rs/print-stdout':'print_stdout','rs/derive-ord-with-manual-partial-ord':'derive_ord_xor_partial_ord','rs/derived-hash-with-manual-eq':'derived_hash_with_manual_eq','rs/uninit-vec':'uninit_vec'}
inv={v:k for k,v in LINTS.items()}
crates=json.load(open('/in/_crates.json'))
results={}
env=dict(os.environ,CARGO_TARGET_DIR='/home/oracle/target',CARGO_TERM_COLOR='never',RUSTFLAGS='--cap-lints=warn')
for c in crates:
    d='/home/oracle/work/'+c
    started=time.time()-1
    shutil.copytree('/in/'+c,d,dirs_exist_ok=True)
    args=['cargo','clippy','--quiet','--message-format=json','--all-targets','--','-A','clippy::all']+sum([['--force-warn','clippy::'+l] for l in LINTS.values()],[])
    try:
        p=subprocess.run(args,cwd=d,env=env,capture_output=True,text=True,timeout=600)
        out=set()
        for line in p.stdout.splitlines():
            try: m=json.loads(line)
            except Exception: continue
            if m.get('reason')!='compiler-message': continue
            msg=m['message']; code=(msg.get('code') or {}).get('code','')
            if not code.startswith('clippy::') or code[8:] not in inv: continue
            for sp in msg['spans']:
                if sp['is_primary']:
                    out.add((inv[code[8:]],sp['file_name'],sp['line_start'])); break
        # The files this run compiled: Cargo's dependency info lists each target's sources.
        compiled=set()
        for dep in glob.glob('/home/oracle/target/*/deps/*.d') + glob.glob('/home/oracle/target/*/examples/*.d'):
            if os.path.getmtime(dep)<started: continue
            for tok in open(dep).read().replace('\\\n',' ').split():
                tok=tok.rstrip(':')
                if not tok.endswith('.rs'): continue
                # The crate's own sources are listed relative to it; dependencies' are absolute.
                if tok.startswith(d+'/'): compiled.add(tok[len(d)+1:])
                elif not tok.startswith(('/', '..')) and os.path.exists(d+'/'+tok): compiled.add(tok)
        results[c]={'compiled':sorted(compiled),'rc':p.returncode,'err':p.stderr.strip().splitlines()[-1][:160] if p.returncode and p.stderr.strip() else '','findings':sorted(out)}
    except subprocess.TimeoutExpired:
        results[c]={'compiled':[],'rc':-1,'err':'timeout','findings':[]}
    shutil.rmtree(d,ignore_errors=True)
    json.dump(results,open('/out/results.json','w'))
    print(c,results[c]['rc'],len(results[c]['findings']),results[c]['err'][:80],flush=True)
print('DONE',flush=True)
