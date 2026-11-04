"""Runs Clippy on each crate under /in, inside the oracle container, and writes
/out/results.json: per crate, its exit code, the files it compiled and each
finding of the lints below. tools/clippy-oracle/README.md has the command.
"""
import glob
import json
import os
import shutil
import subprocess
import time

# sonda rule id -> the Clippy lint it follows. Add a rule's pair here when it lands.
LINTS = {
    'rs/self-assignment': 'self_assignment',
    'rs/identical-operands': 'eq_op',
    'rs/same-condition-in-chain': 'ifs_same_cond',
    'rs/skip-zero': 'iter_skip_zero',
    'rs/step-by-zero': 'iterator_step_by_zero',
    'rs/splitn-limit': 'suspicious_splitn',
    'rs/modulo-one': 'modulo_one',
    'rs/resize-to-zero': 'vec_resize_to_zero',
    'rs/option-env-unwrap': 'option_env_unwrap',
    'rs/uninit-assumed-init': 'uninit_assumed_init',
    'rs/replace-with-uninit': 'mem_replace_with_uninit',
    'rs/null-pointer-from-zero': 'zero_ptr',
    'rs/redundant-field-name': 'redundant_field_names',
    'rs/let-and-return': 'let_and_return',
    'rs/match-on-bool': 'match_bool',
    'rs/else-if-without-else': 'else_if_without_else',
    'rs/wildcard-import': 'wildcard_imports',
    'rs/unnecessary-semicolon': 'unnecessary_semicolon',
    'rs/invisible-characters': 'invisible_characters',
    'rs/approximate-constant': 'approx_constant',
    'rs/never-loop': 'never_loop',
    'rs/no-effect': 'no_effect',
    'rs/vec-init-then-push': 'vec_init_then_push',
    'rs/misnamed-getter': 'misnamed_getters',
    'rs/almost-swapped': 'almost_swapped',
    'rs/iter-next-loop': 'iter_next_loop',
    'rs/inline-without-body': 'inline_fn_without_body',
    'rs/mistyped-literal-suffix': 'mistyped_literal_suffixes',
    'rs/reversed-empty-range': 'reversed_empty_ranges',
    'rs/erasing-op': 'erasing_op',
    'rs/unreadable-literal': 'unreadable_literal',
    'rs/print-stdout': 'print_stdout',
    'rs/derive-ord-with-manual-partial-ord': 'derive_ord_xor_partial_ord',
    'rs/derived-hash-with-manual-eq': 'derived_hash_with_manual_eq',
    'rs/uninit-vec': 'uninit_vec',
}
RULE_OF = {lint: rule for rule, lint in LINTS.items()}
TARGET = '/home/oracle/target'
ENV = dict(os.environ, CARGO_TARGET_DIR=TARGET, CARGO_TERM_COLOR='never', RUSTFLAGS='--cap-lints=warn')
ARGS = ['cargo', 'clippy', '--quiet', '--message-format=json', '--all-targets', '--', '-A', 'clippy::all']
for lint in LINTS.values():
    ARGS += ['--force-warn', 'clippy::' + lint]


def message(line):
    """The compiler message on one line of Cargo's JSON output, or None."""
    try:
        m = json.loads(line)
    except ValueError:
        return None
    return m['message'] if m.get('reason') == 'compiler-message' else None


def finding(line):
    """(rule, file, line) of the lint on one line of Cargo's JSON output, or None."""
    msg = message(line)
    code = ((msg or {}).get('code') or {}).get('code', '')
    rule = RULE_OF.get(code[8:]) if code.startswith('clippy::') else None
    primary = next((sp for sp in msg['spans'] if sp['is_primary']), None) if rule else None
    return (rule, primary['file_name'], primary['line_start']) if primary else None


def compiled_files(crate_dir, started):
    """The files this run compiled: Cargo's dependency info lists each target's sources."""
    compiled = set()
    infos = glob.glob(TARGET + '/*/deps/*.d') + glob.glob(TARGET + '/*/examples/*.d')
    for dep in infos:
        if os.path.getmtime(dep) < started:
            continue
        with open(dep) as f:
            tokens = f.read().replace('\\\n', ' ').split()
        for tok in tokens:
            tok = tok.rstrip(':')
            if not tok.endswith('.rs'):
                continue
            # The crate's own sources are listed relative to it; dependencies' are absolute.
            if tok.startswith(crate_dir + '/'):
                compiled.add(tok[len(crate_dir) + 1:])
            elif not tok.startswith(('/', '..')) and os.path.exists(crate_dir + '/' + tok):
                compiled.add(tok)
    return compiled


def clippy(crate_dir):
    started = time.time() - 1
    try:
        p = subprocess.run(ARGS, cwd=crate_dir, env=ENV, capture_output=True, text=True, timeout=600)
    except subprocess.TimeoutExpired:
        return {'compiled': [], 'rc': -1, 'err': 'timeout', 'findings': []}
    findings = {f for f in map(finding, p.stdout.splitlines()) if f}
    err = p.stderr.strip().splitlines()[-1][:160] if p.returncode and p.stderr.strip() else ''
    return {'compiled': sorted(compiled_files(crate_dir, started)), 'rc': p.returncode, 'err': err, 'findings': sorted(findings)}


def main():
    with open('/in/_crates.json') as f:
        crates = json.load(f)
    results = {}
    for c in crates:
        d = '/home/oracle/work/' + c
        shutil.copytree('/in/' + c, d, dirs_exist_ok=True)
        results[c] = clippy(d)
        shutil.rmtree(d, ignore_errors=True)
        with open('/out/results.json', 'w') as f:
            json.dump(results, f)
        print(c, results[c]['rc'], len(results[c]['findings']), results[c]['err'][:80], flush=True)
    print('DONE', flush=True)


if __name__ == '__main__':
    main()
