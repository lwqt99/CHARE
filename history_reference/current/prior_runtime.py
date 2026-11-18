"""Locate and load the exact previous increment without copying its code.

Set CHARE_R2_ROOT or pass prior_root to select an extracted round-2 package.
Only the three declared, hash-pinned Python modules are loaded.
"""
from pathlib import Path
import hashlib
import importlib.util
import os
import sys

EXPECTED = {
    'auditor/auditor.py': '9c276ecd6da28fca60fb69d01af87c3703f37ef359337840e4acf508a9d46455',
    'curve_replay/toy_pairing.py': '295ebf5a36440109ceae3a147f106e66376843b5c10990cac1e5e417e0a4bf5f',
    'curve_replay/replay_checks.py': 'c31e89f4c98fa26cc309de6836e01c0f7601a7454b078873aa7edb6ecf9c74c2',
}

def locate_prior(prior_root=None):
    here = Path(__file__).resolve().parent
    explicit = prior_root or os.environ.get('CHARE_R2_ROOT')
    candidates = [Path(explicit).expanduser()] if explicit else [
        here.parent/'review_round2',
        here.parent/'CHARE_CCS_Increment_20261114_02',
    ]
    for candidate in candidates:
        if all((candidate/name).is_file() for name in EXPECTED):
            for name,expected in EXPECTED.items():
                actual=hashlib.sha256((candidate/name).read_bytes()).hexdigest()
                if actual != expected:
                    raise ValueError(f'Previous-increment module hash mismatch: {name}')
            return candidate.resolve()
    raise FileNotFoundError('Extract the previous increment and set CHARE_R2_ROOT to its root directory.')

def _load(relative, module_name, prior_root=None):
    root=locate_prior(prior_root)
    path=root/relative
    previous=sys.modules.get(module_name)
    if previous is not None:
        if Path(previous.__file__).resolve() != path:
            raise RuntimeError(f'Module name already belongs to another file: {module_name}')
        return previous
    spec=importlib.util.spec_from_file_location(module_name,path)
    module=importlib.util.module_from_spec(spec)
    sys.modules[module_name]=module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        sys.modules.pop(module_name,None)
        raise
    return module

def load_auditor(prior_root=None):
    return _load('auditor/auditor.py','chare_r2_auditor',prior_root)

def load_pairing(prior_root=None):
    return _load('curve_replay/toy_pairing.py','toy_pairing',prior_root)

def load_replay(prior_root=None):
    load_pairing(prior_root)
    return _load('curve_replay/replay_checks.py','chare_r2_replay',prior_root)
