#!/usr/bin/env bash
# Crea e configura venv2 replicando l'ambiente Python 3.13 funzionante
# (con guesslang+TensorFlow patchati per Python 3.13).
#
# Uso:
#   bash setup_venv2.sh
#
# Idempotente: se venv2 esiste già viene riutilizzato.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$SCRIPT_DIR"
VENV="$ROOT/venv2"
LOCKFILE="$ROOT/requirements_funzionanti.txt"

echo "=== Setup venv2 in $VENV ==="

if [[ ! -f "$LOCKFILE" ]]; then
    echo "ERRORE: lockfile non trovato in $LOCKFILE"
    echo "  Genera prima il file dal PC dove l'ambiente funziona con:"
    echo "    pip freeze > $LOCKFILE"
    exit 1
fi

if [[ ! -d "$VENV" ]]; then
    echo "→ Creazione venv (Python 3.13)…"
    python3 -m venv "$VENV"
fi

# shellcheck disable=SC1091
source "$VENV/bin/activate"

echo "→ Aggiornamento pip, setuptools, wheel…"
pip install --quiet --upgrade pip setuptools wheel

echo "→ Installazione dipendenze lockate…"
pip install --quiet -r "$LOCKFILE"

echo "→ Installazione TensorFlow (≥2.19)…"
pip install --quiet "tensorflow>=2.19"

echo "→ Installazione tensorflow_estimator (compatibilità legacy)…"
pip install --quiet tensorflow_estimator

echo "→ Installazione guesslang (senza deps)…"
pip install --quiet --no-deps guesslang

echo "→ Applicazione patch guesslang per TF moderno…"
python3 - <<'PYEOF'
import os
from pathlib import Path

venv = os.environ['VIRTUAL_ENV']
candidates = list(Path(venv).rglob('guesslang/model.py'))
if not candidates:
    raise SystemExit('ERRORE: guesslang/model.py non trovato')

target = candidates[0]
content = target.read_text()

if '_ModeKeysStub' in content:
    print(f'  patch già applicata a {target}')
else:
    old = '''import tensorflow as tf
from tensorflow.estimator import ModeKeys, Estimator
from tensorflow.python.training.tracking.tracking import AutoTrackable'''
    new = '''import tensorflow as tf
# Patch per TF >=2.16: estimator API, feature_column e AutoTrackable rimossi.
# Servono solo a training/serving in guesslang; per inferenza
# (language_name) basta tf.saved_model.load che esiste ancora.
import types as _types

if not hasattr(tf, 'estimator'):
    _stub_export = _types.ModuleType('export')
    _stub_export.ServingInputReceiver = type('ServingInputReceiver', (), {})
    _stub_estimator = _types.ModuleType('estimator')
    _stub_estimator.RunConfig = type('RunConfig', (), {})
    _stub_estimator.DNNLinearCombinedClassifier = type('DNNLinearCombinedClassifier', (), {})
    _stub_estimator.TrainSpec = type('TrainSpec', (), {})
    _stub_estimator.EvalSpec = type('EvalSpec', (), {})
    _stub_estimator.train_and_evaluate = lambda *a, **k: None
    _stub_estimator.export = _stub_export
    tf.estimator = _stub_estimator

if not hasattr(tf, 'feature_column'):
    _stub_fc = _types.ModuleType('feature_column')
    _stub_fc.categorical_column_with_hash_bucket = lambda *a, **k: None
    _stub_fc.embedding_column = lambda *a, **k: None
    tf.feature_column = _stub_fc

try:
    from tensorflow.estimator import ModeKeys, Estimator
except ImportError:
    class _ModeKeysStub:
        TRAIN = 'train'
        EVAL = 'eval'
        PREDICT = 'predict'
    ModeKeys = _ModeKeysStub
    class Estimator:  # type: ignore
        pass

try:
    from tensorflow.python.training.tracking.tracking import AutoTrackable
except ImportError:
    class AutoTrackable:  # type: ignore
        pass'''
    if old not in content:
        raise SystemExit('ERRORE: blocco di import atteso non trovato in model.py')
    target.write_text(content.replace(old, new))
    print(f'  patch applicata a {target}')
PYEOF

echo "→ Test di import guesslang…"
python3 -c "from guesslang import Guess; g = Guess(); print('  OK, lingua rilevata:', g.language_name('def hello():\n    print(\"hi\")'))"

echo
echo "=== venv2 pronto ==="
echo "Per attivarlo:"
echo "  source $VENV/bin/activate"
