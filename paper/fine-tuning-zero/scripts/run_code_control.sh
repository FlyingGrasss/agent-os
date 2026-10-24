#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

if [ -d "$HOME/agentos-ft" ]; then
  # shellcheck disable=SC1091
  source "$HOME/agentos-ft/bin/activate"
fi

export AGENTOS_FT_DIR="${AGENTOS_FT_DIR:-$HOME/agentos-ft-data}"
export HF_HOME="${HF_HOME:-$AGENTOS_FT_DIR/hf}"
export HF_HUB_OFFLINE="${HF_HUB_OFFLINE:-1}"
export TOKENIZERS_PARALLELISM=false
export PYTORCH_CUDA_ALLOC_CONF=expandable_segments:True

python -u code_control.py
