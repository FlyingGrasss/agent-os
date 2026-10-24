# Fine-tuning zero: reproduction files

This directory contains the scripts and raw results for the note
[`../fine-tuning-zero.md`](../fine-tuning-zero.md).

The experiment fine-tunes `unsloth/Llama-3.2-3B-Instruct` with 4-bit QLoRA on 180 synthetic
summarization examples, then runs the original attack set and several adaptive sets. The
headline result is in the note; this README is only about reproducing it.

The note text is licensed under CC BY 4.0. The scripts are under the repository’s MIT
license.

## What is here

```text
scripts/
  train_eval.py          train the adapter, run the original 120-prompt evaluation
  adaptive_eval.py       640-prompt content sweep (32 families x 20 docs)
  wrapper_eval.py        280-prompt wrapper/channel sweep (14 variants x 20 docs)
  mutation_eval.py       75-prompt targeted mutation sweep (15 variants x 5 docs)
  final_probe.py         50-prompt separate-turn probe (10 variants x 5 docs)
  password_probe.py      15-prompt password probe (3 variants x 5 docs)
  code_control.py        10-prompt code control (2 variants x 5 docs)
  run_all.sh             run the sequence above
  run_code_control.sh    run only the code control
  requirements.txt       Python dependencies
results/
  results.json           original base/fine-tuned results and samples
  adaptive_results.json  640-prompt content results
  wrapper_results.json   280-prompt wrapper/channel results
  mutation_results.json  75-prompt mutation results
  final_probe.json       50-prompt separate-turn results
  password_probe.json    15-prompt password results
  code_control.json      code control results
```

The LoRA adapter is not committed. It is a generated artifact and is large enough that it
belongs in a release or a separate artifact store, not in the repository. Train it with
`train_eval.py`.

## Environment

The runs used WSL2 with a CUDA GPU, Python 3.11, and a virtual environment at
`~/agentos-ft`. A 4-bit 3B model needs roughly 6-8 GB of VRAM for inference; training needs
more. The scripts use `bitsandbytes`, so a CUDA GPU is required.

```bash
python -m venv ~/agentos-ft
source ~/agentos-ft/bin/activate
pip install -r scripts/requirements.txt
```

If you already have a working environment, skip the venv and install only what is missing.

## Data directory

All scripts read `AGENTOS_FT_DIR`, which defaults to `~/agentos-ft-data`. The directory
holds:

```text
~/agentos-ft-data/
  lora/                  adapter and tokenizer written by train_eval.py
  hf/                    Hugging Face cache
  results.json
  adaptive_results.json
  ...
```

The base model is public; set `HF_HOME` to a cache directory. The wrapper scripts set
`HF_HUB_OFFLINE=1` by default because the test environment had a local cache. Remove that
export on the first run if the model is not cached.

## Run

From this directory:

```bash
export AGENTOS_FT_DIR="$HOME/agentos-ft-data"
export HF_HOME="$AGENTOS_FT_DIR/hf"
bash scripts/run_all.sh
```

`run_all.sh` trains the adapter, then runs the adaptive sets. To reuse an existing adapter
and skip training:

```bash
SKIP_TRAIN=1 bash scripts/run_all.sh
```

To run only the code control:

```bash
bash scripts/run_code_control.sh
```

The scripts are deterministic (`do_sample=False`), so the same model, adapter, prompts, and
library versions should reproduce the same outputs. A different GPU, quantization kernel, or
`transformers` version can change the generated tokens at the margin; the note reports the
observed outputs, not a guarantee of bit-for-bit reproduction.

## Reading the results

Each JSON file has a top-level `marker` and a list of experiment entries. For the adaptive
sets, each entry has `n`, `marker`/`contains`, and per-document `rows` with the generated
text. The note quotes the rows that contain `ZEBRA-917`.

The original `results.json` has `base_train`, `base_attack`, `ft_train`, `ft_attack`, and
the benign lists. The fine-tuned attack rows are the 0/120 result; the base rows are the
12/120 comparison.

## Scope and safety

The prompts include adversarial text. Run them against the local fine-tuned model only. Do
not point these scripts at a production model or an agent with real tools, credentials, or
network access. The password probe is a text-generation test, not a credential attack; it
shows that the model will repeat a planted field, not that any real account is compromised.

The result is a case study: one model, one adapter, one seed, one training set. It is not a
population estimate and it does not show that fine-tuning can never help. It shows that a
zero on one attack family is not evidence of elimination, and that a different attack family
can still get exact compliance.
