# maeco-mini-conversion — Usage

Converts dynamic analysis reports (organized as per-sample subdirectories) into an OWL ontology dataset.

## Datasets

Pre-built datasets are available for download at [https://alpha.ploszek.com/sharing/FHqWeYeF5](https://alpha.ploszek.com/sharing/FHqWeYeF5).

## Prerequisites

- Python 3.x
- `owlready2` package (`pip install owlready2`)
- Ontology file present at `./ontologies/maeco-mini-merged.owl` (default path)
- Supporting JSON/CSV files in the working directory:
  - `actions.json`
  - `file_regex.json`
  - `registry_regex.json`
  - `deprecated-techniques.csv`


## Ontology

The converted dataset conforms to the MAECO-Lite ontology included in the [ontologies](ontologies) folder:
- [maeco-lite.owl](ontologies/maeco-lite.owl) is the main files that includes four modules (core, actions, files, registry, techniques) from the [ontologies/lite](ontologies/lite) folder.
- [maeco-lite-merged.owl](ontologies/maeco-lite-merged.owl) is a version merging the entities from all modules. It is provided for use with tools that cannot handle includes properly. It is also copied to all datasets produced by the conversion.

## Sample directory structure

Each sample directory is named after the file hash. If multiple analyses exist for the same file, they are named with an additional suffix separated by a dot (`<hash>.<suffix>`). Only the first occurrence of each hash is loaded; duplicates are ignored.

```
malware_dataset/
    a1b2c3d4e5f6.../          # unique sample — loaded
    f6e5d4c3b2a1.../          # unique sample — loaded
    deadbeefcafe.../          # first analysis — loaded
    deadbeefcafe.<hash2>/     # duplicate, ignored
benign_dataset/
    ...
```

## Arguments

| Argument | Required | Default | Description |
|---|---|---|---|
| `--malware-dir` | yes* | — | Directory containing malware sample subdirectories |
| `--benign-dir` | yes* | — | Directory containing benign sample subdirectories |
| `--dataset-name` | yes | — | Name for the output dataset (used as the output file base name) |
| `--num-malware` | no | all | Maximum number of malware samples per variant |
| `--num-benign` | no | all | Maximum number of benign samples per variant |
| `--variants` | no | `1` | Number of randomly sampled dataset variants to generate |
| `--ontology-path` | no | `./ontologies` | Directory containing the ontology file |
| `--ontology-name` | no | `maeco-mini-merged.owl` | Ontology file name |
| `--output-path` | no | `./converted` | Directory where the output dataset will be saved |
| `--from-manifest` | no | — | Path to a `_manifest.json` to reproduce an exact previously generated dataset |
| `--namespace` | no | `https://orbis-security.com/maeco#` | Ontology namespace IRI |
| `--vx-family` | no | all families | One or more `vx_family` values; only malware samples matching at least one are loaded |

\* Required unless `--from-manifest` is used.

## Examples

**Minimal — use all samples from local example directories:**
```bash
python main.py \
  --malware-dir examples-malign/ \
  --benign-dir  examples-benign/ \
  --dataset-name examples
```

**Limit sample count:**
```bash
python main.py \
  --malware-dir /data/malware_dataset/ \
  --benign-dir  /data/benign_dataset/ \
  --dataset-name dataset_500 \
  --num-malware 500 \
  --num-benign  500
```

**Generate multiple random variants:**
```bash
python main.py \
  --malware-dir /data/malware_dataset/ \
  --benign-dir  /data/benign_dataset/ \
  --dataset-name dataset \
  --num-malware 500 \
  --num-benign  500 \
  --variants 10
```

**Custom ontology and output paths:**
```bash
python main.py \
  --malware-dir /data/malware_dataset/ \
  --benign-dir  /data/benign_dataset/ \
  --dataset-name full_dataset \
  --ontology-path /opt/ontologies/ \
  --ontology-name my-ontology.owl \
  --output-path /results/
```

**Filter malware by family:**
```bash
python main.py \
  --malware-dir /data/malware_dataset/ \
  --benign-dir  /data/benign_dataset/ \
  --dataset-name ransomware_only \
  --vx-family "Lazy.Generic" "Win/malicious_confidence_100%"
```

**Reproduce a previously generated dataset from its manifest:**
```bash
python main.py \
  --from-manifest /results/dataset_v3_manifest.json \
  --dataset-name dataset_v3_reproduced \
  --output-path /results/reproduced/
```

**Show help:**
```bash
python main.py --help
```

## Output

Per variant, three files are written to `<output-path>`:

| File | Description |
|---|---|
| `<dataset-name>.owl` | OWL ontology with all mapped individuals |
| `<dataset-name>_examples.json` | MD5 hashes of samples split by class |
| `<dataset-name>_manifest.json` | Exact sample paths used — allows reproducing the dataset later |

The examples file structure:
```json
{
  "positive_examples": ["a1b2c3d4...", "f6e5d4c3..."],
  "negative_examples": ["deadbeef...", "cafebabe..."]
}
```

The manifest file structure:
```json
{
  "malware_paths": ["/data/malware/a1b2c3d4.../", ...],
  "benign_paths":  ["/data/benign/deadbeef.../", ...]
}
```

With multiple variants (`--variants N`) the base name is suffixed: `<dataset-name>_v1.owl`, `<dataset-name>_v1_manifest.json`, ..., `<dataset-name>_vN.owl`, `<dataset-name>_vN_manifest.json`.

Each variant independently draws a random sample from the full pool, so datasets will differ even when the same counts are specified. Use `--from-manifest` to regenerate an identical dataset after ontology changes.

## Experiments

The [experiments](experiments) directory contains two pre-built datasets, each with 1000 samples (500 malware, 500 benign):

| Directory | Ontology | Description |
|---|---|---|
| [experiments/baseline](experiments/baseline) | [baseline.owl](experiments/baseline/baseline.owl) | Dataset built using the MAEC report ontology |
| [experiments/maeco-lite](experiments/maeco-lite) | [maeco-lite.owl](experiments/maeco-lite/maeco-lite.owl) | Dataset built using the MAEC-Lite ontology |

Both directories also contain five cross-validation fold configuration files (`fold_1.conf` – `fold_5.conf`) for use with [DL-Learner](https://github.com/orbis-security/DL-Learner) (only this fork is supported).

**Running all experiments with Docker (recommended):**

A [Dockerfile](experiments/Dockerfile) and [run_experiments.sh](experiments/run_experiments.sh) are provided in the `experiments/` directory. They build DL-Learner from source and run all 40 experiments (2 ontologies × 4 algorithms × 5 folds) sequentially, writing one log file per fold to a mounted output directory.

```bash
cd experiments/

# Build the image — clones and compiles DL-Learner from source (takes ~10 minutes, cached after first run)
docker build -t maeco-experiments .

# Run all 40 experiments; logs land in ./results/
docker run --rm -it -v "$(pwd)/results:/app/results" maeco-experiments
```

Logs are written to `experiments/results/` as `{ontology}_{algorithm}_fold{N}.log`. Press `Ctrl+C` to stop.

**Memory requirements:** The baseline ontology is large and the DL-Learner JVM is configured with 8 GB heap by default. Make sure Docker has at least 10 GB of memory available (Docker Desktop → Settings → Resources). If experiments fail with an out-of-memory error, increase the heap via:

```bash
docker run --rm -it \
  -e JDK_JAVA_OPTIONS="--add-opens java.base/java.lang=ALL-UNNAMED -Xmx12g" \
  -v "$(pwd)/results:/app/results" \
  maeco-experiments
```
