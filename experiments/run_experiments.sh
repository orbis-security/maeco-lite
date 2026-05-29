#!/usr/bin/env bash
set -euo pipefail

trap 'echo ""; echo "Interrupted."; kill $(jobs -p) 2>/dev/null; exit 130' INT TERM

RESULTS_DIR="${RESULTS_DIR:-/app/results}"
DL_CLI="/opt/dl-learner/bin/cli"
EXPERIMENTS_DIR="/app/experiments"

mkdir -p "$RESULTS_DIR"

ONTOLOGIES=(baseline maeco-lite)
ALGORITHMS=(celoe ocel parcel spacel)
FOLDS=(1 2 3 4 5)

total=$(( ${#ONTOLOGIES[@]} * ${#ALGORITHMS[@]} * ${#FOLDS[@]} ))
count=0

# Extract the last occurrence of a named metric from a log file.
# Handles metrics with spaces (e.g. "True positives", "FP rate").
extract_metric() {
    local log_file="$1"
    local metric_name="$2"
    grep "^${metric_name}: " "$log_file" 2>/dev/null | tail -1 | cut -d' ' -f2-
}

# Given a list of numeric values, print "mean ± stddev" (sample stddev, n-1).
compute_stats() {
    printf '%s\n' "$@" | awk '
        ($1 == $1+0) { sum += $1; sumsq += $1*$1; n++ }
        END {
            if (n == 0) { print "N/A"; exit }
            mean = sum / n
            variance = (n > 1) ? (sumsq - n * mean * mean) / (n - 1) : 0
            stddev = sqrt(variance < 0 ? 0 : variance)
            printf "%.4f +/- %.4f\n", mean, stddev
        }
    '
}

# Parse all fold logs for a given ontology+algorithm and write a summary file.
aggregate_folds() {
    local ontology="$1"
    local algorithm="$2"
    local summary_file="${RESULTS_DIR}/${ontology}_${algorithm}_cv_summary.txt"

    local metrics=(
        "Accuracy"
        "Precission"
        "Recall"
        "Specificity"
        "FP rate"
        "F-measure"
        "True positives"
        "True negatives"
        "False positives"
        "False negatives"
    )

    {
        echo "Cross-validation summary: ${ontology} / ${algorithm}"
        echo "Folds: ${#FOLDS[@]}"
        echo "Date: $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
        echo ""
        printf "%-22s  %-20s  %s\n" "Metric" "Mean +/- Std" "Values per fold"
        printf "%-22s  %-20s  %s\n" "----------------------" "--------------------" "---------------"

        for metric in "${metrics[@]}"; do
            local values=()
            for fold in "${FOLDS[@]}"; do
                local log_file="${RESULTS_DIR}/${ontology}_${algorithm}_fold${fold}.log"
                if [[ -f "$log_file" ]]; then
                    local val
                    val=$(extract_metric "$log_file" "$metric")
                    [[ -n "$val" ]] && values+=("$val")
                fi
            done

            local stats fold_vals
            if [[ ${#values[@]} -gt 0 ]]; then
                stats=$(compute_stats "${values[@]}")
                fold_vals="${values[*]}"
            else
                stats="N/A"
                fold_vals="-"
            fi
            printf "%-22s  %-20s  %s\n" "$metric" "$stats" "$fold_vals"
        done
    } | tee "$summary_file"

    echo ""
}

for ontology in "${ONTOLOGIES[@]}"; do
  for algorithm in "${ALGORITHMS[@]}"; do
    for fold in "${FOLDS[@]}"; do
      count=$(( count + 1 ))
      config_dir="${EXPERIMENTS_DIR}/${ontology}/${algorithm}"
      config_file="fold_${fold}.conf"
      log_file="${RESULTS_DIR}/${ontology}_${algorithm}_fold${fold}.log"

      echo "[${count}/${total}] ${ontology}/${algorithm}/fold_${fold} -> ${log_file}"
      (cd "$config_dir" && "$DL_CLI" "$config_file") > "$log_file" 2>&1 \
        && echo "  done" \
        || echo "  FAILED (exit $?)"
    done

    echo "--- CV summary: ${ontology}/${algorithm} ---"
    aggregate_folds "$ontology" "$algorithm"
  done
done

echo ""
echo "All experiments finished. Logs and summaries in ${RESULTS_DIR}."
