"""Retrains the URL model on fresh threat data and promotes it only if it passes quality gates.

    python retrain.py                  # fetch fresh data, train, check, promote
    python retrain.py --skip-fetch     # reuse data/external/ as it is
    python retrain.py --dry-run        # train and check, but leave the live model alone

Each run trains into runs/<timestamp>/ (model, allowlist, metrics.json and the executed notebook),
so nothing live changes until the candidate has passed. On promotion the previous model and
allowlist are kept as *.previous.* for rollback. Restart the API afterwards to load the new model.
Every run is appended to runs/retrain_log.jsonl. Exit code: 0 promoted (or passed a dry run),
1 failed the gates, 2 could not train.
"""
import argparse
import datetime
import json
import os
import shutil
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
NOTEBOOK = os.path.join(ROOT, 'url_model_v4.ipynb')
RUNS_DIR = os.path.join(ROOT, 'runs')
LIVE_FILES = ['url_classifier_v4.joblib', 'allowlist.txt']

# Minimum held-out quality a candidate needs before it replaces the live model. The live v4 model
# measured 2.4% browsing FPR, 80.4% PhishTank and 89.6% OpenPhish; the gates leave room for
# run-to-run variation from fresh feeds without letting a broken model through.
GATES = {
    'browsing_fpr': ('<=', 0.035),   # normal pages wrongly blocked
    'phishtank_tpr': ('>=', 0.70),   # live phishing caught
    'openphish_tpr': ('>=', 0.80),   # never-trained-on phishing feed caught
    'urlhaus_tpr': ('>=', 0.85),     # malware URLs caught
}


def log(message):
    print(f"[{datetime.datetime.now():%H:%M:%S}] {message}", flush=True)


def check_prerequisites(skip_fetch):
    missing = []
    if not os.path.exists(os.path.join(ROOT, 'malicious_phish.csv')):
        missing.append('malicious_phish.csv (the Kaggle dataset, see README > Retraining)')
    if skip_fetch:
        for name in ['tranco.zip', 'openphish.txt', 'urlhaus_recent.csv', 'urlhaus_full.zip', 'phishtank.csv', 'hn_urls.csv']:
            if not os.path.exists(os.path.join(ROOT, 'data', 'external', name)):
                missing.append(f'data/external/{name} (run without --skip-fetch)')
    return missing


def train(run_dir):
    import nbformat
    from nbclient import NotebookClient

    # The notebook reads its output folder from the environment; the kernel inherits it
    os.environ['THREATSCANNER_OUTPUT_DIR'] = run_dir
    nb = nbformat.read(NOTEBOOK, as_version=4)
    try:
        NotebookClient(nb, timeout=3600, kernel_name='python3', resources={'metadata': {'path': ROOT}}).execute()
    finally:
        # Saved even on failure, so the traceback is in the run folder
        nbformat.write(nb, os.path.join(run_dir, 'url_model_v4.executed.ipynb'))


def check_gates(metrics):
    failures = []
    for name, (op, limit) in GATES.items():
        value = metrics[name]
        ok = value <= limit if op == '<=' else value >= limit
        log(f"  {'pass' if ok else 'FAIL'}  {name:14} {value:7.2%}  (needs {op} {limit:.1%})")
        if not ok:
            failures.append(name)
    return failures


def promote(run_dir):
    for name in LIVE_FILES:
        live = os.path.join(ROOT, name)
        if os.path.exists(live):
            stem, ext = os.path.splitext(name)
            shutil.copy2(live, os.path.join(ROOT, f'{stem}.previous{ext}'))
        shutil.copy2(os.path.join(run_dir, name), live)


def append_log(entry):
    with open(os.path.join(RUNS_DIR, 'retrain_log.jsonl'), 'a', encoding='utf-8') as f:
        f.write(json.dumps(entry) + '\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--skip-fetch', action='store_true', help='reuse the datasets already in data/external/')
    parser.add_argument('--dry-run', action='store_true', help='train and check, but do not replace the live model')
    args = parser.parse_args()

    missing = check_prerequisites(args.skip_fetch)
    if missing:
        log("Cannot retrain, missing:\n  " + "\n  ".join(missing))
        return 2

    run_id = datetime.datetime.now().strftime('%Y%m%d-%H%M%S')
    run_dir = os.path.join(RUNS_DIR, run_id)
    os.makedirs(run_dir)
    entry = {'run': run_id, 'dry_run': args.dry_run}

    try:
        if not args.skip_fetch:
            log("Fetching fresh threat data...")
            import fetch_data
            fetch_data.main()
        log(f"Training (about 10-15 minutes) into runs/{run_id}/ ...")
        train(run_dir)
    except Exception as e:
        log(f"Training failed: {type(e).__name__}: {e}")
        log(f"See runs/{run_id}/url_model_v4.executed.ipynb for the full error")
        append_log({**entry, 'status': 'error', 'error': f'{type(e).__name__}: {e}'[:500]})
        return 2

    with open(os.path.join(run_dir, 'metrics.json'), encoding='utf-8') as f:
        metrics = json.load(f)
    entry['metrics'] = {k: metrics[k] for k in GATES}
    entry['threshold'] = metrics['threshold']

    log(f"Candidate: {metrics['model']} at threshold {metrics['threshold']:.3f}")
    failures = check_gates(metrics)
    if failures:
        log("Candidate rejected; the live model is unchanged.")
        append_log({**entry, 'status': 'rejected', 'failed_gates': failures})
        return 1

    if args.dry_run:
        log("Candidate passed (dry run, live model unchanged).")
        append_log({**entry, 'status': 'passed-dry-run'})
        return 0

    promote(run_dir)
    log("Promoted. Previous model kept as url_classifier_v4.previous.joblib.")
    log("Restart the API to load it:  uvicorn api:app --port 8000")
    append_log({**entry, 'status': 'promoted'})
    return 0


if __name__ == '__main__':
    sys.exit(main())
