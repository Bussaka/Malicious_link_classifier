import json
import os

import pytest

import retrain

PASSING = {'browsing_fpr': 0.024, 'phishtank_tpr': 0.80, 'openphish_tpr': 0.89, 'urlhaus_tpr': 0.95}


def test_gates_pass_for_current_model_numbers():
    assert retrain.check_gates(PASSING) == []


@pytest.mark.parametrize('metric, value', [
    ('browsing_fpr', 0.06),     # blocks too many normal pages
    ('phishtank_tpr', 0.40),    # misses live phishing
    ('openphish_tpr', 0.10),
    ('urlhaus_tpr', 0.50),
])
def test_gates_reject_a_regression(metric, value):
    assert retrain.check_gates({**PASSING, metric: value}) == [metric]


def test_gates_are_inclusive_at_the_limit():
    at_limits = {name: limit for name, (_, limit) in retrain.GATES.items()}
    assert retrain.check_gates(at_limits) == []


@pytest.fixture
def project(tmp_path, monkeypatch):
    monkeypatch.setattr(retrain, 'ROOT', str(tmp_path))
    run_dir = tmp_path / 'runs' / 'candidate'
    run_dir.mkdir(parents=True)
    for name in retrain.LIVE_FILES:
        (tmp_path / name).write_text('live ' + name)
        (run_dir / name).write_text('candidate ' + name)
    return tmp_path, run_dir


def test_promote_replaces_live_files_and_keeps_backups(project):
    root, run_dir = project
    retrain.promote(str(run_dir))
    assert (root / 'url_classifier_v4.joblib').read_text() == 'candidate url_classifier_v4.joblib'
    assert (root / 'allowlist.txt').read_text() == 'candidate allowlist.txt'
    assert (root / 'url_classifier_v4.previous.joblib').read_text() == 'live url_classifier_v4.joblib'
    assert (root / 'allowlist.previous.txt').read_text() == 'live allowlist.txt'


def test_promote_without_existing_model(project):
    root, run_dir = project
    os.remove(root / 'url_classifier_v4.joblib')
    retrain.promote(str(run_dir))
    assert (root / 'url_classifier_v4.joblib').read_text() == 'candidate url_classifier_v4.joblib'
    assert not (root / 'url_classifier_v4.previous.joblib').exists()


def test_missing_dataset_is_reported(tmp_path, monkeypatch):
    monkeypatch.setattr(retrain, 'ROOT', str(tmp_path))
    missing = retrain.check_prerequisites(skip_fetch=True)
    assert any('malicious_phish.csv' in m for m in missing)
    assert any('hn_urls.csv' in m for m in missing)
    # Without --skip-fetch the feeds are downloaded, so only the Kaggle file is required
    assert len(retrain.check_prerequisites(skip_fetch=False)) == 1


def test_rejected_run_leaves_live_model_untouched(project, monkeypatch):
    root, run_dir = project
    monkeypatch.setattr(retrain, 'RUNS_DIR', str(root / 'runs'))
    monkeypatch.setattr(retrain, 'check_prerequisites', lambda skip_fetch: [])
    # Stand in for the 10-minute notebook run: write a failing candidate's metrics
    def fake_train(run_dir):
        with open(os.path.join(run_dir, 'metrics.json'), 'w') as f:
            json.dump({**PASSING, 'browsing_fpr': 0.2, 'model': 'G', 'threshold': 0.7}, f)
    monkeypatch.setattr(retrain, 'train', fake_train)
    monkeypatch.setattr('sys.argv', ['retrain.py', '--skip-fetch'])

    assert retrain.main() == 1
    assert (root / 'url_classifier_v4.joblib').read_text() == 'live url_classifier_v4.joblib'
    log = [json.loads(line) for line in (root / 'runs' / 'retrain_log.jsonl').read_text().splitlines()]
    assert log[-1]['status'] == 'rejected' and log[-1]['failed_gates'] == ['browsing_fpr']
