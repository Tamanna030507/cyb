from __future__ import annotations
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend" / "src"))

from data.generator import EventGenerator
from eval.evaluate import run_full_evaluation
from eval.evasion import run_evasion_experiment
from eval.poisoning import run_poisoning_analysis
from eval.llm_bench import run_llm_benchmark
from eval.clear_eval import run_clear_evaluation
from eval.simulation_regression import run_simulation_regression
from models.eve_encrypted import train_eve_prototype

def main():
    data = ROOT / "data" / "synthetic"
    model = ROOT / "models" / "detector.joblib"
    exp = ROOT / "experiments"
    exp.mkdir(exist_ok=True)
    print("generating data...")
    EventGenerator(42).generate_dataset(n_benign_hosts=80, n_attack_hosts=24, evasive_ratio=0.4, out_dir=data)
    print("evaluating...")
    metrics = run_full_evaluation(data / "events.jsonl", model, exp / "eval_results.json")
    print(json.dumps(metrics, indent=2))
    print("evasion...")
    print(json.dumps(run_evasion_experiment(model, data / "events.jsonl", exp / "evasion_results.json"), indent=2))
    print("poisoning...")
    print(json.dumps(run_poisoning_analysis(data / "events.jsonl", exp / "poisoning_results.json"), indent=2))
    print("llm bench...")
    print(json.dumps(run_llm_benchmark(exp / "llm_bench_results.json"), indent=2))
    print("clear...")
    print(json.dumps(run_clear_evaluation(exp), indent=2))
    print("simulation regression...")
    print(json.dumps(run_simulation_regression(model, data / "events.jsonl", exp / "simulation_regression.json"), indent=2))
    print("eve...")
    print(json.dumps(train_eve_prototype(exp / "eve_results.json"), indent=2))
    print("done")

if __name__ == "__main__":
    main()