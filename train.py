import argparse
import csv
import json
from collections import Counter
from pathlib import Path
from tempfile import NamedTemporaryFile

from sklearn.tree import DecisionTreeClassifier

from detector import FEATURE_NAMES, MODEL_PATH, extract_features, load_model
from evaluate import evaluate, is_test_site, print_results, read_urls


def export_nodes(tree):
    # Branches store a question and two child indexes. Leaves store a score.
    nodes = []
    for index, feature in enumerate(tree.feature):
        if feature < 0:
            legitimate, phishing = tree.value[index][0]
            nodes.append({"score": float(phishing / (legitimate + phishing))})
        else:
            nodes.append({
                "feature": int(feature),
                "cutoff": float(tree.threshold[index]),
                "left": int(tree.children_left[index]),
                "right": int(tree.children_right[index]),
            })
    return nodes


def train(phiusiil_path, url_phish_path):
    sources = ((phiusiil_path, "0"), (url_phish_path, "1"))
    features, labels, groups = [], [], []

    # Keep every URL from the same site on the same side of the split.
    for path, phishing_label in sources:
        source_groups = set()
        for url, phishing in read_urls(path, phishing_label):
            try:
                _, site, values = extract_features(url)
            except ValueError:
                continue
            if not is_test_site(site):
                features.append(values)
                labels.append(phishing)
                source_groups.add(phishing)
                groups.append((path, phishing))
        if len(source_groups) != 2:
            raise ValueError(f"{path.name} must have both labels in the training split.")

    # Give the two classes in each source equal influence during fitting.
    group_sizes = Counter(groups)
    sample_weights = [len(groups) / (len(group_sizes) * group_sizes[group]) for group in groups]
    classifier = DecisionTreeClassifier(max_depth=10, min_samples_leaf=100, random_state=0)
    classifier.fit(features, labels, sample_weight=sample_weights)

    # Save the fitted tree so app.py can run without scikit-learn.
    saved = {
        "features": list(FEATURE_NAMES),
        "nodes": export_nodes(classifier.tree_),
        "threshold": 0.4,
    }
    with NamedTemporaryFile(mode="w", dir=MODEL_PATH.parent, encoding="utf-8", delete=False) as output:
        json.dump(saved, output, indent=2)
        output.write("\n")
    Path(output.name).replace(MODEL_PATH)
    load_model.cache_clear()
    print(f"Training URLs: {len(labels):,}")
    print(f"Saved model to {MODEL_PATH}")

    # Score held-out examples using the saved model the GUI loads.
    total_counts, total_skipped = Counter(), Counter()
    for path, phishing_label in sources:
        print(f"\nHeld-out results for {path.name}")
        counts, skipped = evaluate(path, phishing_label, held_out=True)
        print_results(counts, skipped)
        total_counts.update(counts)
        total_skipped.update(skipped)
    print("\nCombined held-out results")
    print_results(total_counts, total_skipped)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train and test the phishing URL model.")
    parser.add_argument("phiusiil_csv", type=Path)
    parser.add_argument("url_phish_v2_csv", type=Path)
    args = parser.parse_args()
    try:
        train(args.phiusiil_csv, args.url_phish_v2_csv)
    except (OSError, ValueError, csv.Error) as error:
        parser.error(str(error))
