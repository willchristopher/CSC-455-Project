import argparse
import csv
from hashlib import sha256
from pathlib import Path

from detector import analyze_url, load_model


def read_urls(csv_path, phishing_label):
    # Convert each dataset's label convention to True for phishing.
    with csv_path.open(encoding="utf-8-sig", newline="") as source:
        rows = csv.DictReader(source)
        columns = {name.strip().lower(): name for name in rows.fieldnames or []}
        if not {"url", "label"} <= columns.keys():
            raise ValueError("The CSV must contain URL and label columns.")
        for row in rows:
            label = (row[columns["label"]] or "").strip()
            if label not in {"0", "1"}:
                raise ValueError(f"CSV line {rows.line_num} must have a label of 0 or 1.")
            yield row[columns["url"]] or "", label == phishing_label


def is_test_site(site):
    # The first hash byte gives a repeatable split of about 80% train and 20% test.
    return sha256(site.encode("ascii")).digest()[0] < 51


def evaluate(csv_path, phishing_label="0", held_out=False):
    counts = dict.fromkeys(("TP", "FP", "FN", "TN"), 0)
    skipped = {True: 0, False: 0}

    for url, phishing in read_urls(csv_path, phishing_label):
        try:
            result = analyze_url(url)
        except ValueError:
            skipped[phishing] += 1
            continue
        if held_out and not is_test_site(result.site):
            continue

        # Count correct predictions and the two kinds of classification errors.
        if phishing:
            counts["TP" if result.flagged else "FN"] += 1
        else:
            counts["FP" if result.flagged else "TN"] += 1
    return counts, skipped


def percentage(count, total):
    return f"{count / total:.2%}" if total else "n/a"


def print_results(counts, skipped):
    tp, fp, fn, tn = (counts[key] for key in ("TP", "FP", "FN", "TN"))
    total = tp + fp + fn + tn
    print(f"Rows evaluated: {total:,} | Phishing threshold: {load_model().threshold:.0%}")
    print(f"Invalid URLs in source CSV(s): {sum(skipped.values()):,} "
          f"({skipped[True]:,} phishing, {skipped[False]:,} legitimate)")
    print(f"{'Dataset label':<18}{'Flagged':>14}{'Unflagged':>14}")
    print(f"{'Phishing':<18}{tp:>14,}{fn:>14,}")
    print(f"{'Legitimate':<18}{fp:>14,}{tn:>14,}")
    print(f"Accuracy: {percentage(tp + tn, total)}")
    print(f"Precision: {percentage(tp, tp + fp)} | Phishing recall: {percentage(tp, tp + fn)}")
    print(f"False positives: {fp:,} of {fp + tn:,} legitimate ({percentage(fp, fp + tn)})")
    print(f"False negatives: {fn:,} of {fn + tp:,} phishing ({percentage(fn, fn + tp)})")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Evaluate the saved model on a labeled URL CSV.")
    parser.add_argument("csv_file", type=Path, help="Path to a CSV with URL and label columns")
    parser.add_argument("--phishing-label", choices=("0", "1"), default="0",
                        help="Phishing label (0 for PhiUSIIL, 1 for URL-Phish v2)")
    parser.add_argument("--held-out", action="store_true",
                        help="Use only the test sites when evaluating a training source")
    args = parser.parse_args()
    try:
        counts, skipped = evaluate(args.csv_file, args.phishing_label, args.held_out)
        print_results(counts, skipped)
    except (OSError, ValueError, csv.Error) as error:
        parser.error(str(error))
