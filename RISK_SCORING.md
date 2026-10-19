# Risk Scoring, Logging, and Evaluation

## 1. Purpose

The Member 4 module assigns an explainable risk score to ARP and DNS
detector results, records results in CSV format, and generates evaluation
plots. It is designed to support safe testing and integration.

## 2. Risk classification

Scores range from 0 to 100.

| Score | Risk level |
|---|---|
| 0–29 | LOW |
| 30–69 | MEDIUM |
| 70–100 | HIGH |

Scores outside the range 0–100 are rejected by the risk classification
function.

## 3. Event scoring

Only detector results with status "alert" receive a nonzero score.
Other statuses receive score 0 and LOW risk.

For alert events, the current implementation uses these base scores:

| Event type | Base score |
|---|---:|
| ARP | 60 |
| DNS | 70 |
| Unknown alert type | 40 |

The score is calculated as:

    risk_score = round(base_score * confidence)

If the detector does not supply confidence, the implementation uses
0.75 by default. Confidence must be between 0.0 and 1.0.

The default confidence is a heuristic used for this prototype. It is
not a calibrated probability and should be reviewed against evaluation
results before operational use.

## 4. Dry-run isolation recommendation

The risk engine sets dry_run_isolation to true when an alert's final
risk level is HIGH. This is only a recommendation for demonstration,
logging, and evaluation.

The current implementation does not disable network interfaces,
change firewall rules, or block devices.

## 5. CSV logging

The logger appends results to logs/detection_results.csv. The CSV
includes a timestamp, event type, detector status, risk score, risk
level, source IP, domain, reason, and dry-run recommendation.

A header is written when the file is first created or is empty.

## 6. Evaluation plots

The evaluation script reads the CSV and produces:

- plots/risk_distribution.png: number of events in each risk level.
- plots/detection_timeline.png: risk scores over valid timestamps.

Rows with invalid risk scores are excluded. If no valid risk scores
remain, evaluation stops with an explanatory error. If timestamps are
invalid, those rows are omitted from the timeline plot.

## 7. Tests

The current test suite covers risk classification, event scoring,
invalid confidence values, CSV header creation, appending multiple
events, timestamp preservation, missing event fields, invalid or empty
evaluation input, and plot generation.

Run all tests with:

    python -m unittest discover -s tests -v

## 8. Limitations and next steps

- The scoring thresholds and default confidence are prototype heuristics.
- Repeated-event correlation is not currently implemented.
- Compatibility with the team's final ARP, DNS, and packet-capture
  interfaces must be verified during integration.
- Evaluation quality depends on representative, correctly labeled
  test scenarios.
- Real network isolation is outside the current safe dry-run behavior.
