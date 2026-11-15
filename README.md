# CodeShield

A Streamlit-based educational static code-security review prototype.

## Run locally

Requires Python 3.10+.

```bash
python -m venv .venv
# Windows:
.venv\Scripts\activate
# macOS/Linux:
source .venv/bin/activate

pip install -r requirements.txt
streamlit run app.py
```

## Deploy on Streamlit Community Cloud

1. Create a GitHub repository named `codeshield`.
2. Upload the contents of this folder to the repository root.
3. Open https://share.streamlit.io/ and sign in with GitHub.
4. Create an app, select the repository and `main` branch.
5. Set the main file path to `app.py`, then deploy.

## Features

- Python, Go, C, C++, Java, JavaScript, and HTML pattern checks.
- Source editor and source-file upload.
- Line-level findings with severity, confidence labels, explanations, and recommendations.
- Severity filtering.
- JSON, CSV, and SARIF report exports.
- No uploaded code is executed or compiled.

## Important limitations

CodeShield is an educational research prototype, not a production security scanner. It uses a small set of regular-expression heuristics. It does not perform full parsing, control-flow analysis, data-flow/taint analysis, or prove exploitability. It can produce false positives and false negatives. A clean report does not prove code is secure.

Do not upload real credentials, private keys, personal data, or confidential source code.

## Suggested research milestones

1. Build a labelled benchmark of safe and intentionally vulnerable toy programs.
2. Measure precision, recall, F1 score, and line-location accuracy.
3. Compare results with established static-analysis tools on the same benchmark.
4. Introduce parser-aware and data-flow analysis after the baseline evaluation.
