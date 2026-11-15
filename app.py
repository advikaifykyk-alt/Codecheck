import csv
import io
import json
import re
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Dict, List, Tuple

import streamlit as st

st.set_page_config(
    page_title="CodeShield | Static Security Review",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ---------- Visual system ----------
st.markdown(
    """
    <style>
      @import url('https://fonts.googleapis.com/css2?family=DM+Mono:wght@400;500&family=Manrope:wght@400;500;600;700;800&display=swap');
      html, body, [class*="css"] { font-family: 'Manrope', sans-serif; }
      .stApp { background: #0b1020; color: #e8edf7; }
      [data-testid="stHeader"] { background: rgba(11,16,32,0.92); }
      [data-testid="stSidebar"] { background: #10182b; border-right: 1px solid #26324a; }
      [data-testid="stSidebar"] * { color: #dce5f5; }
      h1,h2,h3 { letter-spacing: -0.04em; }
      .hero {
        padding: 1.35rem 1.5rem; border: 1px solid #293653; border-radius: 18px;
        background: linear-gradient(120deg, #172746 0%, #111a2e 58%, #142b36 100%);
        margin-bottom: 1.15rem;
      }
      .eyebrow { color:#72e0c1; font-size:.72rem; font-weight:800; letter-spacing:.16em; text-transform:uppercase; }
      .hero h1 { margin:.25rem 0 .35rem 0; font-size:2.35rem; color:#f4f7ff; }
      .hero p { color:#aebbd2; margin:0; max-width:850px; }
      .muted { color:#9eacc5; }
      .metric-card {
        background:#121d32; border:1px solid #283754; border-radius:14px;
        padding:14px 16px; min-height:94px;
      }
      .metric-label { color:#9eacc5; font-size:.78rem; font-weight:700; }
      .metric-value { color:#f5f8ff; font-size:1.8rem; font-weight:800; line-height:1.25; }
      .finding {
        border:1px solid #2b3954; border-radius:13px; padding:14px 16px;
        background:#111b2e; margin:.55rem 0;
      }
      .tag { display:inline-block; border-radius:999px; padding:3px 9px; font-size:.7rem; font-weight:800; margin-right:7px; }
      .tag-high { background:#51252e; color:#ff9aa8; }
      .tag-medium { background:#4c3821; color:#ffd08a; }
      .tag-low { background:#4b4524; color:#f2e38b; }
      .tag-info { background:#203d58; color:#9bd4ff; }
      .finding-title { font-weight:800; color:#f3f6ff; }
      .finding-meta { color:#9eacc5; font-family:'DM Mono',monospace; font-size:.75rem; }
      div.stButton > button[kind="primary"] {
        background:linear-gradient(90deg,#23b99a,#1d9eaa); color:#06151b;
        border:0; font-weight:800; border-radius:10px; min-height:2.8rem;
      }
      div.stButton > button { border-radius:10px; }
      .stTextArea textarea, .stCode, code { font-family:'DM Mono',monospace !important; }
      .footer { border-top:1px solid #26324a; padding-top:14px; color:#8291ab; font-size:.76rem; }
      [data-testid="stMetric"] { background:#121d32; padding:12px 14px; border:1px solid #283754; border-radius:12px; }
      [data-testid="stMetricLabel"] { color:#9eacc5; }
      [data-testid="stMetricValue"] { color:#f4f7ff; }
    </style>
    """,
    unsafe_allow_html=True,
)

# ---------- Detection rules ----------
@dataclass
class Finding:
    rule_id: str
    language: str
    line: int
    severity: str
    confidence: str
    title: str
    snippet: str
    explanation: str
    recommendation: str

LANGUAGES = ["Python", "Go", "C", "C++", "Java", "JavaScript", "HTML"]

# Pattern checks are deliberately transparent review heuristics, not proof of exploitability.
RULES: Dict[str, List[Tuple[str, str, str, str, str, str, str]]] = {
    "Python": [
        ("PY001", r"\beval\s*\(", "High", "High", "Use of eval()", "eval() evaluates a string as Python code. If untrusted input reaches it, unintended code may execute.", "Avoid eval(). Parse only the specific data format expected, or use a restricted expression parser."),
        ("PY002", r"\bexec\s*\(", "High", "High", "Use of exec()", "exec() executes dynamically supplied Python code and can be dangerous when input is not fully trusted.", "Replace dynamic execution with explicit functions or a safe, limited operation mapping."),
        ("PY003", r"\bpickle\.loads?\s*\(", "High", "High", "Potentially unsafe pickle deserialization", "Loading pickle data from an untrusted source can execute attacker-controlled code.", "Never unpickle untrusted data. Prefer a data-only format such as JSON and validate its schema."),
        ("PY004", r"\bsubprocess\.(?:run|Popen|call)\s*\([^,\n]*\+", "High", "Medium", "Possible command construction from concatenated input", "Building a command by concatenating strings can allow command injection if any part is user-controlled.", "Pass an argument list to subprocess, validate each argument, and avoid shell=True."),
        ("PY005", r"\bcursor\.execute\s*\([^,\n]*(?:%s|\.format\s*\(|f['\"])", "Medium", "Medium", "Possible dynamically constructed SQL", "Formatting values into SQL can permit SQL injection. This pattern is a review hint, not proof.", "Use parameterized queries and pass values separately from the SQL statement."),
    ],
    "Go": [
        ("GO001", r"\bexec\.Command\s*\([^,\n]*\+", "High", "Medium", "Possible command construction from concatenated input", "Concatenating input into a command can create command-injection risk.", "Use fixed executable names and validated argument slices. Avoid passing untrusted text as a shell command."),
        ("GO002", r"\b(fmt\.Sprintf|fmt\.Fprintf)\s*\([^;\n]*SELECT", "Medium", "Medium", "SQL query built with formatting", "Formatting user-controlled values into SQL may permit SQL injection.", "Use database/sql parameter placeholders and pass values as separate arguments."),
        ("GO003", r"\bInsecureSkipVerify\s*:\s*true", "High", "High", "TLS certificate verification disabled", "Disabling certificate verification makes server impersonation easier.", "Keep certificate verification enabled and configure a trusted certificate authority when needed."),
        ("GO004", r"\bhttp\.ListenAndServe\s*\(", "Info", "Low", "HTTP server configuration to review", "Production servers should use suitable timeouts, request limits, and secure transport settings.", "Review server timeouts, TLS termination, request limits, and deployment configuration."),
    ],
    "C": [
        ("C001", r"\bgets\s*\(", "High", "High", "Unsafe gets() call", "gets() does not know the destination buffer size and can cause a buffer overflow.", "Use fgets() with the actual buffer size and validate the returned input."),
        ("C002", r"\bstrcpy\s*\(", "Medium", "High", "Unbounded string copy", "strcpy() does not check destination capacity and may overflow a buffer.", "Use a size-aware approach and verify bounds. Prefer safer APIs and explicit length checks."),
        ("C003", r"\bstrcat\s*\(", "Medium", "High", "Unbounded string concatenation", "strcat() does not check remaining destination capacity.", "Track buffer length and remaining capacity before appending."),
        ("C004", r"\bsprintf\s*\(", "Medium", "High", "Unbounded formatted output", "sprintf() can write beyond the destination buffer if the formatted result is too long.", "Use snprintf() with the destination buffer size and check for truncation."),
        ("C005", r"\b(system|popen)\s*\(", "High", "Medium", "Shell command execution", "Passing constructed or untrusted text to a shell can allow command injection.", "Avoid shell execution where possible. If unavoidable, use fixed commands and strict input validation."),
    ],
    "C++": [
        ("CPP001", r"\bgets\s*\(", "High", "High", "Unsafe gets() call", "gets() does not know the destination buffer size and can cause a buffer overflow.", "Use bounded input operations and validate lengths."),
        ("CPP002", r"\bstrcpy\s*\(", "Medium", "High", "Unbounded string copy", "strcpy() does not check destination capacity and may overflow a buffer.", "Prefer std::string or use explicit bounds-checked copying."),
        ("CPP003", r"\bsprintf\s*\(", "Medium", "High", "Unbounded formatted output", "sprintf() can write beyond the destination buffer.", "Use safer formatting facilities and enforce destination-size limits."),
        ("CPP004", r"\b(system|popen)\s*\(", "High", "Medium", "Shell command execution", "Constructing shell commands with untrusted input can lead to command injection.", "Avoid shell execution or use fixed commands with validated arguments."),
        ("CPP005", r"\bnew\s+\w+\s*\[", "Info", "Low", "Manual dynamic allocation to review", "Manual memory management can lead to leaks or invalid memory access if ownership is mishandled.", "Consider standard containers such as std::vector and RAII-managed resources."),
    ],
    "Java": [
        ("JAVA001", r"\bRuntime\.getRuntime\s*\(\s*\)\.exec\s*\(", "High", "Medium", "Process execution", "Executing constructed commands can create command-injection risk if untrusted input is included.", "Avoid building commands from user input. Use ProcessBuilder with a fixed executable and validated arguments."),
        ("JAVA002", r"\bStatement\s+\w+.*\bexecute(Query|Update)?\s*\(", "Medium", "Low", "SQL Statement to review", "SQL built through Statement may be vulnerable if user input is concatenated into the query.", "Use PreparedStatement with placeholders and pass values separately."),
        ("JAVA003", r"\bObjectInputStream\b", "Medium", "Medium", "Java object deserialization to review", "Deserializing untrusted Java objects can expose applications to dangerous gadget chains.", "Avoid deserializing untrusted data. Use validated data-transfer formats."),
        ("JAVA004", r"\bsetHostnameVerifier\s*\(", "Info", "Low", "Hostname verification override", "Custom hostname verification can weaken TLS security if it accepts invalid hostnames.", "Use the platform's default hostname verification unless an exception is carefully reviewed."),
    ],
    "JavaScript": [
        ("JS001", r"\beval\s*\(", "High", "High", "Use of eval()", "eval() interprets a string as JavaScript code. Untrusted input can become executable code.", "Avoid eval(). Use explicit logic or JSON.parse() for JSON data."),
        ("JS002", r"\binnerHTML\s*=", "Medium", "Medium", "Potentially unsafe HTML insertion", "Assigning untrusted content to innerHTML can create cross-site scripting (XSS).", "Use textContent for plain text, or sanitize HTML with a well-maintained sanitizer."),
        ("JS003", r"\bdocument\.write\s*\(", "Medium", "Medium", "Use of document.write()", "Writing dynamic content into a page can create injection risks and interfere with page behavior.", "Prefer DOM APIs such as createElement() and textContent."),
        ("JS004", r"\bchild_process\.(?:exec|execSync)\s*\(", "High", "Medium", "Shell command execution", "Shell commands built from untrusted input can allow command injection.", "Prefer execFile/spawn with a fixed executable and validated argument arrays."),
    ],
    "HTML": [
        ("HTML001", r"\bon\w+\s*=", "Medium", "Medium", "Inline event handler", "Inline event handlers can make content-security controls harder to enforce and may become dangerous when combined with untrusted markup.", "Prefer addEventListener() in trusted scripts and keep untrusted content out of executable attributes."),
        ("HTML002", r"\bjavascript\s*:", "High", "High", "JavaScript URL", "A javascript: URL can execute script when activated and is dangerous if constructed from untrusted content.", "Avoid javascript: URLs. Use normal links and event listeners."),
        ("HTML003", r"\b(?:src|href)\s*=\s*['\"]http://", "Low", "High", "Insecure HTTP resource reference", "An HTTP resource can be modified in transit and may create mixed-content problems on HTTPS pages.", "Use HTTPS resources where supported."),
        ("HTML004", r"\btarget\s*=\s*['\"]_blank['\"]", "Info", "High", "New-tab link to review", "Links opened in a new tab should generally prevent access to the opener window.", "Add rel=\"noopener noreferrer\" to links using target=\"_blank\"."),
    ],
}

SECRET_PATTERN = re.compile(
    r"""(?i)\b(api[_-]?key|secret|password|token)\b\s*[:=]\s*['"][^'"]{6,}['"]"""
)

SAMPLES = {
    "Python": 'user_input = input("Expression: ")\\nresult = eval(user_input)\\nprint(result)',
    "Go": 'cmd := "sh -c " + userInput\\nexec.Command(cmd)',
    "C": 'char name[10];\\ngets(name);',
    "C++": 'char buffer[20];\\nstrcpy(buffer, userInput);',
    "Java": 'String query = "SELECT * FROM users WHERE name = \'" + name + "\'";\nStatement st = connection.createStatement();\nst.executeQuery(query);',
    "JavaScript": 'const output = document.getElementById("result");\\noutput.innerHTML = userInput;\\nconst x = eval(userInput);',
    "HTML": '<a href="javascript:runCode()" target="_blank">Open</a>',
}

def scan_code(code: str, language: str) -> List[Finding]:
    findings: List[Finding] = []
    lines = code.splitlines()
    for rule_id, pattern, severity, confidence, title, explanation, recommendation in RULES[language]:
        for match in re.finditer(pattern, code, flags=re.IGNORECASE):
            line_no = code.count("\n", 0, match.start()) + 1
            snippet = lines[line_no - 1].strip() if 0 < line_no <= len(lines) else ""
            findings.append(Finding(rule_id, language, line_no, severity, confidence, title, snippet, explanation, recommendation))
    for match in SECRET_PATTERN.finditer(code):
        line_no = code.count("\n", 0, match.start()) + 1
        snippet = lines[line_no - 1].strip() if 0 < line_no <= len(lines) else ""
        findings.append(Finding("GEN001", language, line_no, "High", "Low", "Possible hard-coded secret", snippet,
            "A value that resembles a password, token, or key appears directly in source code. This heuristic can flag harmless examples.",
            "Do not commit real credentials. Move secrets to an appropriate secret manager and rotate any real credential that may have been exposed."))
    order = {"High": 0, "Medium": 1, "Low": 2, "Info": 3}
    return sorted(findings, key=lambda f: (f.line, order.get(f.severity, 9), f.rule_id))

def findings_to_sarif(findings: List[Finding], filename: str) -> dict:
    level_map = {"High": "error", "Medium": "warning", "Low": "note", "Info": "note"}
    rules_by_id = {}
    results = []
    for f in findings:
        rules_by_id[f.rule_id] = {"id": f.rule_id, "name": f.title, "shortDescription": {"text": f.title}}
        results.append({
            "ruleId": f.rule_id,
            "level": level_map.get(f.severity, "note"),
            "message": {"text": f.explanation},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": filename or "pasted-source"},
                    "region": {"startLine": f.line}
                }
            }]
        })
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{"tool": {"driver": {"name": "CodeShield", "rules": list(rules_by_id.values())}}, "results": results}]
    }

def make_csv(findings: List[Finding]) -> bytes:
    out = io.StringIO()
    writer = csv.DictWriter(out, fieldnames=list(Finding.__dataclass_fields__.keys()))
    writer.writeheader()
    for f in findings:
        writer.writerow(asdict(f))
    return out.getvalue().encode("utf-8")

def severity_class(severity: str) -> str:
    return {"High": "high", "Medium": "medium", "Low": "low", "Info": "info"}.get(severity, "info")

# ---------- Session state / callbacks ----------
if "code_text" not in st.session_state:
    st.session_state.code_text = SAMPLES["Python"].replace("\\n", "\n")
if "last_findings" not in st.session_state:
    st.session_state.last_findings = None
if "last_language" not in st.session_state:
    st.session_state.last_language = "Python"
if "last_filename" not in st.session_state:
    st.session_state.last_filename = "pasted-source"

def load_sample():
    lang = st.session_state.get("language_select", "Python")
    st.session_state.code_text = SAMPLES[lang].replace("\\n", "\n")
    st.session_state.last_findings = None

# ---------- Sidebar ----------
with st.sidebar:
    st.markdown("## 🛡️ CodeShield")
    st.caption("STATIC SECURITY REVIEW")
    st.markdown("---")
    language = st.selectbox("Source language", LANGUAGES, key="language_select")
    st.markdown("### Analysis profile")
    st.selectbox("Rule set", ["Core heuristic checks"], disabled=True)
    st.markdown("---")
    st.markdown("**Supported languages**")
    st.caption("Python · Go · C · C++ · Java · JavaScript · HTML")
    st.markdown("---")
    st.caption("Files are read as text. Code is never executed or compiled by this app.")

# ---------- Main interface ----------
st.markdown(
    """
    <div class="hero">
      <div class="eyebrow">Developer security workspace</div>
      <h1>Find risky patterns before they ship.</h1>
      <p>Review source code for selected security-sensitive patterns, inspect line-level findings, and export a report for further analysis.</p>
    </div>
    """,
    unsafe_allow_html=True,
)
tab_scan, tab_about = st.tabs(["🔎  Scanner", "ⓘ  About & limitations"])

with tab_scan:
    top_left, top_right = st.columns([1.25, 1], gap="large")
    with top_left:
        st.subheader("1. Add source code")
        uploaded = st.file_uploader(
            "Upload a source file",
            type=["py", "go", "c", "h", "cpp", "cc", "hpp", "java", "js", "html", "htm"],
            help="Supported text source files only. Maximum size: 1 MB.",
        )
        if uploaded is not None:
            if uploaded.size > 1_000_000:
                st.error("This prototype accepts files up to 1 MB.")
            else:
                try:
                    uploaded_text = uploaded.getvalue().decode("utf-8")
                    if st.session_state.get("active_upload") != uploaded.name:
                        st.session_state.code_text = uploaded_text
                        st.session_state.active_upload = uploaded.name
                        st.session_state.last_findings = None
                    st.caption(f"Loaded: `{uploaded.name}` · {uploaded.size:,} bytes")
                except UnicodeDecodeError:
                    st.error("This prototype accepts UTF-8 text source files.")
        st.text_area(
            "Paste or edit source",
            key="code_text",
            height=330,
            label_visibility="collapsed",
            placeholder="Paste your source code here...",
        )
        c1, c2 = st.columns([1, 1])
        with c1:
            st.button("↻ Load example", on_click=load_sample, use_container_width=True)
        with c2:
            scan_clicked = st.button("🔍  Scan source", type="primary", use_container_width=True)
    with top_right:
        st.subheader("2. Review workflow")
        st.markdown(
            """
            <div class="finding">
              <div class="finding-title">01 / Select language</div>
              <div class="muted">Choose the language that matches the uploaded or pasted source.</div>
            </div>
            <div class="finding">
              <div class="finding-title">02 / Run static checks</div>
              <div class="muted">CodeShield searches for a curated set of security-sensitive patterns.</div>
            </div>
            <div class="finding">
              <div class="finding-title">03 / Investigate findings</div>
              <div class="muted">Review severity, line number, context, and suggested remediation.</div>
            </div>
            <div class="finding">
              <div class="finding-title">04 / Export your report</div>
              <div class="muted">Download findings as JSON, CSV, or SARIF for further review.</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        st.info("CodeShield treats submitted code as text. It does not execute, compile, or send code to an external analysis service.")

    if scan_clicked:
        source = st.session_state.code_text
        if not source.strip():
            st.warning("Add source code before starting a scan.")
        elif len(source.encode("utf-8")) > 1_000_000:
            st.error("Source is larger than the 1 MB prototype limit.")
        else:
            results = scan_code(source, language)
            st.session_state.last_findings = results
            st.session_state.last_language = language
            st.session_state.last_filename = uploaded.name if uploaded is not None else "pasted-source"
            st.session_state.last_scan_time = datetime.now(timezone.utc).isoformat()
            st.success("Scan complete. Review the results below.")

    findings = st.session_state.last_findings
    if findings is not None:
        st.markdown("---")
        st.subheader("3. Scan report")
        high = sum(f.severity == "High" for f in findings)
        medium = sum(f.severity == "Medium" for f in findings)
        low = sum(f.severity == "Low" for f in findings)
        info = sum(f.severity == "Info" for f in findings)
        m1, m2, m3, m4, m5 = st.columns(5)
        m1.metric("Total findings", len(findings))
        m2.metric("High", high)
        m3.metric("Medium", medium)
        m4.metric("Low", low)
        m5.metric("Info", info)

        report_a, report_b = st.columns([1.25, 1], gap="large")
        with report_a:
            st.markdown(f"**File:** `{st.session_state.last_filename}`  ")
            st.markdown(f"**Language:** `{st.session_state.last_language}`  ")
            st.markdown(f"**Scanned:** `{st.session_state.get('last_scan_time', '—')}`")
        with report_b:
            json_data = json.dumps({
                "tool": "CodeShield",
                "prototype": True,
                "language": st.session_state.last_language,
                "filename": st.session_state.last_filename,
                "scan_time_utc": st.session_state.get("last_scan_time"),
                "summary": {"total": len(findings), "high": high, "medium": medium, "low": low, "info": info},
                "findings": [asdict(f) for f in findings],
            }, indent=2)
            sarif_data = json.dumps(findings_to_sarif(findings, st.session_state.last_filename), indent=2)
            d1, d2, d3 = st.columns(3)
            d1.download_button("JSON", json_data, file_name="codeshield-report.json", mime="application/json", use_container_width=True)
            d2.download_button("CSV", make_csv(findings), file_name="codeshield-findings.csv", mime="text/csv", use_container_width=True)
            d3.download_button("SARIF", sarif_data, file_name="codeshield-report.sarif", mime="application/sarif+json", use_container_width=True)

        if not findings:
            st.success("No patterns matched this rule set. This does not establish that the source code is secure.")
        else:
            severity_filter = st.multiselect("Filter by severity", ["High", "Medium", "Low", "Info"], default=["High", "Medium", "Low", "Info"])
            visible = [f for f in findings if f.severity in severity_filter]
            st.caption(f"Showing {len(visible)} of {len(findings)} findings")
            for index, finding in enumerate(visible, start=1):
                tag = severity_class(finding.severity)
                with st.expander(f"{finding.title}  ·  {finding.severity}  ·  Line {finding.line}", expanded=(index == 1)):
                    st.markdown(
                        f'<span class="tag tag-{tag}">{finding.severity.upper()}</span>'
                        f'<span class="finding-meta">{finding.rule_id} · {finding.language} · confidence: {finding.confidence}</span>',
                        unsafe_allow_html=True,
                    )
                    st.markdown("**Source context**")
                    st.code(finding.snippet or "(empty source line)", language=None)
                    st.markdown("**Why this was flagged**")
                    st.write(finding.explanation)
                    st.markdown("**Suggested next step**")
                    st.write(finding.recommendation)
        st.caption("A finding is a prompt for human review, not confirmation that a vulnerability is exploitable.")

with tab_about:
    st.subheader("What CodeShield does")
    st.write("CodeShield is an educational static-analysis research prototype. It checks source text against a small, transparent collection of regular-expression heuristics and reports matching lines.")
    st.subheader("What it does not do")
    st.warning(
        "This is not a production security scanner. It does not parse complete language grammars, "
        "perform control-flow or data-flow analysis, execute tests, or prove exploitability. "
        "It can produce both false positives and false negatives. A clean report does not prove code is secure."
    )
    st.subheader("Privacy and safe use")
    st.write("The app processes source text in the Streamlit session and does not intentionally transmit it to a third-party scanning API. Do not upload real secrets, credentials, private keys, personal data, or confidential source code.")
    st.subheader("Research evaluation roadmap")
    st.markdown(
        """
        1. Build a labelled benchmark of safe and intentionally vulnerable toy examples.
        2. Measure precision, recall, F1 score, and line-location accuracy.
        3. Compare results with established static-analysis tools on the same benchmark.
        4. Add parser-aware analysis only after a reproducible baseline exists.
        """
    )

st.markdown(
    '<div class="footer">CodeShield · Student research prototype · Pattern-based static checks only · Findings require human review.</div>',
    unsafe_allow_html=True,
)
