"""
Foundry Security Spec — reference implementation (Streamlit).

Paste a public GitHub repo URL; the app runs the eight core roles of the Cisco
Foundry Security Spec over it and returns a bounded, prioritised, auditable set
of findings with a coverage/"done" signal.

NOT an official Cisco product. Cisco published a specification, not code — this
is one possible implementation of that spec's role model, for enablement/demo.
"""

import json

import pandas as pd
import streamlit as st

from foundry.ingest import fetch_repo, load_sample, parse_repo_url
from foundry.orchestrator import assess, STAGES
from foundry.llm import DEFAULT_MODEL

st.set_page_config(page_title="Foundry Security Spec — Reference Impl",
                   page_icon="🛡️", layout="wide")

SEV_COLOR = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵", "INFO": "⚪"}


def get_secret(name):
    try:
        return st.secrets.get(name)
    except Exception:
        return None


# ----------------------------------------------------------------- sidebar
with st.sidebar:
    st.header("Run configuration")

    secret_key = get_secret("ANTHROPIC_API_KEY")
    if secret_key:
        st.success("API key loaded from secrets")
        api_key = secret_key
    else:
        api_key = st.text_input("Anthropic API key", type="password",
                                help="Needed for the LLM roles (Cartographer "
                                     "narrative, Detector exploratory hunt, "
                                     "Validator). Billed separately from a "
                                     "Claude.ai subscription. Leave blank to run "
                                     "offline (rule sweep only).")

    offline = st.toggle("Offline mode (rule sweep only)",
                        value=not bool(api_key),
                        help="No API calls. Only the CodeGuard rule sweep + "
                             "heuristic validation run. Free and fast.")

    model = st.selectbox("Model", ["claude-sonnet-4-6", "claude-opus-4-8"],
                         index=0, disabled=offline,
                         help="Sonnet for breadth, Opus for the heavier pass.")

    coverage_floor = st.slider("Coverage floor (%)", 50, 100, 80, 5,
                               help="The operator-defined bar the Coverage-Guide "
                                    "uses to decide 'done'.")
    max_llm_calls = st.slider("LLM budget (max calls)", 5, 80, 40, 5,
                              disabled=offline,
                              help="Hard stop so a run can't spend without limit.")
    gh_token = st.text_input("GitHub token (optional)", type="password",
                             help="Raises the GitHub rate limit; required for "
                                  "private repos.")

    st.divider()
    st.caption("Eight core roles: " + " · ".join(STAGES))


# ----------------------------------------------------------------- header
st.title("🛡️ Foundry Security Spec — Reference Implementation")
st.caption("An eight-role agentic code assessment built to the Cisco Foundry "
           "Security Spec (CiscoDevNet/foundry-security-spec).")

st.info(
    "**Scope honesty.** Cisco published a *specification*, not a scanner. This "
    "app is a **demo-grade reference implementation** of the spec's eight core "
    "roles — not an official Cisco product, and not the full ~130 functional "
    "requirements. It reads source only (never executes it) and is meant for "
    "enablement and BFSI demos.", icon="ℹ️")


# ----------------------------------------------------------------- input
col1, col2 = st.columns([3, 1])
with col1:
    repo_url = st.text_input("GitHub repository URL",
                             placeholder="https://github.com/owner/repo")
with col2:
    use_sample = st.checkbox("Use bundled sample",
                             help="Run against the intentionally vulnerable demo "
                                  "app instead of a repo.")

run = st.button("Run assessment", type="primary", use_container_width=True)


def render_report(report):
    s = report["summary"]
    cov = report["coverage"]

    # ---- top-line metrics
    m = st.columns(5)
    m[0].metric("Confirmed findings", s["total_confirmed"])
    m[1].metric("Critical / High",
                f'{s["by_severity"].get("CRITICAL",0)} / {s["by_severity"].get("HIGH",0)}')
    m[2].metric("Coverage", f'{s["coverage_pct"]}%',
                help=f'floor {s["coverage_floor_pct"]}%')
    m[3].metric("Done signal", "✅ DONE" if s["done"] else "⛔ NOT DONE")
    m[4].metric("LLM calls used", s["llm_calls_used"])

    tabs = st.tabs(["Findings", "Coverage & Done", "Attack surface",
                    "Audit trail", "Run log", "Raw JSON"])

    # ---- findings
    with tabs[0]:
        findings = report["findings"]
        if not findings:
            st.success("No confirmed findings after validation. "
                       "(Check coverage before declaring the target clean.)")
        else:
            rows = [{
                "Sev": SEV_COLOR.get(f["severity"].upper(), "") + " " + f["severity"],
                "Priority": f["priority"],
                "Location": f'{f["file"]}:{f["line"]}',
                "CWE": f["cwe"],
                "CodeGuard": f["rule_id"],
                "Source": f["source"],
                "Finding": f["title"],
            } for f in findings]
            st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)
            st.markdown("#### Detail")
            for f in findings:
                with st.expander(
                        f'{SEV_COLOR.get(f["severity"].upper(),"")} '
                        f'[{f["severity"]}] {f["title"]} — {f["file"]}:{f["line"]}'):
                    st.markdown(f'**CWE:** {f["cwe"]} &nbsp; **CodeGuard rule:** '
                                f'{f["rule_id"]} &nbsp; **via:** {f["detector"]} '
                                f'({f["source"]}) &nbsp; **confidence:** {f["confidence"]:.2f}')
                    st.markdown(f'**Rationale:** {f["rationale"]}')
                    if f.get("validation_note"):
                        st.markdown(f'**Validator:** {f["validation_note"]}')
                    if f.get("snippet"):
                        st.code(f["snippet"])

    # ---- coverage
    with tabs[1]:
        st.markdown(f"### {'✅ DONE' if cov['done'] else '⛔ NOT DONE'} "
                    f"— coverage {cov['coverage_pct']}% vs floor {cov['floor_pct']}%")
        cc = st.columns(3)
        cc[0].metric("Ingestion", f'{cov["ingest_pct"]}%',
                     help=f'{cov["repo_files_indexed"]}/{cov["repo_files_total"]} '
                          f'source files indexed')
        cc[1].metric("Rule sweep", f'{cov["sweep_pct"]}%')
        cc[2].metric("Exploratory hunt", f'{cov["hunt_pct"]}%')
        if cov["gaps"]:
            st.markdown("#### Coverage gaps (what we did *not* assess)")
            for g in cov["gaps"]:
                st.warning(g)
        else:
            st.success("No coverage gaps recorded.")
        if report["rule_gaps"]:
            st.markdown("#### Rule gaps — detection→prevention flywheel")
            st.caption("Exploratory findings with no matching CodeGuard rule. "
                       "These are candidates to generalise into new rules so the "
                       "next sweep catches the class.")
            st.dataframe(pd.DataFrame([{
                "Location": f'{g["file"]}:{g["line"]}', "CWE": g["cwe"],
                "Finding": g["title"]} for g in report["rule_gaps"]]),
                use_container_width=True, hide_index=True)

    # ---- attack surface
    with tabs[2]:
        surf = report["summary"]  # surface counts live in metrics; show notes if any
        st.caption("Cartographer output — where untrusted input enters and which "
                   "sinks it can reach.")
        st.json(cov, expanded=False)

    # ---- audit trail
    with tabs[3]:
        st.caption("Provenance chain per finding: detection → triage → validation "
                   "→ publication. This is the auditable trail a CISO/auditor asks for.")
        for f in report["findings"][:50]:
            with st.expander(f'{f["file"]}:{f["line"]} — {f["title"]}  '
                             f'(fingerprint {f["fingerprint"]})'):
                for ev in f["provenance"]:
                    st.text(f'{ev["ts"]}  {ev["role"]:14} {ev["action"]:12} {ev["detail"]}')

    # ---- run log
    with tabs[4]:
        st.code("\n".join(report["run_log"]))

    # ---- raw json
    with tabs[5]:
        blob = json.dumps(report, indent=2)
        st.download_button("Download findings.json", blob,
                           file_name="foundry-findings.json", mime="application/json")
        st.json(report, expanded=False)


if run:
    try:
        if use_sample:
            files = load_sample("samples/vulnerable_app.py")
            meta = {"owner": "bundled", "repo": "vulnerable_app",
                    "source_files_total": 1, "source_files_indexed": 1,
                    "truncated": False, "cap": 1}
            st.caption("Target: bundled intentionally-vulnerable sample.")
        else:
            if not repo_url.strip():
                st.error("Enter a GitHub repo URL, or tick 'Use bundled sample'.")
                st.stop()
            with st.spinner("Fetching repository from GitHub…"):
                owner, repo = parse_repo_url(repo_url)
                files, meta = fetch_repo(repo_url, token=gh_token or None)
            if not files:
                st.error("No assessable source files found in that repo "
                         "(supported: py, js, ts, java, go, rb, php, c/c++, c#, rs).")
                st.stop()
            st.caption(f'Target: {meta["owner"]}/{meta["repo"]} — '
                       f'{meta["source_files_indexed"]}/{meta["source_files_total"]} '
                       f'source files indexed.')

        prog = st.progress(0.0, text="Starting…")

        def on_progress(stage, frac):
            prog.progress(frac, text=f"{stage} complete")

        report = assess(files, meta, api_key=api_key, model=model,
                        offline=offline, max_llm_calls=max_llm_calls,
                        coverage_floor=float(coverage_floor),
                        rules_path="rules", progress=on_progress)
        prog.empty()
        st.success("Assessment complete.")
        render_report(report)

    except ValueError as e:
        st.error(str(e))
    except Exception as e:
        st.exception(e)
else:
    st.markdown(
        "Enter a public GitHub repo and click **Run assessment**, or tick "
        "**Use bundled sample** to see the pipeline find planted vulnerabilities. "
        "Offline mode (rule sweep only) needs no API key.")
