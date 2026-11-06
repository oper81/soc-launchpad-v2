# soc-launchpad-v2

A training range for entering SOC work (Junior SOC Analyst, L1). Repository:
`soc-launchpad-v2`; package and command: `socsim`. Author:
[oper81](https://github.com/oper81).

> **Honest disclaimer:** the logs here are **synthetic** — generated from
> templates of real formats (sshd, syslog, kern/iptables, nginx combined,
> auditd SYSCALL), not captured from real attacks. This is a **training
> range**, not a SIEM and not a detection system. All "attacks" are confined
> to an isolated lab on your own VMs.

## What it is and why

A stand that mimics L1 work: the engine generates a stream of normal events
(99%) plus rare malicious campaigns, an offline detector catches them with
rules (100100–100140), and the evaluator compares results against ground
truth. You act as L1: triage the alert queue, assign verdicts; the script
scores your verdicts and rule quality.

What it does **not** do: replace Wazuh, "detect in production", or guarantee
parity with real telemetry. It is a learning stand.

## Quick start (Windows PowerShell)

```powershell
python -m socsim --help
python -m socsim demo
```

`demo` runs the whole pipeline on the mini-scenario (`scenarios/demo.json`)
and prints a summary. Details: [`docs/quickstart.md`](docs/quickstart.md).

Optional (after install): `pip install -e .` → the `socsim` command (same thing).

## Full pipeline (your own data)

```powershell
# 1. Generate a scenario (7 days, 6 campaigns)
python -m socsim generate --scenario scenarios\default.json --out labs

# 2. Detect (no tuning)
python -m socsim detect --events labs\events.jsonl --out labs\alerts_before.jsonl

# 3. Evaluate
python -m socsim evaluate --alerts labs\alerts_before.jsonl --events labs\events.jsonl --truth labs\groundtruth.jsonl

# 4. L1 queue + verdicts.csv template
python -m socsim queue --alerts labs\alerts_before.jsonl --verdicts labs\verdicts.csv

# 5. Fill verdicts.csv (true_positive / false_positive / benign), then:
python -m socsim evaluate --alerts labs\alerts_before.jsonl --events labs\events.jsonl --truth labs\groundtruth.jsonl --verdicts labs\verdicts.csv
```

## Results on the synthetic stand (seed=2026, 7 days)

> **Disclaimer without which the numbers lie:** this is **synthetic** data,
> the background is calm, the alert count is small (11–13). `precision = 1.0`
> after tuning **does not** mean production-quality rules. Numbers are
> reproducible with the same seed and the same code version.

| Metric | Before tuning | After tuning |
|---|---|---|
| Total alerts | 13 | 11 |
| TP | 11 | 11 |
| FP on traps | 2 | **0** |
| FP on background | 0 | 0 |
| Precision | 0.846 | **1.0** |
| Campaigns detected | 4 of 5 | **4 of 5** |
| `slow_port_scan` (evasive) | not detected | not detected (by design) |

Honest reading: tuning removed 2 false positives on traps (`nessus_scan`,
`dev_tmp_binary`) and **lost no true positives** on this scenario. Details:
[`docs/tuning.md`](docs/tuning.md).

## Layout

```
socsim/            engine (stdlib only): model, render, background, traps,
                   campaigns, generator, detector, evaluator, queue, CLI
scenarios/         scenarios (JSON) and format description
tests/             unit tests (unittest)
wazuh/             Wazuh rules/decoders + samples for wazuh-logtest
sigma/             Sigma rule versions
windows/           Sysmon fragment, Wazuh rules for Windows, Atomic runbook
docs/              quickstart, tuning, scenarios, report-example, playbooks/
labs/              run artifacts (gitignored)
```

## What is verified and what is not (honest)

**Verified on Python 3.14.4 (Windows), locally:**
- 64 unit tests (`python -m unittest discover -s tests -v`) — `OK`;
- generation, detector, evaluator, queue, CLI, `demo`;
- XML syntax of `wazuh/rules/local_rules.xml`,
  `wazuh/decoders/local_decoder.xml`, `windows/rules/windows_rules.xml`;
- XML syntax of fragments (`wazuh/ossec/ossec.conf.fragment.xml`,
  `windows/sysmon/sysmon-config-fragment.xml`) — wrapped, since they are
  fragments;
- YAML syntax of `sigma/*.yml`.

**NOT verified (needs infrastructure absent in the dev environment):**
- **Wazuh:** behaviour of rules 100100–100140 and decoders. Needs a Wazuh VM
  and `wazuh-logtest`; see [`docs/lab-setup.md`](docs/lab-setup.md).
  **No Docker**, so the path is a VM (Ubuntu + Wazuh Manager/Agent).
- **Windows part:** `windows_rules.xml`, Sysmon filters, Atomic Red Team.
  Needs a Windows VM. `if_sid` values (60122, 60106, …) are **not guaranteed**
  — verify with `wazuh-logtest`.
- **Sigma conversion:** `sigma convert -t wazuh` **does not work** without a
  backend plugin (absent here). YAML parses; conversion does not.
- **`replay --speed > 1`:** compresses correlation windows; evasive campaigns
  (`slow_port_scan`) may stop being evasive. A warning is printed to stderr.

**Honest resume wording:** "Training stand: synthetic telemetry + offline
detector + evaluation. 64 unit tests. Wazuh rules/decoders, Sigma and Windows
parts are included as artifacts; not verified in live infrastructure".

## Limitations (honest)

- Telemetry is **synthetic**; format realism is approximate; no guarantee of
  matching a specific daemon version.
- The tuning exclusion for `100120` is **broad** (`198.18.0.0/15`). In a real
  SOC this is not acceptable without analysis: an attacker from that range
  would be missed. Fine for the stand, since attacker IPs are RFC 5737 only.
- `auditd` lines are simplified; real auditd is richer.
- `precision = 1.0` is an artifact of the calm synthetic background, not of
  rule quality.

## Security

- Attacker IPs: documentation ranges only
  (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`).
- Legitimate external clients: `198.18.0.0/15`.
- No real malicious code. All "attacks" are confined to an isolated lab on
  your own VMs.

## License

MIT, see [`LICENSE`](LICENSE).