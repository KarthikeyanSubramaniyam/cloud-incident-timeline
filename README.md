# Cloud Incident Timeline Reconstructor

<p align="center">
  <img src="https://img.shields.io/badge/Security-Defensive_Auditor-blue?style=flat" alt="Type">
  <img src="https://img.shields.io/badge/Status-Architectural_Showcase-success?style=flat" alt="Status">
  <img src="https://img.shields.io/badge/Python-3.10+-3776AB?style=flat&logo=python&logoColor=white" alt="Python">
</p>

> 🔒 **Technical Showcase & Architecture Specification**  
> *This repository provides public architectural documentation, system specifications, and implementation summaries. Full production source code, internal test suites, and proprietary algorithms are maintained in a secure private repository.*

---

## 📌 Executive Summary

**Category**: Incident Response & Forensics  
**Tech Stack**: `Python 3.10+ · AWS CloudTrail · Digital Forensics · Log Chronology`  

Forensic timeline engine that ingests, deduplicates, and normalizes multi-source CloudTrail logs into high-fidelity investigation chronologies.

---

## 🎯 The Problem It Solves

During active cloud security incidents, raw CloudTrail and audit logs are voluminous, fragmented, and delivered out-of-order. Security analysts waste critical response time manually parsing and correlating timestamp events.

---

## ⚙️ How the Engine Works

1. **Log Ingestion & Parsing**: Ingests raw AWS CloudTrail events and audit streams, parsing complex API call parameters and user identities.
2. **Cryptographic Deduplication**: Generates deterministic hashes across event records (`eventTime`, `eventName`, `userIdentity`, `requestParameters`) to eliminate duplicate log deliveries.
3. **Chronological Event Ordering**: Normalizes heterogeneous timestamp formats into ISO 8601 UTC and constructs an immutable chronological event stream.
4. **Attack Phase Mapping**: Correlates API calls to standard MITRE ATT&CK Cloud phases (Initial Access, Privilege Escalation, Defense Evasion, Exfiltration).
5. **Timeline Synthesis**: Outputs a consolidated investigation timeline highlighting anomalous user activity, burst API usage, and administrative actions.

---

## 🚀 Key Capabilities

- Transforms thousands of raw JSON audit records into clean chronological timelines
- Removes redundant multi-region duplicate records
- Maps user identity transitions (AssumeRole, SwitchRole, ConsoleLogin)
- Exports structured forensic outputs ready for incident responders

---

## 🏗️ System Data Flow & Architecture

```
+-----------------------------------+
|  Target Input / Configuration    |
|  (JSON Snapshots / Policies)      |
+-----------------+-----------------+
                  |
                  v
+-----------------------------------+
|  1. Schema Normalization Engine   |
|  Validates types & formats        |
+-----------------+-----------------+
                  |
                  v
+-----------------------------------+
|  2. Core Analytical Pipeline      |
|  Heuristic rule evaluation,       |
|  invariant checks & drift diffs   |
+-----------------+-----------------+
                  |
                  v
+-----------------------------------+
|  3. Risk Classification           |
|  Assigns severity: INFO / HIGH    |
+-----------------+-----------------+
                  |
                  v
+-----------------------------------+
|  4. Structured Findings & Report  |
|  Root cause, evidence &           |
|  actionable remediation steps     |
+-----------------------------------+
```

---

## 📄 Findings Output Structure

The engine generates structured, machine-parsable JSON reports adhering to this standard audit schema:

```json
{
  "results": [
    {
      "resource": "resource-identifier",
      "severity": "HIGH",
      "check": "CHECK_IDENTIFIER",
      "detail": "Descriptive analysis of the identified security posture issue.",
      "remediation": "Actionable step-by-step guidance to restore compliant state.",
      "evidence": {
        "observed_field": "value",
        "required_policy": "enforced_policy"
      }
    }
  ],
  "count": 1,
  "scope": "Comprehensive defensive security audit"
}
```

---

## 🔒 Source Code & Enterprise Inquiries

To protect proprietary intellectual property and client operational security:
* **Public Repository**: Contains comprehensive architecture specifications, schemas, and design overviews.
* **Private Repository**: Contains the complete production implementation, continuous integration pipelines, and full regression test suites.

For architectural questions or enterprise inquiries, connect via [LinkedIn](https://www.linkedin.com/in/karthikeyansubramaniam04/) or visit the [Portfolio Site](https://karthikeyansubramaniyam.github.io).
