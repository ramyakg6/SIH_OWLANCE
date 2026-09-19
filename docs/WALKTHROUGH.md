# RiskLens — Full Walkthrough

← [Back to README](../README.md)

This walks through the complete user flow, screen by screen, from first
entering a domain through to a shareable proof of security posture.

---

## 1. Tell us about the business

![Business Context](screenshots/01-business-context.png)

Industry, employee count, and revenue band aren't decorative — this
calibrates every loss estimate on the dashboard to the business's actual
size and sector instead of a generic average.

## 2. Connect data sources (optional)

![Data Sources](screenshots/02-data-sources.png)

Passive discovery works with nothing connected. Each source added — cloud,
identity provider, EDR, SIEM — fills in the risk graph with real internal
data instead of an external inference, visibly raising the **Depth** meter
and the platform's confidence in its own numbers. Nothing here is required
to get a first score.

## 3. Confirm scope and consent

![Consent](screenshots/03-consent.png)

Passive discovery (certificate logs, DNS, public breach data) runs
automatically — no authorization needed, since it only reads public
records. Active checks require explicit, logged consent before anything
touches the target's live systems. Every scan action is written to a
tamper-evident audit log.

## 4. Live scan in progress

![Scanning](screenshots/04-scanning.png)

Real-time status reflects exactly what's actually running — subdomain
discovery via CT logs, CVE/EPSS/KEV cross-referencing, MFA status pulled
from a connected identity provider — all calibrated for the business's
declared sector. Nothing here claims to have happened if it didn't.

## 5. Dashboard

![Dashboard](screenshots/05-dashboard.png)

One score (0–900, credit-score scale), Expected Annual Loss, potential
savings, and assets monitored — all computed from the live scan. The
Security Posture and Score Build-up charts show exactly which categories
(Identity, Network, Web App, Cloud, Email) are driving the number.

## 6. Vulnerabilities

![Vulnerabilities](screenshots/06-vulnerabilities.png)

Every finding plotted on an Impact × Likelihood risk matrix, with EPSS
driving the likelihood axis. Each finding shows CVSS, EPSS, status, and
remediation cost — free fixes are labeled as such up front.

## 6b. Causal Risk Graph — Adaptive Depth (Simulated)

![Causal Risk Graph (Simulated)](screenshots/10-causal-risk-graph-simulated.png)

*Note: this view uses a simulated dataset ("Synthetic Org (demo)"), not the
live scan shown above — labeled as such in the toggle, since this platform
never blends real and simulated data without saying so.*

This is Attack-Path Collapse in its full form: Threat → Vulnerability →
Asset → Identity → Control Gap → Business Service → Financial Loss. On a
passive-only external scan this chain runs 2–4 hops; the moment an internal
identity or control data source connects, the *same graph* — not a new one —
extends through the Identity and Control Gap layers shown here. This is the
concrete proof behind the platform's "one adaptive engine, not two tiers"
design: there's no separate SME product and enterprise product, just one
causal graph that gets denser as more sources connect.

## 7. Investment Optimizer

![Investment Optimizer](screenshots/07-investment-optimizer.png)

The core differentiator: drag the budget slider and a greedy-ratio
knapsack algorithm live-recalculates which fixes to prioritize, always
surfacing free fixes first. Every recommendation shows its ROSI — in this
case a free fix returning **Infinite ROI**.

## 8. Risk Passport

![Risk Passport](screenshots/08-risk-passport.png)

A shareable, verifiable proof of security posture — for a bank, insurer,
or client — without exposing what's still open. Unlike tools that score a
company secretly, this passport is owned and shared by the business itself,
backed by a tamper-evident hash-chain, and deliverable straight to WhatsApp
so an owner doesn't need to log into a dashboard to see or share it.

## 9. API Documentation

![Swagger Docs](screenshots/09-swagger-docs.png)

Every number on the dashboard traces back to a real, testable endpoint —
consent logging, passive discovery + composite scoring, and the budget
optimizer are all live and independently verifiable via the interactive
Swagger UI.

---

← [Back to README](../README.md)
