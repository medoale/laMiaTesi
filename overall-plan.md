---
program: Dynamic Benchmarks for Blue and Red Team Cyber-Agents
supervisor: Matteo
last_revised: 2026-05-13
revision: 6
---

# Overall Plan

## Program vision

We aim to build a _dynamic_ benchmark for evaluating blue and red team cyber-agents. The benchmark is dynamic because it grows over time: new CVEs (and possibly undisclosed vulnerabilities) are added to the pool as we find them. Each environment in the pool is a containerised service. It contains a flag that can only be captured by exploiting a known vulnerability of the service. The red-team agent's goal is to capture the flag; the blue-team agent's goal is to defend the environment and detect the attack from logs.

The program contributes along three connected axes:

1. **Sourcing.** Identifying candidate vulnerable services from public threat intelligence, and measuring how AI is changing the rate at which new vulnerabilities appear.
2. **Forging.** Turning a candidate description (CVE, PoC, or just a scraping-agent report) into a working containerised vulnerable environment.
3. **Composition.** Assembling forged environments into multi-host systems that optionally also include non-vulnerable services and decoy flags. These systems produce the actual benchmark traces on which red and blue agents are evaluated.

**Intended use of the benchmark.** Two complementary purposes:

1. **Public release** of the pipeline (the scrape → forge → maze code) and the generated dataset (the benchmark itself). This lets the community build their own dynamic benchmarks and extend ours.
2. **Internal use** by two PhD students whose research runs in parallel with the master's theses: Youness Bouchari runs red-team agent experiments on the forged environments and composed mazes; Giovanni Dettori analyses the resulting logs to perform root-cause analysis on attacker intentions. Their work begins as soon as T2 and T3 produce usable outputs, which makes early "minimal viable" versions important even before the final forms are ready.

The release-scope criteria for the public artifacts — which CVEs are included, age thresholds, exclusions — remain open. See D4 in "Pending decisions".

## Strategic goals

Each goal is tagged either `[build]` (a deliverable that is either done or not done) or `[study]` (an open research question that we keep refining).

- **SG1** `[build]`: Engineer a scraping agent to identify candidate vulnerable services and the specific vulnerabilities exploitable in each.
- **SG2** `[build]`: Provide a way to check whether candidate services are in fact vulnerable. Two independent signals: (i) **temporal** — official disclosure happens within N months of detection; (ii) **constructive** — the SG4 pipeline can successfully reproduce the vulnerability.
- **SG3** `[study]`: Measure the impact of AI agents on the cybersecurity landscape (how often new CVEs appear, time between patch and public report, fraction of disclosures with public PoC, etc.).
- **SG4** `[build]`: Turn candidate vulnerable services into containerised environments with a flag, using AI forging agents.
- **SG5** `[study]`: Measure how well the forging agent works as we give it less information — full public PoC → public report → CVE description → scraping-agent report only.
- **SG6** `[build]`: Combine single containerised environments into multi-host systems containing one or more vulnerable services, non-vulnerable hosts, and decoy flags.
- **SG7** `[build]`: Provide an evaluation framework for measuring red-team agent success, and a logging schema for the attacker's actions that future blue-team work can use as input.
- **SG8** `[study]`: Characterise red-team agent behaviour and performance on the dynamic benchmark. What attack strategies emerge? How does performance scale with maze complexity?
- **SG9** `[study]`: Develop blue-team log analysis and attacker-intent inference (root-cause analysis) on the traces produced by the benchmark. What logging granularity and analysis methods are needed?

### Master's theses (defense target: 2026-09)

| Student    | Thesis title (working)                                                           | Contributes to                      |
| ---------- | -------------------------------------------------------------------------------- | ----------------------------------- |
| Alessandro | Development of an Online Scraper for CTI Gathering                               | SG1, SG2 (temporal signal), SG3     |
| Manuele    | Vuln-Forge: Creating Containerised Vulnerable Environments with LLM-based Agents | SG4, SG5, SG2 (constructive signal) |
| Luigi      | CyberMaze: Creating Multi-Host Vulnerable Systems for Red and Blue Team LLMs     | SG6, SG7                            |

### PhD theses (multi-year, ramp up as T2 and T3 produce usable output)

| Student          | Thesis title (working)                                                   | Contributes to |
| ---------------- | ------------------------------------------------------------------------ | -------------- |
| Youness Bouchari | Red-team agent experiments on the dynamic cyber-agent benchmark          | SG8            |
| Giovanni Dettori | Blue-team log analysis and attacker-intent inference on benchmark traces | SG9            |

## Shared infrastructure

At the steady state, T1 feeds T2, T2 feeds T3, and T2 and T3 together feed the two PhD projects. In the early stages each master's thesis works mostly on its own — T1 has little interaction with the others; T2 and T3 will interact earlier. The PhDs ramp up as T2 and T3 produce usable output.

The following are named shared artifacts. Each becomes a page in `wiki/shared/` and has a designated owner who is responsible for its design:

- **CVE metadata schema** — owner: Alessandro. Output of the scraper, input to the forger. Defines what fields are guaranteed about a candidate vulnerability and with what confidence.
- **Vulnerable-container image format and metadata** — owner: Manuele. Output of the forger; consumed by Luigi (who composes them into mazes) and by Youness (who runs red-team experiments against them). Defines container layout, flag placement, service entry point, expected exploit interface.
- **Red-team action logging schema** — owner: Luigi. Output of the maze evaluation; consumed by Giovanni for log analysis and attacker-intent inference. The schema design must serve both Luigi's evaluation needs and Giovanni's analysis needs.
- **"Is it actually vulnerable" check (SG2)** — co-owned. Alessandro owns the temporal signal; Manuele owns the constructive signal. The design must allow both to feed into a single judgment.
- **Cross-cutting evaluation framework** — owner: Luigi. He designs and maintains the framework based on SG7. Primary users are Youness and Giovanni; they give feedback and request changes as their experiments require.

I do not expect direct interactions between the developed agents themselves, even at steady state. The interactions happen at the artifact level: Youness's red-team agent acts on containers and mazes (via the evaluation framework), and Giovanni's analysis reads the logs that result.

**Note on T3 start-up.** Until T2 produces forged containers, Luigi works with open-source vulnerable containers ([vulhub](https://github.com/vulhub/vulhub)) as placeholders. These come "almost empty" — they reproduce the vulnerability but do not look like running services — so Luigi manually enriches them with benign services and content to make them more realistic. The arrangement is temporary: as T2 starts producing proper containers, these placeholders are replaced. If a specific vulhub environment turns out to be valuable long-term, Manuele's pipeline reproduces it in T2's format. The synthesis pass should flag the placeholders only if Luigi is still using them after T2 starts producing working containers.

**Note on PhD ramp-up.** Youness and Giovanni need T2/T3 outputs to start their experiments. This creates pressure on Manuele and Luigi to produce _minimal viable_ outputs early, even when those outputs are far from their final form. Track in synthesis as a program-level risk if either master's thesis falls significantly behind.

## Responsible disclosure and safety

This program scrapes and reproduces vulnerable services at scale. The plan addresses three concrete risks:

1. **Zero-day exposure during scraping.** If the SG1 scraper identifies a vulnerability that has not yet been publicly disclosed, it must be handled as a sensitive finding. Disclosure protocol _TBD — confirm with supervisor_ (CERT-style 90-day coordinated disclosure? Existing department or university process? Direct vendor contact?).
2. **Risk of becoming a tool for attacks.** The forged environments in SG4 are minimal reproductions of known vulnerabilities. The benchmark must not make it easier to attack real systems than it already is. Mitigations: (i) exclude CVEs younger than N months from any public release; (ii) consider excluding the highest-impact classes (e.g., authentication bypass, unauthenticated remote code execution on widely deployed services); (iii) write down the inclusion and exclusion criteria explicitly. Specific thresholds _TBD — confirm with supervisor_.
3. **Release scope.** Public release of the pipeline and the generated dataset is confirmed (D1). The public release contains only environments that meet the inclusion criteria above, possibly with rate-limited or authenticated access. Agent traces from internal experiments are initially _not_ part of the public release (we can include them later). The specific inclusion criteria are still open under D4.

## External deadlines

- **AISec 2026** (Workshop on AI and Security, co-located with ACM CCS'26) — submission **2026-07-24**.
- **KDD Benchmark Track 2026** — submission **2026-07-31**.
- **Thesis submission** — 2026-08-30.
- **Thesis defense** — 2026-09-15 (tentative).
- Other venues after thesis submission — TBD.

## Pending program-level decisions

Decisions that affect more than one thesis and should be resolved early. The wiki tracks status; the supervisor decides.

- **D1 — Benchmark framing.** **Resolved 2026-05-13**: both. Public release of the pipeline and generated dataset; internal use of agent traces for follow-up red/blue team experiments. See Program Vision.
- **D2 — AISec submission strategy.** Single joint workshop paper covering the full pipeline (with first-authorship to resolve) vs. three separate workshop papers (loses the pipeline narrative). Status: _open_. Hard deadline 2026-07-24.
- **D3 — Same for KDD.** Decision on whether to target the workshop or the main conference will be done after analysing the results. Hard deadline 2026-07-31.
- **D4 — Disclosure protocol** for the zero-day scenario in §Safety. Status: _open_.
- **D5 — Release-scope criteria** for forged environments (CVE age threshold, excluded classes). Status: _open_. Now unblocked: D1 is resolved with a public release confirmed, so these criteria need to be set before the AISec submission.
- **D6 — Evaluation framework ownership.** **Resolved 2026-05-13**: Luigi is the owner and designer; Youness and Giovanni are primary users and provide feedback on the design as their PhD experiments require.

## Program-level open questions

Research questions the program collectively will try to answer. These are `[study]` items: the answer keeps developing rather than being settled once.

- Can we find a reliable source of candidate vulnerable services? How many new CVEs per month? Is the rate increasing as AI agents become more involved in either offensive use or vulnerability research?
- Can the SG1 scraper surface zero-day vulnerabilities? At what false-positive rate?
- How much information does the forger need? Can it work from only the CVE description? From only the scraping-agent report?
- Existing red-team agent demonstrations are mostly limited to single- or two-step CTFs. How do agents perform on multi-step, multi-host traces with decoys? How complex should the maze be (number of steps, number of decoys, branching of the attack graph)?
- How do we measure "deception success" for decoy flags in the maze? Possible metrics: false-positive rate on decoys, time wasted on decoy paths, deception index. To be settled in Luigi's thesis plan.
- How does log volume scale with maze complexity (number of hosts, number of steps, decoys)? Can blue-team analysis keep up? Owner: Giovanni.

## Rationale and history

### 2026-05-13 — Revision 1 (initial plan)

Three theses defined around a scrape → forge → maze pipeline targeting a dynamic cyber-agent benchmark. Pipeline dependencies acknowledged; early-stage independent work assumed for all three theses. Initial scope set by the September 2026 thesis defense window and the July 24 AISec submission deadline.

### 2026-05-13 — Revision 2

Refinements following design review:

- Made the SG2/SG5 validation loop explicit: forging now serves as an independent check on whether a vulnerability is real, not just a step that follows scraping. Manuele's thesis formally contributes to SG2 via the constructive signal.
- Expanded "Shared infrastructure" into a named list of artifacts with designated owners — these become the starting pages of `wiki/shared/`.
- Added "Responsible disclosure and safety" section to address reviewer concerns expected at CCS-adjacent venues.
- Introduced `[build]` and `[study]` tags on strategic goals so the wiki tracks deliverables and research questions differently.
- Added "Pending program-level decisions" (D1–D5) for items that need supervisor input.
- Moved the blue-team-scaling question to "Deferred questions" (no current owner).
- Made it explicit that Luigi starts with hand-crafted placeholder containers while waiting for Manuele, so the synthesis pass does not flag this as a blocker.

### 2026-05-13 — Revision 3

Resolved D1: the program produces both a public release (pipeline + generated dataset) and internal agent traces used in follow-up red/blue team experiments. The follow-up experiments are outside the scope of the current three theses. Updated Program Vision and the Safety section's release-scope item accordingly. D4 (release-scope criteria) is now unblocked and becomes urgent ahead of the AISec submission.

### 2026-05-13 — Revision 4

Two PhD students added to the program: Youness Bouchari (red-team agent experiments, SG8) and Giovanni Dettori (blue-team log analysis and attacker-intent inference, SG9). Their work runs in parallel with the master's theses, starting when T2 and T3 produce usable output. This corrects the Revision 3 framing that called PhD-style work "follow-up outside the scope of the current three theses" — it is parallel, not subsequent. Knock-on changes:

- Added SG8 and SG9 (both `[study]`).
- Restructured "Theses in the program" into "People in the program" with master's and PhD subsections.
- Updated Shared infrastructure entries to name Youness as a consumer of vulnerable-container images, and Giovanni as the consumer of the red-team action logging schema.
- Resolved D5: Luigi owns the evaluation framework; PhDs are primary users and give feedback.
- Moved the blue-team log-volume question from "Deferred questions" to active open questions (Giovanni now owns it).
- Removed the "Deferred questions" section, which became empty.
- Added a note about PhD ramp-up creating pressure on Manuele and Luigi to deliver minimal viable outputs early.

### 2026-05-13 — Revision 5

Consistency pass after cross-file review of the overall plan and the three master's plans:

- **Self-reference fix.** The Revision 4 entry now correctly says "Revision 3 framing" rather than referring to itself.
- **Shared infrastructure section updated to match the Revision 4 changelog.** The vulnerable-container entry now names Luigi and Youness as consumers; the red-team action logging schema entry now names Giovanni. Revision 4 had recorded these changes in its changelog but the actual section had not been edited.
- **D5 "Resolved" prefix added** for consistency with D1.

### 2026-05-13 — Revision 6

Clarified the role of open-source vulnerable containers. Vulhub environments are placeholders Luigi has been manually enriching (they ship "almost empty"); they are not a parallel input format. Manuele's vulnerable-container image format remains the single canonical input format for T3 and downstream PhD work. The T3 start-up note now reflects this.
