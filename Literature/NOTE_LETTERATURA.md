# Note di letteratura per la tesi

Appunti di lavoro: punti citabili di ogni paper, statistiche riutilizzabili e
stato dell'arte. Le citazioni bibliografiche vere vanno recuperate dopo; qui
riporto DOI/arXiv verificati dove disponibili.

**Legenda affidabilità**
- ✅ = verificato (PDF letto in locale, oppure pagina arXiv/ACL confermata online)
- ⚠️ = riferimento citato altrove ma **non** trovato in rete → da non citare

---

## 0. Il nostro sistema, in breve

Serve come ancora per capire quale paper copre quale parte della tesi.

**`agentAnalysisDocker`** esegue un LLM in modalità agentica (OpenCode) dentro un
container Docker usa-e-getta, uno per run, su repository open source montati in
sola lettura al commit **padre** del fix (versione ancora vulnerabile, `.git`
rimosso). Tre configurazioni di input, che sono il cuore del contributo:

| Agente | Cosa vede | Domanda di ricerca |
|---|---|---|
| **agent1** | solo il commit (before / after / diff), nessun repository | un LLM riconosce un *security patch* dal solo diff? |
| **agent2** | repository + lo stesso diff | il contesto del repository aiuta? |
| **agent3** | **solo** il repository, nessun diff, nessun suggerimento | l'agente trova la vulnerabilità da zero (*zero-day style*)? |

Ogni run deve terminare con un blocco fisso `VULNERABILITY_FOUND` / `CWE_ID` /
`CWE_NAME`. Ground truth: 50 commit (uno per repository) da `ground_truth.csv`,
derivato da **CVEfixes**, ciascuno con CVE e CWE noti, mai mostrati all'agente.
50 commit × 3 agenti = **150 run** per modello.

**Filtro temporale — garantito per costruzione.** Il campione è ristretto alle
sole CVE **pubblicate nel 2026**. Il filtro è nel passo a monte della pipeline,
`cveFixes/cveFixes_repo_size_analyzer.py` (`CVE_YEAR = '2026'`, clausola
`WHERE cv.published_date LIKE '2026%'`), che produce `repo_analysis_v2.csv`;
`build_ground_truth.py` campiona poi dentro quell'universo già filtrato.

Verifica sul campione finale: **51 CVE su 51 hanno `published_date` nel 2026**,
nell'intervallo **2026-01-01 → 2026-05-01**. Le 10 CVE con identificativo
`CVE-2025-*` non sono un'eccezione: l'anno nell'ID è quello di **riservazione**,
non di pubblicazione (p.es. `CVE-2025-11157` è stata pubblicata l'1/1/2026).
Nel testo della tesi conviene quindi parlare sempre di **data di pubblicazione**,
mai dell'anno nell'ID, e citare questa distinzione — è una fonte di confusione
frequente.

**Il divario fix → pubblicazione nel nostro campione (dato originale).**
I commit di fix vanno dal 2019-06-17 al 2026-04-23: sembra un'incongruenza, ma è
esattamente il fenomeno che la tesi studia. Misurato sulle 51 coppie:

| | |
|---|---|
| fix **precedente** alla pubblicazione | **47 su 51 (92%)** |
| divario mediano | **15 giorni** |
| divario medio | 88 giorni |
| entro 7 gg / 8–30 / 31–180 / oltre 180 | 21 / 12 / 15 / 3 |
| caso estremo | `CVE-2026-40869`: fix 2019-06-17, pubblicata 2026-04-21 — **2.500 giorni** |

Il nostro dato mediano (15 giorni) è **coerente con e più ampio** della mediana
di poco più di una settimana riportata da `colefunda2023`, e conferma su un
campione indipendente e recente la premessa dell'intera tesi. Il caso da 2.500
giorni è un ottimo esempio d'apertura: la fix era pubblica da quasi sette anni
prima che la vulnerabilità fosse divulgata.

**Contaminazione da pre-training.** Con tutte le CVE pubblicate tra gennaio e
maggio 2026, la proprietà è garantita dalla costruzione del dataset e non va
verificata caso per caso. Resta da documentare la **data di cutoff dichiarata**
di `deepseek-v4` e `gemma-4-31b`: se è anteriore al 2026, l'argomento è chiuso.
Va però notato che il *codice* vulnerabile è ovviamente più vecchio della
pubblicazione e può essere nel training set — ciò che i modelli non possono aver
visto è **l'associazione codice ↔ CVE**, che è precisamente ciò che chiediamo di
ricostruire. Inquadramento teorico: ZeroDayBench (§3.3).

**Controlli sperimentali:** `temperature 0`; tetto di 200 tool round per run;
sotto-agenti vietati (per non dare a un modello un budget di contesto maggiore);
rete isolata su network Docker `--internal` con proxy allowlist verso il solo
endpoint del modello, così l'agente **non può cercare la CVE online**; timeout
container 1800 s; una sola passata, nessun recupero interattivo.

**Risultati finora** (dettagli in `outputs/*/RUN_CONFIG.md`):

| | deepseek-v4 | gemma-4-31b |
|---|---|---|
| run con verdetto parsabile | 117/150 (78%) | 150/150 (100%) |
| errori di formato | 33 | 0 |
| durata totale | 5h 34m | 3h 17m |
| richieste LLM totali | 2.893 | — |
| agent3: durata media | 7,9 min | 2,1 min |

Dei 33 errori di deepseek, **25 contenevano comunque un verdetto valido**
(12 con sintassi non conforme, 13 espressi solo in prosa) e **8 erano perdite
reali** (l'agente non ha concluso o ha chiesto istruzioni). Copertura utile
reale: 142/150 = 94,7%.

Due osservazioni che la letteratura aiuta a inquadrare:
1. Il fallimento dominante **non è analitico ma di formato/protocollo**. Non è
   una nostra anomalia: esiste una linea di ricerca dedicata (§3.8) e i nostri
   numeri sono in linea con essa — anzi migliori, perché imponiamo un solo
   vincolo di formato contro i ~12 di AGENTIF.
2. Gemma ha risposto "vulnerabilità presente" in **99 casi su 100** per agent1 e
   agent2: senza varianza nel sì/no, l'unica metrica informativa diventa la
   correttezza della **CWE**.

---

## 1. I paper nella cartella `Literature/`

### 1.1 ✅ CoLeFunDa — il riferimento principale

> J. Zhou, M. Pacheco, J. Chen, X. Hu, X. Xia, D. Lo, A. E. Hassan,
> "CoLeFunDa: Explainable Silent Vulnerability Fix Identification",
> **ICSE 2023**, pp. 2565–2577. DOI: `10.1109/ICSE48619.2023.00214`
> (Huawei Canada / Zhejiang / SMU / Queen's University)

È il lavoro **concettualmente più vicino all'intero nostro sistema** tra quelli
non basati su LLM: una pipeline in tre task in cascata sugli stessi input che
usiamo noi (commit e function change).

**Il problema che pone — è anche la nostra motivazione.**
La *Coordinated Vulnerability Disclosure* prevede che una vulnerabilità sia
prima corretta e poi divulgata. Ne consegue che **la fix è pubblica in mediana
una settimana prima della disclosure**, e la maggior parte delle OSS adotta una
politica per cui il commit di fix **non dichiara** di essere una fix di sicurezza
(*silent fix*). In quella finestra un attaccante può ricavare l'exploit dal
codice. Esempio portante: **Log4Shell / CVE-2021-44228**, divulgata il 10
dicembre 2021, con la fix pubblica dall'**29 novembre 2021, 11 giorni prima**; il
messaggio di commit era solo *"Restrict LDAP access via JNDI"*, senza alcuna
informazione di sicurezza. Citano anche Equifax / CVE-2017-5638 come esempio di
fix tardiva con danno superiore a **650 milioni di dollari**.

**Architettura (tre fasi).**
1. **FunDa** — data augmentation a livello di funzione. Per ogni function change
   genera *function slices* di funzione originale e modificata (program slicing
   su CFG + DFG con TreeSitter, ancorato alle **variabili cambiate**), più una
   *function change description* (FCDesc) generata con GumTree Spoon AST Diff.
   Combina i pezzi in `FCSample = FCDesc ⊕ OriFSlice ⊕ ModFSlice`.
2. **Contrastive learner** → pre-addestra l'encoder **FCBERT** (architettura
   CodeBERT), massimizzando la distanza tra campioni di CWE diverse, con loss
   NCE. Costruisce coppie positive con due strategie: *self-based* (non
   supervisionata, campioni dallo stesso function change) e *group-based*
   (supervisionata, stessa CWE).
3. **Fine-tuning** su tre task: `CoLeFunDa_fix` (identificazione silent fix),
   `CoLeFunDa_cwe` (classificazione CWE), `CoLeFunDa_exp` (exploitability rating).

**Dataset e problema dello sbilanciamento — molto utile per noi.**
1.436 patch CVE su **310 progetti Java OSS**, 839 CVE, contro **839.682 commit
non-fix**: le fix sono l'**1,71%** del totale. Da uno studio precedente citano
che la percentuale mediana di vulnerability fix in una OSS è **0,35%**.
Dalle patch estraggono 8.423 *function change pairs*.

**Sparsità delle CWE — il punto tecnicamente più riusabile.**
Nel loro dataset compaiono **89 tipi di CWE**; il **92,3%** delle CVE (554 su
600) ha **una sola** CWE assegnata, e il **52,8% delle categorie CWE ha meno di
3 CVE**. Per rendere il problema trattabile **rietichettano ogni CWE con la sua
"ancestor CWE category"** risalendo la gerarchia **CWE-1000 (Research
Concepts)**: si passa a 22 categorie, ridotte a **11** dopo aver rimosso quelle
con meno di 5 elementi. *Se anche noi avremo classi CWE sotto-rappresentate, è
esattamente la tecnica da adottare — e va citata.*

**Exploitability.** Usano CVSS 3.0 in 4 fasce (low 0.1–3.9, medium 4.0–6.9,
high 7.0–8.9, critical 9.0–10.0) → 22 / 46 / 376 / 360 CVE; low e medium vengono
fuse per scarsità.

**Risultati.** Batte VulFixMiner (il SOTA precedente) dell'**11–14%** sulle
metriche effort-aware (CostEffort@5%/20%, P_opt); sulla classificazione CWE
migliora il miglior baseline del **6–72%** (macro AUC/precision/recall/F1);
sull'exploitability del **24–54%**. Ablation: togliere FCDesc o lo slicing
peggiora tutto, il group-based incide meno sulla CWE.

**User study — il precedente diretto della nostra valutazione.**
5 esperti di sicurezza con 5+ anni di esperienza, su **40 CVE prive di CWE**:
il **37,5%** è classificato correttamente al primo suggerimento e il **62,5%**
entro i primi due. Numero utile come termine di paragone per la nostra accuratezza CWE.

**Limiti dichiarati (utili per la nostra sezione *threats to validity*).**
Solo Java; analisi a livello di funzione, quindi fallisce sulle fix multi-file
(le CWE-693 e CWE-691, con ~2 file coinvolti in media, sono quelle su cui va
peggio); il **14%** delle fix produce una FCDesc identica a un'altra fix con CWE
diversa; filtrano i commit con più di 4 function change.

**Predecessore da citare per mostrare l'evoluzione:** *VulFixMiner* — J. Zhou et
al., "Finding a Needle in a Haystack: Automated Mining of Silent Vulnerability
Fixes", **ASE 2021**, pp. 705–716. È il baseline SOTA per la sola identificazione
di silent fix, senza spiegazione.

---

### 1.2 ✅ From LLMs to Agents — il confronto più diretto con il nostro agent1

> J. Han, Z. Yu, L. Bao, J. Liu, Y. Wan, J. Yin, S. Deng, S. Han,
> "From LLMs to Agents: A Comparative Evaluation of LLMs and LLM-based Agents
> in Security Patch Detection", **arXiv:2511.08060** (nov. 2025).
> Codice/dati: `github.com/fzqn/PatchDetection`

Confronta **tre metodi** sullo stesso task (riconoscere se un commit è un
security patch): **Plain LLM** (solo system prompt), **Data-Aug LLM** (con
augmentation del contesto) e **ReAct Agent** (ciclo thought-action-observation).
È il termine di paragone più preciso per il nostro **agent1** e per la scelta
agentica in generale.

**Modelli:** GPT-4o, GPT-4o-mini, GPT-5, DeepSeek-R1 (commerciali), Llama-3.1-8B
e Gemma-3-7B (open source). **Notevole per noi: usano DeepSeek e Gemma, gli
stessi due che stiamo confrontando.**
**Dataset:** PatchDB (313 progetti; parte NVD, parte "wild" da GitHub, parte
sintetica).

**Risultati principali:**
- **Data-Aug LLM** ha la performance complessiva migliore; **ReAct Agent** ha il
  **false positive rate più basso** — il beneficio dell'agente non è l'accuratezza
  grezza ma la riduzione dei falsi positivi.
- GPT-4o + ReAct: precisione **86,15%** con FPR fortemente ridotto.
- I **modelli commerciali battono sistematicamente gli open source** su tutti e
  tre i metodi. Esempio (Plain LLM → Data-Aug): GPT-4o accuratezza 56,97% →
  60,35%; Llama-3.1 45,02% → 51,03%; Gemma-3 43,22% → 49,12%.
- I baseline tradizionali hanno buona accuratezza ma **FPR molto più alto**.
- **RQ6, context window:** finestre più grandi migliorano le metriche (dimostrato
  su Llama-3.1 e Gemma-3, testati a 2.048 / 4.096 / 8.192 token). Osservano il
  trade-off: finestre piccole troncano informazione essenziale, finestre grandi
  introducono rumore e costo. **Da citare a supporto della nostra analisi sul
  `ContextWindowExceededError` di agent3.**
- Statistica citabile: oltre l'**82%** delle segnalazioni di vulnerabilità
  inviate dagli utenti arriva **più di 30 giorni** dopo la scoperta iniziale.
- Contesto di mercato (Black Duck 2025): il **97%** delle codebase dipende da
  OSS, l'**86%** contiene almeno una vulnerabilità nota, l'**81%** ha problemi di
  severità alta o critica, il **91%** include componenti indietro di 10+ versioni.

---

### 1.3 ✅ GitPatchDB — dataset di patch

> "GitPatchDB: A Large-Scale GitHub Commit Databank for Vulnerability Patch
> Analysis", **under review ICLR 2026** (doppio cieco, autori anonimi).

Attacca il problema che tocca anche noi: **le CVE spesso non hanno un riferimento
affidabile alla patch**, e molti commit citati diventano irraggiungibili quando i
repository cambiano. Costruiscono un dataset che accoppia CVE e commit di patch
dove ogni commit è rappresentato **non solo come diff ma come program slice
interprocedurale**. Propongono **CNPP** (Contrastive Natural-language
Programming-language Pre-training) per la ricerca multimodale delle patch:
**95,99% di top-10 accuracy**, oltre 8 punti sopra i metodi manuali di baseline.

**Perché ci serve:** giustifica la scelta di CVEfixes come ground truth e
documenta il *link rot* dei riferimenti patch. La rappresentazione a slice
interprocedurali è la stessa intuizione di CoLeFunDa e di JitVul.

---

### 1.4 ✅ SITPatchTracer — tracciare la patch di una CVE

> X. Liu, J. Zheng, G. Yang, S. Wen, Q. Liu, X. Wang,
> "Improving the Context Length and Efficiency of Code Retrieval for Tracing
> Security Vulnerability Fixes", **arXiv:2503.22935v3** (ago. 2025).
> Stevens Institute of Technology / ZJU-UIUC / UTSA

Task a monte del nostro: dato un CVE, **trovare il commit che lo corregge**.
Due problemi dichiarati: i metodi esistenti non gestiscono diff lunghi e non
scalano all'intero repository.

**Contributo tecnico rilevante per noi: l'*hierarchical embedding***, che estende
la copertura del contesto a **6× quella dei metodi esistenti** coprendo tutti i
file del commit, dentro un framework a tre fasi che bilancia efficacia ed
efficienza. Batte PatchFinder, PatchScout e VFCFinder di margine ampio, e supera
**VoyageAI** (embedding commerciale SOTA, 1,8 $ per 10K commit) del **18% su MRR**
e **28% su Recall@10**. Con il sistema hanno tracciato e integrato i link patch di
**35 nuove CVE** nel GitHub Advisory Database.

**Perché ci serve:** è la prova che **il context length è il collo di bottiglia
strutturale** di questo dominio, non un dettaglio implementativo — lo stesso muro
contro cui ha sbattuto il nostro agent3. Esempio d'effetto citabile:
CVE-2013-1814, il cui link alla patch è mancante in NVD, con **10 anni di ritardo**
prima che gli sviluppatori sapessero di essere affetti.

---

### 1.5 ✅ Ayala et al. — disclosure, advisory e bug bounty

> J. Ayala, Y.-J. Tung, J. Garcia (UC Irvine),
> "Investigating Vulnerability Disclosures in Open-Source Software Using Bug
> Bounty Reports and Security Advisories", **arXiv:2501.17748** (gen. 2025).

Studio empirico su **3.798 advisory GitHub revisionati** e **4.033 bug bounty
report** divulgati. Primi a ricostruire **il processo esplicito** con cui una
vulnerabilità OSS si propaga da advisory e bug bounty fino ai database globali e
ai progetti dipendenti.

**Statistiche citabili (fortissime per l'introduzione):**
- Al **25/09/2023**: **197.609 advisory GitHub NON revisionati**; di questi almeno
  **63.852** sono vulnerabilità **pubblicamente documentate** — quindi note ma non
  propagate, con i progetti dipendenti che restano scoperti.
- GitHub dichiarava oltre **200 milioni di repository attivi** (giugno 2022).
- Le vulnerabilità OSS pubblicate hanno raggiunto **9.658 nel 2020**.
- Kula et al.: l'**81,5%** di oltre 4.600 progetti GitHub mantiene dipendenze
  obsolete.
- I manutentori risolvono più in fretta se esiste una CVE associata.

**Tesi centrale:** le assegnazioni CVE mancanti o ritardate fanno sì che i
progetti non vengano avvisati in tempo. È il buco che il nostro approccio —
guardare il codice invece di aspettare l'advisory — prova ad aggirare.

---

### 1.6 ✅ Imtiaz et al. — "Open or Sneaky?" (tempi di rilascio)

> N. Imtiaz, A. Khanom, L. Williams (NC State),
> "Open or Sneaky? Fast or Slow? Light or Heavy?: Investigating Security
> Releases of Open Source Packages",
> **IEEE TSE**, vol. 49, n. 4, apr. 2023, pp. 1540–1560.
> DOI: `10.1109/TSE.2022.3181010`

**La fonte migliore per la timeline.** 4.377 advisory su **sette ecosistemi**
(Composer, Go, Maven, npm, NuGet, pip, RubyGems).

**Numeri da citare:**
- La **security release mediana** esce entro **4 giorni** dalla fix
  corrispondente…
- …ma **un quarto** delle release arriva **almeno 20 giorni dopo** la fix.
- La release mediana contiene **131 righe di codice** modificate.
- Solo il **61,5%** delle security release ha una release note che documenta la
  fix di sicurezza (il resto è, appunto, *sneaky*).
- **Snyk e NVD impiegano in mediana 17 giorni** dalla release per pubblicare
  l'advisory → ulteriore ritardo nella notifica ai progetti client.
- Il **13,2%** delle security release segnala incompatibilità all'indietro via
  semantic versioning; il **6,4%** cita breaking change nelle note.

**Come usarlo:** insieme a CoLeFunDa costruisce l'argomento centrale della tesi —
*fix nel codice (giorno 0) → release (mediana 4 gg) → advisory (mediana +17 gg)*.
La finestra di esposizione è di settimane, ed è esattamente ciò che un
rilevatore automatico sul codice può accorciare.

---

### 1.7 ✅ Segal et al. — la pipeline di review di GHSA

> C. Segal, P. Segal, C. E. Banjar, F. Paixão, H. S. Borges, P. Silveira,
> E. S. de Almeida, J. C. S. Santos, A. Kocheturov, G. Srivastava, D. S. Menasché,
> "Characterizing and Modeling the GitHub Security Advisories Review Pipeline",
> **MSR 2026**, Rio de Janeiro. **arXiv:2602.06009**. DOI: `10.1145/3793302.3793360`

Studio su **288.604 advisory GHSA (2019–2025)**, di cui **23.563 revisionati** da
GitHub al 21/08/2025. Caratterizza **quali** advisory hanno più probabilità di
essere revisionati e **quanto** si aspetta, identificando **due regimi di latenza
distinti**: un *fast path* dominato dalle GitHub Repository Advisories (GRA) e uno
*slow path* dominato dagli advisory che nascono su NVD. Propongono un **modello a
code** che spiega la dicotomia a partire dalla struttura della pipeline.

**Come usarlo:** è il complemento aggiornato e su larghissima scala di Ayala et
al. — non solo "molti advisory non sono revisionati", ma *quanto* si aspetta e
*perché*. Utile per la sezione motivazionale e per datare il problema al 2026.

---

## 2. Statistiche pronte per introduzione e motivazione

Tutte verificate nei PDF locali. La sequenza racconta da sola il problema.

| Fatto | Valore | Fonte |
|---|---|---|
| La fix è pubblica **prima** della disclosure | mediana **> 1 settimana** | CoLeFunDa |
| Caso Log4Shell (CVE-2021-44228) | fix **11 giorni** prima | CoLeFunDa |
| Security release dopo la fix | mediana **4 giorni** | Imtiaz TSE 2023 |
| Coda lunga delle release | **25%** oltre **20 giorni** | Imtiaz TSE 2023 |
| Advisory dopo la release (Snyk/NVD) | mediana **17 giorni** | Imtiaz TSE 2023 |
| Release note che documentano la fix | **61,5%** | Imtiaz TSE 2023 |
| Report utente oltre 30 gg dalla scoperta | **> 82%** | Han et al. 2025 |
| Advisory GHSA non revisionati (2023) | **197.609**, di cui **63.852** già pubblici | Ayala et al. |
| Advisory GHSA analizzati (2019–2025) | **288.604**, revisionati **23.563** | Segal et al. MSR 2026 |
| Fix di sicurezza sul totale dei commit | **1,71%** (mediana per progetto **0,35%**) | CoLeFunDa |
| CVE con una sola CWE assegnata | **92,3%** | CoLeFunDa |
| Categorie CWE con < 3 CVE | **52,8%** | CoLeFunDa |
| Codebase con almeno una vulnerabilità nota | **86%** (97% dipende da OSS) | Black Duck 2025 via Han et al. |
| Progetti con dipendenze obsolete | **81,5%** | Kula et al. via Ayala et al. |

---

## 3. Stato dell'arte online (tutti verificati)

### 3.1 ✅ JitVul — il riferimento fondamentale che cercavi

> A. Yildiz, S. G. Teo, Y. Lou, Y. Feng, C. Wang, D. M. Divakaran,
> "Benchmarking LLMs and LLM-based Agents in Practical Vulnerability Detection
> for Code Repositories", **ACL 2025** (`2025.acl-long.1490`).
> **arXiv:2503.03586**

**È il paper più vicino in assoluto al nostro impianto sperimentale.** Costruisce
**JitVul**, benchmark di *just-in-time* vulnerability detection che collega ogni
funzione **sia al commit che ha introdotto la vulnerabilità sia a quello che l'ha
corretta**: **879 CVE** su **91 tipi di vulnerabilità**.

Punti che ci riguardano direttamente:
- La detection realistica richiede **analisi interprocedurale**: le vulnerabilità
  emergono da catene di chiamate multi-hop, non da funzioni isolate. È
  esattamente la ragione per cui il nostro agent3 esplora il repository invece di
  ricevere una funzione.
- Critica i benchmark repository-level esistenti (**ReposVul**, **VulEval**):
  costosi, senza valutazione a coppie fix/non-fix, con retrieval del contesto
  limitato.
- **Risultato chiave:** gli **agenti ReAct**, grazie al ciclo
  thought-action-observation e al contesto interprocedurale, **distinguono meglio
  degli LLM semplici** il codice vulnerabile da quello benigno. È la validazione
  in letteratura della nostra scelta agentica.
- La **valutazione a coppie** (stessa funzione prima e dopo il fix) è
  metodologicamente ciò che facciamo con agent1/agent2 rispetto ad agent3.

### 3.2 ✅ VulnGym — il più vicino al nostro agent3

> "VulnGym: Benchmarking Coding Agents for Repository-Level Vulnerability
> Detection", **arXiv:2608.02001**. Codice: `github.com/Tencent/VulnGym`
> (open source dal 15/05/2026)

**184 advisory** e **408 voci di vulnerabilità** su **23 repository**, ognuna con
**annotazioni a livello di riga**. La motivazione dichiarata è la nostra:
i benchmark esistenti fanno *classificazione su snippet preselezionati*, mentre
un coding agent deve **esplorare autonomamente il repository e localizzare da sé
il codice rilevante**. È il setting di agent3, ed è di appena due mesi fa.

### 3.3 ✅ ZeroDayBench — zero-day senza contaminazione

> Lau et al., "ZeroDayBench: Evaluating LLM Agents on Unseen Zero-Day
> Vulnerabilities for Cyberdefense", **arXiv:2603.02297**,
> ICLR 2026 Workshop on Agents in the Wild.

**22 vulnerabilità critiche nuove** che gli agenti devono trovare e correggere.
Il contributo metodologico che ci serve: per evitare la **contaminazione da
pre-training**, *portano* CVE reali ad alta severità dentro repository
funzionalmente simili ma **diversi**, garantendo una valutazione
out-of-distribution. Testano GPT-5.2, Claude Sonnet 4.5 e Grok 4.1 e concludono
che **i modelli di frontiera non sono ancora in grado di risolvere il benchmark
autonomamente**.

> **Come ci posizioniamo.** ZeroDayBench affronta la contaminazione *portando* le
> CVE dentro repository diversi. Noi la affrontiamo per via **temporale**:
> selezioniamo solo CVE del 2025–2026 (41 su 51 sono del 2026), quindi
> plausibilmente successive al cutoff di addestramento dei modelli testati. È una
> mitigazione più semplice della loro, e con un vantaggio: il codice resta
> **autentico**, non trapiantato, quindi il setting è più realistico. In cambio
> non offre la garanzia formale dell'out-of-distribution.
>
> ⚠️ **Resta da documentare:** la data di cutoff dichiarata di `deepseek-v4` e
> `gemma-4-31b`. Senza quel dato la mitigazione è ragionevole ma non dimostrata,
> e un revisore può obiettare. Va messa in tabella nel capitolo sperimentale.

### 3.4 ✅ PrimeVul — per giustificare il rigore della ground truth

> Ding et al., "Vulnerability Detection with Code Language Models: How Far Are
> We?" (**PrimeVul**), **arXiv:2403.18624**, ICSE 2025.

**Il numero da citare:** StarCoder2 passa da **68,26% di F1 su BigVul a 3,09% su
PrimeVul**. I dataset precedenti hanno etichette rumorose (accuratezza 24–60%) e
alta duplicazione, e sovrastimano enormemente le prestazioni. PrimeVul contiene
6.968 funzioni vulnerabili e 228.800 benigne su **140 tipi di CWE**, con split
cronologici anti-leakage e **435 coppie vulnerable–patched** che condividono
almeno l'80% del testo, per costringere il modello a cogliere la semantica e non
la differenza superficiale.

Serve a difendere la nostra scelta di una ground truth costruita da CVEfixes con
commit reali, e a spiegare perché numeri alti su benchmark facili non dicono
nulla.

### 3.5 ✅ Altri lavori agentici recenti (contorno)

| Lavoro | arXiv | Rilevanza |
|---|---|---|
| **SecVulEval** — benchmark C/C++ real-world | 2505.19828 | detection a livello di statement, complementare |
| **VulTrial / mock-court** — agenti LLM in dibattito | 2505.10961 | architettura multi-agente alternativa alla nostra singola |
| **VulnAgent-R2** — auditing multi-agente calibrato sull'evidenza | 2603.13384 | repository-level, multi-agente |
| **AEGIS** — reasoning guidato da grafo con meta-auditing | 2603.20637 | spiegabilità del verdetto |
| **VulInstruct** — root-cause reasoning via specifiche | 2511.04014 | migliora il ragionamento causale |
| **Code-Augur** — detection agentica via inferenza di specifiche | 2606.18619 | l'agente esplicita assunzioni come specifiche e un fuzzer guidato prova a falsificarle |
| **FuzzingBrain V2** — sistema multi-agente, finalista DARPA AIxCC | 2605.21779 | **90% (36/40)** su AIxCC 2025 Final C/C++; **29 zero-day** su 12 progetti reali, 2 con CVE assegnata |
| **CVE-Bench** — agenti che *sfruttano* vulnerabilità web | 2503.17332 | lato offensivo, utile per contrasto |
| **Systematic Literature Review** su LLM e vulnerability detection | 2507.22659 | da citare per inquadrare il campo |

Indice della comunità costantemente aggiornato, utile per non perdere lavori
nuovi: `github.com/huhusmang/Awesome-LLMs-for-Vulnerability-Detection`.

### 3.6 ✅ Classificazione CWE con LLM — colma il buco lasciato dal riferimento falso

Questa era la parte più scoperta delle note: il riferimento multi-agente che
circolava (`arXiv:2508.01451`) non esiste. Ecco i lavori reali.

**Il risultato più importante — ed è negativo, quindi prezioso.**

> "On Using {LLMs} for Vulnerability Classification", Workshop on Large AI
> Systems and Models with Privacy and Security Analysis, 2025.
> DOI: `10.1145/3733800.3763267`

Confronta tre approcci per assegnare la CWE partendo dalla descrizione della CVE:

| approccio | accuratezza |
|---|---|
| Random Forest su embedding LLM (Llama 3.1, Qwen 2.5) | ~44% |
| LLM generativo con prompt | fino a 59% |
| **classificatore banale su embedding TF-IDF** | **74%** |

Un classificatore lessicale batte l'LLM di 15 punti. La spiegazione degli autori:
le descrizioni CVE sono **altamente schematiche**, e le feature basate su parole
chiave catturano il tipo di vulnerabilità direttamente.

**Perché è cruciale per noi.** È il baseline onesto contro cui misurare la nostra
accuratezza CWE, ed è anche un avvertimento: se i nostri agenti classificano
bene, va dimostrato che non stanno semplicemente facendo *pattern matching*
lessicale. Nota però la differenza di setting, che gioca a nostro favore e va
sottolineata: loro classificano partendo dal **testo della CVE**, noi partiamo
dal **codice**, dove le parole chiave della descrizione non ci sono. Il confronto
non è diretto, ma il numero resta il termine di paragone da citare.

**Altri lavori sulla mappatura CVE → CWE:**

| Lavoro | Riferimento | Nota |
|---|---|---|
| CVE-LLM: Ontology-Assisted Automatic Vulnerability Evaluation | AAAI | prompt arricchiti da ontologia; prestazioni paragonabili a esperti umani |
| Simonetto et al., "What Matters Most in Vulnerabilities? Key Term Extraction for CVE-to-CWE Mapping with LLMs" | Springer, 2026 | estrazione dei termini chiave |
| CTIBench | benchmark | include un task di mappatura CVE → CWE ed estrazione di severità |

---

### 3.7 ✅ Contaminazione dei benchmark — la nostra scelta temporale ha un nome

Rafforza direttamente §0: quello che abbiamo fatto filtrando sulle CVE pubblicate
nel 2026 è una pratica riconosciuta in letteratura, con una terminologia propria.

**Il lavoro più allineato al nostro:**

> "JavaVulBench: A Java Vulnerability Benchmark with Realistic Splits, a Unified
> Multi-Backend Harness, and a **Leakage-Aware Evaluation Mode**",
> **arXiv:2607.02825**

Introduce la *leakage-aware evaluation*: il test set è partizionato in un
sottoinsieme **"risky"** (CVE pubblicate **prima** del cutoff di pretraining) e
uno **"clean"** (pubblicate **dopo**). È esattamente la distinzione che il nostro
filtro `published_date LIKE '2026%'` realizza — con la differenza che il nostro
campione è **interamente "clean"** per costruzione, invece che partizionato.
**Da citare come giustificazione metodologica del filtro.**

**La misura di quanto pesa la contaminazione:**

> "Should We Evaluate LLM Based Security Analysis...", **ASE 2025**
> (disponibile su teamscale.com/hubfs/Publications/)

Selezionano istanze prima e dopo il cutoff e misurano un calo di **circa 20 punti
di F1** sui dataset privati, mediamente su tutti i modelli. È il numero che
quantifica il rischio che stiamo evitando.

> ⚠️ **Dettaglio da non sbagliare.** Quello studio partiziona in base alla **data
> di riservazione** della CVE (l'anno nell'ID), noi in base alla **data di
> pubblicazione**. Sono criteri diversi: 10 delle nostre CVE hanno ID 2025 ma
> pubblicazione 2026. Il nostro criterio è più conservativo dal punto di vista
> della disclosure, ma va dichiarato quale si usa, perché i due non coincidono.

**Contorno sulla contaminazione:**

| Lavoro | arXiv | Nota |
|---|---|---|
| Learned or Memorized? Quantifying Memorization Advantage in Code LLMs | 2604.13997 | quantifica il vantaggio da memorizzazione |
| LLM Benchmark Datasets Should Be Contamination-Resistant | 2605.19999 | posizione metodologica generale |
| SEC-bench: Automated Benchmarking of LLM Agents on Security | 2506.11791 | benchmark agentico costruito automaticamente |

Argomento generale citabile: benchmark pubblici come **Juliet**, **OWASP
Benchmark** e gli esempi CVE sono apertamente disponibili e quindi
verosimilmente nei dati di training, per cui un'accuratezza alta può riflettere
memorizzazione e non ragionamento.

---

### 3.8 ✅ Aderenza al formato — il nostro fallimento dominante ha letteratura

Nelle note avevo scritto che il fallimento di formato è "poco trattato nei
benchmark esistenti". Va corretto: esiste una linea di ricerca dedicata, e i
nostri numeri sono in linea con essa.

> **AGENTIF: Benchmarking Instruction Following of Large Language Models in
> Agentic Scenarios**, Tsinghua KEG
> (`keg.cs.tsinghua.edu.cn/persons/xubin/papers/AgentIF.pdf`)

Primo benchmark di *instruction following* per scenari **agentici**: 707
istruzioni da 50 applicazioni reali, lunghe in media 1.717 token e con ~11,9
vincoli ciascuna. **Il modello migliore segue perfettamente meno del 30% delle
istruzioni.**

> **FireBench: Evaluating Instruction Following in Enterprise and API-Driven LLM
> Applications**, **arXiv:2603.04857**

Isola sei capacità, la prima delle quali è la **output format compliance**, e
valuta 21 vincoli di formato distinti (JSON, XML, delimitatori vari e varianti
avversariali). Osservazione centrale citabile: *le violazioni di formato causano
fallimenti a valle anche quando la risposta di merito è corretta*.

**Come usarlo nella nostra discussione.** Il 22% di run non parsabili di
deepseek-v4 — di cui però il 76% conteneva un verdetto valido — non è
un'anomalia del nostro setup ma un fenomeno noto e misurato. Anzi, il nostro
dato è **migliore** di quello di AGENTIF, il che è atteso: noi imponiamo un solo
vincolo di formato, loro in media dodici. Questa letteratura giustifica anche la
scelta ingegneristica di un **parser tollerante**, e rende difendibile riportare
sia l'accuratezza grezza sia quella dopo recupero.


---

## 4. Mappa: quale paper per quale capitolo

| Parte della tesi | Paper |
|---|---|
| **Motivazione** (finestra di esposizione, silent fix) | CoLeFunDa · Imtiaz TSE 2023 · Ayala et al. · Segal MSR 2026 |
| **Background** (CVE, CWE, CVSS, CVD) | CoLeFunDa §II |
| **Dataset e ground truth** | GitPatchDB · SITPatchTracer · PrimeVul |
| **Approccio 1 — solo commit** (agent1) | Han et al. 2511.08060 · CoLeFunDa · VulFixMiner |
| **Approccio 2 — repository + diff** (agent2) | **JitVul** · VulnGym |
| **Approccio 3 — zero-day** (agent3) | **ZeroDayBench** · VulnGym · FuzzingBrain V2 · Code-Augur |
| **Classificazione CWE** | CoLeFunDa (gerarchia CWE-1000, user study) · `llmvulnclassification2025` (baseline TF-IDF) · `cvellm` · `simonetto2026cwemapping` |
| **Contaminazione e validita' della valutazione** | `javavulbench2026` (leakage-aware) · `securityevalase2025` · `memorizationcodellm2026` · `contaminationresistant2026` |
| **Fallimenti di formato del verdetto** | `agentif2025` · `firebench2026` |
| **Perché agenti e non LLM semplici** | JitVul (ReAct meglio) · Han et al. (ReAct = FPR minimo) |
| **Problema del context length** | SITPatchTracer · Han et al. RQ6 |
| **Confronto tra modelli** | Han et al. (usa DeepSeek e Gemma come noi) |
| **Threats to validity** | ZeroDayBench (contaminazione) · PrimeVul (qualità dataset) · CoLeFunDa (limiti linguaggio/funzione) |

---

## 5. Riferimenti da NON citare

Comparivano in una lista precedente ma **non esistono** nei database consultati.
Li segnalo per evitare che finiscano in bibliografia.

- ⚠️ **"Revelio: Cost-Efficient Agentic Memory Safety Vulnerability Detection
  For Repository-Scale Codebases"** (arXiv:2606.22263) — nessun riscontro.
  Per quel ruolo usare **VulnGym** (§3.2) o **VulnAgent-R2**.
- ⚠️ **"CWE Identification with Multi-Agent Large Language Models"**
  (arXiv:2508.01451) — nessun riscontro. Per la classificazione CWE restano
  CoLeFunDa e, come controparte agentica, AEGIS o VulnAgent-R2.

Inoltre, due numeri circolati in precedenza sono **sbagliati** e vanno corretti:
FuzzingBrain V2 riporta **29 zero-day su 12 progetti** (non 124 su 53), e non
risulta che **Code-Augur** confronti Claude e DeepSeek come backend.

---

## 6. Cosa manca / prossimi passi

1. **Recuperare le citazioni BibTeX vere** per tutti i ✅ (DOI già presenti dove
   noti).
2. **Verificare l'ID arXiv di PrimeVul** (2403.18624) sulla pagina ufficiale: il
   titolo esatto è *"Vulnerability Detection with Code Language Models: How Far
   Are We?"*, il nome PrimeVul è quello del dataset.
3. **Leggere per intero JitVul e VulnGym**: sono i due termini di paragone
   diretti e servirà un confronto puntuale di setting e metriche, non solo
   l'abstract.
4. **Decidere la metrica per la CWE.** Vista la sparsità (52,8% delle CWE con <3
   CVE), valutare se adottare la gerarchia *ancestor CWE* di CoLeFunDa: renderebbe
   i nostri risultati confrontabili con i loro.
5. **Confrontare deepseek-v4 e gemma-4-31b sull'accuratezza CWE**, non sul
   sì/no — che con gemma è degenerato (99 sì su 100 per agent1 e agent2).

---

## 7. Chiavi BibTeX

Tutte le fonti sono state inserite in
`Politecnico_di_Torino___Thesis_Template/bibliography.bib` (38 voci, validate con
`biber --tool --validate-datamodel`, zero warning). Backup del file originale:
`bibliography.bib.bak`.

| Fonte | Chiave |
|---|---|
| CoLeFunDa (ICSE 2023) | `colefunda2023` |
| VulFixMiner (ASE 2021) | `vulfixminer2021` |
| From LLMs to Agents | `han2025llmsagents` |
| **JitVul (ACL 2025)** | `yildiz2025jitvul` |
| VulnGym | `vulngym2026` |
| ZeroDayBench | `zerodaybench2026` |
| PrimeVul | `primevul2025` |
| SecVulEval | `secvuleval2025` |
| VulTrial (mock-court) | `vultrial2025` |
| VulnAgent-R2 | `vulnagentr22026` |
| AEGIS | `aegis2026` |
| VulInstruct | `vulinstruct2025` |
| Code-Augur | `codeaugur2026` |
| FuzzingBrain V2 | `fuzzingbrain2026` |
| CVE-Bench | `cvebench2025` |
| Systematic Literature Review | `slrllmvuln2025` |
| SITPatchTracer | `liu2025sitpatchtracer` |
| GitPatchDB | `gitpatchdb2026` |
| Open or Sneaky (TSE 2023) | `imtiaz2023opensneaky` |
| Ayala et al. (bug bounty) | `ayala2025disclosures` |
| GHSA review pipeline (MSR 2026) | `segal2026ghsa` |

**Strumenti e fonti istituzionali**

| Fonte | Chiave |
|---|---|
| **CVEfixes** — paper PROMISE '21 | `cvefixes2021` |
| CVEfixes — dataset Zenodo | `cvefixesdataset` |
| CVEfixes — codice | `cvefixescode` |
| **Criticality Score** — strumento OpenSSF | `criticalityscore` |
| Criticality Score — algoritmo (Rob Pike) | `pikecriticality` |
| Criticality Score — annuncio Google | `googlecriticalprojects` |
| NIST NVD | `nvd`, `nvdapi` |
| OSV | `osv`, `osvschema` |
| CVE Program (MITRE) | `cveprogram` |
| CWE (MITRE) | `cwe`, `cwe1000` |
| CVSS (FIRST) | `cvss` |
| GitHub Advisory Database | `ghsa` |
| OpenCode | `opencode` |
| Docker sandbox | `dockersandbox` |

**Nota su Criticality Score.** Non esiste un paper peer-reviewed: la citazione
ufficiale è il `CITATION.cff` del repository (Arya, Brown, Pike e OpenSSF,
v2.0.2, 2023), affiancata dal documento tecnico *Quantifying Criticality* di Rob
Pike che descrive l'algoritmo, incluso nel repo. Nella tesi conviene citare
`criticalityscore` per lo strumento e `pikecriticality` quando si descrive come
il punteggio è calcolato.

**Classificazione CWE, contaminazione e formato** (sezioni 3.6–3.8)

| Fonte | Chiave |
|---|---|
| On Using LLMs for Vulnerability Classification | `llmvulnclassification2025` |
| CVE-LLM (ontologia, AAAI) | `cvellm` |
| Simonetto et al., CVE-to-CWE key terms | `simonetto2026cwemapping` |
| **JavaVulBench** (leakage-aware evaluation) | `javavulbench2026` |
| Should We Evaluate LLM-Based Security Analysis (ASE 2025) | `securityevalase2025` |
| Learned or Memorized? | `memorizationcodellm2026` |
| Contamination-Resistant Benchmarks | `contaminationresistant2026` |
| SEC-bench | `secbench2025` |
| **AgentIF** (instruction following agentico) | `agentif2025` |
| FireBench (output format compliance) | `firebench2026` |

**Voci con `% TODO autori`.** Molte voci recenti hanno l'elenco autori da
confermare prima della consegna: `vulngym2026`, `zerodaybench2026`,
`primevul2025`, `secvuleval2025`, `vultrial2025`, `vulnagentr22026`, `aegis2026`,
`vulinstruct2025`, `codeaugur2026`, `fuzzingbrain2026`, `cvebench2025`,
`slrllmvuln2025`, `llmvulnclassification2025`, `cvellm`,
`simonetto2026cwemapping`, `javavulbench2026`, `securityevalase2025`,
`memorizationcodellm2026`, `contaminationresistant2026`, `secbench2025`,
`agentif2025`, `firebench2026`. Sono segnalate da un commento nel file `.bib`.
**I PDF sono ora in `Literature/`**, quindi gli autori si estraggono dalla prima
pagina senza tornare online — per le quattro voci non su arXiv
(`llmvulnclassification2025`, `cvellm`, `simonetto2026cwemapping`,
`securityevalase2025`) serve invece la pagina dell'editore.

---

## 8. Sviluppi futuri — dal retrospettivo al real time (vulnRadar)

Da inserire nel capitolo *Future work*. È l'estensione naturale del lavoro e
chiude il cerchio con la motivazione dell'introduzione.

**Il limite dell'impianto attuale.** `agentAnalysisDocker` lavora
**retrospettivamente**: parte da un commit di fix già noto e da una CVE già
pubblicata, e monta il repository al commit padre. Anche agent3, che non vede il
diff, opera su una vulnerabilità che *sappiamo* esserci ed è già stata corretta.
È il setting giusto per **misurare** la capacità dei modelli — serve una ground
truth — ma non è il caso d'uso reale.

**La direzione: agganciare gli agenti a vulnRadar.** `vulnRadar` è già uno
scanner giornaliero che seleziona i repository GitHub **più probabili candidati a
una CVE futura**, con quattro task in parallelo:

1. **Official** — interroga l'API NVD sulle CVE degli ultimi 30 giorni, estrae le
   coppie `(vendor, product)` dai CPE e risolve il repository GitHub reale senza
   mai indovinare il nome;
2. **Hot** — cerca commit delle ultime 7 giorni con parole chiave di sicurezza e
   li arricchisce con due segnali di *silent patch* (picco di attività e ampiezza
   della base utenti via download delle release);
3. **OSV** — dal database OSV;
4. **Criticality** — selezione per criticità con l'OpenSSF Criticality Score
   (`criticalityscore`, `pikecriticality`).

Dopo ogni giro incrocia le selezioni storiche con le CVE appena pubblicate per
verificare se le aveva "predette": alla data del 07/08/2026 il database contiene
**5.804 repository tracciati** e **1.348 match CVE**.

**L'integrazione.** Al posto di ricevere un commit dalla ground truth, agent3
riceverebbe i repository che vulnRadar seleziona ogni giorno, e li analizzerebbe
**prima** che la CVE esista. Il verdetto non sarebbe più confrontabile con
un'etichetta nota al momento dell'analisi, ma **validabile a posteriori** con lo
stesso meccanismo di incrocio che vulnRadar già implementa: se l'agente segnala
una vulnerabilità in un repository e settimane dopo compare una CVE con la CWE
corrispondente, quello è un vero positivo *prospettico*.

**Perché è il contributo più forte, come prospettiva.**
1. Elimina alla radice il problema della contaminazione: il codice analizzato non
   ha ancora una CVE, quindi non può essere nel training set di nessun modello.
2. Colma esattamente la finestra documentata nell'introduzione — fix pubblica
   oltre una settimana prima della disclosure (`colefunda2023`), release a 4
   giorni e advisory a +17 (`imtiaz2023opensneaky`) — perché opererebbe *dentro*
   quella finestra invece che a valle.
3. Nessuno dei benchmark visti (JitVul, VulnGym, ZeroDayBench) valuta in
   prospettiva: sono tutti retrospettivi su CVE note. Una validazione prospettica
   su CVE non ancora pubblicate sarebbe un contributo originale.

**Ostacoli da dichiarare onestamente.** Il costo: agent3 su deepseek impiega ~8
minuti e centinaia di migliaia di token per repository, contro i 30 repository
per task al giorno di vulnRadar. La verifica dei positivi richiede mesi di
attesa, e i veri positivi saranno rari. Serve infine una strategia per i falsi
positivi, che nel nostro run gemma sono il problema dominante (99 "sì" su 100 per
agent1 e agent2): in produzione un rilevatore che segnala quasi sempre è
inutilizzabile, e qui il risultato di `han2025llmsagents` — l'agente ReAct ha il
**false positive rate più basso** fra i tre metodi — diventa il riferimento
progettuale.
