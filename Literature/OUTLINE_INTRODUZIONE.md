# Scaletta — Introduzione, domande 1–5

Traccia operativa per la sezione *Problem & Motivation*. Ogni punto riporta la
chiave BibTeX da citare e il numero esatto.

Q1–Q4 stanno in *Problem & Motivation*; **Q5 apre la sezione *Methodology***.

**Regola di ingaggio:** l'introduzione deve *convincere*, non documentare. Il
Background documenta. **Nessuna cifra prodotta da questo lavoro compare in
introduzione**: le misure nostre stanno nei capitoli di metodo, dati e risultati;
qui si citano solo numeri della letteratura. Dove un punto è segnato → *Background*, il numero non va
messo qui.

---

## Q1 — Qual è il problema

### L'open source è l'infrastruttura di tutto

- Il software open source è la base su cui poggia praticamente ogni sistema
  informatico moderno.
- **97%** delle codebase dipende da OSS; **86%** contiene almeno una
  vulnerabilità nota; **81%** ha problemi di severità alta o critica.
  → `han2025llmsagents` (che riporta il Black Duck Open Source Security and Risk
  Analysis Report 2025)
- GitHub è di fatto la casa dell'open source: oltre **200 milioni di repository
  attivi**. → `ayala2025disclosures`
- Punto chiave da far emergere: la piattaforma è costruita attorno al **commit**,
  quindi ogni singola modifica al codice è **pubblicamente ispezionabile riga per
  riga**, da chiunque, nel momento stesso in cui viene pubblicata.

### Il software viene continuamente modificato, anche per motivi di sicurezza

- I progetti OSS ricevono aggiornamenti costanti: nuove funzionalità,
  refactoring, correzioni di bug e **correzioni di sicurezza**, tutti mescolati
  nello stesso flusso di commit.
- Il modello di *Coordinated Vulnerability Disclosure* (CVD) prescrive di
  **correggere prima e divulgare dopo**. Conseguenza diretta e strutturale: la
  fix è pubblica **prima** che la vulnerabilità sia nota.
  → `colefunda2023`

### Le patch sono silenziose

- Per non offrire indizi agli attaccanti, la CVD raccomanda che il commit di fix
  **non dichiari** di essere una correzione di sicurezza: niente parole chiave,
  niente riferimenti alla CVE. Sono le cosiddette **silent fix**.
  → `colefunda2023`
- 📌 **DECISO: l'esempio Log4Shell NON va in introduzione, ma nella literature
  review.** L'introduzione spiega il meccanismo in astratto; il caso concreto
  serve dove si discute la letteratura sulle silent fix.
  Materiale, da riusare lì: **Log4Shell / CVE-2021-44228**, divulgata il
  **10 dicembre 2021**, con la fix pubblica dal **29 novembre 2021**, **11
  giorni prima**. Il messaggio di commit diceva soltanto *"Restrict LDAP access
  via JNDI"*, senza alcun riferimento alla sicurezza. → `colefunda2023`
- Il paradosso da esplicitare: **la misura pensata per proteggere gli utenti
  li lascia all'oscuro**, mentre chi sa leggere il codice vede tutto.

### Rimando al dato originale (senza cifre)

> ⚠️ **Nessun numero nostro in introduzione.** Le misure prodotte da questo
> lavoro — divario fix→pubblicazione, copertura, accuratezza CWE — appartengono
> ai capitoli dei dati e dei risultati.

- Qui basta un **rimando qualitativo**: il fenomeno descritto da `colefunda2023`
  non viene assunto ma *verificato* su un campione recente e indipendente, e la
  misura è riportata nel capitolo dedicato.
- Formulazione possibile: *"Questo lavoro conferma il fenomeno su un campione di
  CVE recenti, come mostrato nel Capitolo N."* Nessuna cifra.

### Gli utenti restano su software vulnerabile

- **81,5%** di oltre 4.600 progetti GitHub analizzati mantiene dipendenze
  obsolete. → Kula et al., citato in `ayala2025disclosures`
- **91%** delle codebase contiene componenti indietro di **10 o più versioni**.
  → `han2025llmsagents`

---

## Q2 — Perché è importante

### Le tre finestre temporali (distinguerle, non confonderle)

| # | Da → a | Durata | Fonte |
|---|---|---|---|
| 1 | commit di fix → **release** che la contiene | mediana **4 giorni**, **25% oltre 20 giorni** | `imtiaz2023opensneaky` |
| 2 | release → **advisory** (Snyk, NVD) | mediana **17 giorni** → *Background* | `imtiaz2023opensneaky` |
| 3 | commit di fix → **pubblicazione CVE** | mediana > 1 settimana | `colefunda2023` (la nostra misura va nel capitolo dei dati) |

### Il punto centrale: nella finestra 1 l'utente non può aggiornare

- Non è negligenza dell'utente: **la release non esiste ancora**. Il codice della
  fix è pubblico su GitHub, ma il pacchetto installabile no.
- Mediana **4 giorni**, ma per **un quarto dei casi almeno 20 giorni**.
  → `imtiaz2023opensneaky`
- Anche quando la release arriva, **solo il 61,5% delle release note documenta la
  correzione di sicurezza**: in un caso su tre l'utente non sa che
  quell'aggiornamento è urgente. È il *"sneaky"* del titolo del paper.
  → `imtiaz2023opensneaky`

### L'asimmetria informativa — da scrivere esplicitamente

> All'attaccante serve **una sola cosa, disponibile al giorno zero: il commit**.
> Al difensore ne servono **tre**: che esista una release, che sappia che è
> critica, o in alternativa che l'advisory sia stato pubblicato.

- È il cuore della motivazione: la finestra **non è un incidente, è strutturale**
  nel processo di disclosure. Non si chiude dicendo agli utenti di aggiornare.

### Le domande che definiscono la posta in gioco

Da porre esplicitamente in introduzione, perché diventano le domande di ricerca:

- Un attaccante può leggere il **diff** di una silent fix e ricostruire quale
  vulnerabilità c'era prima, così da colpire chi non ha ancora aggiornato?
- Gli attaccanti possono usare **AI accessibili e generiche** per scoprire
  **nuove** vulnerabilità?
- Essendo il codice aperto, **quanto è facile** individuare una vulnerabilità
  *prima* che venga corretta?

### La seconda domanda è già supportata — e la tensione tra le fonti è il gap

Non serve aggiungere riferimenti: bastano due lavori già in bibliografia, che
dicono cose opposte. È proprio il contrasto a definire lo spazio della tesi.

**Sì, gli agenti LLM trovano davvero vulnerabilità nuove.**
FuzzingBrain V2 ha scoperto **29 zero-day in 12 progetti open source, tutte
confermate e corrette dai manutentori, 2 con CVE assegnata**, e raggiunge il
**90% (36 su 40)** sul dataset C/C++ della finale DARPA AIxCC 2025.
→ `fuzzingbrain2026`. Sulla stessa linea, audit condotti interamente da agenti
LLM autonomi che individuano vulnerabilità critiche in software fondamentale
→ `codeaugur2026`.

**No, i modelli di frontiera da soli non ce la fanno.**
Su un benchmark costruito apposta contro la contaminazione, con **22
vulnerabilità critiche nuove**, gli autori concludono che *"i modelli LLM di
frontiera non sono ancora in grado di risolvere autonomamente i nostri task"* —
testando GPT-5.2, Claude Sonnet 4.5 e Grok 4.1. → `zerodaybench2026`

**Da qui il gap, e va scritto così.** I sistemi che *riescono* sono pesanti e
specializzati: architetture multi-agente, integrazione con OSS-Fuzz, analisi
dinamica, strumenti dedicati, finanziamenti DARPA. I modelli generici da soli
*non riescono*. Resta scoperta la fascia intermedia, ed è esattamente quella che
un attaccante reale ha a disposizione: **un modello accessibile, un ciclo
agentico standard, strumenti di sola lettura, nessun fuzzing e nessuna analisi
dinamica**. È la configurazione di agent3, ed è ciò che questa tesi misura.

*(Nota: con questa formulazione CVE-Bench non serve più — riguarda lo
sfruttamento di vulnerabilità già note in applicazioni web, non la scoperta.
Resta correttamente fuori dalla bibliografia.)*

### Inquadratura offensiva/difensiva (una frase qui, sviluppo nel Background)

- I tre agenti del lavoro corrispondono a tre posizioni reali:

| Agente | Cosa vede | Chi simula |
|---|---|---|
| agent1 | solo il diff | l'**attaccante** che weaponizza una silent patch |
| agent2 | repository + diff | attaccante con più contesto / difensore che fa triage |
| agent3 | solo il repository | cacciatore di **zero-day** |

- Il costo misurato (tempo per run, token) è di fatto una **stima del costo per
  l'attaccante**.

### Nota etica (un paragrafo, non di più)

- Strumento a doppio uso: la stessa capacità serve a chi attacca e a chi difende.
- Precedente da citare: `colefunda2023` dichiara esplicitamente che il proprio
  strumento *"può essere usato sia da attori malevoli sia dagli utenti OSS"* e
  motiva la scelta di renderlo aperto con intento difensivo. Adottare la stessa
  posizione.

---

## Q3 — Perché è difficile

### 1. Volume — l'ago nel pagliaio

- Le fix di sicurezza sono **1,71%** dei commit nel dataset di riferimento, con
  una mediana per progetto dello **0,35%**. → `colefunda2023`
- Il lavoro precedente sul tema si intitola letteralmente *Finding a Needle in a
  Haystack*. → `vulfixminer2021`

### 2. Silenzio — il metadato non aiuta

- Il messaggio di commit è inutile o fuorviante per costruzione (vedi Log4Shell).
- L'unica fonte affidabile è **il codice stesso**, che va letto e capito.

### 3. Contesto — non basta guardare la funzione

- Le vulnerabilità reali emergono da **catene di chiamate interprocedurali**, non
  da funzioni isolate. → `yildiz2025jitvul`
- Le fix che coinvolgono **più file** sono proprio quelle su cui gli approcci a
  livello di funzione falliscono. → `colefunda2023` (limiti dichiarati)

### 4. Classificare è più difficile che rilevare

- Non basta dire *"c'è una vulnerabilità"*: serve dire **quale**.
- **52,8%** delle categorie CWE ha meno di 3 CVE associate: le classi sono
  estremamente sbilanciate e sparse. → `colefunda2023`

### 5. Gli strumenti automatici esistenti sono meno affidabili di quanto sembri

- Passando da un dataset "facile" a uno costruito con criteri realistici, l'F1
  crolla da **68% a 3%**. → `primevul2025`
- Non è un caso isolato: già nell'era pre-LLM le prestazioni calavano di **oltre
  il 50%** in scenari realistici, perché i modelli imparavano artefatti dei
  dataset invece che vulnerabilità. → `reveal2022`
- Conclusione da trarre: i numeri pubblicati vanno presi con cautela, e serve una
  valutazione costruita con attenzione — che è ciò che questa tesi fa.

### 6. Costruire una ground truth su cui misurare è a sua volta un problema aperto

- Per valutare qualunque approccio automatico serve un insieme di riferimento:
  coppie **(vulnerabilità, commit che la corregge)**. Ma collegare una CVE al
  commit GitHub che la risolve **non è un'informazione già disponibile**.
- Due ostacoli documentati:
  - molte voci CVE **non riportano affatto il commit di patch**;
  - tra quelle che lo riportano, una quota significativa dei commit diventa
    **irraggiungibile** nel tempo, perché i repository vengono rinominati,
    archiviati o riscritti (*link rot*).
  → `gitpatchdb2026`
- La difficoltà è tale che esiste una linea di ricerca dedicata al solo compito
  di **tracciare la patch di una CVE**. → `liu2025sitpatchtracer`
- **Come lo risolviamo:** la ground truth di questo lavoro non è costruita a
  mano ma tramite **CVEfixes**, che automatizza la raccolta delle CVE e dei loro
  commit di fix a partire da NVD e dai repository. → `cvefixes2021`
- ⚠️ *Se serve una percentuale precisa sulle CVE prive di riferimento alla patch,
  va estratta dal corpo di GitPatchDB: l'abstract parla di "many" e "a
  significant share", senza cifre.*

### 7. Farlo a mano non scala

- L'analisi manuale di ogni commit richiede competenze di sicurezza e tempo
  proporzionale al volume: impraticabile su 200 milioni di repository.

---

## Q4 — Cosa è stato fatto finora, e perché non basta

**Tenere breve e impreciso**: qui bastano due paragrafi con citazioni raggruppate
e zero numeri. Lo stato dell'arte vero è compito del capitolo Background. Il
materiale sotto è il serbatoio da cui pescare, non tutto va scritto.

### Fase 1 — Identificare le fix silenziose (pre-LLM)

- `vulfixminer2021` apre il filone: transformer sulle modifiche a livello di
  commit per riconoscere le silent fix. Il titolo stesso — *Finding a Needle in
  a Haystack* — dichiara la difficoltà.
- `colefunda2023` è il lavoro concettualmente più vicino all'intero sistema:
  - argomenta che **identificare la fix è solo il primo passo**: senza sapere
    *quale* debolezza e quanto sia sfruttabile, l'utente non sa che farsene
    dell'allarme. Da qui la pipeline a tre task (identificazione, CWE,
    exploitability);
  - risolve la sparsità delle CWE **aggregando per antenato** su CWE-1000: da 89
    tipi a 22 categorie;
  - il suo user study è l'unico termine di paragone numerico onesto che abbiamo:
    **37,5% al primo suggerimento, 62,5% entro i primi due**;
  - dichiara esplicitamente il problema del **doppio uso**: precedente utile per
    la nostra nota etica (§Q2).
  - **Limiti dichiarati dagli autori**: solo Java, analisi a livello di funzione
    (fallisce sulle fix multi-file), nessun LLM e nessun agente.

### Fase 2 — LLM e agenti

- `han2025llmsagents` confronta Plain LLM, Data-Aug LLM e ReAct Agent sullo
  stesso task: il Data-Aug vince sull'accuratezza complessiva, ma **l'agente
  ReAct ha il false positive rate più basso**. Usa DeepSeek e Gemma, gli stessi
  due modelli che confrontiamo noi.
- `yildiz2025jitvul` è il più vicino al nostro impianto e merita una frase
  propria, non una parentesi:
  - costruisce **JitVul**: 879 CVE, 91 tipi di CWE, ogni funzione collegata
    **sia al commit che introduce la vulnerabilità sia a quello che la corregge**;
  - si posiziona contro ReposVul (6.134 CVE) e VulEval (4.196) rivendicando due
    cose che quelli non hanno: **valutazione a coppie** e **valutazione di agenti**;
  - **risultato metodologico centrale**: un F1 più alto **non** indica una
    migliore capacità di cogliere la vulnerabilità. I metodi LLM predicono
    "vulnerabile" in oltre il **90%** dei casi in certe configurazioni: recall
    altissimo, precisione ferma intorno al **50%**, F1 gonfiato. Da qui la
    **pairwise accuracy (pAcc)**, ispirata a PrimeVul, che conta solo le coppie
    in cui **entrambe** le versioni sono etichettate correttamente;
  - **gli agenti ReAct vincono su pAcc** (+9,46% e +8,42% sugli LLM con contesto
    pre-caricato) grazie al recupero **adattivo**: invocano gli strumenti una-tre
    volte per prendere i chiamanti che servono, invece di scaricare i Top-5 per
    similarità Jaccard introducendo rumore;
  - CoT e few-shot migliorano gli LLM su pAcc (1,26%–17,76%) ma non
    sistematicamente su F1;
  - concludono che entrambi gli approcci mostrano **analisi incoerenti** tra
    versione vulnerabile e corretta: manca robustezza.

### Fase 3 — Repository interi e zero-day

- `vulngym2026`: 184 advisory, 408 voci, 23 repository con annotazioni a livello
  di riga. Motivazione dichiarata: i benchmark esistenti classificano **snippet
  preselezionati**, mentre un agente deve esplorare il repository da sé. È il
  setting di agent3.
- `zerodaybench2026`: 22 vulnerabilità critiche nuove, trapiantate in repository
  diversi per evitare la contaminazione. Conclusione: **i modelli di frontiera
  non sono ancora in grado di risolvere autonomamente i task**.
- `fuzzingbrain2026` e `codeaugur2026` mostrano il contrario, ma con sistemi
  pesanti (multi-agente, OSS-Fuzz, analisi dinamica): **29 zero-day reali in 12
  progetti, 2 con CVE assegnata**.

### Fase 4 — L'affidabilità della valutazione

- `reveal2022`: le prestazioni dei modelli DL calano di oltre il 50% in scenari
  realistici, perché imparavano artefatti dei dataset.
- `primevul2025`: stesso fenomeno un'era dopo — F1 dal 68% al 3% cambiando
  dataset. Introduce la valutazione a coppie che JitVul poi adotta.
- `javavulbench2026`: la contaminazione da pre-training, con la partizione
  "risky" / "clean" rispetto al cutoff del modello.

### Perché il problema non è chiuso

Da usare come **una sola frase di tensione** in chiusura di sezione;
l'argomentazione completa va in Q5.

- Chi **riesce** a trovare zero-day usa sistemi specializzati e costosi; i
  modelli generici da soli **non ci riescono**. La fascia intermedia — modello
  accessibile, ciclo agentico standard, soli strumenti di lettura — non risulta
  misurata, ed è quella realisticamente disponibile a un attaccante.
- Ogni lavoro **fissa un'unità di analisi** e misura lì dentro. Nessuno tiene
  fermo il commit variando **soltanto** quanto l'agente vede.
- Quasi tutti si fermano al **binario**; la classificazione CWE resta appannaggio
  dei lavori pre-LLM.
- Lo dicono gli autori stessi: JitVul chiude affermando che gli agenti ReAct
  necessitano di design più mirati e che manca robustezza.

> ⚠️ **Non scrivere "nessuno ha mai fatto X".** Usare *"per quanto ci risulta"*,
> o meglio girare in positivo: *"questi lavori rispondono a domande diverse"*.
> Più difficile da smentire e altrettanto efficace.

### Due elementi emersi dalla lettura di JitVul

- **Il problema di formato è documentato in letteratura.** JitVul riporta che
  gli agenti ReAct con **Llama3.1-8B** mostrano prestazioni molto inferiori, con
  il processo che **spesso fallisce per problemi di formattazione e parsing**.
  Il nostro 22% di run non conformi su deepseek non è un'anomalia del setup: è
  un fenomeno osservato indipendentemente. Citazione preziosa, da affiancare a
  `agentif2025` e `firebench2026`.
- ⚠️ **Obiezione da anticipare.** Il messaggio centrale di JitVul è che l'F1
  inganna quando il modello dice "vulnerabile" quasi sempre, e che il rimedio è
  la **valutazione a coppie**. È esattamente la nostra situazione: agent1 e
  agent2 rispondono "sì" nel 96–100% dei casi. Un revisore che conosce JitVul
  chiederà perché non abbiamo valutato a coppie, **avendo i commit di fix**:
  basterebbe far girare l'agente anche sulla versione corretta e verificare che
  risponda "no". Da valutare prima della stesura definitiva.

---

## Q5 — Cosa abbiamo fatto, e a cosa risponde

Apre la sezione **Methodology**. Per decisione presa: **il gap si argomenta qui**,
non in Q4, così da essere adiacente al contributo. In fondo a Q4 resta solo una
frase di tensione.

### 1. Aprire con il gap, non con la descrizione tecnica

Prima frase della sezione, altrimenti il lettore arriva agli agenti Docker senza
sapere che problema risolvono. Due gap, non di più:

- **Gap A — la fascia intermedia non è misurata.** I sistemi che trovano zero-day
  sono pesanti e specializzati (`fuzzingbrain2026`, `codeaugur2026`); i modelli di
  frontiera da soli non ci riescono (`zerodaybench2026`). Nessuno misura la
  configurazione **realisticamente disponibile a un attaccante**: modello
  accessibile, ciclo agentico standard, soli strumenti di lettura.
- **Gap B — nessuno isola il contesto come variabile.** I lavori esistenti fissano
  un'unità di analisi e misurano lì dentro: la funzione con contesto
  interprocedurale (`yildiz2025jitvul`), il repository intero (`vulngym2026`), il
  diff (`han2025llmsagents`). **Nessuno tiene fermo il commit variando soltanto
  quanto l'agente vede.**

> ⚠️ Formulare i gap in modo **neutro rispetto all'esito**: *"nessuno ha misurato
> cosa un'AI accessibile riesca a fare"*, **non** *"nessuno ha dimostrato che
> riesca"*. La seconda crea un'aspettativa che i dati poi deludono.

### 2. Il disegno sperimentale: tre scenari, una sola variabile

Il cuore del contributo. Stesso commit, tre livelli di contesto:

| Agente | Cosa vede | Domanda | Chi simula |
|---|---|---|---|
| agent1 | solo il diff (before / after / diff) | il segnale della patch basta? | attaccante che weaponizza una silent patch |
| agent2 | repository + diff | il contesto aggiunge qualcosa? | attaccante con più contesto / difensore in triage |
| agent3 | solo il repository | si può trovare senza indizi? | cacciatore di zero-day |

**Tutto il resto è tenuto costante**: stesso prompt, stesso modello,
`temperature 0`, stesso tetto di 200 tool round, stesso isolamento, stesso
formato di output richiesto. È ciò che rende l'impianto un **esperimento
controllato** e non un ennesimo benchmark — ed è la risposta diretta al Gap B.

### 3. I controlli che rendono i numeri credibili

Da elencare in modo compatto, sono quattro:

- **Contaminazione risolta per costruzione**: il campione è ristretto alle sole
  CVE **pubblicate nel 2026** (filtro `published_date` a monte della pipeline),
  quindi successive al cutoff dei modelli. Confronto utile: `javavulbench2026`
  partiziona in "risky"/"clean", il nostro campione è interamente clean.
  *(Le numerosità esatte vanno nel capitolo della metodologia.)*
- **Isolamento di rete**: container su rete Docker `--internal`, proxy con
  allowlist verso il solo endpoint del modello. **L'agente non può cercare la CVE
  online**, nemmeno avendo `bash`.
- **Ground truth non costruita a mano** ma con `cvefixes2021`, che risolve il
  problema di tracciabilità CVE↔commit documentato in `gitpatchdb2026`.
- **Nessun sotto-agente**: vietato per non concedere a un modello un budget di
  contesto maggiore di un altro.

### 4. Cosa misuriamo, e cosa no

Da dichiarare subito, perché è una scelta onesta che previene obiezioni:

- **Il dataset è composto solo da istanze positive.** Ogni commit corregge una CVE
  reale e il repository è montato al commit padre: la vulnerabilità c'è sempre.
- Conseguenza: si misurano **recall** e **accuratezza della classificazione CWE**.
  **Non** si misurano accuratezza, precisione di detection, falsi positivi,
  specificità.
- Due stadi:
  - **Stadio 1 — copertura**: su tutte le istanze, in quale frazione l'agente
    riconosce che c'è qualcosa. Il trend fra i tre scenari è già un risultato.
  - **Stadio 2 — accuratezza CWE condizionata**: solo dove l'agente ha prodotto
    una CWE, quanto è corretta. Metriche multi-etichetta (hit, top-1, exact set,
    F1 per esempio).

### 5. I contributi, in forma di elenco

- Un **impianto sperimentale controllato** che isola il contesto come unica
  variabile, su ground truth priva di contaminazione.
- La **prima misura della configurazione "accessibile"**: modello generico,
  harness standard, soli strumenti di lettura.
- Una lettura in chiave **offensiva**: il costo misurato (tempo, token) è una
  stima del costo per l'attaccante.
- La **valutazione congiunta di rilevamento e classificazione CWE**, dove quasi
  tutta la letteratura si ferma al binario.
- L'**aderenza al formato trattata come risultato** e non come rumore, con
  `agentif2025`, `firebench2026` e l'osservazione analoga in `yildiz2025jitvul`.

### 6. La frase conclusiva — lasciare segnaposto

L'esito va scritto **per ultimo**, quando l'analisi è chiusa. Il gap non dipende
dai risultati, la frase di chiusura sì: cambia il verbo (*"mostriamo che è
possibile"* contro *"mostriamo i limiti di"*), non la premessa.

Direzione che i dati preliminari suggeriscono, **da esprimere in forma
qualitativa e senza cifre**: l'AI accessibile è una minaccia concreta per
weaponizzare una patch già pubblicata, molto meno per scoprire vulnerabilità da
zero. Più interessante di entrambi gli estremi — ma da confermare.

---

## Budget delle statistiche in introduzione

Tenere **poche cifre, scelte per colpire**. Proposta:

| Tenere in introduzione | Spostare nel Background |
|---|---|
| 97% / 86% (ubiquità OSS) | 81% severità alta, 91% dieci versioni indietro |
| Log4Shell: 11 giorni | timeline completa a tre finestre |
| 4 giorni mediani fix → release | 17 giorni release → advisory, coda dei 20 giorni |
| 61,5% release note | 197.609 advisory non revisionati |
| *(nessuna cifra nostra)* | tutte le misure prodotte da questo lavoro |
| 1,71% fix sui commit | 0,35% mediana per progetto, 52,8% sparsità CWE |
| 68% → 3% di F1 | calo >50% di ReVeal |

---

## Arco narrativo suggerito

1. L'open source è ovunque e tutto è pubblico → **Q1**
2. Le fix arrivano prima della divulgazione e sono silenziose (Log4Shell) → **Q1**
3. L'utente non può aggiornare anche volendo: l'asimmetria → **Q2**
4. Da qui le domande: l'attaccante può farlo? con un'AI? quanto costa? → **Q2**
5. Ma farlo è difficile, per cinque ragioni misurabili → **Q3**
6. Altri ci hanno provato, il problema resta aperto perché… → **Q4** (breve)
7. Questa tesi fa X e risponde a Y → **Q5**
