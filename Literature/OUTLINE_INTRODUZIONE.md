# Scaletta — Introduzione, domande 1–3

Traccia operativa per la sezione *Problem & Motivation*. Ogni punto riporta la
chiave BibTeX da citare e il numero esatto. Le domande 4 e 5 sono da definire.

**Regola di ingaggio:** l'introduzione deve *convincere*, non documentare. Il
Background documenta. Dove un punto è segnato → *Background*, il numero non va
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
- **Esempio portante da usare in apertura — Log4Shell / CVE-2021-44228:**
  divulgata il **10 dicembre 2021**, ma la fix era pubblica dal **29 novembre
  2021**, **11 giorni prima**. Il messaggio di commit diceva soltanto
  *"Restrict LDAP access via JNDI"*, senza alcun riferimento alla sicurezza.
  → `colefunda2023`
- Il paradosso da esplicitare: **la misura pensata per proteggere gli utenti
  li lascia all'oscuro**, mentre chi sa leggere il codice vede tutto.

### Dato originale della tesi (anticiparlo qui, misurarlo nel capitolo dati)

- Sul campione di **51 CVE pubblicate nel 2026** usato in questo lavoro, il
  **92% delle fix precede la pubblicazione della CVE**, con una **mediana di 15
  giorni** e un caso estremo di **2.500 giorni** (fix del 2019 per una CVE
  divulgata nel 2026).
- Serve a due cose: conferma su dati recenti e indipendenti la premessa di
  `colefunda2023`, e annuncia che la tesi *misura* il fenomeno, non lo assume.

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
| 3 | commit di fix → **pubblicazione CVE** | mediana 15 giorni (dato nostro) | `colefunda2023` + dato originale |

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

### 6. Farlo a mano non scala

- L'analisi manuale di ogni commit richiede competenze di sicurezza e tempo
  proporzionale al volume: impraticabile su 200 milioni di repository.

---

## Budget delle statistiche in introduzione

Tenere **poche cifre, scelte per colpire**. Proposta:

| Tenere in introduzione | Spostare nel Background |
|---|---|
| 97% / 86% (ubiquità OSS) | 81% severità alta, 91% dieci versioni indietro |
| Log4Shell: 11 giorni | timeline completa a tre finestre |
| 4 giorni mediani fix → release | 17 giorni release → advisory, coda dei 20 giorni |
| 61,5% release note | 197.609 advisory non revisionati |
| 15 giorni mediani (dato nostro) | 92% e caso da 2.500 giorni |
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
