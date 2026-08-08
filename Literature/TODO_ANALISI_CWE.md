# TODO — metriche di corrispondenza CWE

Approcci da tentare per valutare quanto le CWE prodotte dagli agenti si
avvicinano alla ground truth. Sostituiscono la mappa "per famiglia" fatta a mano
usata nell'analisi preliminare, che **non è pubblicabile** (confini decisi a
occhio, copertura parziale, non riproducibile).

---

## Approccio 1 — Normalizzazione a livello fisso (stile CoLeFunDa)

Mappare **ogni** CWE al suo antenato a un livello prestabilito, poi confrontare
le etichette normalizzate. Non si decidono i passi di risalita, si decide la
**destinazione**: una Variant profonda può farne quattro, una Class uno solo.

- Precedente da citare: `colefunda2023`, che risale la vista **CWE-1000
  (Research Concepts)** per assegnare la *ancestor CWE category*.
- ⚠️ **Non copiare il loro risultato alla cieca.** Le loro 22 categorie mescolano
  pillar veri (CWE-664, CWE-691, CWE-693, CWE-707, CWE-284) con **vecchie
  categorie NVD deprecate** (CWE-16, CWE-19, CWE-254, CWE-264, CWE-310,
  CWE-399). Citarli per l'idea di aggregare, ma definire una regola di risalita
  pulita e dichiararla.

## Approccio 2 — Normalizzazione al livello Base (guidance MITRE)

Normalizzare ogni CWE al suo **antenato Base più vicino** e considerare match
l'uguaglianza a quel livello.

- Vantaggio: la soglia non è inventata da noi. MITRE indica il livello **Base**
  come la granularità corretta per mappare vulnerabilità reali, e sconsiglia
  Pillar e Class perché troppo astratti.
- È severo: CWE-787 e CWE-805 sono entrambe Base, quindi resterebbero distinte.
  Difendibile proprio per questo.
- ⚠️ **Da verificare prima di citare:** titolo esatto, URL e formulazione della
  mapping guidance MITRE (campo *Mapping Notes* con valori Allowed /
  Allowed-with-Review / Discouraged / Prohibited, introdotto attorno a CWE 4.9).
  Non ancora controllato di persona. I livelli di astrazione in sé
  (Pillar / Class / Base / Variant) sono invece documentati e citabili.

## Formato di presentazione — curva di tolleranza

Indipendentemente dall'approccio scelto, **riportare l'intera scala** invece di
una sola soglia: toglie di mezzo l'arbitrarietà e mostra il comportamento
completo.

| Criterio (cumulativo) | agent1 | agent2 | agent3 |
|---|---|---|---|
| CWE identica | | | |
| genitore o figlio diretto | | | |
| fratelli (stesso genitore) | | | |
| stesso antenato di livello Class | | | |
| stesso pillar | | | |

Se il grosso del guadagno arriva già alla riga "fratelli", è un risultato forte;
se serve salire fino al pillar, è un segnale debole — e va mostrato lo stesso.

---

## Cosa serve per implementarlo

- Scaricare il catalogo CWE da MITRE in formato leggibile da macchina.
  **Il dato non è in CVEfixes**: la tabella `cwe` ha `cwe_id`, `cwe_name`,
  `description`, `url`, `is_category`, ma **nessuna colonna di parentela**.
- Costruire il grafo delle relazioni `ChildOf` limitate alla vista **CWE-1000**.
  Usare solo `ChildOf` per la gerarchia: `PeerOf`, `CanPrecede` e `CanAlsoBe`
  sono relazioni diverse e più lasche.
- Calcolare, per ogni CWE, gli antenati e il livello di astrazione.

## Decisioni da dichiarare esplicitamente in tesi

1. **Quale vista** (CWE-1000 vs CWE-699): danno raggruppamenti diversi per la
   stessa CWE.
2. **Politica sul DAG**: una CWE può avere più genitori, quindi i percorsi di
   risalita sono multipli. Match se *qualunque* percorso tocca un antenato
   comune, oppure solo lungo il genitore primario? Due statistiche diverse,
   entrambe legittime, ma va detto quale.
3. **Livello di aggregazione** e sua giustificazione.
4. **Esclusione dei segnaposto**: nella ground truth c'è un `NVD-CWE-noinfo`
   (NVD non ha assegnato alcuna CWE). Non è una debolezza: va escluso dal
   calcolo, non contato come errore.

## Avvertenze sui numeri

- 50 campioni, **41 CWE distinte**: quasi ogni classe compare una volta sola.
  Qualunque aggregazione produrrà celle da uno o due elementi.
- Riportare sempre i **conteggi assoluti accanto alle percentuali**: "6 su 27"
  dice la verità, "22%" da solo suggerisce una precisione inesistente.
- **Niente confusion matrix per CWE**: con questi numeri sarebbe rumore.
- I valori dell'analisi preliminare (73% e 79% "per famiglia") vengono dalla
  mappa fatta a mano: **da non citare**, cambieranno con la gerarchia vera.
