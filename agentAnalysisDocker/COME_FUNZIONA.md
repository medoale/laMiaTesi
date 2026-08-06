# Come far girare un agente LLM dentro un container

Guida pratica e generica: come usare [OpenCode](https://opencode.ai) — un agente
che sa esplorare file e ragionare a più passi — dentro un container Docker,
collegato a un endpoint LLM **OpenAI-compatibile** (qualsiasi: un proxy LiteLLM,
vLLM, OpenRouter, un server locale…).

Serve per qualunque compito automatico su una cartella di file: analizzare un
progetto, generare un riassunto, estrarre dati, controllare qualcosa. Il compito
lo definisci tu nel prompt; l'infrastruttura è sempre questa.

L'idea di fondo: **non si scrive l'agente**. OpenCode sa già leggere file, fare
ricerche e ragionare in più passi. Il lavoro consiste nel configurarlo e
lanciarlo in modo controllato e ripetibile.

---

## Passo 0 — Prerequisiti

Verificare che l'endpoint risponda e vedere quali modelli espone:

```bash
curl https://IL_TUO_ENDPOINT/v1/models -H "Authorization: Bearer LA_TUA_CHIAVE"
```

I nomi restituiti vanno poi usati **esattamente** così com'è.

Scaricare l'immagine con OpenCode già installato:

```bash
docker pull docker/sandbox-templates:opencode
```

---

## Passo 1 — Dichiarare il provider

OpenCode conosce i provider più diffusi, ma un endpoint personalizzato va
dichiarato. Si crea un file `opencode.json`:

```jsonc
{
  "$schema": "https://opencode.ai/config.json",
  "provider": {
    "mio-provider": {                          // nome libero
      "npm": "@ai-sdk/openai-compatible",      // adattatore generico
      "options": {
        "baseURL": "https://IL_TUO_ENDPOINT/v1",  // NB: con /v1 finale
        "apiKey": "{env:MIA_API_KEY}"             // letta da variabile d'ambiente
      },
      "models": {
        "nome-modello-1": {},
        "nome-modello-2": {}
      }
    }
  }
}
```

Da qui in poi il modello si indica come **`mio-provider/nome-modello-1`**, cioè
`<nome-provider>/<nome-modello>`.

La chiave **non** va scritta nel file: `{env:MIA_API_KEY}` dice a OpenCode di
leggerla da una variabile d'ambiente, che passeremo al container.

---

## Passo 2 — Definire l'agente

Nello stesso file si definisce un "agente": il profilo di comportamento, cioè
quali strumenti può usare, con quali permessi e quanti passi al massimo.

```jsonc
"agent": {
  "mio-agente": {
    "mode": "primary",
    "temperature": 0,                    // 0 = risposte ripetibili
    "maxSteps": 200,                     // tetto ai giri di ragionamento
    "tools":      { "read": true, "glob": true, "grep": true, "bash": true,
                    "write": false, "edit": false },
    "permission": { "read": "allow", "glob": "allow", "grep": "allow",
                    "bash": "allow",
                    "webfetch": "deny", "websearch": "deny" },
    "prompt": "Istruzioni generali su come deve comportarsi l'agente."
  }
}
```

Punti che contano:

- **`permission: allow`** è indispensabile in modalità headless: senza, OpenCode
  si ferma a chiedere conferma per ogni azione e resta appeso all'infinito.
- **`maxSteps`** è l'unico freno al costo di una singola esecuzione: ogni passo
  è una chiamata al modello.
- **`write`/`edit` a `false`** se l'agente deve solo leggere e non modificare.
- **`webfetch`/`websearch` a `deny`** se non vuoi che vada su internet (occhio:
  con `bash` attivo potrebbe comunque usare `curl` — vedi in fondo).

---

## Passo 3 — Lanciare il container

Un container **effimero** per ogni esecuzione: `--rm` lo distrugge alla fine,
quindi nessuno stato sopravvive da un'esecuzione all'altra.

```bash
docker run --rm \
  -v /percorso/ai/file:/work:ro \            # cosa può leggere (sola lettura)
  -v /percorso/output:/output \              # dove scrive i risultati
  -v "$PWD/opencode.json:/opencode.json:ro" \
  -e OPENCODE_CONFIG=/opencode.json \        # dove sta la config
  -e MIA_API_KEY="$KEY" \                    # la chiave
  --entrypoint /bin/sh \
  docker/sandbox-templates:opencode /entrypoint.sh
```

Da codice è identico, costruito come lista di argomenti:

```python
cmd  = ['docker', 'run', '--rm']
cmd += ['-v', f'{workspace}:/work:ro', '-v', f'{output_dir}:/output']
cmd += ['-v', f'{config_file}:/opencode.json:ro']
cmd += ['-e', 'OPENCODE_CONFIG=/opencode.json', '-e', f'MIA_API_KEY={key}']
cmd += ['--entrypoint', '/bin/sh', 'docker/sandbox-templates:opencode', '/entrypoint.sh']
subprocess.run(cmd, timeout=1800, capture_output=True, text=True)
```

Il montaggio di `/output` è ciò che permette ai risultati di **sopravvivere alla
distruzione del container**.

---

## Passo 4 — Eseguire OpenCode in modalità headless

Lo script che gira **dentro** il container:

```sh
#!/bin/sh
# La sessione (transcript completo) va sotto /output, così resta sull'host
export XDG_DATA_HOME=/output/opencode-data
mkdir -p "$XDG_DATA_HOME"

PROMPT="$(cat /output/PROMPT.txt)"      # il compito, scritto dall'host

cd /work
opencode run -m "$MODELLO" --agent mio-agente --print-logs "$PROMPT" \
    >/output/answer.txt 2>/output/opencode.log
echo "$?" >/output/exit_code.txt
```

OpenCode legge il prompt, apre i file che ritiene utili e a ogni passo chiama
l'endpoint del modello, finché non produce la risposta finale. Quella va su
**stdout** (`answer.txt`), i log dell'attività su **stderr** (`opencode.log`).

Passare il prompt tramite file invece che come argomento evita problemi di
escaping con testi lunghi o con caratteri speciali.

---

## Passo 5 — Ottenere una risposta leggibile da un programma

Un LLM risponde in prosa. Per estrarne dati strutturati basta imporre un blocco
finale fisso nel prompt:

```
Puoi ragionare liberamente sopra, ma termina la risposta con esattamente
questo blocco:

RISULTATO: <valore>
MOTIVO: <una riga>
```

e poi estrarlo con una regex tollerante (maiuscole/minuscole, eventuale
grassetto markdown attorno al nome del campo):

```python
m = re.search(rf'\**{campo}\**\s*:\s*\**\s*([^\n*]+)', testo, re.IGNORECASE)
valore = m.group(1).strip() if m else None
```

Regola pratica: se la risposta **non** contiene il blocco valido, conviene
marcare l'esecuzione come fallita invece che riuscita — altrimenti resta un buco
silenzioso nei dati che non verrà mai ritentato.

---

## Problemi che si incontrano davvero

| Sintomo | Causa | Soluzione |
|---|---|---|
| `not a valid model ID` | nome modello incompleto | usare l'id esatto di `/v1/models`, prefisso provider incluso |
| Container appeso, nessuna richiesta al modello | OpenCode aspetta un permesso | `permission: allow` (o `--dangerously-skip-permissions`) |
| `answer.txt` vuoto con exit code 0 | il modello non ha concluso | prompt più stringente; controllare `maxSteps` |
| `503 No ready replicas` | modello spento lato server | attendere l'avvio (può richiedere minuti) |
| Tutto lentissimo | modelli "thinking" | disattivare il ragionamento se l'endpoint lo consente |
| HTTP 429 | rate limit | i limiti sono spesso **per account**, non per token: due token dello stesso utente non raddoppiano la quota |

Il secondo è il più insidioso: il container parte, sembra tutto a posto, ma non
arriva **nessuna richiesta** al modello — perché l'agente è fermo su una domanda
di autorizzazione che nessuno può leggere.

---

## Bloccare davvero internet (se serve)

Mettere `webfetch`/`websearch` su `deny` toglie gli strumenti web, ma se `bash`
è attivo l'agente può comunque usare `curl`. Per una garanzia reale serve una
barriera di rete:

1. si crea una rete Docker `--internal` (senza alcuna uscita verso internet) e
   ci si mette il container dell'agente;
2. si aggiunge un piccolo container proxy, collegato **sia** alla rete interna
   **sia** a quella normale, che inoltra solo verso gli host in allowlist;
3. si punta l'agente al proxy con `HTTPS_PROXY`.

La garanzia forte è la rete `--internal`: anche se l'agente ignorasse la
variabile d'ambiente, non esiste altra strada verso l'esterno.

---
