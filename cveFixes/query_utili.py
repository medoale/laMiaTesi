import sqlite3

DB = '/home/medo/laMiaTesi/cveFixes/CVEfixes/Code/Data/CVEfixes.db'


def conn():
    return sqlite3.connect(DB)


def q1_conteggio_tabelle():
    c = conn()
    for t in ['cve', 'fixes', 'commits', 'file_change', 'method_change', 'cwe', 'cwe_classification', 'repository']:
        n = c.execute(f'SELECT COUNT(*) FROM {t}').fetchone()[0]
        print(f'{t}: {n}')
    c.close()


def q2_repo_con_codice_prima_e_dopo():
    c = conn()
    n_repo = c.execute("""
        SELECT COUNT(DISTINCT co.repo_url)
        FROM commits co
        JOIN file_change f ON f.hash = co.hash
        WHERE f.code_before != '' AND f.code_after != ''
    """).fetchone()[0]
    n_file = c.execute("""
        SELECT COUNT(*) FROM file_change
        WHERE code_before != '' AND code_after != ''
    """).fetchone()[0]
    print(f'Repo con code_before e code_after: {n_repo}')
    print(f'File change con code_before e code_after: {n_file}')
    c.close()


def q3_cve_per_repo():
    repo = input('URL repo (es. https://github.com/python/cpython): ').strip()
    c = conn()
    rows = c.execute("""
        SELECT f.cve_id, cv.severity, cv.cvss3_base_score, co.hash, co.msg
        FROM fixes f
        JOIN cve cv     ON cv.cve_id = f.cve_id
        JOIN commits co ON co.hash   = f.hash
        WHERE f.repo_url = ?
        ORDER BY cv.cvss3_base_score DESC
    """, (repo,)).fetchall()
    print(f"\n{'CVE ID':<20} {'Severity':<10} {'Score':>5}  {'Hash':<9}  Commit message")
    print('─' * 90)
    for cve_id, severity, score, hash_, msg in rows:
        subject = (msg or '').split('\n')[0][:50]
        score_s = f'{float(score):.1f}' if score not in (None, '') else '  n/a'
        print(f'{cve_id:<20} {(severity or "n/a"):<10} {score_s:>5}  {hash_[:9]}  {subject}')
    c.close()


def q4_top20_repo_per_cve():
    c = conn()
    rows = c.execute("""
        SELECT repo_url, COUNT(DISTINCT cve_id) as n
        FROM fixes
        GROUP BY repo_url
        ORDER BY n DESC
        LIMIT 20
    """).fetchall()
    print(f"\n{'Repo':<55} {'CVE':>5}")
    print('─' * 62)
    for repo, n in rows:
        print(f'{repo:<55} {n:>5}')
    c.close()


def q5_distribuzione_severita():
    c = conn()
    rows = c.execute("""
        SELECT COALESCE(severity, 'n/a') as sev, COUNT(*) as n
        FROM cve
        GROUP BY sev
        ORDER BY n DESC
    """).fetchall()
    print(f"\n{'Severity':<12} {'Count':>7}")
    print('─' * 20)
    for sev, n in rows:
        print(f'{sev:<12} {n:>7}')
    c.close()


def q6_top20_cwe():
    c = conn()
    rows = c.execute("""
        SELECT cc.cwe_id, cw.cwe_name, COUNT(*) as n
        FROM cwe_classification cc
        LEFT JOIN cwe cw ON cw.cwe_id = cc.cwe_id
        GROUP BY cc.cwe_id
        ORDER BY n DESC
        LIMIT 20
    """).fetchall()
    print(f"\n{'CWE ID':<12} {'Count':>6}  Nome")
    print('─' * 70)
    for cwe_id, name, n in rows:
        print(f'{cwe_id:<12} {n:>6}  {(name or "")[:50]}')
    c.close()


def q7_distribuzione_linguaggi():
    c = conn()
    rows = c.execute("""
        SELECT COALESCE(programming_language, 'n/a') as lang, COUNT(*) as n
        FROM file_change
        GROUP BY lang
        ORDER BY n DESC
        LIMIT 20
    """).fetchall()
    print(f"\n{'Linguaggio':<20} {'File changes':>12}")
    print('─' * 34)
    for lang, n in rows:
        print(f'{lang:<20} {n:>12}')
    c.close()


def q8_linee_cambiate_per_severita():
    c = conn()
    rows = c.execute("""
        SELECT COALESCE(cv.severity, 'n/a') as sev,
               ROUND(AVG(co.num_lines_added + co.num_lines_deleted), 1) as avg_lines,
               COUNT(*) as n_commits
        FROM cve cv
        JOIN fixes f    ON f.cve_id  = cv.cve_id
        JOIN commits co ON co.hash   = f.hash
        GROUP BY sev
        ORDER BY avg_lines DESC
    """).fetchall()
    print(f"\n{'Severity':<12} {'Avg lines changed':>18} {'Commits':>9}")
    print('─' * 42)
    for sev, avg, n in rows:
        print(f'{sev:<12} {avg:>18} {n:>9}')
    c.close()


def q9_codice_prima_e_dopo():
    cve = input('CVE ID (es. CVE-2025-4517): ').strip()
    c = conn()
    rows = c.execute("""
        SELECT f.filename, f.programming_language, f.code_before, f.code_after
        FROM fixes fx
        JOIN file_change f ON f.hash = fx.hash
        WHERE fx.cve_id = ?
          AND f.code_before != '' AND f.code_after != ''
    """, (cve,)).fetchall()
    for filename, lang, before, after in rows:
        print(f'\n{"═"*60}')
        print(f'File: {filename}  [{lang}]')
        print(f'{"─"*30} BEFORE {"─"*30}')
        print((before or '')[:800])
        print(f'{"─"*30} AFTER  {"─"*30}')
        print((after or '')[:800])
    c.close()


MENU = {
    '1': ('Conteggio righe di tutte le tabelle',       q1_conteggio_tabelle),
    '2': ('Repo con code_before e code_after',          q2_repo_con_codice_prima_e_dopo),
    '3': ('CVE e fix di una repo specifica',            q3_cve_per_repo),
    '4': ('Top 20 repo per numero di CVE',              q4_top20_repo_per_cve),
    '5': ('Distribuzione CVE per severità',             q5_distribuzione_severita),
    '6': ('Top 20 CWE',                                 q6_top20_cwe),
    '7': ('Distribuzione per linguaggio',               q7_distribuzione_linguaggi),
    '8': ('Media linee cambiate per severità',          q8_linee_cambiate_per_severita),
    '9': ('Codice prima e dopo per una CVE specifica',  q9_codice_prima_e_dopo),
}

if __name__ == '__main__':
    print('\n═══════════════════════════════════')
    print('  CVEfixes — Query utili')
    print('═══════════════════════════════════')
    for k, (desc, _) in MENU.items():
        print(f'  {k}. {desc}')
    print()
    scelta = input('Scegli una query (1-9): ').strip()
    if scelta in MENU:
        print()
        MENU[scelta][1]()
    else:
        print('Scelta non valida.')
