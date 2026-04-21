# Obtaining and processing CVE data from NVD API 2.0
# Downloads CVEs from NIST NVD API 2.0 for the selected year range,
# caches results locally as JSON, and extracts all entries into the database.

import datetime
import json
import time
import pandas as pd
import requests
from pathlib import Path

from extract_cwe_record import add_cwe_class, extract_cwe
import configuration as cf
import database as db

# ---------------------------------------------------------------------------------------------------------------------

API_BASE_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
RESULTS_PER_PAGE = 2000
REQUEST_DELAY = 6  # seconds between paginated requests (NVD rate limit: 5 req/30s without API key)

initYear = 2025
endYear = 2026
currentYear = datetime.datetime.now().year

# Consider only current year CVE records when sample_limit>0 for the simplified example.
if cf.SAMPLE_LIMIT > 0:
    initYear = currentYear
    endYear = currentYear

df = pd.DataFrame()

ordered_cve_columns = ['cve_id', 'published_date', 'last_modified_date', 'description', 'nodes', 'severity',
                       'obtain_all_privilege', 'obtain_user_privilege', 'obtain_other_privilege',
                       'user_interaction_required',
                       'cvss2_vector_string', 'cvss2_access_vector', 'cvss2_access_complexity', 'cvss2_authentication',
                       'cvss2_confidentiality_impact', 'cvss2_integrity_impact', 'cvss2_availability_impact',
                       'cvss2_base_score',
                       'cvss3_vector_string', 'cvss3_attack_vector', 'cvss3_attack_complexity',
                       'cvss3_privileges_required',
                       'cvss3_user_interaction', 'cvss3_scope', 'cvss3_confidentiality_impact',
                       'cvss3_integrity_impact',
                       'cvss3_availability_impact', 'cvss3_base_score', 'cvss3_base_severity',
                       'exploitability_score', 'impact_score', 'ac_insuf_info',
                       'reference_json', 'problemtype_json']

cwe_columns = ['cwe_id', 'cwe_name', 'description', 'extended_description', 'url', 'is_category']

# ---------------------------------------------------------------------------------------------------------------------


def _fetch_chunk(start_date, end_date):
    """
    Fetch all CVEs for a date range (max 120 days) from NVD API 2.0 with pagination.
    :param start_date: ISO 8601 string e.g. '2020-01-01T00:00:00.000'
    :param end_date:   ISO 8601 string e.g. '2020-03-31T23:59:59.999'
    :return: list of vulnerability dicts
    """
    all_vulnerabilities = []
    start_index = 0
    total_results = None

    while total_results is None or start_index < total_results:
        params = {
            'pubStartDate': start_date,
            'pubEndDate': end_date,
            'startIndex': start_index,
            'resultsPerPage': RESULTS_PER_PAGE,
        }
        response = requests.get(API_BASE_URL, params=params, timeout=60)
        response.raise_for_status()
        data = response.json()

        total_results = data.get('totalResults', 0)
        vulnerabilities = data.get('vulnerabilities', [])
        all_vulnerabilities.extend(vulnerabilities)
        start_index += len(vulnerabilities)

        cf.logger.info(f'  [{start_date[:10]} → {end_date[:10]}] fetched {start_index}/{total_results}')

        if start_index < total_results:
            time.sleep(REQUEST_DELAY)

    return all_vulnerabilities


def fetch_year_cves(year):
    """
    Fetch all CVEs published in a given year from NVD API 2.0.
    The year is split into quarterly chunks (NVD API 2.0 allows max 120-day windows).
    Results are cached locally as a single JSON file to avoid re-downloading on re-runs.
    :param year: the year to fetch
    :return: list of vulnerability dicts from the API
    """
    json_dir = Path(cf.DATA_PATH) / 'json'
    json_dir.mkdir(parents=True, exist_ok=True)
    cache_file = json_dir / f'nvdcve-2.0-{year}.json'

    if cache_file.exists():
        cf.logger.warning(f'Reusing the {year} CVE json file that was downloaded earlier...')
        with open(cache_file) as f:
            return json.load(f)

    # Split year into quarters to stay within the 120-day API limit
    quarters = [
        (f'{year}-01-01T00:00:00.000', f'{year}-03-31T23:59:59.999'),
        (f'{year}-04-01T00:00:00.000', f'{year}-06-30T23:59:59.999'),
        (f'{year}-07-01T00:00:00.000', f'{year}-09-30T23:59:59.999'),
        (f'{year}-10-01T00:00:00.000', f'{year}-12-31T23:59:59.999'),
    ]

    all_vulnerabilities = []
    for start_date, end_date in quarters:
        chunk = _fetch_chunk(start_date, end_date)
        all_vulnerabilities.extend(chunk)
        if (start_date, end_date) != quarters[-1]:
            time.sleep(REQUEST_DELAY)

    with open(cache_file, 'w') as f:
        json.dump(all_vulnerabilities, f)

    return all_vulnerabilities


def parse_cve_item(vuln):
    """
    Convert a single NVD API 2.0 vulnerability dict into a row
    compatible with ordered_cve_columns.
    :param vuln: dict with a 'cve' key from the API response
    :return: dict with column names as keys
    """
    cve = vuln['cve']

    # English description
    descriptions = cve.get('descriptions', [])
    description = next((d['value'] for d in descriptions if d['lang'] == 'en'), '')

    # CVSS v2
    metrics = cve.get('metrics', {})
    cvss2_list = metrics.get('cvssMetricV2', [])
    cvss2 = cvss2_list[0] if cvss2_list else {}
    cvss2_data = cvss2.get('cvssData', {})

    exploitability_score = cvss2.get('exploitabilityScore', '')
    impact_score = cvss2.get('impactScore', '')

    # CVSS v3.1 with fallback to v3.0
    cvss3_list = metrics.get('cvssMetricV31', []) or metrics.get('cvssMetricV30', [])
    cvss3 = cvss3_list[0] if cvss3_list else {}
    cvss3_data = cvss3.get('cvssData', {})

    # Fall back to v3 scores if v2 absent
    if not exploitability_score:
        exploitability_score = cvss3.get('exploitabilityScore', '')
    if not impact_score:
        impact_score = cvss3.get('impactScore', '')

    # References — keep {url, name, refsource, tags} structure expected by extract_project_links
    references = cve.get('references', [])
    ref_list = [
        {'url': r.get('url', ''), 'name': r.get('url', ''),
         'refsource': r.get('source', ''), 'tags': r.get('tags', [])}
        for r in references
    ]

    # Weaknesses — merge all descriptions into one dict (format expected by add_cwe_class)
    # NVD API 2.0 may have multiple weakness entries (Primary/Secondary); add_cwe_class
    # expects exactly one item per CVE, so we flatten all descriptions into a single list.
    weaknesses = cve.get('weaknesses', [])
    all_descriptions = []
    for w in weaknesses:
        all_descriptions.extend(w.get('description', []))
    problemtype_data = [{'description': all_descriptions}]

    return {
        'cve_id': cve.get('id', ''),
        'published_date': cve.get('published', ''),
        'last_modified_date': cve.get('lastModified', ''),
        'description': description,
        'nodes': str(cve.get('configurations', [])),
        'severity': cvss2.get('baseSeverity', ''),
        'obtain_all_privilege': str(cvss2.get('obtainAllPrivilege', '')),
        'obtain_user_privilege': str(cvss2.get('obtainUserPrivilege', '')),
        'obtain_other_privilege': str(cvss2.get('obtainOtherPrivilege', '')),
        'user_interaction_required': str(cvss2.get('userInteractionRequired', '')),
        'cvss2_vector_string': cvss2_data.get('vectorString', ''),
        'cvss2_access_vector': cvss2_data.get('accessVector', ''),
        'cvss2_access_complexity': cvss2_data.get('accessComplexity', ''),
        'cvss2_authentication': cvss2_data.get('authentication', ''),
        'cvss2_confidentiality_impact': cvss2_data.get('confidentialityImpact', ''),
        'cvss2_integrity_impact': cvss2_data.get('integrityImpact', ''),
        'cvss2_availability_impact': cvss2_data.get('availabilityImpact', ''),
        'cvss2_base_score': str(cvss2_data.get('baseScore', '')),
        'cvss3_vector_string': cvss3_data.get('vectorString', ''),
        'cvss3_attack_vector': cvss3_data.get('attackVector', ''),
        'cvss3_attack_complexity': cvss3_data.get('attackComplexity', ''),
        'cvss3_privileges_required': cvss3_data.get('privilegesRequired', ''),
        'cvss3_user_interaction': cvss3_data.get('userInteraction', ''),
        'cvss3_scope': cvss3_data.get('scope', ''),
        'cvss3_confidentiality_impact': cvss3_data.get('confidentialityImpact', ''),
        'cvss3_integrity_impact': cvss3_data.get('integrityImpact', ''),
        'cvss3_availability_impact': cvss3_data.get('availabilityImpact', ''),
        'cvss3_base_score': str(cvss3_data.get('baseScore', '')),
        'cvss3_base_severity': cvss3_data.get('baseSeverity', ''),
        'exploitability_score': str(exploitability_score),
        'impact_score': str(impact_score),
        'ac_insuf_info': str(cvss2.get('acInsufInfo', '')),
        'reference_json': str(ref_list),
        'problemtype_json': str(problemtype_data),
    }


def assign_cwes_to_cves(df_cve: pd.DataFrame):
    df_cwes = extract_cwe()
    cf.logger.info('Adding CWE category to CVE records...')
    df_cwes_class = df_cve[['cve_id', 'problemtype_json']].copy()
    df_cwes_class['cwe_id'] = add_cwe_class(df_cwes_class['problemtype_json'].tolist())

    df_cwes_class = df_cwes_class.assign(
        cwe_id=df_cwes_class.cwe_id).explode('cwe_id').reset_index()[['cve_id', 'cwe_id']]
    df_cwes_class = df_cwes_class.drop_duplicates(subset=['cve_id', 'cwe_id']).reset_index(drop=True)
    df_cwes_class['cwe_id'] = df_cwes_class['cwe_id'].str.replace('unknown', 'NVD-CWE-noinfo')

    valid_cwe_ids = set(df_cwes.cwe_id)
    no_ref_cwes = set(df_cwes_class.cwe_id) - valid_cwe_ids
    if no_ref_cwes:
        cf.logger.warning(f'CWEs not found in CWE table, mapping to NVD-CWE-noinfo: {no_ref_cwes}')
        df_cwes_class['cwe_id'] = df_cwes_class['cwe_id'].apply(
            lambda x: x if x in valid_cwe_ids else 'NVD-CWE-noinfo'
        )
        df_cwes_class = df_cwes_class.drop_duplicates(subset=['cve_id', 'cwe_id']).reset_index(drop=True)

    assert df_cwes.cwe_id.is_unique, "Primary keys are not unique in cwe records!"
    assert df_cwes_class.set_index(['cve_id', 'cwe_id']).index.is_unique, \
        'Primary keys are not unique in cwe_classification records!'

    df_cwes = df_cwes[cwe_columns].reset_index()
    df_cwes.to_sql(name="cwe", con=db.conn, if_exists='replace', index=False)
    df_cwes_class.to_sql(name='cwe_classification', con=db.conn, if_exists='replace', index=False)
    cf.logger.info('Added cwe and cwe_classification tables')


def import_cves():
    """
    Gather CVE records from NVD API 2.0 for the configured year range (2020-2026).
    """
    cf.logger.info('-' * 70)
    cve_exists = db.table_exists('cve')
    cwe_exists = db.table_exists('cwe')

    if cve_exists and cwe_exists:
        cf.logger.warning('The cve and cwe tables already exist, loading and continuing extraction...')
        return

    if not cve_exists:
        rows = []
        for year in range(initYear, endYear + 1):
            year_vulns = fetch_year_cves(year)
            year_rows = [parse_cve_item(v) for v in year_vulns]
            # Filter out CVEs with no references (same behaviour as original code)
            year_rows = [r for r in year_rows if r['reference_json'] != str([])]
            rows.extend(year_rows)
            cf.logger.info(f'The CVE data for {year} has been merged ({len(year_rows)} CVEs with references)')

        df_cve = pd.DataFrame(rows, columns=ordered_cve_columns)
        df_cve = df_cve.drop_duplicates(subset=['cve_id']).reset_index(drop=True)
        df_cve = df_cve.apply(lambda col: col.map(str))

        assert df_cve.cve_id.is_unique, 'Primary keys are not unique in cve records!'
        df_cve.to_sql(name="cve", con=db.conn, if_exists="replace", index=False)
        cf.logger.info(f'Total CVEs collected ({initYear}-{endYear}): {len(df_cve)}')
        cf.logger.info('All CVEs have been merged into the cve table')
        cf.logger.info('-' * 70)
    else:
        cf.logger.warning('The cve table exists but cwe table is missing — loading cve from DB for CWE assignment...')
        df_cve = pd.read_sql('SELECT cve_id, problemtype_json FROM cve', con=db.conn)

    assign_cwes_to_cves(df_cve=df_cve)
