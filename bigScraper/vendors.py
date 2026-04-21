# (org_handle, display_name)
VENDOR_ORGS: list[tuple[str, str]] = [
    # Linux kernel & distros
    ('torvalds',      'Linux Kernel'),
    ('canonical',     'Ubuntu'),
    ('debian',        'Debian'),
    ('archlinux',     'Arch Linux'),
    ('gentoo',        'Gentoo'),
    ('opensuse',      'openSUSE'),
    ('fedora-infra',  'Fedora'),
    ('rhinstaller',   'Red Hat'),

    # Big tech
    ('microsoft',     'Microsoft'),
    ('google',        'Google'),
    ('apple',         'Apple'),
    ('NVIDIA',        'NVIDIA'),
    ('mozilla',       'Mozilla'),
    ('meta-llvm',     'Meta'),
    ('facebook',      'Meta'),
    ('aws',           'Amazon'),
    ('netflix',       'Netflix'),
    ('twitter',       'Twitter/X'),
    ('linkedin',      'LinkedIn'),
    ('airbnb',        'Airbnb'),
    ('uber',          'Uber'),

    # Cloud & infra
    ('hashicorp',     'HashiCorp'),
    ('kubernetes',    'Kubernetes'),
    ('docker',        'Docker'),
    ('helm',          'Helm'),
    ('istio',         'Istio'),
    ('grafana',       'Grafana'),
    ('prometheus',    'Prometheus'),
    ('elastic',       'Elastic'),
    ('ansible',       'Ansible'),

    # Databases
    ('postgres',      'PostgreSQL'),
    ('redis',         'Redis'),
    ('mongodb',       'MongoDB'),
    ('cockroachdb',   'CockroachDB'),
    ('pingcap',       'TiDB/PingCAP'),
    ('clickhouse',    'ClickHouse'),

    # Languages & runtimes
    ('golang',        'Go'),
    ('rust-lang',     'Rust'),
    ('python',        'Python'),
    ('nodejs',        'Node.js'),
    ('php',           'PHP'),
    ('JetBrains',     'JetBrains'),
    ('llvm',          'LLVM'),

    # Security & networking
    ('openssl',           'OpenSSL'),
    ('openssh',           'OpenSSH'),
    ('curl',              'curl'),
    ('nginx',             'nginx'),
    ('apache',            'Apache'),
    ('wireshark',         'Wireshark'),

    # Cybersecurity
    ('CrowdStrike',       'CrowdStrike'),
    ('PaloAltoNetworks',  'Palo Alto Networks'),

    # Infrastructure & software
    ('broadcom',          'Broadcom'),
    ('cisco-open-source', 'Cisco'),
    ('linuxfoundation',   'Linux Foundation'),

    # Finance
    ('jpmorganchase',     'JPMorganChase'),
]
