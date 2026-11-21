import csv
import io
import random
from datetime import datetime, timedelta

SCENARIOS = {
    'mixed': {
        'name': 'Mixed Enterprise SOC Attack',
        'description': 'Realistic blend of normal traffic, brute force, account takeover, and perimeter probes.',
        'default_count': 95,
    },
    'brute_force': {
        'name': 'Credential Stuffing & Brute Force',
        'description': 'High-volume failed login waves from rotating external IPs targeting privileged accounts.',
        'default_count': 75,
    },
    'takeover': {
        'name': 'Account Takeover & Lateral Movement',
        'description': 'Repeated failed logins followed by sudden compromise and sensitive file/API access.',
        'default_count': 65,
    },
    'ddos_probe': {
        'name': 'Perimeter Probe & DDoS Burst',
        'description': 'Rapid port scans, unauthorized access attempts, and API flood bursts.',
        'default_count': 85,
    },
}

NORMAL_USERS = ['jdoe', 'asmith', 'bwayne', 'ckent', 'dprince', 'tstark', 'bbanner', 'pparker', 'nromanoff', 'srogers']
PRIVILEGED_TARGETS = ['admin', 'root', 'sysadmin', 'db_admin', 'sec_ops', 'deploy_bot']
INTERNAL_IPS = ['192.168.1.10', '192.168.1.22', '192.168.1.50', '192.168.1.80', '10.0.0.15', '10.0.0.34', '10.0.0.45']
ATTACKER_IPS = ['185.220.101.44', '45.155.205.91', '91.132.147.203', '194.26.135.88', '203.0.113.55', '172.16.0.88']


def _fmt_ts(dt: datetime) -> str:
    return dt.strftime('%Y-%m-%d %H:%M:%S')


def generate_simulation_csv(scenario: str = 'mixed', event_count: int | None = None) -> tuple[bytes, str, dict]:
    """Generate a realistic real-time SOC log CSV dataset for the given scenario."""
    if scenario not in SCENARIOS:
        scenario = 'mixed'

    spec = SCENARIOS[scenario]
    target_count = event_count or spec['default_count']
    now = datetime.now()
    start_time = now - timedelta(minutes=45)

    rows: list[tuple[datetime, str, str, str, str]] = []

    def add_normal_noise(n: int):
        for _ in range(n):
            ts = start_time + timedelta(seconds=random.randint(0, 2600))
            ip = random.choice(INTERNAL_IPS)
            user = random.choice(NORMAL_USERS)
            ev = random.choice(['login_attempt', 'session_start', 'file_access', 'api_request', 'logout'])
            rows.append((ts, ip, ev, user, 'success'))

    def add_brute_force_burst(attacker_ip: str, target_user: str, base_ts: datetime, attempts: int = 7):
        for i in range(attempts):
            ts = base_ts + timedelta(seconds=i * random.randint(4, 15))
            rows.append((ts, attacker_ip, 'login_attempt', target_user, 'failed'))

    def add_account_takeover(attacker_ip: str, victim: str, base_ts: datetime):
        for i in range(5):
            ts = base_ts + timedelta(seconds=i * random.randint(8, 18))
            rows.append((ts, attacker_ip, 'login_attempt', victim, 'failed'))
        # Sudden success + post-compromise activity
        comp_ts = base_ts + timedelta(seconds=110)
        rows.append((comp_ts, attacker_ip, 'login_attempt', victim, 'success'))
        rows.append((comp_ts + timedelta(seconds=18), attacker_ip, 'file_access', victim, 'success'))
        rows.append((comp_ts + timedelta(seconds=35), attacker_ip, 'api_request', victim, 'success'))

    def add_perimeter_probe(attacker_ip: str, base_ts: datetime, bursts: int = 8):
        for i in range(bursts):
            ts = base_ts + timedelta(seconds=i * random.randint(3, 10))
            ev, status = random.choice([
                ('port_scan', 'detected'),
                ('unauthorized_access', 'forbidden'),
                ('access_denied', 'blocked'),
            ])
            rows.append((ts, attacker_ip, ev, 'unknown', status))

    if scenario == 'mixed':
        add_brute_force_burst(ATTACKER_IPS[0], 'admin', start_time + timedelta(minutes=5), attempts=8)
        add_brute_force_burst(ATTACKER_IPS[1], 'root', start_time + timedelta(minutes=14), attempts=6)
        add_account_takeover(ATTACKER_IPS[2], 'ckent', start_time + timedelta(minutes=22))
        add_perimeter_probe(ATTACKER_IPS[4], start_time + timedelta(minutes=30), bursts=10)
    elif scenario == 'brute_force':
        for idx, ip in enumerate(ATTACKER_IPS[:4]):
            add_brute_force_burst(
                ip,
                random.choice(PRIVILEGED_TARGETS),
                start_time + timedelta(minutes=4 + idx * 9),
                attempts=random.randint(7, 11),
            )
    elif scenario == 'takeover':
        add_account_takeover(ATTACKER_IPS[0], 'tstark', start_time + timedelta(minutes=6))
        add_account_takeover(ATTACKER_IPS[2], 'bwayne', start_time + timedelta(minutes=20))
        add_account_takeover(ATTACKER_IPS[3], 'dprince', start_time + timedelta(minutes=33))
    elif scenario == 'ddos_probe':
        for idx, ip in enumerate(ATTACKER_IPS[:4]):
            add_perimeter_probe(ip, start_time + timedelta(minutes=3 + idx * 10), bursts=12)

    remaining = max(10, target_count - len(rows))
    add_normal_noise(remaining)

    rows.sort(key=lambda r: r[0])

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(['timestamp', 'source_ip', 'event_type', 'username', 'status'])
    for ts, ip, ev, user, status in rows:
        writer.writerow([_fmt_ts(ts), ip, ev, user, status])

    csv_bytes = buf.getvalue().encode('utf-8')
    filename = f"sim_{scenario}_{now.strftime('%Y%m%d_%H%M%S')}.csv"
    meta = {
        'scenario': scenario,
        'scenario_name': spec['name'],
        'description': spec['description'],
        'generated_at': now.isoformat(),
        'row_count': len(rows),
    }
    return csv_bytes, filename, meta
