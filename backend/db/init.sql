-- CloudGuard AI — PostgreSQL Schema
-- Auto-executed on first DB startup via Docker Compose

-- Threat Events table
CREATE TABLE IF NOT EXISTS threat_events (
    id          UUID        PRIMARY KEY,
    type        VARCHAR(20) NOT NULL CHECK (type IN ('safe','suspicious','threat')),
    protocol    VARCHAR(10),
    ip_address  VARCHAR(45),
    message     TEXT        NOT NULL,
    score       NUMERIC(5,3),
    model       VARCHAR(50),
    ts          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_threat_events_type ON threat_events(type);
CREATE INDEX IF NOT EXISTS idx_threat_events_ts   ON threat_events(ts DESC);

-- Alerts / Incidents table
CREATE TABLE IF NOT EXISTS alerts (
    id          UUID        PRIMARY KEY,
    severity    VARCHAR(10) NOT NULL CHECK (severity IN ('critical','high','medium','low','info')),
    title       TEXT        NOT NULL,
    source      TEXT,
    status      VARCHAR(10) NOT NULL DEFAULT 'open' CHECK (status IN ('open','resolved')),
    ts          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    resolved_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_alerts_status   ON alerts(status);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);

-- Reports table
CREATE TABLE IF NOT EXISTS reports (
    id           UUID        PRIMARY KEY,
    title        TEXT        NOT NULL,
    threat_count INTEGER     DEFAULT 0,
    event_count  INTEGER     DEFAULT 0,
    model        VARCHAR(50),
    payload      JSONB,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Audit Log table
CREATE TABLE IF NOT EXISTS audit_logs (
    id       UUID        PRIMARY KEY,
    category VARCHAR(50),
    message  TEXT        NOT NULL,
    ts       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_logs(ts DESC);

-- Seed initial demo alerts so the dashboard is not empty on first run
INSERT INTO alerts (id, severity, title, source, status, ts) VALUES
    (gen_random_uuid(), 'critical', 'Ransomware C2 beacon detected',    '10.24.18.42 -> finance-api',  'open',     NOW() - INTERVAL '2 minutes'),
    (gen_random_uuid(), 'high',     'Unusual outbound data transfer',    '10.24.33.18 -> external IP',  'open',     NOW() - INTERVAL '18 minutes'),
    (gen_random_uuid(), 'medium',   'Suspicious authentication pattern', 'admin@cloudguard.io',          'open',     NOW() - INTERVAL '42 minutes'),
    (gen_random_uuid(), 'high',     'Phishing payload blocked',          'mail-gateway -> inbox',        'resolved', NOW() - INTERVAL '1 hour'),
    (gen_random_uuid(), 'medium',   'Port scan anomaly detected',        '172.16.0.88 -> core-vpc',     'resolved', NOW() - INTERVAL '2 hours')
ON CONFLICT DO NOTHING;

-- Connected Devices table
CREATE TABLE IF NOT EXISTS devices (
    id         VARCHAR(50)  PRIMARY KEY,
    name       VARCHAR(100) NOT NULL,
    type       VARCHAR(50)  NOT NULL,
    role       VARCHAR(100),
    ip         VARCHAR(45)  NOT NULL,
    mac        VARCHAR(30),
    vpc        VARCHAR(100),
    zone       VARCHAR(50),
    proto      VARCHAR(50),
    in_mb      NUMERIC(8,2) DEFAULT 0,
    out_mb     NUMERIC(8,2) DEFAULT 0,
    pps        INTEGER      DEFAULT 0,
    status     VARCHAR(30)  DEFAULT 'online',
    os         VARCHAR(100),
    isolated   BOOLEAN      DEFAULT FALSE,
    updated_at TIMESTAMPTZ  DEFAULT NOW()
);

INSERT INTO devices (id, name, type, role, ip, mac, vpc, zone, proto, in_mb, out_mb, pps, status, os, isolated) VALUES
    ('dev-01', 'k8s-prod-worker-01',     'server',      'Kubernetes Worker Node',   '10.0.12.4',    '02:42:0a:00:0c:04', 'prod-vpc-us-east', 'us-east-1a', 'TCP / 10250', 412.8, 189.4, 2450, 'online',      'Ubuntu 22.04 LTS (K8s v1.29)', FALSE),
    ('dev-02', 'api-gateway-prod',       'gateway',     'Envoy Edge API Gateway',   '10.0.1.10',    '02:42:0a:00:01:0a', 'dmz-vpc-us-east',  'us-east-1a', 'HTTPS / 443',  890.2, 742.1, 4890, 'online',      'Alpine Linux (Envoy Proxy)',   FALSE),
    ('dev-03', 'postgres-primary-db',    'database',    'PostgreSQL DB Primary',    '10.0.8.25',    '02:42:0a:00:08:19', 'data-vpc-us-east', 'us-east-1b', 'TCP / 5432',   674.3, 891.0, 3720, 'high-traffic','Debian 12 (PostgreSQL 16)',    FALSE),
    ('dev-04', 'redis-cache-cluster-01', 'database',    'Redis Cache Cluster',      '10.0.4.88',    '02:42:0a:00:04:58', 'data-vpc-us-east', 'us-east-1b', 'TCP / 6379',   320.1, 210.5, 3100, 'online',      'Alpine Linux (Redis 7.2)',     FALSE),
    ('dev-05', 'auth-service-pod-3b',    'server',      'Auth Microservice Pod',    '10.244.3.15',  '02:42:0a:f4:03:0f', 'prod-vpc-us-east', 'us-east-1a', 'gRPC / 50051',  154.6, 98.2,  1420, 'online',      'Go Container (Distroless)',    FALSE),
    ('dev-06', 'edge-load-balancer-us',  'gateway',     'Global Cloud Load Balancer','192.168.1.1', '52:54:00:12:34:56', 'edge-anycast-net', 'global-edge','HTTP2 / 443',   1240.5,1180.2,6900, 'high-traffic','EdgeOS / Cloudflare Node',     FALSE),
    ('dev-07', 'bastion-jump-host',      'security',    'SSH Bastion Jump Host',    '10.0.99.2',    '02:42:0a:00:63:02', 'mgmt-vpc-us-east', 'us-east-1c', 'SSH / 22',     45.3,  38.1,  410,  'online',      'Hardened Alpine Linux',        FALSE),
    ('dev-08', 'secops-analyst-laptop',  'workstation', 'Security Analyst Endpoint', '192.168.50.12','a4:83:e7:21:bc:44','corp-vpn-pool',   'remote-office','HTTPS / 443',  68.4,  32.7,  580,  'online',      'macOS Sonoma (SecOps)',        FALSE),
    ('dev-09', 'corp-vpn-gateway',       'gateway',     'WireGuard VPN Gateway',    '172.16.0.1',   '02:42:ac:10:00:01', 'vpn-vpc-us-east',  'us-east-1a', 'UDP / 51820',   290.4, 280.9, 2150, 'online',      'Linux Kernel (WireGuard)',     FALSE),
    ('dev-10', 'iot-telemetry-collector','security',    'IoT Fleet Telemetry Node', '10.0.35.80',   '02:42:0a:00:23:50', 'iot-vpc-us-east',   'us-east-1c', 'MQTT / 8883',   185.0, 42.1,  1890, 'suspicious',  'FreeBSD 14 / Mosquitto',       FALSE)
ON CONFLICT (id) DO NOTHING;
