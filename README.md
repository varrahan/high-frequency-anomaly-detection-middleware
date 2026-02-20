# High-Frequency Anomaly Detection Platform

A hybrid distributed system for real-time network telemetry ingestion and anomaly detection. Sensors POST raw packet data to a Rails middleware layer, which writes to a Redis Stream. A multi-threaded C++ worker pulls from the stream, scores each packet for anomalies, and POSTs results back to Rails, which broadcasts them live to a WebSocket-connected dashboard.

---

## Architecture

```
Sensor / curl
     │
     │  POST /ingest  (Bearer token)
     ▼
┌─────────────────────────────────────┐
│  Rack Middleware (AnomalyIngester)  │  ← Position 0 in stack, bypasses Rails router
│  Authenticates → XADD Redis Stream │  ← Returns 200 OK in microseconds
└─────────────────────────────────────┘
     │
     │  Redis Stream  (anomaly:raw)
     ▼
┌─────────────────────────────────────┐
│  C++ Analyzer Worker                │  ← XREADGROUP + thread pool
│  Feature extraction + scoring       │  ← Shannon entropy, port heuristics, TTL, SYN flood
│  HTTP POST results → Rails API      │
└─────────────────────────────────────┘
     │
     │  POST /api/v1/anomalies  (X-Worker-Token)
     ▼
┌─────────────────────────────────────┐
│  Rails API Controller               │  ← Validates + persists to PostgreSQL
│  Anomaly Model                      │  ← after_create_commit → Turbo broadcast
└─────────────────────────────────────┘
     │
     │  Action Cable WebSocket
     ▼
┌─────────────────────────────────────┐
│  Browser Dashboard                  │  ← turbo_stream_from "anomalies"
│  Live DOM updates, no page refresh  │
└─────────────────────────────────────┘
```

---

## Project Structure

```
├── app/
│   ├── channels/                          # Action Cable channels
│   ├── controllers/
│   │   ├── api/v1/anomalies_controller.rb # Worker-facing API endpoint
│   │   ├── application_controller.rb
│   │   └── dashboards_controller.rb       # Dashboard UI
│   ├── models/
│   │   ├── anomaly.rb                     # ActiveRecord + Turbo broadcast callback
│   │   └── application_record.rb
│   └── views/
│       ├── anomalies/_anomaly.html.erb    # Turbo Stream partial
│       ├── dashboards/show.html.erb       # Live dashboard
│       └── layouts/application.html.erb
├── config/
│   ├── application.rb                     # Middleware insertion
│   ├── environments/
│   │   ├── development.rb
│   │   └── production.rb
│   ├── initializers/
│   │   └── redis.rb                       # Connection pool
│   ├── cable.yml
│   ├── database.yml
│   └── routes.rb
├── db/
│   └── migrate/
│       └── 20260219120000_create_anomalies.rb
├── external_workers/
│   └── analyzer/
│       ├── main.cpp                       # Worker daemon, Redis consumer loop
│       ├── packet_parser.cpp / .h         # Feature extraction + anomaly scoring
│       ├── thread_pool.h                  # Header-only C++17 thread pool
│       └── CMakeLists.txt
├── lib/
│   └── middleware/
│       └── ingester.rb                    # High-speed Rack ingestion middleware
└── docker-compose.yml                     # PostgreSQL + Redis only
```

---

## Prerequisites

| Dependency | Version | Purpose |
|---|---|---|
| Ruby | 3.4+ | Rails runtime |
| Rails | 7.2 | Web framework |
| PostgreSQL | 16 | Anomaly persistence |
| Redis | 7 | Stream + Action Cable pub/sub |
| g++ / clang++ | C++17 | Worker compilation |
| CMake | 3.16+ | Worker build system |
| libhiredis-dev | any | Redis client for C++ |
| libcurl4-openssl-dev | any | HTTP POST from worker |
| nlohmann-json3-dev | any | JSON parsing in worker |
| Docker + Compose | any | Running Postgres + Redis |

---

## Setup

### 1. Start PostgreSQL and Redis via Docker

```bash
docker compose up -d
```

Verify both are reachable:
```bash
redis-cli -h 127.0.0.1 -p 6379 ping   # → PONG
psql -h localhost -U postgres -d postgres -c "SELECT 1"
```

Your `docker-compose.yml` must expose both ports to the host:
```yaml
postgres:
  ports:
    - "5432:5432"
redis:
  ports:
    - "6379:6379"
```

---

### 2. Configure environment variables

Create a `.env` file in the project root:

```dotenv
# Datastores
DATABASE_URL=postgres://postgres:postgres@localhost:5432/anomaly_development
REDIS_URL=redis://localhost:6379/0

# Rails
RAILS_ENV=development
SECRET_KEY_BASE=           # bundle exec rails secret

# Shared secrets
ANOMALY_WORKER_TOKEN=      # openssl rand -hex 32
INGESTION_TOKEN=           # openssl rand -hex 32

# Ingestion middleware
INGESTION_PATH=/ingest
REDIS_STREAM_NAME=anomaly:raw
STREAM_MAX_LEN=50000

# C++ worker
RAILS_API_URL=http://localhost:3000/api/v1/anomalies
CONSUMER_GROUP=analyzers
CONSUMER_NAME=worker-0
THREAD_COUNT=0
BATCH_SIZE=64
BLOCK_MS=200
```

Generate the secrets:
```bash
bundle exec rails secret        # → paste into SECRET_KEY_BASE
openssl rand -hex 32            # → paste into ANOMALY_WORKER_TOKEN
openssl rand -hex 32            # → paste into INGESTION_TOKEN
```

---

### 3. Install Ruby dependencies

```bash
bundle install
```

---

### 4. Set up the database

```bash
bundle exec rails db:create
bundle exec rails db:migrate
bundle exec rails db:migrate:status   # confirm "up"
```

---

### 5. Build the C++ worker

```bash
cd external_workers/analyzer
cmake -B build -DCMAKE_BUILD_TYPE=Release .
cmake --build build --parallel
```

---

## Running

You need three terminals.

**Terminal 1 — Rails:**
```bash
bundle exec rails server -p 3000
```

**Terminal 2 — C++ worker:**
```bash
cd external_workers/analyzer
set -a && source ../../.env && set +a
./build/analyzer
```

Expected output:
```
[main] Starting C++ analyzer
       threads=8
       stream=anomaly:raw
       group=analyzers
[main] Entering main loop…
```

**Terminal 3 — Send a test packet:**
```bash
curl -X POST http://localhost:3000/ingest \
  -H "Authorization: Bearer dev-ingest-token" \
  -H "Content-Type: application/json" \
  -d '{
    "src_ip":      "10.0.0.1",
    "dst_ip":      "10.0.0.2",
    "protocol":    "TCP",
    "src_port":    12345,
    "dst_port":    4444,
    "payload_len": 0,
    "ttl":         64,
    "tcp_flags":   2,
    "payload_hex": "deadbeef",
    "pkt_rate":    15000
  }'
```

Open `http://localhost:3000` — the anomaly should appear on the dashboard in real time without a page refresh.

---

## Anomaly Scoring

The C++ worker applies an additive heuristic scoring model. Scores are normalised to `[0.0, 1.0]`.

| Signal | Score |
|---|---|
| Suspicious destination port (4444, 6667, 1337, etc.) | +0.30 |
| SYN-only TCP packet (possible SYN flood) | +0.25 |
| High payload entropy > 7.5 (encrypted/obfuscated) | +0.20 |
| Packet rate > 10,000 pkt/s from single source | +0.20 |
| Abnormal TTL (< 10 or = 255) | +0.15 |
| Oversized payload > 65,000 bytes | +0.10 |

| Score range | Severity | Dashboard colour |
|---|---|---|
| 0.00 – 0.25 | low | gray |
| 0.25 – 0.50 | medium | yellow |
| 0.50 – 0.75 | high | orange |
| 0.75 – 1.00 | critical | red |

---

## API Reference

### `POST /ingest`
Ingested by Rack middleware before hitting Rails. Writes directly to Redis Stream.

| Header | Value |
|---|---|
| `Authorization` | `Bearer <INGESTION_TOKEN>` |
| `Content-Type` | `application/json` |

**Payload fields:**

| Field | Type | Description |
|---|---|---|
| `src_ip` | string | Source IP address |
| `dst_ip` | string | Destination IP address |
| `protocol` | string | TCP / UDP / ICMP etc. |
| `src_port` | integer | Source port |
| `dst_port` | integer | Destination port |
| `payload_len` | integer | Payload size in bytes |
| `ttl` | integer | IP time-to-live |
| `tcp_flags` | integer | TCP flag bitmask |
| `payload_hex` | string | Hex-encoded payload bytes |
| `pkt_rate` | float | Packets/second from source |

**Responses:** `200 OK`, `400 Bad Request`, `401 Unauthorized`, `503 Service Unavailable`

---

### `POST /api/v1/anomalies`
Internal endpoint called by the C++ worker only.

| Header | Value |
|---|---|
| `X-Worker-Token` | `<ANOMALY_WORKER_TOKEN>` |
| `Content-Type` | `application/json` |

**Responses:** `201 Created`, `401 Unauthorized`, `422 Unprocessable Entity`

---

## Scaling the Worker

Run multiple worker instances by giving each a unique `CONSUMER_NAME`. Redis consumer groups distribute messages automatically across all active workers:

```bash
# Worker 0
CONSUMER_NAME=worker-0 ./build/analyzer

# Worker 1 (separate terminal)
CONSUMER_NAME=worker-1 ./build/analyzer
```

`THREAD_COUNT=0` auto-detects CPU cores per worker. For a machine with 8 cores running 2 worker processes you get 16 total processing threads.