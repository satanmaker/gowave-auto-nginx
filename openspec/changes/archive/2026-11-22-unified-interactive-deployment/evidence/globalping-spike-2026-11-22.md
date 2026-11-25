# Globalping feasibility spike — 2026-11-22

Task: `2.3` of `unified-interactive-deployment`.
Design reference: `D4 — Globalping is an optional provider behind a narrow diagnostic contract`,
and the open question "Exact Globalping probe availability for RU, CN, and IR".

All measurements below used public fixtures only (`example.com`, `github.com`).
No deployment target, credential, or operator host was submitted.

## Method

- Base URL `https://api.globalping.io/v1`, no API token.
- `GET /limits` for the unauthenticated allowance.
- `GET /probes` once, then counted `location.country` on the client (the `?country=`
  query parameter did not filter: it returned the same 5603 probes for every value).
- `POST /measurements` for DNS and HTTP, then `GET /measurements/{id}` with a bounded
  1 s poll loop.
- Official documents read: the API docs link returned by a validation error, and the
  upstream `jsdelivr/globalping` README (measurement types, limits, public-results notice).

## Observed: allowed measurement types

A `POST` with `"type": "tcp"` was refused:

```
HTTP 400
{"error":{"type":"validation_error","message":"Parameter validation failed.",
 "params":{"type":"\"type\" must be one of [ping, traceroute, dns, mtr, http]"}}}
```

The README states the same set: **ping, traceroute, mtr, dns (dig-like), http (curl GET/HEAD)**.
There is **no raw TCP-connect measurement type**. The `http` type accepts a custom
`port` and reports `timings.tcp`, but its verdict is an HTTP verdict.

## Observed: probe availability in the target countries

`GET /probes` → 5603 probes, 123 countries. Client-side counts:

| Country | Probes |
|---------|--------|
| RU | 175 |
| CN | 50 |
| IR | 11 |
| DE | 561 |
| US | 1118 |

All three target countries have probes.

## Observed: DNS measurements succeed from RU, CN, IR

| Country | Measurement ID | Status | Probe | Result |
|---------|----------------|--------|-------|--------|
| RU | `24VpvpKEzREkZ59FL00021YAk` | finished | RU / Moscow / Timeweb (AS9123) | `NOERROR`, A records returned, `timings.total=1` |
| CN | `2GTFKl2xK6rVK5ZiA00021YAk` | finished | CN / Chengdu | `NOERROR`, answers returned, `timings.total=1` |
| IR | `2Q11BtQdTja3sNKR100021YAk` | finished | IR / Tehran | `NOERROR`, answers returned, `timings.total=16` |

Each finished within about one second of creation. Structured fields are usable:
`results[].result.statusCodeName`, `answers[]`, `timings`, `probe.country/city/network`.

## Observed: HTTP measurement supports a served port

`POST` with `{"type":"http","target":"example.com","locations":[{"country":"RU"}],
"limit":1,"measurementOptions":{"protocol":"HTTPS","port":443,"request":{"method":"HEAD","path":"/"}}}`

- ID `2FXt3NEwQqtD3qaFD00021YAk`, status `finished`, probe RU / Moscow,
  `statusCodeName=OK`, `timings={total:87,dns:1,tcp:10,tls:46,firstByte:30,download:0}`.

## Observed: HTTP is not a TCP probe (the blocking criterion)

Two HTTP probes were sent to `github.com` from DE on a port with an open TCP
listener (22, SSH) and on a closed port (9):

| Target port | Measurement ID | `result.status` | `failureSource` | `timings.tcp` | `rawOutput` |
|-------------|----------------|-----------------|-----------------|---------------|-------------|
| 22 (open, not HTTP) | `2qmrs6hhoPPrs8Xoi00021YAk` | failed | target | `7` | `other side closed` |
| 9 (closed) | `20CbR8uOiSuJuJWkV00021YAk` | failed | target | `null` | `Request timed out while establishing the TCP connection` |

A non-null `timings.tcp` distinguishes a completed TCP connect from a refused one,
but that is an undocumented side channel inside an HTTP probe: both cases report
`status=failed`, `failureSource=target`, and the HTTP verdict is unusable against
an SSH listener. Treating the timing field as a TCP verdict would also turn every
probe against the SSH port into an HTTP `fail`, which the product must not report
as a blocked port.

## Observed: limits and terms

`GET /limits` (unauthenticated, 2026-11-22):

```
{"rateLimit":{"measurements":{"create":{"type":"ip","limit":250,"remaining":250,"reset":0}}}}
```

Upstream README, unauthenticated users:

- 250 tests per hour per IP address; a test is one successful measurement from one probe.
- at most 50 probes per measurement; 2 `GET` requests per second per measurement.
- measurements are public, retrievable by anyone holding the ID, may be published or
  made discoverable, and are typically retained for about six months;
- do not put credentials or confidential information in a target, option, or header;
- public endpoints only, no local-network tests.

## Criteria and outcome

| Criterion | Result | Evidence |
|-----------|--------|----------|
| Supported query form for country-scoped DNS | pass | DNS finished from RU/CN/IR |
| Supported query form for a raw TCP connect on the served SSH port | **fail** | no `tcp` type; HTTP is an HTTP verdict |
| Probe availability in RU, CN, IR | pass | 175 / 50 / 11 probes |
| Bounded result polling | pass | `in-progress` → `finished`/`failed`, finished ≈ 1 s, bounded loop |
| Provider limits compatible with a low-volume preflight | pass with disclosure | 250 tests/hour, 50 probes/measurement |
| Terms compatible with a consented, public-target diagnostic | pass with the disclosure notice | results are public and retained |

**Outcome: the spike does not pass.** The product requirement is a TCP check on the
port that is served at the time of the check — the SSH port before installation —
and Globalping exposes no documented TCP measurement. The HTTP timing field is not
an acceptable substitute.

## Consequence

- The optional provider is **not enabled**. No Globalping URL, client, credential, or
  request exists in `gowave-auto.sh`, `gowave-node-auto.sh`, `modules/*.sh`, or
  `assets/**/*.sh` (grep for `globalping|api.globalping` returns no matches).
- A build with the provider disabled makes no third-party request and installation
  stays independent of the service.
- `2.4` and `2.5` are not applicable as written: both begin "If the Globalping spike
  passes", and it does not. Their non-verdict classes remain the contract for any
  future provider that can perform the required TCP probe.
- The local, unauthenticated SSH readiness check (`ssh_bootstrap_scan` /
  `ssh-keyscan` plus banner filter) remains the pre-mutation reachability mechanism,
  as specified.
