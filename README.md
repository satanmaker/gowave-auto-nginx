# GoWave Auto NGINX

**English** | [Русский — полный перевод](README.ru.md)

A native Linux installer and lifecycle manager for the [GoWave](https://github.com/aaaSaZaN/gowave)
Panel and [GoWave Node](https://github.com/aaaSaZaN/gowave-node), with NGINX, per-user subscriptions and
SSH-based remote node provisioning. Start with the domain plan, deploy on the Panel VPS, then import a
subscription into a compatible client and verify traffic—not just service status.

## Contents

1. [Purpose and scope](#purpose)
2. [Features, profiles and clients](#features)
3. [Architecture and topology](#architecture)
4. [Requirements and preparation](#requirements)
5. [Domains, DNS, ports and certificates](#domains)
6. [Installation](#installation)
7. [First login and first connection](#first-connection)
8. [Remote nodes](#remote-nodes)
9. [Day-to-day operations and recovery](#operations)
10. [CLI and environment reference](#reference)
11. [Files, services and security](#security)
12. [Troubleshooting](#troubleshooting)
13. [Testing and evidence](#testing)
14. [Project and contribution links](#project)

<a id="purpose"></a>
## 1. Purpose and scope

This repository integrates upstream GoWave with a public NGINX entrypoint and host lifecycle tooling.
It is intended for operators who control their VPS, DNS and firewall, can maintain root access, and
need a guided route from a clean server to a working client connection. It does not replace the Panel's
user-management interface or the Node's Xray supervisor.

Production installation is **native systemd**, not Docker Compose: the installer downloads Panel
release assets, installs GoWave Node where needed, renders NGINX configuration, obtains certificates
and provisions profiles, nodes, Internal Squads, Host records and an initial user through the Panel API.
Docker and Podman are **not production prerequisites**; Podman is used by the acceptance testbed.

Upstream binaries are treated as external, unmodified components. The Panel owns users, subscriptions
and node configuration; GoWave Node supervises Xray-core. This project manages the surrounding ports,
services, certificates, provisioning and recovery. It sets `GOWAVE_PROXY=external` in the Panel's
`.env` so GoWave does not manage NGINX itself.

<a id="features"></a>
## 2. Features, profiles and clients

- Interactive English/Russian setup and lifecycle menu, plus complete positional commands for automation.
- Panel-only, All-in-One and multi-server deployment plans; remote Workers provisioned over SSH stdin.
- NGINX Stream SNI routing on public TCP 443, TLS termination for web transports, and a static camouflage
  site/REALITY loopback fallback. The decoy is not an open proxy.
- Per-node profiles and Host records, per-user subscriptions, optional confirmed egress-country labels.
- Certificate renewal integration, UFW, Fail2ban, strict DNS-over-TLS, swap and BBR configuration.
- Mutation locking, snapshots, SQLite Online Backup, recovery journals and Format v1 backup/restore.
  These reduce failure risk; they do not guarantee reversal of every external or host-side change.

A traffic node receives these default profiles; a Panel-only host receives no traffic inbounds:

| Profile | Transport/security | Client-facing endpoint |
| --- | --- | --- |
| VLESS REALITY Vision | TCP + REALITY, `xtls-rprx-vision` | Node entry domain:443, camouflage domain as SNI |
| VLESS XHTTP | XHTTP + TLS | Node entry domain:443, `/xhttp-down/` |
| VLESS WebSocket | WebSocket + TLS | Node entry domain:443, `/ws` |
| Trojan gRPC | gRPC + TLS | Node entry domain:443, service `trojan-grpc` |
| Optional VLESS TLS Vision | TCP + TLS, `xtls-rprx-vision` | Separate Vision domain:443 |

The four subscription families are base64 share links, Xray JSON, Mihomo YAML and compact Clash YAML.
Use the family your application actually imports; a JSON configuration array is not a v2rayNG
subscription. The [acceptance matrix](tests/cases/matrix.yaml) pins **Xray 26.11.9** and
**Mihomo 1.19.34**, with artifact digests. These are the maintained test-engine builds, not a promise
that every application embedding them is compatible. The current REALITY server requires modern
hybrid-key-share support; an old embedded core can fail even when the subscription parses. Prefer an
up-to-date client with the required transports and check its actual core version.

**Non-goals:** automatic client failover, a managed DNS service, universal GUI-client support,
automatic migration from arbitrary existing installations, or guarantees against detection, blocking,
outages or data loss. No performance capacity is promised by a profile count.

<a id="architecture"></a>
## 3. Architecture and topology

Recommended separation:

```text
Operator/browser ---- HTTPS ---- Panel VPS (Panel-only)
                                  NGINX -> GoWave Panel :3000
                                  Panel -- restricted mTLS :3002 --> Worker VPS
Client --------------------------- TCP :443 ---------------------> Worker VPS
                                                                  NGINX -> Node/Xray
                                                                  static decoy
```

On a traffic host, all public client protocols share TCP 443:

```text
Public :443 -> NGINX Stream (SNI)
  entry domain       -> loopback TLS frontend :7443 -> web transports / Panel where present
  camouflage domain  -> Xray REALITY :8443 -> unauthenticated fallback -> static decoy :9443
  Vision domain      -> Xray TLS Vision :8444 (optional)
  unknown SNI        -> static decoy, not the Panel or a general-purpose proxy
```

| Topology | Panel host | Other hosts | Recommendation and failure boundary |
| --- | --- | --- | --- |
| Panel-only + remote nodes | Panel and static camouflage site; no local Xray traffic plane | One or more Workers | Recommended for production isolation: losing the control host does not itself remove a separate traffic endpoint |
| All-in-One | Panel and local Node/Xray | None required | Evaluation/personal use: one failure affects both management and traffic |
| All-in-One + remote nodes | Panel and one traffic endpoint | Additional Workers | Supported, but still couples one traffic endpoint to the control plane |

Panel-only by itself cannot carry VPN traffic: add at least one Worker before expecting a usable
subscription. A Panel outage can still affect subscriptions and management; isolation is not a promise
that every existing session survives. **No topology automatically moves clients to another node.**
That depends on client selection/failover settings and reachable configured nodes.

<a id="requirements"></a>
## 4. Requirements and preparation

Before starting, check **each** planned server:

| Requirement | Operator preparation |
| --- | --- |
| Supported OS | Ubuntu **24.04 / 26.04 LTS**, Debian **12 / 13**, with systemd and APT |
| CPU architecture | `x86_64` → `amd64`; `aarch64`/`arm64` → `arm64`. Other architectures are refused |
| Privilege | Root on the Panel VPS and root-capable access to each Worker; keep provider console/recovery access |
| Clean host | Prefer a fresh dedicated VPS, without another Panel, proxy, web server or conflicting listener/configuration |
| Resources | Budget RAM/CPU for the Panel plus actual node traffic; disk for release staging, database, logs, snapshots and off-host backups. This guide does not assert an unmeasured universal minimum |
| Public network | Stable reachable public address; DNS records must reach the actual installation host. Publish IPv6 only when it really works |
| Inbound access | Provider firewall/security group and host firewall must permit the roles in the port table below |
| Outbound access | APT repositories, DNS/DoT, ACME, GitHub release/raw endpoints and their asset delivery hosts must be reachable |
| Local tools | A terminal and Git to obtain the complete repository. The installer bootstraps missing runtime packages |

Installation can change networking and system services. Take a provider snapshot/backup first when the
host has anything valuable, and leave a second administrative session or provider console available.
The installer inspects SSH non-destructively; this is not a substitute for checking that the intended
SSH port remains reachable through **both** firewalls.

The low-memory swap branch may create a **1 GiB** `/swapfile` when memory is at most about 1 GiB and
no swap is active; it skips container allocation and refuses to overwrite an unmanaged existing file.
That behavior is not a recommended RAM sizing target. Check free disk space before deployment and
before backups/updates.

<a id="domains"></a>
## 5. Domains, DNS, ports and certificates

### Plan names before installation

All examples below use reserved documentation addresses and domains. Replace them with names and
addresses you control; `203.0.113.10`, `203.0.113.20` and `example.com` are not deployable examples.
A domain argument is a hostname, not a URL, path or IP address.

| Name/record | Example | A record target | Purpose |
| --- | --- | --- | --- |
| Panel entry | `panel.example.com` | Panel VPS, e.g. `203.0.113.10` | Browser, API and subscriptions; local web transports in All-in-One |
| Panel camouflage | `cover.example.com` | Same Panel VPS | Static decoy; REALITY SNI if a local node exists |
| Optional Panel Vision | `vision.example.com` | Same Panel VPS | Local TLS Vision only; not accepted in Panel-only mode |
| Worker entry | `node1.example.net` | Worker VPS, e.g. `203.0.113.20` | Remote client endpoint, not another Panel UI |
| Worker camouflage | `cover1.example.net` | Same Worker VPS | Worker REALITY SNI/static decoy |
| Optional Worker Vision | `vision1.example.net` | Same Worker VPS | Worker's TLS Vision endpoint |
| Optional Master cover apex | `example.com` | The Master VPS you select | Static cover site for the bare address; selected explicitly, never inferred |
| Optional Master `www` alias | `www.example.com` | Same Master VPS | Second cover name, only when enabled with `GOWAVE_COVER_WWW=yes` (default `no`) |

Use distinct entry, camouflage and optional Vision names for each host. The wizard refuses duplicate
names in the deployment plan and lets you correct the offending field. A Worker does not reuse the
Panel's camouflage name on a different address. If sharing a registered domain across hosts, assign
separate subdomains and account for the shared issuance budget.

Use **DNS-only** records, not Cloudflare orange-cloud/proxied records: the preflight refuses known
proxied answers. HTTP-01 validation must reach this host on port 80. Do not add a speculative AAAA
record; a stale IPv6 answer can break validation and clients despite a correct A record.

**The Master cover apex is selected, not derived.** The reviewed plan picks it, or a positional
install sets `GOWAVE_COVER_DOMAIN`; `www` is a separate alias (`GOWAVE_COVER_WWW`, default `no`).
There is no public-suffix guessing: a deployment that selects no apex serves no cover under an
inferred one, and a selection that is not a hostname, repeats the Panel name, or does not resolve to
this host is refused with its reason. A Worker has no apex at all: it serves the camouflage site
under its own camouflage name, which is also its REALITY SNI, so a Worker never claims the Master's
apex.

DNS-to-host examples:

| Topology | Records | Result |
| --- | --- | --- |
| Master with cover, own zone | `panel.example.com`, `cover.example.com`, `example.com`, optional `www.example.com` → `203.0.113.10` | One host owns the apex pair; the cover certificate names the names you selected |
| Same-zone Worker | `node1.example.com`, `cover1.example.com`, `vision1.example.com` → `203.0.113.20` | Worker issues only its own names; the Master apex/`www` stay on the Master |
| Worker in its own zone | `node2.example.net`, `cover2.example.net` → `203.0.113.30` | Worker camouflage lives under its own `cover2.example.net`; it does not claim `example.net` or another zone's apex |

Never move the Master apex or its `www` to a Worker: two hosts cannot validate the same HTTP-01
names, and the certificate would be issued on the wrong machine.

### Port plan

All ports listed here are TCP. These are roles, not instructions to expose every listener publicly.

| Port | Host/role | Allowed reachability |
| --- | --- | --- |
| SSH port, normally `22` | Every host | Your administrative source; Panel-to-Worker for provisioning |
| `80` | Every deployed web/traffic host | Public HTTP-01 challenge and web handling; allow at provider firewall too |
| `443` | Panel and Workers | Public HTTPS/SNI/client traffic |
| `3000` | Panel HTTP API/UI backend | Loopback behind NGINX; do not expose directly |
| `3002` | Node management API | Local node: isolated from external access. Worker: allow only the Panel's address, with mTLS |
| `7443` | NGINX TLS frontend | Loopback, behind the stream entrypoint |
| `8443` | Xray REALITY | NGINX upstream uses loopback, but the template does not restrict the bind address; block direct external access with host/provider firewalls |
| `8444` | Optional Xray TLS Vision | Loopback, behind NGINX Stream |
| `9443` | Static decoy/fallback | Loopback, not a separate public management interface |
| `10001`, `10002`, `10003` | XHTTP, WebSocket, Trojan gRPC backends | Loopback behind NGINX |

On both Master and Worker, `/xhttp-down/` carries VLESS XHTTP `stream-up`. NGINX terminates TLS and forwards this location over cleartext HTTP/2 to Xray at `127.0.0.1:10001` using `grpc_pass`. This is an internal hop, not a gRPC subscription or another public port.

The port-443 stream router writes one line per connection to `/var/log/nginx/gowave-edge-access.log`: the SNI the client sent, the negotiated protocol, the client address and the local port. This is the file to read when you need to know which host carried a connection and under which name. It contains client addresses, so treat it like any other access log; the `gowave-*.log` rotation rule already covers it. The Panel and the transport locations stay unlogged.

The preflight also reserves `3001` and `9444` along with the above managed ports. A free/reserved port
does not mean a service should be listening on it. On Workers, replicate the Panel-only restriction for
3002 in the provider firewall; allowing it globally is not required. For strict DoT, outbound TCP 853
must work. Restrict inbound rules without blocking established outbound connections and ACME/downloads.
The per-role rule matrix, the conflicts the preflight refuses, the exceptions it preserves and the
route back from a failed firewall change are documented in
[Node API ingress and firewall recovery](docs/SETUP_WIZARD.md#node-api-ingress-and-firewall-recovery--входящий-доступ-к-node-api-и-восстановление-файрвола).

### Certificate policy

The wizard estimates the planned certificate budget as `2 + v_panel + 2N + k`: the Panel and camouflage
orders, optional Panel Vision, two orders per remote node, and the optional Worker Vision orders.
The camouflage certificate may include the owning apex and `www` as SANs, rather than separate orders.
Let's Encrypt's **50 certificates per registered domain per 7 days** budget is shared by the cluster
and any other service using that registered domain. The conservative plan ceilings are **24** nodes
without Vision, **23** with Vision on the Panel host only, **16** with Vision on every Worker under a
Panel-only host, and **15** with Vision everywhere under an All-in-One host. These are planning limits,
not evidence that issuance is available now; other CA limits also apply.

- **The remaining budget cannot be queried.** Preflight counts this plan, not previous issuance by you
  or other services. Do not repeatedly reinstall to investigate an ACME error.
- **The apex and `www` camouflage certificate belongs to a single host.** Another host sharing that
  registered apex can serve a decoy at its own subdomain, not independently own the same apex website.
- **Wildcard is not a remedy for a shared domain.** Repeating `[domain, *.domain]` across hosts reaches
  the five-per-exact-set limit at about five hosts per week; it does not remove the shared budget.

Prepare DNS first, allow propagation, and review the names and count before confirming deployment.

### Browser fallback and what the camouflage listener serves

The camouflage name is where a browser, a scanner or an unauthenticated TLS probe lands; it is not a
control surface. Over HTTPS on any traffic host it serves the static cover site rendered from the
bundled assets — the same site on the public listener, on the REALITY fallback through
`127.0.0.1:9443` and on the Worker's own edge. A known asset comes from the rendered tree, an unknown
ordinary path returns the site's branded `404` page, and a malformed ClientHello may be closed
without any HTTP answer at all.

- **No management content on that path.** On the Worker's primary listener `/api/` — management and
  subscription paths alike — is refused before the static handler, and the decoy listener declares no
  Panel, API or subscription location at all. An unauthenticated probe never reads control data,
  however it names the host.
- **Unknown, absent or mismatched names fall back, they do not escalate.** An SNI the stream map does
  not list, an absent SNI and a request whose `Host` differs from the presented SNI end in cover or in
  a closed connection, never in Panel content.
- **The fallback listeners are not public.** `9443` and the decoy are reachable on loopback only; do
  not open them at the provider or in the host firewall, and do not read the cover site's
  availability as evidence that the Panel is healthy.

### Certificate names and who owns them

Each role issues only the names it owns and serves them from the lineage it selected:

| Role | Names in its lineages | Never included |
| --- | --- | --- |
| Panel host | `panel_domain`, the camouflage name, optional Vision; the selected cover apex and `www` only when this host owns them | Names of another host |
| Worker | Its entry name, its camouflage name, optional Vision | The Master's apex, `www` or camouflage name |

An existing certificate is adopted only when it covers the intended name, names the expected issuing
directory and is still valid; the listener is then rendered from the live path that lineage actually
uses, not from an assumed directory name. Wrong SANs, an expired leaf, a key that does not match or a
name the host does not own are refused before activation, and after activation the served certificate
is read back from the client side. A same-zone Worker renews only its own lineages; the Master's pair
is never touched by a Worker step.

### Renewal and what a successful install proves

Renewal is HTTP-01 through the port 80 vhost, so that vhost is production state: it serves
`/.well-known/acme-challenge/` for every name this host owns, redirects other requests on those names
to their HTTPS endpoint and refuses every other host. Once the production configuration is live, the
installer runs `certbot renew --dry-run --cert-name <lineage>` for each lineage the run owns, through
NGINX and the recorded authenticator, before it reports success; a dry run that fails fails the step.
Later renewals come from `certbot.timer`, and the deploy hook
`/etc/letsencrypt/renewal-hooks/deploy/gowave-nginx.sh` runs `nginx -t` and reloads only when the
configuration validates.

Do not reinstall to investigate a renewal failure: the remaining CA budget cannot be queried, so read
the Certbot logs, the renewal configuration and the port 80 path first.

<a id="installation"></a>
## 6. Installation

### Interactive path (recommended)

**Execution host:** the VPS that will run the Panel, not your laptop and not the future Worker.
**Prerequisites:** the checklist and DNS/port plan above. This procedure installs packages and changes
host services/firewall; do not run it merely to inspect the menu on an unrelated production server.

Obtain the **complete repository**: `gowave-auto.sh` sources sibling modules and uses assets. Downloading
only that script is insufficient. If Git is missing, install it on the Panel VPS first:

```bash
sudo apt-get update
sudo apt-get install -y git

git clone https://github.com/satanmaker/gowave-auto-nginx.git
cd gowave-auto-nginx
sudo ./gowave-auto.sh
```

1. Select English or Russian, then the deployment action. An argument-less `install` on a terminal
   also starts the setup wizard.
2. Choose topology. For production isolation, choose **Panel-only** and request remote nodes; for
   evaluation, All-in-One gives one local traffic node.
3. Enter Panel/camouflage domains, ACME email and optional Vision where a traffic node exists. Give
   each node a unique name (letters/digits/dot/underscore/hyphen, starting with a letter or digit).
   The wizard trims names, rejects blanks and case-insensitive duplicates, and asks country confirmation
   for labels when applicable.
4. Enter remote node cards and prepare their SSH access. The temporary password/key flow is described
   in [Remote nodes](#remote-nodes); verify fingerprints through an independent trusted channel.
5. Review **every host, domain, topology, name and certificate count**. Edit the relevant card if wrong.
   Start rechecks DNS and the budget. Cancel at plan review changes no server.
6. Confirm deployment and keep the terminal open. Package/download/ACME/provisioning steps can take
   time; a Panel-installed banner can precede remote node onboarding. Wait for the final summary.

**Expected result:** a reachable HTTPS Panel, a protected credentials file, and an onboarding result for
each planned Worker. A verified registration means the Panel returned the expected node identity; it
is not proof that a client can carry traffic. Follow the next section before declaring deployment done.

**On failure:** preserve the named stage and sanitized diagnostics. Do not erase the host or repeatedly
reinstall. A Panel can be installed while one Worker fails; retain successful components and use the
selective retry route. A critical/incomplete rollback message requires inspection of the recovery
journal before another mutation.

### Complete positional installations

Run these **alternative** examples on a prepared Panel VPS, not one after another. The positional path
is prompt-free for installation inputs; partial arguments are refused, not completed interactively.
Without a terminal, bare `install` prints usage and exits rather than guessing a plan.

```bash
# Panel-only; add remote traffic nodes separately.
sudo ./gowave-auto.sh install --panel-only panel.example.com cover.example.com admin@example.com

# All-in-One; local node name defaults to local-node.
sudo ./gowave-auto.sh install panel.example.com cover.example.com admin@example.com

# All-in-One with an additional local TLS Vision domain.
sudo ./gowave-auto.sh install panel.example.com cover.example.com admin@example.com vision.example.com
```

`--mode panel-only` is equivalent to `--panel-only`. Panel-only refuses the fourth Vision domain
because there is no local traffic plane. Do not use `install` as the normal Panel upgrade command.

<a id="first-connection"></a>
## 7. First login and first client connection

### Sign in privately

**Execution host:** inspect credentials on the Panel VPS; open the Panel from your own browser.
The installer saves `/root/gowave-credentials.txt` with mode **0600**, containing the Panel URL,
admin username/password and, when generated, a scoped API token. Read it only in a private root session:

```bash
sudo less /root/gowave-credentials.txt
```

Do not paste that file into tickets, chat, screenshots or logs. Use the saved `PANEL_URL`, verify the
browser's certificate and sign in using the saved credentials. Secure your admin account and store
recovery credentials privately. A browser certificate warning on a normal production deployment is a
reason to investigate DNS/issuance, not to disable verification globally.

### Check the initial user and available hosts

Provisioning creates/adopts `default-user`. A newly created user is `ACTIVE`, uses `NO_RESET` traffic
strategy and has expiry `2099-01-01T00:00:00.000Z`; this is bootstrap behavior, **not a recommended
access policy**. Review its limits, expiry and squad membership in the Panel, and create separate
users for distribution instead of sharing the bootstrap account.

A Panel-only install initially has no traffic squad/Hosts. Its first successful node registration
creates the managed squad and attaches an unassigned `default-user`; an already assigned user is not
silently reassigned. For other users, select the intended Internal Squad yourself in the Panel. If the
subscription says no hosts are available, first check that at least one node/Host exists and the user
is assigned to its squad.

### Retrieve and import the right subscription

On the Panel VPS, print the initial user's links in a **private** terminal:

```bash
sudo ./gowave-auto.sh user links
```

The command reads the stored initial `defaultUserShortUuid`. It is not a general username-to-user
lookup: if that stored ID exists, `user links <id>` still uses it. For another user, retrieve that
user's actual subscription URL from the Panel UI instead of assuming an argument changes the owner.
A subscription URL contains a bearer-like per-user identifier; treat the entire URL and its QR code
as a secret. Do not put real subscription URLs in shell arguments or public diagnostics.

| URL path after the Panel origin | Use |
| --- | --- |
| `/api/sub/<shortUuid>` | Base64 share links: subscription import in v2rayNG, NekoBox, Hiddify, v2rayN 6+ where supported |
| `/api/sub/<shortUuid>/v2ray-json` | Xray JSON configuration array: JSON/file import, **not** a v2rayNG subscription updater |
| `/api/sub/<shortUuid>/mihomo` | Mihomo/Meta YAML: applications such as Clash Verge Rev or FlClash with compatible cores |
| `/api/sub/<shortUuid>/clash` | Compact Clash YAML: compatible Clash/Clash Meta clients; supported transports still depend on the core |

In the application, add the appropriate subscription URL privately, update it, select one node/profile
and enable its proxy/VPN routing. **GoWave requires a non-empty `User-Agent` header.** Use a real client
or a diagnostic client with an explicit appropriate User-Agent; an empty header can cause refusal
regardless of TLS and authentication. Choosing YAML does not give an old Clash core XHTTP or modern
REALITY support. For GUI applications, inspect the actual embedded core rather than relying on the
application name alone.

### Verify an actual connection

**Execution host:** your client device, on the network where you will use it.

1. Refresh the subscription and confirm expected node/profile labels, addresses and port 443.
2. Select one profile and load an HTTPS site you trust through the enabled client. Compare the observed
   public egress with the selected Worker's expected outbound route, not the Panel's location.
3. Review the client's handshake/connection log and the Panel's node/user traffic indications. Repeat
   for the other profiles you intend to use and for each node, including optional Vision separately.
4. Confirm that disabling the client changes the route as expected. Do not publish raw client configs,
   subscription bodies, keys or user identifiers while diagnosing a failure.

A successful subscription download proves delivery/format only; a parser check proves syntax only;
`health` proves local listeners only. Actual proxied HTTPS traffic is the next required check. If import
works but traffic does not, use the [troubleshooting table](#troubleshooting) rather than regenerating
keys or reinstalling immediately.

<a id="remote-nodes"></a>
## 8. Remote nodes

### Interactive temporary access

**Execution host:** normally the existing Panel VPS, in its repository checkout. Start the menu and
choose **Connect a remote server as a node to the existing Panel**. This is not an instruction to
install a second Panel on the Worker. The flow detects/offers the local Panel and verifies the API
before collecting Worker credentials. A remote Panel domain can also be checked, but the local
credentials needed for authoritative registration readback are not available there; prefer running
on the actual Panel host.

Before onboarding, prepare the Worker's supported OS, unique domains, DNS, SSH/root access and provider
firewall rules. Through the provider console or another **already trusted** Worker session, obtain
its Ed25519 host-key fingerprint:

```bash
ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub -E sha256
```

Run that command **on the Worker**. Compare its `SHA256:...` value with the wizard's scanned fingerprint
and type the full value when requested. A key obtained by scanning the same untrusted connection is
not independent verification. Stop on mismatch; do not disable host-key checks.

The wizard authorizes a temporary key using the SSH password, runs onboarding, then revokes that
specific `authorized_keys` entry on success **and** failure. A Worker systemd timer removes it within
**two hours** if normal cleanup is interrupted; normal cleanup also disables/deletes that timer.
The password is read once and is not put in argv. This is temporary automation access, not a change
to your permanent SSH administration policy.

For unattended bootstrap inputs, `GOWAVE_SSH_FINGERPRINT` must contain the independently verified
fingerprint, and `GOWAVE_SSH_PASSWORD_FILE` must name a password file with mode **0600** (`0644` is
refused). Create/transfer it privately, never pass a password literal in argv, and remove it securely
when finished. These are bootstrap inputs; they do **not** turn bare positional `node add` into a
password-authentication command.

### Positional onboarding with existing SSH access

**Execution host:** the Panel VPS. Positional `node add` uses existing key-only SSH access and strict
host-key verification. Ensure the root execution context has the correct trusted known-host entry and
usable key/agent before running it. The remote payload needs root privileges; merely naming an
unprivileged SSH user is not a privilege-elevation mechanism.

```bash
sudo ./gowave-auto.sh node add worker-1 203.0.113.20 node1.example.net cover1.example.net

# Alternative: a Worker with its own optional TLS Vision endpoint.
sudo ./gowave-auto.sh node add --vision-domain vision1.example.net \
  worker-1 203.0.113.20 node1.example.net cover1.example.net root 22
```

The two commands describe alternatives for the same Worker, not a batch to run blindly. Panel API
credentials and the Node secret are obtained locally; no secret is a positional input. Remote variables
and secrets are serialized over SSH stdin to `bash -s`, not included in the remote command line.

### Read the final result and retry only the failed node

- **Registered and verified in the Panel:** successful onboarding plus local authenticated `/api/nodes`
  readback matching name, address, port and the Panel's own UUID. Still verify client traffic.
- **Registered; a Panel on another host cannot confirm it from here:** onboarding returned success, but
  authoritative local readback was unavailable. Check that Panel yourself; do not call it verified.
- **Failed:** the result identifies a stage/reason (SSH scan/fingerprint, authorization, provisioning,
  cleanup or Panel verification). A missing/wrong Panel registration is not reported as success.

A failed Worker does not require deleting the installed Panel or verified nodes. The wizard offers
individual failed nodes for retry; fix that node's cause, confirm its identity again, and retry it or
use the menu's add-node action later. Do not retry an unverified remote result as if it were a proven
failure: first inspect the actual Panel to avoid conflicting registrations. `node list` shows stored
state; also check the live Panel inventory and the Worker's service/logs.

<a id="progress-stages"></a>
## Progress stages, budgets and recovery actions

The wizard and onboarding flow report safe, allowlisted stages with finite budgets. Stages are
machine-readable markers on stderr; raw credential-bearing output is never used as progress. When
no controlling terminal exists, safe events go to the documented event sink instead of `/dev/null`.

### Stage catalog and budgets (onboarding SSH path)

| Stage | Budget | Description | Recovery on timeout/failure |
| --- | --- | --- | --- |
| `prepare_key` | 2 min | Generate temporary Ed25519 key for bootstrap | Retry; key is disposable |
| `scan` | 2 min | Read Worker SSH host public key | Verify network/DNS; retry |
| `fingerprint` | 1 min | Compute SHA256 fingerprint | Retry; local operation |
| `confirm_fingerprint` | 5 min | Wait for operator fingerprint confirmation | Operator action required |
| `resolve_ip` | 2 min | DNS resolve Worker address | Fix DNS; retry |
| `pin_host_key` | 1 min | Pin confirmed host key to known_hosts | Retry; local operation |
| `prepare_password` | 3 min | Read SSH password for key authorization | Provide password file 0600 |
| `authorise` | 3 min | Authorize temporary key on Worker | Verify password/key; retry |
| `start_agent` | 2 min | Load key into SSH agent | Retry; local operation |
| `country` | 3 min | Collect country entry for GeoIP | Operator input required |
| `registration` | 2 min | Register Worker in Panel API | Check Panel health; retry |
| `add_node` | 3 min | Panel node provisioning call | Verify Panel API; retry |
| `deployment` | 60 min | Full SSH payload deployment | Check network; worker logs; budget notice |
| `hardening` | 10 min | Prerequisites, firewall, Fail2ban, DoT, sysctl | Check target logs; retry |
| `acme` | 15 min | Certificates and NGINX configuration | Check DNS/port 80; Certbot logs |
| `verification` | 5 min | Service checks and security readback | Check service status; SSH access |
| `revoke` | 2 min | Revoke temporary key on Worker | Automatic; timer cleanup ≤ 2 h |
| `stop_agent` | 1 min | Unload temporary key from agent | Automatic |

### Multi-node onboarding progress display

During the 60-minute `deployment` stage the wizard prints heartbeat notices:
```
Still waiting for worker-1 (stage: hardening).
```
The notice shows the last reported stage. A timeout notice appears when a stage exceeds its budget:
```
Stage hardening on worker-1 exceeded its budget: 720 seconds elapsed (budget: 10 minutes).
```

### Wizard exit codes

| Code | Meaning | Action |
| --- | --- | --- |
| `0` | All requested components confirmed | Proceed to traffic verification |
| `1` | Panel failed or pre-deployment check blocked | Inspect Panel logs; do not retry Workers |
| `2` | Panel ready but ≥1 Worker failed/unconfirmed | Inspect per-Worker result; retry only failed nodes |

### Recovery actions by failed stage

| Failed stage | Evidence to collect | Recovery action |
| --- | --- | --- |
| SSH scan/fingerprint | Provider console key, network reachability | Fix network/DNS; confirm key independently |
| Authorization | Password file 0600, key/agent in root context | Correct credentials; retry |
| Country entry | Operator input | Re-enter country; plan preserved |
| Panel registration | Panel API health, `/api/nodes` | Fix Panel; retry node |
| Provisioning/deployment | Worker service logs, SSH session log | Fix cause; retry failed node |
| ACME | DNS A/AAAA, port 80, Certbot journal | Fix reachability/CA error; retry |
| Verification | `systemctl status`, security report JSON | Fix service/control; retry verification |
| Cleanup/revoke | Worker `authorized_keys`, timer status | Timer auto-cleans ≤ 2 h; verify |

### Important distinctions

- **Registration ≠ data-plane verification:** A Worker reported "registered and verified in the Panel"
  means the Panel API accepted the registration and local readback matched. You must still verify
  actual client traffic through the Worker's port 443.
- **Security report freshness:** The security report is valid for 300 seconds by default. Future or
  older reports are rejected for readiness checks.
- **Partial completion:** Exit code 2 means the Panel is ready. Inspect the per-Worker result before
  retrying; an existing registration with unfinished cleanup is not a reason to register again.
- **Draft preservation:** The wizard saves accepted answers. On compatible draft, choose Continue,
  Start over, or Leave without installing. Draft abandonment never uninstalls components.

### Pinned Xray core

Local and remote node installations stage the digest-verified **Xray 26.11.9** core at
`<install_dir>/rw-core` **before** running the upstream installer. With the default pin, that installer
need not query `api.github.com` to discover/download a missing core. This is a narrow node-install
property, not a promise that every Panel download, update or lifecycle command avoids GitHub's API.

- An unavailable or unverifiable pinned artifact stops installation and names the artifact/version;
  there is no silent fallback. `XRAY_SERVER_VERSION=latest` explicitly opts out and lets the upstream
  installer choose/fetch the core, restoring its network/API behavior and losing pinned reproducibility.
- On a host without an earlier managed stock core, `gowave-node core reset` answers
  `no managed stock core is available`: staging `rw-core` does not manufacture a `.stock` backup.
- The Node's own release archive and missing `geoip.dat`/`geosite.dat` are still downloaded from
  `github.com`. Core pinning skips neither; these direct downloads themselves do not consume GitHub
  API quota. It also does not remove existing geodata.

<a id="operations"></a>
## 9. Day-to-day operations and recovery

Unless noted otherwise, run these commands **on the Panel VPS from the complete repository**. Retain
a compatible checkout for installed helpers and take an off-host backup before maintenance. Do not
start concurrent mutations on the same deployment.

### Status, health and node inventory

```bash
sudo ./gowave-auto.sh status
sudo ./gowave-auto.sh health
sudo ./gowave-auto.sh node list
```

`status` prints services, selected listeners and certificate expiry. In Panel-only mode an absent local
Node is expected. `health` checks the local Panel HTTP listener (with a root-page fallback) and warns
about the Node listener; **HEALTHY is not a public TLS, Worker, subscription or traffic test**.
`node list` prints stored node state, not an independent live traffic measurement. Combine these with
the Panel UI and a real client connection after every meaningful change.

### Panel releases versus channels

Use the **Panel's own update interface** for Panel release upgrades. This installer provisions
`gowave-update.path` watching `/run/gowave/update-request` and a root `gowave-update.service` helper.
Do not hand-create update-request files as a normal update interface, and do not assume an updater
button's return means the new release is live: read the helper log, actual running version, Panel health,
public HTTPS and a subscription/client connection afterward.

A channel operation is different: it snapshots local state, changes `GOWAVE_CHANNEL` and restarts/checks
the Panel. It does **not** itself download a new release binary or upgrade every Worker.

```bash
sudo ./gowave-auto.sh channel dev
```

The default channel is `stable`. A return from `dev` to `stable` may encounter irreversible schema
migrations. The current CLI implementation requires the literal second argument `true` to acknowledge
that risk: `channel stable true`. Despite the diagnostic saying `--force`, `--force` is **not** the
accepted confirmation value in this implementation. Do not infer a schema downgrade from a successful
channel switch. Preserve a tested pre-dev backup and compatible binaries before attempting a return.

### Change the Panel host's domains

**Prerequisites:** new unique DNS names already reach this Panel VPS; port 80/443 and certificate budget
are available. Schedule disruption and back up first.

```bash
sudo ./gowave-auto.sh domain-change panel-new.example.com cover-new.example.com
```

This obtains certificates, rewrites this host's NGINX/Panel environment and restarts/verifies the Panel
with snapshot-based rollback on handled failures. It is **not a cluster-wide domain migration**: do
not assume it updates remote Worker DNS, all stored API Host records, optional Vision endpoints,
previously distributed subscription URLs or client caches. Inspect live records and reissue/reimport
links as needed. Keep old DNS available until external HTTPS and client verification succeed. If rollback
is reported incomplete, retain the journal/snapshot and investigate before changing DNS again.

### Replace an existing deployment (explicit migration)

An install, or a `node reapply`, that finds a managed deployment already on the host does not
overwrite it silently. The installer inspects the recorded identity and what the host actually serves,
prints the preview of the identity it would adopt — the Worker's primary and camouflage routes, the
vhosts and the lineages — and waits for you. Nothing mutates before that confirmation.

- At a terminal the confirmation is the prompt's answer; in automation it is
  `GOWAVE_MIGRATE_EXISTING=yes` in the environment of the same command. Declining leaves the host
  exactly as it was, and a run with no terminal to ask on exits non-zero instead of guessing.
- A Worker re-provision is refused for the same reason and names the command to rerun, so an
  unattended `node reapply` cannot rewrite an edge nobody confirmed.
- Registration, the node UUID, its profile and the Panel's Host records are reused; a migration does
  not create a second node for the same host.
- The confirmed run keeps the transaction that owns it: the ACME snapshot, the before-image and the
  recovery journal. A step that fails restores the previous routes, vhosts and certificate references
  rather than leaving half of the new identity live, and a rollback it reports as incomplete keeps its
  journal for you to inspect instead of being retried blindly.

### Backup, verify and restore

**Execution host:** the host whose state is being saved/restored. Panel backups are not full disk images
and do not back up every Worker. Format v1 Panel archives contain a SQLite Online Backup, Panel `.env`,
managed NGINX snippets, state and the included Let's Encrypt archive/live/renewal tree. Node archives
contain the Worker's `.env`, not its binaries or the full traffic configuration. Keep the repository,
compatible upstream releases and a host/DNS inventory available for rebuilding services.

**Archives are unencrypted and secret-bearing**, including credentials/database/private TLS material.
They are published mode **0600**; permissions are not encryption. Encrypt and store an off-host copy
using your own trusted backup process. Do not upload one as a troubleshooting attachment.

```bash
# On the Panel VPS: save to an explicit protected location.
sudo ./gowave-auto.sh backup /var/backups/gowave/panel-before-maintenance.tar.gz
sudo ./assets/backup/gowave-backup.sh verify /var/backups/gowave/panel-before-maintenance.tar.gz panel

# On a Worker, from a complete checkout: separate credential backup.
sudo ./assets/backup/gowave-backup.sh backup --type node /var/backups/gowave/node-before-maintenance.tar.gz
sudo ./assets/backup/gowave-backup.sh verify /var/backups/gowave/node-before-maintenance.tar.gz node
```

Without an explicit output, the default store is `/var/backups/gowave` with timestamped archive names.
The validator checks Format v1/type, paths, allowed members, metadata, hashes, symlinks and size/member
limits before application. A successful `verify`/`inspect` validates the archive contract; it is **not**
a successful restore rehearsal or evidence that external DNS/clients will work.

Restore overwrites covered state and can stop/restart services. Use a maintenance window, keep a
separate copy of the current state, and rehearse on a disposable compatible host first. Existing service
binaries, units and host prerequisites still matter; restoring an archive alone is not bare-metal
provisioning. Only after making that decision, on the target host:

```bash
# Panel restore (overwrites covered Panel state).
sudo ./gowave-auto.sh restore /var/backups/gowave/panel-before-maintenance.tar.gz

# Worker restore (overwrites covered Worker credentials).
sudo ./assets/backup/gowave-backup.sh restore /var/backups/gowave/node-before-maintenance.tar.gz --type node
```

Afterward inspect services, served certificates, Panel data, node identity, subscriptions and actual
traffic. A failed restore can attempt compensating rollback and retain recovery state; do not delete
the journal to suppress its warning. A backup taken after damage is not a substitute for a known-good
pre-change backup.

### Recovery and uninstall boundaries

Recovery services use `/var/lib/gowave-auto-nginx/recovery/journal.json` and retained snapshots to
recover interrupted **covered** file/provision operations. Preserve them and inspect the failing phase,
logs and both Panel/Worker state before manual recovery. The `recover --boot-files` and
`recover --boot-provision` forms are boot/service repair entrypoints, not a generic user-facing
“repair everything” command. A bare `recover` performs no repair.

**Uninstall is disruptive**, even though it deliberately preserves data:

```bash
sudo ./gowave-auto.sh uninstall
```

The prompt requires `YES`; `uninstall --yes`/`-y` bypasses that confirmation. It stops/removes managed
services and NGINX configuration, so the Panel and local traffic can become unavailable. It preserves
application data, node binaries, backups, state and webroots for manual review; it is not a clean-room
factory reset, a restoration of all pre-install hardening, or remote-Worker removal. Inspect preserved
contents and keep backups before deleting anything yourself. `gowave-cleanup.sh` is a separate,
aggressive tool—not the normal uninstall/retry procedure.

<a id="reference"></a>
## 10. CLI and environment reference

Commands below assume the repository root and administrative execution on the Panel host unless the
row says otherwise. Angle brackets denote required values; square brackets optional values. **Do not
paste the notation literally.** The no-argument terminal entrypoint selects language and opens the
menu; positional commands remain a separate automation interface.

| Command after `sudo ./gowave-auto.sh` | Purpose / important qualification |
| --- | --- |
| *(no arguments)* | Interactive language selection and lifecycle menu; needs a terminal for normal use |
| `install` | Interactive installation wizard on a terminal; without one, usage/refusal |
| `install [--panel-only \| --mode panel-only] <panel-domain> <camouflage-domain> <acme-email> [vision-domain]` | Complete positional install; optional Vision only with local traffic node |
| `status` | Local service/listener/certificate report |
| `health` | Local Panel health; Node listener warning is not an end-to-end failure verdict |
| `node add [--vision-domain <domain>] <worker-name> <worker-ip> <worker-domain> <reality-domain> [ssh-user] [ssh-port]` | Provision/register a Worker using existing trusted key-only SSH; defaults `root`, `22` |
| `node list` | Read stored node inventory |
| `node reapply <worker-name> [ssh-user] [ssh-port]` | Reapply the stored Worker's deployment; mutates that host and needs working SSH/DNS |
| `node rollback [--vision-domain <domain>] <worker-ip> <worker-domain> <reality-domain> [ssh-user] [ssh-port]` | Specialist remote compensating cleanup; not a general node-delete API; inspect ownership/state first |
| `channel <stable\|dev>` | Change Panel update channel and restart/check; not a release download |
| `channel stable true` | Risk acknowledgement for dev → stable; cannot undo schema migrations |
| `domain-change <panel-domain> <reality-domain>` | Change local Panel/NGINX domains, not all cluster records |
| `backup [--type panel\|node] [output]` | Format v1 archive; defaults to type `panel` |
| `restore <archive> [--type panel\|node]` | Restore covered state on this host; defaults to type `panel` |
| `user links [id]` | Print secret-bearing URLs; stored initial short UUID wins, so not arbitrary username lookup |
| `uninstall [--yes\|-y]` | Disrupt managed services/configuration; preserve data for review |
| `recover --boot-files` | Internal/boot recovery of covered file transactions |
| `recover --boot-provision` | Internal/boot recovery of covered provisioning transactions |

Additional backup-only interfaces are `sudo ./assets/backup/gowave-backup.sh verify <archive> [panel|node]`
and `inspect <archive> [panel|node]`; both validate rather than apply. `gowave-node-auto.sh` payload,
rollback and finalize entrypoints are internal orchestration machinery, not a standalone quick-start
replacement for `node add`.

### Node input precedence and defaults

| Variable | Positional/flag equivalent | Default |
| --- | --- | --- |
| `GOWAVE_NODE_NAME` | `<worker-name>` | Required |
| `GOWAVE_NODE_IP` | `<worker-ip>` | Required |
| `GOWAVE_WORKER_DOMAIN` | `<worker-domain>` | Required |
| `GOWAVE_REALITY_DOMAIN` | `<reality-domain>` | Required |
| `GOWAVE_SSH_USER` | `[ssh-user]` | `root` |
| `GOWAVE_SSH_PORT` | `[ssh-port]` | `22` |
| `GOWAVE_VISION_DOMAIN` | `--vision-domain <domain>` | None; legacy `VISION_DOMAIN` is a fallback |
| `XRAY_SERVER_VERSION` | No positional | `26.11.9` when unset; `latest` explicitly opts out of the pin |

A non-empty positional input (or Vision flag) wins over its environment variable. An empty variable
counts as unset. Both paths use the same field validation. No Worker secret is accepted through this
input contract: the secret is read from the Panel's `.env` and passed over stdin, never as a node-add
argument or an exported Worker-secret input.

```bash
sudo GOWAVE_NODE_NAME=worker-1 GOWAVE_NODE_IP=203.0.113.20 \
  GOWAVE_WORKER_DOMAIN=node1.example.net GOWAVE_REALITY_DOMAIN=cover1.example.net \
  ./gowave-auto.sh node add
```

### Other operator-facing configuration

Use explicit `sudo NAME=value ...` assignments for the non-secret overrides you intend; do not rely on
`sudo` preserving your shell environment, and do not use broad environment forwarding to pass secrets.

| Identifier | Meaning/default and caution |
| --- | --- |
| `GOWAVE_WIZARD_LANG` | `en` or `ru`; otherwise terminal language selection |
| `GOWAVE_PANEL_VERSION` | Panel release selector at install; default `latest`, with checksum verification |
| `GOWAVE_NODE_VERSION` | Node release selector during deployment; default `latest`, separate from the pinned installer/core |
| `VISION_DOMAIN` | Legacy local-install optional Vision fallback; explicit fourth domain wins |
| `GOWAVE_SSH_FINGERPRINT` | Independently verified Worker fingerprint for temporary-access bootstrap |
| `GOWAVE_SSH_PASSWORD_FILE` | Private mode-0600 password file for bootstrap; not a password value |
| `GOWAVE_REALITY_FINGERPRINT` | REALITY uTLS preset; default `firefox`. Changing presets can affect compatibility |
| `GOWAVE_MIHOMO_X25519` | Advanced subscription compatibility override; automatic behavior follows the pinned server. Do not change to mask an outdated client |
| `GOWAVE_ACME_SERVER` | Override the default Let's Encrypt production directory; certificate lineages must remain consistent with the selected CA |
| `GOWAVE_TLS_CA_FILE` | Additional explicit trust input for applicable TLS verification; regular non-symlink CA file, not a “skip verification” switch |
| `GOWAVE_CHANNEL` | Installed Panel `.env` channel; initial default `stable`, changed with `channel` |
| `BACKUP_STORE` | Backup helper's default output directory, `/var/backups/gowave` |

Artifact-file, installer-commit/checksum, state-path and ACME/Podman-test overrides exist for maintainers
and isolated testbeds. They are not required production settings; use the owning source/test guide
before changing them. Never put `SECRET_KEY`, admin passwords, JWTs, private keys or subscription URLs
in argv, issue attachments or diagnostic logs. Redact values, not just variable names.

<a id="security"></a>
## 11. Files, services and security model

| Path/service | Owner/purpose |
| --- | --- |
| `/opt/gowave` | Panel executable/frontend, `.env` and `gowave.db`; sensitive application state |
| `/opt/gowave-node` | Node installation, `.env` and `rw-core`; Xray supervised by Node, not a second watchdog unit |
| `/root/gowave-credentials.txt` | Root-only bootstrap administrative credentials/token |
| `/var/lib/gowave-auto-nginx/state.json` | Installer inventory and initial-user identifier; keep private |
| `/var/lib/gowave-auto-nginx/recovery` | Recovery journal and snapshots; do not discard during unresolved failure |
| `/var/backups/gowave` | Default unencrypted secret-bearing Format v1 archives |
| `/etc/nginx/conf.d/gowave-*.conf`, `/etc/nginx/stream-enabled/gowave-*.conf` | Managed HTTP/TLS/stream configuration |
| `/etc/letsencrypt` | Certificate lineages, private keys, renewal configuration/hooks |
| `/var/www/gowave-auto-nginx/cover-reality`, `/var/www/gowave-acme` | Static cover assets and HTTP-01 webroot |
| `gowave.service` | Native Panel service, unprivileged `gowave` account |
| `gowave-node.service` | Node/Xray supervision on traffic hosts; absent on Panel-only |
| `gowave-update.path`, `gowave-update.service` | Panel-requested root update helper; installed repository/helper paths must remain usable |
| `gowave-recover.service`, `gowave-recover-provision.service` | Boot recovery integration |
| `nginx.service`, `fail2ban.service`, `systemd-resolved.service` | Public routing, SSH abuse protection and DNS resolution |

Installation also enables/configures UFW, Fail2ban with the systemd backend, strict DoT and resolver
settings, BBR/sysctl tuning, conditional swap, log rotation and unattended security updates without
automatic reboot. SSH is inspected without rewriting its authentication policy. These are host-wide
side effects: applications outside GoWave may be affected by firewall, DNS or kernel-setting changes.
A successful application rollback does not imply all these host changes were reversed.

Trust boundaries matter: the Panel's Node secret and authenticated API control configuration; Workers
accept management only from the Panel address and require mTLS; SSH host-key confirmation anchors
bootstrap trust. A compromised root/Panel account or leaked backup/subscription is outside the protection
of “hidden” ports or a decoy. The static cover does not make an endpoint invisible or guarantee safety
from scanning or blocking.

Mutations use an exclusive lock, staged/atomic file publication where implemented, snapshots and
journaling. Handled failures attempt rollback of covered resources; the code can explicitly report
**incomplete rollback** and retain evidence for operator recovery. CA issuance/rate limits, DNS changes,
external API effects, upstream schema migrations, disk failures and lost hosts cannot be universally
undone. Keep independent backups and provider recovery access.

Panel release assets are verified against release `SHA256SUMS`; Node installer content is pinned by
commit/digest, and the default Xray archive by version/digest. Panel and Node **release versions** still
default to `latest`. Checksums establish correspondence with the selected source, not an independent
security audit. This repository neither vendors nor modifies the upstream binaries.

<a id="troubleshooting"></a>
## 12. Troubleshooting

Start with the smallest read-only check on the host named in the failure. Preserve the failing phase
and a bounded log window; sanitize credentials, URLs and identifiers before sharing. Do not “fix” a
certificate or SSH error by globally disabling verification.

| Symptom | Safe check / execution host | Interpretation and next action |
| --- | --- | --- |
| Bare install exits with usage | Check terminal and complete syntax on Panel VPS | Wizard needs a terminal; automation must supply all positional inputs |
| OS/architecture refused | `uname -m` and OS release on the failing host | Use a supported target; changing a displayed version does not add artifact support |
| Preflight reports occupied ports | `sudo ss -ltnp` on that host | Identify the owner; do not kill an unrelated service or flush its firewall blindly |
| DNS mismatch/proxied answer | `getent ahostsv4 panel.example.com` on Panel VPS; check authoritative records separately | Point DNS-only A records at the actual host, remove stale AAAA, then wait for propagation |
| ACME refused/connection timed out | DNS plus provider inbound 80 and local NGINX/Certbot logs on the named host | Fix reachability/CA error; budget is not queryable, and repeat orders can consume limits |
| HTTPS serves decoy instead of Panel | Check requested hostname/SNI and DNS from the client | An IP-only request/unknown SNI can intentionally reach the decoy; use the Panel domain |
| Panel banner appeared but install seems unfinished | Keep terminal; inspect final onboarding summary | Panel completion can precede SSH node steps; do not start a second install |
| SSH fingerprint mismatch | Independently read Worker host key in provider console | Confirm rebuild/key rotation or investigate interception; stop before credentials are sent |
| Password file refused | `stat -c '%a %U %n'` on your private password file | Require 0600; never solve by placing the password on the command line |
| Positional SSH authentication fails | Check root-context key/agent and pinned known-host entry on Panel VPS | Bare `node add` is key-only, unlike wizard bootstrap; repair intended access first |
| Worker registered but absent/unverified in Panel | Read live Panel nodes and the failed verification phase | Do not equate stored state or SSH success with live registration; retry only after identity/conflict is resolved |
| Empty/no-host subscription | Panel user squad, node/profile and Host inventory | Panel-only needs a Worker; other users need appropriate squad membership |
| Subscription download refused | Client logs: HTTPS, identifier and non-empty User-Agent | Correct family/header/user state without publishing the secret URL |
| Import succeeds, traffic fails | Client core/version/handshake log; selected Worker's 443 and outbound route | Check modern REALITY support, transport availability, SNI and correct Worker; parser success is insufficient |
| Pinned Xray archive unavailable/mismatched | Installer's named version/artifact error | Repair download/integrity cause; `XRAY_SERVER_VERSION=latest` is an explicit reproducibility/API opt-out, not silent repair |
| `core reset` says no stock core | Check whether this host ever had a managed stock core | Expected on a fresh staged-core install; do not invent a `.stock` file |
| `health` is green but public access fails | External HTTPS and real client on another network | Local Panel liveness does not prove provider firewall, SNI, subscription or data plane |
| Update/restart failed or rollback incomplete | Helper/service journal and recovery journal on Panel VPS | Keep snapshots; resolve recorded phase before another mutation; a successful restart alone does not establish new version |
| Restore validation fails | Run `verify` for the correct archive type | Do not extract/force an untrusted archive into `/`; obtain a valid matching backup |

Useful bounded diagnostics, on the **affected** Panel or Worker host:

```bash
sudo ./gowave-auto.sh status
sudo nginx -t
sudo ss -ltnp
sudo ufw status verbose
sudo journalctl -u gowave.service -u gowave-node.service -u nginx.service --since '30 minutes ago' -n 200 --no-pager
sudo journalctl -u gowave-update.service --since '30 minutes ago' -n 100 --no-pager
```

A Worker need not have `gowave.service`. The selected window and `-n` caps can truncate relevant events;
state that limitation when reporting a problem. Review output privately before attaching it. For
renewal problems also inspect the local Certbot logs and renewal configuration; a live certificate
served on 443 is stronger evidence than merely finding a PEM file on disk.

<a id="testing"></a>
## 13. Testing and evidence

Tests are for development/acceptance, **not a post-install checklist to execute on production**.
Supported targets, declared scenarios, CI jobs and a specific measured PASS are different claims.
This README does not claim a current runtime PASS or convert specification counts into results.

### Five privilege-separated Python suites

The suite registry is [tests/run_ci.py](tests/run_ci.py). Run from the repository root in the prepared
Python/test environment described in [CONTRIBUTING.md](CONTRIBUTING.md).

| Suite | Run as | Scope / safety boundary |
| --- | --- | --- |
| `nonroot` | Ordinary user | Source/lint/documentation, contracts, helpers and isolated/fake-runner tests; not real deployment acceptance |
| `integration` | Ordinary user | Panel API client/provisioning integration with test fixtures; distinct from Podman topology runs |
| `services` | Ordinary user | Service/network fixture tests; needs its declared test environment |
| `root` | Root, disposable isolated host only | Privileged lifecycle/firewall/recovery tests that can modify host state |
| `systemd` | Root, disposable systemd host only | Service-manager/boot runner behavior, not safe on an installed server |

Cheap development checks, **on a development checkout as an ordinary user**:

```bash
python3 tests/run_ci.py --check-completeness
python3 tests/run_ci.py --suite nonroot
```

Completeness checks that TestCase classes are assigned; it does not run acceptance traffic. The root
and nonroot suite names are **not** Podman scopes. Do not prefix a whole nonroot suite with `sudo` to
bypass a fixture/permission problem.

### Rootful Podman product acceptance

The container testbed runs the shipped installers against disposable systemd hosts, local DNS and an
ACME fixture, then reads back state and drives client traffic. It supports `aio`, `multi-node` and
`panel-only` topologies and the Ubuntu/Debian aliases in [images.lock.yaml](tests/cases/images.lock.yaml).
Panel-only tests include onboarding to a separate Worker; they do not invent a local traffic plane.
The client image installs the matrix's digest-verified real Xray and Mihomo engines, not just YAML/JSON
parsers. Tuple coverage and topology are defined in [matrix.yaml](tests/cases/matrix.yaml), with case
mapping in [traceability.yaml](tests/cases/traceability.yaml).

**Execution host:** a dedicated Linux test machine with rootful Podman, cgroup v2, netavark/nftables,
Python/PyYAML, sufficient disk and outbound artifact access. These commands create privileged test
infrastructure; do not run them on the deployed Panel/Worker. From the repository root:

```bash
sudo python3 -m tools.podman_e2e.environment
sudo python3 -m tools.run_podman_e2e --topology aio
sudo python3 -m tools.run_podman_e2e --topology multi-node
sudo python3 -m tools.run_podman_e2e --topology panel-only
```

Read [Podman E2E](docs/PODMAN_E2E.md) for prerequisites, distributions, Vision flags, budget ceilings,
retention, failures and cleanup before starting. Do not run overlapping suites against shared test
infrastructure without the harness's explicit support. Registry/download outages and GitHub limits
can prevent acceptance from completing; distinguish them from an observed product defect.

The default artifact root is `artifacts/podman-e2e`; inspect the run's **`result.json`**, per-case
outcomes, logs and diagnostics, not just the last console lines. A missing/unrun case, exhausted budget
or `INCOMPLETE` is not a pass. Record the tested commit/tree, topology/distribution, optional features,
run directory, case outcomes and bounded diagnostic sample. An older or unrelated run cannot prove
that a later change works, and a clean exit alone is not readback from the affected system.

The [Podman acceptance workflow](.github/workflows/podman-acceptance.yml) covers PRs into `develop`,
pushes to `develop` and manual dispatch; do not assume every repository workflow has the same triggers.
Its product-acceptance invocations use the default Ubuntu 24.04 target; support for four distributions
and separate compatibility/systemd checks must not be described as a full product E2E run on each.
See [discovery](docs/PODMAN_E2E_DISCOVERY.md), [behavior index](docs/PODMAN_E2E_BEHAVIORS.md) and
[traceability guide](docs/PODMAN_E2E_TRACEABILITY.md) for the maintained coverage route rather than
relying on a prose scenario total.

### Live VPS acceptance

[Live VPS testing](docs/LIVE_VPS_TESTING.md) describes `tools/run_live_vps.py`, its interactive operator
workflow and private environment/configuration inputs. Use dedicated clean-room VPSs and test domains:
this layer spends real infrastructure/CA/network resources and can change firewall/services. It is not
an unattended smoke test to point at a working production server. Keep real addresses, SSH material,
credentials and results out of tracked examples.

Container acceptance cannot prove provider routing/firewall behavior, public DNS/ACME availability or
GUI application compatibility. Live acceptance and your first-client checks complement it; neither
justifies a blanket promise across every client/network/version. Cite the actual measured scope and
what was not run.

<a id="project"></a>
## 14. Project and contribution links

| Location | Contents |
| --- | --- |
| [gowave-auto.sh](gowave-auto.sh) | Main lifecycle/menu/CLI entrypoint |
| [gowave-node-auto.sh](gowave-node-auto.sh) | Remote Worker orchestrator and streamed payloads |
| [modules/](modules/) | OS/preflight, API, NGINX, security, locking and recovery helpers |
| [assets/](assets/) | Backup helper, hardening tools, camouflage assets and canonical Xray profiles |
| [tests/](tests/) and [tools/](tools/) | Suite registry, contracts, acceptance catalogs/runners and release tooling |
| [openspec/specs/](openspec/specs/) | Behavioral requirements; declarations are not test results |
| [Setup wizard guide](docs/SETUP_WIZARD.md) | Detailed plan editing, bootstrap and result/retry behavior |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Development setup, checks and contribution route |
| [AGENTS.md](AGENTS.md) | Repository engineering and credential-handling rules |

Linked specialist guides are primarily English; the essential installation-to-client and maintenance
procedures are included in both README languages. Contribute on a focused branch through a PR into
`develop`, run the relevant cheap checks first and report actual evidence and limitations. Bash changes
use `set -Eeuo pipefail`, syntax checks and ShellCheck; never weaken a safety assertion merely to make
a suite green. Do not include real server identities, passwords, tokens or secret-bearing archives in
issues or pull requests.

External upstream projects: [GoWave Panel](https://github.com/aaaSaZaN/gowave),
[GoWave Node](https://github.com/aaaSaZaN/gowave-node), [Xray-core](https://github.com/XTLS/Xray-core)
and [Mihomo](https://github.com/MetaCubeX/mihomo). Their documentation and licenses govern their own
components; this repository's integration does not imply upstream endorsement.

This project is licensed under [GPL-3.0](LICENSE). See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)
for third-party notices; external components remain under their respective licenses.
