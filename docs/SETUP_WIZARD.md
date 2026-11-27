# Setup wizard and deployment variants

`gowave-auto.sh` has a unified interactive entrypoint and prompt-free positional forms. The interactive
entrypoint selects the language first, then presents a menu that routes to all lifecycle operations.
The positional forms remain English-only and prompt-free.

```bash
# Unified interactive entrypoint: selects language, shows menu, routes to operations
sudo ./gowave-auto.sh

# Interactive install (legacy, still works):
sudo ./gowave-auto.sh install

# Non-interactive install (prompt-free):
sudo ./gowave-auto.sh install [--panel-only | --mode panel-only] \
    <panel-domain> <camouflage-domain> <acme-email> [vision-domain]
```

`--panel-only` and `--mode panel-only` are the same flag. Panel-only accepts no Vision domain: it deploys
no traffic plane, so the fourth positional argument is refused.

## Interactive menu

Running `gowave-auto.sh` without arguments (and with a terminal) enters the interactive mode:

1. **Language selection** — `ru` or `en`, before any menu text is rendered
2. **Menu** — numbered options for all lifecycle operations:
   - Show installation status
   - Deploy a new Panel (and optional nodes)
   - Connect a remote server as a node to the existing Panel
   - Change domains
   - Switch channel (stable ↔ dev)
   - Create Backup
   - Restore Backup
   - Show User Subscription Links
   - Uninstall
   - Exit

Every action stays on screen until Enter is pressed, and only then does the menu redraw: the menu starts
with a clear, so a status report or a result that ended the branch would otherwise be erased before it
could be read. End of input (Ctrl-D) leaves the menu the way Exit does. The positional `status` command
never waits, because a script or a CI case has nobody to press Enter.

## The three deployment variants

| Variant | What runs on this host | Production use |
| --- | --- | --- |
| Panel only | Panel and a static camouflage site; stream `default` goes to the decoy at `:9443` | Recommended: control plane only, no client traffic |
| Panel and one node | Panel and a local Node, with Xray/REALITY/Vision on `:8443`/`:8444` | Evaluation and personal use only |
| Panel and one node plus remote nodes | The same host, then each Worker onboarded over SSH | Not recommended: one host is both control plane and one of the traffic endpoints |

The recommended shape is Panel-only on this host with every node on a separate server: losing the
Panel host then costs the control plane but no client endpoint. Every variant that runs a node here
puts one traffic endpoint on the same host as the control plane, and no scheme moves clients between
nodes automatically when one fails — failover is a property of the client configuration and the node
inventory, not of this installer.

## Naming servers

Every server in the plan is given a name of the operator's own choosing, asked separately from its
domain: the local node right after the Panel card, each remote node right after its own card. A
Panel-only host runs no local node, so it asks for no local name and no Vision. The name is what the
Panel, the subscriptions and the Host records call the server, so it is not derived from DNS and does
not have to look like one — `ams-01` is a fine name for a host whose domain is `node1.example.com`.

The same rules apply wherever a name is asked — during collection, in the review editor, and when
adding a node to an existing Panel:

- surrounding spaces are removed, so a pasted name is accepted as typed;
- a blank name is refused and only that question is repeated;
- letters, digits, dot, underscore and hyphen are allowed, and the first character is a letter or a
  digit. This is the rule the Panel enforces on registration, so a name the wizard accepts is a name
  `node add` accepts instead of failing after the SSH session opened;
- two servers cannot share a name, and a difference in case alone is a shared name. The refusal names
  the server that already holds it.

The accepted name reaches everything the server is registered with: profile tags, Host remarks, the
`node add` argument and `state.json`. An installation that collects no plan — a positional
`gowave-auto.sh install …` run — keeps the historical `local-node` name, so a repeated non-interactive
install does not register a second local node under a new name.

## Reviewing the plan

Collecting the answers builds a plan; nothing on a server changes until the review is started. A name
the plan already holds — the Panel host, the Panel camouflage, a node's own two other names, or the
name another server was given — is refused at the field that typed it and asked again, so a second
node's cover domain cannot cost the Panel and the first node. The review prints the summary and four
kinds of action:

```
  1) Start deployment with this plan
  2) Edit the Panel and plan settings
  3) Edit node 1
  0) Cancel and return to the menu
```

Adding remote nodes puts one `Edit node N` line per node, so node 2 is always action 4 and cannot
reach node 1's fields. Each editor lists that group's fields with their current values and a number
for each, and `0` returns to the action list. An empty answer keeps the current value, except a
Vision domain, where empty removes Vision; a refused value prints its reason and leaves the editor
open, so the operator fixes that one field instead of retyping the whole card.

Every server line says what its names serve, so a Worker is never read as a second Panel:

- the Panel host shows `panel=` (the browser address, API and subscriptions), `camouflage=` (the
  REALITY SNI) and `vision=`;
- a Worker shows `transport=` — XHTTP, WS and gRPC plus the static cover its primary name answers —
  `camouflage=` (the REALITY SNI) and `vision=`, and never `panel=`;
- the Master cover apex is its own owned name on its own line: `Master static cover:` shows the
  selected apex and, when chosen, its `www` alias, or `none selected — no apex is inferred`.

The Worker question carries the same distinction: the primary name is asked as the XHTTP/WS/gRPC and
static-cover name "no Panel runs here", and the second name as the REALITY SNI. With Vision the
Worker owns three names; without it, two. The four mandatory profiles stay in the plan either way.

The reviewed names are not only a screen: before the first certificate is ordered they are written
to `state.json` as `domainOwnership` — the role (`master` or `worker`), each name by role, and the
SAN set each certificate has to carry — so a later domain change or resume reads the selection the
operator made instead of re-deriving one.

Start re-runs the DNS check and the certificate-budget check, so a plan refused during editing cannot
be started anyway. A failure that belongs to one answer is routed back to the field that holds it
instead of restarting the plan:

- a name the resolver cannot answer prints `Back to <field>: <name> does not resolve here.` and
  asks only for that field — the Panel, the other nodes, the language and every earlier answer stay;
- a shared domain whose certificate count exceeds the ceiling prints the ceiling and asks for the
  node count, which is the field that produced the count; lowering it to the ceiling meets the
  budget, and the shared consent is then asked for the new count.

The shared-domain consent is remembered for the certificate count it was given for, and asked again
only when the count changes. Cancel prints `Deployment cancelled. No server was changed.` and returns
to the menu with the plan discarded: no lock is taken, and no install step runs.

## Adding nodes to an existing Panel (menu option 3)

The "Connect a remote server as a node to the existing Panel" menu option onboards a new Worker to a
Panel that is already deployed. The flow is:

1. **Local Panel detection** — If a `gowave.service` is active on this host, its domain is read from
   NGINX config, `state.json`, or `.env` and offered for confirmation.
2. **Panel address entry** — If no local Panel is found or the operator declines it, the Panel
   domain is prompted. An address is not accepted: the certificate the Panel serves names its
   domain, so a bare IP offers nothing to verify.
3. **Panel API verification** — Before any SSH credentials are collected or the Worker is mutated,
   the Panel API is verified:
   - For a Panel running on this host, and for `127.0.0.1`/`localhost`: plaintext HTTP to
     `127.0.0.1:3000/api/system/health`. The Panel itself speaks plaintext on 3000; TLS is
     terminated by the NGINX in front of it.
   - For a remote domain: HTTPS to `https://<domain>/api/system/health` on 443, validated against
     the system CA bundle. If validation fails, the certificate fingerprint (SHA-256) is displayed
     and the operator must confirm it; the certificate is read again after the answer, and a
     changed one refuses the request.
   - A bare IP address is refused: the certificate names the Panel's domain, and the stream
     demultiplexer answers a connection carrying no name from the decoy, so an address has no
     identity to verify.
   - A wrong target, an unverified certificate without confirmation, a bare address, and an
     unreachable API are all rejected before any Worker access or credential transmission.
4. **Worker details** — Worker name, IP, domain, and camouflage domain are prompted. The name is
   read with the same rules as in a deployment plan: trimmed, never blank, and only the characters
   the Panel accepts, so a rejected name costs one question instead of a finished SSH session. The
   question also holds the Panel's own node list: a name the Panel already lists is refused there
   and answered with the address of the node that holds it, because registering it again would
   rewrite that server's address and move its traffic. Only a Panel on this host is read — its API
   token is in this host's credentials file, and a remote Panel's token is not this installer's to
   hold. A remote Panel therefore prints that the name is checked when the node registers, and a
   local Panel whose list cannot be read says so and offers to read it again before the question,
   never treating an unread list as a free name.
5. **Onboarding** — The Worker is registered via the Panel API and provisioned over SSH with
   temporary key authorisation (same process as initial deployment). The registration repeats the
   name check against the live Panel, and a name held by a different address or port is refused
   before any profile, inbound or Host record exists, so a collision that appeared since the
   question costs no rollback.

## The result screen

The install does not announce completion because the Panel started. The Panel step is reported in its
own words (`Panel installed: …`), then every planned Worker is onboarded and the run ends with a
summary that states what the Panel itself holds:

```
=== Node Onboarding Summary ===
  Panel installed: https://panel.example.com
  ams-01: registered and verified in the Panel (uuid 3d5c9a71-6f24-4b8e-9c07-2a1f5e8d4b63)
  fra-01: failed (phase: scan, reason: Could not read the SSH host key of fra-01.)
  Registered and verified in the Panel: 1 of 2.
The Panel and the verified nodes stay as they are. The wizard then offers the failed nodes for a
retry, and one can also be added from the menu (option 3).
```

Each node is one of three states:

- **registered and verified in the Panel** — `node add` succeeded *and* the Panel's own `/api/nodes`
  list, read from this host with this host's token, answered with the same name, address and port, and
  its own uuid. The uuid on the screen is that answer, not a value the installer chose.
- **registered; a Panel on another host cannot confirm it from here** — `node add` succeeded but the
  Panel is remote, so no read-back is possible: its token is not this host's to hold. Nothing was
  disproved, so the node is not reported as a failure and no retry is offered for it — but an
  unconfirmed registration is not readiness either, so the run does not exit zero.
- **failed, with the stage and a reason** — the Worker's own failing stage (`prepare_key`, `scan`,
  `fingerprint`, `confirm_fingerprint`, `resolve_ip`, `pin_host_key`, `prepare_password`,
  `authorise`, `start_agent`, `add_node`, `revoke`, `stop_agent`), or the stage `verify` when the Panel
  answered and does not hold what `node add` claimed — either the name is absent
  (`the Panel's node list does not hold this node`) or it is held at another address
  (`the Panel lists it at <address>:<port>`). A failure at `add_node`, `revoke` or `stop_agent` runs
  after the registration, so the reason starts with `registered in the Panel as <uuid> at
  <address>:<port>` when the Panel holds the node: the registration and the cleanup that did not
  finish are two different facts and are reported as such.

The `Registered and verified in the Panel: N of M.` line counts only the first state. The install
exits `0` only when every node is verified and its required cleanup is verified too; a ready Panel with
any failed or unconfirmed node exits `2`, including when no node registered at all. Exit `1` belongs to
a Panel that did not deploy, which ends the run before node onboarding starts. The completion banner is
printed only for `0`.

A `verify` failure is a real failure: the Panel is the authority on what it registered, and a read-back
that contradicts `node add` means the traffic path the operator expects does not exist. A node reported
this way may still need a manual `node rollback` before it is retried.

Registration evidence has a stated limit: it proves the Panel lists the node at that name, address,
port and uuid. It does not prove that a client's traffic crossed that node — `node add` connects the
node's control plane, and the data path is proved by a client request, which the summary does not
attempt.

After a partial failure the wizard offers a retry that names only the failed nodes; a successful
sibling is not offered, and the Panel step is not repeated:

```
Some nodes failed. Select a node to retry, or skip:
  1) fra-01
  2) Skip retry for all failed nodes
Choice: 1
```

Choosing a node prints that node's read-only diagnostics — whether the recovery journal names it,
whether its SSH server answers, and whether the host already holds a managed install — and then asks
`Retry onboarding for fra-01 now? [y/N]: `. Nothing is mutated before that `y`. A confirmed retry
prints `Retrying fra-01...` and reruns the onboarding for that node alone: the Panel step and the
sibling that succeeded are not touched, and the retried node's row in the summary and in the saved
results file is the one that is replaced. The reply is `Retry succeeded: fra-01` followed by a
reprinted summary of the Panel and every node with its state, or `Retry failed: fra-01` with the stage
and reason of the new attempt. Declining answers `Retry declined, fra-01 was not touched.` and returns
to the same list. The list is printed again under the summary after every attempt and holds only the
nodes that still failed, so the numbers always name the node the next answer is about.

A node that neither record answered for is refused before the question is asked: `Refusing to retry
fra-01: neither its recovery journal nor its SSH server answered, so its state cannot be verified
from here.` Its failed attempt may have left the host half-provisioned, and rerunning the onboarding
over that is exactly what the inspection exists to prevent — finish a `node rollback` on it first.
`Skip retry for all failed nodes` prints `Retry skipped.` and leaves everything as it was.

The retry is offered after every failed batch, not only after a mixed one: the Panel is already
installed and serving, so with every node failed the alternative to a retry is a second installation
over work that succeeded. A batch whose retries all verify exits `0`; one that still has a failed node
keeps exit `2`. Declining a retry changes nothing and leaves that code where it was.

A node that failed at `revoke` or `stop_agent` was already registered by the attempt that failed, so
retrying it must not ask the Panel for a second node by the same name. The wizard reads the Panel's
node list before it onboards such a node, and when the Panel holds the planned name it keeps that
registration instead:

```
Retry kept the registration the failed attempt made: the Panel holds fra-01 at 203.0.113.7:3002
(uuid 3d5c9a71-6f24-4b8e-9c07-2a1f5e8d4b63), so the node was not registered again. Whether the
temporary key was removed cannot be checked from here, so the run stays incomplete.
```

The temporary key is bounded by its own revoke timer on the Worker, which removes it at the end of
`GOWAVE_SSH_LIFETIME_MINUTES` whether or not the panel-side revoke ran; what cannot be done from here
is confirming that it went early. The node therefore keeps its failed row and the run keeps exit `2`
— a registration is not a completed cleanup.

Menu option 3 prints its own outcome in the same vocabulary — a node addition that the Panel confirmed,
one it could not confirm, or one that failed at a named stage — and never a Panel installation
statement.

## The exit country of a node

Each traffic node is asked once, after it serves, which country its traffic leaves from:

```
Exit country check: one request from the node itself to https://ipinfo.io/country, which sees the node's address and nothing else.
Exit country of ams-01: 🇳🇱 Netherlands (NL)
Press Enter to confirm, or type a two-letter country code:
```

The request is made by the node, not by the Panel on its behalf: on the local node it leaves through
this host's own outbound route, and on a Worker it runs over the SSH session the temporary key was
already authorised for. That is why the two nodes of one deployment can be offered different
countries even when the Panel is somewhere else entirely. No name, domain, token or password is sent;
the service necessarily sees the node's source address, and that disclosure is the sentence printed
above the question. `GOWAVE_COUNTRY_LOOKUP_URL` moves the request to another service,
`GOWAVE_COUNTRY_LOOKUP_TIMEOUT` (default 5 seconds) bounds it.

Enter accepts the suggestion. A typed ISO 3166-1 alpha-2 code overrides it, in any case: `de` on a
node offered `NL` is accepted as `DE` and shown as `🇩🇪 Germany (DE)`. Only assigned codes are
countries, so `UK`, `EU` or a fragment of prose is refused with `That is not an assigned two-letter
country code; try again.` and the same question is repeated — the answer is never replaced by a
guess. The country is a label for the subscription and nothing else: no routing, firewall rule or
inbound is changed by it.

A lookup that does not answer asks for the code directly (`The country lookup did not answer for
ams-01. Enter the two-letter code of its exit country: `) instead of ending the installation. The
confirmed code is stored in the node entry of `state.json` and carried forward by a later run, so an
install that asks nothing keeps the label the operator already confirmed.

Only the interactive wizard and the add-node menu ask. A positional install — `gowave-auto.sh
install …`, a scripted run, a CI case — neither prompts nor contacts the service, and a Panel-only
host asks nothing because it runs no traffic node of its own; its Workers are asked when they are
onboarded. The plan review names the country as still to come rather than opening SSH to a server
before the operator starts the deployment.

The label is carried by the node's Host records, so changing it — a country, a node name — updates
the records the deployment already published instead of adding a second set. The deployment
recognises its own Hosts by the UUIDs it recorded in `state.json` and, for records written before it
kept them, by the profile inbound and node they belong to; a remark on its own proves nothing. A
Host it cannot claim that way stops the run and names it, and the rollback puts the previous labels
back, so a refused relabel leaves the Panel as it was.

### What a client sees

The remark of a Host record is the name a subscription shows, so the country and the node name are
in the client's proxy list: one line per enabled profile, in the same order on every node.

```
🇳🇱 VLESS · REALITY · Vision — ams-01
🇳🇱 VLESS · TLS · Vision — ams-01
🇳🇱 VLESS · XHTTP · TLS — ams-01
🇳🇱 VLESS · WebSocket · TLS — ams-01
🇳🇱 Trojan · gRPC · TLS — ams-01
```

The Vision line is the optional profile: a deployment that was not given a third domain publishes
the other four, and a node whose country was never confirmed — a positional install, a scripted run
— carries the same names without a flag rather than with a guessed one. Two nodes that exit through
one country are told apart by the last part of the line, which is the node's name and nothing else.

Only the label changes with either of them. The address a client dials, the SNI it presents, the
ALPN it offers, the transport path and the protocol settings are the same records as before, and
the deployment updates the Host it already owns. The Panel names the proxy in both the Xray JSON and
the Mihomo YAML from that remark and lists the same names in the proxy group, so a client that had
selected a proxy may need to reselect it once after the labels change and a refresh.

## Edge access log / Журнал соединений на краю

The port-443 stream router writes one line per connection to
`/var/log/nginx/gowave-edge-access.log` on the Master and on every Worker:

```
panel.testbed.internal TLSv1.3 203.0.113.7 443 2026-11-27T13:45:01+00:00
```

SNI, negotiated protocol, client address, local port, time. This is the file to
read when a client reports "the node does not answer": if the line is there, the
connection reached that host under that name and the fault is behind the edge; if
it is absent, the client never arrived — check DNS, the provider firewall and the
port. The Panel and the transport locations stay unlogged, so a line means an
edge connection, not a proxied request. The file records client addresses; it is
rotated by the `gowave-*.log` rule.

`tail -f /var/log/nginx/gowave-edge-access.log` while the client retries is the
fastest way to tell "wrong node" from "no connection".

## Temporary SSH access for remote nodes

The wizard authorises an Ed25519 key on a Worker only after the operator types the Worker's host-key
fingerprint in full. The flow prints the fingerprint the Worker presents, then asks for it, so the operator
confirms that value against the one the provider's console shows; the question and the password prompt are
written to the terminal, not to the captured diagnostic stream. Two variables provide the non-interactive
inputs:

- `GOWAVE_SSH_FINGERPRINT` — the SHA-256 fingerprint the operator read from the Worker. It must equal the
  key the Worker presents; a mismatch refuses the onboarding before `authorized_keys` is touched.
- `GOWAVE_SSH_PASSWORD_FILE` — a file containing the SSH password, mode `0600`. A file with any other mode
  is refused. The password is read once, written into the private key directory, and never placed in a
  command line: `ssh` reads it through an `SSH_ASKPASS` helper.

```bash
sudo GOWAVE_SSH_FINGERPRINT='SHA256:...' \
     GOWAVE_SSH_PASSWORD_FILE=/root/worker-password.txt \
     ./gowave-auto.sh install
```

The plan questions still come from the terminal; the two variables replace only the SSH prompts of the
onboarding step. The wizard reads them around the `node add` it runs, so the operator is asked once per
Worker.

A systemd timer on the Worker removes the temporary entry within two hours, and the entry is also revoked
at the end of `node add` on success and on failure.

After country entry, the wizard announces Panel registration, SSH deployment, hardening, ACME
and NGINX, service and security verification, and temporary-access cleanup. The remote deployment
SSH session has a 60-minute budget. During a silent interval, the terminal reports the last known
stage after a minute, at most 59 times for that session. If the budget expires, the installer reports
the timeout and attempts recovery. A disconnected SSH session does not prove that the Worker stopped
or rolled back. Inspect the transaction journal before retrying. A registration in the Panel does
not by itself prove that traffic reaches the Worker or that its security controls are effective.

Each onboarding and Worker stage has a finite timeout budget. If a stage exceeds its budget,
the operator sees a timeout notice naming the stage, the host, elapsed seconds and the budget.
Budgets (minutes): `prepare_key` 2, `scan` 2, `fingerprint` 1, `confirm_fingerprint` 5,
`resolve_ip` 2, `pin_host_key` 1, `prepare_password` 3, `authorise` 3, `start_agent` 2,
`country` 3, `registration` 2, `add_node` 3, `deployment` 60, `hardening` 10, `acme` 15,
`verification` 5, `revoke` 2, `stop_agent` 1. Timeout attribution survives SSH disconnects —
the final check runs when the session ends so the operator always sees which stage overran.

После выбора страны мастер сообщает о регистрации в панели, удалённом развёртывании, настройке
защиты, выпуске сертификатов и настройке NGINX, проверке служб и защиты, а также об отзыве временного
доступа. SSH-сеанс развёртывания ограничен 60 минутами. Если Worker минуту не выдаёт новых строк,
терминал показывает последний известный этап — не более 59 таких сообщений за сеанс. По истечении
лимита установщик сообщает об этом и пытается выполнить восстановление. Разрыв SSH не доказывает,
что Worker остановился или откатился. Перед повтором проверьте журнал транзакции. Регистрация в панели
сама по себе не доказывает, что Worker принимает трафик или что его настройки защиты действуют.

Каждый этап подключения и этап Worker имеет фиксированный бюджет таймаута. Если этап превышает
свой бюджет, оператор видит уведомление с именем этапа, хостом, затраченными секундами и бюджетом.
Бюджеты (минуты): `prepare_key` 2, `scan` 2, `fingerprint` 1, `confirm_fingerprint` 5,
`resolve_ip` 2, `pin_host_key` 1, `prepare_password` 3, `authorise` 3, `start_agent` 2,
`country` 3, `registration` 2, `add_node` 3, `deployment` 60, `hardening` 10, `acme` 15,
`verification` 5, `revoke` 2, `stop_agent` 1. Атрибуция таймаутов сохраняется при разрыве SSH —
финальная проверка запускается при завершении сессии, поэтому оператор всегда видит, какой этап
превысил лимит.

## Deployment persistence and security-report formats / Форматы состояния и отчёта

The security report is written by every role this installer hardens. An All-in-One or Panel-only
installation writes it after the firewall has been applied and read back; a Worker writes it after its
own ingress, SSH jail, update schedule and resolver have been verified. The helper re-reads every
control — the live ruleset, the SSH jail, the update schedule and the resolver — and writes
`/var/lib/gowave-auto-nginx/security-report.json` atomically, so the file describes the host at the end
of hardening rather than restating what an earlier step printed. A report that cannot be produced, or
whose verdict is `failed`, stops the installation.

After a successful multi-node deployment, the Master aggregates all Worker reports into
`/var/lib/gowave-auto-nginx/security-report-aggregate.json`. The aggregate contains the Master's own
report under `master` and one entry per Worker under `workers`, keyed by the planned host name. A
Worker whose report could not be fetched or is invalid is recorded with `status: "fetch_failed"` or
`"invalid"` so the operator sees the gap. The aggregate is written atomically (tmp → sync → rename
→ sync) at mode 0600 and is produced only after all requested Workers have been onboarded.

A Worker derives its ingress from the same helper as the Master: the rules are the role policy, not a
hand-written set, so a Worker that would expose an internal port or an unrestricted Node API port is
refused by the preflight before the first rule changes instead of passing as hardened.

The setup wizard saves accepted answers and offers three actions when it finds a compatible draft:

1. **Continue** restores the answers, asks for missing fields, and shows the plan for review before changes. You can edit pending work, but you cannot change the identity of a completed component or remove a Worker whose registration was already recorded. Use a separate migration for identity changes. An unfinished transaction blocks deployment until recovery is complete.
2. **Start over** discards the draft before collecting new answers. It does not uninstall or roll back anything the previous run deployed.
3. **Leave without installing** keeps the draft for another run and makes no deployment changes.

For a plan started in the wizard, exit `0` means all requested components were confirmed. Exit `1` means the Panel could not be deployed or verified, or a pre-deployment check blocked the run. Exit `2` means the Panel is ready but at least one requested Worker remains failed or unconfirmed. Inspect the per-Worker result before retrying: an existing registration with unfinished cleanup is not a reason to register the Worker again.

A recorded Worker is checked against its registered UUID, profile and Host associations, then against its public TLS listeners and effective security controls. The security check needs existing non-interactive root SSH access with a trusted host key (`GOWAVE_SSH_PORT`, default `22`); it does not install another temporary key. If access or a check fails, the Worker stays unconfirmed and is not rebuilt. Check the affected Worker before resuming. A previous best-effort DNS recovery verdict is not reused as evidence of current readiness.

Отчёт защиты записывает каждая роль, которую этот установщик защищает. Установка All-in-One или
Panel-only пишет его после того, как файрвол применён и прочитан обратно; воркер — после проверки
своего входящего трафика, jail SSH, расписания обновлений и резолвера. Хелпер заново читает каждый
контроль — действующий набор правил, jail SSH, расписание обновлений и резолвер — и атомарно пишет
`/var/lib/gowave-auto-nginx/security-report.json`, так что файл описывает хост в конце настройки защиты,
а не пересказывает вывод предыдущего шага. Если отчёт не удалось создать или его вердикт `failed`,
установка останавливается.

После успешного развёртывания в режиме multi-node мастер агрегирует все отчёты Worker'ов в
`/var/lib/gowave-auto-nginx/security-report-aggregate.json`. Агрегат содержит собственный отчёт
мастера под `master` и по одной записи на Worker под `workers`, ключ — запланированное имя хоста.
Worker, чей отчёт не удалось получить или он невалиден, записывается со статусом `fetch_failed`
или `invalid`, чтобы оператор увидел пробел. Агрегат пишется атомарно (tmp → sync → rename → sync)
с правом 0600 и создаётся только после того, как все запрошенные Worker'ы подключены.

Воркер выводит входящий трафик тем же хелпером, что и Master: правила — это ролевая политика, а не
написанный вручную набор, поэтому воркер, который открыл бы внутренний порт или Node API без
ограничения источника, отклоняется префлайтом до изменения первого правила, а не проходит как
защищённый.

Мастер сохраняет принятые ответы и предлагает три действия, если найдёт совместимый черновик:

1. **Продолжить** — восстановить ответы, заполнить пропуски и проверить план до внесения изменений. Можно править ещё не выполненную часть плана, но нельзя менять идентичность готового компонента или исключать Worker, регистрация которого уже записана. Для смены идентичности нужна отдельная миграция. Если прежняя транзакция не завершена, сначала нужно закончить восстановление.
2. **Начать заново** — удалить черновик перед сбором новых ответов. Уже развёрнутые компоненты не удаляются и не откатываются.
3. **Выйти без установки** — оставить черновик для следующего запуска и ничего не менять в развёртывании.

Для плана, запущенного из мастера, код `0` означает, что все запрошенные компоненты подтверждены. Код `1` означает, что панель не удалось развернуть или подтвердить либо проверка остановила запуск до установки. Код `2` означает, что панель готова, но как минимум один запрошенный Worker завершился с ошибкой или не подтверждён. Перед повтором проверьте итог по конкретному Worker: незавершённая очистка после регистрации не повод регистрировать узел повторно.

Для записанного в черновике Worker мастер сверяет UUID, профиль и привязки Host-записей, затем проверяет публичные TLS-слушатели и действующие настройки безопасности. Для проверки настроек нужен уже настроенный неинтерактивный SSH-доступ от root с доверенным ключом хоста (`GOWAVE_SSH_PORT`, по умолчанию `22`); новый временный ключ не устанавливается. Если доступ или одна из проверок не сработали, Worker остаётся неподтверждённым, а мастер не развёртывает его повторно. Проверьте этот Worker перед продолжением. Старый результат восстановления DNS при `best-effort` не считается подтверждением текущей готовности.

| File / Файл | Format / Формат | Access / Доступ |
| --- | --- | --- |
| `/var/lib/gowave-auto-nginx/deployment/active.json` | Deployment schema 1 / Схема развёртывания 1 | Root-owned directory 0700, file 0600 / Каталог root 0700, файл 0600 |
| `/var/lib/gowave-auto-nginx/security-report.json` | Security schema 1 / Схема защиты 1 | File 0600; root-owned parent without group/world-write, existing 0755 preserved / Файл 0600; родитель root без записи для группы и остальных, существующий 0755 сохраняется |
| `/var/lib/gowave-auto-nginx/security-report-aggregate.json` | Aggregate schema 1 / Схема агрегата 1 | File 0600; root-owned parent, same as per-host / Файл 0600; родитель root, как у хостового отчёта |

New directories use 0700. The shared report parent is not chmodded: this preserves existing state/recovery
consumers. Its file names may be visible, but report contents remain root-only. Writable parents, even
with a sticky bit, are refused; the dedicated draft directory always requires 0700.

Новые каталоги создаются с 0700. Права общего родителя отчёта не меняются, чтобы не затрагивать
потребителей state/recovery. Имена файлов могут быть видны, но содержимое отчёта доступно только root.
Каталог с записью для группы или остальных отклоняется даже со sticky bit; отдельный каталог черновика
всегда требует 0700.

Deployment fields are `schema_version`, `revision`, `installer_revision`, `operation_id`, `kind`,
`topology`, `language`, `answers`, `nodes`, `reviewed_digest` and `checkpoints`. The digest authorizes
only the reviewed plan, not changed answers. Each write uses an expected revision and a non-blocking
writer lock; stale revisions and a different active operation are refused. Files are written to private
siblings, synced, atomically renamed and followed by a directory sync. Symlinks and non-regular files
are refused. Passwords, tokens, private keys, temporary access and raw logs have no schema fields.

Поля черновика перечислены выше без перевода, как в JSON. `reviewed_digest` относится только к
проверенному плану; изменение ответов требует нового подтверждения. Запись проверяет ожидаемую
ревизию и блокировку: устаревшая ревизия или другая активная операция отклоняется. Запись идёт через
временный файл с синхронизацией, атомарным переименованием и синхронизацией каталога. Символические
ссылки и специальные файлы отклоняются. Полей для паролей, токенов, приватных ключей, временного
доступа и сырых логов в схеме нет.

Security fields are `schema_version`, `host_id`, `role`, `installer_revision`, `observed_at` and
`controls`. Required control names are `firewall`, `ssh_protection`, `security_updates` and `dot`.
Each control has `policy`, `status`, `reason_code`, `recovery` and `evidence_codes`. Reasons/evidence
are codes, not captured command output. Default freshness is 300 seconds; future or older reports
are rejected for readiness. Stale reports may remain historical files but are not current evidence.
A failed required control blocks readiness; best-effort DoT failure permits warnings only after
verified DNS recovery. Registration, readiness, cleanup and recovery remain separate final outcomes.

Отчёт защиты содержит указанные поля и четыре контроля. Причины и доказательства записываются кодами,
не выводом команд. По умолчанию отчёт пригоден для проверки готовности в течение 300 секунд; будущая
дата и более старый отчёт отклоняются. Старый файл может остаться историей, но не доказывает текущее
состояние. Ошибка обязательного контроля блокирует готовность. Ошибка необязательного DoT допускает
продолжение с предупреждением только после проверенного восстановления DNS. Регистрация, готовность,
очистка доступа и восстановление учитываются отдельно.

Files have no automatic expiry or deletion in the storage layer. Retain a failed operation until its
actual state is reconciled; a stored success is not permission to skip readback. Abandoning a draft
must never uninstall components or compensate completed nodes. The storage layer intentionally does
not implement abandonment, resource rollback or automatic switching to a new operation; those are
orchestration responsibilities. Do not delete an active file to bypass a writer conflict.

Слой хранения сам не удаляет и не просрочивает файлы. Сохраняйте неуспешную операцию до сверки с
реальным состоянием; сохранённый успех не заменяет повторную проверку. Отказ от черновика не должен
удалять компоненты или откатывать готовые узлы. Отказ, rollback ресурсов и переход к новой операции
пока не реализованы в слое хранения: это задачи оркестратора. Не удаляйте активный файл ради обхода
конфликта записи.

### What the report proves / Что отчёт доказывает

`ready` means every control was read back as effective at `observed_at`. `ready-with-warnings` means an
optional control could not be applied and the host was left working: DoT is reported `failed` with
`recovery` `verified`, and the host is not described as fully hardened. `failed` means a required
control, or DoT asked as `required`, was not effective — or a rollback was not proven, which is
`recovery` `unknown` or `failed`. Readiness is blocked in that case.

`ready` означает, что каждый контроль прочитан обратно как действующий на момент `observed_at`.
`ready-with-warnings` — необязательный контроль применить не удалось, но хост остался рабочим: DoT
записан как `failed` с `recovery` `verified`, и хост не называется полностью защищённым. `failed` —
обязательный контроль или DoT в режиме `required` не действует, либо откат не доказан (`recovery`
`unknown` или `failed`). В этом случае готовность блокируется.

Control and recovery are never merged. `verified` is reserved for a control that needed no recovery;
a failed control that was put back stays `failed` and says `recovery` `verified`, and a control that
could not be read at all is `failed` with `recovery` `unknown`. `skipped` is the honest status of a
policy that writes nothing — `off` is `skipped`, never `verified`. `unsupported` marks a control this
host cannot run; it is never a pass, and a required `unsupported` control blocks readiness.

Контроль и восстановление не сливаются. `verified` зарезервирован за контролем, которому не требовался
откат; неуспешный контроль, который вернули, остаётся `failed` и указывает `recovery` `verified`, а
контроль, который вообще не удалось прочитать, — `failed` с `recovery` `unknown`. `skipped` — честный
статус политики, которая ничего не пишет: `off` это `skipped`, а не `verified`. `unsupported` отмечает
контроль, который на этом хосте выполнить нельзя; это не успех, и обязательный `unsupported` блокирует
готовность.

Preserved APT origins are proven by the configuration step, which reads the schedule before the managed
policy is written. The report re-verifies that the required security origin is effective and that the
periodic schedule and timers are enabled; it does not claim a preservation it did not witness. The same
limit applies to DoT: the `dot` control covers the system resolver only, applications that speak DNS
themselves bypass it, DNSSEC validation is a separate control this policy does not enable, and neither
DoT nor the firewall promises DPI invisibility or upstream DDoS protection.

Сохранение исходных origin APT доказывает шаг настройки: он читает расписание до записи управляемой
политики. Отчёт заново проверяет, что обязательный origin безопасности действует, а периодическое
расписание и таймеры включены, но не заявляет о сохранении, свидетелем которого не был. То же
ограничение у DoT: контроль `dot` охватывает только системный резолвер, приложения со своим DNS его
обходят, проверка DNSSEC — отдельный контроль, который эта политика не включает, и ни DoT, ни файрвол
не обещают невидимости для DPI или защиты от DDoS на стороне провайдера.

## Node API ingress and firewall recovery / Входящий доступ к Node API и восстановление файрвола

UFW is the only firewall this installer manages, and it refuses to change one it could not put back.
A host with `firewalld` or `nftables` active is rejected before any mutation, because two managers
writing the same tables leave no state that can be named or restored. The rendered policy is a role
matrix: every SSH port discovered from sshd and its socket (normally `22`), plus `80` and `443`, stays
open to every source; the internal listeners `3000`, `3001`, `7443`, `8443`, `8444`, `9443`, `9444`,
`10001`, `10002` and `10003` are denied to every source; and the Node API port depends on the role.

UFW — единственный файрвол, которым управляет установщик, и он отказывается менять тот, который не
сможет вернуть. Хост с активными `firewalld` или `nftables` отклоняется до любых изменений: два
менеджера на одних таблицах не оставляют состояния, которое можно назвать и восстановить.
Отрисованная политика — матрица ролей: каждый найденный порт SSH (из sshd и его сокета, обычно `22`),
а также `80` и `443` открыты любому источнику; внутренние слушатели `3000`, `3001`, `7443`, `8443`,
`8444`, `9443`, `9444`, `10001`, `10002` и `10003` закрыты для всех; порт Node API зависит от роли.

| Role / Роль | Node API | Rule / Правило | Verdict / Вердикт |
| --- | --- | --- | --- |
| `aio` | `3002`, the only port this role installs / единственный порт этой роли | source-independent deny, no public allow / deny независимо от источника, публичного allow нет | `denied-to-every-source` |
| `worker` | the port `node add` returned, `3002` by default / порт, который вернул `node add`, по умолчанию `3002` | allow from the Master's single addresses, then deny the same port to everyone / allow с одиночных адресов Master, затем deny того же порта всем | `allowed-only-from-the-master` |
| `panel-only` | none: no Node and no listener / нет: узла и слушателя нет | no rule and no listener / ни правила, ни слушателя | `no-rule-and-no-listener` |

A Worker registered on a non-default port gets the same protection: the acceptance case asks the
shipped renderer for `3302`, a port the install never uses, and requires the answer to differ in the
port number and in nothing else. On a Panel-only host both answers name no Node port at all. The
All-in-One role reads only `3002`, because `install_local_node` hardwires it; a non-default port has
no installed counterpart there, and the case says so instead of inventing one.

Воркер, зарегистрированный не на стандартном порту, получает ту же защиту: приёмочный кейс
запрашивает у отгруженного рендерера `3302` — порт, который установка не использует, — и требует,
чтобы ответ отличался номером порта и ничем больше. На Panel-only оба ответа не содержат порта Node
вовсе. Роль All-in-One читает только `3002`, потому что `install_local_node` жёстко его задаёт: у
нестандартного порта там нет установленного двойника, и кейс это называет, а не выдумывает.

### Conflicts and preserved exceptions / Конфликты и сохранённые исключения

Before any mutation the preflight reads the persisted `/etc/ufw/user.rules` and `user6.rules` and
classifies them. An ACCEPT rule that reaches a protected port from a broad, range or single-port
source is refused unless it is exactly the Worker's allow from its own Master; a rule shape this
installer does not model is refused rather than guessed at, as is a symlinked rules file. Remediate by
scoping the rule to the source that needs it, removing it, or stopping the competing manager — not by
disabling UFW and not by widening a managed rule. Allows outside the managed ports, and allows for
protocols other than TCP, are kept and reported as `preserved_exceptions`; the SSH and web allows this
installer wrote itself are not reported back to the operator on a rerun.

До любых изменений preflight читает сохранённые `/etc/ufw/user.rules` и `user6.rules` и
классифицирует их. Правило ACCEPT, открывающее защищённый порт широкому, диапазонному или одиночному
источнику, отклоняется, кроме ровно того allow воркера с его Master; форма правила, которую установщик
не моделирует, отклоняется, а не угадывается, как и файл правил, являющийся символической ссылкой.
Лечится это сужением правила до нужного источника, его удалением или остановкой конкурирующего
менеджера — не отключением UFW и не расширением управляемого правила. Allow вне управляемых портов и
allow для протоколов кроме TCP сохраняются и попадают в отчёт как `preserved_exceptions`; правила SSH
и веб-портов, которые установщик написал сам, на повторном запуске оператору не выдаются.

`ufw status` saying `active` is not evidence that the policy landed: after applying, the installer
reads the live ruleset back on both families and compares it with the policy the preflight approved.
A host where only one family is checked is a host whose second family is unknown.

`active` в выводе `ufw status` не доказывает, что политика применилась: после применения установщик
перечитывает действующий набор правил в обоих семействах и сравнивает его с политикой, одобренной
preflight. Хост, у которого проверено только одно семейство, — это хост, второе семейство которого
неизвестно.

### Recovery route / Маршрут восстановления

The baseline is captured to
`/var/lib/gowave-auto-nginx/recovery/<transaction>/firewall-before-image` before the first mutation.
If the capture fails, the run stops with the firewall untouched: it will not change a firewall it
cannot save. A later failure gets exactly one restore attempt, followed by a read-back; a failed
restore keeps the image and prints a `CRITICAL` line naming the step that failed, so the operator
restores by hand instead of re-running over an unknown state. A verified install removes the image:
its absence is the record that nothing is pending.

Базовый снимок сохраняется в
`/var/lib/gowave-auto-nginx/recovery/<transaction>/firewall-before-image` до первого изменения. Если
снимок не удался, запуск останавливается, не трогая файрвол: установщик не меняет то, что не сможет
сохранить. При последующей ошибке делается ровно одна попытка восстановления с последующим
перечитыванием; неудачное восстановление сохраняет снимок и печатает строку `CRITICAL` с названием
сбойного шага, чтобы оператор восстановил вручную, а не перезапускал установку поверх неизвестного
состояния. Проверенная установка удаляет снимок: его отсутствие и есть запись о том, что ничего не
висит.

The matrix above is enforced by `FW-05` (All-in-One), `FW-06` (Worker) and `PO-FIREWALL` (Panel-only)
in the disposable Podman suite. They read the applied rules, the declared policy for the installed and
for a non-default port, the discovered SSH ports, and the rules again after `systemctl restart
ufw.service`, the unit a boot runs. Container acceptance proves the host rule set; it does not prove
the provider firewall or a real internet path, which remain live-host checks.

Матрицу выше проверяют `FW-05` (All-in-One), `FW-06` (Воркер) и `PO-FIREWALL` (Panel-only) в
одноразовом наборе Podman. Они читают применённые правила, объявленную политику для установленного и
для нестандартного порта, найденные порты SSH и правила снова после `systemctl restart ufw.service`,
той самой службы, которую запускает загрузка. Приёмка в контейнере доказывает набор правил хоста, но
не файрвол провайдера и не реальный интернет-путь: это остаётся проверкой на живом хосте.

## Non-interactive answers

`GOWAVE_WIZARD_LANG=ru` or `en` selects the wizard's message catalog. It is read per invocation and is
never written to `state.json`, because the language is not installation state. Unknown values fall back
to English.

## DNS-over-TLS policy / Политика DNS-over-TLS

Both roles run one control through `assets/security/managed.py`, and the policy is selected with the
`GOWAVE_DOT_POLICY` environment variable. It is an environment variable rather than a positional
argument so the command line keeps its shape, a rerun reads the same value, and the streamed Worker
payload receives it without a new flag. The default is `best-effort`.

| `GOWAVE_DOT_POLICY` | Managed drop-in | Verified state | When it fails |
| --- | --- | --- | --- |
| `best-effort` (default) | `DNSOverTLS=opportunistic` in `/etc/systemd/resolved.conf.d/90-gowave-auto-nginx.conf` | the opportunistic mode is read back and uncached queries resolve | restore the original files and service state, verify resolution, then continue with the control reported as failed |
| `required` | `DNSOverTLS=yes` in the same file | the strict mode is read back and uncached queries resolve | stop the host |
| `off` | no document this installer owns; a drop-in an earlier run wrote is removed | resolution alone is verified, and no mode is claimed | stop the host |

Continuation is allowed only when the rollback is verified: the original resolver files and
`systemd-resolved` state came back and a query resolves. An unverified restoration stops the deployment
in every mode, and `required` stops even after a verified one. The control and the recovery are
reported as separate facts, so a host that continued after a `best-effort` failure is never called
fully hardened.

Обе роли выполняют один и тот же шаг через `assets/security/managed.py`, а политика выбирается
переменной окружения `GOWAVE_DOT_POLICY`. Переменная, а не позиционный аргумент: командная строка
сохраняет свою форму, повторный запуск читает то же значение, а потоковый payload воркера получает
его без нового флага. По умолчанию — `best-effort`.

| `GOWAVE_DOT_POLICY` | Управляемый drop-in | Проверенное состояние | При сбое |
| --- | --- | --- | --- |
| `best-effort` (по умолчанию) | `DNSOverTLS=opportunistic` в `/etc/systemd/resolved.conf.d/90-gowave-auto-nginx.conf` | режим opportunistic читается обратно, запросы без кэша разрешаются | вернуть исходные файлы и состояние службы, проверить разрешение имён и продолжить, отчитавшись о сбое контроля |
| `required` | `DNSOverTLS=yes` в том же файле | строгий режим читается обратно, запросы без кэша разрешаются | остановить хост |
| `off` | ни одного документа, которым владеет установщик; drop-in прошлого запуска удаляется | проверяется только разрешение имён, режим не заявляется | остановить хост |

Продолжать можно только при проверенном откате: исходные файлы резолвера и состояние
`systemd-resolved` вернулись, а запрос разрешается. Непроверенное восстановление останавливает
установку в любом режиме, а `required` — даже после проверенного. Контроль и восстановление
отчитываются раздельно, поэтому хост, продолживший после сбоя `best-effort`, никогда не называется
полностью защищённым.

Three limits are part of the choice and not footnotes. The control covers the global
`systemd-resolved` resolver only: a link or VPN DNS route and an application with its own resolver
bypass it, so `resolvectl status` is worth reading after the install. It is not DNSSEC, which is a
separate chain of trust. And it is not invisibility: encrypted DNS over TCP/853 is not proof that DPI
or an upstream flood cannot see the host. On a rerun over the already installed package the same files
are rewritten and read back, so the policy can be changed without uninstalling anything.

Три ограничения входят в сам выбор, а не в сноски. Контроль охватывает только глобальный резолвер
`systemd-resolved`: DNS-маршрут link или VPN и приложение со своим резолвером его обходят, поэтому
после установки стоит посмотреть `resolvectl status`. Это не DNSSEC — у него своя цепочка доверия. И
это не невидимость: шифрованный DNS по TCP/853 не доказывает, что DPI или апстрим-флуд не видят хост.
На повторном запуске поверх уже установленного пакета те же файлы перезаписываются и читаются
обратно, поэтому политику можно сменить, ничего не удаляя.

## Domain and certificate policy

The preflight counts `C = 2 + v_panel + 2N + k` certificates, where `v_panel` is 1 when the Panel host has
Vision, `N` is the number of Workers, and `k` is the number of Workers with Vision. The 50-per-7-days
Let's Encrypt limit for a registered domain yields four node ceilings:

| Vision placement | Ceiling under one registered domain |
| --- | --- |
| None | 24 nodes |
| Panel host only | 23 nodes |
| Everywhere, Panel-only Panel | 16 nodes |
| Everywhere, Panel and one node on this host | 15 nodes |

Separate registered domains proceed without a question because each host spends its own budget. A shared
domain within the ceiling proceeds only after an explicit confirmation that names the count and the
ceiling; above the ceiling the plan is refused and one registered domain per host is recommended.

Three limits are stated rather than worked around:

1. **The remaining budget cannot be queried.** Let's Encrypt exposes no endpoint for it, so the preflight
   counts only the plan in front of it.
2. **The apex and `www` camouflage certificate belongs to a single host.** A second host on the same apex
   cannot serve that website; it can only run a decoy at its own subdomain.
3. **Wildcard is not a remedy for a shared domain.** Every host would order the identical
   `[domain, *.domain]` set, and the five-per-exact-set limit caps a shared-domain cluster at about five
   hosts per week.

**The Master cover apex is selected, never derived.** The plan asks for it as an owned name
(`GOWAVE_COVER_DOMAIN` for a positional install) and offers `www.<apex>` as a second name only when the
operator asks for it (`GOWAVE_COVER_WWW=yes`, default `no`). A value that is not a fully qualified name,
a name that repeats the Panel domain, or a name that does not resolve to this host — over IPv4 and, on
a dual-stack host, over AAAA — disables the cover with a message naming the record to fix; it is not
replaced by a suffix guess. A plan with no cover apex serves no cover site and spends no certificate
name on one. The old last-two-label derivation survives only to read a pre-existing installation, and
nothing new is decided from it. A Worker has no apex at all: it serves the camouflage site under its
own camouflage name, which is also its REALITY SNI, so it takes neither the Master's apex nor a
derived one.

DNS-to-host examples:

| Topology | Records | Ownership |
| --- | --- | --- |
| Master with cover in its own zone | `panel.example.com`, `cover.example.com`, `example.com`, optional `www.example.com` → `203.0.113.10` | The Master owns the apex pair and its Panel names |
| Worker in the Master's zone | `node1.example.com`, `cover1.example.com`, `vision1.example.com` → `203.0.113.20` | The Worker issues only its own names; the apex and `www` stay on the Master |
| Worker in its own zone | `node2.example.net`, `cover2.example.net` → `203.0.113.30` | The Worker owns its primary and camouflage names, not `example.net` or another zone's apex |

Never move the Master apex or its `www` to a Worker: two hosts cannot validate the same HTTP-01
names, and the certificate would be issued on the wrong machine.

## DNS preflight

Every planned name must resolve before the first ACME order. The check runs before any host is modified
and names the names that do not resolve. `GOWAVE_WIZARD_RESOLVER` overrides the resolver command (default
`getent`) for test harnesses.
