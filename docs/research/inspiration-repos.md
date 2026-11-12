# Каталог внешних репозиториев для вдохновения

Ветка: `research/inspiration-scan` (от `feature/podman-full-e2e`), 2026-11-12.

**Статус:** разбор завершён. Семь репозиториев склонированы в `/tmp/inspiration/`, прочитан код
(не только README), сырые отчёты лежат в `/tmp/inspiration/reports/`. Ни один внешний установщик
не запускался, рабочее дерево GoWave не изменялось.

Назначение: зафиксировать идеи, пригодные для GoWave Auto NGINX, и отделить их от того, что
копировать нельзя. Внедрение — только после того, как e2e- и podman-тесты дописаны, закоммичены и
дают стабильный прогон; дальше — изменения с постоянными прогонами.

## Критерии отбора

Приоритеты проекта, в порядке убывания:

1. **Ресурсы** — минимум RAM/CPU/диска; целевой VPS 1 GB RAM, без Docker.
2. **Скрытность** — устойчивость к активному пробингу, обнаружению и блокировкам.
3. **Стабильность** — предсказуемое восстановление, идемпотентность, отсутствие «тихих» поломок.
4. **Удобство** — простая эксплуатация, понятные команды, минимум ручных шагов.

Ограничения: наш стек — bash + systemd + upstream-бинарники; 443 принадлежит NGINX Stream
(`ssl_preread` SNI: REALITY → loopback Xray, остальное → статический decoy). Мы не переходим на
Docker Compose и не модифицируем upstream GoWave/GoWave Node.

Обозначения сложности: **S** ≤ полдня, **M** 1–3 дня, **L** > 3 дней. Приоритеты: **P0** — дефект или
утечка, чинить при следующем касании; **P1** — следующий релиз; **P2** — бэклог; **P3** — знать.

## Сводка

| # | Репозиторий | Лицензия | Что это | Главная ценность для нас | Брать |
|---|-------------|----------|---------|--------------------------|-------|
| 1 | [getmeridian/meridian](https://github.com/getmeridian/meridian) | MIT | Python CLI-флот: nginx SNI + Xray + своя панель + агент | `plan`/`apply` с хешем плана, вынос `default` SNI из Xray, probe-ресурсы, машинный режим | 6 идей P1 |
| 2 | [DigneZzZ/remnawave-scripts](https://github.com/DigneZzZ/remnawave-scripts) | MIT | Три bash-монолита с Docker Compose | Guarded write против затирания конфигов, baseline-проба после reload, зеркала, retention | 6 идей P1 |
| 3 | [eGamesAPI/remnawave-reverse-proxy](https://github.com/eGamesAPI/remnawave-reverse-proxy) | MIT | Bash + NGINX/Xray + SelfSteal | Гигиена панели и decoy, UDS-fallback, сертификаты, UFW с маркером владения | 8 идей P1 |
| 4 | [Capybara-z/RemnaSetup](https://github.com/Capybara-z/RemnaSetup) | MIT | Bash env-матрица + Docker Compose | Контракт неинтерактивного ввода, DNS-01 wildcard, offsite-бэкап | 3 контракта |
| 5 | [Case211/remnawave-admin](https://github.com/Case211/remnawave-admin) | AGPL-3.0 | Панель + node-agent + анти-абуз | UA-классификация, торрент-тег, procfs-метрики, trusted-proxy | 9 идей P1/P2 |
| 6 | [remnawave/subscription-page](https://github.com/remnawave/subscription-page) | AGPL-3.0 | Node/NestJS-обёртка страницы подписки | Гигиена подписки: robots, глухие ошибки, обязательный UA | 4 идеи P0 |
| 7 | [iphizic/remna-playbook](https://github.com/iphizic/remna-playbook) | не указана | Ansible-обвязка без самой установки | Negative-ценность: как разваливается идемпотентность и текут секреты | 3 практики P1 |

Отброшены: **AsanFillter/Remnawave-AutoSetup** (README прямо запрещает production, дублирует
сценарии 2–4), **distillium/remnawave-backup-restore** (у нас формат v1 сильнее),
**warp-native / netbird / terraform-provider-remnawave** (не наш сценарий).

---

## 1. Meridian — ближайший архитектурный аналог

**Паспорт.** MIT, Python 3.11 (CLI, control service, панель) + Rust (агент ноды), версия `4.0.0b13`,
~160k строк Python и ~8.5k Rust, тег `v4.0.0b13` от 2026-11-05. Есть контракты в
`contracts/meridian/v1/`, ~350 pytest-файлов, Playwright e2e, CI на реальных VM. `plan`/`apply`
помечены `stability: preview`.

**Архитектура.** Флот живёт на машине оператора (`~/.config/meridian/cluster.yml`); на серверах
состояния флота нет. `compile_topology()` собирает граф ресурсов с `desired_hash`, зависимостями и
postconditions. `plan` только наблюдает и выходит с кодом 2 при расхождениях; `apply` идёт в
топологическом порядке с чекпоинтом на шаг. Взаимоисключение — lease на 30 минут с `fleet_id`,
`generation`, `plan_hash`. Инфраструктура ставится push по SSH, рантайм (Xray-конфиг, пользователи)
— pull-агентом с long-poll. 443 — тот же `ssl_preread`-роутинг, что у нас.

**Что брать.**

| Идея | Доказательство | Что улучшит | P | Сл. |
|------|----------------|-------------|---|-----|
| `apply` принимает `expected_plan_hash` и отказывается применять пересчитанный план | `setup/runtime.py:202-214` | Утверждённый план нельзя подменить между review и запуском | P1 | M |
| `plan` — read-only, exit 2 = «есть изменения» | `commands.json:3565-3630` | `--check` для CI и e2e без мутаций | P1 | S |
| Чекпоинт на шаг со статусом `unknown`, наблюдение перед повтором, бюджет попыток | `resource_executor.py:80,403-410` | Лечит оборванный `node add`/update и залипший lock | P1 | M |
| Lease-fence (`generation` + `plan_hash`) вместо простого mutation-lock | `reconciler/fence.py:22,85` | Lock не залипает навсегда; два оператора безопасны | P1 | M |
| Probe-ресурсы в плане (`node/listener/subscription`) с postcondition | `compiler/probes.py:8-52` | Сходимость доказана, а не заявлена | P1 | M |
| Типизированные `VerificationCheck` (passed/failed/warning/skipped + remediation, коды 0/3/4) | `core/verification.py:1-60` | Один `verify` для человека и CI | P1 | M |
| Машинный режим: JSON в stdout, лог в stderr, `--events=jsonl`, схемы в `contracts/` + CI-сверка | `core/events.py:7-21` | Стабильный интерфейс, автоловля дрейфа документации | P1 | M |
| `default` SNI увести из Xray (реальный dest или `127.0.0.1:9`), плюс `proxy_socket_keepalive on` | `provision/nginx_render.py:36-60,88-110` | Снимает differential и нагрузку проб с Xray на 1 GB | P1 | S |
| Stock-тела 403/404 и `access_log off` на путях с токенами | `nginx_render.py:386-400` | Изъятый сервер не хранит, кто что запрашивал | P1 | S |
| Выбор decoy по живому сканированию (`RealiTLScanner`, фильтры, проверка TLS1.3+h2) | `diagnostics/camouflage.py:92-186` | Автовыбор камуфляжа вместо ручного | P1 | M |
| Пре-деплойная проверка занятых портов с легаси-маркерами | `port_check.py:1-60` | Половина провалов установки | P1 | S |
| `--json` без `--yes` = отказ (exit 2) | `v4_topology.py:55-92` | CI не применит случайно | P1 | S |
| Периодическая перевалидация камуфляжа (у них её нет — наш шанс сделать лучше) | `commands/sni.py:1-6` | «Сгнивший» decoy становится детектором | P1 | M |
| age-снапшоты на device-ключи + recovery key, чистка секретных таблиц, перевыпуск CA при restore | `control/snapshot.py:63-78`, `restore.py:263-300` | Восстановление без панели и без доверия изъятому серверу | P2 | M |
| Обновление агента с `.prev`-откатом, staged self-check, успех только по hello новой версии | `agent_upgrade.py:40-80` | Транзакционный апдейт ноды без переenrollment | P2 | M |
| hello: nonce ±300 с + таблица nonce | `enrollment.py:66-72,268-310` | mTLS не спасает от replay; дешёвый второй слой | P2 | M |
| Path/unit allowlist в агенте (`..` запрещён, только `net*.service`) | `agent/src/fsutil.rs:11-56` | Control plane не превращается в универсальный shell | P2 | M |
| Strip-hop для PROXY перед камуфляжным сайтом | `server_render.py:178-191` | Сайт не получает PROXY-заголовок | P2 | S |
| App-level lockout: приложение видит loopback, per-IP jail не работает | `login_limits.py:1-25` | Явно закрыть brute-force панели за stream | P2 | S |

**Что не брать.** 160k строк и пять мест состояния ради масштаба; открытый TCP-релей на чужой
`host:port` по дизайну; `upstream` на hostname без `resolver` (залипает при ротации IP); камуфляж без
таймера переоценки; root-юниты агента/Xray без `ProtectSystem`/`NoNewPrivileges`; beta-форматы под
видом продакшена.

**Security-находки у них.** Root-токен панели открытым текстом в `cluster.yml` рядом с `device.key`;
агент и Xray — root без sandbox; обновление агента проверяется только локально посчитанным SHA-256;
`renew` не отзывает прежний сертификат узла; `report`/`stats` без подписи (нода может врать про
health и трафик). Плюсы: секреты нигде не в argv, recovery key из stdin, replay-защита, path/unit
allowlist, sha256-пины на внешние артефакты.

**Вердикт.** Три главные идеи: (1) `plan`/`apply` с review hash, read-only `plan` и чекпоинтами —
прямо лечит наши самые дорогие инциденты; (2) вынести `default` SNI из Xray и добавить keepalive —
дешёвая правка, снимающая главный differential пробинга; (3) самодоказывающееся применение
(probes + типизированные проверки + машинный режим).

---

## 2. DigneZzZ — зрелый bash-lifecycle

**Паспорт.** MIT, 34.6k строк bash, `remnawave.sh` — 16.5k строк, node 5.0k, selfsteal 6.0k, версии
panel 6.8.0 / node 4.6.2 / selfsteal 2.11.1. Docker Compose + acme.sh. Высокая зрелость для одного
автора: 263 функции, версионные миграции `.env`, четыре shell-набора тестов, комментарии с разбором
прод-инцидентов. CI нет.

**Архитектура.** Три независимых монолита без общей библиотеки; каждый самоустанавливается в
`/usr/local/bin`. `update` сравнивает digest образов, делает safety backup, тянет образы, прогоняет
миграции, пересоздаёт контейнеры. Бэкап — `pg_dump` + tar + `backup-metadata.json` +
`RESTORE-INSTRUCTIONS.md`; restore проверяет версии и откатывается на safety backup. Decoy — Caddy или
nginx в контейнере, REALITY отдаёт в `/dev/shm/nginx.sock` с `xver: 1`.

**Что брать.**

| Идея | Доказательство | Что улучшит | P | Сл. |
|------|----------------|-------------|---|-----|
| **Guarded write**: маркер владения + sha256-сайдкар → `written/unchanged/kept`, diff, `<file>.new-<ver>`, ротация 10, `--strict` | `remnawave.sh:1150-1421` | `update` перегенерирует NGINX/systemd/`.env`; правки оператора сейчас могут теряться | P1 | M |
| **Baseline до/после reload + откат**: снимок «что отвечало», reload, повторный замер, откат при регрессии | `remnawave.sh:9714-9915` | Защита от «reload ок, маршрут пропал» | P1 | M |
| **Зеркала + валидация артефакта**: raw + четыре jsDelivr-хоста, проверка shebang, `SCRIPT_VERSION`, `bash -n` | `remnawave.sh:1873-1921` | Bootstrap не срывается при блокировке одного хоста | P1 | S |
| **Мутация decoy per-install**: снос README/LICENSE, random title/brand/desc, hue-rotate, байтовый шум, новый favicon | `selfsteal.sh:3725-3835` | Одинаковые cover-сайты — кластерная сигнатура | P1 | M |
| **Три-стейт compat при restore** (exact / minor / major / unknown) + проверка major БД | `remnawave.sh:396-418,3387-3480` | Бэкап с другой major — только с подтверждением | P1 | S-M |
| **Pre-update snapshot с гейтом** (нет бэкапа → вопрос, по умолчанию N) | `remnawave.sh:14693-14747` | Мутация не начинается без снимка | P1 | S |
| **Retention: дни + пол «всегда N новейших»** | `remnawave.sh:5692-5710` | На 1 GB бэкапы — главный пожиратель; пол не даёт удалить единственный | P1 | S |
| **TESTABLE-BLOCK** + структурный тест «каждая запись через guard» | `tests/lib/harness.sh` | Лечит наш баг-класс «тест вырезает функцию по якорю» | P1 | M |
| Major-jump guard с ручным вводом номера | `remnawave.sh:15230-15275` | GoWave/Xray major — только по согласию | P2 | S |
| Digest-only проверка обновлений, параллельно, общий таймаут 10 с, «нет сети» → SKIP | `remnawave.sh:14593-14685` | `update --check` не висит на медленной сети | P2 | S |
| Метаданные бэкапа: `upstream_version`, карта образов, `system_info` | `remnawave.sh:5356-5390` | Дополнить наш формат v1 | P2 | S |
| Идемпотентный install: уже стоит → отказ, `--force` = переустановка | `remnanode.sh:1804-1815` | Повторный install/`node add` = no-op либо явный `--reinstall` | P2 | S |
| Валидация запрошенной версии + «did you mean» | `remnanode.sh:1246-1275` | `--gowave-version/--xray-version` не падает посреди установки | P2 | S |
| Responsive help + `help <cmd>` | `remnawave.sh:16141-16198` | Важно в SSH 80×24 | P2 | S |
| Миграции как версионные предикаты, каждая с `cp` перед `sed -i` | `remnawave.sh:480-800` | Эволюция `.env` дешевле перегенерации | P2 | S |

**Что не брать.** Монолит на 16k строк; три разные грамматики CLI с `@`-префиксом; `install`,
завершающийся `docker compose logs -f` (ворует stdin в SSH-пайплайне); `rm -rf` до распаковки
архива; «running» = «healthy»; отсутствие авто-отката при падении update; `eval` по строкам из
конфига; Xray-core с pre-release; ACME TLS-ALPN с iptables REDIRECT без гарантированной очистки.

**Security-находки у них.** `--secret-key=KEY` в argv (документировано в README); пароль админа и
Bearer-токен в argv `curl`; `.env` с `APP_SECRET`/`SECRET_KEY` без 0600; генерируемый `backup.sh` с
токеном бота и паролем БД в 755-файле; `curl | sh` без целостности; Xray-zip без sha256; секреты в
`/tmp` с предсказуемыми именами; `tar -xzf` без валидации записей.

**Вердикт.** Главная ценность — не код, а зафиксированный прод-инцидент: `update` перегенерировал
Caddyfile и снёс добавленные вручную сайты, клиенты получили `tlsv1 alert internal error`. Это ровно
наш риск при генерации NGINX-конфигов, и их решение (маркер + sha256 + `kept` + diff + кандидат)
стоит перенести первым.

---

## 3. eGamesAPI — эксплуатационные мелочи и гигиена панели

**Паспорт.** MIT, ~31.9k строк bash (`install_remnawave.sh` 2.2k, модули ~21k), v3.8.4 от
2026-10-16. Docker Compose (postgres, valkey, backend, sub-page, node, nginx/caddy) + certbot + UFW.
Автор сам пишет: «УЧЕБНЫЙ ПРИМЕР … НЕ ДЛЯ ПРОДАКШНА».

**Архитектура.** Xray слушает 443 (REALITY), `dest = /dev/shm/nginx.sock` с `xver: 1`; nginx слушает
`unix:… ssl proxy_protocol` и термирует TLS уже в сокете. Три vhost по `server_name`: панель,
подписка, SelfSteal. Дефолтный server — `ssl_reject_handshake on; return 444`. Панель закрыта
секретной парой cookie/query, отказ — 418 → статика. Подписка на отдельном домене, ошибки → 444.
Сертификаты — wildcard DNS-01 (CF/Gcore/Bunny) либо per-host HTTP-01. UFW открывает SSH-порты из
`sshd -T`, 443 и 2222 только с IP панели.

**Что брать.**

| Идея | Доказательство | Что улучшит | P | Сл. |
|------|----------------|-------------|---|-----|
| Секретный cookie/query-гейт панели: `map $http_cookie` + `map $arg_<rand>` → `$authorized`, отказ 418 → статика, cookie `HttpOnly; Secure; SameSite=Strict` | `install_panel_node.sh:421-481` | Панель не отвечает сканерам ничем, кроме заглушки; два map-а = 0 RAM | P1 | S |
| `ssl_reject_handshake on` + `return 444` в default-server decoy-листенера | `install_node.sh:148-154` | Чужой SNI не получает сертификат реального домена | P1 | S |
| REALITY-fallback в UDS вместо `127.0.0.1:9443` (`dest: /run/gowave/decoy.sock`, `xver: 1`) | `remnawave_api.sh:456-461` | Минус listener 9443, минус TCP-сокет и буферы на каждую пробу | P1 | S-M |
| Резолв certbot-lineage по покрытию SAN/CN (+`-0001`, +wildcard-база) | `certificates.sh:10-36,1064-1086` | Идемпотентные переустановки: конфиг ссылается на реальный каталог | P1 | S |
| Рандомизация decoy (title/meta/комментарий/класс/футер) + пул + stage→swap | `selfsteal_templates.sh:113-360` | Убирает кластерный фингерпринт; stage-swap не оставляет полусайт | P1 | M |
| API-заголовки через FD (`-H @<(printf …)`), тело `--data-binary @-` | `remnawave_api.sh:11-30` | Bearer и ключи REALITY не в argv/`ps` | P1 | S |
| UFW: маркер владения комментарием + точный матч `^8443/tcp[[:space:]]` | `manage_panel.sh:857-863,1126-1140` | Идемпотентные open/close, чужие правила целы | P1 | S |
| Preflight «домен за Cloudflare» для REALITY/decoy-домена (кэш CF-диапазонов 7 дней) | `install_remnawave.sh:1860-1970` | Ловит «REALITY за оранжевым облаком» до выпуска сертификатов | P1 | S |
| Wildcard на зону DNS-01 (CF/Gcore/Bunny) + валидация базы зоны | `certificates.sh:109-175,202-330` | Один серт и одно продление на панель/подписку/decoy | P2 | M |
| ACME-hook: 80 открыт только в окне продления (маркер в `/run`), правим только свои hooks | `certificates.sh:95-107,708-736` | 80 всегда закрыт; чужие hooks целы | P2 | S |
| Cert-sync на воркеры по sha256 пары fullchain+privkey, `.restart-pending`, замена двумя `.new` + `mv` | `add_node.sh:320-410` | Нет рассинхрона и рваных пар на edge | P2 | M |
| Cron-скрипт с встроенной копией модуля + version-marker | `add_node.sh:320-380` | Наш баг-класс: cron ссылается на перезаписанный апдейтом файл | P2 | S |
| Пресеты response-rules: strict/standard/allow-all, unknown UA → 404/drop | `subscription_rules.sh:60-75,196-270` | Анти-энумерация ссылок подписок | P2 | S-M |
| Аварийная дверь панели: доп. `listen 8443 ssl` + UFW с комментарием + команда закрытия | `manage_panel.sh:851-960` | Панель доступна при сломанной SNI-карте без SSH-туннеля | P2 | S-M |
| Anti-abuse в inbound: `geoip:private → BLOCK`, `bittorrent → BLOCK` | `remnawave_api.sh:474-480` | 2 строки, 0 RAM, тег ставит сам Xray | P2 | S |
| SSH к воркерам: `BatchMode`, `accept-new`, отдельный known_hosts, `IdentitiesOnly`, показ fp при смене ключа | `remote_exec.sh:140-186,401-434` | Сверить с нашим worker-путём | P2 | S |
| TLS-гигиена decoy: 1.2+1.3, `ssl_session_tickets off`, `ssl_session_cache shared:…:10m`, `server_tokens off` | `install_node.sh:126-146` | У нас decoy строго TLSv1.3 — «слишком новый» отпечаток | P2 | S |

**Про «Xray владеет 443» vs нашу схему.** Переносить не нужно. Их выигрыш — на гигабитах: у нас
туннелируемый трафик проходит userspace-копию nginx stream плюс вторую пару loopback-TCP; у них одна
UDS-копия. На провальных пробах наоборот: у нас две копии, у них одна. RAM: у нас две пары сокетных
буферов на соединение. Пробинг: у них одна точка решения, у нас две (SNI-карта, затем REALITY), зато
наша схема переживает падение Xray — сайт, панель и подписка остаются живы, а их 443 умирает целиком
(отсюда аварийная дверь 8443). Наш риск — жёсткая связка `proxy_protocol on` +
`acceptProxyProtocol: true`: если Xray перестанет ждать PROXY-заголовок, все соединения из nginx
умрут; это надо проверять в валидации конфига. Обсуждать «Xray впереди» имеет смысл только по
триггеру «>50% ядра на 300+ Мбит/с».

**Что не брать.** Docker-стек из шести контейнеров на 1 GB; `.env`/`nginx.conf` с секретами 644;
10-летний wildcard-токен со `scopes:[*]`; `pip --break-system-packages`; нетранзакционный self-update
по одному модулю; `eval` по state-файлу; секрет в query без `access_log off`; гейт как единственная
защита (нет 2FA/TTL/ротации); `ufw allow from 172.30.0.0/16` на 2222.

**Security-находки у них.** `.env` панели читается любым локальным юзером (`APP_SECRET`,
`POSTGRES_PASSWORD`); cookie-секрет гейта лежит в `nginx.conf` 644; секрет панели в query без
`access_log off`; админ-пароль только в stdout, файла 0600 нет; долгоживущий wildcard-токен;
UDS в world-writable `/dev/shm` с включённым `proxy_protocol` позволяет локально подделать
`$remote_addr`; API ноды открыт всей docker-подсети. Плюсы: токены не в argv, ни одного `curl -k`,
аккуратный SSH, права на certbot-креды, ELF-проверка ядра.

**Вердикт.** Четыре идеи стоят одного-двух строк конфига и прямо усиливают приоритеты №1–2: гейт
панели, `ssl_reject_handshake`, UDS-fallback, TLS-гигиена decoy.

---

## 4. RemnaSetup — контракты, а не код

**Паспорт.** MIT, 44 файла, 9.6k строк bash, коммит от 2026-08-09. Docker Compose (backend,
postgres, valkey, node, caddy) + host-пакеты. Вход — `install.sh` → zip в `/opt/remnasetup` → меню,
либо `remnasetup.sh <команда>` (7 команд). `install_remnawave.sh` — вендорная копия eGamesAPI.

**Что брать.** Только контракты:

| Идея | Доказательство | Что улучшит | P | Сл. |
|------|----------------|-------------|---|-----|
| Fail-closed валидация неинтерактивного входа: regex/диапазон/обязательность, ошибка до мутаций | `install-nginx.sh:341-420` | `node add/rollback` не примут мусор и не упадут на середине | P1 | S |
| Env-контракт (`GOWAVE_NODE_IP`…) как второй канал ввода рядом с позиционными аргументами | `README.md:57-121` | Машиночитаемый provisioning для флота/CI, секретов в argv нет | P1 | S |
| DNS-01 wildcard как режим сертификата (CF/Gcore, ECDSA p384) | `install-nginx.sh:96-262,272-287` | Нода без открытого 80, один серт на `*.apex` | P2 | M |
| Encrypted offsite-бэкап + ротация (S3 keep-N, Telegram, `-mtime +N`) | `backup_script_s3.sh:46,81-102` | Offsite-копия к нашему Backup Format v1 | P2 | M |
| `--skip-<component>` (аналог `SKIP_*`) | `install-full.sh:36-152` | Частичный перепровижининг: только серт / только decoy | P2 | S |
| «Уже установлено ⇒ update» как явное логируемое решение | `install-node.sh:58-100` | Повторный `node add` печатает одно решение, а не молча переписывает | P2 | S |

**Что не брать.** Отсутствие `set -euo pipefail` во всех файлах; prompt-циклы без обработки EOF
(для нас смертельно: payload идёт по stdin — `read` получает EOF и крутится горячим циклом);
`cp template → sed -i "s|$VAR|"` вместо рендера (ломается на `|`, `&`, `\`); перезапись
`/etc/nginx/nginx.conf` целиком без бэкапа; `chmod -R 777` на `/opt` и `/var/www`; `chown -R
$SUDO_USER` на root-исполняемый код; `latest`-теги и `curl get.docker.com | sh`; обновление без
снапшота; `docker volume rm` как «переустановка».

**Security-находки у них.** Три Critical: `chmod -R 777 /opt` (локальный юзер подменяет код,
исполняемый root'ом), `chown -R $SUDO_USER /opt/remnasetup`, секреты с правами 0644
(`APP_SECRET`, `DB_PASSWORD`, `SECRET_KEY`, `BOT_TOKEN`, S3-ключи, пароль архива). Restore без
подписи и хеша = root-RCE. Плюсы: `SECRET_KEY` не в argv (только env), вывод маскируется,
certbot-креды и приватные ключи 0600.

**Вердикт.** Код не переносить, ценность — три контракта: (а) формат машиночитаемого входа для
`node add`, (б) правило «всё провалидировано или явная ошибка до мутаций», (в) режимы сертификатов и
offsite-бэкапов. `proxy_protocol` — не идея: у нас цепочка уже полная (`modules/nginx.sh:197`,
`assets/xray/vless-reality.json:29`, decoy `listen … proxy_protocol`).

---

## 5. remnawave-admin — анти-абуз и наблюдаемость

**Паспорт.** AGPL-3.0 (до 2.15.x MIT), Python 3.12 + FastAPI + Telegram-бот + PostgreSQL + Redis +
React, всё в Docker Compose (7 контейнеров). Node-agent — отдельный Python-контейнер на каждой ноде,
версия 1.9.0, ~50 MB RSS, требования автора — 4 GB RAM на панель.

**Архитектура.** Агент сам исходящим шлёт батчи в панель (`Authorization: Bearer <agent_token>`) раз
в 30 с; параллельно держит WS как канал команд. Команды подписаны HMAC-SHA256, окно 60 с. Агент —
контейнер `privileged`, `pid: host`, `network_mode: host`, умеет `nsenter` в PID 1. Анти-абуз
считается на панели (~4.1k строк анализаторов), агент лишь поставляет факты.

**Что брать.**

| Идея | Доказательство | Что улучшит | P | Сл. |
|------|----------------|-------------|---|-----|
| UA-классификация подписки: whitelist клиентов, blacklist ботов (`curl`, `Go-http-client`), извлечение ссылок из UA | `analyzers/user_agent.py:68-157` | Безопасный дефолт + 204 для сканеров | P1 | S |
| Признак заглушки `^Mozilla/5\.0\s*$` | `user_agent.py:98-103` | Ловит перепубликацию подписки | P2 | S |
| Simultaneity по `access.log`: уникальные IP на пользователя за окно, отдельный порог для CGNAT | `temporal.py:127-147,241-307` | Дешёвый анти-шаринг: loopback-Xray видит все IP клиента | P2 | M |
| Демпфирование перекрывающихся сигналов ×0.15/0.4/0.7 | `temporal.py:270-307` | Не эскалировать при массовом сбое — это стабильность | P1 | S |
| Пороговая лестница + hard floor (monitor/warn/soft_block/temp_block/hard_block) | `detector.py:38-78` | Одна детерминированная таблица политики вместо разбросанных `if` | P2 | M |
| Xray routing `{"protocol":["bittorrent"],"outboundTag":"TORRENT"}` | `xray.snippets.ts:141` | Ноль CPU/RAM, тег ставит сам Xray | P1 | S |
| Честная фиксация ограничений торрент-детекта | `node-agent/README.md` | Меньше разочарований у операторов | P1 | S |
| Подавление повторных алертов (`_already_reviewed`) | `user_agent.py`, `hwid_guard.py` | Не спамить и не крутить цикл каждые 30 с | P1 | S |
| Метрики только из procfs (`net/dev`, `netstat`, `snmp`, conntrack, diskstats, meminfo) | `network_metrics.py:29-37,148-189` | Наш агент = bash+awk 2–4 MB вместо Python 50 MB | P1 | S |
| Детект атаки: медиана 6 ч + болевой сигнал + два тика | `attack_detector.py:56-79,122-170` | На 1 GB ловит SYN-флуд и conntrack-full раньше пользователей | P2 | M |
| Per-node лимит батчей 1/с (429) + чанки 5000/1.1 с + backoff | `collector.py:288-290,591-598` | Защита от шторма при массовом реконнекте | P2 | S |
| HMAC-подпись команд `_ts` + `compare_digest` | `agent_hmac.py:14-40` | Второй слой поверх mTLS; обязательно с `jti`/nonce | P2 | M |
| Trusted-proxy allowlist для IP клиента | `api/deps.py:600-632` | fail2ban/rate-limit не обходятся подделкой XFF | P1 | S |
| Byte-based cap буфера вместо count-based (антипаттерн `max_buffer_size=50_000` записей) | `config.py:73` | 50k объектов = десятки MB при лимите 128 MB | P1 | S |
| Enum действий вместо `exec_script` | `command_runner.py` | Никакого произвольного shell от панели | P1 | S |
| `/metrics` + внешний скрейп вместо Prometheus-сервера | `main.py:1120-1150` | Не тянуть Prometheus на 1 GB | P3 | S |

**Про self-update.** Их трюк `systemd-run --collect` лечит перезапуск агента изнутри своего юнита.
У нас payload `gowave-node-auto.sh` выполняется отдельным transient-процессом поверх SSH, поэтому эта
ловушка пока не воспроизводится; брать только если появится self-update изнутри `gowave-node`.

**Транспорт не переносить.** Bearer-токен поверх обычного TLS, токен в query string WS, plaintext в
БД, нет привязки ключа к ноде и отзыва, HMAC без nonce. Наша mTLS-модель строго сильнее.

**Security-находки у них.** Critical: `--ws-secret <WEB_SECRET_KEY>` уходит каждому узлу, а этот ключ
подписывает JWT и Fernet для TOTP — компромисс любой ноды даёт admin-JWT. `privileged` +
`pid:host` + `nsenter` в PID 1: токен агента = root на хосте. High: токен в query string WS; токены
plaintext и сравнение `==`; `.env` без 0600. Medium: подпись команд без nonce; доверие правому XFF;
префикс токена в логах; supply chain с ветки `main` и `:latest`.

**Вердикт.** Как продукт — анти-модель (root-на-хосте, токен в URL, мастер-ключ в argv). Как источник
идей — точечно полезен: 9 недорогих идей без нового демона и без роста RAM.

---

## 6. subscription-page — гигиена вокруг подписки

**Паспорт.** AGPL-3.0, v8.0.1 от 2026-10-22. Backend — NestJS 11 + Express 5 (1951 строк TS),
frontend — React 19 + Mantine 9, рантайм `node:24-slim` + PM2 cluster. Тестов нет.

**Главное.** Они **не генерируют** ни Xray JSON, ни Mihomo YAML, ни sing-box: всё форматирование
остаётся в панели, сервис — тонкий реверс-прокси + SSR-обёртка HTML. Выбор представления — по UA:
браузерные и preview-боты получают HTML, остальные — конфиг.

**Что брать.**

| Идея | Доказательство | Что улучшит | P | Сл. |
|------|----------------|-------------|---|-----|
| `X-Robots-Tag: noindex, nofollow, noarchive, nosnippet` на ответы подписки | `no-robots.middleware.ts:3-5` | Ссылка не попадает в индекс и архивы — главный реальный канал утечки sub-URL | P0 | S |
| Убрать shortUuid из access-лога для `/api/sub/` | `main.ts:110-117` (у них та же ошибка) | У кого лог — у того все подписки | P0 | S |
| UA-денлист preview-ботов (`TelegramBot`, `WhatsApp`, `facebookexternalhit`, `Slackbot`, `Discordbot`) | `is-browser.ts:5-16` | Вставленная в чат ссылка иначе сливает credentials в кэш мессенджера | P0 | S |
| `Cache-Control: no-store, private` с `always` | `axios.service.ts:305`; наш `modules/nginx.sh:398` | У нас `add_header` без `always` не применяется к 4xx/5xx (502 от панели) | P0 | S |
| Allowlist `clientType` до проксирования + 444 на мусор | `client-type.middleware.ts:10-22` | Сканерские пути не доходят до панели | P1 | S |
| Глухой 444 вместо 404 с телом на любой промах | `subscription.service.ts:32-35` | Убирает oracle перебора shortUuid | P1 | S |
| Allowlist заголовков ответа вместо blacklist | `ignored-headers.constant.ts:1-47` | Blacklist протекает: новые заголовки панели молча уезжают клиенту | P1 | M |
| `server_tokens off` на vhost подписок | `main.ts:73` | Одинаковая подпись `nginx/<ver>` связывает сервисы при сканировании | P2 | S |
| Fail-fast валидация шаблонов (zod + `exit(1)`) | `webpage.service.ts:40-89` | Эквивалент `xray run -test` в конце install | P1 | S |
| Канонизация ссылки (срезать query/hash/userinfo) | `construct-subscription-url.tsx:3-19` | Битые ссылки в `user links` | P2 | S |

**Что не брать.** UA как селектор формата при явном типе в пути (их же баг: `/{uuid}/mihomo` с
браузерным UA отдаёт HTML); blacklist заголовков, вырезающий `Cache-Control`/`ETag` из ответа;
отдельный демон ради статики + PM2 на 1 vCPU + `--max-old-space-size=16384`; конфиг только на старте
с `exit(1)`; `socket.destroy()` как универсальный обработчик; ноль тестов на security-чувствительном
коде; `CORS: *` на персональной подписке; JWT-cookie для статики.

**Security-находки у них.** shortUuid в access-логе (High); целый `AxiosError` в лог, включая
`Authorization: Bearer <panel token>` (High); legacy-режим печатает JWT (High); `CORS: *` как oracle
существования UUID; директивы кэша вырезаются из ответа, а HTML без `Vary: User-Agent`; stored XSS
из конфига панели при `contentSecurityPolicy: false`; `TRUST_PROXY=1` без проверки значения
`X-Forwarded-For`; нет rate limiting.

**Вердикт.** Архитектуру копировать нельзя, но четыре дешёвые идеи закрывают реальные каналы утечки
подписки, и три из них — строки в NGINX. Наш контракт «обязательный UA + формат по пути» строго
лучше их «формат по UA»: их собственный баг это доказывает.

---

## 7. remna-playbook — негативная ценность

**Паспорт.** Ansible + Jinja2, 46 файлов, коммит от 2026-06-11. Сама установка Remnawave — во внешних
galaxy-ролях `iphizic.remna-server` / `iphizic.remna-node`, которых в репозитории нет и версии
которых не закреплены. В репозитории — только обвязка: hardening, firewall, Docker, Caddy,
Headscale, Baikal, мониторинг.

**Что брать (практики, не код).**

| Практика | Доказательство | Что улучшит | P | Сл. |
|----------|----------------|-------------|---|-----|
| Render-if-changed: рендер → sha256 → запись только при отличии, факт изменения через код возврата | `roles/caddy/tasks/main.yml:17-23` | Убирает лишние рестарты и дребезг при `update` | P1 | S |
| Очередь handler'ов: копить `CHANGED_UNITS`, рестарт каждого юнита ровно один раз в конце | `roles/headplane/handlers/main.yml:1-5` | Нет restart storm и промежуточных полу-рабочих состояний | P1 | S |
| Инвариант «меняешь конфиг ⇒ объяви reload» + тест на каждый managed-конфиг | `roles/caddy/tasks/main.yml:17-29` против `headplane/tasks/main.yml:21,30` | Ловит забытый `notify` — у них конфиг пишется, сервис не перезагружается | P1 | S |
| Preflight-контракт обязательных переменных на компонент | `all.yml.example:14`, `remna_node.yml:4` | Проверка до первой записи на диск; у них отсутствует | P1 | S |
| `no_log`-дисциплина (у них 0 совпадений при 6 секретах в шаблонах) | grep по репо | `set +x` в функциях с секретом + линт-тест на утечку в трассировку | P1 | S |
| Слои переменных all → group → host | `group_vars/*`, `host_vars/*` | Предсказуемые дефолты + переопределение одного узла | P2 | M |
| `--dry-run` с построчным diff | `ansible.cfg:10-13` | Наш `--dry-run` печатает diff, а не «ok» | P2 | M |

**Что не брать.** `curl`-скрипт установщика прямо в оболочку без `creates`/checksum (RCE на каждом
прогоне); GPG-ключ репозитория по `http://`; дублирование установки в двух ролях; ноль `assert` и
`example.com` в боевых переменных; `host_key_checking = False` глобально; `[diff] always` при
секретах в шаблонах и нуле `no_log`; `become: true` на весь play; Docker-порты, обходящие
INPUT-фильтр; мониторинг с `privileged`, `pid: host` и `/var/run:rw`.

**Security-находки у них.** Critical: в git закоммичен реальный приватный EC-ключ узла (base64-JSON
с `nodeKeyPem`, подтверждено декодированием). High: захардкоженный `cookie_secret`; `change_me` в
JWT-секретах; `host_key_checking = False`; `[diff] always` без `no_log`; `curl | shell` без
checksum; `POSTGRES_PASSWORD: postgres`.

**Вердикт.** Код не переносить. Ценность негативная: репозиторий наглядно показывает, где
идемпотентность разваливается и как IaC протекает секретами. Наши Zero-Leak и транзакционный update
на этом фоне — обоснованный минимум, а не избыточность.

---

## Сводный бэклог

Дедуплицировано; источник в скобках. Порядок внутри блока — по приоритету.

### A. Утечки и отпечатки (почти всё S, приоритет 2)

| # | Что | Источник | Наша точка | P |
|---|-----|----------|------------|---|
| A1 | `X-Robots-Tag: noindex, nofollow, noarchive, nosnippet` на `/api/sub/` | subscription-page | `modules/nginx.sh` подписочный location | P0 |
| A2 | `add_header … always` для `Cache-Control: no-store, private` | subscription-page | `modules/nginx.sh:398` | P0 |
| A3 | `access_log off` (или маскирующий `log_format`) на `/api/sub/` | subscription-page, meridian | `modules/nginx.sh:389-400` | P0 |
| A4 | UA-денлист preview-ботов на подписке | subscription-page | NGINX `map` + `if`/`return 204` | P0 |
| A5 | `server_tokens off` в панельном, подписочном и decoy-vhost | subscription-page, eGamesAPI | `modules/nginx.sh:373,478` | P1 |
| A6 | 444 на сканерские пути + allowlist `clientType` | subscription-page, eGamesAPI | NGINX location | P1 |
| A7 | TLS-гигиена decoy: 1.2+1.3, `ssl_session_tickets off`, кэш сессий | eGamesAPI | `modules/nginx.sh:485` | P2 |
| A8 | Stock-тела 403/404 без подписей | meridian | decoy vhost | P2 |
| A9 | Trusted-proxy allowlist для `X-Forwarded-For` (у нас proxy_protocol — проверить, что XFF не принимается откуда попало) | remnawave-admin | панельный vhost | P1 |

### B. Надёжность и идемпотентность (S/M, приоритет 3)

| # | Что | Источник | Наша точка | P |
|---|-----|----------|------------|---|
| B1 | Guarded write: sha256-сайдкар + `written/unchanged/kept` + diff + `<file>.new-<ver>` + ротация | DigneZzZ | все генераторы `modules/nginx.sh`, `modules/node.sh` | P1 |
| B2 | Общий render-if-changed (сейчас только deploy-hook и CA) | playbook, DigneZzZ | `modules/nginx.sh:553,726,846` | P1 |
| B3 | Очередь отложенных рестартов на конец транзакции | playbook | `reload_nginx_strict` и update-путь | P1 |
| B4 | Preflight-контракт обязательных переменных на компонент | playbook | `modules/preflight.sh` | P1 |
| B5 | Pre-update snapshot с гейтом (нет бэкапа — не начинаем) | DigneZzZ | update/channel-путь | P1 |
| B6 | Retention: дни + пол «всегда N новейших» | DigneZzZ | `assets/backup/gowave-backup.sh` | P1 |
| B7 | Три-стейт compat при restore (exact/minor/major/unknown) | DigneZzZ | backup v1 preflight | P1 |
| B8 | Резолв certbot-lineage по покрытию SAN/CN | eGamesAPI | `modules/nginx.sh:941-1017` | P1 |
| B9 | Baseline-проба SNI до/после reload с откатом | DigneZzZ | `verify_public_tls_sni` + матрица | P1 |
| B10 | Пре-деплойная проверка занятых портов с легаси-маркерами | meridian | `modules/preflight.sh` | P1 |
| B11 | `plan` (read-only, exit 2) + `apply` с `expected_plan_hash` + чекпоинты `unknown` | meridian | lifecycle-команды | P2 |
| B12 | Замена mutation-lock на lease-fence (`generation` + `plan_hash`) | meridian | `modules/lock.sh` | P2 |

### C. Скрытность и анти-пробинг (M, приоритет 2)

| # | Что | Источник | Наша точка | P |
|---|-----|----------|------------|---|
| C1 | Увести `default` SNI из Xray (в decoy или `127.0.0.1:9`) + `proxy_socket_keepalive on` | meridian | SNI-карта `modules/nginx.sh:193-201` | P1 |
| C2 | Убрать чужой SNI из выдачи сертификата: `ssl_reject_handshake` (решение с trade-off) | eGamesAPI | decoy vhost | P1 |
| C3 | REALITY-fallback в UDS вместо TCP-loopback (замерить) | eGamesAPI | decoy listener 9443 | P1 |
| C4 | Мутация/рандомизация decoy per-install + периодическая перевалидация | DigneZzZ, eGamesAPI, meridian | `render_cover_site` | P1 |
| C5 | Секретный cookie/query-гейт панели (файл 0600, ротация, `access_log off`) | eGamesAPI | панельный vhost | P1 |
| C6 | Wildcard DNS-01 (CF/Gcore/Bunny) + валидация базы зоны | eGamesAPI, RemnaSetup | `ensure_tls_cert`/`run_certbot` | P2 |
| C7 | 80 открыт только в окне ACME-продления (маркер + свои hooks) | eGamesAPI | `configure_certbot_deploy_hook` | P2 |
| C8 | Preflight «домен за Cloudflare» для REALITY/decoy | eGamesAPI | `modules/preflight.sh` | P1 |
| C9 | PROXY strip-hop перед decoy-сайтом | meridian | decoy vhost | P2 |
| C10 | Периодический аудит: чужой SNI, пустой SNI, TLS-версии, Alt-Svc | meridian, DigneZzZ | verify/e2e | P2 |

### D. Анти-абуз и наблюдаемость (M, приоритет 2/3)

| # | Что | Источник | Наша точка | P |
|---|-----|----------|------------|---|
| D1 | Xray routing `bittorrent → BLOCK` (политика, 2 строки) | remnawave-admin, eGamesAPI | `assets/xray/*` | P1 |
| D2 | UA-классификация подписки (whitelist клиентов, blacklist ботов) | remnawave-admin | NGINX map / панель | P1 |
| D3 | Демпфирование сигналов и подавление повторных алертов | remnawave-admin | если появится алертинг | P1 |
| D4 | Метрики из procfs (bash+awk), без Python-демона | remnawave-admin | `cmd_status`/`cmd_health` | P2 |
| D5 | Simultaneity по `access.log` (сначала observe-only) | remnawave-admin | Xray access log | P2 |
| D6 | Детект атаки по болевым сигналам (медиана + 2 тика) | remnawave-admin | `cmd_health` | P2 |
| D7 | HMAC+nonce как второй слой над mTLS | remnawave-admin, meridian | control plane | P2 |
| D8 | Enum действий вместо произвольного exec | remnawave-admin, meridian | control plane | P2 |

### E. Удобство и CLI (S, приоритет 4)

| # | Что | Источник | Наша точка | P |
|---|-----|----------|------------|---|
| E1 | Зеркала bootstrap + sha256-пин (сейчас один хост) | DigneZzZ, eGamesAPI, RemnaSetup | bootstrap/`update` | P1 |
| E2 | Env-контракт для `node add` рядом с позиционными аргументами | RemnaSetup | `gowave-auto.sh:565` | P1 |
| E3 | `--name` (namespace установки) | DigneZzZ | пути/юниты/порты | P1 |
| E4 | `--skip-<component>` для частичного перепровижининга | RemnaSetup | `cmd_install`/`cmd_node` | P2 |
| E5 | Короткая обёртка в `PATH` + `help <cmd>` | DigneZzZ, eGamesAPI | установка симлинка | P2 |
| E6 | `--json`/`--events=jsonl` + `--json` без `--yes` = отказ | meridian | все команды | P2 |
| E7 | Идемпотентный install: уже стоит → no-op либо `--reinstall` | DigneZzZ | `cmd_install` | P2 |
| E8 | Валидация запрошенной версии + «did you mean» | DigneZzZ | версии GoWave/Xray | P2 |
| E9 | Канонизация ссылки подписки (query/hash/userinfo) | subscription-page | `cmd_user_links` | P2 |

## Решения, которые нужно принять (trade-off, не «багфиксы»)

1. **`default` SNI.** Сейчас неизвестный SNI идёт в Xray. Варианты: (а) оставить; (б) увести в decoy —
   проба видит живой сайт, Xray разгружен; (в) увести в `127.0.0.1:9` — самый тихий, но проба видит
   обрыв. Проверять на podman и живых VPS с Xray+Mihomo, чтобы не задеть REALITY-клиентов.
2. **Чужой SNI на decoy.** `ssl_reject_handshake` убирает утечку имени домена, но превращает «проба
   видит сайт» в «проба видит обрыв TLS». Выбор между двумя отпечатками.
3. **Торрент-тег Xray.** Дёшево и без RAM, но это продуктовая политика: MSE/uTP обходят детект, а
   ложные срабатывания бьют по легитимным клиентам.
4. **Wildcard DNS-01.** Один серт на всё и 80 закрыт, но появляется зависимость от API-токена
   DNS-провайдера и плагина certbot.
5. **Гейт панели.** Секретная cookie/query-пара — 0 RAM, но ссылка утекает через историю/логи, если
   не отключить лог; альтернатива — Basic Auth/TinyAuth (+1 процесс) или ничего.
6. **UDS вместо loopback.** Минус listener и копия, но права на сокет, tmpfiles и совместимость
   `dest` в нашей версии Xray надо проверить до внедрения.

## Подтверждённые дефекты в нашем коде

Проверено чтением, независимо от отчётов агентов:

| # | Факт | Где | Следствие |
|---|------|-----|-----------|
| 1 | `add_header Cache-Control …` без `always` | `modules/nginx.sh:398` | На 502/504 от панели заголовок не отдаётся |
| 2 | `location ^~ /api/sub/` не задаёт свой `access_log` | `modules/nginx.sh:389-400` | shortUuid попадает в общий `access.log` |
| 3 | `X-Robots-Tag` отсутствует во всём репозитории | — | Ссылка подписки может попасть в индекс/архив |
| 4 | `server_tokens off` есть только в vision-fallback | `modules/nginx.sh:526` | Панель, подписка и decoy выдают версию NGINX |
| 5 | Decoy — единственный server-блок, TLSv1.3-only, сертификат REALITY-домена | `modules/nginx.sh:478-508` | Проба с любым SNI получает сертификат реального домена |
| 6 | 27 маркеров `# Managed by GoWave`, но нет sha256-сайдкара и `kept`-логики | `modules/` | Ручные правки конфигов не детектируются при перегенерации |
| 7 | Нет `proxy_socket_keepalive` и `resolver` | SNI-роутер | Больше обрывов на долгих соединениях |
| 8 | Нет routing-правил в шаблонах Xray | `assets/xray/` | Торрент-трафик не отсекается на уровне ядра |
| 9 | Render-if-changed только для deploy-hook и CA | `modules/nginx.sh:553,726,846` | Остальные конфиги перезаписываются всегда |
| 10 | `proxy_protocol`-цепочка полная | `modules/nginx.sh:197`, `assets/xray/vless-reality.json:29`, decoy `listen … proxy_protocol` | Идея RemnaSetup уже реализована, дублировать не нужно |
| 11 | `node add` валидирует SSH-порт/юзера/IP и пиннит host key | `gowave-auto.sh:628-655` | Дыра уже́, чем у RemnaSetup: нет валидации доменов и env-канала |
| 12 | Decoy частично рандомизирован (brand + 3 цвета из домена) | `modules/nginx.sh:85-101` | Две установки на разных доменах различаются; полной мутации нет |

## Анти-паттерны, которые не берём ни в каком виде

`curl | sh` без sha256; секреты в argv; `.env` 644; `chmod -R 777`; `chown` root-кода на юзера;
`latest`-теги; `eval` по конфигу/state; blacklist заголовков вместо allowlist; UA как селектор
формата при явном типе в пути; отдельный демон ради статики; Docker Compose как способ обойти
systemd; восстановление архива без подписи; `host_key_checking = False`; `privileged`/`pid:host`/
`nsenter` в агенте; токен в query string; `rm -rf` до распаковки; «running» = «healthy».

## Порядок после зелёных тестов

1. **Волна 1 (P0, строки в NGINX):** A1–A4 — robots, `always`, лог подписки, UA-денлист. Плюс тест на
   каждый пункт: заголовок есть на 200 и на 502; shortUuid отсутствует в логе.
2. **Волна 2 (P1, дешёвое):** A5, A6, A9, B2, B4, B8, C8, E1, E2, D1. Каждая — с тестом; ничего не
   меняет архитектуру.
3. **Волна 3 (P1, контракты):** B1 (guarded write), B3 (очередь рестартов), B5–B7 (бэкап), B9
   (baseline-проба), B10 (порты), C3/C4 (decoy), C5 (гейт панели) — по одной, с прогоном e2e+podman.
4. **Волна 4 (P2, архитектурное):** B11/B12 (plan/apply, fence), C6/C7 (сертификаты), D2–D8
   (анти-абуз, наблюдаемость), E3–E9 (CLI).

Решения из блока trade-off принимаются до соответствующей волны, а не внутри неё.

## Лицензии и происхождение

MIT: meridian, DigneZzZ, eGamesAPI, RemnaSetup — код можно переписывать под наш стиль; при дословных
фрагментах нужна отметка в `THIRD_PARTY_NOTICES.md`. AGPL-3.0: subscription-page, remnawave-admin —
идеи и контракты берём, код не копируем. remna-playbook — лицензия в репозитории не указана, код не
копируем.

Сырые отчёты: `/tmp/inspiration/reports/{meridian,dignezzz,egamesapi,remnasetup,remnawave-admin,subscription-page,remna-playbook}.md`.
