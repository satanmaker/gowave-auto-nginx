# Third-Party Notices and License Scope

## License Scope

Copyright (C) 2026 GoWave Auto NGINX contributors.

Original code, configuration templates, test suites, and documentation authored by GoWave Auto NGINX contributors are licensed under the [GNU General Public License v3.0](LICENSE) (GNU GPL-3.0-only).

This grant applies strictly to original materials created for this project. It does not relicense third-party or inherited software.

---

## Upstream Compatibility & Separate Components

GoWave Auto NGINX interacts with separately obtained and deployed upstream components exclusively as independent processes across documented network protocols, REST APIs, and system interfaces.

### GoWave Panel & GoWave Node
- **Upstream Authors**: aaaSaZaN and GoWave contributors
- **Repositories**: [GoWave](https://github.com/aaaSaZaN/gowave) and [GoWave Node](https://github.com/aaaSaZaN/gowave-node)
- **License**: GNU Affero General Public License v3.0 (GNU AGPL-3.0)
- **Interaction Model**: GoWave Auto NGINX acts as an external orchestrator and lifecycle manager (`GOWAVE_PROXY=external`). It interacts with GoWave Panel exclusively via HTTP/HTTPS REST APIs and manages its systemd service. GoWave Node is orchestrated via its official installer script, systemd configuration, and standard environment variables. Neither GoWave nor GoWave Node source code is modified, linked statically, or embedded into GoWave Auto NGINX binaries.

### Xray-core
- **Upstream Project**: [XTLS/Xray-core](https://github.com/XTLS/Xray-core)
- **License**: Mozilla Public License 2.0 (MPL-2.0)
- **Attribution**: Copyright (c) Xray-core authors. Used as an independent supervised daemon via `gowave-node`.

### NGINX
- **Upstream Project**: [NGINX](https://nginx.org)
- **License**: 2-clause BSD-like license
- **Attribution**: Copyright (C) Igor Sysoev, NGINX Inc.

### Certbot
- **Upstream Project**: [EFF Certbot](https://github.com/certbot/certbot)
- **License**: Apache License 2.0
- **Attribution**: Copyright (C) Electronic Frontier Foundation and other contributors.

---

## Retained Upstream Attributions

### community-baseline
- **Upstream Project**: [community-baseline](https://github.com/community-baseline/community-baseline)
- **License**: GNU General Public License v3.0 (GNU GPL-3.0-only)
- **Attribution**: Copyright (C) 2026 community-baseline contributors.
- **Notice**: Infrastructure architecture, NGINX Stream multiplexing models, transactional security hardening drop-ins, and backup/restore verification methodologies are adapted from `community-baseline`.

### mozaroc
- **Upstream Reference**: [mozaroc/3x-ui-pro](https://github.com/mozaroc/3x-ui-pro)
- **Attribution**: Copyright (C) mozaroc. Predecessor and reference fork for earlier 3x-ui infrastructure automation.

### MHSanaei (3x-ui)
- **Upstream Project**: [MHSanaei/3x-ui](https://github.com/MHSanaei/3x-ui)
- **License**: GNU General Public License v3.0 (GNU GPL-3.0)
- **Attribution**: Copyright (C) MHSanaei and contributors.

### LibreSpeed
- **Upstream Project**: [LibreSpeed](https://github.com/librespeed/speedtest)
- **License**: GNU Lesser General Public License v3.0 (LGPL-3.0)
- **Attribution**: Copyright (C) 2016-2022 Federico Dossena.
- **Notice**: Embedded speedtest assets retain their original LGPL-3.0 licensing and author attribution headers.
