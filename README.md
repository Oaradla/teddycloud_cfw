# TeddyCloud

## What teddyCloud CFW adds

teddyCloud CFW serves first-generation Tonieboxes (CC3200 and ESP32-S3) that run the custom firmware (CFW). Everything sits behind the setting **CFW support** (`cfw.enabled`). It is off by default, and then teddyCloud behaves like the original. Requests that only the CFW sends never go to the cloud, and towards the cloud the box presents itself as an original box.

**Settings per tonie** (in the tonie's edit dialog)
- **Figure profile:** resume (the figure continues where it stopped, even if other figures played in between), shuffle (every chapter exactly once), sleep timer (gets quieter after a third of the time, switches the box off at the end), maximum volume and LED brightness while the figure is on the box, slap, tilt and volume locks.
- **Event tag:** plays nothing, but runs actions, either for the next figure or for the whole box. Actions can be combined (e.g. sleep timer, locks, volume limit, start volume, LED), and each one can switch on, switch off or toggle. Optional confirmation tones: rising for "on", falling for "off". A box without the CFW hears a notice instead (German, English or French).

**Settings per box**
- Speaker and headphone volume limits in 15 steps instead of 4.
- Switch off by briefly pressing both ears.
- Slap, tilt and volume locks.
- Changes made on the box are synchronised with teddyCloud.

**Remote control and status** (box card)
- Pause, continue, stop, next/previous chapter, volume, play a given tonie, request the status, check for an update now.
- Firmware version, battery voltage and charging station shown; optional battery log per box as CSV.
- The same remote control in Home Assistant through MQTT: buttons, a volume slider, a text field that plays a tag UID, and the player state and chapter, on the box's MQTT device (needs `mqtt.enabled`; the box needs remote control on).

**Firmware updates through teddyCloud** (tab *Tonieboxes → Box Update*)
- Library for release packages (CC3200, ESP32 and setup page in one zip) and single images.
- Channels release, beta and alpha; per box manual assignment or automatically the newest image of the channel.
- Download from GitHub releases, manually or automatically at an interval, with certificate and digest check.
- **Trial start:** the box writes the update into a free slot and starts it once as a trial. If the new image does not confirm itself, the box starts the previous one again; teddyCloud detects the rollback and does not offer that image again.
- The matching setup page is delivered along with the image.
- ESP32 boxes: the way back to the original firmware also goes through teddyCloud, with the server and port patches applied.

**What the box can do with the CFW**
- **Slap upside down:** restarts the content from the beginning.
- **Setup page of the box** (in setup mode, through its own Wi-Fi access point): Wi-Fi with network scan, box language, server host and port, certificate upload (CA, client certificate, private key), and **delete buttons** for stored Wi-Fi networks, local contents and settings, and the server settings. They replace the factory reset.
- Plus everything above on the box side: figure profiles, event tags, remote control, updates with trial start.

## Features
TeddyCloud is an alternative server for your Toniebox, allowing you to host the cloud services locally.
This gives you the control about which data is sent to the original manufacturer's cloud and allows you
to host your own figurine audio files on e.g. your NAS or any other server.

Currently implemented are:
* Provide audio content over the air
* Cache original tonie audio content
* Simulate live content (.live)
* Passthrough original tonie audio content
* Convert any audio file to a tonie audio file (web)
* On-the-fly convert audio streams via ffmpeg for webradio and streams
* Basic Web fronted
* Filter custom tags to prevent deletion (.nocloud)
* Configure maximum volume for speaker and headphones
* Configure LED
* Configure slapping
* Customize original box sounds (ex. jingle) over the air
* Extract/Inject certitifcates on a esp32 firmware dump
* Decode RTNL logs
* MQTT client
* Home Assistant integration (MQTT)
* Optional web UI login (disabled by default): up to 128 users, TOTP two-factor authentication, lockout, fail2ban support, reverse proxy aware
* [Web frontend](https://github.com/toniebox-reverse-engineering/teddycloud_web) (full stack developers welcome)

## Planned
* teddyBench integration
* Toniebox 2 support

## Web UI login

Login protection is **off by default**. When enabled, the web interface requires a username and password; Toniebox cloud APIs on the box port are unchanged.

- Create users and turn login on in the web UI (Settings → Web login). Up to 128 users.
- Passwords are stored as salted PBKDF2-SHA256 hashes in `web_users.json` under the config directory (owner-only file). Hashes of older releases are upgraded at the next login. New passwords need at least 10 characters (`web_auth.password_min_length`) and must not be a common password.
- **Two-factor authentication (TOTP)** with any authenticator app, plus ten one-time recovery codes. It can be required per user or for everyone (`web_auth.require_2fa`); such users must set it up at their next login. TOTP secrets are encrypted with a key in `web_auth.key`.
- Sessions use an `HttpOnly`, `SameSite=Strict` cookie (`Secure` over HTTPS), survive restarts (only token hashes are stored in `web_sessions.json`), expire after `web_auth.session_days` and after `web_auth.session_idle_hours` without use. Users see and end their sessions; a password change ends the other sessions.
- Brute-force protection: after `web_auth.lockout_attempts` failed logins an address is locked for `web_auth.lockout_minutes`, doubling with every further lockout (max. 24 hours). Many failures for one account from outside lock that account for logins from outside only, so you can still log in from your LAN. Admins see a security log and can unlock addresses.
- Every failed login is logged as `Web UI login failed for user '<name>' from <ip> (<reason>)`; a fail2ban filter and jails are in [`contrib/fail2ban`](contrib/fail2ban).
- Sensitive changes (users, turning the login off, security settings such as `web_auth.*` and certificates) need the password, and the 2FA code, again when the last confirmation is older than 10 minutes, so a stolen session alone can not take over accounts.
- Requests to the API from other sites are rejected (`Sec-Fetch-Site`/`Origin` check); the web UI is sent with `X-Frame-Options`, `frame-ancestors`, `nosniff` and `Referrer-Policy` headers.
- Set `TEDDYCLOUD_WEB_AUTH_DISABLE=1` to bypass login and all network filters (for recovery).
- Removing `web_users.json` (no users left) turns login protection off again.

### Permissions

With the login on, every user has a level:

- **admin**: everything. Users from older releases and the first user are admins; at least one admin always remains.
- **user**: owns boxes, tonies and library folders and shares them with other users, with chosen rights. Creates and manages users of the same or a lower level.
- **guest** (shown as "child" in the web UI): only what is shared with them.

Admins can add own groups (up to 32), each of the kind user or guest with its own limit of rights; a user in a group has the level of its kind.

Rights are `box.view`, `box.settings` (or single settings as `box.setting:<name>`, e.g. `box.setting:toniebox.max_vol_spk`), `box.cfw`, `tonie.view`, `tonie.assign`, `tonie.edit`, `folder.read`, `folder.write`, the `*.share` rights of owners, `users.manage` and `model.create` (add custom tonies and their pictures; users change and delete the custom tonies they added, and those used only in folders and on tonies they may change, and pictures shown only by such tonies; never with the audio id of an official tonie). Admins assign the owners of boxes, set the most a level or group may have (this also counts on the user's own boxes) and can take further rights from single users.

- A new tag belongs to the owners of the box it is first placed on; tags from before belong to nobody (usable by all users) until they are placed on a box. Admins assign tags by hand.
- Library: `by/` is readable for all, new top-level folders are readable and writable for all, `private/<user>` belongs to the user, who can share sub folders. A tonie can only point at library files the user may read.
- Global settings, files outside the library, certificates, plugins, firmware, tonies.json and settings that touch the server or the files (directories, certificates, cloud and network options) stay with the admins, also per box.
- The live event stream carries no box, so only admins get it.

Stored in `web_acl.json` in the config directory; without the login everyone may do everything, as before.

### Exposing the web UI to the internet

The login protects every web API, the box APIs keep their client certificate check (`core.boxCertAuth`, pin the certificates of your boxes with `toniebox.certPin`). Before you publish TeddyCloud:

1. Enable login, use strong passwords and require 2FA (`web_auth.require_2fa`).
2. **Behind a reverse proxy** (Traefik, nginx, Caddy, ...): put the proxy's address or network into `web_auth.trusted_proxies`. Only then does TeddyCloud see the real client address (`X-Forwarded-For`) and HTTPS (`X-Forwarded-Proto`); otherwise every client looks like the proxy, usually a local address. Settings → Web login shows the address TeddyCloud sees for you and warns about an untrusted proxy.
3. **Without a reverse proxy**: publish the HTTPS web port (`core.server.https_web_port`) with your own certificate, e.g. from Let's Encrypt: `core.server_cert.file.web_crt` (fullchain) and `core.server_cert.file.web_key`. Renewed files are picked up without a restart. Do not publish the plain HTTP port, or enable `web_auth.remote_https_only`.
4. Optional: `web_auth.remote_access = false` keeps the web UI to your local networks (`web_auth.lan_networks`) plus `web_auth.allow_networks` (e.g. a VPN), `web_auth.deny_networks` blocks networks, and users can be marked "LAN only" (e.g. admins).
5. The boxes connect to the box port (TLS with client certificates). It can be published on another port than 443 if your boxes are configured for it.

A Traefik example that separates the web UI (HTTP) from the Toniebox port (TLS passthrough) is in [`docker/docker-compose.traefik.example.yaml`](docker/docker-compose.traefik.example.yaml).

## Where to start?
If you want to get started, please follow our [guide on our website](https://toniebox-reverse-engineering.github.io/docs/tools/teddycloud/).

## Development and bulding
Please use the [develop](tree/develop) for your development and pull requests. Stable builds are available from the master branch. Don't forget to clone the submodules with --recurse-submodules.
To catch sanitizer in you IDE set a breakpoint on `__asan::ReportGenericError`.

### Local Development Sandbox

**`dev-sandbox/`** – Run TeddyCloud locally with mock data (tonies, Toniebox, TAF) to try out features and see changes during development. Builds and runs a local image.

Details: [dev-sandbox/README.md](./dev-sandbox/README.md).

### Build and Run in Editor (VS Code)
- Build once: `Terminal (or F1) -> Run Task -> build` (uses `.vscode/tasks.json`).
- Debug/run: open `Run and Debug`, select `[linux] teddyCloud`, press `F5` (uses `.vscode/launch.json`).
- `F5` runs the prelaunch build task automatically and starts `bin/teddycloud` with `gdb`.
- For web UI in devcontainer, open `http://localhost:<port>/web` on your forwarded HTTP port (You can find the port in `F1 -> 'Ports: Focus on Ports view`).

### Contribution Workflow (teddycloud + teddycloud_web)

TeddyCloud consists of two repositories: the backend (teddycloud) and the web frontend ([teddycloud_web](https://github.com/toniebox-reverse-engineering/teddycloud_web)) as a submodule. Built web files live in `contrib/data/www/`.

**Workflow for contributors:**

1. **Backend-only changes:** Open a PR against teddycloud – no submodule changes needed.
2. **Frontend-only changes:** Open a PR against teddycloud_web – no PR against teddycloud needed.
3. **Changes in both repos:** Create and merge both PRs separately (teddycloud_web first, then teddycloud). **Do not commit submodule pointer changes in the teddycloud PR** – a maintainer will handle that.

**Build and publish workflows (GitHub Actions):**

| Workflow | Trigger | Description |
|----------|---------|-------------|
| [Make web and commit](https://github.com/toniebox-reverse-engineering/teddycloud/actions/workflows/build_commit_web.yml) | Manual (`workflow_dispatch`) | Builds the web from the teddycloud_web submodule, commits files to `contrib/data/www/`, pushes, and triggers the Docker build. |
| [Docker Image Publish Matrix](https://github.com/toniebox-reverse-engineering/teddycloud/actions/workflows/publish_docker_matrix_all.yml) | Push to `master`/`develop` or tags | Builds Docker images automatically. |

**After merging:** Once both PRs are merged, a maintainer runs the "Make web and commit" workflow. It builds the frontend from the current teddycloud_web state (same branch), commits the built files, and updates the submodule pointer if needed. The subsequent push triggers the Docker build automatically.

## Legal

Toniebox, Tonie and tonies are trademarks of tonies GmbH (formerly Boxine
GmbH). This project is not affiliated with, endorsed or supported by tonies
GmbH; the names only say which devices the software works with.

Changing the firmware of a box, opening it or connecting to its debug port
is at your own risk: a box can become unusable, and it can affect claims
against the manufacturer. The software comes without any warranty (see the
licence).

## Attribution
The icons used are from here:
* img_empty.png: https://www.flaticon.com/free-icon/ask_1372671
* img_unknown.png: https://www.flaticon.com/free-icon/ask_1923795
* img_custom.png/favicon.ico: https://www.flaticon.com/free-icon/dog_2829818

Thanks for the original authors for these great icons.
