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
* Optional web UI login (disabled by default; enable in the web interface)
* [Web frontend](https://github.com/toniebox-reverse-engineering/teddycloud_web) (full stack developers welcome)

## Planned
* teddyBench integration
* Toniebox 2 support

## Web UI login

Login protection is **off by default**. When enabled, the web interface requires a username and password; Toniebox cloud APIs on the box port are unchanged.

- Create users and turn login on in the web UI (Settings).
- Users are stored as salted SHA-256 hashes in `web_users.json` under the config directory.
- After five failed logins from the same IP, further attempts are blocked for 10 minutes.
- Set `TEDDYCLOUD_WEB_AUTH_DISABLE=1` to bypass login (for recovery).
- Removing `web_users.json` (no users left) turns login protection off again.
- **Still not recommended for public exposure:** the login only protects the web UI. The direct APIs are still unprotected, so do not host TeddyCloud publicly unless you know how to secure a self-hosted service (for example behind a VPN or an authenticating reverse proxy). TeddyCloud does not treat LAN and reverse-proxy traffic differently (a proxy often looks like a local client).

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

## Attribution
The icons used are from here:
* img_empty.png: https://www.flaticon.com/free-icon/ask_1372671
* img_unknown.png: https://www.flaticon.com/free-icon/ask_1923795
* img_custom.png/favicon.ico: https://www.flaticon.com/free-icon/dog_2829818

Thanks for the original authors for these great icons.
