# Remote Docker Deploy Script

`deploy.sh` is a one-shot, **idempotent** Bash script that automates deploying a Dockerized app to a **remote Linux server**, fronts it with **Nginx**, and logs everything for troubleshooting.

## Features

- ✅ Collects & validates inputs (repo URL, PAT, SSH details, branch, app port)
- ✅ Clones/updates your repo locally (PAT optional for public repos)
- ✅ Prepares remote host (Docker, Compose, Nginx, rsync, curl)
- ✅ Syncs project to `/opt/<app-name>` (configurable)
- ✅ Builds & runs (Compose if present; else Dockerfile path)
- ✅ Adds Nginx reverse proxy (port 80 → `127.0.0.1:<APP_PORT>`)
- ✅ Validates via `curl` (on server and from your machine)
- ✅ Logs to `./logs/deploy_YYYYMMDD_HHMMSS.log`
- ✅ Safe to re-run (cleans old containers/orphans). `--cleanup` to remove all.

---

## Prerequisites

**Local (where you run the script)**  
- Bash (macOS/Linux), `git`, `ssh`, `rsync`, `curl`
- Network access to the server over SSH (port 22 or port-forwarded)
- GitHub **PAT** (if your repo is private). For public repos you can pass `--pat x`

**Remote (the target server)**  
- Linux distro with `apt`, `dnf`, or `yum` (Ubuntu/Debian/CentOS/Fedora/RHEL)
- `sudo` privileges
- Port **80** open to the internet (for HTTP; add 443 after TLS)
- Your app listens on a known **internal port** (e.g., 8080)

---

## Quick Start

```bash
chmod +x deploy.sh

./deploy.sh \
  --repo https://github.com/<ORG>/<REPO>.git \
  --pat  <PAT_or_x_for_public> \
  --branch main \
  --ssh-user <USER> \
  --ssh-host <IP_or_DNS> \
  --ssh-key ~/.ssh/<KEYFILE> \
  --port <APP_INTERNAL_PORT>
