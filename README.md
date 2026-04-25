# NetIRC Defender V3

Modular IRC security service for **P10** (ircu-style) uplinks: DNSBL checks, flood controls, G-lines, channel enforcement, optional GeoIP (`ipinfo`), console **`whois`** from the link cache, and more. Written in Perl.

**Lineage:** the codebase shares roots with the public [key2peace/defender](https://github.com/key2peace/defender) project (Defender IRC service). You do **not** need a GitHub “Fork” of that repo to publish this tree: a **standalone repository** is fine. **NetIRC Defender V3** is this project’s name and P10-focused evolution. Keep the **GPL-2.0** license file and existing copyright headers in source files when you redistribute (see [License](#license)).

## Requirements

- Perl **5.10+**. Networking uses **`Socket`** and **`IO::Socket`**, which ship with a normal Perl build as **core modules** (they are not separate CPAN installs when you use the `perl` package from your Linux distribution).
- Linux (or similar) is assumed for production; P10 link to your hub.
- **Config parsing:** this tree bundles `Config::General` and `Tie::IxHash` under `Config/` and `Tie/` — you do not install those from CPAN.
- **`dnsbl` module:** uses the same core **`Socket`** helpers (`gethostbyname` / `inet_ntoa`) for RBL DNS lookups — no **`Net::DNS`** or other CPAN DNS stack. Lists and replies are read from **`dnsbl.conf`** in your `datadir` (not committed; ship your own).

## New server: install Perl (VPS / bare metal)

Install the **`perl`** (and on some distros **`perl-modules`**) package from your distribution; you do **not** need to compile Perl from source.

**`Socket` / `IO::Socket`:** these are part of **perl-core**. A stock `apt install perl` or `dnf install perl` pulls them in, so you do not run `cpan` / `cpanm` for the IRC uplink, **dnsbl** RBL checks, or other DNS-style lookups in this codebase.

**Extra CPAN:** not required for this tree — config helpers and related code are bundled.

**Debian / Ubuntu**

```bash
sudo apt update
sudo apt install -y perl perl-modules openssl ca-certificates
perl -v   # confirm 5.10 or newer
```

**Rocky Linux / AlmaLinux / Fedora / RHEL**

```bash
sudo dnf install -y perl perl-IO-Socket-SSL openssl
perl -v
```

Then continue with [Quick start](#quick-start) (clone, `defender.conf`, run).

## Quick start

1. Clone the repository.
2. Copy the sample config and edit it:

   ```bash
   cp defender.conf.example defender.conf
   $EDITOR defender.conf
   ```

   If you add the **`version`** module to `modules=`, add rules in **`datadir/deny_version.conf`** (see `datadir` in `defender.conf`; it is often your clone/install directory):

   ```bash
   cp deny_version.conf.example /path/to/your/deny_version.conf
   $EDITOR /path/to/your/deny_version.conf
   ```

3. Run (foreground debug):

   ```bash
   perl defender.pl --debug
   ```

   Or daemon mode (default when not passing `--debug`), per `defender.pl` / `Modules/Main.pm`.

### Service control (manual)

Use **`defender.sh`** for normal operator actions (same directory as `defender.pl`):

```bash
chmod +x defender.sh
./defender.sh start    # daemon via defender.pl
./defender.sh stop     # SIGINT, then SIGKILL if needed
./defender.sh restart
./defender.sh status
```

### Watchdog (automatic, cron only)

**`checkD.sh`** is **not** a replacement for `defender.sh`: it is meant only for **cron** so the process comes back after **reboot** or **crash** (uses `nohup` + lock file). If you already start/stop by hand with `defender.sh`, keep using that; add `checkD.sh` on a timer if you want an automatic safety net.

```bash
chmod +x checkD.sh
# crontab -e — example:
* * * * * /path/to/defender-master/checkD.sh >/dev/null 2>&1
```

See the top of `checkD.sh` for `CHECKD_LOG`, `CHECKD_DEBUG`, and `CHECKD_LOG_EVERY_RUN`.

## Configuration

- **`defender.conf`** — hub `server` / `port` / `password`, `linktype=p10`, service identity (`servername`, `sid`, …), `channel` (control channel, e.g. `#console`), `modules=…`, paths, thresholds. **ipinfo** reads **`ipinfo_token`**, **`ipinfo_line_delay_ms`**, **`ipinfo_cache_ttl_sec`**, **`ipinfo_burst_limit`**, **`ipinfo_burst_window_sec`**, **`ipinfo_http_timeout_sec`** (see `defender.conf.example`). Optional **`control_channel_line_delay_ms`** (else falls back to `ipinfo_line_delay_ms`) spaces consecutive bot lines when sent within ~1.5s of each other: **PRIVMSG** to the control channel **and** **`globops`** (wallops / `WA`).
- **`defender.conf` is not committed** (see `.gitignore`); use **`defender.conf.example`** as the template.
- Other local files (under **`datadir`**, usually your install directory) that are not committed: `dnsbl.conf`, `regexp_akill.conf`, `glines.conf`, `killchans.conf`, `deny_version.conf`, `defender_persistent_counters.v1`, `seen_state.sto` (from the **seen** module), logs, `defender.pid`. Repository templates: `defender.conf.example`, `deny_version.conf.example` — copy to `datadir` and edit. A commented `cgiirc.conf` may live at the project root in this tree; the running service reads **`$datadir/cgiirc.conf`** (create or copy there if you use the **cgiirc** module). Optional: **`seen_max_entries`** in `defender.conf` (default 10000) limits last-seen records.

## Control channel & commands

Commands below are sent on the **control channel** set in `defender.conf` as **`channel`** (e.g. `#console`). Replace `<botnick>` with your configured bot nick. On the uplink, **IRC operator** status is required for most operator commands (`message.pl` and several modules call `isoper`).

### Core (`message.pl`)

| Command | Operator? | Description |
|--------|-------------|-------------|
| `help` | yes | Short index; lists each loaded module’s `cmd_help` line. |
| `help <module>` | yes | Help for one scan module name (as in `modules=`). |
| `info` | yes | Short network snapshot counts (servers / users / channels seen on the link). |
| `info help` | yes | Longer explanation of `info` subcommands and related lookups. |
| `info servers` | yes | List of server names from the P10 cache. |
| `info users` | yes | User counts grouped by uplink server. |
| `info users list` | yes | Capped flat list of cached nicks. |
| `info chans` | yes | Per-server channel name statistics (JOIN-derived; rows overlap). |
| `info chans list` / `info channels list` | yes | Capped flat list of distinct channel names seen. |
| `status` | yes | Process start time, uptime, metrics, loaded modules, link capabilities. |
| `status all` | yes | Same metrics plus **`stats`** output for **every** loaded scan module. |
| `status <module>` | yes | **`stats`** for scan modules whose name matches (e.g. `status dnsbl`). |
| `<botnick> rehash` | yes | Reload `defender.conf` and rescan module list (SIGHUP-style). |
| `<botnick> quit` | yes | Shut down Defender. |

CTCP to the bot’s nick (VERSION, TIME, …) is answered in `message.pl` with rate limiting; not specific to scan modules.

### Scan modules (`modules=`)

Only modules **listed** in `defender.conf` are active. Names must match `Modules/Scan/<name>.pm` without `.pm`.

| Module | What it does | Commands on the control channel |
|--------|----------------|----------------------------------|
| **conn_average** | Tracks connection rate; can G-line burst sign-ons. | None (automatic). Use `status conn_average` if `stats` is defined. |
| **flood** | Per-channel flood detection and temporary `+f` (and related) lock. | None (automatic). |
| **dnsbl** | Checks new users against RBL zones from `dnsbl.conf` in `datadir`. | None (automatic). |
| **nickflood** | Kills rapid nick changes (`nickflood_limit`). | None (automatic). |
| **killchan** | G-lines non-opers who **join** listed channels after a grace period. | **`killchan add #channel reason`**, **`killchan del #channel`**, **`killchan list`** — **oper**; list stored in `killchans.conf`. |
| **message** | Logs **private messages to the bot** to the control channel and auto-replies once with support channel info. | No `#console` commands (PM-only behaviour). |
| **verbose** | Announces joins/parts/modes/KILLs/etc. on the control channel. | None (automatic). |
| **gline** | Manages G-lines (local cache + IRCd); syncs GL traffic from the link. | **`gline`**, **`gline help`** — help text. **`gline add …`**, **`gline del …`**, **`gline list`**, **`gline del all`**. Shorthand: **`gline <target> [time] [reason]`** (same as `gline add`). **oper**. |
| **ipinfo** | GeoIP / host info via ipinfo.io (token in `defender.conf`). | **`ip`** or **`ip <target>`** (address, hostname, or nick) — **oper**. |
| **whois** | Snapshot from the P10 client cache (not the IRCd’s full `/WHOIS`). | **`whois <nick>`** or **`whois nick <nick>`** — **oper**. |
| **seen** | Last **quit** / **kill** for a nick, or **online** from the P10 cache. Changing nick **removes** the old nick from last-seen. | **`seen <nick>`** — **oper**; `datadir/seen_state.sto` (pruned, persisted). |
| **regexp_akill** | On sign-on, matches `nick!ident@host` + realname against regexes; G-lines on match. | **`regexp_akill add <pattern> <reason>`**, **`regexp_akill del <pattern>`**, **`regexp_akill list`** — **oper**; file `regexp_akill.conf`. |
| **cgiirc** | Detects unauthorised CGI:IRC via VERSION notices; optional `cgiirc.conf` whitelist. | None (automatic). |
| **version** | CTCP VERSION fingerprinting / `deny_version.conf` rules (when **version** is in `modules=`). | **`version ctcp-all`** — sends CTCP VERSION to `$*.net`; **oper**. Replies still filtered by `deny_version.conf`. |

To see the **exact** help string a module registers, use **`help <module>`** on the control channel (same text as in the bot output).

## Project layout (high level)

| Path | Role |
|------|------|
| `defender.pl` | Entry point |
| `message.pl` | PRIVMSG/NOTICE routing, CTCP, help text |
| `Modules/Main.pm` | Config load, module wiring |
| `Modules/Link/p10.pm` | P10 uplink |
| `Modules/Scan/*` | Scan / policy modules |
| `Modules/Log/Text.pm` | File logging (`logto=Text`) |
| `defender.sh` | Manual `start` / `stop` / `restart` / `status` |
| `checkD.sh` | Cron watchdog only (auto restart after reboot/crash) |
| `defender.conf.example` | Config template (copy to `datadir` as `defender.conf`) |
| `deny_version.conf.example` | Template for the **version** module’s `deny_version.conf` in `datadir` |

## License

This program is free software licensed under the **GNU General Public License v2.0** — see the [`LICENSE`](LICENSE) file. Running `perl defender.pl --help` also references GPL v2.

Bundled third-party code (for example under `Config/` and `Tie/`) retains its own copyright and license notices in the respective files.

## Contributing

Issues and pull requests are welcome. Do not commit secrets: keep `defender.conf`, API tokens, and hub passwords out of git (use `defender.conf.example` only for structure).

---

*Defender is an IRC network tool: use it only on networks and systems you are allowed to administer.*
