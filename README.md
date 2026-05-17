# NetIRC Defender V3 - P10 IRC Security Service (Perl)

[![License: GPL-2.0](https://img.shields.io/badge/License-GPL--2.0-blue.svg)](LICENSE)
![Language: Perl](https://img.shields.io/badge/Language-Perl-39457E)
![Link Protocol: P10](https://img.shields.io/badge/Link-P10-informational)
![Platform: Linux](https://img.shields.io/badge/Platform-Linux-success)

NetIRC Defender V3 is a modular **IRC security service** for **P10 / ircu-style uplinks**.  
It provides production-focused abuse controls for IRC networks: DNSBL checks, flood protection, G-line automation, channel policy enforcement, optional GeoIP lookups, and operator tooling (`info`, `status`, `whois`, `seen`) backed by link-side cache data.

If you run or secure an IRC network, this project is designed as a practical **IRC defender bot / service** with low external dependencies and predictable operations.

## Highlights

- **P10-native architecture** for ircu-style server links.
- **Modular scan pipeline** (`Modules/Scan/*`) with configurable policy order.
- **Abuse mitigation toolkit**: DNSBL, nick flood, channel enforcement, regex akill, CGI:IRC detection.
- **Operator-first control channel UX** with structured help, status, and live link insights.
- **Perl core friendly** runtime (bundled config helpers, minimal CPAN friction).
- **GPL-2.0 licensed** and straightforward to deploy on Linux servers.

**Relevant search terms:** `irc security`, `irc defender`, `p10`, `ircu`, `dnsbl`, `gline`, `irc services`, `perl`.

## Table of contents

- [Requirements](#requirements)
- [Support matrix](#support-matrix)
- [New server: install Perl (VPS / bare metal)](#new-server-install-perl-vps--bare-metal)
- [Quick start](#quick-start)
- [Configuration](#configuration)
- [Control channel & commands](#control-channel--commands)
- [Troubleshooting](#troubleshooting)
- [Project layout (high level)](#project-layout-high-level)
- [Security](#security)
- [License](#license)
- [Contributing](#contributing)

## Project lineage

The codebase shares roots with the public [key2peace/defender](https://github.com/key2peace/defender) project (Defender IRC service). You do **not** need a GitHub fork of that repository to publish this tree: a standalone repository is fine.  
**NetIRC Defender V3** is this project's P10-focused evolution. Keep the **GPL-2.0** license file and existing copyright headers in source files when redistributing (see [License](#license)).

## Requirements

- Perl **5.10+**. Networking uses **`Socket`** and **`IO::Socket`**, which ship with a normal Perl build as **core modules** (they are not separate CPAN installs when you use the `perl` package from your Linux distribution).
- Linux (or similar) is assumed for production; P10 link to your hub.
- **Config parsing:** this tree bundles `Config::General` and `Tie::IxHash` under `Config/` and `Tie/` — you do not install those from CPAN.
- **`dnsbl` module:** uses the same core **`Socket`** helpers (`gethostbyname` / `inet_ntoa`) for RBL DNS lookups — no **`Net::DNS`** or other CPAN DNS stack. Lists and replies are read from **`dnsbl.conf`** in your `datadir`. Use **`dnsbl.conf.example`** in the repository as a template (copy to `datadir/dnsbl.conf` and replace with zones you are allowed to query).

## Support matrix

| Component | Status |
|---|---|
| Link protocol | **P10 / ircu-style uplinks** |
| Runtime | **Perl 5.10+** |
| OS target | **Linux production** (Unix-like environments also possible) |
| Dependency model | **Perl core first**, bundled config helpers |
| Deployment mode | Foreground debug and daemon mode |

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
2. Copy the sample config next to **`defender.pl`** and edit it (`defender.conf` is always loaded from that directory, not from `datadir`):

   ```bash
   cp defender.conf.example defender.conf
   $EDITOR defender.conf
   ```

   If you add the **`version`** module to `modules=`, add rules in **`datadir/deny_version.conf`** (see `datadir` in `defender.conf`; it is often your clone/install directory):

   ```bash
   cp deny_version.conf.example /path/to/your/deny_version.conf
   $EDITOR /path/to/your/deny_version.conf
   ```

   If **`dnsbl`** is in `modules=`, create **`datadir/dnsbl.conf`** (Config::General; one block per RBL zone). You can start from the template:

   ```bash
   cp dnsbl.conf.example /path/to/your/dnsbl.conf
   $EDITOR /path/to/your/dnsbl.conf
   ```

   **Optional — `regexp_akill`:** not enabled in the default **`modules=`** list in `defender.conf.example`. If you add **`regexp_akill`** to `modules=`, create **`datadir/regexp_akill.conf`** (the module logs if the file is missing). Template:

   ```bash
   cp regexp_akill.conf.example /path/to/your/regexp_akill.conf
   $EDITOR /path/to/your/regexp_akill.conf
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

- **`defender.conf`** — hub `server` / `port` / `password`, `linktype=p10`, service identity (`servername`, `sid`, …), `channel` (control channel for operator commands), `modules=…`, paths, thresholds. On connect, **`verbose`** + **`version`** `scan_user` are always run before other modules (so **`dnsbl`** does not delay “Signed on” or CTCP VERSION); on quit / join / part / kill / nick change, **`verbose`** runs before the rest so **`seen`** (disk) and other hooks do not delay “Signed off” and similar lines. Optional **`control_channel_line_delay_ms`** spaces consecutive **PRIVMSG** to the control channel and **`globops`** when sends are within ~1.5s; **unset means no delay** (older trees mistakenly reused **`ipinfo_line_delay_ms`** for that — it is not used by **`ipinfo`** here). Automatic profile switch is controlled by **`attack_mode_auto`**, **`attack_mode_enter_conn_per_min`**, **`attack_mode_hold_sec`**. **dnsbl** reads **`dnsbl_cache_ttl`**, **`dnsbl_query_timeout_sec`**, **`dnsbl_cb_trigger_conn_per_min`**, **`dnsbl_cb_trigger_timeouts_per_min`**, **`dnsbl_cb_cooldown_sec`**, **`dnsbl_backlog_skip_ttl_sec`** plus `attack_...` overrides. **ipinfo** reads **`ipinfo_token`**, **`ipinfo_cache_ttl_sec`**, **`ipinfo_burst_limit`**, **`ipinfo_burst_window_sec`**, **`ipinfo_http_timeout_sec`** (see `defender.conf.example`).
- **`defender.conf` is not committed** (see `.gitignore`); use **`defender.conf.example`** as the template.
- **Under `datadir`** (see `datadir=` in `defender.conf`), usually not committed: `dnsbl.conf`, `regexp_akill.conf`, `glines.conf`, `killchans.conf`, `deny_version.conf`, `defender_persistent_counters.v1`, `seen_state.sto` (from the **seen** module). **Beside `defender.pl`:** `defender.conf`, **`defender.pid`**, and (if `logto=Text`) the file at **`logpath`** — often the same folder as `datadir`, but paths are independent. Templates: **`defender.conf.example`** → **`defender.conf`** next to **`defender.pl`**; **`deny_version.conf.example`**, **`dnsbl.conf.example`**, **`regexp_akill.conf.example`** → **`datadir`** with the names above. A commented `cgiirc.conf` may live at the project root in this tree; the running service reads **`$datadir/cgiirc.conf`** (create or copy there if you use the **cgiirc** module). Optional: **`seen_max_entries`** in `defender.conf` (default 10000) limits last-seen records.

## Control channel & commands

Commands below are sent on the **control channel** set in `defender.conf` as **`channel`**. Replace `<botnick>` with your configured bot nick. On the uplink, **IRC operator** status is required for most operator commands (`message.pl` and several modules call `isoper`).

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
| `<botnick> shutdown` | yes | Shut down Defender. |

CTCP to the bot’s nick (VERSION, TIME, …) is answered in `message.pl` with rate limiting; not specific to scan modules.

### Scan modules (`modules=`)

Only modules **listed** in `defender.conf` are active. Names must match `Modules/Scan/<name>.pm` without `.pm`.

**Order:** for each new client, `scan_user` runs in list order until a module calls `gline()` (that increments an internal counter and **skips** remaining modules for that client). Keep **`conn_average`** (and any other always-on counters) **before** modules that may G-line from `scan_user` (**`dnsbl`**, **`regexp_akill`**, **`cgiirc`**, etc.) so connection-rate stats stay accurate.

| Module | What it does | Commands on the control channel |
|--------|----------------|----------------------------------|
| **conn_average** | Counts sign-ons per minute; if above `conn_average_max`, sends **GLOBOPS**; if `conn_average_mirror_console` is not `0`, repeats the warning on the control channel. Can auto-enable global attack mode and (optionally) force emergency G-lines while attack mode is active. | None (automatic). Use `status conn_average` if `stats` is defined. |
| **dnsbl** | Checks new users against RBL zones from `dnsbl.conf` in `datadir`. | None (automatic). |
| **version** | CTCP VERSION fingerprinting / `deny_version.conf` rules (when **version** is in `modules=`). G-line duration for `G` rules is fixed in code (86400s). Global outbound CTCP limiting is configurable via `version_ctcp_global_burst`, `version_ctcp_global_window_sec`, `version_ctcp_global_mute_sec` (and `attack_...` overrides while attack mode is active). | **`version ctcp-all`** — sends CTCP VERSION to `$*.net`; **oper**. Replies still filtered by `deny_version.conf`. |
| **regexp_akill** | On sign-on, matches `nick!ident@host` + realname against regexes; G-lines on match (~600s). **Off by default** — add **`regexp_akill`** to `modules=` and maintain `regexp_akill.conf` if you use it. | **`regexp_akill add <pattern> <reason>`**, **`regexp_akill del <pattern>`**, **`regexp_akill list`** — **oper**; file `regexp_akill.conf`. |
| **flood** | Per-channel flood detection and temporary `+f` (and related) lock. | None (automatic). |
| **nickflood** | Kills rapid nick changes (`nickflood_limit`). | None (automatic). |
| **killchan** | G-lines non-opers who **join** listed channels after a grace period. | **`killchan add #channel reason`**, **`killchan del #channel`**, **`killchan list`** — **oper**; list stored in `killchans.conf`. |
| **message** | Logs **private messages to the bot** to the control channel and auto-replies once with support channel info. | No control-channel commands (PM-only behaviour). |
| **verbose** | Announces joins/parts/modes/KILLs/etc. on the control channel. | None (automatic). |
| **gline** | Manages G-lines (local cache + IRCd); syncs GL traffic from the link. | **`gline`**, **`gline help`** — help text. **`gline add …`**, **`gline del …`**, **`gline list`**, **`gline del all`**. Shorthand: **`gline <target> [time] [reason]`** (same as `gline add`). **oper**. |
| **ipinfo** | GeoIP / host info via ipinfo.io (token in `defender.conf`). | **`ip`** or **`ip <target>`** (address, hostname, or nick) — **oper**. |
| **whois** | Snapshot from the P10 client cache (not the IRCd’s full `/WHOIS`): user/host, IP, account if known, sign-on, server, channels, privileges. The command also requests live IRCd WHOIS **away** (`301`), **idle** (`317`) and **account** (`330`) and prints them when received. | **`whois <nick>`** or **`whois nick <nick>`** — **oper**. |
| **seen** | Last **quit** / **kill** for a nick, or **online** from the P10 cache (server/channels). For online users it can trigger live IRCd **away** lookup to correct stale pre-link away state. Changing nick **removes** the old nick from last-seen. | **`seen <nick>`** — **oper**; `datadir/seen_state.sto` (pruned, persisted). |
| **cgiirc** | Detects unauthorised CGI:IRC via VERSION notices; optional `cgiirc.conf` whitelist. | None (automatic). |

To see the **exact** help string a module registers, use **`help <module>`** on the control channel (same text as in the bot output).

**Away / live WHOIS data:** away state in the P10 cache is accurate after relevant `A` lines have been seen while Defender is linked. Users already away before link-up can be stale; **whois** now asks IRCd live away (`301`) and **seen** can request live away for online users, so displayed state is corrected on demand. **whois** also asks for live idle (`317`) and account (`330`); if idle reply does not arrive within timeout, it reports `n/a (IRCd timeout)`.

## Troubleshooting

- **`(unknown)` in `info users` / `info chans`:** restart Defender after deploying parser/cache fixes so old runtime cache does not pollute new stats.
- **No output from a module command:** verify the module is listed in `modules=` and check `help <module>` / `status <module>`.
- **DNSBL not triggering:** confirm `datadir/dnsbl.conf` exists, zones are valid, and your network is allowed to query those RBL providers.
- **Service not staying up:** use `./defender.sh status` and (optionally) cron with `checkD.sh` as watchdog.
- **GeoIP / ipinfo issues:** validate `ipinfo_token` and timeout/rate settings in `defender.conf`.

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
| `defender.conf.example` | Config template: copy to **`defender.conf`** in the **same directory as `defender.pl`** (not necessarily `datadir`; see `datadir=` for policy files) |
| `deny_version.conf.example` | Template for the **version** module’s `deny_version.conf` in `datadir` |
| `dnsbl.conf.example` | Template for **`dnsbl.conf`** (Config::General: RBL zones, `duration`, `reason`, `<reply>`) |
| `regexp_akill.conf.example` | Template for **`regexp_akill.conf`** (tab: regex, reason); use only if **`regexp_akill`** is in `modules=` |

## Security

- Treat `defender.conf`, hub passwords, and API tokens as secrets; never commit them.
- Keep Defender on trusted infrastructure and restrict shell access to operators.
- Use least privilege for runtime accounts and filesystem permissions.
- Apply changes in staging first when adjusting aggressive modules (`dnsbl`, `regexp_akill`, `killchan`, `gline`).
- This tool is for authorized network administration only.

## License

This program is free software licensed under the **GNU General Public License v2.0** — see the [`LICENSE`](LICENSE) file. Running `perl defender.pl --help` also references GPL v2.

Bundled third-party code (for example under `Config/` and `Tie/`) retains its own copyright and license notices in the respective files.

## Contributing

Issues and pull requests are welcome. Do not commit secrets: keep `defender.conf`, API tokens, and hub passwords out of git (use `defender.conf.example` only for structure).

---

*Defender is an IRC network tool: use it only on networks and systems you are allowed to administer.*
