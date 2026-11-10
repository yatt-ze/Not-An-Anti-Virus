# `navd` privileged-daemon threat model

Adversarial review of the planned root daemon, written 2026-11-09 against
commit `b15a64e` (v0.4.0, design doc v0.90).

This is a review, not a design change. Nothing under `docs/design/` was
edited; §8 lists the edits it proposes. The phase-0b A2 plan already says
"scanning as root is a threat surface … the threat model is a real Phase 2
item" — this is that item, done before Stage C wires an event source to the
scanner.

Every finding is marked **EXISTING** (in the code at this commit) or
**PLANNED** (a risk in functionality the design describes but nobody has
built). Planned risks are not vulnerabilities today.

## 1. Conclusions

1. **The installed daemon has no exploitable surface today.** Bare `navd` is
   a stay-alive loop: it reads no file, opens no socket and spawns nothing
   (`crates/navd/src/daemon.rs`). I found no way for an unprivileged user to
   influence it.
2. **The scanner is not safe to run as root over files another user
   controls, and that is reproducible now.** A root `navd scan-once` over a
   directory owned by an unprivileged user was made to read a root-only file
   outside that directory (twice, by two different swaps) and to hang
   forever (§5, E1–E2). Today this is reachable only when someone runs the
   scanner as root by hand (`sudo navctl scan`, `sudo navd scan-once`).
3. **The design as written would turn that into a privilege boundary
   failure.** §2 has root `navd` link `nav-core` and scan event paths
   in-process. Built that way, a local user gets: a root reader with Full
   Disk Access pointed at any file they name (R1), parsing of their bytes by
   Apple's C/C++ tools at uid 0 (R7), and — once quarantine exists — a root
   file move and a root file write at a path they steer (R4). Those are the
   three to design out first.
4. **Yes, the scanning engine should be a separate, unprivileged, sandboxed
   process.** Nothing in static analysis needs uid 0 once a readable file
   descriptor exists. The recommended shape (§7) is a small root broker that
   never parses file content, opens files *as the user who owns the watched
   location*, and hands the descriptor to a throwaway worker.
5. **Several current choices are right and should be kept as rules:**
   members are read in memory and never extracted to disk; the walker and
   bundle resolver do not follow symlinks; `hdiutil` is pinned to an
   absolute path with a timeout, an output cap and empty stdin; the scratch
   root is checked for ownership and mode; the daemon never mounts an image
   on its own (§6); a notification action carries an opaque finding id and a
   nonce, never a path (§9.2); the LaunchDaemon runs a root-owned copy.

## 2. What exists and what is planned

| Component | State at `b15a64e` | Runs as | Reads attacker-controlled input? |
|---|---|---|---|
| `navd` (LaunchDaemon) | Stay-alive loop only | root | No |
| `navd scan-once` | Temporary B3 spike instrument | whoever runs it (root in the spike) | Yes, whatever path it is given |
| `navctl scan` / `rules test` | Built | invoking user (root under `sudo`) | Yes |
| Disk-image mounting | Built, in `navctl` only | invoking user | Yes (`hdiutil`, kernel filesystem) |
| `navctl service install/uninstall` | Built | root | The `navd` file beside `navctl` |
| Event sources (FSEvents, DiskArbitration) | Planned, Phase 0b Stage C | root | — |
| Socket, verdict cache, event log | Planned, Phase 0b–3 | root | — |
| `navnotify`, notification actions | Planned (stub prints "not implemented") | per user | — |
| Quarantine, allowlist, config | Planned, Phase 3 | root | — |
| Daemon scratch mount, `.pkg` payload extraction | Planned (§6.2) | root | — |
| Packet capture | Planned, Phase 0c/2 | root | — |

## 3. Threat model

**Attacker.** An ordinary local account with no admin rights and no `sudo`.
It can create files, directories, symlinks, hard links, FIFOs, archives,
packages and disk images anywhere it can write, rename them at any moment,
mount its own disk images and network shares, and run code continuously. It
also stands for malware running as the logged-in user, which is NAV's stated
primary threat (§1) and, on most Macs, is in the `admin` group without
knowing the password.

**What it wants.** (a) Read data it cannot read: other users' files, root-only
files, TCC-protected data that `navd`'s Full Disk Access grant unlocks.
(b) Write, move or delete a file as root. (c) Run code as root. (d) Blind NAV:
stall it, crash it, starve it, or make it report its own malware clean.
(e) Make NAV act against a victim: a false alert, or a quarantine of a file
the victim needs.

**Assets.** uid 0 itself; the FDA grant attached to `navd`'s code identity;
every file root can read; the event log and verdict history (paths,
hostnames, process arguments of all users); the allowlist, config and
ruleset; the integrity of verdicts and notifications.

**Trust boundaries.** Unprivileged user → root daemon. User A → user B
through the daemon. File content → the process that parses it. A path string
→ the object it names at the moment it is used. Client → socket method.
Scanner output → the terminal, log or notification that renders it.

**Not covered.** A remote network attacker except where noted (packet
parsing, R7), kernel filesystem bugs as such, physical access, and the
dev-only `sudo cargo xtask verify --real` runner.

## 4. The planned flow and where each trust decision sits

| Step | Design text | Attacker controls | What goes wrong if done naively |
|---|---|---|---|
| 1. Event | FSEvents reports "a change at this path" (§4.1, §4.2) | The path string (any bytes), how many events, when | Flooding and starvation (R12). Newlines and escapes in paths reach logs (#156). |
| 2. Queue | Not specified | Volume, timing | No dedupe, fairness or loss accounting is specified. |
| 3. Open | "Scan through an opened file descriptor" (§11.7) | What the path names by the time it is opened | Root follows a symlink, hard link or swapped parent (E1, R1, R2). A FIFO blocks (E2). |
| 4. Parse | `navd` links `nav-core` (§2, §3) | Every byte | A crash or stall is a daemon outage (R13). |
| 5. Path tools | `codesign`, `spctl`, `xattr` by path (§5.2) | The object at the path, again, later | A second and third resolve of the same path; Apple parsers at uid 0 (R7, R8). |
| 6. Mount | Daemon scratch mount under `/private/var/navd/scratch` (§6.2) | The image | Root mounts a filesystem the attacker built (R9). |
| 7. Report | Verdict cache, event log, socket, `navnotify` (§2, §9) | File names, content-derived strings in signal text | Disclosure to the wrong user (R1, R10, R11). Spoofed verdicts (R6). |
| 8. Act | Quarantine, restore, one-click action (§7, §9.2) | The path between verdict and action | Root moves or writes the wrong file (R4). |

## 5. Existing weaknesses

Checked at `b15a64e`. "Run" means reproduced in this review on Linux with a
root scanner and an attacker at uid 65534; "read" means found by reading and
not executed, usually because it needs macOS.

| Id | Weakness | Evidence | Reach today | Tracked |
|---|---|---|---|---|
| E1 | A path swapped after the directory listing is followed, at the last component or any parent, and the target is read with the scanner's privileges | Run | Scanner run as root by hand over a directory another user can write | New. #161 covers only the FIFO half |
| E2 | A file swapped for a FIFO blocks the scan forever, and results already computed are lost | Run | Same | #161 |
| E3 | `service install` trusts the `navd` beside `navctl`, and the copy inherits that file's metadata | Read | Whoever can write `navctl`'s directory, when an admin runs `sudo navctl service install` | #163, #157, #24; the metadata point is new |
| E4 | State directory is `0755` and launchd creates the log files world-readable | Read | No impact while the logs hold one start line | #163 |
| E5 | `navctl` mounting as root: checks and attach resolve the image path separately; scratch root falls back to `/tmp` | Read | `sudo navctl scan x.dmg` | New, low |
| E6 | `codesign`/`spctl` have no timeout or output cap; tools resolved through `PATH`; a leading `-` in a path is an option; raw paths in terminal output | Read | `navctl` users today | #158, #157, #162, #156 |

### E1. Root follows a swapped path (EXISTING, low today)

`collect_files` decides what is a regular file from `DirEntry::file_type()`
at listing time (`target.rs:321`), collects the whole tree, sorts it
(`:349`), and only then scans each path in order (`:260`).
`ScanContext::load_if` opens each one with a plain `File::open(path)`
(`context.rs:155`): symlinks are followed in every component and nothing
checks what was opened. The window is not a race. It is as long as the scan
of every file sorted earlier, so one large file sorted first gives the
attacker seconds to minutes.

Reproduction (debug build, `navd scan-once --json` as root; `watched/` is
owned by uid 65534 and holds a 500 MiB sparse `a_slow.bin` and a six-byte
`z_note.txt`; `root-secret.sh` is mode `0600`, owned by root, outside
`watched/`):

```
# one second after the scan starts, as uid 65534:
ln -s …/root-secret.sh watched/.swap && mv -fT watched/.swap watched/z_note.txt

a_slow.bin  score=0  no-action
z_note.txt  score=19 notify
    suspicious-strings 19 | matched 3 indicator(s): download piped to a shell; …
```

The verdict printed for the attacker's path describes the root-only file.
The same result came from swapping a parent instead (`watched/sub` renamed
aside and replaced by a symlink to a `0700` root directory, with
`--recursive`): `watched/sub/inner.txt` scored 19 from a file the attacker
cannot reach.

On macOS the scan then resolves the same path again, each time
independently: `xattr::get` (`quarantine_xattr.rs:43`), `canonicalize`
(`container.rs:149`), and up to four `codesign`/`spctl` runs. The §11.7
identity check does not catch this case. It compares the opened handle with
a later `stat` of the path, and both see the symlink's target, so they
agree.

**Why low today:** the reader is root only when a person runs the scanner as
root, and the output goes to that person, not to the attacker. It is listed
because it is the exact code path §2 has the daemon call. #161's proposed
fix (`O_NONBLOCK` plus an `is_file` check on the handle) closes E2 but not
E1: a symlink to a regular file passes both.

### E2. FIFO swap hangs the scan (EXISTING, tracked in #161)

Same setup, swapping in a FIFO: the scan was still blocked in `open` when a
60-second limit killed it (the same directory scans in 39 seconds
untouched), and it had printed nothing, because results are emitted only
after the whole target is scanned. #161 said "not reproduced as a race";
with a slow file sorted first no race is needed.

### E3. Install trusts and inherits from the source `navd` (EXISTING, hardening)

#163 already states the main point: the copy source is user-writable under
both documented installs, and that is the same trust as `sudo navctl`
itself. Two details are not in the issue:

- On macOS `std::fs::copy` clones the file (`fclonefileat`) or falls back to
  `fcopyfile` with `COPYFILE_ALL` (`orchestrate.rs:58`). Either way the copy
  carries the source's ACL and extended attributes, and a clone made by root
  also keeps the source's owner. The following `chmod 0755` and `chown
  root:wheel` reset mode and owner but not an ACL. An access-control entry
  on the source that grants its owner write would then sit on the root
  daemon's binary. Whether `codesign -f` replaces the file and drops it was
  not tested. This needs a Mac to confirm.
- `navd_src.is_file()` follows symlinks, so a `navd` that is a symlink to a
  root-only file is copied to a world-readable `0755` path.

Neither crosses a boundary the attacker does not already hold, since the
same person can replace `navctl`. They matter because the root-owned copy is
meant to be independent of the user-writable source after install.

### E5. `navctl` disk-image mounting under `sudo` (EXISTING, low, read only)

- `isencrypted`, `imageinfo`, `attach` and `nav-core`'s probe each open the
  image by path (`diskimage.rs:148`, `:155`, `:180`). Swapping the file
  between them makes the 16 GiB / 64 GiB limits and the encryption check
  advisory.
- No option states how ownership and setuid bits on the image are treated,
  and nothing checks the resulting mount flags. For a user this is the
  system default. For root it should be asserted, not assumed (R9).
- `scratch_root` is `temp_dir()/navctl-scratch` (`:313`). Where `TMPDIR` is
  unset, which I expect under `sudo`, that is `/tmp/navctl-scratch`. Any
  user can create that directory first. The ownership check then refuses to
  mount, so the result is `Partial` with a reason: it fails closed, but one
  user can switch off image mounting for root.

## 6. Risks in planned functionality

None of this is built. Each risk says what the design text permits and what
would have to be true for the attack to work. Severity is "if built as the
design currently reads".

### Q1. Can a user steer root to files outside the scan target?

**R1. Root with Full Disk Access as a confused deputy (PLANNED, high).**
FSEvents delivers a path string seconds after the fact. If `navd` hands it
to `scan_target`, E1 applies with three differences: the reader is root with
FDA, it runs without anyone asking, and the result is reported somewhere the
attacker may see. The attacker creates `~/Downloads/a`, then replaces it
with a symlink to `/Users/victim/Library/Mail/…`, a browser profile, or
`/etc/master.passwd`.

What comes back is not the bytes but it is not nothing. Signal descriptions
embed strings taken from the file: a launchd plist's program path
(`persistence.rs:93`), dylib and rpath strings and entitlement keys
(`macho_structure.rs`), up to ten ZIP member names of up to 256 characters
each (`zip_member.rs`), install-script names (`package.rs`). The verdict
itself answers yes/no questions about content ("does it mention `TCC.db`",
"is it a signed Mach-O", "is it a ZIP holding a script"). §11.7 proposes
binding a digest of the scanned bytes into the result; shown to the wrong
user, that confirms any guess at the content.

**R2. Hard links (PLANNED, medium, needs a Mac).** `O_NOFOLLOW` does nothing
against a hard link. If macOS lets a user link a file they cannot read into
a directory they own (it has no documented equivalent of Linux's
`protected_hardlinks`; verify per supported version), the daemon scans
another user's inode under the attacker's name with no symlink anywhere.

**R3. Passive volume inventory (PLANNED, medium).** §6.1 has the daemon
enumerate a volume the user mounted. That is a directory walk over a
filesystem the attacker built, so E1's list-then-open gap applies, plus
symlinks on the volume that point back into the host.

### Q2. Symlink, hard-link and TOCTOU attacks on privileged operations

**R4. Quarantine and restore (PLANNED, critical).** This is the class that
has repeatedly produced local root in antivirus products. As designed, the
finding id and nonce stop a forged *request* (§9.2), but nothing says how
the file operation itself is made safe.

- *Quarantine moves the wrong file.* NAV alerts on `~/Downloads/d/evil`. The
  attacker renames `d` aside and puts a symlink to `/etc` or to another
  user's directory in its place. `rename` does not follow a final symlink
  but does follow every parent. Root moves `/etc/<name>` into quarantine.
  With auto-quarantine on, no click is needed.
- *Restore writes where the attacker points.* The attacker gets its own file
  quarantined from `~/x/com.evil.plist`, replaces `~/x` with a symlink to
  `/Library/LaunchDaemons`, and asks for a restore. Root writes
  attacker-chosen content under an attacker-chosen name into a directory
  launchd runs as root at boot.
- *The verdict is about different bytes.* The scan read the file at one
  moment; the action happens later, on a name.

**R5. Extraction to scratch as root (PLANNED, critical if built in the
daemon).** §6.2 plans "archives extracted to scratch space" and a bounded
`.pkg` payload extraction. Writing members to disk as root brings the whole
archive-extraction class: `../` and absolute member names, a symlink member
followed by a later member that writes through it, hard-link members, device
nodes, and ownership and setuid bits taken from a cpio or pax header. A
setuid-root file landing anywhere a user can reach is local root.

**R6. Unprivileged writes into root-owned state (PLANNED, medium).** §2 has
`navctl` push its own verdict to the daemon's log and verdict cache "for
unified history". That lets any client that can connect invent verdicts: a
fake "clean" for a path (harmful if the cache is ever consulted to skip a
scan or shown as history), a fake alert about a victim's file (with a
quarantine button under it), and unbounded log growth.

### Q3. Does parsing attacker files as root create an avoidable escalation path?

**R7. Yes, mainly through code that is not `nav-core` (PLANNED, medium
likelihood of an outage, low likelihood but full impact for code
execution).**

- `nav-core` itself is a reasonable thing to expose: no `unsafe` (#171 would
  enforce it), hand-written bounded parsers, fuzz targets. Memory corruption
  there is unlikely. Its realistic failure is availability (R13).
- The memory-unsafe parsers on the input path are Apple's. `codesign` and
  Security.framework parse the Mach-O, the CMS blob, certificates, plists
  and the bundle's resource tree. `spctl` hands the object to `syspolicyd`.
  `hdiutil` and its helpers parse the image container, and the kernel parses
  the filesystem inside it. §3's rule "no third-party code on the
  attacker-controlled-input path" does not count these, but they read the
  same hostile bytes, and spawned from `navd` they run at uid 0.
- §3 plans a Swift/Objective-C shim calling Security.framework in-process.
  Inside a root daemon that puts C parsers of hostile input in the same
  address space as everything else `navd` holds.
- Phase 2 adds a ClientHello parser fed by packets. That input is controlled
  by remote hosts, not only local users.

Static analysis needs none of root's powers once it has a readable
descriptor, so all of the above is privilege the parser does not need.

### Q4. Can an attacker make privileged subprocesses do something unintended?

**R8. `codesign` and `spctl` as root on attacker paths (PLANNED, medium).**
Beyond what #157, #158 and #162 already track:

- Each run resolves the path again. Root's `codesign` opens whatever is
  there at that moment.
- `--deep --strict` on a bundle's main executable validates the whole
  enclosing bundle, so the attacker chooses how much root reads and hashes.
  There is no deadline.
- `spctl` assessment can contact Apple for notarization and revocation
  status. A user dropping files would be driving network lookups from a root
  daemon and loading a service the whole system shares.
- Children inherit the daemon's environment, working directory and open
  descriptors unless each is set explicitly.

**R9. `hdiutil attach` as root (PLANNED, high if a daemon mount is ever
triggered by something a user controls).** §6.2 names a daemon scratch
mount point but §6 and §9.1 say the daemon never mounts on its own and never
scans on request, so the design does not say what would trigger it. If
anything a user controls can, then:

- the image may hold a setuid-root binary and device nodes. Whether a mount
  made by root honours them depends on defaults I could not check; if it
  does and any user can reach the mount point, that is local root;
- a file dropped by a browser would get its filesystem parsed by the kernel
  with no user action, which is new exposure for remote content;
- a mount point under a `0755` directory shows one user's volume to all.

**R10. Client-named scan paths (PLANNED, high).** §2 lists "anything under
FDA-gated paths" among the cases where `navd` scans. Read as a service — a
client names a path, `navd` scans it with FDA — this is a TCC bypass and a
cross-user read oracle for every client. §9.1 says the opposite ("not for
on-demand scans"). The two sections need to agree, in §9.1's favour.

### Q5. Cross-user isolation, permissions and information leakage

**R11. Socket authorization (PLANNED, high).** §9.1 gives connection access
to "root + admin group" and defers per-method peer checks to Phase 3
hardening. Three problems:

- Malware running as the logged-in admin user is the primary threat (§1),
  and it is in the admin group. If `allowlist add`, `config set`, `notify
  disable`, `rules reload` or `quarantine restore` need only group
  membership, the first thing a sample does is allowlist itself and switch
  notifications off. §11.11 raises this for direct file edits; the socket is
  the same hole.
- Every admin-group process can read every user's events: file names in
  other users' home directories, hostnames, process arguments.
- Standard users cannot connect at all, so `navctl status` and `events tail`
  do not work for them, which will create pressure to loosen the mode.

Smaller items under this question, not numbered separately:

- *State on disk.* E4 becomes real the day `navd` logs a scanned path. The
  planned SQLite log (§11.4) adds `-wal` and `-shm` files created under the
  process umask.
- *Notification routing.* A verdict about user A's file posted in user B's
  session discloses A's path, and B's click would act on A's file. §14
  leaves multi-user behaviour open.
- *Mount and scratch names.* Mount points and image paths are visible to all
  users through `mount` and `hdiutil info`.

### Q6. Denial of service against the daemon

**R12. Starvation as evasion (PLANNED, high).** The useful DoS is not a
crash but a delay: flood the queue from one account, then drop the real
payload, so its verdict arrives late or never. One event is cheap for the
attacker and expensive for NAV. A single file can cost two 512 MiB streams,
a 64 MiB ranged-read allowance and a 256 MiB archive read-back, and a
directly named file does not consult the scan budget at all (§11.12). Sparse
files make the bytes free: the 500 MiB file in §5 occupied no disk and cost
39 seconds of CPU in a debug build. Touching it re-queues it.

**R13. Crash loop (PLANNED, medium).** A panic, a stack overflow or an
out-of-memory abort in an in-process parser kills the daemon. launchd
restarts it; if the event stream is replayed from the last saved position,
the same file is scanned again. `catch_unwind` (which §3 already rejects)
does not catch aborts.

**R14. Operations that never return (PLANNED, medium).**

- FIFOs (E2), and `codesign`/`spctl` with no deadline (#158).
- A filesystem that stops answering: a network share or user-space
  filesystem the attacker serves. A thread blocked in the kernel cannot be
  cancelled; only a process can be abandoned. A user-space filesystem can
  also return different bytes to root than to the user who later runs the
  file, which no descriptor discipline fixes.
- Cloud-backed placeholder files: reading one makes the system download it.

**R15. Smaller items.** Unrotated launchd log files and an unbounded
quarantine store fill the disk. A verdict cache keyed on values the file's
owner can set (path, size, mtime) lets an attacker change content, restore
the mtime and reuse a clean verdict.

### Q7. Should the engine run in a separate, unprivileged or sandboxed process?

Yes. §7 gives the shape. The argument in one paragraph: the daemon needs
root for three things — seeing every user's filesystem events, opening
files behind TCC with its FDA grant, and (later) opening `/dev/bpf` and
moving files into quarantine. None of them is parsing. Every parsing step
needs only bytes. Splitting on that line removes R7 and R13 outright, turns
R8 into an unprivileged child working on a private copy, and makes R14 a
killed worker and one `Indeterminate` verdict.

## 7. Recommended architecture

```
 FSEvents / DiskArbitration ── path strings, treated as hints ──┐
                                                                ▼
┌────────────────────────────────────────────────────────────────────┐
│ navd — root, holds the FDA grant. Parses no file content.          │
│  queue: dedupe by (dev, inode), per-uid fair share, loss counted   │
│  opener: drop to the owning uid → open → fstat → identity          │
│  owns: socket + authorization, event log, verdict store, policy    │
└───────────────┬───────────────────────────────────▲────────────────┘
   read-only fd + job id (SCM_RIGHTS)                │ fixed-schema, size-capped verdict
┌───────────────▼───────────────────────────────────┴────────────────┐
│ scan worker — dedicated unprivileged uid, sandboxed, no network,   │
│ no filesystem beyond its scratch, deadline enforced by the broker  │
│  nav-core on the descriptor; codesign/spctl on a private clone     │
└────────────────────────────────────────────────────────────────────┘
```

**A. The broker never opens a user-influenced path as root.** For each job
it determines the uid that owns the watched location (the home directory
owner; for a mounted volume, the user who mounted it; a fixed unprivileged
uid for world-readable system locations such as `/Library/LaunchAgents`) and
performs the open with that user's credentials, in a short-lived child that
drops privileges permanently and sends the descriptor back. The kernel then
enforces the boundary: a symlink, hard link or swapped parent that leads to
something that user cannot read fails with `EACCES`. This closes R1, R2 and
R3 by construction instead of by checks. TCC grants follow code identity,
not uid, so the FDA grant should still apply; this is the first spike to
run (§9).

**B. The object is the descriptor, never the path.** Open with no symlink
following in any component, non-blocking, close-on-exec. Then `fstat`:
regular file only; record device, inode, size, mtime and ctime. Everything
after this reads through the descriptor. Files that would be fetched on read
are reported as not scanned. Only local volumes are scanned automatically.

**C. The worker.** One dedicated role account created at install, never the
file's owner (a same-uid process could stop or kill it). It sandboxes itself
before reading any job: no network, no file access outside its scratch
directory, exec limited to the Apple tools it needs. One job per process, or
recycled after a small number. The broker enforces a wall-clock deadline and
kills on expiry; a killed or crashed worker yields `Indeterminate` for that
object and a poison record keyed by identity so a restart does not retry it
immediately.

**D. Path-only tools run on a snapshot.** The worker clones the descriptor
into its scratch directory (a copy-on-write clone on the same APFS volume,
a bounded copy otherwise) and runs `codesign`/`spctl` on the clone, by
absolute tool path, with a cleared environment, a deadline and an output
cap. The object verified is then the object scanned, which is the "real
close" §11.7 defers. Bundle-seal validation needs the whole bundle; in
daemon mode report it as not checked rather than walking the attacker's tree
by path.

**E. The broker does not trust the worker.** Verdicts come back in a fixed
schema with caps on counts and string lengths. The broker attaches the path
and owner it recorded for the job id; the worker cannot name a path. All
strings are escaped before they reach a log, a terminal or a notification.

**F. No disk extraction and no mounting in the daemon.** Keep the current
in-memory member reading as the rule. Keep image mounting where it is, in
`navctl`, as the invoking user. Delete the daemon scratch mount from §6.2
unless a concrete trigger is designed; if one ever is, attach without
mounting, mount explicitly read-only with setuid and device files disabled
and ownership ignored, verify the flags on the result, and keep the mount
point under a `0700` directory.

**G. Socket.** Check the peer's credentials on every connection from the
first commit that adds the socket, not in Phase 3. Three tiers:

| Tier | Methods | Who |
|---|---|---|
| Read own | `status`, events and verdicts about the caller's own files | Any local user |
| Read all | All users' events, logs | Root, or an admin after an authorization prompt |
| Change | `allowlist`, `denylist`, `config set`, `rules reload/rollback`, `notify disable`, `quarantine restore/purge`, `uninstall` | Root, or a fresh interactive authorization. Never group membership alone |

Add versioned framing with a maximum frame size at the same time. Create the
socket in a directory only root can write. State the invariant: **`navd`
never scans, mounts, reads or reports on a path a client names.**

**H. State.** State and config directories `0700`, process umask `077`, a
`Umask` key in the plist, log rotation with a size cap. Client-submitted
verdicts (R6) go in a separate table tagged with the peer's uid,
rate-limited, and are never used for a cache hit, a notification or an
action. Verdict cache keys include ctime or a content digest (R15).

**I. Quarantine (Phase 3).** Bind every finding to device, inode and a
digest of the scanned bytes. To act: reopen as in A and B, compare identity
and digest, and refuse on mismatch. Perform the removal with the owner's
credentials so root never moves a file that user could not. Restore with the
owner's credentials, refusing to follow symlinks or overwrite, clearing
setuid bits, and refusing when the original parent directory is no longer
the same object unless the user picks a destination. Bind action requests to
the uid and login session that received the notification, with an expiry and
single use.

**J. Queue.** Bounded, with a fair share per uid so one account's flood
degrades only that account's coverage. Coalesce by identity. Count what is
dropped and report it per §11.8. A hard per-object byte and time budget
(#104, #166) applies to directly named objects too.

**K. Install.** In addition to #163 and #157: open the source without
following symlinks, require a regular file, create the destination
exclusively and write the bytes instead of cloning, then confirm it carries
no ACL. Validate that a pre-existing `/Library/PrivilegedHelperTools` is
root-owned and not group- or world-writable.

**L. Packet capture (Phase 0c/2).** Same split: the broker opens the capture
device, sets and locks the filter, and passes the descriptor to an
unprivileged sandboxed parser.

**Alternative considered: scan in a per-user agent instead of a root
daemon.** It removes the confused-deputy problem entirely. It was not
recommended as the primary design because the agent runs as the same user as
the malware NAV targets, which can stop it or tamper with its results; a
root broker keeps the record out of that process's reach.

## 8. Proposed design-doc edits and gating

| Section | Edit |
|---|---|
| §2 | Replace "`navd` also links `nav-core`" with the broker/worker split; add the invariant in G. Remove "anything under FDA-gated paths" or restate it as event-driven only |
| §3 | Extend the input-path rule: no parsing of attacker-controlled input at uid 0, Apple's tools included. Move the Security.framework shim into the worker |
| §6.2 | Remove or constrain the daemon scratch mount; state that members are never extracted to disk as root |
| §9.1 | Peer-credential checks and method tiers are part of the first socket commit, not Phase 3. Drop or fence the verdict push from `navctl` |
| §9.2 | Route notifications by the file owner's session; bind actions to uid and session |
| §11.4 | Directory and file modes, umask, rotation |
| §11.7 | Open with the owner's credentials, descriptor-only reads, snapshot for path tools, digest binding |
| New §11.13 | Privilege separation: broker and worker responsibilities, the worker's sandbox, deadlines, poison records, queue fairness |
| §12 | Stage C gate: no event source is wired to a scan until A–E exist. Add the spikes in §9 below |

Order of work, cheapest first: fix E1 and E2 in `nav-core` now (they are
independent of the daemon and make `sudo navctl scan` safe: open without
following symlinks, non-blocking, check the handle; walk with directory
descriptors instead of joined paths). Tighten state modes and install (H,
K). Then the broker/worker split before any Stage C code. Quarantine rules
(I) can wait for Phase 3 but should be written into the design now.

## 9. Not verified

I had no macOS host. These claims rest on documentation or memory and each
needs a short test before the design depends on it:

| Claim | Affects |
|---|---|
| An FDA grant still applies after the opener drops to another uid, and to a descriptor passed to a process without the grant | A, C |
| A flag that refuses symlinks in every path component is available on the minimum supported macOS | B |
| The worker can sandbox itself with a custom profile, and `codesign`/`spctl` still work inside it and on a bare clone outside its bundle | C, D |
| A user can hard-link a file they cannot read | R2 |
| How a root-initiated `hdiutil attach` treats setuid bits, device nodes and ownership by default | R9, E5 |
| `fs::copy` carries an ACL onto the installed binary, and whether `codesign -f` drops it | E3 |
| `sudo` on stock macOS keeps the caller's `PATH` and clears `TMPDIR` | #157, E5 |
| Per-process memory limits are enforceable for the worker | C |
| Reading a cloud placeholder can be made to fail instead of downloading | B, R14 |

E1 and E2 were reproduced on Linux only. The code path is platform-neutral
(`std::fs` open and directory listing), but the reproduction should be
repeated on macOS when the fix lands, as a regression test.
