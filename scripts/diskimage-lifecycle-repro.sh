#!/bin/bash
# Adversarial reproductions for navctl's disk-image mount lifecycle (§6.2).
# macOS only. Observes and prints; it asserts nothing and changes no code.
#
#   scripts/diskimage-lifecycle-repro.sh target/debug/navctl [case ...]
#
# Each case runs navctl with a private TMPDIR, so its scratch root is
# <work>/<case>/tmp/navctl-scratch. `STATE` lines list what `hdiutil info`
# still shows for the case afterwards; an empty STATE is a clean exit.
set -u

[ "$(uname)" = Darwin ] || { echo "macOS only" >&2; exit 2; }
[ $# -ge 1 ] || { echo "usage: $0 <navctl> [case ...]" >&2; exit 2; }
NAVCTL=$(cd "$(dirname "$1")" && pwd -P)/$(basename "$1")
shift
REPO=$(cd "$(dirname "$0")/.." && pwd -P)
DROPPER=$REPO/crates/nav-core/fixtures/suspicious/dropper.sh
WORK=$(cd "$(mktemp -d /tmp/navrepro.XXXXXX)" && pwd -P)
HD=/usr/bin/hdiutil
C=

cat >"$WORK/attached.py" <<'EOF'
import plistlib, subprocess, sys
root = sys.argv[1]
out = subprocess.run(["/usr/bin/hdiutil", "info", "-plist"], capture_output=True).stdout
for img in plistlib.loads(out).get("images", []):
    ents = img.get("system-entities", [])
    mounts = [e["mount-point"] for e in ents if "mount-point" in e]
    path = img.get("image-path", "")
    if path.startswith(root) or any(m.startswith(root) for m in mounts):
        devs = ",".join(e.get("dev-entry", "?") for e in ents)
        print("%s\t%s\t%s" % (devs, path.replace(root, "<work>"),
                              ",".join(mounts).replace(root, "<work>") or "-"))
EOF

cat >"$WORK/entities.py" <<'EOF'
import plistlib, sys
d = plistlib.loads(sys.stdin.buffer.read())
imgs = d.get("images", [d])
want = sys.argv[1] if len(sys.argv) > 1 else None
for img in imgs:
    if want and img.get("image-path") != want:
        continue
    for i, e in enumerate(img.get("system-entities", [])):
        print("    [%d] %s hint=%s mountable=%s mount=%s" % (
            i, e.get("dev-entry"), e.get("content-hint"),
            e.get("potentially-mountable"), "yes" if "mount-point" in e else "-"))
EOF

cat >"$WORK/summary.py" <<'EOF'
import json, sys
try:
    v = json.load(open(sys.argv[1]))
except Exception as e:
    print("    json: unparsable (%s)" % e)
    sys.exit()
rs = v.get("results", [])
by = {}
for r in rs:
    by[r.get("completeness")] = by.get(r.get("completeness"), 0) + 1
print("    json: coverage_complete=%s results=%d completeness=%s unreadable=%d volumes=%s mount_gaps=%s budget=%s" % (
    v.get("coverage_complete"), len(rs), by, len(v.get("unreadable", [])),
    v.get("volumes"), v.get("mount_gaps"), v.get("budget_limit")))
for r in rs[:int(sys.argv[2]) if len(sys.argv) > 2 else 0]:
    print("      " + str(r.get("path")).rsplit("/", 1)[-1])
EOF

say() { printf '%s\n' "$*"; }
attached() { python3 "$WORK/attached.py" "$WORK"; }
state() {
    local s
    s=$(attached)
    if [ -z "$s" ]; then say "  STATE ($1): clean"; else
        say "  STATE ($1):"
        printf '%s\n' "$s" | sed 's/^/    /'
    fi
}
detach_all() {
    local d
    attached | cut -f1 | cut -d, -f1 | while read -r d; do
        [ -n "$d" ] && $HD detach "$d" -force -quiet
    done
}
show() { # show <label> <file>: indented, scratch paths shortened
    [ -s "$2" ] && sed -e "s|$WORK|<work>|g" -e "s/^/    $1: /" "$2" | head -n "${3:-12}"
}
new_case() {
    C=$WORK/$1
    mkdir -p "$C/tmp" "$C/src"
    say
    say "=== $1: $2"
}
end_case() {
    detach_all
    pkill -KILL -f "hdiutil .*$C" 2>/dev/null
    sleep 1
}
# Foreground only: `nav ... &` would background a subshell, not navctl.
nav() { env TMPDIR="$C/tmp" "$NAVCTL" "$@"; }
scratch() { echo "$C/tmp/navctl-scratch"; }
mounted() { mount | grep -F "$(scratch)/" | head -1; }
# wait_mount <pid>: until a volume is mounted under the scratch root.
wait_mount() {
    while kill -0 "$1" 2>/dev/null; do
        [ -n "$(mounted)" ] && return 0
    done
    return 1
}
# wait_child <pid> <verb>: prints the pid of navctl's `hdiutil <verb>` child.
wait_child() {
    local c
    while kill -0 "$1" 2>/dev/null; do
        c=$(pgrep -P "$1" -f "hdiutil $2" | head -1)
        [ -n "$c" ] && { echo "$c"; return 0; }
    done
    return 1
}
# reap <pid> <limit seconds>: sets RC and SECS; SIGKILLs navctl at the limit.
reap() {
    local start=$SECONDS
    ( sleep "$2"; kill -KILL "$1" 2>/dev/null ) &
    local dog=$!
    wait "$1"
    RC=$?
    SECS=$((SECONDS - start))
    kill "$dog" 2>/dev/null
    wait "$dog" 2>/dev/null
}
mk_image() { # mk_image <out> <srcdir> [fs]
    $HD create -quiet -volname NavRepro -fs "${3:-HFS+}" -format UDRO -srcfolder "$2" "$1" ||
        say "  !! hdiutil create failed for $1"
    sleep 1
    detach_all "$WORK"
}

# Shared images: a small one, and a big one whose walk takes long enough to
# interrupt (20 000 small files).
mkdir -p "$WORK/small-src" "$WORK/big-src"
echo hello >"$WORK/small-src/readme.txt"
python3 - "$WORK/big-src" <<'EOF'
import os, sys
for d in range(400):
    p = os.path.join(sys.argv[1], "d%03d" % d)
    os.mkdir(p)
    for f in range(50):
        with open(os.path.join(p, "f%02d.txt" % f), "w") as h:
            h.write("plain text %d %d\n" % (d, f) * 20)
EOF
SMALL=$WORK/small.dmg
BIG=$WORK/big.dmg
mk_image "$SMALL" "$WORK/small-src"
mk_image "$BIG" "$WORK/big-src"
say "macOS $(sw_vers -productVersion) $(uname -m); work dir $WORK"

case_baseline() {
    new_case baseline "uninterrupted scans of both images"
    nav scan "$SMALL" >"$C/out" 2>"$C/err"
    say "  small: rc=$?"
    show out "$C/out"
    show err "$C/err"
    local t=$SECONDS
    nav rules test --json "$BIG" >"$C/json" 2>"$C/err"
    say "  big: rc=$? in $((SECONDS - t)) s"
    python3 "$WORK/summary.py" "$C/json"
    state "after both"
    end_case
}

# Finding 1: a cancel signal after the attach.
case_signal_during_walk() {
    local sig
    for sig in INT TERM HUP; do
        new_case "sig$sig-walk" "SIG$sig while the walker is on the mounted volume"
        env TMPDIR="$C/tmp" "$NAVCTL" scan "$BIG" >"$C/out" 2>"$C/err" &
        local pid=$!
        if wait_mount $pid; then
            kill -$sig $pid
            reap $pid 120
            say "  rc=$RC after ${SECS} s"
            show err "$C/err"
            state "right after navctl exited"
            sleep 5
            state "5 s later"
            say "  scratch root: $(ls "$(scratch)" 2>/dev/null | tr '\n' ' ')"
        else
            wait $pid
            say "  inconclusive: navctl finished before a mount was seen"
        fi
        if [ "$sig" = INT ]; then
            nav scan "$SMALL" >"$C/out2" 2>"$C/err2"
            say "  next navctl run in the same TMPDIR: rc=$?"
            show err "$C/err2"
            state "after the next run"
        fi
        end_case
    done
}

case_sigint_during_attach() {
    new_case sigint-attach "SIGINT while hdiutil attach is running"
    env TMPDIR="$C/tmp" "$NAVCTL" scan "$BIG" >"$C/out" 2>"$C/err" &
    local pid=$!
    if wait_child $pid attach >/dev/null; then
        kill -INT $pid
        reap $pid 120
        say "  rc=$RC after ${SECS} s"
        show err "$C/err"
        state "right after navctl exited"
        sleep 8
        state "8 s later"
    else
        wait $pid
        say "  inconclusive: no attach child seen"
    fi
    end_case
}

# SIGKILL, and what the next run's stale sweep recovers.
case_sigkill() {
    new_case sigkill-walk "SIGKILL during the walk, then a second run"
    env TMPDIR="$C/tmp" "$NAVCTL" scan "$BIG" >"$C/out" 2>"$C/err" &
    local pid=$!
    if wait_mount $pid; then
        kill -KILL $pid
        wait $pid 2>/dev/null
        state "after SIGKILL"
        nav scan "$SMALL" >"$C/out2" 2>"$C/err2"
        say "  next run: rc=$?"
        show err "$C/err2"
        state "after the next run"
    else
        wait $pid
        say "  inconclusive"
    fi
    end_case

    new_case sigkill-unmounted "SIGKILL during the walk, volume unmounted (device kept), second run"
    env TMPDIR="$C/tmp" "$NAVCTL" scan "$BIG" >"$C/out" 2>"$C/err" &
    pid=$!
    if wait_mount $pid; then
        kill -KILL $pid
        wait $pid 2>/dev/null
        local mp
        mp=$(mounted | sed -e 's/^[^ ]* on //' -e 's/ (.*$//')
        diskutil unmount force "$mp" >/dev/null 2>&1 || umount -f "$mp"
        state "after SIGKILL and unmount"
        nav scan "$SMALL" >"$C/out2" 2>"$C/err2"
        say "  next run: rc=$?"
        show err "$C/err2"
        state "after the next run"
        say "  scratch root: $(ls "$(scratch)" 2>/dev/null | tr '\n' ' ')"
    else
        wait $pid
        say "  inconclusive"
    fi
    end_case

    new_case sigkill-attach "SIGKILL while hdiutil attach is running"
    env TMPDIR="$C/tmp" "$NAVCTL" scan "$BIG" >"$C/out" 2>"$C/err" &
    pid=$!
    if wait_child $pid attach >/dev/null; then
        kill -KILL $pid
        wait $pid 2>/dev/null
        say "  hdiutil still running right after: $(pgrep -f "hdiutil attach.*$C" | tr '\n' ' ')"
        sleep 8
        say "  hdiutil still running 8 s later: $(pgrep -f "hdiutil attach.*$C" | tr '\n' ' ')"
        state "8 s after SIGKILL"
        nav scan "$SMALL" >"$C/out2" 2>"$C/err2"
        say "  next run: rc=$?"
        show err "$C/err2"
        state "after the next run"
    else
        wait $pid
        say "  inconclusive"
    fi
    end_case
}

# hdiutil hangs, simulated by SIGSTOPping navctl's child.
case_hang_attach() {
    new_case hang-attach "hdiutil attach hangs (SIGSTOP) until the 60 s timeout"
    env TMPDIR="$C/tmp" "$NAVCTL" scan "$SMALL" >"$C/out" 2>"$C/err" &
    local pid=$! c
    if c=$(wait_child $pid attach); then
        kill -STOP "$c"
        reap $pid 150
        say "  rc=$RC after ${SECS} s"
        show out "$C/out"
        show err "$C/err"
        state "right after navctl exited"
        sleep 8
        state "8 s later"
    else
        wait $pid
        say "  inconclusive"
    fi
    end_case
}

case_hang_detach() {
    new_case hang-detach "every hdiutil detach hangs (SIGSTOP)"
    env TMPDIR="$C/tmp" "$NAVCTL" scan "$SMALL" >"$C/out" 2>"$C/err" &
    local pid=$! c n=0
    while kill -0 $pid 2>/dev/null; do
        for c in $(pgrep -P $pid -f "hdiutil detach"); do
            kill -STOP "$c" 2>/dev/null && n=$((n + 1))
        done
    done &
    local stopper=$!
    reap $pid 200
    wait $stopper 2>/dev/null
    say "  rc=$RC after ${SECS} s"
    show out "$C/out"
    show err "$C/err"
    state "after navctl exited"
    say "  scratch root: $(ls "$(scratch)" 2>/dev/null | tr '\n' ' ')"
    end_case
}

case_hang_info() {
    new_case hang-info "hdiutil info hangs (SIGSTOP) during cleanup only"
    env TMPDIR="$C/tmp" "$NAVCTL" scan "$SMALL" >"$C/out" 2>"$C/err" &
    local pid=$! c
    wait_child $pid attach >/dev/null
    while kill -0 $pid 2>/dev/null; do
        for c in $(pgrep -P $pid -f "hdiutil info"); do kill -STOP "$c" 2>/dev/null; done
    done &
    local stopper=$!
    reap $pid 200
    wait $stopper 2>/dev/null
    say "  rc=$RC after ${SECS} s"
    show out "$C/out"
    show err "$C/err"
    state "after navctl exited"
    end_case
}

# The image is already attached before navctl starts.
case_already_attached() {
    new_case pre-mounted "image already mounted elsewhere (as after a double click)"
    mkdir "$C/vol"
    $HD attach -quiet -nobrowse -mountpoint "$C/vol" "$SMALL"
    state "before navctl"
    nav scan "$SMALL" >"$C/out" 2>"$C/err"
    say "  rc=$?"
    show out "$C/out"
    show err "$C/err"
    state "after navctl"
    end_case

    new_case pre-nomount "image already attached with -nomount by someone else"
    $HD attach -nomount "$SMALL" 2>&1 | sed 's/^/    foreign attach: /'
    state "before navctl"
    nav scan "$SMALL" >"$C/out" 2>"$C/err"
    say "  rc=$?"
    show out "$C/out"
    show err "$C/err"
    state "after navctl (is the other party's attachment still there?)"
    end_case
}

# A foreign -nomount attach landing between navctl's `hdiutil info` snapshot
# and its own attach, held open by stopping navctl's attach child.
case_race_nomount() {
    new_case race-nomount "foreign -nomount attach between navctl's snapshot and its attach"
    env TMPDIR="$C/tmp" "$NAVCTL" scan "$SMALL" >"$C/out" 2>"$C/err" &
    local pid=$! c
    if c=$(wait_child $pid attach); then
        kill -STOP "$c"
        $HD attach -nomount "$SMALL" 2>&1 | sed 's/^/    foreign attach: /'
        state "foreign attachment in place, navctl's attach still stopped"
        kill -CONT "$c"
        reap $pid 150
        say "  navctl rc=$RC"
        show out "$C/out"
        show err "$C/err"
        state "after navctl (is the foreign attachment still there?)"
    else
        wait $pid
        say "  inconclusive"
    fi
    end_case
}

case_concurrent() {
    new_case two-navctl "two navctl runs on the same image at once"
    env TMPDIR="$C/tmp" "$NAVCTL" rules test --json "$BIG" >"$C/json1" 2>"$C/err1" &
    local a=$!
    wait_mount $a
    env TMPDIR="$C/tmp" "$NAVCTL" rules test --json "$BIG" >"$C/json2" 2>"$C/err2" &
    local b=$!
    wait $b
    say "  second (started during the first's walk): rc=$?"
    show err "$C/err2"
    python3 "$WORK/summary.py" "$C/json2"
    wait $a
    say "  first: rc=$?"
    show err "$C/err1"
    python3 "$WORK/summary.py" "$C/json1"
    state "after both"
    end_case

    new_case foreign-attach "another process attaches the image during the walk"
    env TMPDIR="$C/tmp" "$NAVCTL" scan "$BIG" >"$C/out" 2>"$C/err" &
    a=$!
    if wait_mount $a; then
        $HD attach -nobrowse "$BIG" >"$C/foreign" 2>&1
        say "  foreign hdiutil attach: rc=$?"
        show foreign "$C/foreign"
    fi
    wait $a
    say "  navctl rc=$?"
    state "after navctl (the foreign attach's view of the image)"
    end_case
}

# Another process detaches the volume while the walker is on it.
case_foreign_detach() {
    local delay
    for delay in 0 0.3 1; do
        new_case "foreign-detach-$delay" "volume force-detached $delay s into the walk"
        env TMPDIR="$C/tmp" "$NAVCTL" rules test --json "$BIG" >"$C/json" 2>"$C/err" &
        local pid=$!
        if wait_mount $pid; then
            sleep "$delay"
            local dev
            dev=$(mounted | cut -d' ' -f1)
            $HD detach "$dev" -force -quiet
            say "  detached $dev"
        fi
        reap $pid 300
        say "  rc=$RC after ${SECS} s (20000 files on the image)"
        show err "$C/err" 6
        python3 "$WORK/summary.py" "$C/json"
        env TMPDIR="$C/tmp" "$NAVCTL" scan "$BIG" >"$C/out2" 2>"$C/err2" &
        pid=$!
        if wait_mount $pid; then
            sleep "$delay"
            $HD detach "$(mounted | cut -d' ' -f1)" -force -quiet
        fi
        reap $pid 300
        say "  plain scan, same race: rc=$RC, $(wc -l <"$C/out2" | tr -d ' ') stdout lines"
        show out "$C/out2" 3
        show err "$C/err2" 6
        end_case
    done
}

# The image file is swapped between detection and attach.
case_replace() {
    new_case replace "image replaced after imageinfo, before attach"
    mkdir "$C/other-src"
    cp "$DROPPER" "$C/other-src/swapped-in.sh"
    mk_image "$C/other.dmg" "$C/other-src"
    cp "$SMALL" "$C/target.dmg"
    env TMPDIR="$C/tmp" "$NAVCTL" scan --verbose "$C/target.dmg" >"$C/out" 2>"$C/err" &
    local pid=$!
    if wait_child $pid imageinfo >/dev/null; then
        mv -f "$C/other.dmg" "$C/target.dmg"
    else
        say "  inconclusive: imageinfo child not seen"
    fi
    reap $pid 120
    say "  rc=$RC (the checked image held only readme.txt)"
    show out "$C/out"
    show err "$C/err"
    state "after navctl"
    end_case

    new_case replace-encrypted "image replaced by an encrypted one after the encryption check"
    printf pw | $HD create -quiet -encryption AES-128 -stdinpass -format UDZO \
        -srcfolder "$WORK/small-src" "$C/enc.dmg"
    sleep 1
    detach_all "$WORK"
    cp "$SMALL" "$C/target.dmg"
    env TMPDIR="$C/tmp" "$NAVCTL" scan "$C/target.dmg" >"$C/out" 2>"$C/err" &
    pid=$!
    if wait_child $pid imageinfo >/dev/null; then
        mv -f "$C/enc.dmg" "$C/target.dmg"
    else
        say "  inconclusive: imageinfo child not seen"
    fi
    reap $pid 120
    say "  rc=$RC after ${SECS} s (137 = hung until the watchdog)"
    show out "$C/out"
    show err "$C/err"
    state "after navctl"
    end_case
}

# Scratch root and run directories tampered with.
case_scratch() {
    new_case scratch-open "scratch root pre-created group/world accessible"
    mkdir -m 755 "$(scratch)"
    nav scan "$SMALL" >"$C/out" 2>"$C/err"
    say "  rc=$?"
    show out "$C/out"
    show err "$C/err"
    end_case

    new_case scratch-symlink "scratch root is a symlink to another directory"
    mkdir -m 700 "$C/elsewhere"
    ln -s "$C/elsewhere" "$(scratch)"
    nav scan "$SMALL" >"$C/out" 2>"$C/err"
    say "  rc=$?"
    show err "$C/err"
    say "  symlink target now holds: $(ls -A "$C/elsewhere" | tr '\n' ' ')"
    end_case

    new_case scratch-planted "stale-looking run directories holding files and symlinks"
    mkdir -m 700 "$(scratch)"
    /usr/bin/true &
    local dead=$!
    wait $dead
    mkdir -p "$C/victim-empty" "$C/victim-full"
    echo precious >"$C/victim-full/file"
    mkdir -p "$(scratch)/$dead-aaaa/keep"
    echo precious >"$(scratch)/$dead-aaaa/keep/file"
    ln -s "$C/victim-empty" "$(scratch)/$dead-bbbb"
    mkdir "$(scratch)/$dead-cccc"
    ln -s "$C/victim-empty" "$(scratch)/$dead-cccc/link-empty"
    ln -s "$C/victim-full" "$(scratch)/$dead-cccc/link-full"
    mkdir "$(scratch)/$dead-dddd" "$(scratch)/$dead-dddd/empty-mountpoint"
    nav scan "$SMALL" >"$C/out" 2>"$C/err"
    say "  rc=$?"
    show err "$C/err"
    say "  scratch root after: $(ls -A "$(scratch)" | tr '\n' ' ')"
    say "  $dead-aaaa/keep/file: $(cat "$(scratch)/$dead-aaaa/keep/file" 2>&1)"
    say "  victim-empty exists: $([ -d "$C/victim-empty" ] && echo yes || echo NO)"
    say "  victim-full/file: $(cat "$C/victim-full/file" 2>&1)"
    end_case

    new_case scratch-rundir-removed "run directory's mount point checked after a normal run"
    nav scan "$SMALL" >"$C/out" 2>"$C/err"
    say "  rc=$?; scratch root after: '$(ls -A "$(scratch)" | tr '\n' ' ')'"
    end_case
}

# More than one volume on the image; entity order hdiutil reports.
case_multi_volume() {
    new_case multi-volume "one image, two mountable volumes"
    $HD create -quiet -size 120m -layout NONE "$C/multi.dmg"
    local dev
    dev=$($HD attach -nomount "$C/multi.dmg" | awk 'NR==1{print $1}')
    if diskutil partitionDisk "$dev" 2 GPT HFS+ NAVA 50% ExFAT NAVB 50% >"$C/part" 2>&1; then
        echo hello >/Volumes/NAVA/a.txt
        cp "$DROPPER" /Volumes/NAVB/install.sh
        sync
    else
        say "  !! partitionDisk failed"
        show part "$C/part"
    fi
    $HD detach "$dev" -quiet || $HD detach "$dev" -force -quiet
    sleep 1
    mkdir "$C/mr"
    say "  hdiutil attach -plist entity order:"
    $HD attach -plist -readonly -nobrowse -mountrandom "$C/mr" "$C/multi.dmg" |
        python3 "$WORK/entities.py"
    say "  hdiutil info -plist entity order:"
    $HD info -plist | python3 "$WORK/entities.py" "$C/multi.dmg"
    detach_all
    nav rules test --json "$C/multi.dmg" >"$C/json" 2>"$C/err"
    say "  navctl rules test: rc=$?"
    show err "$C/err"
    python3 "$WORK/summary.py" "$C/json" 5
    python3 - "$C/json" <<'EOF'
import json, sys
try:
    for r in json.load(open(sys.argv[1]))["results"]:
        print("    path: ..." + r["path"][-40:])
except Exception as e:
    print("    (no results: %s)" % e)
EOF
    state "after navctl"
    end_case

    new_case apfs "APFS image: entity order and cleanup"
    $HD create -quiet -fs APFS -volname NavApfs -format UDRO \
        -srcfolder "$WORK/small-src" "$C/apfs.dmg" || say "  !! APFS create failed"
    sleep 1
    detach_all
    mkdir "$C/mr"
    say "  hdiutil attach -plist entity order:"
    $HD attach -plist -readonly -nobrowse -mountrandom "$C/mr" "$C/apfs.dmg" |
        python3 "$WORK/entities.py"
    say "  hdiutil info -plist entity order:"
    $HD info -plist | python3 "$WORK/entities.py" "$C/apfs.dmg"
    detach_all
    nav scan "$C/apfs.dmg" >"$C/out" 2>"$C/err"
    say "  navctl scan: rc=$?"
    show out "$C/out"
    show err "$C/err"
    state "after navctl"
    end_case

    new_case small-hfs "HFS+ image: entity order (reference)"
    mkdir "$C/mr"
    say "  hdiutil attach -plist entity order:"
    $HD attach -plist -readonly -nobrowse -mountrandom "$C/mr" "$SMALL" |
        python3 "$WORK/entities.py"
    say "  hdiutil info -plist entity order:"
    $HD info -plist | python3 "$WORK/entities.py" "$SMALL"
    end_case
}

# What hdiutil does when the -mountrandom directory is gone (the state a
# stale sweep leaves for an attach still in flight).
case_mountrandom_missing() {
    new_case mountrandom-missing "hdiutil attach -mountrandom into a removed directory"
    $HD attach -readonly -nobrowse -mountrandom "$C/gone" "$SMALL" >"$C/out" 2>&1
    say "  hdiutil rc=$?"
    show hdiutil "$C/out"
    state "after hdiutil"
    end_case
}

# Ctrl-C from a terminal reaches the whole foreground process group, so it
# also hits the hdiutil children navctl spawns for cleanup.
case_group_sigint() {
    new_case group-sigint "SIGINT to the process group, repeated (Ctrl-C mashing)"
    python3 - "$NAVCTL" "$BIG" "$C" <<'EOF' &
import os, signal, subprocess, sys, time
navctl, image, case = sys.argv[1:4]
env = dict(os.environ, TMPDIR=case + "/tmp")
p = subprocess.Popen([navctl, "scan", image], env=env, start_new_session=True,
                     stdout=open(case + "/out", "w"), stderr=open(case + "/err", "w"))
scratch = case + "/tmp/navctl-scratch/"
while p.poll() is None:
    if scratch in subprocess.run(["mount"], capture_output=True, text=True).stdout:
        break
for _ in range(40):
    if p.poll() is not None:
        break
    os.killpg(p.pid, signal.SIGINT)
    time.sleep(0.05)
try:
    print("  rc=%s" % p.wait(120))
except subprocess.TimeoutExpired:
    os.killpg(p.pid, signal.SIGKILL)
    print("  rc=hung, killed")
EOF
    wait $!
    show err "$C/err"
    state "after navctl"
    end_case
}

ALL="baseline signal_during_walk sigint_during_attach sigkill hang_attach hang_detach
hang_info already_attached race_nomount concurrent foreign_detach replace scratch multi_volume
mountrandom_missing group_sigint"
for name in ${*:-$ALL}; do
    "case_$name"
done

C=$WORK
say
say "=== leftovers under the work dir before final cleanup"
state final
detach_all "$WORK"
rm -rf "$WORK" 2>/dev/null
exit 0
