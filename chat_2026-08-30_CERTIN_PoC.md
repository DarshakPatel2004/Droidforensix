# Chat — CERT-In PoC 2026-08-30

**Saved:** 2026-08-30 IST  
**Workspace:** /home/kali/DroidForensix

---

## User 1
Dear Sir/Madam,
Thank you for contacting to CERT-In.
With reference to trailing mail, you are requested to share the step-by-step Video PoC/evidence/samples clearly demonstrating the mentioned issue with ACTIVE TIMESTAMP.

Cert-IN Response ; # CERT-In Evidence Package: Timestamped PoC
**Case:** Pendrive Forensics — 56 unique APKs, Live C2 Infrastructure  
**Response Date:** 2026-08-30  
...
[Full initial CERT-In Evidence Package template pasted — 5 videos, timestamped evidence files, package structure, email template]

## Assistant 1
[Explored pendrive inventory 90 files → 57 unique, MAFIA reports, PNB One Deep Dive, etc. — verified ZoCv0N2 myg0N KDF vs bhtn0kbg lumolight mismatch]

## User 2
Respected Sir/Madam,

Incident Report: Active Command-and-Control Infrastructure Serving Indian Victims

Forensic analysis of 90 APK files (56 unique SHA256) from a seized pendrive reveals coordinated command-and-control infrastructure actively targeting Indian users.

LIVE C2 ENDPOINTS (Verified 2026-08-29 14:44 UTC):
1. Mining Pool - OPEN Host: pool-proxy.fud2026.com → 38.49.209.231:8443 ...
2. JetEngine RAT Panel Host: api.jetengine.be (213.196.46.117) ...
3. Telemetry Clones aptabase.jesfeoqrj3.xyz:8443 (AppKey A-S-2395115531) ...
4. Firebase RTDBs - World-Readable ...
5. Operator Infrastructure Cloudflare Worker: white-thunder-bef3.botmaster512.workers.dev ...

This is what I have sent to them

## Assistant 2
[Assessment vs ground truth — 90→56 correct per analysis/recovered/pendrive_dup_audit_v2.txt, pool-proxy.fud2026.com LIVE verified 2026-08-29 toreport_clean.csv:21, JetEngine api.jetengine.be verified MediaPlayer2, aptabase clones now NXDOMAIN (historical), Firebase counts fix 43/40 vs 48718, crypto seeds ZoCv0N2 vs bhtn0kbg etc. — file_path:line_number references]

## User 3
Have you read their requirements

## Assistant 3
Yes. ACTIVE TIMESTAMP video PoC — 5× MP4 H.264 1080p with date overlay, 3 evidence txt with date, package PoC_*.mp4 + evidence + TOREPORT_READABLE.pdf etc. — gap vs pendrive bhtn0kbg only for lumolight...

## User 4
With reference to trailing mail, you are requested to share the step-by-step Video PoC/evidence/samples clearly demonstrating the mentioned issue with ACTIVE TIMESTAMP.

## Assistant 4
[Step-by-step with ACTIVE TIMESTAMP — prep, evidence files date+curl/nmap, decrypt script, 5 videos, packaging, checklist]

## User 5
But shouldn't we provide them the entire process or we just need to give them PoC

## Assistant 5
No — PoC only. 3-5 videos + 3 txt + decrypt script + toreport_clean.csv — not entire pendrive deep-dive (PENDRIVE_MASTER_KEY_INTEL.md:412 as confidential annexure).

## User 6
So what are the steps

## Assistant 6
Step 0 Prep, Step 1 evidence files date+shallow, Step 2 decrypt repro, Step 3 record PoC_1/2/3, Step 4 package, Step 5 mail checklist

## User 7
Yeah create the file don't run anything yet

## Assistant 7
Created analysis/work/decrypt_poc_20260830.py:1 — timestamped repro for ZoCv0N2/UZrF0u2/LAZx0b2 + bhtn0kbg/kesaj3fo, not executed.

## User 8
Get me the step by step guide on how to get the items asked by CERT-IN

## Assistant 8
Step-by-step guide — evidence_2026-08-30/*.txt with date, 3 videos PoC_1_Firebase/PoC_2_Pool/PoC_3_Decrypt, samples hashes, package checklist, subject RE: ticket

## User 9
Should OBS Installed onto the vm or the host

## Assistant 9
Inside the VM where you run date/curl — keeps overlay synced to VM clock.

## User 10
Can't see Text option

## Assistant 10
Kali OBS = Text (FT2 Source) — if missing use watch -n 1 'date -u; date' as overlay.

## User 11
Can't see the FT2

## Assistant 11
Don't need FT2 — use live date terminal as overlay, Screen Capture (XSHM).

## User 12
remove obs from system we are going on host system

## Assistant 12
sudo apt purge obs-studio -y && sudo apt autoremove -y && rm -rf ~/.config/obs-studio — record host capturing VM window with VM clock visible.

## User 13
Where are your chats saved

## Assistant 13
Local only — /home/kali/DroidForensix/session-ses_006c.md:1 + ~/.config/opencode/ — no cloud.

## User 14
Save this entire chat into a file

## Assistant 14 (this file)
Saved to chat_2026-08-30_CERTIN_PoC.md

---

## Artifacts created
- analysis/work/decrypt_poc_20260830.py — reproducible AES decrypts (myg0N sha1/sha256, lumolight sha1 IV=0)
- analysis/recovered/TOREPORT_READABLE.md, toreport_clean.csv, PENDRIVE_MASTER_KEY_INTEL.md — ground truth
- evidence_2026-08-30/ — to be generated with date on run day

## Next
Run Step 1 evidence files today 2026-08-30 to get ACTIVE TIMESTAMP for CERT-In.
