# Deploying Sfumato on Google Cloud (free tier, team access)

One command puts the whole platform on a single **Compute Engine e2-micro** VM (Google's Free Tier VM) with HTTPS and a
team login. The AI report uses **Gemini (free tier)** through the OpenAI-compatible provider, so no GPU is needed.

```powershell
gcloud auth login ; gcloud config set project <PROJECT_ID>     # once; the project needs a billing account
.\scripts\gcp_setup.ps1 -Bucket <unique-name> -BillingAccount <ID>   # once: bucket, service accounts, budget
.\scripts\gcp_vm.ps1 up                                         # VM + static IP + firewall + deploy (first boot: about 6 minutes)
```

The script prints the URL (`https://<ip-with-dashes>.sslip.io`, a real Let's Encrypt certificate, no domain to buy) and
creates a first team account `admin` whose password is saved in `secrets/gcp-team-credentials.txt` (git-ignored).

| Command | Effect |
|---|---|
| `.\scripts\gcp_vm.ps1 update` | rebuild the package, upload it, restart the VM (database and disk are kept) |
| `status` / `url` / `logs` | state, address, filtered boot log |
| `team-add -User bob` / `team-remove -User bob` | accounts (bcrypt hashes only leave your machine); then run `update` |
| `teardown` | deletes VM + disk + static IP + firewall rule (asks you to type DELETE); the bucket stays |

## What runs on the VM

```
Internet ──443──► Caddy (HTTPS, basic-auth team login) ──► Next.js dashboard :3000 ──► FastAPI + embedded worker :8000 (SQLite)
                                                           (the dashboard proxy adds the API key; ports 3000/8000 are not open)
```

* Package: `deploy/gcp/build_package.py` builds `dist/sfumato-deploy.tar.gz` (frontend built on your machine, because
  1 GB of RAM cannot run `next build`). It refuses to include `.env` files, databases, private keys or any local secret.
* The package is uploaded to your private bucket (`deploy/`); the VM downloads it with its own identity
  (`sfumato-reader`, read-only) and **verifies its sha256**, which is written in the instance metadata by the deploy
  script. Someone who can only write to the bucket cannot make the VM run their code.
* Secrets (`API_KEYS`, `SECRET_KEY`, `ARTIFACT_SIGNING_KEY`, the team hashes) travel in **instance metadata**, never in
  the bucket. They are readable by anyone with access to the project's VMs.
* Production settings: `secrets/gcp-vm.env` (generated on first run with a fresh API key and secret, not your local ones).
  Edit it and run `update` to change them.
* Systemd units `sfumato-api`, `sfumato-web`, `caddy`; a 2 GB swap file; logs in `/var/log/sfumato-startup.log` and
  `journalctl -u sfumato-api`.

## Gemini (free) for the AI report

`gcp-vm.env` already points the `openai` provider at Gemini's OpenAI-compatible endpoint with `gemini-3.5-flash-lite`.
Until a key exists the report falls back to the deterministic investigator (the AI status says
`openai API key missing`). To enable Gemini: open the dashboard, **Settings**, enter the Gemini key (stored encrypted on
the VM, write-only). Create the key in a Google project **without billing**, otherwise it is not the free tier.
On the free tier Google may use prompts to improve its products: use demo/synthetic incidents only. Data is
pseudonymised before leaving the VM, which reduces but does not remove the exposure.

## Cost, honestly

* e2-micro (1 per month, in `us-central1`, `us-east1` or `us-west1`) and 30 GB standard disk are in the Free Tier, per
  [Google's list](https://docs.cloud.google.com/free/docs/free-cloud-features); the bucket (< 5 GB, `us-central1`) too.
* A static external IPv4 address is, to my knowledge, billed by the hour (a few cents per day); it is **not** on that
  list and I did not verify the current price. It is covered by your credit.
* GPUs and TPUs are not part of the Free Tier, and a GPU is not needed with Gemini.
* Spending stops mattering after your credit ends (12 February 2027 for this account): run `teardown`
  before that date, or unlink billing, unless a payment method on the billing account is intended to pay.

## Measured on a real e2-micro

First boot 5 min 30 s (apt + Python dependencies); incident `SFUMATO-2026-0102` investigated in about 5 s; peak memory
about 660 MB during installation (swap used). HTTPS certificate valid; unauthenticated and wrong-password requests get
401; plain HTTP redirects to HTTPS; ports 3000 and 8000 are unreachable from the Internet; the API key does not appear
in the page. **Not measured:** several simultaneous users, the dashboard under load, a Gemini call (no key was entered),
the GUIDE model and knowledge base (not published to the bucket yet; the VM reached the bucket and reported
"nothing published", which proves its read access works).

## Limits

* The e2-micro is a shared 0.25-vCPU machine with 1 GB of RAM: fine for a team demo, not for heavy load. For more room,
  `-MachineType e2-small` is a paid option (cost not verified here).
* One shared API key behind a shared-password login: no roles, no per-person audit trail of actions in Sfumato.
* SSH (port 22) stays open to the Internet through GCP's default rule, as on any new project; restrict
  `default-allow-ssh` to your address if you do not need remote access.
* SQLite on the VM disk; there is no automatic backup. Take disk snapshots if the data matters.
* A new IP (after `teardown` then `up`) means a new URL and a new certificate.
