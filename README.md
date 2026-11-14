# Encrypted calendar

A password-protected planning calendar that runs as a static web app on GitHub Pages: weeks, events, months, tripwires, premortem, priorities, backcast and a focus flow.

Everything specific to its owner lives in `data/calendar.enc.json`: the entries, plus every label, event type, colour rule and name. That file is encrypted with AES-256-GCM, using a key derived from the password via PBKDF2-SHA256 with 600,000 rounds. It is decrypted only in the browser, or by `tools/cal.py`. The code in this repository is generic.

## First-time setup

A new repository holds no calendar data. On first visit the site shows a setup screen:

1. Choose the one-time **setup file** and enter its **setup code**. Both are handed over privately and never committed.
2. Choose **your own password** (a long passphrase).
3. Paste a **GitHub token** (see below) and press **Create calendar**.

The browser opens the setup file, locks the calendar with your password and commits it. The repository only ever holds data locked with your password. Delete the setup file afterwards.

## Using it

1. Open the site and enter the password.
2. Click any cell to edit it. "Fixed this week", the gate flag, "Weeks to …", "Days left" and "Score" are calculated, not typed.
3. Press **Save** (or Ctrl/Cmd+S). This commits the encrypted file to the repository, and the site updates about a minute later.

Unsaved edits stay on that device, encrypted, until you save. If the file changed on GitHub since you opened it, the app asks whether to reload or overwrite. Nothing is merged silently.

### Saving needs a token on each device (one-off)

1. GitHub → Settings → Developer settings → **Fine-grained personal access tokens** → Generate new token.
2. Repository access: **Only select repositories** → this repository.
3. Permissions → Repository permissions → **Contents: Read and write**. Leave everything else at No access.
4. Set an expiry, generate the token and copy it.
5. In the app: **Settings** → paste it under **Token** → **Test connection** → **Save settings**.

The token is stored only in that browser. Without one, the app is read-only.

### Changing the password

Settings → Change the calendar password → Save. Older versions in the git history stay readable with the old password, so rewrite the history if the old password leaked.

## Editing from the command line (or with Claude)

```bash
pip install cryptography openpyxl
export CAL_PASSWORD='…'
python tools/cal.py decrypt          # -> calendar.json (plaintext, git-ignored)
python tools/cal.py summary          # next 21 days + tripwires
# edit calendar.json
python tools/cal.py check
python tools/cal.py encrypt          # -> data/calendar.enc.json
python tools/cal.py export-xlsx snapshot.xlsx   # spreadsheet copy; never commit it
```

## Hosting

GitHub Pages: Settings → Pages → Deploy from a branch → `main` / root. On the free plan the repository must be public, which is safe here because only encrypted data is committed. The page talks to nothing except `api.github.com` when saving, loads no external scripts, and asks search engines not to index it.

## Security notes

- The password is the protection. Use a long passphrase: anyone with the encrypted file can try guesses offline.
- Commit messages for data changes are always "Update calendar".
- Never commit `calendar.json`, a plaintext export or an `.xlsx`. `.gitignore` blocks them.
