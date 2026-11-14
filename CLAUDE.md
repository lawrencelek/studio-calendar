# CLAUDE.md

This repository is an encrypted planning calendar: a static web app on GitHub Pages, with all of its content in `data/calendar.enc.json`. It is the owner's canonical calendar.

## Rules
- **Never commit plaintext.** Only `data/calendar.enc.json` holds data. `calendar.json`, exports and `.xlsx` files stay local (`.gitignore` covers them). Check `git status` before every commit.
- **Keep the code generic.** Names, projects, people, places, labels, event types and colour rules belong in the encrypted `settings`, never in `app.js`, `index.html`, `style.css`, `tools/`, this file or the README.
- **Ask for the password** if `CAL_PASSWORD` is not set. Never write it into a file, commit, log or memory.
- **The commit message for data changes is always `Update calendar`.** Code-change messages must not describe calendar content either.
- **Pull before editing** (`git pull`), because the web app commits too. If a push is rejected, pull, then re-run decrypt → edit → encrypt.
- Keep edits literal to what was asked; don't reorganise the calendar.

## Workflow
```bash
pip install cryptography openpyxl --quiet
git pull
CAL_PASSWORD='…' python tools/cal.py decrypt
# edit calendar.json (schema below)
python tools/cal.py check
CAL_PASSWORD='…' python tools/cal.py encrypt
git add data/calendar.enc.json && git commit -m "Update calendar" && git push
rm calendar.json
```
`python tools/cal.py summary --days 30` prints what's coming up. For a fresh, empty repository, `make-setup OUT` writes a one-time setup file and prints its code; give both to the owner privately, never commit them. The site's setup screen re-locks the data with the owner's password. `export-xlsx out.xlsx` makes a spreadsheet snapshot to send to the owner (never commit it).

## Schema (calendar.json)
- `settings`:
  - `title`, `brand`
  - `eventTypes[]` (`{name, tone}`), where tone ∈ red, slate, orange, blue, purple, green, yellow, grey, light
  - `gateType`, `defaultEventType`, `defaultSource`
  - `dayNames[7]`, `defaultWeek[7]`
  - `dayCategories[]` (`{label, match: [keywords], color, exclusive?}`), which colour the week cells
  - `openingTripwire` (the tripwire `n` whose date drives the countdown), `countdownLabel`, `countdownShort`
- `events[]`: `{id, date: "YYYY-MM-DD", until: "" | "YYYY-MM-DD", item, type ∈ settings.eventTypes, source}`. Month-only items go on the 1st. New ids are `ev-` followed by 8 hex characters.
- `weeks[]`: `{start: Monday "YYYY-MM-DD", days: [7 strings], notes}`.
- `months[]`: keys and labels as listed in `monthColumns`.
- `tripwires[]`: `{id, n, checkpoint, by: "YYYY-MM-DD" or words, byNote, ifMissed, status}`, where status ∈ Open, On track, At risk, Met, Missed.
- `premortem[]`: `{id, n, how, why, luck, guard, source, likelihood: 1–5|null, impact: 1–5|null, owner, status, notes}`, where status ∈ Open, Guard in place, Watching, Happened, Closed.
- `priorities[]`, `backcast[]`, `focus[]` (`{id, title, steps[]}`), and `sheets{}` (titles and notes per view).

The app computes the derived values (fixed this week, gate, weeks to target, days left, score). Don't store them.
