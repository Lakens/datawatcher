# datawatcher: a tamper-evident file log for showing when research data were collected

Daniël Lakens, Eindhoven University of Technology

Software: <https://github.com/Lakens/datawatcher> (GPL-3.0)

## Abstract

A preregistration is only informative if the data were collected after it was
written. Readers usually have to take the researcher's word for this. This
paper describes datawatcher, a small program that a researcher runs on the
computer where data are collected. It records every version of every file in a
folder in a log in which each entry is linked to the previous one, so any later
change to the record can be detected. Each entry is placed in a time window
whose ends are set by outside parties the researcher does not control. The
earliest possible time comes from public random values that nobody can know in
advance (the NIST Randomness Beacon and the drand network). The latest possible
time comes from signed timestamp receipts (RFC 3161) and from the Bitcoin
blockchain (OpenTimestamps). Copies of the log are published continuously to
GitHub and, at chosen moments, to Zenodo. The program is a single file with
nothing to install, and needs no cooperation from the software that produces
the data. The log does not prove that data are genuine, and a determined
researcher can still copy data collected earlier into the watched folder. What
the log does is make the honest workflow fully documented at almost no cost,
and turn the most common ambiguities about timing into claims that can be
checked. Being dishonest then requires deliberate concealment rather than
vagueness. The second half of the paper is a step-by-step tutorial.

## 1. The problem

Preregistration separates predictions from the data used to test them (Nosek,
Ebersole, DeHaven, & Mellor, 2018; Wagenmakers, Wetzels, Borsboom, van der
Maas, & Kievit, 2012). Its value depends entirely on the order of events. A
hypothesis registered after the data were seen is not a prediction. Yamada
(2018) called this "preregistering after results are known" and pointed out
that a registry timestamp alone cannot rule it out. A registry shows when the
preregistration was submitted. It says nothing about when the data were
collected.

Several other questions about timing come up in review and are rarely
answerable:

- Were data collected before the preregistration was submitted, for example in
  a pilot that later became part of the main sample?
- Is the data file analysed the same file that was collected, or was it edited,
  replaced, or merged with something else afterwards?
- Were some sessions or participants removed without being reported?
- Was the preregistration document changed after it was first written?

Researchers who did everything correctly have no easy way to show it. The aim
of datawatcher is to give them one, at a cost low enough that it can be used
routinely.

## 2. The idea

### 2.1 Fingerprints

A SHA-256 hash, which this paper calls a *fingerprint*, is a 64-character code
computed from the contents of a file. Changing even one character of the file
produces a completely different fingerprint. It is practically impossible to
create two different files with the same fingerprint. A fingerprint therefore
identifies one exact version of a file without revealing its contents.

### 2.2 A linked log

datawatcher keeps a log in which each entry records one event, such as "file
`session1.csv` now has fingerprint `bff416c4…`". Each entry also contains the
fingerprint of the entry before it. Changing, removing or reordering any entry
therefore changes its fingerprint, and the next entry no longer points to it.
Anyone can recompute the links and see that the log was changed. This structure
goes back to Haber and Stornetta (1991). It is the core of tamper-evident
logging in computer security (Schneier & Kelsey, 1999; Crosby & Wallach, 2009),
and it is the way blocks are linked in a blockchain. No network of computers is
needed here, because there is only one author.

### 2.3 Two outside clocks

A linked log on its own shows the order of entries, not their times. The clock
of the researcher's computer cannot be trusted, because the researcher controls
it. datawatcher therefore places every entry between two times set by outside
parties.

**The earliest possible time.** Each entry contains the most recent value from
two public randomness beacons. The NIST Randomness Beacon publishes a new
512-bit random value every minute, signed and archived (Kelsey, Brandão,
Peralta, & Booth, 2019). The drand network, run by the League of Entropy, a
group of universities and companies, publishes one every 30 seconds. Nobody
can know these values before they are published. An entry that contains a
value published at 14:47 cannot have been written before 14:47.

**The latest possible time.** Every few minutes, datawatcher sends the
fingerprint of the newest entry to two timestamp services that follow the
RFC 3161 standard (Adams, Cain, Pinkas, & Zuccherato, 2001): freetsa.org and
DigiCert. Each returns a receipt signed with its own key, stating the time at
which it received that fingerprint. Because each entry contains the fingerprint
of the entry before it, one receipt covers the newest entry and every entry
before it. Once an hour, and at the start and end of each session, the
fingerprint is also sent to OpenTimestamps (Todd, 2016). OpenTimestamps
records it in the Bitcoin blockchain within a few hours, so that proof does not
depend on any single company continuing to exist.

Every entry, and so every logged version of every file, therefore lies in a
window: written after time T1 (a beacon value), and existing by time T2 (a
receipt). In practice, the window is a few seconds to a few minutes wide.

### 2.4 Public copies

A receipt shows that a log entry existed at a certain time. It does not show
that the researcher has not since started a second log, or rewritten later
parts of the first. The defence against an author rewriting their own log is
that other parties hold copies of it from earlier moments. Certificate
Transparency, the public log of all website security certificates, works on
the same principle (Laurie, Langley, & Kasper, 2013). datawatcher uploads the
log to a GitHub repository every 30 seconds while it changes; each upload is a
commit, dated by GitHub. At the end of a session, the researcher can publish
the log as a new version of a Zenodo record, which receives a permanent DOI
and cannot be deleted.

### 2.5 One log per study

A researcher could run two logs and show only the more favourable one. To
prevent this, datawatcher shows the fingerprint of a new log's first entry when
the log is created. The researcher puts this fingerprint in the
preregistration. Because the registry dates the preregistration, the
fingerprint commits the study to exactly one log before data collection starts.

## 3. Using the log to show that data were collected after a preregistration

The workflow is:

1. Create the study folder and start datawatcher on it. It creates the log
   and shows the fingerprint of the first entry.
2. Write the preregistration, including that fingerprint, and save it in the
   watched folder. The watcher logs it, and within five minutes obtains
   receipts that show this exact version existed by time T2(prereg).
3. Submit the same document to a registry such as OSF or AsPredicted. The
   registry's own timestamp is a second, independent proof of when it existed.
4. Collect data into the watched folder, with the watcher running whenever data
   are collected. Every data file version is logged with a window T1..T2.
5. In the analysis script, record the fingerprint of every data file that is
   loaded.
6. At publication, cite the Zenodo DOI of the log and report the fingerprints of
   the analysed files.

A reviewer can then check:

- **One log.** The first entry's fingerprint matches the one in the registered
  preregistration.
- **Intact log.** All links are correct, and the copies on GitHub and Zenodo
  match the log.
- **Unchanged preregistration.** The registered preregistration has the same
  fingerprint as the version logged at T2(prereg).
- **Order of events.** Every data file was first logged at a T1 later than
  T2(prereg).
- **Analysed data are logged data.** Every analysed file has a fingerprint that
  appears in the log.
- **No unreported removals.** Every file removed or replaced during collection
  is visible as a `file_removed` or `file_changed` entry.
- **Continuous logging.** The sessions cover the collection period. Changes
  made while the watcher was not running are visible, because the watcher
  compares the folder with the log each time it starts and marks such changes
  as `found_at_startup`.

### 3.1 What remains possible, and how far it is limited

The log records when a file *appeared in the watched folder*, not when the
measurement it contains took place. A researcher who collects data before
writing the preregistration, keeps those files elsewhere, and copies them into
the folder later will produce a log in which those files appear after the
preregistration. The log alone cannot detect this. The same holds for data that
are fabricated outright. No logging approach that does not involve the
measuring instrument itself can close this gap; signing data inside the
instrument at the moment of capture, as the C2PA standard does for cameras, is
the only route.

Three things make this attack harder than it sounds, and much harder than
under current practice:

1. **Internal timestamps.** Most experiment software writes the date and time
   into the data: E-Prime records `SessionDate` and `SessionTime`, PsychoPy puts
   the date in the file name and in the data, and Qualtrics and Prolific record
   start and end times. Each must match the logged window. Copying old data in
   therefore also requires editing these fields consistently, which is
   deliberate fabrication rather than a debatable choice.
2. **Pattern over time.** In a real study, files appear one session at a time
   over days or weeks, in step with the lab schedule, booking systems, and
   participant payments. A large set of files that all appear at once is
   visible in the log and asks for an explanation.
3. **No room for vagueness.** Without a log, the question "was this pilot data
   included?" usually has no answer, and a researcher may honestly not
   remember. With a log, the answer is in the record. The remaining ways to
   mislead are those that require planning and active concealment, which is
   both rarer and a clearer case of misconduct.

The log is therefore best understood as making the honest path documented and
cheap, and narrowing the dishonest path to deliberate fraud. It does not make
fraud impossible.

### 3.2 Other attacks

| Attempt | What the log shows |
|---|---|
| Edit or replace a data file after it was logged | The analysed file's fingerprint differs from the logged one, or a `file_changed` entry shows the replacement |
| Remove unfavourable sessions | A `file_removed` entry |
| Change the log afterwards | Broken links; mismatch with GitHub commits and Zenodo versions |
| Remove the last entries of the log | Mismatch with GitHub and Zenodo copies, and with receipts already published |
| Keep two logs and report the better one | The first-entry fingerprint in the preregistration names one log |
| Make changes while the watcher is off | The next start records them as `found_at_startup` |
| Set the computer's clock back | Times come from beacons and receipts, not from the computer's clock |
| Use beacon values from the past in a fabricated entry | Possible, but only makes the entry look *later* than T1, which gives no advantage. Receipts cannot be obtained for past times |
| Fake a receipt | Requires the timestamp service's private signing key |

### 3.3 What the researcher must trust

Checking a log requires trusting that SHA-256 cannot be broken in practice,
that NIST and drand did not publish their values in advance, and that the two
timestamp services sign honestly. The two services are independent of each
other, and OpenTimestamps adds a third time source that does not depend on any
single organisation. GitHub and Zenodo are trusted only to keep copies; their
role is to make rewriting visible. Nobody needs to trust datawatcher itself:
the log format is simple, and a separate checking script (and standard tools
such as `openssl`) can check everything without running datawatcher.

## 4. How it works in detail

### 4.1 The program

datawatcher is written in Go and uses only Go's standard library. It is
distributed as one program file per operating system (Windows, macOS, Linux)
of about 7 MB, with nothing to install. All settings are entered by answering
questions in its window.

### 4.2 Watching the folder

Every two seconds the program lists all files in the watched folder and its
subfolders, with their size and modification time. It does not use the
operating system's change notifications. Listing works the same on every
system and on network drives.

- **New or changed files.** When a file's size or time changes, the program
  waits until the file has stayed unchanged between two listings, so that a
  file still being written is not logged half-finished. It then computes the
  fingerprint. If the fingerprint differs from the last logged one, it writes a
  `file_added` or `file_changed` entry. A file whose time changes but whose
  content does not is not logged again. If the file changes while its
  fingerprint is being computed, or another program holds it locked, the
  program tries again at the next listing.
- **Removed files.** A logged file that is missing from two listings in a row
  is logged as `file_removed`. Two listings are required because some programs
  save a file by deleting it and writing it again.
- **The folder itself is unavailable.** If the watched folder cannot be read,
  for example because a network drive was disconnected, the program prints a
  warning and logs nothing. This prevents a disconnected drive from being
  logged as every file being removed.
- **Files that are skipped.** The `.provenance` folder (which holds the log),
  `.git` folders, `Thumbs.db`, `desktop.ini`, `.DS_Store`, files starting with
  `~$` (temporary Office files) or `._` (macOS metadata files), and the
  datawatcher program file itself if it is placed in the folder.
- **Starting and stopping.** When a session starts, every file is
  fingerprinted and compared with the log. Differences are logged with
  `found_at_startup: true`. When a session ends, the same full check runs once
  more, so that changes from the last seconds are included.

### 4.3 The log file

The log is `.provenance/chain.jsonl` inside the watched folder. Each line is
one entry in JSON format. The fingerprint of an entry is the SHA-256 of the
exact bytes of its line, without the line break. Using the exact bytes, instead
of a reconstructed form, means that any program in any language can check the
links. A typical entry looks like this (shortened):

```json
{"seq":2,"type":"file_added","prev":"277409e7dd…","local_time":"2026-10-10T16:47:47+02:00",
 "session":"02828592c159","path":"prereg.txt","sha256":"f09d2ec9db…","size":21,
 "file_modified":"2026-10-10T14:47:39.98Z",
 "nist":{"uri":"https://beacon.nist.gov/beacon/2.0/chain/2/pulse/1977490","pulse_index":1977490,
         "time":"2026-10-10T14:47:00.000Z","output_value":"336E4156…"},
 "drand":{"chain":"8990e7a9…","round":6540421,"time":"2026-10-10T14:47:30Z",
          "randomness":"bf3f14c0…","signature":"88857c14…","previous_signature":"8677f2df…"}}
```

| Field | Meaning |
|---|---|
| `seq` | Entry number, starting at 0 |
| `type` | `chain_start`, `session_start`, `file_added`, `file_changed`, `file_removed`, `timestamp`, or `session_end` |
| `prev` | Fingerprint of the previous line (empty for the first entry) |
| `local_time` | The computer's clock; for information only, not trusted |
| `session` | Random code identifying the session |
| `orcid`, `tool`, `platform`, `folder` | Recorded in `chain_start` and `session_start` entries |
| `path`, `sha256`, `size`, `file_modified` | The file, relative to the watched folder, and its fingerprint |
| `found_at_startup` | The change happened while the watcher was not running |
| `nist`, `drand` | Beacon values: the entry was written after these were published |
| `beacon_error` | Why a beacon could not be reached, if so |
| `anchors` | In `timestamp` entries: receipts for an earlier entry |
| `note` | For example, that the previous session ended without a `session_end` entry |

Beacon values are stored for up to 20 seconds and reused for entries written
in that time, so that many file changes at once do not cause many requests. A
reused value is a few seconds older, which makes the earliest possible time a
few seconds earlier. The bound is slightly wider but still correct. If a
beacon cannot be reached, the most recent value obtained is used and the
problem is recorded in `beacon_error`.

Each entry is written to disk, and the disk write is confirmed, before the
program continues. When the program starts, it checks all links in the
existing log and refuses to continue if any is broken, rather than adding
entries to a damaged log.

### 4.4 Receipts

A `timestamp` entry holds receipts in its `anchors` list. Each receipt
contains `anchored_seq` (the entry it covers), `anchored_hash` (that entry's
fingerprint), the `service`, and the receipt itself in base64 encoding.

- **RFC 3161 receipts** (`kind: "rfc3161"`) are requested every five minutes
  while there are new entries, at the start of each session, and at its end.
  Before storing a receipt, the program checks that the service granted the
  request, that the receipt is for the fingerprint that was sent, and that it
  answers this particular request. The receipt's stated time is copied to the
  `time` field for convenience. To keep the log small, the first receipt from
  each service in a session includes the service's certificates, and later
  receipts in the same session do not. A checker uses the certificates from
  the first receipt.
- **OpenTimestamps proofs** (`kind: "opentimestamps"`) are requested at the
  start of each session, at most once an hour during it, and at its end. The
  proof is first incomplete. The calendar server completes it once the Bitcoin
  transaction is confirmed, usually within a few hours. The program also saves
  each anchored entry and its proof as a pair of files in
  `.provenance/opentimestamps/`, in the standard `.ots` format.

### 4.5 Uploads

- **GitHub.** While the log changes, it is uploaded every 30 seconds to a
  chosen path in a chosen repository, using GitHub's contents interface with a
  personal access token. Each upload replaces the file and becomes a commit
  dated by GitHub. If an upload fails, it is tried again 30 seconds later.
- **Zenodo.** At the end of a session the program asks whether to publish. The
  first time, it creates a new Zenodo record. Later times, it creates a new
  version of the same record, replaces the files, and publishes. Each version
  has its own DOI, and one "concept" DOI refers to all versions together. The
  record is a dataset under CC-BY-4.0 with the researcher (name and ORCID) as
  creator. It contains `chain.jsonl` and a `README.txt` that explains the
  format and how to check it.

### 4.6 Settings and tokens

Settings that belong to the study, such as the ORCID iD, the repository name,
and the Zenodo record number, are stored in `.provenance/settings.json`. Tokens
are stored only in the user's own settings folder, never in the watched folder,
because the watched folder may be shared:

- Windows: `%AppData%\datawatcher\config.json`
- macOS: `~/Library/Application Support/datawatcher/config.json`
- Linux: `~/.config/datawatcher/config.json`

## 5. Limitations

- **Logged is not measured.** The log shows when a file appeared, not when the
  measurement was taken, and not whether the data are genuine (Section 3.1).
- **The researcher must run it.** The log covers only periods when the watcher
  ran. Changes made while it was off are visible at the next start, but data
  collected entirely outside the watched folder are not.
- **The researcher's computer is trusted for the moment of writing.** Someone
  with full control of the computer can change a file before the watcher
  first sees it.
- **Outside services.** If the beacons or timestamp services are unreachable,
  the time windows of affected entries become wider. The log still records
  them, and receipts obtained later still cover them.
- **Program signing.** The program files are not signed with a paid code
  signing certificate, so Windows and macOS warn the first time they are run.
- **Typed tokens are visible** in the window while they are entered.

## 6. Reporting

A methods section can say, for example:

> All data were collected into a folder watched by datawatcher 0.1.0
> (Lakens, 2026), which logged every version of every file with outside
> timestamps. The log's first entry has fingerprint `e3dd5787…`, which is
> listed in the preregistration (https://osf.io/xxxxx). The full log is
> available at https://doi.org/10.5281/zenodo.xxxxxxx. The analysed data files
> have SHA-256 fingerprints `…` and `…`, which appear in the log as entries 812
> and 815; both were first logged after the preregistration's last timestamp.

## References

Adams, C., Cain, P., Pinkas, D., & Zuccherato, R. (2001). *Internet X.509
Public Key Infrastructure Time-Stamp Protocol (TSP)* (RFC 3161). Internet
Engineering Task Force.

Crosby, S. A., & Wallach, D. S. (2009). Efficient data structures for
tamper-evident logging. In *Proceedings of the 18th USENIX Security Symposium*
(pp. 317–334).

Haber, S., & Stornetta, W. S. (1991). How to time-stamp a digital document.
*Journal of Cryptology, 3*(2), 99–111.

Kelsey, J., Brandão, L. T. A. N., Peralta, R., & Booth, H. (2019). *A
reference for randomness beacons: Format and protocol version 2* (NISTIR 8213,
draft). National Institute of Standards and Technology.

Laurie, B., Langley, A., & Kasper, E. (2013). *Certificate Transparency*
(RFC 6962). Internet Engineering Task Force.

Nosek, B. A., Ebersole, C. R., DeHaven, A. C., & Mellor, D. T. (2018). The
preregistration revolution. *Proceedings of the National Academy of Sciences,
115*(11), 2600–2606.

Schneier, B., & Kelsey, J. (1999). Secure audit logs to support computer
forensics. *ACM Transactions on Information and System Security, 2*(2),
159–176.

Todd, P. (2016). *OpenTimestamps: Scalable, trust-minimized, distributed
timestamping with Bitcoin.* https://petertodd.org/2016/opentimestamps-announcement

Wagenmakers, E.-J., Wetzels, R., Borsboom, D., van der Maas, H. L. J., &
Kievit, R. A. (2012). An agenda for purely confirmatory research.
*Perspectives on Psychological Science, 7*(6), 632–638.

Yamada, Y. (2018). How to crack pre-registration: Toward transparent and open
science. *Frontiers in Psychology, 9*, 1831.

---

# Tutorial

This tutorial goes through a complete study, from installing the program to
checking a published log. Steps 1 to 4 are done once. Steps 5 to 9 follow the
study. Step 10 is for reviewers and readers.

## Step 1. Download the program

Go to <https://github.com/Lakens/datawatcher/releases> and download the file
for your computer:

| Computer | File |
|---|---|
| Windows (almost all) | `datawatcher-windows-amd64.exe` |
| Windows on ARM (e.g. Surface Pro X, Snapdragon laptops) | `datawatcher-windows-arm64.exe` |
| Mac with Apple chip (M1 or later) | `datawatcher-darwin-arm64.zip` |
| Mac with Intel chip | `datawatcher-darwin-amd64.zip` |
| Linux | `datawatcher-linux-amd64.zip` or `datawatcher-linux-arm64.zip` |

To see which Mac you have, open the Apple menu and choose *About This Mac*. The
line *Chip* says Apple M1, M2, and so on; *Processor* with Intel means an Intel
Mac.

Put the program anywhere, for example in your Documents folder. It can also be
inside the study folder; it will not log itself.

**First start on Windows.** Double-click the file. Windows may show "Windows
protected your PC". Click *More info* and then *Run anyway*. This appears
because the program is not signed with a paid certificate. Your institute's
IT policy may block programs that are not signed; in that case, ask IT to
allow it.

**First start on a Mac.** Double-click the zip file to unpack it, then
double-click `datawatcher-darwin-arm64` (or `-amd64`). macOS will say it cannot
check the program for malicious software. Open *System Settings → Privacy &
Security*, scroll down to the message about datawatcher, and click *Open
Anyway*. Then double-click the program again. It opens in a Terminal window.

**First start on Linux.** Unpack the zip file, then run `./datawatcher-linux-amd64`
in a terminal.

## Step 2. Create a GitHub repository and token (recommended)

The GitHub copy is what lets others see that the log was not rewritten, so it
is strongly recommended.

1. Sign in at <https://github.com> (create a free account if needed).
2. Click **+** at the top right, then **New repository**. Choose a name, for
   example `mystudy-log`. Choose **Public**, so that others can see the
   history. Click **Create repository**.
3. Create a token that can write only to this repository. Open
   <https://github.com/settings/personal-access-tokens/new>, which is the page
   for creating a *fine-grained* token.
   - **Token name:** for example `datawatcher mystudy`.
   - **Expiration:** choose a date after the end of data collection. When the
     token expires, uploads stop until you enter a new one (Step 4,
     `-setup`).
   - **Repository access:** *Only select repositories*, and select the
     repository you just created.
   - **Permissions:** under *Repository permissions*, set **Contents** to
     **Read and write**. Leave everything else as it is.
   - Click **Generate token** and copy it. It starts with `github_pat_`. GitHub
     shows it only once.

Keep the token private. Anyone who has it can change files in that repository.

## Step 3. Create a Zenodo token (optional)

If you want to publish the log with a DOI, you need a Zenodo token. Try
everything first on the Zenodo test site, which has its own accounts and
tokens, and whose records are not permanent:

1. Sign in at <https://sandbox.zenodo.org> (for testing) or
   <https://zenodo.org> (for real use). You can sign in with your ORCID or
   GitHub account.
2. Open the account menu at the top right, choose **Applications**, and under
   **Personal access tokens** click **New token**.
3. Give it a name, tick the scopes **deposit:write** and **deposit:actions**,
   and click **Create**. Copy the token.

Publishing on the real Zenodo site creates a permanent record with a DOI that
cannot be deleted. That is the point, but test on the sandbox first.

## Step 4. Set up the study folder

Create a folder for the study, for example:

```
mystudy/
  preregistration/
  data/
```

Everything inside `mystudy` will be logged. Put materials, the
preregistration, and the data inside it. Keep temporary files, large analysis
outputs that change all the time, and anything private outside it. The log is
public, so file *names* become public as well (file contents do not, only
their fingerprints). Do not use participant names in file names.

Start datawatcher by double-clicking it. Answer the questions:

```
datawatcher 0.1.0

Folder to watch (you can drag the folder into this window, then press Enter):
```

Drag the `mystudy` folder into the window and press Enter. On Windows you can
also copy the path from the address bar of File Explorer and paste it with a
right-click.

```
Setting up C:\Users\you\Documents\mystudy

Your ORCID iD, for example 0000-0002-1825-0097: 0000-0002-1825-0097
This ORCID record belongs to Carberry, Josiah. Is that you? [Y/n]
```

The program reads your name from your public ORCID record. Press Enter to
confirm. If your ORCID record has no public name, you are asked to type it as
"Family name, Given names".

```
GitHub: the log can be copied to a GitHub repository every 30 seconds.
Each copy becomes a public, dated commit.
Repository as owner/name (press Enter to skip): yourname/mystudy-log
Create a fine-grained token at https://github.com/settings/personal-access-tokens/new
with access to only this repository and the permission Contents: Read and write.
Token (it will be stored in your user settings folder, not in the watched folder): github_pat_...
Where in the repository should the log go? [mystudy/chain.jsonl]
```

Type the repository as `yourname/repositoryname`, paste the token, and press
Enter to accept the suggested place for the log. The program checks the
repository and token immediately and tells you if they do not work.

```
Zenodo: at the end of each session you can publish the log as a new version
of one Zenodo record. Every version gets a permanent DOI and cannot be deleted.
Offer to publish to Zenodo at the end of each session? [y/N] y
Use the Zenodo test site (sandbox.zenodo.org) instead of the real one? [y/N] y
Create a token at https://sandbox.zenodo.org/account/settings/applications/tokens/new/
with the scopes deposit:write and deposit:actions.
Token (stored in your user settings folder):
```

Then the watcher starts:

```
Watching: C:\Users\you\Documents\mystudy
Log:      C:\Users\you\Documents\mystudy\.provenance\chain.jsonl
GitHub:   yourname/mystudy-log/mystudy/chain.jsonl
Zenodo:   you will be asked at the end of the session

Started a new log. The fingerprint of its first entry is
  e3dd57875682ec33393eac4a34632256bb8670e49b8da89128c97dba634974e7
Put this fingerprint in your preregistration, so that this log is the only one that counts for the study.

Checking the files already in the folder...
0 files are in the log. Watching for changes.
Type stop and press Enter to end the session.

16:47:52  timestamped entries up to 1 (freetsa.org, DigiCert, OpenTimestamps)
```

**Copy the fingerprint of the first entry** into a document you will use for
the preregistration. You can find it again later: the checking script prints
it near the top of its output (Step 10).

To change these settings later, start the program from a terminal with
`datawatcher -setup`, or on Windows create a shortcut to the program and add
` -setup` after the program path in the shortcut's *Target* field.

## Step 5. Write and log the preregistration

Write the preregistration. Include a sentence such as:

> Data collection will be logged with datawatcher. The log's first entry has
> SHA-256 fingerprint e3dd5787…974e7. The log will be published on Zenodo.

Save the final version as a PDF (or another format that will not change when
opened) in `mystudy/preregistration/`, with the watcher running. Within a few
seconds the window shows:

```
16:52:16  added    preregistration/prereg.pdf  73cb3858a687
```

and within five minutes:

```
16:56:21  timestamped entries up to 4 (freetsa.org, DigiCert)
```

From then on, two independent services have signed that this exact file
existed. Now submit the **same file** to your registry (OSF, AsPredicted,
or a journal for a Registered Report). Do not edit it again. If you have to,
save the new version under a new name, so both versions and their order are
visible in the log.

## Step 6. Collect data

Set your experiment software to save its output files in `mystudy/data/`:

- **E-Prime:** E-Prime saves its `.edat` and `.txt` files in the folder of the
  experiment file it runs. Put the experiment file in `mystudy/data`, and
  check after the first test session that the data files appear there.
- **PsychoPy:** the data folder is set in *Experiment settings → Data → Data
  filename*. Make it point to `mystudy/data`.
- **jsPsych, lab.js, or other online studies, and Qualtrics or Prolific:**
  download each export into `mystudy/data` as soon as possible after collection.
  The log then shows when each export was made, and the platform's own start
  and end times inside the export provide an extra check.
- **Physiological recordings, EEG, eye tracking:** point the recording software
  to a subfolder of `mystudy/data`. Large files are fine; a file is
  fingerprinted once it has stopped changing.

Leave the datawatcher window open during data collection. You will see a line
for each new or changed file:

```
10:14:03  added    data/sub-001_session1.csv  e0a2e8d23ddf
10:41:27  added    data/sub-002_session1.csv  9b1e44a0c7f2
```

Some practical points:

- **A program keeps a file open while it writes.** The file is logged once it
  has stayed unchanged for one check, so a file that grows during a session
  may be logged several times as it grows. Each version is in the log, and the
  last one is the final file.
- **The computer sleeps or the network fails.** The watcher continues where it
  left off. Entries written without internet have no beacon values or have
  older ones, and receive receipts when the connection returns. Their time
  windows are wider, but they are still in the log.
- **Several lab computers.** Run one watcher, with its own folder and log, on
  each computer, and list the first-entry fingerprint of every log in the
  preregistration.
- **The data folder is in OneDrive, Dropbox or SURFdrive.** This works, but
  turn off "files on demand" for that folder. Otherwise the watcher downloads
  each file to fingerprint it.
- **Excluding data.** Do not delete data files from the watched folder to
  exclude them. Exclude them in the analysis and report it. A removal is
  logged and will need to be explained.

## Step 7. End a session

Type `stop` and press Enter (or press Ctrl+C):

```
Ending the session...
17:00:10  timestamped entries up to 19 (freetsa.org, DigiCert, OpenTimestamps)
Session ended. The log has 21 entries; the fingerprint of the last one is
  d9d61f9046d968ddc3ebb4ebe6342e92dffabae33992dcc41452c01099e480b6

Publish this log as a new version on Zenodo? This creates a permanent public record. [y/N]
```

Answer `y` at sensible moments: after the preregistration is logged, at the
end of each week of data collection, and at the end of data collection. On
other days answer `n` or press Enter. The GitHub copy is updated regardless.
After publishing you see the DOIs:

```
Published. DOI of this version: 10.5281/zenodo.618608
DOI of all versions together:   10.5281/zenodo.618607
```

The second DOI always leads to the newest version; cite that one in the paper.

If you close the window instead of typing `stop`, the program records the end
of the session but skips the final receipts and uploads. The next session
obtains them.

The next day, double-click the program again. It asks:

```
Watch C:\Users\you\Documents\mystudy again? [Y/n]
```

Press Enter. It checks every file, logs anything that changed while it was not
running (marked "happened while nothing was watching"), and continues the same
log.

## Step 8. Record which files were analysed

In the analysis script, compute and print the fingerprint of every data file
it reads, so that the output shows which logged version was used.

**R** (with the `digest` package):

```r
library(digest)
files <- list.files("mystudy/data", pattern = "\\.csv$", full.names = TRUE)
fingerprints <- data.frame(
  file = files,
  sha256 = vapply(files, digest, character(1), algo = "sha256", file = TRUE)
)
print(fingerprints, row.names = FALSE)
write.csv(fingerprints, "analysed_files_sha256.csv", row.names = FALSE)
dat <- do.call(rbind, lapply(files, read.csv))
```

The `openssl` package gives the same result:
`as.character(openssl::sha256(file("mystudy/data/sub-001.csv")))`.

**Python:**

```python
import hashlib, pathlib
for p in sorted(pathlib.Path("mystudy/data").glob("*.csv")):
    print(p, hashlib.sha256(p.read_bytes()).hexdigest())
```

**Command line:** `sha256sum file.csv` (Linux, Git Bash),
`shasum -a 256 file.csv` (macOS), or `certutil -hashfile file.csv SHA256`
(Windows).

Keep the analysis scripts in the watched folder too. The log then also shows
when the analysis code was written relative to the data.

## Step 9. Report

At the end of data collection, publish a final Zenodo version. In the paper:

- cite the Zenodo concept DOI of the log;
- give the first-entry fingerprint and point to the preregistration that
  contains it;
- list the fingerprints of the analysed data files (or share
  `analysed_files_sha256.csv` with the data);
- mention any `file_removed` entries, `found_at_startup` entries, and gaps
  between sessions, with a short explanation.

Section 6 gives an example text.

## Step 10. Check a log (for reviewers and readers)

You need the log (`chain.jsonl`, from the Zenodo record or the GitHub
repository), the preregistration, and, if shared, the data files. You also
need Python 3 (any recent version) and the script
[`tools/check_log.py`](tools/check_log.py) from the datawatcher repository.
The script uses only Python's standard library and does not use any
datawatcher code.

**10.1 Links, time windows and data files.**

```
python check_log.py chain.jsonl --data path/to/shared/data --online
```

Example output (from the example log in this repository):

```
OK: all 35 entries are correctly linked.
First entry fingerprint (compare with the preregistration): e3dd57875682ec33393eac4a34632256bb8670e49b8da89128c97dba634974e7
Last entry fingerprint:  95dcd91fea58301afd03620c92b6e5493fda4d909cff28e9acf0341d279f08aa
Log started for ORCID 0000-0002-1825-0097, folder 'data', with datawatcher 0.1.0
Sessions: 6 started, 6 ended normally

File history (time window: written after .. existed by):
      2 added    prereg.txt                     f09d2ec9dbea 2026-10-10 14:47:30 UTC .. 2026-10-10 14:47:49 UTC  [happened while not watching]
      5 changed  session1.csv                   e9e0f519d9e2 2026-10-10 14:47:30 UTC .. 2026-10-10 14:47:59 UTC
      7 removed  prereg.txt                                  2026-10-10 14:47:30 UTC .. 2026-10-10 14:48:06 UTC
     ...

Files in path/to/shared/data:
  session1.csv: logged in entry 28, written after 2026-10-10 15:06:00 UTC, existed by 2026-10-10 15:06:47 UTC (DigiCert)

Comparing beacon values with the public archives...
  checked 13 beacon values, 0 mismatches
```

If a data file was changed after it was logged, the script says:

```
  session1.csv: NOT IN THE LOG (this version was never logged)
WARNING: 1 file(s) do not match any logged version.
```

Then go through this list:

1. The first-entry fingerprint matches the one in the registered
   preregistration.
2. The preregistration's entry has an "existed by" time, and the registry's own
   timestamp, before the "written after" time of the first data file.
3. The registered preregistration file has the same fingerprint as the logged
   one (compute it with one of the commands in Step 8).
4. Every analysed data file is in the log.
5. `--online` reports 0 mismatches. This means the beacon values in the log are
   the real published values.
6. Look at the file history. Do files appear in a pattern that fits the
   described data collection? Are there removals, or many changes found at
   startup? Do the times match the dates recorded inside the data files?
7. Compare with the public copies. On GitHub, open the log file and click
   *History*: the commits should run through the collection period, and each
   should be a shorter version of the final log. On Zenodo, each version
   should likewise be a shorter version of the next.

**10.2 Check the signatures of the timestamp receipts.** The script reports the
receipt times, but checking the signatures requires `openssl`. It is
preinstalled on macOS and Linux, and comes with Git for Windows (use Git
Bash).

```
python check_log.py chain.jsonl --receipts receipts
cd receipts
```

This saves every receipt as a `.tsr` file and prints the command for each.
For freetsa.org, download its certificates once:

```
curl -O https://freetsa.org/files/cacert.pem
curl -O https://freetsa.org/files/tsa.crt
openssl ts -verify -in entry3-freetsa.org.tsr -digest <anchored_hash> -CAfile cacert.pem -untrusted tsa.crt
```

For DigiCert, the root certificate is in the standard certificate collection
of your system. The certificates of the service itself are in the first
DigiCert receipt of each session; extract them once:

```
openssl ts -reply -in entry3-DigiCert.tsr -token_out -out token.der
openssl pkcs7 -inform DER -in token.der -print_certs -out digicert.pem
openssl ts -verify -in entry5-DigiCert.tsr -digest <anchored_hash> -CAfile /etc/ssl/cert.pem -untrusted digicert.pem
```

The standard certificate collection is `/etc/ssl/cert.pem` on macOS,
`/etc/ssl/certs/ca-certificates.crt` on Debian and Ubuntu, and
`/mingw64/etc/ssl/certs/ca-bundle.crt` in Git Bash on Windows. Each command
should print `Verification: OK`. To read the time in a receipt, use
`openssl ts -reply -in entry3-DigiCert.tsr -text`.

**10.3 Check the OpenTimestamps proofs.** The `--receipts` option also saves
each OpenTimestamps proof as a pair: `entry-000003.txt` (the log entry it
covers) and `entry-000003.txt.ots` (the proof). Go to
<https://opentimestamps.org>, drop the `.ots` file on the page, and then the
`.txt` file. The site completes the proof from the calendar server and shows
the Bitcoin block and its date.

## Troubleshooting

**"The existing log could not be used: entry N does not match the entry before
it."** The log file was changed, for example by opening and saving it in a text
editor that changed the line endings, or by a file-sync conflict. Do not
repair it by hand. Restore the latest copy from GitHub (the repository holds
every version), then start the program again. If the most recent entries are
missing from the copy, the program will add the changes again as
`found_at_startup`.

**"The last line of chain.jsonl is incomplete."** The computer stopped while
an entry was being written. Restore the latest copy from GitHub, as above.

**"Warning: no timestamp from freetsa.org"** or **"NIST beacon: …"**. One
outside service is unreachable. The program continues and tries again. One
working service of each kind is enough.

**"GitHub upload failed, will try again"** with status 401. The token expired.
Create a new one (Step 2) and run `datawatcher -setup`.

**A file is not logged.** It may still be open in another program and keep
changing, or be locked. It is logged once it stops changing. Files whose name
starts with `~$` or `._`, and the system files listed in Section 4.2, are
skipped on purpose.

**Changing the watched folder's location.** Move the whole folder, including
`.provenance`. The log uses paths relative to the watched folder, so nothing
changes in the log. Start the program and give it the new location.

**Options.** Run `datawatcher -help` to see them: `-setup` (ask the questions
again), `-anchor-every` (how often to obtain receipts, default `5m`),
`-push-every` (GitHub uploads, default `30s`) and `-ots-every`
(OpenTimestamps, default `1h`). A folder can be given after the options, for
example `datawatcher C:\Users\you\Documents\mystudy`.
