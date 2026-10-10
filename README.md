# datawatcher

datawatcher watches a folder and keeps a tamper-evident log of every version
of every file in it. The log shows when each file version existed, using times
that the researcher cannot control. You can use it to show that a
preregistration existed before data collection began, and that the data files
analysed are the ones that were logged during collection.

It is one program file with nothing to install.

**Read [paper.md](paper.md)** for the idea, how it works, what it can and
cannot show, and a step-by-step tutorial.

## Download

Download the file for your computer from the
[releases page](https://github.com/Lakens/datawatcher/releases). Step 1 of the
[tutorial](paper.md#tutorial) explains which file to choose and how to start it
the first time.

## In short

1. Double-click the program and answer the questions: the folder to watch,
   your ORCID iD, and optionally a GitHub repository and a Zenodo token.
2. Put the fingerprint of the log's first entry in your preregistration.
3. Leave the window open while you collect data. Type `stop` and press Enter
   to end a session.

The log is kept in the `.provenance` folder inside the watched folder. Tokens
are stored in your user settings folder, never in the watched folder.

## Checking a log

[`tools/check_log.py`](tools/check_log.py) checks a log without using any
datawatcher code (Python 3, standard library only):

```
python tools/check_log.py chain.jsonl --data path/to/data --online --receipts receipts
```

[`example/chain.jsonl`](example/chain.jsonl) is a log from a test run that you
can practise on.

## Building

Install Go, then run `sh build.sh`. The program uses only Go's standard
library. Tests: `go test ./...`.

## License

GPL-3.0. See [LICENSE](LICENSE).
