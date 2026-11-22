# Read a dashboard value

Use this when you need a count or named state from a dashboard WEIR can already observe. Supply the visible label and, for an image-only value, a rectangle containing both the label and its value. The reading records what the page showed at the source capture time.

## From an existing observation

Use the evidence directory, SQLite session ledger and site profiles belonging to the original browser broker. Set `WEIR_PROFILE_DIR` if that broker used a custom profile directory. For image reads, install WEIR with its `visual` extra and the trusted Lugos Aire package in the same virtual environment. Windows can use Windows Media OCR with an installed language. For RapidOCR, install `onnxruntime` and provision its detector, classifier and recognizer model files before the first read.

    weir visual read --sessions browser.sqlite3 --store evidence --capture CAPTURE_ID --label "In review" --region 32 32 480 96

The four numbers are the left edge, top edge, width and height in original screenshot pixels. Start from the upper left. The rectangle must fit inside the image, cover at most 1,048,576 opaque pixels and measure at most 2,048 pixels on either side. Counts include zero. For a named state, supply allowed values, for example `--label "Build" --choice Passing --choice Failed`.

The command writes a JSON reading with an ID, value, method, original URL, capture time and evidence references. Exit code 0 means it found a value. Exit code 3 means a person needs to inspect the evidence. Exit code 2 reports an invalid request, policy rejection or evidence verification failure.

    weir visual show --sessions browser.sqlite3 --store evidence --reading READING_ID --export-crop dashboard.png

The second command works after the browser closes and without an OCR runtime. It verifies the observation and reading against their ledger entries, parses each reader's retained text again and compares the crop with the original screenshot pixels. Replay requires the same bound site policy. A subsequent change to that policy can deny access to the archived reading. The optional export creates a new file. It inherits the sensitivity of the source dashboard.

## From an open browser session

Use `weir.visual_evidence.observe_value` with the broker, its session ID, the owning `WorkContext`, a `ValueQuery`, the caller's expected revision and epoch, and an operation ID. Pass a `Region` to allow a targeted fallback. The helper first asks the existing worker for a structured observation. If the label cannot be read, it requests a fresh atomic observation with a screenshot through the same broker. Both passes respect its controller, domain and profile checks. A structured answer or duplicate label ends the search immediately. A saved capture without a screenshot reports `screenshot_missing` if the operator requests pixels.

## Interpretation and evidence

The source includes the committed browser session revision and epoch. If an observation fails partway, reload the session from the broker and use a fresh operation ID with its current revision before trying again.

Aire owns the local visual interpretation role called Argus in the original roadmap. Its region readers receive only the crop. On Windows, WEIR uses Windows Media OCR and RapidOCR together when both are available. With one backend it compares the original and a larger, contrast-adjusted rendering and records the shared engine. Agreement can still reproduce the same OCR error. Model downloads are disabled during RapidOCR inference.

An answer needs the full label followed by exactly one nonnegative integer or one supplied state. Two matching visual readings yield a value. Conflicting readings, duplicate labels, unreadable regions and unavailable readers carry a null value. The receipt retains the bounded candidates, source and crop for inspection. All outputs inherit the source data classification and untrusted-content label.

Pixel retention requires a bound read-only site profile with full screenshot evidence enabled. The read command registers the digest of the derived evidence in the existing browser ledger. The show command opens that ledger read-only. A missing ledger is an error. Install the reader in the same virtual environment as WEIR so its isolated Python process can load the trusted packages. The receipt records an observation and carries no website action authority.

WEIR 0.8.0 was exercised with authenticated Chromium fixtures on Windows and Debian. The release record includes the two OCR candidates, the ambiguity results and the Linux replay of a Windows capture. [Acceptance record](acceptance/visual-dashboard-20261122.json)
