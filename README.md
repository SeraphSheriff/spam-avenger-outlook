# Spam Avenger for Outlook

The Spam Avenger trace-and-report panel as an Office Add-in — the same
engine, the same panel, the same rules as
[Spam Avenger for Gmail](https://github.com/SeraphSheriff/spam-avenger),
running in Outlook on Windows, Mac, and the web.

Open a message, click **Spam Avenger**, and the pane traces the message
to the server that really sent it: origin IP, host, network owner, the
abuse desk's published contact, the red flags, and the links in the
body. The pane is an accordion (v1.2.3): every task starts as one
collapsed button in a stack, and clicking it expands that task's
instructions and details — one task open at a time, so the pane
stays focused on what you're doing.

- **Abuse complaint — ready to send** — *Open in Outlook* opens a
  compose pre-filled to the abuse desk (review and send it yourself;
  nothing is ever sent automatically).
- **Report it** — *Report to FTC* and *Report to Google Safe
  Browsing* walk you through the form from inside their sections:
  the "Open the … form" button opens the form and the case details
  are copied for pasting (an add-in can't fill in a web form, and
  the panel says so). *Forward phish to APWG + CISA* opens a compose
  to both intake desks carrying the full headers and evidence, and
  *Report to Microsoft* points at Outlook's own Report button.
- **Not Spam but still unwanted?** — drafts a formal data-deletion
  demand under your state's privacy law (lib/demand.js, the same
  letter engine as the Gmail version). Your details are stored only
  in this browser's local storage.

**Privacy:** everything runs in the pane, on your machine. No data
leaves the client except RDAP lookups of the *sender's* IP — the same
lookups the Gmail version makes. No server, no account, no tracking.

**Platform note:** Office Add-ins only run on Exchange-backed accounts
(Outlook.com, Microsoft 365). Messages in IMAP/POP accounts added to
Outlook can't host add-ins — that's a Microsoft platform limit, not
an add-in setting.

## Sideload it (testing)

You need `manifest.xml` from this repo (download the raw file).

1. Save `manifest.xml` to your PC (Downloads is fine).
2. In your browser, go to **https://aka.ms/olksideload** and sign in with
   the Outlook account you want it on. That opens Outlook on the web
   with the Add-ins dialog up.
3. Click **My add-ins**.
4. Under **Custom Add-ins**, choose **Add a custom add-in → Add from File…**
5. Pick `manifest.xml`, then **Install** on the warning dialog (the
   warning just means "not from the store" — that's what sideloading is).
6. Restart the Outlook app. Open any email, click the **Apps** button on
   the message, and choose **Spam Avenger**. You can pin it from there.

Already had the test skeleton installed? Remove the old custom add-in
in that same dialog first, then add this manifest — the display name
changed from "Spam Avenger for Outlook (Test)" to "Spam Avenger for
Outlook".

## Files

| File | What it is |
|---|---|
| `taskpane.html` / `.js` / `.css` | The panel (Phase 1, v1.2.3 — accordion layout: one focused task expanded at a time) |
| `commands.html` / `.js` | Minimal FunctionFile the manifest requires |
| `analyze.js` | The Spam Avenger engine (unmodified copy of the Gmail build) |
| `demand.js` | The data-deletion demand engine (Gmail build; only the storage choke point differs — localStorage instead of chrome.storage) |
| `icon16.png` / `icon48.png` / `icon128.png` | Shield icons |
| `manifest.xml` | The add-in manifest (what you sideload) |

Hosted at https://seraphsheriff.github.io/spam-avenger-outlook/ via GitHub Pages.
