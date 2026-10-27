# Spam Avenger for Outlook — skeleton test add-in

A **test skeleton only** — not the full Spam Avenger port, not in any store.

Its one job: prove what Outlook (Office.js) actually hands over for an open
message — subject, sender, full internet headers, body text, attachments —
and prove the existing Spam Avenger analysis engine runs on that data.
Open a message, click **Spam Avenger**, then **Inspect this message** in the
pane. It displays every field it could (and could not) read, then runs the
engine on the reconstructed message and shows the extracted origin IP.

The engine (`analyze.js`) is an unmodified copy of the one shipping in
[Spam Avenger for Gmail](https://github.com/SeraphSheriff/spam-avenger).

**Privacy:** everything runs in the pane, on your machine. No data leaves
the client except RDAP lookups of the *sender's* IP — the same lookups the
Gmail version makes. No server, no account, no tracking.

## Sideload it (testing)

You need `manifest.xml` from this repo (download the raw file).

1. Save `manifest.xml` to your PC (Downloads is fine).
2. In your browser, go to **https://aka.ms/olksideload** and sign in with the
   Outlook account you want it on. That opens Outlook on the web with the
   Add-ins dialog up.
3. Click **My add-ins**.
4. Under **Custom Add-ins**, choose **Add a custom add-in → Add from File…**
5. Pick `manifest.xml`, then **Install** on the warning dialog (the warning
   just means "not from the store" — that's what sideloading is).
6. Restart the Outlook app. Open any email, click the **Apps** button on the
   message, and choose **Spam Avenger**. You can pin it from there.

## Files

| File | What it is |
|---|---|
| `taskpane.html` / `.js` / `.css` | The test pane |
| `commands.html` / `.js` | Minimal FunctionFile the manifest requires |
| `analyze.js` | The Spam Avenger engine (unmodified copy) |
| `icon16.png` / `icon48.png` / `icon128.png` | Shield icons |
| `manifest.xml` | The add-in manifest (what you sideload) |

Hosted at https://seraphsheriff.github.io/spam-avenger-outlook/ via GitHub Pages.
