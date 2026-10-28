/* Spam Avenger for Outlook — task pane (Phase 1, v1.1.2).
 *
 * The Gmail addon's panel, rebuilt on Office.js. On open (and on
 * item change) it runs the trace automatically: full internet
 * headers + body from Office.js, then the SAME engine the Gmail
 * version ships (analyze.js investigate(): header parse, origin
 * IP, RDAP abuse contact, reverse DNS, complaint builder) and the
 * SAME demand-letter engine (demand.js) for the PID section.
 *
 * Mirrors the Gmail panel's layout, wording, section order and
 * button colors. The differences are platform-forced and labeled
 * in place: Outlook compose windows replace Gmail compose links
 * (displayNewMessageForm — nothing is ever sent by the add-in),
 * and the Safe Browsing / FTC lanes degrade to "open the form +
 * copy the case details" because an add-in cannot fill in a web
 * form the way a content script can.
 *
 * Every async call is wrapped with a timeout and every failure
 * surfaces as a short user-readable line carrying the version
 * tag — the pane never hangs silently.
 */
(function () {
  "use strict";

  var VERSION = "1.1.2";
  var TAG = "v" + VERSION;

  function $(id) { return document.getElementById(id); }

  // textContent-only element builder, same shape as the Gmail
  // panel's h(): no innerHTML anywhere, so message content can
  // never become markup in the pane.
  function h(tag, attrs) {
    var el = document.createElement(tag);
    if (attrs) {
      Object.keys(attrs).forEach(function (k) {
        if (k === "class") el.className = attrs[k];
        else el.setAttribute(k, attrs[k]);
      });
    }
    for (var i = 2; i < arguments.length; i++) {
      var c = arguments[i];
      if (c === null || c === undefined || c === false) continue;
      if (Array.isArray(c)) {
        c.forEach(function (x) {
          if (x !== null && x !== undefined && x !== false) {
            el.appendChild(typeof x === "object" ? x : document.createTextNode(String(x)));
          }
        });
      } else {
        el.appendChild(typeof c === "object" ? c : document.createTextNode(String(c)));
      }
    }
    return el;
  }

  function clearEl(el) { while (el.firstChild) el.removeChild(el.firstChild); }

  function errText(e) {
    if (!e) return "unknown error";
    var name = e.name || "";
    var msg = e.message || String(e);
    return (name && name !== msg) ? name + " — " + msg : msg;
  }

  function esc(s) {
    return String(s == null ? "" : s)
      .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  }

  // Plain text -> htmlBody for displayNewMessageForm, in a <pre>
  // so the complaint's aligned evidence fields keep their shape.
  function textToHtml(text) {
    return '<pre style="font-family:Consolas,\'Courier New\',monospace;' +
      'font-size:13px;white-space:pre-wrap;word-wrap:break-word;">' +
      esc(text) + "</pre>";
  }

  // THE shared clipboard helper — every copy action in the pane
  // goes through here. The async clipboard API is unreliable
  // inside the Office add-in webview (v1.1.1 field result: the
  // FTC case-details copy silently never landed), so a copy is
  // only ever CLAIMED after one of the real paths worked:
  //   "api"    navigator.clipboard.writeText resolved
  //   "exec"   temp textarea + document.execCommand("copy")
  //   "manual" both failed — opts.onManual() runs (callers use it
  //            to reveal the text on screen), opts.selectEl's
  //            contents are selected, and the status line tells
  //            the user to press Ctrl+C. Never a fake "Copied!".
  // statusEl (optional) receives the outcome line:
  // opts.successText on api/exec, opts.manualText on manual.
  function copyText(text, statusEl, opts) {
    opts = opts || {};
    function say(msg) {
      if (statusEl) { try { statusEl.textContent = msg; } catch (e) {} }
    }
    function manual() {
      if (opts.onManual) { try { opts.onManual(); } catch (e) {} }
      var el = opts.selectEl || null;
      if (el) {
        try { if (el.focus) el.focus(); } catch (e) {}
        try {
          if (typeof el.select === "function") el.select();
          else if (el.setSelectionRange) {
            el.setSelectionRange(0, String(el.value || "").length);
          }
        } catch (e) {}
      }
      say(opts.manualText ||
        "⚠ Copy didn't take — the text above is selected, " +
        "press Ctrl+C (" + TAG + ").");
      return "manual";
    }
    function legacy() {
      var tmp = null;
      try {
        tmp = document.createElement("textarea");
        tmp.value = text;
        tmp.setAttribute("readonly", "");
        tmp.style.position = "absolute";
        tmp.style.left = "-9999px";
        tmp.style.top = "0";
        document.body.appendChild(tmp);
        tmp.select();
        var ok = false;
        try { ok = !!document.execCommand("copy"); } catch (e) { ok = false; }
        document.body.removeChild(tmp);
        if (ok) {
          say(opts.successText || "✓ Copied (" + TAG + ")");
          return "exec";
        }
        return manual();
      } catch (e) {
        if (tmp && tmp.parentNode) {
          try { tmp.parentNode.removeChild(tmp); } catch (e2) {}
        }
        return manual();
      }
    }
    if (typeof navigator !== "undefined" && navigator.clipboard &&
        typeof navigator.clipboard.writeText === "function") {
      return navigator.clipboard.writeText(text).then(function () {
        say(opts.successText || "✓ Copied (" + TAG + ")");
        return "api";
      }, function () { return legacy(); });
    }
    return Promise.resolve(legacy());
  }

  function flashLabel(btn, text, ms) {
    var orig = btn.textContent;
    btn.textContent = text;
    setTimeout(function () { btn.textContent = orig; }, ms || 1500);
  }

  /* ---------- Office.js reads, promise-wrapped + timed ---------- */

  // Race a promise against a clock; the loser resolves as
  // {ok:false} with a timeout error instead of hanging the pane.
  function timed(promise, ms, label) {
    return Promise.race([
      promise,
      new Promise(function (resolve) {
        setTimeout(function () {
          resolve({ ok: false, error: new Error(label + " timed out after " +
            Math.round(ms / 1000) + "s (" + TAG + ")") });
        }, ms);
      })
    ]);
  }

  function getHeaders(item) {
    var p = new Promise(function (resolve) {
      try {
        if (!item || typeof item.getAllInternetHeadersAsync !== "function") {
          resolve({ ok: false, error: new Error("this Outlook doesn't offer full headers (getAllInternetHeadersAsync unavailable)") });
          return;
        }
        item.getAllInternetHeadersAsync(function (result) {
          try {
            if (result && result.status === Office.AsyncResultStatus.Succeeded) {
              resolve({ ok: true, value: result.value || "" });
            } else {
              resolve({ ok: false, error: (result && result.error) ||
                new Error("Outlook didn't return the headers") });
            }
          } catch (e) { resolve({ ok: false, error: e }); }
        });
      } catch (e) { resolve({ ok: false, error: e }); }
    });
    return timed(p, 20000, "Reading the headers");
  }

  function getBody(item, coercionType, label) {
    var p = new Promise(function (resolve) {
      try {
        if (!item || !item.body || typeof item.body.getAsync !== "function") {
          resolve({ ok: false, error: new Error("this Outlook doesn't offer the message body") });
          return;
        }
        item.body.getAsync(coercionType, function (result) {
          try {
            if (result && result.status === Office.AsyncResultStatus.Succeeded) {
              resolve({ ok: true, value: result.value || "" });
            } else {
              resolve({ ok: false, error: (result && result.error) ||
                new Error("Outlook didn't return the body") });
            }
          } catch (e) { resolve({ ok: false, error: e }); }
        });
      } catch (e) { resolve({ ok: false, error: e }); }
    });
    return timed(p, 20000, label);
  }

  /* ---------- Compose (never sends — the user reviews + sends) --- */

  function openCompose(params, btn) {
    try {
      Office.context.mailbox.displayNewMessageForm(params);
      if (btn) flashLabel(btn, "Opened — review and hit Send", 4000);
      return true;
    } catch (e) {
      if (btn) {
        btn.textContent = "Couldn't open it (" + String(errText(e)).slice(0, 120) +
          ") — " + TAG;
        setTimeout(function () { btn.disabled = false; }, 0);
      }
      return false;
    }
  }

  /* ---------- Panel states ---------- */

  var runSeq = 0;
  var loadingStepEl = null;

  function renderLoading(step) {
    var body = $("panel-body");
    clearEl(body);
    loadingStepEl = h("p", null, step || "Working…");
    body.appendChild(h("div", { "class": "sf-loading" },
      h("div", { "class": "sf-spin" }), loadingStepEl));
  }

  function setStep(step) {
    if (loadingStepEl) {
      try { loadingStepEl.textContent = step; } catch (e) {}
    }
  }

  function renderError(msg) {
    var body = $("panel-body");
    clearEl(body);
    loadingStepEl = null;
    var retry = h("button", { "class": "sf-btn-green", "type": "button" },
      "Try again");
    retry.addEventListener("click", runTrace);
    body.appendChild(h("p", { "class": "sf-warn" }, msg));
    body.appendChild(h("div", { "class": "sf-actions" }, retry));
  }

  function mkRow(label, value, mono) {
    return h("div", { "class": "sf-row" },
      h("span", null, label),
      h("b", mono ? { "class": "sf-mono" } : null, String(value)));
  }

  /* ---------- Case evidence shared by the report lanes ---------- */

  function caseDetailsText(a) {
    var L = [];
    L.push("Spam/phishing report — details collected by Spam Avenger");
    L.push("Sender: " + (a.from || "unknown"));
    L.push("Subject: " + (a.subject || "unknown"));
    L.push("Date: " + (a.date || "unknown"));
    if (a.ip) L.push("Sending IP: " + a.ip);
    if (a.host) L.push("Server: " + SpamAvenger.displayHost(a.host));
    if (a.org) L.push("Network owner: " + a.org);
    if (a.urls && a.urls.length) {
      L.push("Links in the message:");
      a.urls.slice(0, 10).forEach(function (u) { L.push("  " + u); });
    }
    return L.join("\n");
  }

  function forwardBody(a, bodyText) {
    var L = [];
    L.push("Reporting a phishing/spam message received in Outlook. " +
      "The original message could not be attached as a file by the " +
      "add-in, so the full headers and body are pasted below as evidence.");
    L.push("");
    L.push("From: " + (a.from || "unknown"));
    L.push("Subject: " + (a.subject || "unknown"));
    L.push("Date received: " + (a.date || "unknown"));
    if (a.ip) L.push("Sending IP: " + a.ip);
    if (a.host) L.push("Server: " + SpamAvenger.displayHost(a.host));
    if (a.org) L.push("Network owner: " + a.org);
    if (a.urls && a.urls.length) {
      L.push("Links in the message (defanged — read hxxps as https and [.] as .):");
      a.urls.slice(0, 10).forEach(function (u) {
        L.push("  - " + SpamAvenger.defangUrl(u));
      });
    }
    L.push("");
    L.push("----- FULL HEADERS -----");
    var th = SpamAvenger.trimHeaders(String(a.fullHeaders || ""));
    var fh = th.text;
    var truncated = fh.length > 12000;
    if (truncated) fh = fh.slice(0, 12000);
    L.push(fh);
    if (th.stripped) L.push("[ARC/DKIM signature blocks omitted — routing and authentication headers are complete]");
    if (truncated) L.push("[headers truncated at 12000 characters]");
    L.push("");
    L.push("----- ORIGINAL MESSAGE BODY (plain text, links defanged) -----");
    var bt = SpamAvenger.defangText(String(bodyText || a.bodyText || "").slice(0, 8000));
    L.push(bt);
    return L.join("\n");
  }

  /* ---------- Result rendering (mirrors Gmail renderResult) ----- */

  function renderResult(a, bodyText, lookupNote) {
    var body = $("panel-body");
    clearEl(body);
    loadingStepEl = null;

    if (lookupNote) body.appendChild(h("p", { "class": "sf-warn" }, lookupNote));

    // Details start collapsed behind the toggle, exactly like the
    // Gmail panel (v1.0.36): the panel opens focused on the actions.
    var details = h("div", { "class": "sf-details" });
    details.style.display = "none";
    var toggle = h("button", {
      "class": "sf-details-toggle", "type": "button",
      "aria-expanded": "false"
    }, "Show details ▸");
    toggle.addEventListener("click", function () {
      var open = details.style.display !== "none";
      details.style.display = open ? "none" : "";
      toggle.textContent = open ? "Show details ▸" : "Hide details ▾";
      toggle.setAttribute("aria-expanded", open ? "false" : "true");
    });
    body.appendChild(toggle);
    body.appendChild(details);

    details.appendChild(mkRow("From", a.from || "unknown"));
    details.appendChild(mkRow("Subject", a.subject || "(no subject)"));
    if (!a.ip) {
      body.appendChild(h("p", { "class": "sf-warn" },
        "Couldn't find the sending server in the headers. " +
        "That happens with mailing lists, forwards, and some bulk senders. " +
        "Nothing to complain to directly — but the report links below still apply."));
    } else {
      details.appendChild(mkRow("Sending IP", a.ip, true));
      details.appendChild(mkRow("Server",
        a.host ? SpamAvenger.displayHost(a.host) : "unknown"));
      details.appendChild(mkRow("Owned by", a.org || "unknown"));
      details.appendChild(mkRow("Abuse contact", a.abuse || "not published"));
      details.appendChild(h("p", { "class": "sf-note" },
        'The "From" address is makeup. The IP is the face underneath.'));
    }
    if (a.flags && a.flags.length) {
      var fw = h("div", { "class": "sf-flags" }, h("b", null, "Red flags"));
      var ul = h("ul");
      a.flags.forEach(function (f) { ul.appendChild(h("li", null, f)); });
      fw.appendChild(ul);
      details.appendChild(fw);
    }
    // Links found — the trace summary. (In Gmail these only reach
    // the user inside the complaint text; Outlook's report lanes
    // copy them, so they get a visible list of their own.)
    var linksDiv = h("div", { "class": "sf-flags" },
      h("b", null, "Links found (" + (a.urls ? a.urls.length : 0) + ")"));
    if (a.urls && a.urls.length) {
      var lu = h("ul", { "class": "sf-links-list" });
      a.urls.forEach(function (u) { lu.appendChild(h("li", null, u)); });
      linksDiv.appendChild(lu);
    } else {
      linksDiv.appendChild(h("p", { "class": "sf-fine" },
        "No links found in the message body."));
    }
    details.appendChild(linksDiv);

    // Color legend flags, built from what this render actually
    // shows (Gmail v1.0.48 rule: never explain an absent color).
    var showOrange = false;

    if (a.complaint) {
      var c = a.complaint;
      var cw = h("div", { "class": "sf-complaint" },
        h("b", null, "Ready-to-send complaint"));
      var ta = h("textarea", { id: "sf-complaint-text" });
      ta.readOnly = true;
      ta.value = "To: " + c.to + "\nSubject: " + c.subject + "\n\n" + c.body;
      cw.appendChild(ta);
      // OVHcloud deflects emailed complaints to its web form
      // (Gmail panel behavior, confirmed 2026-10-15) — warn upfront.
      if (/ovh/i.test(c.to + " " + (a.org || ""))) {
        var ovhNote = h("p", { "class": "sf-warn" },
          "Heads up: this server belongs to OVHcloud, and their abuse desk " +
          "ignores emailed complaints — they want their web form instead: ");
        ovhNote.appendChild(h("a", {
          href: "https://www.ovhcloud.com/en/abuse/",
          "class": "sf-ovh-btn",
          target: "_blank", rel: "noopener"
        }, "ovhcloud.com/en/abuse"));
        cw.appendChild(ovhNote);
      }
      var copyBtn = h("button", { id: "sf-copy",
        "class": "sf-btn-orange", "type": "button" },
        "Copy complaint — paste it into an email");
      var compBtn = h("button", { id: "sf-compose",
        "class": "sf-btn-green", "type": "button" },
        "Open in Outlook — just click Send");
      showOrange = true;
      cw.appendChild(h("div", { "class": "sf-actions" }, copyBtn, compBtn));
      body.appendChild(cw);
      copyBtn.addEventListener("click", function () {
        copyText(ta.value, null, { selectEl: ta }).then(function (outcome) {
          flashLabel(copyBtn, outcome !== "manual" ? "Copied!" :
            "Copy didn't take — the text above is selected, " +
            "press Ctrl+C (" + TAG + ")", 4000);
        });
      });
      compBtn.addEventListener("click", function () {
        openCompose({
          toRecipients: [c.to],
          subject: c.subject,
          htmlBody: textToHtml(c.body)
        }, compBtn);
      });
    } else if (a.ip && !a.skipComplaint) {
      body.appendChild(h("p", { "class": "sf-warn" },
        "No published abuse contact for this IP. " +
        "Report the links below via Google Safe Browsing instead."));
    } else if (a.skipComplaint) {
      body.appendChild(h("p", { "class": "sf-warn" },
        a.providerAdvice ||
        ("This came from a big mailbox provider’s own servers — " +
         "no complaint generated (it would hit the wrong target).")));
    }

    // Legend (green + yellow are guaranteed by the report row;
    // orange only when the Copy button is on screen).
    var legend = h("p", { "class": "sf-legend" }, "Button colors: ");
    var legendEntries = [
      ["sf-dot-green", " green — Spam Avenger does the work; you just review and send."],
      ["sf-dot-yellow", " yellow — needs a few steps from you, and I'll guide you through them."]
    ];
    if (showOrange) {
      legendEntries.push(["sf-dot-orange",
        " orange — you're on your own with this one; no guide after the click."]);
    }
    legendEntries.forEach(function (e, i) {
      legend.appendChild(h("span", { "class": e[0] }, "●"));
      legend.appendChild(document.createTextNode(
        e[1] + (i < legendEntries.length - 1 ? " " : "")));
    });
    body.appendChild(legend);

    body.appendChild(h("div", { "class": "sf-links" },
      h("b", null, "Also report it: ")));
    var caseStatus = h("p", { "class": "sf-fine", id: "sf-case-status" }, "");

    // Safe Browsing / FTC, degraded per the port sketch: an add-in
    // can't fill in a web form, so the button opens the form AND
    // copies the case details — the guidance line says exactly
    // what to paste where. No autofill is claimed anywhere.
    // v1.1.2: the case details ALSO land in a visible box in the
    // pane BEFORE the copy runs, and stay there — the v1.1.1
    // clipboard write silently failed in the webview, leaving the
    // user at the form with nothing to paste. Now the box is the
    // fallback: if the copy doesn't take, its contents are left
    // selected with a Ctrl+C instruction.
    var caseLabel = h("b", { id: "sf-case-label" }, "");
    var caseTa = h("textarea", { id: "sf-case-text" });
    caseTa.readOnly = true;
    var caseBox = h("div", { "class": "sf-casebox" }, caseLabel, caseTa);
    caseBox.style.display = "none";
    function showCaseBox(label) {
      caseLabel.textContent = label;
      caseTa.value = caseDetailsText(a);
      caseBox.style.display = "";
    }

    var ftcBtn = h("button", { id: "sf-report-ftc",
      "class": "sf-btn-yellow", "type": "button" }, "Report to FTC");
    ftcBtn.addEventListener("click", function () {
      // Order matters: window.open goes FIRST, synchronously in
      // the click handler, because popup blockers eat a tab opened
      // after any await. The box + copy run right after, in the
      // same handler — and if opening the tab steals the focus the
      // clipboard write needs, copyText's select + Ctrl+C fallback
      // below covers it.
      window.open("https://reportfraud.ftc.gov/", "_blank", "noopener");
      showCaseBox("Case details for the FTC form — paste these " +
        "into the Comments box:");
      copyText(caseTa.value, caseStatus, {
        selectEl: caseTa,
        successText: "✓ Copied — the FTC form is open in a new " +
          "tab: click Report Now there, follow the phishing path " +
          "it offers, click the Comments box and press Ctrl+V. " +
          "Spam Avenger can't fill in web forms from Outlook, so " +
          "nothing was filled in for you. If nothing pastes, the " +
          "details stay in the box above — copy them from there.",
        manualText: "⚠ Copy didn't take — the case details in " +
          "the box above are selected: press Ctrl+C, then paste " +
          "them into the FTC form's Comments box with Ctrl+V (" +
          TAG + ")."
      });
    });
    var sbBtn = h("button", { id: "sf-report-sb",
      "class": "sf-btn-green", "type": "button" },
      "Report to Google Safe Browsing");
    sbBtn.addEventListener("click", function () {
      window.open("https://safebrowsing.google.com/safebrowsing/report_phish/",
        "_blank", "noopener");
      showCaseBox("Case details for the Safe Browsing form:");
      var firstLink = (a.urls && a.urls.length)
        ? " The first link in the box is the one to paste into " +
          "the form's URL box."
        : "";
      copyText(caseTa.value, caseStatus, {
        selectEl: caseTa,
        successText: "✓ Copied — the Safe Browsing form is open " +
          "in a new tab: click its URL box and press Ctrl+V, " +
          "then submit." + firstLink + " Spam Avenger can't fill " +
          "in web forms from Outlook, so nothing was filled in " +
          "for you. If nothing pastes, the details stay in the " +
          "box above — copy them from there.",
        manualText: "⚠ Copy didn't take — the case details in " +
          "the box above are selected: press Ctrl+C, then paste " +
          "them into the Safe Browsing form with Ctrl+V (" +
          TAG + ")."
      });
    });
    body.appendChild(h("div", { "class": "sf-actions" }, ftcBtn, sbBtn));
    body.appendChild(caseBox);
    body.appendChild(caseStatus);

    // Forward to APWG + CISA: a compose pre-addressed to both
    // intake desks, carrying the full headers + analysis + body
    // as pasted evidence (a true .eml attachment is phase 2).
    var fwdBtn = h("button", { id: "sf-fwd-phish",
      "class": "sf-btn-green", "type": "button" },
      "Forward phish to APWG + CISA");
    fwdBtn.addEventListener("click", function () {
      openCompose({
        toRecipients: ["reportphishing@apwg.org", "contact@cisa.dhs.gov"],
        subject: "Fwd: " + (a.subject || "(no subject)"),
        htmlBody: textToHtml(forwardBody(a, bodyText))
      }, fwdBtn);
    });
    body.appendChild(h("div", { "class": "sf-actions" }, fwdBtn));

    // Report to Microsoft — honest positioning, no fake API call:
    // Outlook's own Report button is the only route to Microsoft.
    var msGuide = h("p", { "class": "sf-note" },
      "Use Outlook's own Report button: with this message selected, " +
      "click the shield-shaped Report button on the ribbon (Home tab) " +
      "and choose Report phishing. That sends the message to Microsoft " +
      "so their filters learn — it never reaches the sender's host. " +
      "The complaint at the top of this panel is the report that does.");
    msGuide.style.display = "none";
    var msBtn = h("button", { id: "sf-report-ms", "type": "button" },
      "Report to Microsoft");
    msBtn.addEventListener("click", function () {
      var open = msGuide.style.display !== "none";
      msGuide.style.display = open ? "none" : "";
    });
    body.appendChild(h("div", { "class": "sf-actions" }, msBtn));
    body.appendChild(msGuide);

    body.appendChild(h("p", { "class": "sf-fine" },
      "Nothing is sent automatically. You review and send the complaint yourself."));

    renderDemandZone(body, a);
  }

  /* ---------- The trace ---------- */

  function runTrace() {
    var seq = ++runSeq;
    var item = null;
    try { item = Office.context.mailbox.item; } catch (e) { item = null; }
    if (!item) {
      renderError(TAG + " — no message is open. Open a single email " +
        "first, then the trace runs itself.");
      return;
    }
    if (typeof SpamAvenger === "undefined" || !SpamAvenger.investigate) {
      renderError(TAG + " — the Spam Avenger engine (analyze.js) " +
        "didn't load. Try closing and reopening the pane.");
      return;
    }
    renderLoading("Reading the message…");

    var headersP = getHeaders(item);
    var bodyHtmlP = getBody(item, Office.CoercionType.Html, "Reading the body");
    var bodyTextP = getBody(item, Office.CoercionType.Text, "Reading the body");

    Promise.all([headersP, bodyHtmlP, bodyTextP]).then(function (res) {
      if (seq !== runSeq) return; // a newer item took over
      var headers = res[0], bodyHtml = res[1], bodyText = res[2];
      if (!headers.ok) {
        renderError(TAG + " — Outlook didn't hand over this message's " +
          "headers, so there's nothing to trace. (" +
          errText(headers.error) + ") This can happen with some " +
          "accounts and message types.");
        return;
      }
      if (!headers.value || !headers.value.trim()) {
        renderError(TAG + " — the headers came back empty for this " +
          "message, so there's nothing to trace.");
        return;
      }
      // The engine eats headers + body, exactly like a Gmail
      // "Show Original" page. HTML body when we can get it (the
      // links live in the hrefs — body text has none), text body
      // as evidence/display and as the fallback feed.
      var feed = bodyHtml.ok && bodyHtml.value ? bodyHtml.value
        : (bodyText.ok ? bodyText.value : "");
      var raw = headers.value + "\r\n\r\n" + feed;
      var displayText = bodyText.ok ? bodyText.value : "";

      var inv = SpamAvenger.investigate(raw, function (step) {
        if (seq === runSeq) setStep(step);
      });
      var watchdog = new Promise(function (resolve) {
        setTimeout(function () { resolve(null); }, 60000);
      });
      Promise.race([inv, watchdog]).then(function (a) {
        if (seq !== runSeq) return;
        if (!a) {
          // The RDAP/PTR chain outran the watchdog — fall back to
          // the headers alone rather than hanging the pane.
          var partial = null;
          try { partial = SpamAvenger.analyze(raw); } catch (e) {}
          if (partial) {
            if (!displayText) displayText = partial.bodyText || "";
            renderResult(partial, displayText,
              TAG + " — the host lookup timed out, so this trace is " +
              "headers only: no abuse contact was found. You can " +
              "close and reopen the pane to try again.");
          } else {
            renderError(TAG + " — the trace timed out and even the " +
              "headers wouldn't parse. Try again.");
          }
          return;
        }
        if (!displayText) displayText = a.bodyText || "";
        renderResult(a, displayText, null);
      }).catch(function (e) {
        if (seq !== runSeq) return;
        renderError(TAG + " — the trace failed: " + errText(e));
      });
    });
  }

  /* ---------- PID: "Your data in their hands" (demand.js) ------- */
  /* Mirrors the Gmail panel's v1.0.55 demand step: Send-to starts
   * EMPTY in all cases; the sender domain's RDAP registration
   * contact is offered as ONE clickable suggestion, never
   * auto-filled; otherwise the user pastes the address published
   * on the company's own website. The letter is always addressed
   * to the company behind the SENDER domain. Nothing auto-sends. */

  var EXPLAINER = "The buttons above are for strangers and " +
    "scammers. This one is for a company you once dealt with — " +
    "signed up, bought something, or clicked 'accept' on a " +
    "terms box years ago. Their email may be perfectly legal " +
    "and still unwanted. If you want the relationship over " +
    "and your data gone, this drafts a formal deletion demand " +
    "using your state's privacy law.";

  function renderDemandZone(body, a) {
    var D = (typeof window !== "undefined") ? window.SpamDemand : null;
    if (!D) return;

    var demandBody = h("div", { "class": "sf-demand-body" });
    demandBody.style.display = "none";
    var wrap = h("div", { "class": "sf-demand" });
    demandBody.appendChild(wrap);

    var fightGlyph = document.createTextNode("? ▸");
    var fightToggle = h("button", {
      "class": "sf-details-toggle sf-fight-toggle",
      "type": "button", "aria-expanded": "false"
    }, "Not Spam but still ", h("b", null, "unwanted"), fightGlyph);
    fightToggle.addEventListener("click", function () {
      var open = demandBody.style.display !== "none";
      demandBody.style.display = open ? "none" : "";
      fightGlyph.textContent = open ? "? ▸" : "? ▾";
      fightToggle.setAttribute("aria-expanded", open ? "false" : "true");
    });
    body.appendChild(h("div", { "class": "sf-fight" }, fightToggle, demandBody));

    function renderDetailsForm() {
      clearEl(wrap);
      wrap.appendChild(h("b", null, "Your data in their hands"));
      wrap.appendChild(h("p", { "class": "sf-demand-intro" }, EXPLAINER));
      wrap.appendChild(h("p", { "class": "sf-fine" },
        "It needs your details once to fill the letter in — " +
        "they stay in your browser and are used for nothing else."));
      wrap.appendChild(D.buildDetailsForm(function (saved) {
        renderDemandStep(saved);
      }));
    }

    function renderDemandStep(det) {
      clearEl(wrap);
      wrap.appendChild(h("b", null, "Your data in their hands"));
      wrap.appendChild(h("p", { "class": "sf-demand-intro" }, EXPLAINER));
      var senderDom = D.registrableDomain(a.senderDomain || "");
      var rdapState = senderDom ? "pending" : "none";
      var stepOpen = false;
      var step = h("div", { "class": "sf-demand-step" });
      step.style.display = "none";
      var draftBtn = h("button", { id: "sf-demand-draft",
        "class": "sf-btn-green", "type": "button" },
        "Draft a data-deletion demand");
      wrap.appendChild(h("div", { "class": "sf-actions" }, draftBtn));
      wrap.appendChild(h("p", { "class": "sf-fine sf-demand-sub" },
        "— opens in Outlook, just review + Send"));
      wrap.appendChild(step);
      draftBtn.addEventListener("click", function () {
        var open = step.style.display !== "none";
        step.style.display = open ? "none" : "";
        stepOpen = !open;
        draftBtn.textContent = open ? "Draft a data-deletion demand"
          : "Hide the demand ▾";
        if (!open) {
          if (rdapState === "pending") {
            setMx("muted", "Looking up the domain's registration contact…");
          } else {
            runMxCheck();
          }
        }
      });

      step.appendChild(h("div", { "class": "sf-row" },
        h("span", null, "Send to")));
      // NO guessed default, NO auto-fill — the field starts EMPTY
      // in all cases (Gmail v1.0.55 rule).
      var toField = h("input", { "class": "sf-input",
        "type": "text", "aria-label": "Demand recipient" });
      toField.placeholder = "Paste the address from their website";
      step.appendChild(toField);

      // RDAP suggestion row — hidden until the registration lookup
      // lands a contact; clicking it is the only way a record
      // contact reaches the field.
      var rdapContact = null;
      var srcEl = h("button", { "class": "sf-demand-src", "type": "button" });
      srcEl.style.display = "none";
      srcEl.addEventListener("click", function () {
        if (!rdapContact) return;
        toField.value = rdapContact.email;
        refresh();
        runMxCheck();
      });
      step.appendChild(srcEl);

      // Advisory mail-server sanity check under the Send-to field
      // (never blocks the compose button).
      var mxEl = h("p", { "class": "sf-demand-mx" }, "");
      mxEl.style.display = "none";
      step.appendChild(mxEl);
      var mxTimer = null;
      var mxSeq = 0;
      function setMx(kind, text) {
        mxEl.textContent = text || "";
        mxEl.className = "sf-demand-mx" + (kind ? " sf-mx-" + kind : "");
        mxEl.style.display = text ? "" : "none";
      }
      function runMxCheck() {
        var dom = D.mxDomainOf(toField.value);
        var seq = ++mxSeq;
        if (!dom) { setMx("", ""); return; }
        setMx("muted", "Checking whether " + dom + " can receive email…");
        D.checkRecipientMx(toField.value).then(function (res) {
          if (seq !== mxSeq) return;
          if (D.mxDomainOf(toField.value) !== dom) return;
          var cls = res.kind === "ok" ? "ok"
            : res.kind === "error" ? "muted"
            : res.kind === "none" ? "" : "warn";
          setMx(cls, res.text);
        }).catch(function () {
          if (seq === mxSeq) {
            setMx("muted", "Couldn't check " + dom +
              "'s mail servers — the address is a best guess.");
          }
        });
      }
      function scheduleMxCheck() {
        if (mxTimer) clearTimeout(mxTimer);
        mxTimer = setTimeout(runMxCheck, 600);
      }
      toField.addEventListener("input", scheduleMxCheck);

      // The website errand: find the published address, paste it in.
      var instrEl = null;
      if (senderDom) {
        var lookupBtn = h("button", { "class": "sf-lookup-btn",
          "type": "button" },
          "Open " + senderDom + "'s website ↗");
        lookupBtn.addEventListener("click", function () {
          window.open("https://" + senderDom + "/", "_blank", "noopener");
        });
        step.appendChild(lookupBtn);
        instrEl = h("p", { "class": "sf-fine sf-demand-instr" },
          "Look for an email address in the footer or on " +
          "their Privacy Policy page. If you find one, paste " +
          "it into the Send to box above — a published " +
          "address beats any guess we can make, and privacy@ " +
          "is almost always a guess.");
        step.appendChild(instrEl);
      }
      var instrFlashTimer = null;
      function flashInstr() {
        if (!instrEl) return;
        instrEl.classList.remove("sf-flash");
        void instrEl.offsetWidth; // restart the highlight
        instrEl.classList.add("sf-flash");
        if (instrFlashTimer) clearTimeout(instrFlashTimer);
        instrFlashTimer = setTimeout(function () {
          instrEl.classList.remove("sf-flash");
        }, 1800);
      }

      if (senderDom && D.fetchRegistrationContact) {
        D.fetchRegistrationContact(senderDom).then(function (found) {
          rdapState = found ? "found" : "none";
          if (found) {
            rdapContact = found;
            clearEl(srcEl);
            srcEl.appendChild(document.createTextNode(
              "Registration record lists: " + found.email +
              " (" + found.role +
              (found.org ? " — " + found.org : "") + ") · "));
            srcEl.appendChild(h("b", null, "Use this address"));
            srcEl.style.display = "";
          }
          if (stepOpen && !toField.value.trim()) setMx("", "");
        });
      } else {
        rdapState = "none";
      }

      var letterBox = h("div", {});
      letterBox.style.display = "none";
      var letterTa = h("textarea", {});
      letterTa.readOnly = true;
      letterBox.appendChild(letterTa);
      var pToggle = h("button", {
        "class": "sf-details-toggle", "type": "button",
        "aria-expanded": "false"
      }, "Preview the letter ▸");
      pToggle.addEventListener("click", function () {
        var open = letterBox.style.display !== "none";
        letterBox.style.display = open ? "none" : "";
        pToggle.textContent = open ? "Preview the letter ▸"
          : "Hide letter ▾";
        pToggle.setAttribute("aria-expanded", open ? "false" : "true");
      });
      step.appendChild(pToggle);
      step.appendChild(letterBox);

      var openBtn = h("button", { id: "sf-demand-open",
        "class": "sf-btn-green", "type": "button" },
        "Open in Outlook — just click Send");
      var copyBtn = h("button", { id: "sf-demand-copy",
        "class": "sf-btn-orange", "type": "button" },
        "Copy demand letter");
      step.appendChild(h("div", { "class": "sf-actions" }, openBtn, copyBtn));
      step.appendChild(h("p", { "class": "sf-fine" },
        "Goes out from you: " + det.name + " (" + det.email + ")" +
        (det.state ? ", " + (D.stateName(det.state) || det.state) : "") +
        ". Details live only in this browser — change them any " +
        "time with the button below."));
      var editBtn = h("button", {
        "class": "sf-details-toggle sf-edit-details", "type": "button"
      }, "Edit my details");
      editBtn.addEventListener("click", renderDetailsForm);
      step.appendChild(editBtn);

      // The letter never depends on the To field: it is always
      // addressed to the company behind the SENDER domain.
      var letter = null;
      function refresh() {
        letter = D.buildDemand({
          name: det.name, email: det.email, state: det.state,
          companyDomain: senderDom
        });
        letterTa.value = "Subject: " + letter.subject + "\n\n" + letter.body;
      }
      toField.addEventListener("input", refresh);
      refresh();

      openBtn.addEventListener("click", function () {
        var to = toField.value.trim();
        if (!to) {
          // An empty To must never open a compose — point at the
          // field and flash the errand that fills it.
          toField.focus();
          flashInstr();
          return;
        }
        if (!letter) refresh();
        openCompose({
          toRecipients: [to],
          subject: letter.subject,
          htmlBody: textToHtml(letter.body)
        }, openBtn);
      });
      copyBtn.addEventListener("click", function () {
        if (!letter) refresh();
        copyText(letterTa.value, null, {
          selectEl: letterTa,
          // The letter preview starts hidden; if both copy paths
          // fail, reveal it so the selection the user is told to
          // Ctrl+C is actually on screen.
          onManual: function () {
            letterBox.style.display = "";
            pToggle.textContent = "Hide letter ▾";
            pToggle.setAttribute("aria-expanded", "true");
          }
        }).then(function (outcome) {
          flashLabel(copyBtn, outcome !== "manual" ? "Copied!" :
            "Copy didn't take — the letter above is selected, " +
            "press Ctrl+C (" + TAG + ")", 4000);
        });
      });
    }

    D.loadDetails().then(function (det) {
      if (D.detailsComplete(det)) renderDemandStep(det);
      else renderDetailsForm();
    }).catch(function () { renderDetailsForm(); });
  }

  // Test hook: lets the Node harness exercise copyText's three
  // paths with stubbed navigator/document. Inert in the browser
  // (no module system there).
  if (typeof module !== "undefined" && module.exports) {
    module.exports = { copyText: copyText, VERSION: VERSION };
  }

  /* ---------- Boot ---------- */

  if (typeof Office === "undefined") {
    $("no-office").hidden = false;
    return;
  }
  Office.onReady(function () {
    if (!Office.context || !Office.context.mailbox) {
      $("no-office").hidden = false;
      return;
    }
    $("app").hidden = false;
    // Auto-run on open, and re-run whenever the open item changes
    // (pinned pane) where the host offers the event.
    try {
      if (typeof Office.context.mailbox.addHandlerAsync === "function" &&
          Office.EventType && Office.EventType.ItemChanged) {
        Office.context.mailbox.addHandlerAsync(
          Office.EventType.ItemChanged,
          function () { runTrace(); },
          function () {});
      }
    } catch (e) { /* item-change is a bonus, never a blocker */ }
    runTrace();
  });
})();
