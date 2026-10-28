/* Spam Avenger for Outlook — task pane (Phase 1, v1.2.0).
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
 * form the way a content script can. v1.1.3: the Safe Browsing
 * lane is a two-step walkthrough (raw URL for the form's URL box,
 * then an 800-char-budgeted summary for its details box) — the
 * v1.1.2 single paste left the user fishing the URL out of the
 * blob, and the form's URL field stayed empty.
 *
 * v1.2.0: the pane is an accordion (Michael's design call,
 * 2026-10-27). Since the add-in can't walk the user ON an
 * external page, the pane stays focused on the one task being
 * followed: all sections start collapsed as a stack of buttons;
 * clicking one expands its instructions + details below it and
 * closes whichever was open. The window.open calls moved off
 * the section toggles into inner "Open the … form" buttons.
 *
 * Every async call is wrapped with a timeout and every failure
 * surfaces as a short user-readable line carrying the version
 * tag — the pane never hangs silently.
 */
(function () {
  "use strict";

  var VERSION = "1.2.0";
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

  // Safe Browsing's details box is small (the Gmail reportfill
  // lane budgets 800 chars for it), so this lane gets its own
  // SHORT summary instead of the full case text: who it claims to
  // be from, subject, the sending IP + network owner, date. NO
  // link list — the URL itself is step 1 of the walkthrough; any
  // further links collapse into a "(+N more links…)" tail line.
  var SB_DETAILS_CAP = 800;
  var SB_NO_LINKS = "No links found in this message — Safe " +
    "Browsing needs a URL, so this lane can't report it.";
  var SB_INSTRUCTIONS = "1. Open the form. 2. Paste the URL in " +
    "'URL to report'. 3. Paste the details in 'Additional " +
    "details'. 4. Pick 'This page is not safe' and a threat " +
    "type, then Submit — Google does the rest.";
  var FTC_INSTRUCTIONS = "In the form: Report Now → answer the " +
    "category questions → when you reach the Comments box, click " +
    "in it and press Ctrl+V → finish and Submit. The Yes/No " +
    "answers are yours.";

  function sbDetailsText(a) {
    var L = [];
    L.push("Spam/phishing report — details collected by Spam Avenger");
    L.push("Sender: " + (a.from || "unknown"));
    L.push("Subject: " + (a.subject || "unknown"));
    if (a.date) L.push("Date: " + a.date);
    if (a.ip) L.push("Sending IP: " + a.ip);
    if (a.org) L.push("Network owner: " + a.org);
    if (a.urls && a.urls.length > 1) {
      L.push("(+" + (a.urls.length - 1) + " more links in the email)");
    }
    var s = L.join("\n");
    if (s.length > SB_DETAILS_CAP) s = s.slice(0, SB_DETAILS_CAP - 3) + "...";
    return s;
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

  /* ---------- Result rendering: the accordion (v1.2.0) -------- */
  /* Michael's design call (2026-10-27): an Office add-in can't
   * walk the user ON an external form the way the Gmail content
   * script can, so the pane itself has to stay focused on the ONE
   * task being followed. On open, every task is a single button in
   * a stack with everything collapsed; clicking one expands its
   * instructions + details directly below it, and opening another
   * closes the first (strictly one open at a time). The trace
   * details stay OUTSIDE the accordion, behind their own toggle —
   * they're reference info, not a task. Nothing auto-opens, and
   * no window.open happens anywhere except inside the inner
   * "Open the … form" buttons (a direct user click, so popup
   * blockers stay satisfied). A fresh trace rebuilds this DOM
   * from scratch, so a new message always starts all-collapsed
   * with no leftover per-section state. */

  function renderResult(a, bodyText, lookupNote) {
    var body = $("panel-body");
    clearEl(body);
    loadingStepEl = null;

    if (lookupNote) body.appendChild(h("p", { "class": "sf-warn" }, lookupNote));

    // Details start collapsed behind their own toggle, exactly
    // like the Gmail panel (v1.0.36): reference info, not a task,
    // so this toggle is NOT part of the accordion below.
    var details = h("div", { "class": "sf-details" });
    details.style.display = "none";
    var toggle = h("button", {
      "class": "sf-details-toggle", "type": "button",
      "id": "sf-details-toggle", "aria-expanded": "false"
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
        "Nothing to complain to directly — but the report sections below still apply."));
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

    /* ----- The accordion stack: one focused task at a time ----- */
    var stack = h("div", { "class": "sf-stack", "id": "sf-stack" });
    body.appendChild(stack);
    var currentSection = null;
    function accSection(id, toggleClass, label) {
      var caret = h("span", { "class": "sf-acc-caret" }, "▸");
      var tgl = h("button", {
        "class": "sf-acc-toggle " + toggleClass, "type": "button",
        "id": id + "-toggle", "aria-expanded": "false",
        "aria-controls": id + "-panel"
      }, caret, label);
      var panel = h("div", { "class": "sf-acc-panel", "id": id + "-panel" });
      panel.style.display = "none";
      var sec = { toggle: tgl, panel: panel };
      sec.setOpen = function (open) {
        panel.style.display = open ? "" : "none";
        caret.textContent = open ? "▾" : "▸";
        tgl.setAttribute("aria-expanded", open ? "true" : "false");
      };
      tgl.addEventListener("click", function () {
        if (currentSection === sec) {
          sec.setOpen(false);
          currentSection = null;
        } else {
          if (currentSection) currentSection.setOpen(false);
          sec.setOpen(true);
          currentSection = sec;
        }
      });
      stack.appendChild(tgl);
      stack.appendChild(panel);
      return sec;
    }
    function secStatus(id) {
      return h("p", { "class": "sf-fine sf-status", "id": id }, "");
    }

    // Color legend flags, built from what this render actually
    // shows (Gmail v1.0.48 rule: never explain an absent color).
    // Orange appears only when the Copy complaint button exists.
    var showOrange = !!a.complaint;

    /* 1 — the abuse complaint (only when the trace made one) */
    if (a.complaint) {
      var c = a.complaint;
      var compSec = accSection("sf-sec-complaint", "sf-btn-green",
        "Abuse complaint — ready to send");
      var cw = h("div", { "class": "sf-complaint" });
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
      cw.appendChild(h("div", { "class": "sf-actions" }, copyBtn, compBtn));
      var compStatus = secStatus("sf-comp-status");
      cw.appendChild(compStatus);
      compSec.panel.appendChild(cw);
      copyBtn.addEventListener("click", function () {
        copyText(ta.value, compStatus, {
          selectEl: ta,
          manualText: "⚠ Copy didn't take — the complaint text " +
            "above is selected: press Ctrl+C (" + TAG + ")."
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
      stack.appendChild(h("p", { "class": "sf-warn" },
        "No published abuse contact for this IP. " +
        "Report the links via Google Safe Browsing instead."));
    } else if (a.skipComplaint) {
      stack.appendChild(h("p", { "class": "sf-warn" },
        a.providerAdvice ||
        ("This came from a big mailbox provider’s own servers — " +
         "no complaint generated (it would hit the wrong target).")));
    }

    /* 2 — Report to FTC. Expanding the section only shows the
     * walkthrough; the form itself opens from the inner button —
     * a direct user click, so popup blockers stay satisfied, and
     * the case-details copy runs in that same click. */
    var ftcSec = accSection("sf-sec-ftc", "sf-btn-yellow", "Report to FTC");
    var caseLabel = h("b", { id: "sf-case-label" },
      "Case details for the FTC form — paste these into the Comments box:");
    var caseTa = h("textarea", { id: "sf-case-text" });
    caseTa.readOnly = true;
    caseTa.value = caseDetailsText(a);
    var caseBox = h("div", { "class": "sf-casebox" }, caseLabel, caseTa);
    var ftcStatus = secStatus("sf-ftc-status");
    var ftcOpenBtn = h("button", { id: "sf-ftc-open",
      "class": "sf-btn-yellow", "type": "button" }, "Open the FTC form");
    ftcOpenBtn.addEventListener("click", function () {
      window.open("https://reportfraud.ftc.gov/", "_blank", "noopener");
      copyText(caseTa.value, ftcStatus, {
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
    ftcSec.panel.appendChild(h("p", { "class": "sf-note",
      "id": "sf-ftc-instr" }, FTC_INSTRUCTIONS));
    ftcSec.panel.appendChild(h("div", { "class": "sf-actions" }, ftcOpenBtn));
    ftcSec.panel.appendChild(caseBox);
    ftcSec.panel.appendChild(ftcStatus);

    /* 3 — Report to Google Safe Browsing: the two-step
     * walkthrough from v1.1.3 (raw URL for step 1, the
     * 800-char-budgeted summary for step 2), now in its own
     * section. The form opens from the inner button only;
     * nothing is copied until a step's own copy button is
     * clicked — two different boxes on Google's form need two
     * different texts, so one auto-copy can't serve both. */
    var sbSec = accSection("sf-sec-sb", "sf-btn-green",
      "Report to Google Safe Browsing");
    var sbStatus = secStatus("sf-sb-status");
    var sbOpenBtn = h("button", { id: "sf-sb-open",
      "class": "sf-btn-green", "type": "button" },
      "Open the Safe Browsing form");
    sbOpenBtn.addEventListener("click", function () {
      window.open("https://safebrowsing.google.com/safebrowsing/report_phish/",
        "_blank", "noopener");
    });
    var sbUrlTa = h("textarea", { id: "sf-sb-url" });
    sbUrlTa.readOnly = true;
    var sbCopyUrlBtn = h("button", { id: "sf-sb-copy-url",
      "class": "sf-btn-green", "type": "button" }, "Copy the URL");
    var sbUrlActions = h("div", { "class": "sf-actions" }, sbCopyUrlBtn);
    var sbNoLinks = h("p", { "class": "sf-warn" }, SB_NO_LINKS);
    var sbStep1 = h("div", { "class": "sf-sbstep" },
      h("b", null, "Step 1 — the URL for Google's 'URL to report' box:"),
      sbUrlTa, sbUrlActions, sbNoLinks);
    var sbDetTa = h("textarea", { id: "sf-sb-details" });
    sbDetTa.readOnly = true;
    var sbCopyDetBtn = h("button", { id: "sf-sb-copy-details",
      "class": "sf-btn-green", "type": "button" }, "Copy the details");
    var sbStep2 = h("div", { "class": "sf-sbstep" },
      h("b", null, "Step 2 — details for the 'Additional details' box:"),
      sbDetTa,
      h("div", { "class": "sf-actions" }, sbCopyDetBtn));
    var sbWalk = h("div", { "class": "sf-sbwalk" },
      sbStep1, sbStep2,
      h("p", { "class": "sf-note" }, SB_INSTRUCTIONS));
    // Populate at render time (the v1.1.3 showSbWalk logic — the
    // section toggle now owns visibility). Step 1 gets the RAW
    // first link: the complaint defangs links for email, but
    // Google's form wants the real URL.
    if (a.urls && a.urls.length) {
      sbUrlTa.value = a.urls[0];
      sbNoLinks.style.display = "none";
    } else {
      sbUrlTa.value = "";
      sbUrlTa.style.display = "none";
      sbUrlActions.style.display = "none";
      sbNoLinks.style.display = "";
    }
    sbDetTa.value = sbDetailsText(a);
    sbCopyUrlBtn.addEventListener("click", function () {
      copyText(sbUrlTa.value, sbStatus, {
        selectEl: sbUrlTa,
        successText: "✓ Copied the URL — in the Safe Browsing " +
          "form, click 'URL to report' and press Ctrl+V (" + TAG + ").",
        manualText: "⚠ Copy didn't take — the URL in the Step 1 " +
          "box above is selected: press Ctrl+C, then paste it " +
          "into 'URL to report' with Ctrl+V (" + TAG + ")."
      });
    });
    sbCopyDetBtn.addEventListener("click", function () {
      copyText(sbDetTa.value, sbStatus, {
        selectEl: sbDetTa,
        successText: "✓ Copied the details — in the Safe Browsing " +
          "form, click 'Additional details' and press Ctrl+V (" +
          TAG + ").",
        manualText: "⚠ Copy didn't take — the details in the " +
          "Step 2 box above are selected: press Ctrl+C, then " +
          "paste them into 'Additional details' with Ctrl+V (" +
          TAG + ")."
      });
    });
    sbSec.panel.appendChild(h("div", { "class": "sf-actions" }, sbOpenBtn));
    sbSec.panel.appendChild(sbWalk);
    sbSec.panel.appendChild(sbStatus);

    /* 4 — Forward phish to APWG + CISA: a compose pre-addressed
     * to both intake desks, carrying the full headers + analysis
     * + body as pasted evidence (a true .eml attachment is
     * phase 2). The compose opens from the inner button. */
    var fwdSec = accSection("sf-sec-fwd", "sf-btn-green",
      "Forward phish to APWG + CISA");
    var fwdBtn = h("button", { id: "sf-fwd-phish",
      "class": "sf-btn-green", "type": "button" },
      "Open the forwarded email");
    fwdBtn.addEventListener("click", function () {
      openCompose({
        toRecipients: ["reportphishing@apwg.org", "contact@cisa.dhs.gov"],
        subject: "Fwd: " + (a.subject || "(no subject)"),
        htmlBody: textToHtml(forwardBody(a, bodyText))
      }, fwdBtn);
    });
    fwdSec.panel.appendChild(h("p", { "class": "sf-note" },
      "Opens a new email addressed to reportphishing@apwg.org and " +
      "contact@cisa.dhs.gov with the full headers and analysis " +
      "pasted in as evidence — you review and click Send."));
    fwdSec.panel.appendChild(h("div", { "class": "sf-actions" }, fwdBtn));

    /* 5 — Report to Microsoft: honest positioning, no fake API
     * call — Outlook's own Report button is the only route in. */
    var msSec = accSection("sf-sec-ms", "sf-btn-red", "Report to Microsoft");
    msSec.panel.appendChild(h("p", { "class": "sf-note" },
      "Use Outlook's own Report button: with this message selected, " +
      "click the shield-shaped Report button on the ribbon (Home tab) " +
      "and choose Report phishing. That sends the message to Microsoft " +
      "so their filters learn — it never reaches the sender's host. " +
      "The abuse complaint section above is the report that does."));

    /* 6 — PID: "Not Spam but still unwanted?" The entire demand
     * flow renders unchanged inside this section's panel (only
     * when demand.js is present, as before). */
    var Demand = (typeof window !== "undefined") ? window.SpamDemand : null;
    if (Demand) {
      var pidSec = accSection("sf-sec-pid", "sf-btn-yellow",
        "Not Spam but still unwanted?");
      renderDemandZone(pidSec.panel, a);
    }

    // Legend — one compact line under the stack, built from the
    // colors this render actually shows.
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

    body.appendChild(h("p", { "class": "sf-fine" },
      "Nothing is sent automatically. You review and send the complaint yourself."));
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

  // v1.2.0: renders into the PID accordion section's panel —
  // the section toggle replaced the old bottom-of-pane "fight"
  // toggle; the flow inside is unchanged.
  function renderDemandZone(panel, a) {
    var D = (typeof window !== "undefined") ? window.SpamDemand : null;
    if (!D) return;

    var wrap = h("div", { "class": "sf-demand" });
    panel.appendChild(wrap);

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
  // paths with stubbed navigator/document, and the report-lane
  // text builders against fixture analysis output. Inert in the
  // browser (no module system there).
  if (typeof module !== "undefined" && module.exports) {
    module.exports = {
      copyText: copyText,
      caseDetailsText: caseDetailsText,
      sbDetailsText: sbDetailsText,
      SB_NO_LINKS: SB_NO_LINKS,
      SB_INSTRUCTIONS: SB_INSTRUCTIONS,
      FTC_INSTRUCTIONS: FTC_INSTRUCTIONS,
      SB_DETAILS_CAP: SB_DETAILS_CAP,
      VERSION: VERSION,
      _test: { renderResult: renderResult, runTrace: runTrace }
    };
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
