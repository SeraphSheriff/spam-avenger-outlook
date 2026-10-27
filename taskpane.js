/* Spam Avenger for Outlook (Test) — task pane logic.
 *
 * ONE job: show exactly what Office.js hands over for the open message,
 * then prove the Spam Avenger engine (analyze.js) runs on that data.
 * Every API call is wrapped: a failure is displayed in its own section
 * as "FAILED: ..." instead of killing the pane.
 */
(function () {
  "use strict";

  function $(id) { return document.getElementById(id); }

  function errText(e) {
    if (!e) return "unknown error";
    var name = e.name || "";
    var msg = e.message || String(e);
    return (name && name !== msg) ? name + " — " + msg : msg;
  }

  /* Render one labeled field: presence + char count + content in a <pre>. */
  function fieldHtml(label, text) {
    var present = text !== null && text !== undefined && String(text).length > 0;
    var body = present ? String(text) : "(nothing returned)";
    return {
      present: present,
      count: present ? String(text).length : 0,
      html: '<div class="field"><h3>' + label +
        ' <span class="status' + (present ? "" : " absent") + '">' +
        (present ? "— present, " + String(text).length + " characters" : "— ABSENT") +
        "</span></h3><pre></pre></div>",
      body: body
    };
  }

  function addField(container, label, text) {
    var f = fieldHtml(label, text);
    var wrap = document.createElement("div");
    wrap.innerHTML = f.html;
    wrap.querySelector("pre").textContent = f.body;
    container.appendChild(wrap.firstChild);
    return f;
  }

  function addFailedField(container, label, e) {
    return addField(container, label, "FAILED: " + errText(e));
  }

  /* getAllInternetHeadersAsync as a promise that never rejects. */
  function getHeaders(item) {
    return new Promise(function (resolve) {
      try {
        if (!item || typeof item.getAllInternetHeadersAsync !== "function") {
          resolve({ ok: false, error: new Error("API unavailable: item.getAllInternetHeadersAsync is not a function") });
          return;
        }
        item.getAllInternetHeadersAsync(function (result) {
          try {
            if (result && result.status === Office.AsyncResultStatus.Succeeded) {
              resolve({ ok: true, value: result.value || "" });
            } else {
              var err = (result && result.error) || new Error("getAllInternetHeadersAsync did not succeed");
              resolve({ ok: false, error: err });
            }
          } catch (e) { resolve({ ok: false, error: e }); }
        });
      } catch (e) { resolve({ ok: false, error: e }); }
    });
  }

  /* item.body.getAsync('text') as a promise that never rejects. */
  function getBodyText(item) {
    return new Promise(function (resolve) {
      try {
        if (!item || !item.body || typeof item.body.getAsync !== "function") {
          resolve({ ok: false, error: new Error("API unavailable: item.body.getAsync is not a function") });
          return;
        }
        item.body.getAsync(Office.CoercionType.Text, function (result) {
          try {
            if (result && result.status === Office.AsyncResultStatus.Succeeded) {
              resolve({ ok: true, value: result.value || "" });
            } else {
              var err = (result && result.error) || new Error("body.getAsync did not succeed");
              resolve({ ok: false, error: err });
            }
          } catch (e) { resolve({ ok: false, error: e }); }
        });
      } catch (e) { resolve({ ok: false, error: e }); }
    });
  }

  function showContext(info) {
    var el = $("context");
    var rows = [];
    function row(k, v) {
      rows.push("<dt>" + k + "</dt><dd>" + (v === undefined || v === null || v === "" ? "(not provided)" : v) + "</dd>");
    }
    try { row("Host", info && info.host ? String(info.host) : "(unknown)"); } catch (e) { row("Host", "FAILED: " + errText(e)); }
    try { row("Platform", Office.context && Office.context.platform ? String(Office.context.platform) : "(not provided)"); } catch (e) { row("Platform", "FAILED: " + errText(e)); }
    try {
      var profile = Office.context.mailbox.userProfile;
      row("Your email (mailbox profile)", profile && profile.emailAddress);
      row("Your name (mailbox profile)", profile && profile.displayName);
    } catch (e) { row("Mailbox profile", "FAILED: " + errText(e)); }
    el.innerHTML = '<dl class="kv">' + rows.join("") + "</dl>";
  }

  function runEngine(headersText, bodyText) {
    var card = $("engine-card");
    var el = $("engine");
    card.hidden = false;
    el.innerHTML = "";
    if (typeof SpamAvenger === "undefined" || !SpamAvenger.analyze) {
      el.innerHTML = "<p>FAILED: the Spam Avenger engine (analyze.js) did not load.</p>";
      return;
    }
    try {
      var rawText = headersText + "\r\n\r\n" + (bodyText || "");
      var a = SpamAvenger.analyze(rawText);
      var origin = a.ip || null;
      // Cross-check with the direct originIp() call on the parsed headers.
      var direct = null;
      try {
        if (typeof SpamAvenger.originIp === "function" && typeof SpamAvenger.parseHeaders === "function") {
          direct = SpamAvenger.originIp(SpamAvenger.parseHeaders(rawText));
        }
      } catch (e) { direct = "FAILED: " + errText(e); }
      var parsed = [];
      try { parsed = SpamAvenger.parseHeaders(rawText); } catch (e) { parsed = []; }
      function firstHeader(name) {
        for (var i = 0; i < parsed.length; i++) {
          if (parsed[i].name === name) return parsed[i].value;
        }
        return "";
      }
      var lines = [];
      lines.push('<dl class="kv">');
      lines.push("<dt>Origin IP (engine: analyze)</dt><dd class='big'>" + (origin || "(none found in headers)") + "</dd>");
      lines.push("<dt>Origin IP (engine: originIp, direct)</dt><dd>" + (direct === null ? "(not exposed / no result)" : direct) + "</dd>");
      lines.push("<dt>From (from headers)</dt><dd>" + (a.from || firstHeader("from") || "(none)") + "</dd>");
      lines.push("<dt>Return-Path (from headers)</dt><dd>" + (firstHeader("return-path") || "(none)") + "</dd>");
      lines.push("<dt>Subject (from headers)</dt><dd>" + (a.subject || "(none)") + "</dd>");
      lines.push("<dt>Links found in body</dt><dd>" + (a.urls ? a.urls.length : 0) + "</dd>");
      lines.push("</dl>");
      if (a.urls && a.urls.length) {
        var pre = document.createElement("pre");
        // Plain text via textContent below; build list safely.
        el.innerHTML = lines.join("");
        var wrap = document.createElement("div");
        wrap.className = "field";
        var h = document.createElement("h3");
        h.textContent = "URLs the engine extracted";
        pre.textContent = a.urls.join("\n");
        wrap.appendChild(h); wrap.appendChild(pre);
        el.appendChild(wrap);
      } else {
        el.innerHTML = lines.join("");
      }
    } catch (e) {
      el.innerHTML = "<p>FAILED: engine threw — " + errText(e) + "</p>";
    }
  }

  function inspect() {
    var btn = $("inspect");
    btn.disabled = true;
    btn.textContent = "Reading the message…";
    var results = $("results");
    results.innerHTML = "";
    $("engine-card").hidden = true;

    var item = null;
    try { item = Office.context.mailbox.item; } catch (e) { /* handled below */ }
    if (!item) {
      addField(results, "Message item", "FAILED: Office.context.mailbox.item is not available — open an email first, then click Inspect.");
      btn.disabled = false;
      btn.textContent = "Inspect this message";
      return;
    }

    // --- Synchronous fields, each in its own try/catch ---
    try { addField(results, "Subject (item.subject)", item.subject); }
    catch (e) { addFailedField(results, "Subject (item.subject)", e); }

    try {
      var fromText = "";
      if (item.from) {
        fromText = (item.from.displayName || "") + " <" + (item.from.emailAddress || "") + ">";
      }
      addField(results, "From (item.from)", fromText);
    } catch (e) { addFailedField(results, "From (item.from)", e); }

    try {
      addField(results, "Date created (item.dateTimeCreated)",
        item.dateTimeCreated ? item.dateTimeCreated.toString() : null);
    } catch (e) { addFailedField(results, "Date created (item.dateTimeCreated)", e); }

    try { addField(results, "Internet Message ID (item.internetMessageId)", item.internetMessageId); }
    catch (e) { addFailedField(results, "Internet Message ID (item.internetMessageId)", e); }

    try { addField(results, "Conversation ID (item.conversationId)", item.conversationId); }
    catch (e) { addFailedField(results, "Conversation ID (item.conversationId)", e); }

    try {
      if (!item.attachments || !Array.isArray(item.attachments)) {
        addField(results, "Attachments (item.attachments)", "API unavailable: item.attachments is not an array in this context");
      } else if (item.attachments.length === 0) {
        addField(results, "Attachments (item.attachments)", "(no attachments on this message)");
      } else {
        var attLines = item.attachments.map(function (att, i) {
          var size = (att.size !== undefined && att.size !== null) ? att.size + " bytes" : "size unknown";
          return (i + 1) + ". " + (att.name || "(unnamed)") + " — " + (att.attachmentType || att.contentType || "type unknown") + " — " + size;
        });
        addField(results, "Attachments (item.attachments) — " + item.attachments.length + " attached", attLines.join("\n"));
      }
    } catch (e) { addFailedField(results, "Attachments (item.attachments)", e); }

    // --- Async fields ---
    var headersPromise = getHeaders(item);
    var bodyPromise = getBodyText(item);

    headersPromise.then(function (h) {
      if (h.ok) { addField(results, "All internet headers (item.getAllInternetHeadersAsync)", h.value); }
      else { addFailedField(results, "All internet headers (item.getAllInternetHeadersAsync)", h.error); }
      return h;
    }).then(function (h) {
      return bodyPromise.then(function (b) {
        if (b.ok) { addField(results, "Body as text (item.body.getAsync)", b.value); }
        else { addFailedField(results, "Body as text (item.body.getAsync)", b.error); }
        btn.disabled = false;
        btn.textContent = "Inspect this message";
        if (h.ok && h.value) {
          runEngine(h.value, b.ok ? b.value : "");
        } else {
          var card = $("engine-card");
          card.hidden = false;
          $("engine").innerHTML = "<p>Engine check skipped: no headers were returned, so there is nothing to reconstruct a message from.</p>";
        }
      });
    });
  }

  // --- Boot ---
  if (typeof Office === "undefined") {
    $("no-office").hidden = false;
    return;
  }
  Office.onReady(function (info) {
    $("app").hidden = false;
    showContext(info);
    $("inspect").addEventListener("click", inspect);
  });
})();
