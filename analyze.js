/* Spam Avenger for Gmail — analysis engine.
 * Ported from spamfighter.py. No dependencies, no network except
 * RDAP + DNS-over-HTTPS lookups of the SPAMMER's IP.
 * Works in the browser extension and in Node (for tests).
 */
(function () {
  "use strict";

  var RDAP_BASES = [
    "https://rdap.arin.net/registry/ip/",
    "https://rdap.db.ripe.net/ip/",
    "https://rdap.apnic.net/ip/",
    "https://rdap.lacnic.net/rdap/ip/",
    "https://rdap.afrinic.net/rdap/ip/"
  ];

  // Never generate complaints against the big mailbox providers' own
  // infrastructure — their IPs show up in headers for YOUR OWN mail too.
  var PROVIDER_WHITELIST = [
    "google.com", "googlemail.com", "outlook.com", "hotmail.com",
    "live.com", "microsoft.com", "yahoo.com", "aol.com", "icloud.com",
    "me.com", "mac.com", "apple.com", "proton.me", "protonmail.com", "zoho.com"
  ];

  var SKETCHY_TLDS = ["shop", "top", "xyz", "click", "buzz", "lol", "gdn",
    "win", "bid", "loan", "men", "stream", "sbs", "quest"];

  var URL_RE = /https?:\/\/[^\s<>"']+/g;

  function isPrivateIp(ip) {
    var parts = String(ip).split(".");
    if (parts.length !== 4) return true;
    var n = parts.map(function (p) { return parseInt(p, 10); });
    if (n.some(function (p) { return isNaN(p) || p < 0 || p > 255; })) return true;
    var a = n[0], b = n[1];
    return (a === 10 || a === 127 ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168));
  }

  // Split raw message text into unfolded headers [{name, value}, ...].
  function parseHeaders(rawText) {
    var head = String(rawText).split(/\r?\n\r?\n/)[0] || "";
    var headers = [];
    var current = null;
    head.split(/\r?\n/).forEach(function (line) {
      if (/^[ \t]/.test(line) && current) {
        current.value += " " + line.trim();
      } else {
        var m = line.match(/^([^:]+):\s*(.*)$/);
        if (m) {
          current = { name: m[1].toLowerCase(), value: m[2] };
          headers.push(current);
        } else {
          current = null;
        }
      }
    });
    return headers;
  }

  function getAll(headers, name) {
    return headers.filter(function (h) { return h.name === name; })
      .map(function (h) { return h.value; });
  }

  function getFirst(headers, name) {
    var all = getAll(headers, name);
    return all.length ? all[0] : "";
  }

  // First public IPv4 in the oldest Received header (ingress hop).
  // Tries bracketed IPs first (highest confidence), then bare IPs.
  function originIp(headers) {
    var recvd = getAll(headers, "received");
    var bracketPat = /\[(\d{1,3}(?:\.\d{1,3}){3})\]/g;
    var barePat = /(?:^|[^0-9.])([0-9]{1,3}(?:\.[0-9]{1,3}){3})(?![0-9.])/g;
    function validIp(ip) {
      var parts = String(ip).split(".");
      if (parts.length !== 4) return false;
      return parts.every(function (p) {
        return /^\d{1,3}$/.test(p) && parseInt(p, 10) <= 255;
      });
    }
    function candsFrom(text, pat) {
      var cands = [], m;
      pat.lastIndex = 0;
      while ((m = pat.exec(text))) {
        if (validIp(m[1]) && !isPrivateIp(m[1])) cands.push(m[1]);
      }
      return cands;
    }
    function sweep(pat) {
      var cands = [];
      if (recvd.length) {
        cands = candsFrom(recvd[recvd.length - 1], pat);
      }
      for (var i = 0; i < recvd.length && !cands.length; i++) {
        cands = candsFrom(recvd[i], pat);
      }
      return cands;
    }
    var cands = sweep(bracketPat);
    if (!cands.length) cands = sweep(barePat);
    return cands.length ? cands[0] : null;
  }

  function fetchJson(url, timeoutMs) {
    return new Promise(function (resolve) {
      var done = false;
      var timer = setTimeout(function () {
        if (!done) { done = true; resolve(null); }
      }, timeoutMs || 8000);
      fetch(url, { headers: { "Accept": "application/json" } })
        .then(function (res) {
          if (done) return;
          done = true;
          clearTimeout(timer);
          resolve(res.ok ? res.json().catch(function () { return null; }) : null);
        })
        .catch(function () {
          if (!done) { done = true; clearTimeout(timer); resolve(null); }
        });
    });
  }

  function rdapLookup(ip) {
    var chain = Promise.resolve(null);
    RDAP_BASES.forEach(function (base) {
      chain = chain.then(function (found) {
        if (found) return found;
        return fetchJson(base + encodeURIComponent(ip), 8000);
      });
    });
    return chain;
  }

  function vcardEmail(vcardArray) {
    if (!vcardArray || vcardArray.length < 2) return null;
    var props = vcardArray[1] || [];
    for (var i = 0; i < props.length; i++) {
      var item = props[i];
      if (Array.isArray(item) && item.length >= 4 && item[0] === "email") {
        return item[3];
      }
    }
    return null;
  }

  function vcardFn(vcardArray) {
    if (!vcardArray || vcardArray.length < 2) return null;
    var props = vcardArray[1] || [];
    for (var i = 0; i < props.length; i++) {
      var item = props[i];
      if (Array.isArray(item) && item.length >= 4 && item[0] === "fn") {
        return item[3];
      }
    }
    return null;
  }

  function extractAbuse(obj) {
    if (!obj || !obj.entities) return null;
    for (var i = 0; i < obj.entities.length; i++) {
      var ent = obj.entities[i];
      var roles = (ent.roles || []).map(function (r) { return String(r).toLowerCase(); });
      if (roles.indexOf("abuse") !== -1) {
        var em = vcardEmail(ent.vcardArray);
        if (em) return em;
      }
      var nested = extractAbuse(ent);
      if (nested) return nested;
    }
    return null;
  }

  function extractOrg(obj) {
    if (!obj) return null;
    (obj.entities || []).forEach(function () {});
    var ents = obj.entities || [];
    for (var i = 0; i < ents.length; i++) {
      var roles = (ents[i].roles || []).map(function (r) { return String(r).toLowerCase(); });
      if (roles.indexOf("registrant") !== -1) {
        var fn = vcardFn(ents[i].vcardArray);
        if (fn) return fn;
      }
    }
    return obj.name || null;
  }

  // Reverse DNS via DNS-over-HTTPS (no raw DNS in a browser).
  function reverseDns(ip) {
    var rev = String(ip).split(".").reverse().join(".") + ".in-addr.arpa";
    return fetchJson("https://dns.google/resolve?name=" +
      encodeURIComponent(rev) + "&type=PTR", 8000).then(function (d) {
        try {
          var ans = d.Answer || [];
          for (var i = 0; i < ans.length; i++) {
            if (ans[i].type === 12 && ans[i].data) {
              return String(ans[i].data).replace(/\.$/, "");
            }
          }
        } catch (e) {}
        return "unknown";
      });
  }

  // v1.0.68: Michael's "no website" tell. A throwaway sending
  // domain often runs NO website at all — no A or AAAA records
  // for the apex or its www host — because it exists only to
  // send mail. Checked over the same dns.google permission the
  // reverse-DNS lookup above already uses; no new permissions.
  // Resolves true ONLY on a confirmed-empty result (every query
  // answered, none carrying any Answer record). Resolves false
  // when any record exists, and null on ANY error or uncertainty
  // (a failed or timed-out query, a SERVFAIL, a malformed
  // reply) — callers assert the tell only on === true and stay
  // silent otherwise. Results are cached per domain.
  var noWebsiteCache = {};
  function dnsAnswerList(name, type) {
    return fetchJson("https://dns.google/resolve?name=" +
      encodeURIComponent(name) + "&type=" + type, 3000)
      .then(function (d) {
        if (!d || typeof d.Status !== "number") return null;
        if (d.Status === 3) return []; // NXDOMAIN: the name is not there
        if (d.Status !== 0) return null; // SERVFAIL etc: no conclusion
        return Array.isArray(d.Answer) ? d.Answer : [];
      })
      .catch(function () { return null; });
  }
  function domainNoWebsite(domain) {
    domain = String(domain || "").toLowerCase().replace(/\.$/, "");
    if (!domain || domain.indexOf(".") === -1) {
      return Promise.resolve(null);
    }
    if (noWebsiteCache[domain]) return noWebsiteCache[domain];
    var jobs = [];
    [domain, "www." + domain].forEach(function (name) {
      ["A", "AAAA"].forEach(function (type) {
        jobs.push(dnsAnswerList(name, type));
      });
    });
    var p = Promise.all(jobs).then(function (rs) {
      for (var i = 0; i < rs.length; i++) {
        if (rs[i] === null) return null; // one unknown poisons the verdict
        if (rs[i].length) return false; // a record exists: it has web DNS
      }
      return true; // every name answered, all empty: no website
    }).catch(function () { return null; });
    noWebsiteCache[domain] = p;
    return p;
  }

  function whitelisted(host) {
    host = String(host || "").toLowerCase();
    return PROVIDER_WHITELIST.some(function (w) {
      return host === w || host.endsWith("." + w);
    });
  }

  // When mail genuinely came from a mailbox provider, the header trail
  // ends there — but the SENDER'S ACCOUNT can still be reported. Tailored
  // advice per provider; null means use the generic message.
  function providerAdvice(host) {
    host = String(host || "").toLowerCase();
    function has(d) { return host === d || host.endsWith("." + d); }
    if (has("google.com") || has("googlemail.com")) {
      return "Sent from a real Gmail account — the header trail ends here. " +
        "To kill it, report the account itself: in Gmail, open the three-dot " +
        "menu on this message and choose \u201CReport phishing\u201D.";
    }
    if (has("outlook.com") || has("hotmail.com") || has("live.com") ||
        has("msn.com") || has("protection.outlook.com")) {
      return "Sent from a real Microsoft account — the header trail ends here. " +
        "In Outlook, select the message and use Report \u2192 Report phishing " +
        "to flag the account.";
    }
    if (has("yahoo.com") || has("aol.com")) {
      return "Sent from a real Yahoo/AOL account — the header trail ends here. " +
        "Use your mail app's \u201CReport phishing\u201D option to flag the " +
        "sender's account.";
    }
    if (has("icloud.com") || has("me.com") || has("mac.com") || has("apple.com")) {
      return "Sent from a real iCloud account — the header trail ends here. " +
        "Forward it to reportphishing@apple.com to flag the account.";
    }
    return null;
  }

  // --- v1.0.67: Microsoft tenant-account detection (integrated
  // into the Report Abuse lane, Michael's correction Nov 2 2026:
  // NOT a separate lane) ---
  // When a phish is sent by a REAL Microsoft 365 tenant account,
  // the traced IP is a Microsoft outbound-protection pool address
  // shared by thousands of tenants. A host complaint to
  // abuse@microsoft.com reports Microsoft to Microsoft for running
  // Outlook and dies in that queue. The account itself is the
  // offender, and Microsoft's phishing desk
  // (phish@office365.microsoft.com) is the desk that can act on
  // the account. Detection requires BOTH: (1) the sending server
  // is the Outlook protection pool, and (2) SPF, DKIM and DMARC
  // all pass for the From domain — a real account, not a spoof.
  // When it fires, the EXISTING Report Abuse lane switches its
  // recipient and body (see buildComplaint's dispatch below);
  // there is no separate lane, section, or button.

  // Parse SPF/DKIM/DMARC verdicts out of Authentication-Results
  // and ARC-Authentication-Results. A mechanism is "pass" when
  // ANY auth block reports pass for it: the live first case
  // (Jessica Huber, Nov 2 2026) carries ARC results of
  // spf=pass / dkim=pass / dmarc=pass alongside a later
  // Authentication-Results block reading dkim=none / dmarc=none,
  // so requiring every block to agree would miss the real
  // account. Any other verdict is the first one seen.
  function parseAuthResults(headers) {
    var out = { spf: null, dkim: null, dmarc: null };
    if (!headers) return out;
    var blocks = getAll(headers, "authentication-results")
      .concat(getAll(headers, "arc-authentication-results"));
    var text = blocks.join("; ").toLowerCase();
    ["spf", "dkim", "dmarc"].forEach(function (mech) {
      var re = new RegExp(mech + "\\s*=\\s*([a-z]+)", "g");
      var m, first = null;
      while ((m = re.exec(text))) {
        if (first === null) first = m[1];
        if (m[1] === "pass") { out[mech] = "pass"; return; }
      }
      out[mech] = first;
    });
    return out;
  }

  function authAllPass(auth) {
    return !!(auth && auth.spf === "pass" &&
      auth.dkim === "pass" && auth.dmarc === "pass");
  }

  // True for the Outlook protection pool only:
  // protection.outlook.com itself or any subdomain of it
  // (mail-*.outbound.protection.outlook.com in the wild).
  // A bare outlook.com / prod.outlook.com internal hop is NOT
  // the outbound pool and does not fire this.
  function isMicrosoftProtectionHost(host) {
    var hst = String(host || "").trim().toLowerCase()
      .replace(/\.$/, "");
    if (!hst) return false;
    return hst === "protection.outlook.com" ||
      hst.endsWith(".protection.outlook.com");
  }

  // Hostnames named in Received headers, in header order.
  function receivedHosts(headers) {
    var out = [];
    getAll(headers, "received").forEach(function (v) {
      var m = String(v).match(/^\s*from\s+([A-Za-z0-9._-]+)/i);
      if (m && out.indexOf(m[1].toLowerCase()) === -1) {
        out.push(m[1].toLowerCase());
      }
    });
    return out;
  }

  // The sending server named in the Received hop that carried
  // the traced IP (falling back to the oldest Received hop).
  function sendingServerFor(headers, ip) {
    var recvd = getAll(headers, "received");
    function hostOf(v) {
      var m = String(v).match(/^\s*from\s+([A-Za-z0-9._-]+)/i);
      return m ? m[1] : null;
    }
    if (ip) {
      for (var i = recvd.length - 1; i >= 0; i--) {
        if (recvd[i].indexOf(ip) !== -1) return hostOf(recvd[i]);
      }
    }
    return recvd.length ? hostOf(recvd[recvd.length - 1]) : null;
  }

  function senderEmail(from) {
    var m = String(from || "").match(/([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})/);
    return m ? m[1] : "";
  }

  // Where Microsoft tenant-account reports go (the phishing
  // desk). junk@office365.microsoft.com is the mere-spam sibling;
  // this addon reports phishing accounts, so the phish desk it is.
  var MS_PHISH_DESK = "phish@office365.microsoft.com";

  // The account report that REPLACES the host complaint inside
  // the Report Abuse lane for a real Microsoft tenant account.
  // Same {to, subject, body} shape as buildComplaint, same
  // header/body caps, same trimHeaders treatment. NOTE on
  // attachments: Microsoft's filters 550-block raw .eml
  // attachments (proven in the manual Nov 2 2026 send, which
  // had to ZIP the original), and the Gmail compose lane this
  // addon drives cannot attach a ZIP either — so the full
  // headers ride IN THE BODY, exactly as the normal complaint
  // already carries them. No .eml attachment is designed in.
  function buildMsAccountReport(a, opts) {
    opts = opts || {};
    var headerCap = opts.headerCap != null ? opts.headerCap : 8000;
    var bodyCap = opts.bodyCap != null ? opts.bodyCap : 4000;
    if (!a) return null;
    var account = senderEmail(a.from) || a.from || "unknown";
    var domain = (String(account).match(/@([\w.-]+)/) || [])[1] ||
      a.senderDomain || "unknown";
    var server = a.host || a.sendingServer || "unknown";
    var auth = a.authResults || {};
    function av(k) { return auth[k] ? String(auth[k]) : "unknown"; }
    var L = [];
    L.push("Hello Microsoft Phishing Team,");
    L.push("");
    L.push("I received a phishing / spam message sent by a real " +
      "Microsoft 365 account. I am reporting the account itself.");
    L.push("");
    L.push("  Sender account: " + account);
    L.push("  Subject:        " + (a.subject || "unknown"));
    L.push("  Date received:  " + (a.date || "unknown"));
    L.push("  Sending server: " + displayHost(server));
    L.push("  Source IP:      " + (a.ip || "unknown") +
      " (Microsoft's shared outbound protection pool — not the " +
      "sender's own server)");
    L.push("  Authentication: SPF " + av("spf") + ", DKIM " +
      av("dkim") + ", DMARC " + av("dmarc") +
      " for " + domain + " — this is a live tenant account, " +
      "not a spoofed address.");
    // v1.0.68: the no-website tell, as one body line — only
    // when investigate confirmed it (senderDomainNoWebsite is
    // set solely on a confirmed-empty DNS result).
    if (a.senderDomainNoWebsite) {
      L.push("  Website:        " + domain + " has no website " +
        "(no A or AAAA records for the domain or www." + domain +
        "). It exists only to send mail.");
    }
    if (a.urls && a.urls.length) {
      L.push("  Links in message (defanged so spam filters don't eat this report — read hxxps as https and [.] as .):");
      a.urls.slice(0, 10).forEach(function (u) { L.push("    - " + defangUrl(u)); });
    }
    L.push("");
    L.push("The account itself is the offender. The sending IP is " +
      "Microsoft's shared outbound pool, used by thousands of " +
      "unrelated tenants, so action against the IP or a host " +
      "complaint to the IP's abuse contact cannot stop this " +
      "sender. Please investigate this account and take " +
      "appropriate action on the account.");
    L.push("");
    if (a.fullHeaders) {
      var th = trimHeaders(String(a.fullHeaders));
      var fh = th.text;
      var truncated = fh.length > headerCap;
      if (truncated) fh = fh.slice(0, headerCap);
      L.push("Full headers (plain text, as received):");
      fh.split("\n").forEach(function (ln) { L.push("  " + ln); });
      if (th.stripped) L.push("  [ARC/DKIM signature blocks omitted — routing and authentication headers are complete]");
      if (truncated) L.push("  [headers truncated at " + headerCap + " characters]");
      L.push("");
    } else {
      L.push("Key headers as evidence:");
      L.push("  Message-ID: " + (a.messageId || "unknown"));
      if (a.ingressReceived) L.push("  " + a.ingressReceived);
      L.push("");
    }
    if (a.bodyText && bodyCap > 0) {
      var bt = defangText(String(a.bodyText).slice(0, bodyCap));
      L.push("Message body (plain text, links defanged so spam filters don't eat this report — read hxxps as https and [.] as .):");
      bt.split("\n").forEach(function (ln) { L.push("  " + ln); });
      L.push("");
    }
    L.push("Thank you.");
    return {
      to: MS_PHISH_DESK,
      subject: "Phishing account report: " + account,
      body: L.join("\n")
    };
  }

  // v1.0.68: the details-panel note for the Microsoft
  // tenant-account case. The generic panel line ('The "From"
  // address is makeup. The IP is the face underneath.') is
  // BACKWARDS here: the From account is real and is itself the
  // offender, and the IP is just Microsoft's shared outbound
  // pool. Michael's live test of v1.0.67 caught the old line
  // sitting on the Huber message; this is the flipped line,
  // naming the account. It gains the no-website sentence only
  // when investigate confirmed it (a.senderDomainNoWebsite —
  // set solely on a confirmed-empty DNS result, never on an
  // error). Returns null when the case doesn't fire.
  function msDetailsNote(a) {
    if (!a || !(a.msAccountReport || isMsAccountCase(a))) return null;
    var account = senderEmail(a.from) || a.from || "The sender account";
    var note = "No makeup this time: " + account + " is the face. " +
      "The IP is just Microsoft's shared mail truck.";
    if (a.senderDomainNoWebsite) {
      var domain = (String(account).match(/@([\w.-]+)/) || [])[1] ||
        a.senderDomain || "";
      if (domain) {
        note += " " + domain + " doesn't even run a website. " +
          "It exists only to send mail.";
      }
    }
    return note;
  }

  // True when the analysis (headers + optionally the PTR host /
  // RDAP org gathered by investigate) is the Microsoft
  // tenant-account case: protection-pool sending server AND
  // SPF/DKIM/DMARC all passing.
  function isMsAccountCase(a) {
    if (!a || !authAllPass(a.authResults)) return false;
    if (a.msProtectionHost) return true;
    if (isMicrosoftProtectionHost(a.host)) return true;
    if (isMicrosoftProtectionHost(a.sendingServer)) return true;
    var hosts = a.receivedHosts || [];
    for (var i = 0; i < hosts.length; i++) {
      if (isMicrosoftProtectionHost(hosts[i])) return true;
    }
    return false;
  }

  // The abuse POC's identity (fn / email / handle) of the first
  // abuse-role entity in the record, nested or top-level — the
  // same traversal as extractAbuse. The POC is where an emailed
  // complaint actually lands, so when a provider parks one
  // dedicated cloud-abuse desk on a block, that identity says
  // "cloud" even when the net name and org don't (see below).
  function abusePoc(obj) {
    if (!obj || !obj.entities) return null;
    for (var i = 0; i < obj.entities.length; i++) {
      var ent = obj.entities[i];
      var roles = (ent.roles || []).map(function (r) {
        return String(r).toLowerCase();
      });
      if (roles.indexOf("abuse") !== -1) {
        return {
          fn: String(vcardFn(ent.vcardArray) || ""),
          email: String(vcardEmail(ent.vcardArray) || ""),
          handle: String(ent.handle || "")
        };
      }
      var nested = abusePoc(ent);
      if (nested) return nested;
    }
    return null;
  }

  // Hyperscaler CLOUD blocks: spam sent from a rented cloud VM
  // traces to the provider's giant network block (GOOGLE-CLOUD,
  // an Amazon allocation, MSFT ...). The RDAP abuse contact
  // exists, but those compliance desks are deflection-grade —
  // the providers' abuse FORMS are the lane that acts (the
  // OVHcloud lesson, one size up). Detection reads only the RDAP
  // identity already fetched (network name, registrant org, and
  // the abuse POC's identity) and demands a cloud-provider
  // identity, so big MAILBOX providers never trip it:
  // Gmail/Outlook sending is the skipComplaint path and stays
  // untouched.
  // Returns "google" | "aws" | "azure" | null.
  function hyperscalerOf(rdap) {
    if (!rdap) return null;
    var net = String(rdap.name || "").toUpperCase();
    var org = "";
    var ents = rdap.entities || [];
    for (var i = 0; i < ents.length; i++) {
      var roles = (ents[i].roles || []).map(function (r) {
        return String(r).toLowerCase();
      });
      if (roles.indexOf("registrant") !== -1) {
        org = String(vcardFn(ents[i].vcardArray) || "").toUpperCase();
        if (org) break;
      }
    }
    var poc = abusePoc(rdap) || { fn: "", email: "", handle: "" };
    var pocFn = poc.fn.toUpperCase();
    var pocEmail = poc.email.toLowerCase();
    var pocHandle = poc.handle.toUpperCase();
    // Google Cloud — net names like GOOGLE-CLOUD, a Google
    // Cloud org, OR the GC Abuse POC. The POC signal is load-
    // bearing: some Cloud allocations wear neither marker —
    // GOOGL-2 (NET-34-128-0-0-1) is plain "Google LLC" space by
    // name/org, but its abuse desk is the same GCABU-ARIN
    // "GC Abuse" <google-cloud-compliance@google.com> as
    // GOOGLE-CLOUD's, so the complaint lands on Cloud
    // Compliance either way. Plain GOOGLE / GOGL blocks do NOT
    // carry that POC (verified 2026-10-28 on 142.250.80.1 and
    // 8.8.8.8: ABUSE5250-ARIN "Abuse" <network-abuse@google
    // .com>), so generic Google addresses never fire this.
    if ((net.indexOf("GOOGLE") !== -1 && net.indexOf("CLOUD") !== -1) ||
        org.indexOf("GOOGLE CLOUD") !== -1 ||
        pocEmail === "google-cloud-compliance@google.com" ||
        pocHandle === "GCABU-ARIN" ||
        pocFn.indexOf("GC ABUSE") !== -1) return "google";
    // Amazon AWS — AMAZON / AMAZON-EC2-* net names, or an Amazon
    // registrant org (some AWS allocations carry handle-style
    // net names — the 52.0.0.0/10 block is "AT-88-Z" — so the
    // registrant org is the reliable marker there), OR the
    // AEA8-ARIN "Amazon EC2 Abuse" POC, which rides every AWS
    // allocation checked (AT-88-Z, AMAZON-S3; 2026-10-28).
    if (net.indexOf("AMAZON") !== -1 || /(^|[-_])AWS([-_]|$)/.test(net) ||
        org.indexOf("AMAZON") !== -1 ||
        pocFn.indexOf("AMAZON EC2") !== -1) return "aws";
    // Microsoft Azure — AZURE net names, or MICROSOFT / MSFT
    // net names registered to Microsoft Corporation. Deliber-
    // ately NOT keyed on the abuse POC: MAC74-ARIN "Microsoft
    // Abuse Contact" <abuse@microsoft.com> is Microsoft's
    // general abuse desk (mail included), not cloud-distinct.
    if (net.indexOf("AZURE") !== -1 ||
        (/(^|[-_])(MICROSOFT|MSFT)([-_]|$)/.test(net) &&
         org.indexOf("MICROSOFT") !== -1)) return "azure";
    return null;
  }

  function stripTags(html) {
    return String(html)
      .replace(/<img\b[^>]*\balt="([^"]*)"[^>]*>/gi, " $1 ")
      .replace(/<[^>]+>/g, " ")
      .replace(/&amp;/g, "&").replace(/&lt;/g, "<")
      .replace(/&gt;/g, ">").replace(/&quot;/g, '"')
      .replace(/&#39;/g, "'");
  }

  // v1.0.65 test2 (Michael's live catch, 2026-10-30): phish kits
  // ship hrefs with multiplied slashes — the Safe Browsing lane
  // was handed "https://////w2.xiongmao-outdoor.com////////
  // g4herty////////s234r3wa1.html" verbatim and the mangled
  // string landed in the report form's URL field. A user cannot
  // be expected to clean slashes by hand, so collection
  // normalizes every URL: in the part before any ? or #, each
  // run of 2+ slashes collapses to one and the scheme separator
  // comes out as exactly "://". Query and fragment pass through
  // byte-for-byte (a "//" inside a query value can be data, not
  // sloppiness), an already-clean URL is unchanged, and a string
  // with no http(s) scheme is returned as-is. Runs here, inside
  // extractUrls(), so every downstream lane — Safe Browsing and
  // FTC stash/prefill, the URL picker, complaint text, form-kit
  // evidence — gets the clean form, and defangUrl() parses it
  // again (it silently no-ops on a slash-mangled URL).
  function normalizeUrl(u) {
    var s = String(u);
    var m = s.match(/^(https?:)\/+([\s\S]*)$/i);
    if (!m) return s;
    var rest = m[2];
    var cut = rest.length;
    var qi = rest.indexOf("?"), fi = rest.indexOf("#");
    if (qi !== -1 && qi < cut) cut = qi;
    if (fi !== -1 && fi < cut) cut = fi;
    return m[1] + "//" +
      rest.slice(0, cut).replace(/\/{2,}/g, "/") + rest.slice(cut);
  }

  function extractUrls(text) {
    var urls = [];
    var m;
    URL_RE.lastIndex = 0;
    while ((m = URL_RE.exec(text))) {
      var u = m[0].replace(/[.,;!)\]}"'=]+$/, "");
      u = normalizeUrl(u);
      if (u && urls.indexOf(u) === -1 && urls.length < 20) urls.push(u);
    }
    return urls;
  }

  // v1.0.64 (Michael's live-test catch, 2026-10-28): an asset URL —
  // one whose path ends in an image/media/font/style extension —
  // is set dressing (a hotlinked logo, a tracking pixel), never the
  // phishing landing page. Both report lanes lead with urls[0]
  // (the FTC "Phishing URL:" line, the Safe Browsing URL field),
  // and on the Medicare Kit lure that slot went to a Wikimedia
  // logo (.svg.png) while the real phish page sat third.
  function isAssetUrl(u) {
    var p = String(u).split(/[?#]/)[0].toLowerCase();
    return /\.(png|jpe?g|gif|svg|webp|bmp|ico|tiff?|avif|mp4|mp3|woff2?|ttf|css)$/.test(p);
  }

  // Stable partition: page candidates first (original order),
  // asset URLs after (original order). Nothing is dropped — the
  // complaint body still quotes every link as evidence — only the
  // ORDER changes, so urls[0] is a page whenever the message has
  // one. If every link is an asset, the order is untouched.
  function leadWithPages(urls) {
    var pages = [], assets = [];
    urls.forEach(function (u) { (isAssetUrl(u) ? assets : pages).push(u); });
    return pages.concat(assets);
  }

  function redFlags(fromAddr, urls, text) {
    var flags = [];
    var dm = (String(fromAddr || "").match(/@([\w.-]+)/) || [])[1] || "";
    dm = dm.toLowerCase();
    var tld = dm.indexOf(".") !== -1 ? dm.split(".").pop() : "";
    if (SKETCHY_TLDS.indexOf(tld) !== -1) {
      flags.push("Sender uses a ." + tld + " domain — throwaway domains scammers burn through by the dozen.");
    }
    var urlHosts = {};
    urls.forEach(function (u) {
      var hm = u.match(/https?:\/\/([^/]+)/);
      if (hm) urlHosts[hm[1].toLowerCase().replace(/^www\./, "")] = 1;
    });
    urlHosts = Object.keys(urlHosts);
    if (dm && urlHosts.length && !urlHosts.some(function (h) {
      return dm.indexOf(h) !== -1 || h.indexOf(dm) !== -1;
    })) {
      flags.push("The links go somewhere completely different from the sender's domain — classic redirector trick.");
    }
    var low = String(text || "").toLowerCase();
    [["act now", "pressure tactic ('act now')"],
     ["limited time", "pressure tactic ('limited time')"],
     ["verify your account", "phishing phrase ('verify your account')"],
     ["suspended", "threat that your account is 'suspended'"],
     ["gift card", "gift-card mention — huge scam marker"],
     ["{{", "unfilled template placeholders like {{date}} — mass-sent phish kit"]
    ].forEach(function (pair) {
      if (low.indexOf(pair[0]) !== -1) flags.push("Contains " + pair[1] + ".");
    });
    return { flags: flags, senderDomain: dm, urlHosts: urlHosts };
  }

  // Defang a URL for safe transit inside an abuse complaint: hxxp(s)
  // scheme and bracketed dots in the host. A complaint that quotes live
  // phishing links scores as spam at the receiving desk's filter — the
  // report gets eaten (or the reporter listed) before a human sees it.
  // The path stays byte-for-byte intact so the desk loses nothing.
  function defangUrl(u) {
    var s = String(u || "");
    var m = s.match(/^(https?):\/\/([^/?#]+)([\s\S]*)$/i);
    if (!m) return s;
    var scheme = m[1].toLowerCase() === "https" ? "hxxps" : "hxxp";
    return scheme + "://" + m[2].replace(/\./g, "[.]") + m[3];
  }

  // Defang every URL inside a block of text (for quoted message bodies).
  function defangText(t) {
    return String(t || "").replace(/(https?):\/\/([A-Za-z0-9\-._~%!$&'()*+,;=]+)/gi,
      function (m, scheme, host) {
        return (scheme.toLowerCase() === "https" ? "hxxps" : "hxxp") +
          "://" + host.replace(/\./g, "[.]");
      });
  }

  // Cryptographic signature headers (Google's ARC seals, the sender's
  // DKIM) are kilobytes of base64 that say nothing an abuse desk can
  // act on — the desk needs the routing chain and the authentication
  // VERDICTS, which live in Received / Authentication-Results. Left
  // in, the signatures bloat a complaint until Gmail's compose link
  // refuses it outright (v1.0.57 field failure: Error 400 on
  // Open-in-Gmail). Strip the signature blocks, folded lines and all.
  var SIGNATURE_HEADERS = {
    "arc-seal": true, "arc-message-signature": true,
    "dkim-signature": true, "domainkey-signature": true
  };

  function trimHeaders(raw) {
    var lines = String(raw || "").split(/\r?\n/);
    var out = [];
    var dropping = false, stripped = false;
    lines.forEach(function (ln) {
      if (/^[ \t]/.test(ln)) {           // folded continuation line
        if (!dropping) out.push(ln);
        return;
      }
      var m = ln.match(/^([A-Za-z0-9-]+):/);
      if (m && SIGNATURE_HEADERS[m[1].toLowerCase()]) {
        dropping = true; stripped = true;
        return;
      }
      dropping = false;
      out.push(ln);
    });
    return { text: out.join("\n"), stripped: stripped };
  }

  // Some sending IPs carry placeholder reverse DNS — the classic being
  // "undefined.hostname.localhost", seen live on the Anthem EFT phish
  // (103.244.33.253, Oct 20 2026). Printing the junk verbatim makes the
  // complaint itself look broken to the abuse desk reading it, so
  // placeholders collapse to a plain statement that there is no real
  // record. Display-only: a.host keeps the raw PTR value because the
  // whitelist / provider logic upstream keys off it.
  function displayHost(host) {
    var raw = String(host || "").trim().replace(/\.$/, "");
    var h = raw.toLowerCase();
    if (!h || h === "unknown" || h === "localhost" ||
        h.endsWith(".localhost") || h.indexOf("undefined") === 0) {
      return "no valid reverse DNS record";
    }
    return raw;
  }

  function buildComplaint(a, opts) {
    opts = opts || {};
    var headerCap = opts.headerCap != null ? opts.headerCap : 8000;
    var bodyCap = opts.bodyCap != null ? opts.bodyCap : 4000;
    // v1.0.67: the Microsoft tenant-account case switches THIS
    // lane's target and body — same Report Abuse lane, same
    // review-first compose flow, no separate lane. It fires
    // before the skipComplaint / abuse-contact guards because
    // the whole point is that there is no usable host complaint
    // for a shared-pool IP: the report goes to Microsoft's
    // phishing desk about the account instead. A traced IP is
    // still required — no origin, no account report.
    if (a && a.ip && (a.msAccountReport || isMsAccountCase(a))) {
      return buildMsAccountReport(a, opts);
    }
    if (a.skipComplaint || !a.ip || !a.abuse) return null;
    var L = [];
    L.push("Hello Abuse Team,");
    L.push("");
    L.push("I received spam originating from your network:");
    L.push("");
    L.push("  Source IP:      " + a.ip);
    L.push("  Server name:    " + displayHost(a.host));
    L.push("  Claimed sender: " + (a.from || "unknown"));
    L.push("  Subject:        " + (a.subject || "unknown"));
    L.push("  Date received:  " + (a.date || "unknown"));
    if (a.urls && a.urls.length) {
      L.push("  Links in message (defanged so spam filters don't eat this complaint — read hxxps as https and [.] as .):");
      a.urls.slice(0, 10).forEach(function (u) { L.push("    - " + defangUrl(u)); });
    }
    L.push("");
    if (a.fullHeaders) {
      // Desks (AWS Trust & Safety explicitly) bounce complaints that
      // offer headers "on request" — attach the full block: it is
      // evidence. Two trims keep it shippable: signature blocks are
      // stripped (trimHeaders, above), and the result is capped so a
      // pathological header block can't bloat the complaint past
      // usability.
      var th = trimHeaders(String(a.fullHeaders));
      var fh = th.text;
      var truncated = fh.length > headerCap;
      if (truncated) fh = fh.slice(0, headerCap);
      L.push("Full headers (plain text, as received):");
      fh.split("\n").forEach(function (ln) { L.push("  " + ln); });
      if (th.stripped) L.push("  [ARC/DKIM signature blocks omitted — routing and authentication headers are complete]");
      if (truncated) L.push("  [headers truncated at " + headerCap + " characters]");
      L.push("");
    } else {
      L.push("Key headers as evidence:");
      L.push("  Message-ID: " + (a.messageId || "unknown"));
      if (a.ingressReceived) L.push("  " + a.ingressReceived);
      L.push("");
    }
    if (a.bodyText && bodyCap > 0) {
      var bt = defangText(String(a.bodyText).slice(0, bodyCap));
      L.push("Message body (plain text, links defanged so spam filters don't eat this complaint — read hxxps as https and [.] as .):");
      bt.split("\n").forEach(function (ln) { L.push("  " + ln); });
      L.push("");
    }
    L.push("Please investigate the account or customer responsible and take appropriate action. Thank you.");
    return {
      to: a.abuse,
      subject: "Network abuse complaint — spam from " + a.ip,
      body: L.join("\n")
    };
  }

  // Render a header date as a UTC stamp for the form-evidence
  // block ("Wed, 28 Oct 2026 09:27:25 UTC"). Unparseable input
  // passes through raw — a form reviewer can still read it.
  function utcStamp(s) {
    var raw = String(s || "").trim();
    if (!raw) return "unknown";
    var d = new Date(raw);
    if (!isNaN(d.getTime())) return d.toUTCString().replace("GMT", "UTC");
    return raw;
  }

  // Form-kit evidence (v1.0.64): some hosts act ONLY on reports
  // filed through their own abuse form — the hyperscaler clouds
  // (a.hyperscaler) and OVHcloud. An emailed complaint to those
  // desks is deflected to the form anyway, so for those panels
  // buildComplaint's email is never shown; instead the user
  // gets ONE paste-ready evidence block for the form's
  // details/description field: a summary paragraph, the labeled
  // facts the forms ask for, and the full headers with the same
  // trimHeaders treatment the emailed complaint gets (signature
  // blocks stripped, capped), so the paste stays shippable.
  // Returns the block text, or null when there is no traced IP
  // to report.
  //
  // v1.0.69: opts.mirrorComplaint (the Azure/MSRC kit) adds the
  // two labeled facts the emailed complaint carries that the
  // standard block omits — the server name and the defanged
  // links (same slice cap of 10, same defangUrl) — so the block
  // pasted into the MSRC form's details field mirrors the
  // complaint's evidence. The headers treatment is unchanged
  // (trimHeaders, same 8000 cap). Default off: the other form
  // kits' blocks stay byte-identical to before.
  function buildFormEvidence(a, opts) {
    opts = opts || {};
    var headerCap = opts.headerCap != null ? opts.headerCap : 8000;
    if (!a || !a.ip) return null;
    var L = [];
    L.push("I received a spam/phishing message originating from " +
      "your network. It was sent from IP address " + a.ip +
      (a.org ? " (registered to " + a.org + ")" : "") +
      " and received on " + utcStamp(a.date) + ". " +
      "Please investigate the account or customer responsible " +
      "and take appropriate action. The message details and " +
      "full headers follow as evidence.");
    L.push("");
    L.push("Source IP: " + a.ip);
    if (opts.mirrorComplaint) L.push("Server: " + displayHost(a.host));
    L.push("Date/time (UTC): " + utcStamp(a.date));
    L.push("From: " + (a.from || "unknown"));
    L.push("Subject: " + (a.subject || "unknown"));
    if (a.ingressReceived) L.push("Received: " + a.ingressReceived);
    if (opts.mirrorComplaint && a.urls && a.urls.length) {
      L.push("Links in message (defanged \u2014 read hxxps as https and [.] as .):");
      a.urls.slice(0, 10).forEach(function (u) { L.push("  - " + defangUrl(u)); });
    }
    L.push("");
    if (a.fullHeaders) {
      var th = trimHeaders(String(a.fullHeaders));
      var fh = th.text;
      var truncated = fh.length > headerCap;
      if (truncated) fh = fh.slice(0, headerCap);
      L.push("Full headers (plain text, as received):");
      fh.split("\n").forEach(function (ln) { L.push(ln); });
      if (th.stripped) L.push("[ARC/DKIM signature blocks omitted — routing and authentication headers are complete]");
      if (truncated) L.push("[headers truncated at " + headerCap + " characters]");
    } else if (a.ingressReceived) {
      L.push("Key headers as evidence:");
      L.push("  Message-ID: " + (a.messageId || "unknown"));
      L.push("  Received: " + a.ingressReceived);
    }
    return L.join("\n");
  }

  // Per-field form evidence (v1.0.69, combined build): the
  // Google Cloud / AWS / OVHcloud abuse forms do NOT share the
  // MSRC form's shape — each splits the report across its own
  // boxes (verified against the live forms and the providers'
  // own reporting docs, 2026-11-02). One paste block fits none
  // of them: Google caps its "Abuse details" box at 1,000
  // characters and takes the headers as an uploaded log file
  // instead; AWS asks for the incident as log-style lines
  // (source IP, ISO date/time, time zone) plus log extracts;
  // OVHcloud asks for a location (IP or URL), a description it
  // forwards to the service owner, and logs/technical elements
  // separately. So the panel's form kits declare their form's
  // fields (content.js HYPER_FORM_HINTS `fields`) and each
  // field's Copy button carries the slice built here, keyed by
  // the field's `copy` name:
  //   "ip"            the bare source IP (a location/IP box)
  //   "date"          the message day, ISO YYYY-MM-DD (a date box)
  //   "urls"          the message's URLs, one per line, RAW —
  //                   a dedicated URL box is where the desk
  //                   needs the literal addresses (same call as
  //                   the Safe Browsing lane's URL box), cap 10
  //   "googleDetails" the facts sized for Google's 1,000-char
  //                   details box: summary, IP, From/Subject,
  //                   defanged links that fit; headers are NOT
  //                   here — they ride the logs upload instead
  //   "awsIncident"   AWS's incident lines: type, ISO 8601
  //                   date/time, time zone (UTC), source IP,
  //                   claimed sender, subject
  //   "logs"          the log slice: the ingress Received line
  //                   plus the full headers (trimHeaders, the
  //                   usual 8000 cap) — an email's log extract
  //   "description"   a facts-only narrative for OVHcloud's
  //                   description box: what arrived, from
  //                   where, when, the defanged links, a body
  //                   excerpt; no headers (the logs field
  //                   carries them) and no reporter identity —
  //                   OVHcloud transfers the description to the
  //                   service owner, so it is facts only
  // Returns the slice text, or null when the slice cannot be
  // built (no traced IP, no URLs for "urls", no headers or
  // Received line for "logs", an unparseable date for "date") —
  // the panel skips a step whose slice is null. Reporter-
  // identity fields are never built here at all: name/email
  // boxes on these forms are the user's own to fill in.
  function isoDayStamp(s) {
    var d = new Date(String(s || "").trim());
    if (isNaN(d.getTime())) return null;
    return d.toISOString().slice(0, 10);
  }
  function isoFullStamp(s) {
    var d = new Date(String(s || "").trim());
    if (isNaN(d.getTime())) return null;
    return d.toISOString();
  }
  function buildFormFieldEvidence(a, key) {
    if (!a || !a.ip) return null;
    if (key === "ip") return a.ip;
    if (key === "date") return isoDayStamp(a.date);
    if (key === "urls") {
      if (!a.urls || !a.urls.length) return null;
      return a.urls.slice(0, 10).join("\n");
    }
    if (key === "googleDetails") {
      var gd = [];
      gd.push("Spam/phishing email received from IP address " + a.ip +
        (a.org ? " (registered to " + a.org + ")" : "") +
        " on " + utcStamp(a.date) + ".");
      gd.push("Source IP: " + a.ip);
      gd.push("From: " + (a.from || "unknown"));
      gd.push("Subject: " + (a.subject || "unknown"));
      if (a.urls && a.urls.length) {
        gd.push("Links in the message (defanged \u2014 read hxxps " +
          "as https and [.] as .):");
        for (var gi = 0; gi < a.urls.length && gi < 10; gi++) {
          var line = "  - " + defangUrl(a.urls[gi]);
          if (gd.join("\n").length + line.length + 1 > 1000) break;
          gd.push(line);
        }
      }
      if (a.fullHeaders) {
        var note = "Full message headers are in the logs file " +
          "attached to this report (Additional logs).";
        if (gd.join("\n").length + note.length + 1 <= 1000) gd.push(note);
      }
      var gout = gd.join("\n");
      return gout.length > 1000 ? gout.slice(0, 1000) : gout;
    }
    if (key === "awsIncident") {
      var aw = [];
      aw.push("Type of abuse: Spam / phishing email");
      aw.push("Date/time of incident (ISO 8601): " +
        (isoFullStamp(a.date) || utcStamp(a.date)));
      aw.push("Time zone: UTC");
      aw.push("Source IP address: " + a.ip);
      aw.push("Claimed sender: " + (a.from || "unknown"));
      aw.push("Subject: " + (a.subject || "unknown"));
      return aw.join("\n");
    }
    if (key === "logs") {
      if (!a.fullHeaders && !a.ingressReceived) return null;
      var lg = [];
      if (a.ingressReceived) lg.push("Received: " + a.ingressReceived);
      if (a.fullHeaders) {
        var lth = trimHeaders(String(a.fullHeaders));
        var lfh = lth.text;
        var ltrunc = lfh.length > 8000;
        if (ltrunc) lfh = lfh.slice(0, 8000);
        if (lg.length) lg.push("");
        lg.push("Full headers (plain text, as received):");
        lfh.split("\n").forEach(function (ln) { lg.push(ln); });
        if (lth.stripped) lg.push("[ARC/DKIM signature blocks omitted \u2014 routing and authentication headers are complete]");
        if (ltrunc) lg.push("[headers truncated at 8000 characters]");
      } else {
        lg.push("Message-ID: " + (a.messageId || "unknown"));
      }
      return lg.join("\n");
    }
    if (key === "description") {
      var de = [];
      de.push("I received a spam/phishing message originating from " +
        "your network. It was sent from IP address " + a.ip +
        (a.org ? " (registered to " + a.org + ")" : "") +
        " and received on " + utcStamp(a.date) + ". " +
        "Please investigate the account or customer responsible " +
        "and take appropriate action. The message details follow " +
        "as evidence.");
      de.push("");
      de.push("Source IP: " + a.ip);
      de.push("Server: " + displayHost(a.host));
      de.push("Date/time (UTC): " + utcStamp(a.date));
      de.push("From: " + (a.from || "unknown"));
      de.push("Subject: " + (a.subject || "unknown"));
      if (a.ingressReceived) de.push("Received: " + a.ingressReceived);
      if (a.urls && a.urls.length) {
        de.push("Links in message (defanged \u2014 read hxxps as " +
          "https and [.] as .):");
        a.urls.slice(0, 10).forEach(function (u) {
          de.push("  - " + defangUrl(u));
        });
      }
      var dout = de.join("\n");
      if (a.bodyText) {
        var btHead = "\n\nMessage body (plain text, links defanged):\n";
        var room = 4000 - dout.length - btHead.length - 40;
        if (room > 0) {
          var dbt = defangText(String(a.bodyText));
          var cut = dbt.length > room;
          dout += btHead + dbt.slice(0, room) +
            (cut ? "\n[body excerpt truncated]" : "");
        }
      }
      if (dout.length > 4000) {
        dout = dout.slice(0, 4000 - 40) + "\n[description truncated]";
      }
      return dout;
    }
    return null;
  }

  // Gmail's compose-by-link (?view=cm) rejects very long URLs with a
  // bare "Error 400" — no explanation, dead end (v1.0.57 field
  // failure). Keep every compose URL under a conservative budget by
  // shrinking the complaint in steps (body excerpt first, headers
  // last — the links section is never cut), and if even the smallest
  // useful complaint won't fit, fall back to paste mode: the caller
  // copies the FULL complaint to the clipboard and opens a compose
  // carrying only To/Subject plus a short "press Ctrl+V" note. The
  // panel's complaint text (and its Copy button) always carries the
  // unshrunk complaint.
  //
  // v1.0.59: the budget itself was wrong, not just optimistic.
  // v1.0.58 budgeted 10,000 chars and STILL field-failed with a
  // 400 (Oct 20, 2026, iCloud phish from 82.152.197.57): the
  // ladder landed that complaint at an 8,997-char URL — inside
  // the budget, dead anyway. Probed against mail.google.com the
  // same day with content-free URLs: an absolute URL of 8,200
  // chars is accepted (302 to login), 8,201 chars gets the 400 —
  // a hard length cliff at Gmail's edge, nothing to do with the
  // complaint's content (the real 8,997-char URL and a synthetic
  // one of the same length both 400; an 8,200-char one doesn't).
  // Budget is now 8,000: under the measured cliff, with a small
  // margin for URL-shape variance (account index, delegated
  // paths) the probe didn't exercise.
  var COMPOSE_URL_BUDGET = 8000;

  var PASTE_NOTE = "The complaint was too long for a direct email link, " +
    "so Spam Avenger copied it to your clipboard instead.\n\n" +
    "Click in this box, press Ctrl+V (Cmd+V on a Mac) to paste the " +
    "full complaint here, then click Send.";

  function composeUrl(acct, c, bodyOverride) {
    return "https://mail.google.com/mail/u/" + acct +
      "/?view=cm&fs=1" +
      "&to=" + encodeURIComponent(c.to) +
      "&su=" + encodeURIComponent(c.subject) +
      "&body=" + encodeURIComponent(
        bodyOverride != null ? bodyOverride : c.body);
  }

  function fitForCompose(acct, a) {
    var full = a.complaint || buildComplaint(a);
    if (!full) return null;
    var url = composeUrl(acct, full);
    if (url.length <= COMPOSE_URL_BUDGET) {
      return { mode: "direct", complaint: full, url: url };
    }
    var ladder = [
      { bodyCap: 2000 }, { bodyCap: 800 }, { bodyCap: 0 },
      { bodyCap: 0, headerCap: 3000 }, { bodyCap: 0, headerCap: 1500 }
    ];
    for (var i = 0; i < ladder.length; i++) {
      var c2 = buildComplaint(a, ladder[i]);
      if (!c2) continue;
      var u2 = composeUrl(acct, c2);
      if (u2.length <= COMPOSE_URL_BUDGET) {
        return { mode: "shrunk", complaint: c2, url: u2 };
      }
    }
    return { mode: "paste", complaint: full,
             url: composeUrl(acct, full, PASTE_NOTE) };
  }

  // Decode RFC 2047 encoded-words: =?charset?Q?...?= / =?charset?B?...?=
  function decodeMimeWords(s) {
    return String(s || "").replace(/=\?([^?\s]+)\?([qQbB])\?([^?]*)\?=/g,
      function (m, charset, enc, text) {
        try {
          var bytes;
          if (enc.toUpperCase() === "B") {
            var bin = atob(text);
            bytes = new Uint8Array(bin.length);
            for (var i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
          } else {
            var qp = text.replace(/_/g, " ");
            var arr = [];
            for (var j = 0; j < qp.length; j++) {
              if (qp[j] === "=" && j + 2 < qp.length &&
                  /^[0-9a-fA-F]{2}$/.test(qp.substr(j + 1, 2))) {
                arr.push(parseInt(qp.substr(j + 1, 2), 16));
                j += 2;
              } else {
                arr.push(qp.charCodeAt(j) & 0xff);
              }
            }
            bytes = new Uint8Array(arr);
          }
          return new TextDecoder(charset || "utf-8").decode(bytes);
        } catch (e) {
          return m;
        }
      });
  }

  // Decode quoted-printable body text (soft breaks + =XX escapes).
  function decodeQP(text) {
    return String(text || "")
      .replace(/=\r?\n/g, "")
      .replace(/=([0-9A-Fa-f]{2})/g, function (m, hex) {
        return String.fromCharCode(parseInt(hex, 16));
      });
  }

  function decodeBody(bodyText, headers) {
    var cte = getFirst(headers, "content-transfer-encoding").toLowerCase();
    var t = String(bodyText || "");
    try {
      if (cte.indexOf("base64") !== -1 && t.length > 100) {
        var bin = atob(t.replace(/\s+/g, ""));
        var bytes = new Uint8Array(bin.length);
        for (var i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
        return new TextDecoder("utf-8").decode(bytes);
      }
    } catch (e) {}
    // v1.0.33: decode quoted-printable ONLY when this entity/part
    // actually declares it, or the text shows QP soft line breaks
    // ("=" at end of line). The old bare /=[0-9A-Fa-f]{2}/ sniff
    // false-fired on innocent plain text containing "=32" etc.
    // (e.g. "pid=32344&vid=222…"): decodeQP then converted "=32" to
    // "2" and "=22" to a `"` byte, which truncated URLs at the
    // extractUrls regex — real links came out mangled.
    if (cte.indexOf("quoted-printable") !== -1 || /=\r?\n/.test(t)) {
      try { return decodeQP(t); } catch (e) {}
    }
    return t;
  }

  // --- MIME part walking (v1.0.32) ---
  // Typical spam is multipart/*: the TOP-LEVEL headers rarely declare
  // a Content-Transfer-Encoding — each MIME part carries its own.
  // decodeBody() alone only honors the top level, so a base64 HTML
  // part was never decoded and extractUrls() scanned base64 gibberish
  // (the confirmed root cause of empty link lists on multipart spam).

  // Boundary parameter out of the Content-Type header, or null.
  function mimeBoundary(headers) {
    var ct = getFirst(headers, "content-type");
    var m = ct.match(/boundary\s*=\s*(?:"([^"]+)"|([^;\s]+))/i);
    if (!m) return null;
    return m[1] || m[2] || null;
  }

  // Split a multipart entity's body into [{headers, body}, ...].
  // Returns [] when the entity isn't multipart or has no boundary.
  function mimeParts(bodyText, headers) {
    var ct = getFirst(headers, "content-type").toLowerCase();
    if (ct.indexOf("multipart/") !== 0) return [];
    var boundary = mimeBoundary(headers);
    if (!boundary) return [];
    var segments = String(bodyText).split("--" + boundary);
    var parts = [];
    for (var i = 1; i < segments.length; i++) { // [0] is the preamble
      var seg = segments[i];
      if (/^--/.test(seg)) break; // closing delimiter; rest is epilogue
      seg = seg.replace(/^[ \t]*\r?\n/, "").replace(/\r?\n[ \t]*$/, "");
      if (!seg.trim()) continue;
      parts.push({
        headers: parseHeaders(seg),
        body: seg.split(/\r?\n\r?\n/).slice(1).join("\n\n")
      });
    }
    return parts;
  }

  // Decode every MIME part per its OWN Content-Transfer-Encoding.
  // One level of nesting is walked (e.g. multipart/alternative
  // inside multipart/mixed). Returns an array of decoded part bodies.
  function decodeMimeParts(bodyText, headers) {
    var out = [];
    mimeParts(bodyText, headers).forEach(function (p) {
      out.push(decodeBody(p.body, p.headers));
      mimeParts(p.body, p.headers).forEach(function (sub) {
        out.push(decodeBody(sub.body, sub.headers));
      });
    });
    return out;
  }

  // The Received header the traced IP actually came from (best evidence).
  function evidenceHeader(headers, ip) {
    var recvd = getAll(headers, "received");
    if (!ip || !recvd.length) {
      return recvd.length ? recvd[recvd.length - 1].slice(0, 300) : null;
    }
    for (var i = recvd.length - 1; i >= 0; i--) {
      if (recvd[i].indexOf(ip) !== -1) return recvd[i].slice(0, 300);
    }
    return recvd[recvd.length - 1].slice(0, 300);
  }

  function analyze(rawText) {
    var headers = parseHeaders(rawText);
    var rawBody = String(rawText).split(/\r?\n\r?\n/).slice(1).join("\n\n");
    var bodyText = decodeBody(rawBody, headers);
    var text = stripTags(bodyText).slice(0, 100000);
    var from = decodeMimeWords(getFirst(headers, "from"));
    var subject = decodeMimeWords(getFirst(headers, "subject"));
    var date = getFirst(headers, "date");
    var messageId = getFirst(headers, "message-id");
    // v1.0.32: also decode each MIME part on its own terms (a base64
    // or quoted-printable part inside a multipart message) and scan
    // the decoded part bodies — raw and tag-stripped — for links.
    var urlText = bodyText + " " + text;
    decodeMimeParts(rawBody, headers).forEach(function (partBody) {
      urlText += " " + partBody + " " + stripTags(partBody);
    });
    var urls = leadWithPages(extractUrls(urlText));
    var ip = originIp(headers);
    var rf = redFlags(from, urls, text);
    // v1.0.67: Microsoft tenant-account signals, from the
    // headers alone (investigate re-checks with the PTR host).
    var authResults = parseAuthResults(headers);
    var recvHosts = receivedHosts(headers);
    var sendingServer = sendingServerFor(headers, ip);
    var a0 = {
      from: from, subject: subject, date: date, messageId: messageId,
      ip: ip, urls: urls, urlHosts: rf.urlHosts, senderDomain: rf.senderDomain,
      flags: rf.flags,
      ingressReceived: evidenceHeader(headers, ip),
      fullHeaders: String(rawText).split(/\r?\n\r?\n/)[0] || "",
      bodyText: text,
      bodyPreview: text.slice(0, 1500),
      authResults: authResults,
      authAllPass: authAllPass(authResults),
      receivedHosts: recvHosts,
      sendingServer: sendingServer,
      msProtectionHost: recvHosts.some(isMicrosoftProtectionHost) ||
        isMicrosoftProtectionHost(sendingServer)
    };
    a0.msAccountReport = isMsAccountCase(a0);
    return a0;
  }

  // Full pipeline: analyze -> RDAP -> PTR -> complaint.
  function investigate(rawText, onProgress) {
    var a = analyze(rawText);
    function prog(s) { if (onProgress) { try { onProgress(s); } catch (e) {} } }
    if (!a.ip) {
      a.stage = "no-ip";
      return Promise.resolve(a);
    }
    prog("Looking up " + a.ip + "…");
    return rdapLookup(a.ip).then(function (rdap) {
      a.org = rdap ? extractOrg(rdap) : null;
      a.abuse = rdap ? extractAbuse(rdap) : null;
      a.hyperscaler = rdap ? hyperscalerOf(rdap) : null;
      prog("Reverse DNS…");
      return reverseDns(a.ip);
    }).then(function (host) {
      a.host = host;
      // v1.0.67: re-check the Microsoft tenant-account case with
      // the PTR host in hand (the headers alone usually settle
      // it — the protection hostname rides the ingress Received
      // hop — but a PTR naming the pool counts too). When it
      // fires, the Report Abuse lane is NOT skipped: it switches
      // to the account report built by buildComplaint below.
      a.msAccountReport = isMsAccountCase(a);
      a.skipComplaint = a.msAccountReport
        ? false : whitelisted(host);
      a.providerAdvice = (!a.msAccountReport && a.skipComplaint)
        ? providerAdvice(host) : null;
      // Gmail's report flow can be driven from the page; other providers can't.
      a.gmailAutoReport = !!(a.skipComplaint &&
        /google\.com|googlemail\.com/i.test(String(host || "")));
      // v1.0.68: in the Microsoft tenant-account case only,
      // check the "no website" tell for the sender domain
      // (A/AAAA for the apex and the www host, via dns.google).
      // The flag is set ONLY on a confirmed-empty result; any
      // error or uncertainty leaves it unset and nothing is
      // asserted anywhere. The four queries run in parallel
      // on a short timeout and any failure falls through to
      // the normal finish — the panel never blocks on this.
      var finish = function () {
        var c = buildComplaint(a);
        a.complaint = c;
        a.stage = "done";
        return a;
      };
      if (a.msAccountReport) {
        var dom = (senderEmail(a.from).match(/@([\w.-]+)/) || [])[1] ||
          a.senderDomain || "";
        return domainNoWebsite(dom).then(function (none) {
          a.senderDomainNoWebsite = none === true;
          return finish();
        }).catch(function () { return finish(); });
      }
      return finish();
    });
  }

  var api = {
    parseHeaders: parseHeaders, originIp: originIp, isPrivateIp: isPrivateIp,
    analyze: analyze, investigate: investigate, buildComplaint: buildComplaint,
    buildFormEvidence: buildFormEvidence,
    buildFormFieldEvidence: buildFormFieldEvidence,
    displayHost: displayHost,
    trimHeaders: trimHeaders, fitForCompose: fitForCompose,
    composeUrl: composeUrl, COMPOSE_URL_BUDGET: COMPOSE_URL_BUDGET,
    defangUrl: defangUrl, defangText: defangText,
    extractAbuse: extractAbuse, extractOrg: extractOrg, whitelisted: whitelisted,
    providerAdvice: providerAdvice, hyperscalerOf: hyperscalerOf,
    parseAuthResults: parseAuthResults, authAllPass: authAllPass,
    isMicrosoftProtectionHost: isMicrosoftProtectionHost,
    buildMsAccountReport: buildMsAccountReport,
    buildMicrosoftAccountReport: buildMsAccountReport,
    isMsAccountCase: isMsAccountCase, senderEmail: senderEmail,
    MS_PHISH_DESK: MS_PHISH_DESK, msDetailsNote: msDetailsNote,
    domainNoWebsite: domainNoWebsite,
    redFlags: redFlags, RDAP_BASES: RDAP_BASES,
    isAssetUrl: isAssetUrl, leadWithPages: leadWithPages,
    normalizeUrl: normalizeUrl, extractUrls: extractUrls
  };

  if (typeof module !== "undefined" && module.exports) {
    module.exports = api; // Node (tests)
  } else {
    window.SpamAvenger = api; // browser
  }
})();
