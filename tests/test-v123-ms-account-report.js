// Spam Avenger for Outlook v1.2.3 — Microsoft tenant-account
// parity with the Gmail addon's v1.0.67/v1.0.68 behavior.
// The engine (analyze.js) is the unmodified Gmail build, so
// most checks mirror the Gmail suites against the real first
// case (Jessica Huber, Nov 2 2026); the pane checks pin the
// taskpane.js wiring: the SAME abuse-complaint section switches
// (no new section), the details Abuse contact row names the
// phishing desk, and the details note flips via the engine's
// msDetailsNote. The DNS "no website" tell asserts only on a
// confirmed-empty result. The Azure form kit (Michael's second
// live case, Nov 2 2026) is covered at the end: an Azure-hosted
// spam keeps its emailed complaint AND flags the hyperscaler
// the pane kit keys off; a tenant case whose RDAP reads as a
// Microsoft cloud block still stays on the phishing desk.
//
// Run: node tests/test-v123-ms-account-report.js
"use strict";
const fs = require("fs");
const path = require("path");

const ROOT = path.join(__dirname, "..");
const analyzeSrc = fs.readFileSync(path.join(ROOT, "analyze.js"), "utf8");
const taskpaneSrc = fs.readFileSync(path.join(ROOT, "taskpane.js"), "utf8");
const htmlSrc = fs.readFileSync(path.join(ROOT, "taskpane.html"), "utf8");
const manifestSrc = fs.readFileSync(path.join(ROOT, "manifest.xml"), "utf8");
const analyze = require(path.join(ROOT, "analyze.js"));

// taskpane.js boots against Office/DOM in the browser; stub the
// one call its no-Office path makes so the harness can read its
// exported VERSION. Nothing else in the file runs at load. The
// pane also reads the engine through the browser global
// SpamAvenger (window.SpamAvenger, set by analyze.js there) —
// provide it here so the pane's exported text builders run.
global.document = { getElementById: function () { return {}; } };
global.SpamAvenger = analyze;
const taskpane = require(path.join(ROOT, "taskpane.js"));

let pass = 0, fail = 0;
function ok(name, cond, extra) {
  if (cond) { pass++; console.log("  ok   " + name); }
  else { fail++; console.log("  FAIL " + name + (extra ? " — " + extra : "")); }
}

// ---------- version pins ----------
ok("taskpane VERSION is 1.2.3", taskpane.VERSION === "1.2.3",
  "got " + taskpane.VERSION);
ok("taskpane.html tag shows v1.2.3", htmlSrc.indexOf("v1.2.3") !== -1);
ok("manifest version is 1.2.3.0",
  manifestSrc.indexOf("<Version>1.2.3.0</Version>") !== -1);

// dist mirrors (only exist in the working tree, not the repo)
const distDir = path.join(ROOT, "dist");
if (fs.existsSync(distDir)) {
  const v123 = fs.readFileSync(path.join(distDir, "manifest-v123.xml"), "utf8");
  const distRoot = fs.readFileSync(path.join(distDir, "manifest.xml"), "utf8");
  ok("dist/manifest-v123.xml is the new live manifest", v123 === manifestSrc);
  ok("dist/manifest.xml mirrors the live manifest", distRoot === manifestSrc);
  const draft = fs.readFileSync(
    path.join(distDir, "manifest-store-draft.xml"), "utf8");
  ok("store draft carries 1.2.3.0",
    draft.indexOf("<Version>1.2.3.0</Version>") !== -1);
  function stripVolatile(s) {
    return s.split("\n").filter(function (ln) {
      return ln.indexOf("<Version>") === -1 &&
        ln.indexOf("<IconUrl") === -1 && ln.indexOf("<SupportUrl") === -1;
    }).join("\n");
  }
  ok("store draft still differs only in IconUrl/SupportUrl/Version",
    stripVolatile(draft) === stripVolatile(manifestSrc) &&
    draft.indexOf("icon64.png") !== -1 &&
    draft.indexOf("support.html") !== -1);
}

// Engine parity: analyze.js is an unmodified copy of the Gmail
// build — byte-identical when a sibling checkout is on disk.
(function () {
  const sibs = [
    path.join(ROOT, "..", "spam-avenger-gmail", "lib", "analyze.js"),
    path.join(ROOT, "..", "spam-avenger", "lib", "analyze.js")
  ];
  for (const s of sibs) {
    if (fs.existsSync(s)) {
      ok("analyze.js is byte-identical to the Gmail engine",
        fs.readFileSync(s, "utf8") === analyzeSrc);
      return;
    }
  }
  console.log("  skip engine byte-parity (no sibling checkout found)");
})();

// ---------- fixtures (same shapes as the Gmail suites) ----------
const MS_RAW = [
  "Return-Path: <jessica.h@lumeracrescent.co>",
  "Received: from mail-centralusazon11021138.outbound.protection.outlook.com ([52.101.62.138]:2623 helo=DM5PR21CU001.outbound.protection.outlook.com)",
  "\tby ben.ace-host.net with esmtps id 1xO2AG-0001 for <mjf@colorami.com>;",
  "\tMon, 02 Nov 2026 19:14:14 -0500",
  "ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass",
  " smtp.mailfrom=lumeracrescent.co; dmarc=pass action=none",
  " header.from=lumeracrescent.co; dkim=pass header.d=lumeracrescent.co; arc=none",
  "DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=lumeracrescent.co;",
  " s=selector1; b=DEADBEEFCAFEBABE0123456789==",
  "Authentication-Results: mx.microsoft.com 1; dkim=none (message not signed)",
  " header.d=none;dmarc=none action=none header.from=lumeracrescent.co;",
  "From: Jessica Huber <jessica.h@lumeracrescent.co>",
  "To: mjf@colorami.com",
  "Subject: re: Franktown Firearms",
  "Message-ID: <01a19ec0-8b2d-7db9-aa71-cbd19fd0db3c@lumeracrescent.co>",
  "Date: Tue, 03 Nov 2026 00:13:01 +0000",
  "Content-Type: text/plain; charset=utf-8",
  "",
  "Hello, please review the attached offer at https://bait.example.com/offer today."
].join("\n");

// Same pool origin, but nothing passes — a spoof riding the
// pool's name, NOT a real account: the case must not fire.
const SPOOF_RAW = MS_RAW
  .split("spf=pass").join("spf=fail")
  .split("dkim=pass").join("dkim=fail")
  .split("dmarc=pass").join("dmarc=fail");

// Same case, different sender domain (keeps the domain-website
// cache from leaking between the investigate scenarios below).
const MS_FAIL_RAW = MS_RAW.split("lumeracrescent.co").join("failmail.example")
  .replace("jessica.h@", "huber@");

const NORMAL_RAW = [
  "Received: from mail.spammy.example ([203.0.113.9]) by mx.example with smtp",
  "Authentication-Results: mx.example; spf=none smtp.mailfrom=spammy.example",
  "From: Deals <deals@spammy.example>",
  "Subject: You won",
  "Message-ID: <win@spammy.example>",
  "Date: Wed, 28 Oct 2026 00:00:00 +0000",
  "",
  "Claim at https://spammy.example/win"
].join("\n");

// Michael's second live case (Nov 2 2026): a "FINAL WARNING"
// phish sent from a computer rented on Microsoft Azure —
// Microsoft-owned IP, NO protection.outlook.com server, auth
// failing. Not a tenant account: the host complaint stands,
// and the pane adds the MSRC form kit.
const AZURE_RAW = [
  "Received: from mail.0gjiueaplmtubdhyxp.example ([52.242.95.45]) by mx.example with smtp",
  "Authentication-Results: mx.example; spf=fail smtp.mailfrom=0gjiueaplmtubdhyxp.example",
  "From: Cloud Team <vwjrt8jp@0gjiueaplmtubdhyxp.example>",
  "Subject: FINAL WARNING regarding your account",
  "Message-ID: <finalwarn@0gjiueaplmtubdhyxp.example>",
  "Date: Mon, 02 Nov 2026 03:06:00 +0000",
  "",
  "Verify now: http://hc00brf6dp.acros.fun/cl/3147_rd/2007/0/280/294"
].join("\n");

// ---------- detection (headers alone) ----------
const msA = analyze.analyze(MS_RAW);
ok("analyze: Huber case flagged as a Microsoft account report",
  msA.msAccountReport === true);
ok("analyze: auth all-pass parsed from the ARC block",
  msA.authAllPass === true &&
  msA.authResults.spf === "pass" && msA.authResults.dkim === "pass" &&
  msA.authResults.dmarc === "pass");
ok("analyze: traced IP is the protection pool address",
  msA.ip === "52.101.62.138", "got " + msA.ip);
ok("host matcher: pool subdomains fire, internal hops don't",
  analyze.isMicrosoftProtectionHost(
    "mail-x.outbound.protection.outlook.com") === true &&
  analyze.isMicrosoftProtectionHost("protection.outlook.com") === true &&
  analyze.isMicrosoftProtectionHost("prod.outlook.com") === false &&
  analyze.isMicrosoftProtectionHost("outlook.com") === false);
ok("analyze: pool origin without passing auth is NOT the case",
  analyze.analyze(SPOOF_RAW).msAccountReport === false);
const normalA = analyze.analyze(NORMAL_RAW);
ok("analyze: normal sender is not the case",
  normalA.msAccountReport === false && analyze.isMsAccountCase(normalA) === false);

// ---------- the complaint lane switch (engine dispatch) ----------
const msComplaint = analyze.buildComplaint(msA);
ok("complaint: MS case targets the phishing desk",
  !!msComplaint && msComplaint.to === "phish@office365.microsoft.com" &&
  msComplaint.to === analyze.MS_PHISH_DESK,
  msComplaint && msComplaint.to);
ok("complaint: subject names the sender account",
  !!msComplaint &&
  msComplaint.subject === "Phishing account report: jessica.h@lumeracrescent.co",
  msComplaint && msComplaint.subject);
ok("complaint: body reports the account, headers ride in the body",
  !!msComplaint &&
  msComplaint.body.indexOf("The account itself is the offender") !== -1 &&
  msComplaint.body.indexOf("Full headers") !== -1 &&
  msComplaint.body.indexOf("shared outbound protection pool") !== -1);
const normalComplaint = analyze.buildComplaint(
  Object.assign({}, normalA, { abuse: "abuse@spammy.example" }));
ok("complaint: normal sender still gets the host complaint",
  !!normalComplaint && normalComplaint.to === "abuse@spammy.example" &&
  normalComplaint.subject.indexOf("Network abuse complaint") === 0);

// ---------- the flipped details note + the tell in the body ----------
const BASE_NOTE = "No makeup this time: jessica.h@lumeracrescent.co " +
  "is the face. The IP is just Microsoft's shared mail truck.";
ok("note: MS case gets the flipped note naming the account",
  analyze.msDetailsNote(msA) === BASE_NOTE,
  JSON.stringify(analyze.msDetailsNote(msA)));
const msWeb = Object.assign({}, msA, { senderDomainNoWebsite: true });
ok("note: confirmed no-website adds the domain sentence",
  analyze.msDetailsNote(msWeb) === BASE_NOTE +
    " lumeracrescent.co doesn't even run a website. " +
    "It exists only to send mail.");
ok("note: normal sender gets NO flipped note (old line stands)",
  analyze.msDetailsNote(normalA) === null);
const bodyWith = analyze.buildComplaint(msWeb);
ok("body: confirmed no-website adds the Website line",
  !!bodyWith && bodyWith.body.indexOf(
    "lumeracrescent.co has no website (no A or AAAA records for " +
    "the domain or www.lumeracrescent.co). It exists only to " +
    "send mail.") !== -1);
const bodyWithout = analyze.buildComplaint(msA);
ok("body: no flag, no Website line (silence on uncertainty)",
  !!bodyWithout && bodyWithout.body.indexOf("has no website") === -1);

// ---------- pane wiring (source pins) ----------
ok("pane: abuse contact row switches to the phishing desk in the MS case",
  taskpaneSrc.indexOf(
    'a.msAccountReport ? "phish@office365.microsoft.com"') !== -1 &&
  taskpaneSrc.indexOf('mkRow("Abuse contact"') !== -1);
ok("pane: non-MS abuse contact still falls back to RDAP / not published",
  taskpaneSrc.indexOf(': (a.abuse || "not published")') !== -1);
ok("pane: details note comes from the engine's flipped note in the MS case",
  taskpaneSrc.indexOf("SpamAvenger.msDetailsNote") !== -1 &&
  taskpaneSrc.indexOf("detailNote ||") !== -1);
ok("pane: the original makeup line still stands for normal senders",
  taskpaneSrc.indexOf(
    "address is makeup. The IP is the face underneath.") !== -1);
ok("pane: complaint section carries the switch note in the MS case",
  taskpaneSrc.indexOf(
    "this report goes to Microsoft's phishing desk") !== -1 &&
  taskpaneSrc.indexOf("about the account itself") !== -1);
ok("pane: still ONE complaint section — the MS section stays guidance only",
  (taskpaneSrc.match(/accSection\("sf-sec-/g) || []).length === 6 &&
  taskpaneSrc.indexOf("help improve their spam filters") !== -1);
ok("pane: complaint compose still goes through displayNewMessageForm",
  taskpaneSrc.indexOf("displayNewMessageForm") !== -1 &&
  taskpaneSrc.indexOf("toRecipients: [c.to]") !== -1);

// ---------- the Azure form kit (pane) ----------
ok("azure: form URL is the exact prefilled MSRC link",
  taskpane.AZURE_FORM_URL ===
  "https://msrc.microsoft.com/report/abuse?ThreatType=IpAddress&IncidentType=Spam",
  taskpane.AZURE_FORM_URL);
ok("pane: kit triggers on the hyperscaler flag, tenant case excluded",
  taskpaneSrc.indexOf(
    'if (a.hyperscaler === "azure" && !a.msAccountReport)') !== -1);
ok("pane: kit wording names the form as where a case gets opened",
  taskpaneSrc.indexOf("computer rented on Microsoft") !== -1 &&
  taskpaneSrc.indexOf("the form is where a case") !== -1);
ok("pane: kit carries the form-details box and its copy button",
  taskpaneSrc.indexOf("sf-azure-form-text") !== -1 &&
  taskpaneSrc.indexOf("sf-azure-copy") !== -1 &&
  taskpaneSrc.indexOf("Copy the details for the form") !== -1);
ok("pane: kit link is the printed URL itself, opened in a new tab",
  taskpaneSrc.indexOf("}, AZURE_FORM_URL));") !== -1 &&
  taskpaneSrc.indexOf('href: AZURE_FORM_URL') !== -1);

const azureA = analyze.analyze(AZURE_RAW);
ok("analyze: Azure spam traces to the Azure IP, not the tenant case",
  azureA.ip === "52.242.95.45" && azureA.msAccountReport === false,
  "ip=" + azureA.ip + " ms=" + azureA.msAccountReport);
const azDetails = taskpane.azureFormDetailsText(
  Object.assign({}, azureA, { host: "mail.0gjiueaplmtubdhyxp.example" }));
ok("azure details: the form facts ride in the block",
  azDetails.indexOf("Source IP: 52.242.95.45") !== -1 &&
  azDetails.indexOf("Date/time (UTC): Mon, 02 Nov 2026 03:06:00 UTC") !== -1 &&
  azDetails.indexOf("From: Cloud Team <vwjrt8jp@0gjiueaplmtubdhyxp.example>") !== -1 &&
  azDetails.indexOf("Subject: FINAL WARNING regarding your account") !== -1 &&
  azDetails.indexOf("Server: mail.0gjiueaplmtubdhyxp.example") !== -1);
ok("azure details: links defanged, full headers attached",
  azDetails.indexOf("hxxp://hc00brf6dp[.]acros[.]fun/cl/3147_rd/2007/0/280/294") !== -1 &&
  azDetails.indexOf("http://hc00brf6dp.acros.fun") === -1 &&
  azDetails.indexOf("Full headers (plain text, as received):") !== -1 &&
  azDetails.indexOf("Received: from mail.0gjiueaplmtubdhyxp.example") !== -1);
ok("azure details: form evidence, not the email (no greeting)",
  azDetails.indexOf("Hello Abuse Team") === -1);
(function () {
  const filler = [];
  for (let i = 0; i < 300; i++) {
    filler.push("X-Filler-" + i + ": " + new Array(61).join("x"));
  }
  const big = taskpane.azureFormDetailsText(Object.assign({},
    azureA, { fullHeaders: filler.join("\n") }));
  ok("azure details: headers capped like the complaint (8000)",
    big.indexOf("[headers truncated at 8000 characters]") !== -1);
})();

// ---------- domainNoWebsite verdicts (stubbed DNS) ----------
function dnsStub(table, defaultPayload) {
  return function (url) {
    const u = new URL(url);
    const key = u.searchParams.get("name") + "/" + u.searchParams.get("type");
    const payload = Object.prototype.hasOwnProperty.call(table, key)
      ? table[key] : defaultPayload;
    if (payload === "REJECT") return Promise.reject(new Error("boom"));
    return Promise.resolve({
      ok: true, json: function () { return Promise.resolve(payload); }
    });
  };
}
const EMPTY = { Status: 0 };
const NXD = { Status: 3 };
const A_REC = { Status: 0, Answer: [{ name: "x", type: 1, TTL: 300, data: "192.0.2.1" }] };
const SERVFAIL = { Status: 2 };

const RDAP_SPAMMY = {
  name: "SPAMMY-NET",
  entities: [
    { roles: ["abuse"], vcardArray: ["vcard",
      [["email", {}, "text", "abuse@spammy.example"]]] },
    { roles: ["registrant"], vcardArray: ["vcard",
      [["fn", {}, "text", "Spammy LLC"]]] }
  ]
};

// An Azure allocation's RDAP shape: MSFT net name registered
// to Microsoft Corporation, general Microsoft abuse desk —
// hyperscalerOf reads this as "azure".
const RDAP_AZURE = {
  name: "MSFT",
  entities: [
    { roles: ["abuse"], vcardArray: ["vcard",
      [["fn", {}, "text", "Microsoft Abuse Contact"],
       ["email", {}, "text", "abuse@microsoft.com"]]] },
    { roles: ["registrant"], vcardArray: ["vcard",
      [["fn", {}, "text", "Microsoft Corporation"]]] }
  ]
};

async function run() {
  global.fetch = dnsStub({}, EMPTY);
  ok("dns: all four queries NOERROR-empty confirms no website",
    await analyze.domainNoWebsite("nodata.example") === true);
  global.fetch = dnsStub({}, NXD);
  ok("dns: NXDOMAIN everywhere also confirms no website",
    await analyze.domainNoWebsite("nxd.example") === true);
  global.fetch = dnsStub({ "hasa.example/A": A_REC }, EMPTY);
  ok("dns: an apex A record defeats the tell",
    await analyze.domainNoWebsite("hasa.example") === false);
  global.fetch = dnsStub({ "servfail.example/AAAA": SERVFAIL }, EMPTY);
  ok("dns: one SERVFAIL among empties = uncertainty, stay silent",
    await analyze.domainNoWebsite("servfail.example") === null);
  global.fetch = dnsStub({}, "REJECT");
  ok("dns: fetch failures = uncertainty, stay silent",
    await analyze.domainNoWebsite("boom.example") === null);
  ok("dns: garbage domain is uncertainty, not a tell",
    await analyze.domainNoWebsite("") === null &&
    await analyze.domainNoWebsite("nodot") === null);

  // ---------- investigate() end to end ----------
  function pipeStub(opts) {
    return function (url) {
      if (url.indexOf("rdap") !== -1) {
        return Promise.resolve({ ok: !!opts.rdap, json: function () {
          return Promise.resolve(opts.rdap || {});
        } });
      }
      const u = new URL(url);
      const name = u.searchParams.get("name");
      const type = u.searchParams.get("type");
      if (opts.queried) opts.queried.push(name + "/" + type);
      if (type === "PTR") {
        return Promise.resolve({ ok: true, json: function () {
          return Promise.resolve({ Status: 0, Answer: [{ type: 12,
            data: opts.ptr }] });
        } });
      }
      if (opts.dnsDown) return Promise.reject(new Error("dns down"));
      return Promise.resolve({ ok: true, json: function () {
        return Promise.resolve(opts.dnsPayload || EMPTY);
      } });
    };
  }

  // A: the real case shape — pool PTR, empty web DNS.
  global.fetch = pipeStub({
    rdap: null,
    ptr: "mail-centralusazon11021138.outbound.protection.outlook.com."
  });
  const invA = await analyze.investigate(MS_RAW);
  ok("investigate: MS case is not skipped and carries no provider advice",
    invA.msAccountReport === true && invA.skipComplaint === false &&
    !invA.providerAdvice);
  ok("investigate: MS case confirmed the no-website tell",
    invA.senderDomainNoWebsite === true);
  ok("investigate: complaint is the account report WITH the tell",
    !!invA.complaint &&
    invA.complaint.to === "phish@office365.microsoft.com" &&
    invA.complaint.body.indexOf("has no website") !== -1);
  ok("investigate: panel note for the real case carries both sentences",
    analyze.msDetailsNote(invA) === BASE_NOTE +
      " lumeracrescent.co doesn't even run a website. " +
      "It exists only to send mail.");

  // B: DNS down — pipeline still completes, tell unasserted.
  global.fetch = pipeStub({ rdap: null, dnsDown: true,
    ptr: "mail-x.outbound.protection.outlook.com." });
  const invB = await analyze.investigate(MS_FAIL_RAW);
  ok("investigate: DNS failure never breaks the pipeline",
    invB.stage === "done" && !!invB.complaint);
  ok("investigate: DNS failure leaves the tell unset and unasserted",
    invB.senderDomainNoWebsite === false &&
    invB.complaint.body.indexOf("has no website") === -1 &&
    invB.complaint.to === "phish@office365.microsoft.com");

  // C: spoof from the pool — old skip + provider-advice path.
  global.fetch = pipeStub({ rdap: null,
    ptr: "mail-x.outbound.protection.outlook.com." });
  const invS = await analyze.investigate(SPOOF_RAW);
  ok("investigate: pool spoof stays on the skip/provider-advice path",
    invS.msAccountReport === false && invS.skipComplaint === true &&
    !invS.complaint && /real Microsoft account/.test(invS.providerAdvice || ""),
    JSON.stringify({ skip: invS.skipComplaint,
      advice: invS.providerAdvice }));

  // D: normal sender — host complaint, no website check.
  const queried = [];
  global.fetch = pipeStub({ rdap: RDAP_SPAMMY,
    ptr: "mail.spammy.example.", queried: queried });
  const invC = await analyze.investigate(NORMAL_RAW);
  ok("investigate: normal sender gets the RDAP host complaint",
    !!invC.complaint && invC.complaint.to === "abuse@spammy.example" &&
    invC.skipComplaint === false);
  ok("investigate: normal sender never triggers the website check",
    !invC.senderDomainNoWebsite &&
    queried.indexOf("spammy.example/A") === -1 &&
    queried.indexOf("www.spammy.example/A") === -1,
    queried.join(","));
  ok("investigate: normal sender has no hyperscaler flag (no form kit)",
    !invC.hyperscaler, "got " + invC.hyperscaler);

  // E: Azure-hosted spam — the emailed complaint stays, the
  // hyperscaler flag fires for the pane's form kit.
  global.fetch = pipeStub({ rdap: RDAP_AZURE,
    ptr: "52-242-95-45.cloudapp.azure.com." });
  const invE = await analyze.investigate(AZURE_RAW);
  ok("investigate: Azure spam flags the hyperscaler",
    invE.hyperscaler === "azure", "got " + invE.hyperscaler);
  ok("investigate: Azure spam is neither the tenant case nor skipped",
    invE.msAccountReport === false && invE.skipComplaint === false);
  ok("investigate: Azure spam keeps the emailed complaint to abuse@microsoft.com",
    !!invE.complaint && invE.complaint.to === "abuse@microsoft.com" &&
    invE.complaint.subject.indexOf("Network abuse complaint") === 0,
    invE.complaint && invE.complaint.to);
  const invEDet = taskpane.azureFormDetailsText(invE);
  ok("investigate: Azure form details carry the traced facts",
    invEDet.indexOf("Source IP: 52.242.95.45") !== -1 &&
    invEDet.indexOf("hxxp://hc00brf6dp[.]acros[.]fun") !== -1 &&
    invEDet.indexOf("Full headers") !== -1);

  // F: the tenant case, but its pool IP's RDAP reads as a
  // Microsoft cloud block — the hyperscaler fires, yet the
  // account report still owns the lane (the pane kit's
  // !msAccountReport guard keys off exactly this combination).
  global.fetch = pipeStub({ rdap: RDAP_AZURE,
    ptr: "mail-centralusazon11021138.outbound.protection.outlook.com." });
  const invF = await analyze.investigate(MS_RAW);
  ok("investigate: tenant case + Azure RDAP stays on the phishing desk",
    invF.msAccountReport === true && invF.hyperscaler === "azure" &&
    !!invF.complaint &&
    invF.complaint.to === "phish@office365.microsoft.com",
    JSON.stringify({ hyper: invF.hyperscaler,
      to: invF.complaint && invF.complaint.to }));

  console.log("\n" + pass + " passed, " + fail + " failed");
  process.exit(fail ? 1 : 0);
}

run().catch(function (e) {
  console.log("  FAIL async suite crashed — " + (e && e.stack || e));
  console.log("\n" + pass + " passed, " + (fail + 1) + " failed");
  process.exit(1);
});
