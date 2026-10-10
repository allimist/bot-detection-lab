export function EmbedPage() {
  const origin = location.origin;
  return (
    <div className="stack" style={{ maxWidth: 900 }}>
      <section className="panel">
        <h2>Use it on your own site</h2>
        <p>
          Add the collector to any page (a signup form, checkout, a landing page that buys traffic). It runs the same checks as the Check page and
          posts them here. Your server then asks this API for the verdict, so a bot can't just claim to be human.
        </p>
        <h3>1. Add the script</h3>
        <pre>{`<script src="${origin}/collector.js" data-auto data-site="shop-signup"></script>`}</pre>
        <h3>2. Send the visit id with the form</h3>
        <pre>{`<script>
  addEventListener('botcheck', (e) => {
    // e.detail is the full response: { visitId, result: { verdict, score, flags, findings }, ... }
    document.querySelector('#signup input[name=visitId]').value = e.detail.visitId;
  });
</script>`}</pre>
        <p className="muted small">
          Or call it yourself: <code>const r = await BotCheck.run({'{'} site: 'checkout' {'}'})</code>. Behaviour (mouse, keys) is sent again
          automatically when the page closes, and the stored score is updated.
        </p>
        <h3>3. Verify on your server</h3>
        <pre>{`// Node / Express
const r = await fetch(\`${origin}/api/check/\${req.body.visitId}\`, {
  headers: { authorization: \`Bearer \${process.env.BOTCHECK_TOKEN}\` }, // only if the server sets API_TOKEN
}).then((r) => r.json());

if (r.result.verdict === 'bot') return res.status(403).send('Automated traffic is not allowed.');
if (r.result.flags.includes('vpn')) flagForReview(req.body);   // decide per flag
if (r.ip.ip !== req.ip) { /* the check ran from a different IP than the form post */ }`}</pre>
        <pre>{`curl ${origin}/api/check/<visitId>`}</pre>
      </section>

      <section className="panel">
        <h2>API</h2>
        <table>
          <thead><tr><th>Endpoint</th><th>What it does</th></tr></thead>
          <tbody>
            <tr><td className="mono">POST /api/collect</td><td>Body <code>{'{ signals, site }'}</code> from the collector. Returns the scored visit.</td></tr>
            <tr><td className="mono">POST /api/collect/:id/behavior</td><td>Adds mouse / keyboard behaviour to a visit (within 30 min) and re-scores it.</td></tr>
            <tr><td className="mono">GET /api/check/:id</td><td>Server-side verification of a visit. Needs <code>Authorization: Bearer</code> when <code>API_TOKEN</code> is set.</td></tr>
            <tr><td className="mono">GET /api/inspect</td><td>Scores the request itself with no JavaScript: what curl or a scraper would get.</td></tr>
            <tr><td className="mono">GET /api/visits, /api/stats</td><td>Dashboard data (token-protected when <code>API_TOKEN</code> is set).</td></tr>
            <tr><td className="mono">GET /collector.js</td><td>The standalone collector bundle (~15 KB, no dependencies).</td></tr>
          </tbody>
        </table>
      </section>

      <section className="panel">
        <h2>Response</h2>
        <pre>{`{
  "visitId": "4c0d…",
  "fingerprintId": "1f3a9c0b2d4e5f",
  "ip": { "ip": "185.1.2.3", "country": "NL", "asOrg": "M247", "datacenter": true, "vpnRange": true, "tor": false, … },
  "webrtcIp": { "ip": "84.229.10.20", "country": "IL", … },
  "tls": { "ja4": "t13d1516h2_8daaf6152771_d8a2da3f94cd", "alpn": "h2", "grease": true, … },
  "result": {
    "score": 85,                       // bot risk 0-100
    "verdict": "bot",                  // human < 25 <= suspicious < 60 <= bot
    "flags": ["datacenter", "proxy", "vpn"],
    "findings": [{ "id": "net.datacenter", "status": "fail", "points": 30, "title": "Datacenter IP", "detail": "…" }, …]
  }
}`}</pre>
      </section>
    </div>
  );
}
