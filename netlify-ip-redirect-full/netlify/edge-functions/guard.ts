// Netlify Edge Function: Redirect ISP users, block hosting/VPN/bots

export default async (request: Request, context: any) => {
  const ua = (request.headers.get("user-agent") || "").toLowerCase();

  if (isKnownBot(ua)) {
    return block("Blocked: known bot");
  }

  const ip = context?.ip || getIpFromHeaders(request.headers) || "";
  if (!ip) return context.next();

  const token = Deno.env.get("IPINFO_TOKEN");
  if (!token) return context.next();

  try {
    const resp = await fetch(`https://ipinfo.io/${ip}?token=${token}`, { headers: { Accept: "application/json" } });
    if (!resp.ok) return context.next();
    const data = await resp.json();

    if (data?.bogon) return block("Blocked: bogon IP");

    const privacy = data?.privacy || {};
    const companyType = (data?.company?.type || "").toLowerCase();

    const isHosting =
      privacy.hosting || privacy.vpn || privacy.proxy || privacy.tor ||
      companyType === "hosting" || companyType === "business";

    const isIspUser =
      companyType === "isp" &&
      !privacy.hosting && !privacy.vpn && !privacy.proxy && !privacy.tor;

    if (isHosting && !isIspUser) {
      return block("Access denied (hosting/cloud/VPN/proxy IP)");
    }

    if (isIspUser) {
      return Response.redirect("https://myworkshop.net", 302);
    }

    return context.next();
  } catch {
    return context.next();
  }
};

function getIpFromHeaders(h: Headers): string | null {
  const xff = h.get("x-forwarded-for");
  if (xff) return xff.split(",")[0].trim();
  return h.get("cf-connecting-ip") || h.get("x-real-ip") || null;
}

function block(message: string): Response {
  const body = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>Access Denied</title>
  <style>
    body{font-family:Arial,sans-serif;background:#111;color:#eee;display:grid;place-items:center;min-height:100vh}
    .card{padding:2rem;background:#1c1c1c;border-radius:12px;max-width:600px}
    h1{margin:0 0 1rem}
    p{margin:0.25rem 0}
    code{background:#333;padding:0.2rem 0.4rem;border-radius:4px}
  </style>
</head>
<body>
  <div class="card">
    <h1>403 • Access Denied</h1>
    <p>${escapeHtml(message)}</p>
    <p>If this is unexpected, please try again without VPN/Proxy or from a normal ISP connection.</p>
  </div>
</body>
</html>`;
  return new Response(body, { status: 403, headers: { "content-type": "text/html; charset=utf-8" } });
}

function escapeHtml(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

function isKnownBot(ua: string): boolean {
  const patterns: RegExp[] = [
    /\bbot\b/i, /crawler/i, /spider/i, /archiver/i, /uptime/i, /monitor/i, /validator/i,
    /fetcher/i, /scrape/i, /curl\//i, /wget\//i, /python-requests/i, /httpclient/i,
    /googlebot/i, /bingbot/i, /yandex/i, /baiduspider/i, /duckduckbot/i,
    /ahrefsbot/i, /semrushbot/i, /mj12bot/i, /facebookexternalhit/i,
    /facebookbot/i, /twitterbot/i, /slackbot/i, /discordbot/i, /linkedinbot/i
  ];
  return patterns.some((re) => re.test(ua));
}
