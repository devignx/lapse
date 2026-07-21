// Email delivery — the only external dependency. All auth logic is ours;
// this is a thin pipe over an HTTP send API (Resend). Swap the fetch block to
// change providers. With no API key (local dev) it logs the link instead of
// sending, so the flow stays testable without a provider.

export async function sendMagicLink(env, email, link) {
  const from = env.MAIL_FROM || "Lapse <login@lapse.in>";

  if (!env.RESEND_API_KEY) {
    console.log(`[magic-link] no RESEND_API_KEY — would send to ${email}:\n${link}`);
    return { ok: true, dev: true };
  }

  const res = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${env.RESEND_API_KEY}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      from,
      to: email,
      subject: "Your Lapse login link",
      text: `Log in to Lapse:\n${link}\n\nThis link expires in 15 minutes and can be used once. If you didn't request it, ignore this email.`,
      html: `<div style="font-family:system-ui,sans-serif;max-width:420px">
        <p>Click to log in to <strong>Lapse</strong>:</p>
        <p><a href="${link}" style="display:inline-block;background:#6F00FF;color:#fff;text-decoration:none;padding:10px 20px;border-radius:999px">Log in</a></p>
        <p style="color:#777;font-size:13px">This link expires in 15 minutes and can be used once. If you didn't request it, ignore this email.</p>
      </div>`,
    }),
  });

  if (!res.ok) {
    const body = await res.text();
    throw new Error(`email send failed: ${res.status} ${body.slice(0, 200)}`);
  }
  return { ok: true };
}
