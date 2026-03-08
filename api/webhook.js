export const config = {
  api: {
    bodyParser: false,
  },
};

function readRawBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', (chunk) => chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)));
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

async function safeReadText(resp) {
  try {
    return await resp.text();
  } catch {
    return '';
  }
}

export default async function handler(req, res) {
  const WOLL_WEBHOOK_URL = process.env.WOLL_WEBHOOK_URL;
  const META_VERIFY_TOKEN = process.env.META_VERIFY_TOKEN;

  if (!WOLL_WEBHOOK_URL) {
    return res.status(500).json({ ok: false, error: 'Missing WOLL_WEBHOOK_URL env var' });
  }

  if (req.method === 'GET') {
    const mode = req.query['hub.mode'];
    const token = req.query['hub.verify_token'];
    const challenge = req.query['hub.challenge'];

    if (mode === 'subscribe' && token === META_VERIFY_TOKEN) {
      return res.status(200).send(challenge);
    }

    return res.status(403).send('Forbidden');
  }

  if (req.method !== 'POST') {
    res.setHeader('Allow', 'GET, POST');
    return res.status(405).send('Method Not Allowed');
  }

  const rawBody = await readRawBody(req);

  const incomingHeaders = req.headers || {};
  const forwardHeaders = {
    'content-type': incomingHeaders['content-type'] || 'application/json',
  };

  if (incomingHeaders['x-hub-signature-256']) {
    forwardHeaders['x-hub-signature-256'] = incomingHeaders['x-hub-signature-256'];
  }
  if (incomingHeaders['x-hub-signature']) {
    forwardHeaders['x-hub-signature'] = incomingHeaders['x-hub-signature'];
  }
  if (incomingHeaders['user-agent']) {
    forwardHeaders['user-agent'] = incomingHeaders['user-agent'];
  }

  try {
    const wollResp = await fetch(WOLL_WEBHOOK_URL, {
      method: 'POST',
      headers: forwardHeaders,
      body: rawBody,
    });

    const wollText = await safeReadText(wollResp);

    console.log('Forwarded to Woll:', {
      status: wollResp.status,
      bodyPreview: wollText.slice(0, 500),
    });

    if (!wollResp.ok) {
      return res.status(502).json({
        ok: false,
        error: 'Woll rejected forwarded webhook',
        wollStatus: wollResp.status,
        wollResponse: wollText.slice(0, 1000),
      });
    }

    return res.status(200).json({ ok: true, forwarded: true });
  } catch (error) {
    console.error('Proxy error:', error);
    return res.status(500).json({ ok: false, error: error?.message || 'Unknown proxy error' });
  }
}
