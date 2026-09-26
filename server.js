/**
 * BDWebs High-Performance Anti-Framing Web Proxy
 * Zero-dependency native Node.js microservice for Coolify & BDWebs Desk
 * 
 * Features:
 * - Eliminates NSURLErrorCannotDecodeRawData (-1015) via clean Brotli/Gzip/Deflate stream normalization
 * - Strips X-Frame-Options, CSP (frame-ancestors), COOP, COEP
 * - Injects HTML <base> and client-side link/form interceptors
 * - Modifies Set-Cookie with SameSite=None; Secure for iframe persistence
 * - Preserves redirects (301/302/307/308) inside proxy
 * - Full streaming support for large assets, CSS, JS, images, fonts
 * - Forwards POST, PUT, DELETE request bodies
 * - Zero external dependencies (pure Node.js http/https/zlib)
 */

const http = require('http');
const https = require('https');
const urlModule = require('url');
const zlib = require('zlib');

const PORT = process.env.PORT || 3000;
const PROXY_TOKEN = process.env.PROXY_TOKEN || ''; // Optional secret token

// Standard CORS headers for all responses
const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS, PATCH',
  'Access-Control-Allow-Headers': '*',
  'Access-Control-Allow-Credentials': 'true'
};

// Client-side helper script injected into HTML responses
const INJECTED_HELPER_SCRIPT = `
<script id="bdwebs-proxy-helper">
(function() {
  // Prevent frame-busting scripts from escaping the iframe
  try {
    Object.defineProperty(window, 'top', { get: function() { return window.self; } });
    Object.defineProperty(window, 'parent', { get: function() { return window.self; } });
  } catch (e) {}

  var currentUrlParams = new URLSearchParams(window.location.search);
  var currentToken = currentUrlParams.get('token');
  var tokenParam = currentToken ? ('&token=' + encodeURIComponent(currentToken)) : '';

  // Intercept links to keep navigation inside the proxy
  document.addEventListener('click', function(e) {
    var target = e.target;
    while (target && target.tagName !== 'A') {
      target = target.parentElement;
    }
    if (target && target.href && !target.href.startsWith('javascript:') && !target.href.startsWith('#')) {
      var href = target.href;
      if (href.indexOf('/proxy?url=') !== -1 || href.startsWith('mailto:') || href.startsWith('tel:')) return;
      e.preventDefault();
      var proxyBase = window.location.origin + '/proxy?url=' + encodeURIComponent(href) + tokenParam;
      window.location.href = proxyBase;
    }
  }, true);

  // Intercept form submissions
  document.addEventListener('submit', function(e) {
    var form = e.target;
    if (form && form.action) {
      var action = form.action;
      if (action.indexOf('/proxy?url=') === -1) {
        var proxyBase = window.location.origin + '/proxy?url=' + encodeURIComponent(action) + tokenParam;
        form.action = proxyBase;
      }
    }
  }, true);
})();
</script>
`;

/**
 * Robust Decompressor for Brotli, Gzip, Deflate
 */
function decompressBuffer(buffer, encoding, callback) {
  if (!encoding || !buffer || buffer.length === 0) {
    return callback(null, buffer);
  }
  const enc = encoding.toLowerCase();
  if (enc.includes('br')) {
    return zlib.brotliDecompress(buffer, callback);
  }
  if (enc.includes('gzip') || enc.includes('deflate')) {
    return zlib.unzip(buffer, callback);
  }
  return callback(null, buffer);
}

/**
 * Main Proxy Handler
 */
function handleProxyRequest(req, res, targetUrlStr, tokenStr) {
  let parsedTarget;
  try {
    if (!targetUrlStr.startsWith('http://') && !targetUrlStr.startsWith('https://')) {
      targetUrlStr = 'https://' + targetUrlStr;
    }
    parsedTarget = new urlModule.URL(targetUrlStr);
  } catch (err) {
    res.writeHead(400, { 'Content-Type': 'text/plain', ...CORS_HEADERS });
    return res.end('Invalid target URL provided.');
  }

  const isHttps = parsedTarget.protocol === 'https:';
  const transport = isHttps ? https : http;

  // Prepare outgoing request headers
  const outgoingHeaders = { ...req.headers };
  delete outgoingHeaders['host'];
  delete outgoingHeaders['connection'];
  outgoingHeaders['host'] = parsedTarget.host;
  outgoingHeaders['referer'] = parsedTarget.origin + '/';
  outgoingHeaders['origin'] = parsedTarget.origin;
  outgoingHeaders['user-agent'] = req.headers['user-agent'] || 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36';
  outgoingHeaders['accept-encoding'] = 'gzip, deflate, br';

  const requestOptions = {
    protocol: parsedTarget.protocol,
    hostname: parsedTarget.hostname,
    port: parsedTarget.port || (isHttps ? 443 : 80),
    path: parsedTarget.pathname + parsedTarget.search,
    method: req.method,
    headers: outgoingHeaders,
    rejectUnauthorized: false
  };

  const targetReq = transport.request(requestOptions, (targetRes) => {
    const statusCode = targetRes.statusCode || 200;
    const incomingHeaders = { ...targetRes.headers };

    // 1. Strip Anti-Framing & Security Restrictions
    delete incomingHeaders['x-frame-options'];
    delete incomingHeaders['content-security-policy'];
    delete incomingHeaders['content-security-policy-report-only'];
    delete incomingHeaders['cross-origin-opener-policy'];
    delete incomingHeaders['cross-origin-embedder-policy'];
    delete incomingHeaders['cross-origin-resource-policy'];

    // 2. Allow Framing & CORS
    Object.assign(incomingHeaders, CORS_HEADERS);

    // 3. Rewrite Set-Cookie for iframe persistence
    if (incomingHeaders['set-cookie']) {
      const rawCookies = Array.isArray(incomingHeaders['set-cookie'])
        ? incomingHeaders['set-cookie']
        : [incomingHeaders['set-cookie']];

      incomingHeaders['set-cookie'] = rawCookies.map(cookieStr => {
        let modified = cookieStr.replace(/Domain=[^;]+;?\s*/gi, '');
        if (/SameSite=[^;]+/i.test(modified)) {
          modified = modified.replace(/SameSite=[^;]+/gi, 'SameSite=None');
        } else {
          modified += '; SameSite=None';
        }
        if (!/Secure/i.test(modified)) {
          modified += '; Secure';
        }
        return modified;
      });
    }

    // 4. Rewrite Redirects (301, 302, 303, 307, 308)
    if (statusCode >= 300 && statusCode < 400 && incomingHeaders['location']) {
      try {
        const resolvedRedirect = new urlModule.URL(incomingHeaders['location'], targetUrlStr).href;
        const tokenParam = tokenStr ? `&token=${encodeURIComponent(tokenStr)}` : '';
        incomingHeaders['location'] = `/proxy?url=${encodeURIComponent(resolvedRedirect)}${tokenParam}`;
      } catch (err) {
        // preserve location if parsing fails
      }
      res.writeHead(statusCode, incomingHeaders);
      return targetRes.pipe(res);
    }

    const contentType = incomingHeaders['content-type'] || '';
    const isHtml = contentType.toLowerCase().includes('text/html');

    // 5. If HTML: Collect, decompress, inject <base>, and send as clean uncompressed UTF-8
    // Removing content-encoding eliminates Safari's NSURLErrorDomain:-1015 completely
    if (isHtml) {
      delete incomingHeaders['content-length'];
      delete incomingHeaders['content-encoding'];
      delete incomingHeaders['transfer-encoding'];

      const chunks = [];
      targetRes.on('data', chunk => chunks.push(chunk));
      targetRes.on('end', () => {
        const rawBuffer = Buffer.concat(chunks);
        const encoding = targetRes.headers['content-encoding'] || '';

        decompressBuffer(rawBuffer, encoding, (err, decodedBuffer) => {
          let html = '';
          if (err || !decodedBuffer) {
            console.warn('Decompression notice, falling back to raw buffer:', err?.message);
            html = rawBuffer.toString('utf8');
          } else {
            html = decodedBuffer.toString('utf8');
          }

          // Target Base URL for relative assets
          const baseHref = parsedTarget.origin + parsedTarget.pathname.substring(0, parsedTarget.pathname.lastIndexOf('/') + 1);
          const baseTag = `<base href="${baseHref}">\n${INJECTED_HELPER_SCRIPT}\n`;

          // Inject right after <head> or at beginning of <html>
          if (/<head[^>]*>/i.test(html)) {
            html = html.replace(/(<head[^>]*>)/i, `$1\n${baseTag}`);
          } else if (/<html[^>]*>/i.test(html)) {
            html = html.replace(/(<html[^>]*>)/i, `$1\n<head>${baseTag}</head>`);
          } else {
            html = baseTag + html;
          }

          const modifiedBuffer = Buffer.from(html, 'utf8');
          incomingHeaders['content-length'] = modifiedBuffer.length;
          res.writeHead(statusCode, incomingHeaders);
          res.end(modifiedBuffer);
        });
      });

      targetRes.on('error', (err) => {
        console.error('Target response error:', err);
        if (!res.headersSent) {
          res.writeHead(502, { 'Content-Type': 'text/plain', ...CORS_HEADERS });
          res.end('502 Bad Gateway - Target stream error');
        }
      });
      return;
    }

    // 6. For all non-HTML assets (CSS, JS, Fonts, Images, JSON): Stream directly
    res.writeHead(statusCode, incomingHeaders);
    targetRes.pipe(res);
  });

  targetReq.on('error', (err) => {
    console.error('Proxy target request error:', err);
    if (!res.headersSent) {
      res.writeHead(502, { 'Content-Type': 'text/html; charset=utf-8', ...CORS_HEADERS });
      res.end(`
        <div style="font-family: -apple-system, sans-serif; padding: 2rem; background: #fff5f5; border: 1px solid #feb2b2; border-radius: 8px; color: #9b2c2c; max-width: 600px; margin: 2rem auto;">
          <h3 style="margin-top:0;">502 Bad Gateway</h3>
          <p>Could not connect to: <code>${targetUrlStr}</code></p>
          <p style="font-size: 12px; color: #718096;">Reason: ${err.message}</p>
        </div>
      `);
    }
  });

  // Pipe incoming request body (for POST, PUT, file uploads)
  req.pipe(targetReq);
}

// Landing page HTML
function sendLandingPage(res) {
  res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', ...CORS_HEADERS });
  res.end(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <title>BDWebs Web Proxy</title>
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0b0c10; color: #c5c6c7; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; }
        .card { background: #1f2833; padding: 2.5rem; border-radius: 1rem; border: 1px solid #45a29e; max-width: 520px; box-shadow: 0 20px 40px rgba(0,0,0,0.5); }
        h1 { color: #66fcf1; margin-top: 0; font-size: 1.5rem; display: flex; align-items: center; gap: 0.5rem; }
        p { font-size: 0.95rem; line-height: 1.6; }
        code { background: #0b0c10; padding: 0.2rem 0.4rem; border-radius: 0.3rem; color: #45a29e; font-family: monospace; }
        .form-group { margin-top: 1.5rem; display: flex; gap: 0.5rem; }
        input { flex: 1; padding: 0.75rem 1rem; border-radius: 0.5rem; border: 1px solid #45a29e; background: #0b0c10; color: #fff; font-size: 0.9rem; outline: none; }
        button { background: #66fcf1; color: #0b0c10; border: none; padding: 0.75rem 1.25rem; font-weight: bold; border-radius: 0.5rem; cursor: pointer; }
        button:hover { background: #45a29e; }
        .badge { display: inline-block; background: rgba(102, 252, 241, 0.15); color: #66fcf1; padding: 0.2rem 0.6rem; border-radius: 9999px; font-size: 0.75rem; font-weight: 600; margin-bottom: 0.75rem; }
      </style>
    </head>
    <body>
      <div class="card">
        <div class="badge">🟢 Online & Operational</div>
        <h1>⚡ BDWebs Web Proxy</h1>
        <p>This high-performance reverse proxy removes anti-framing headers (<code>X-Frame-Options</code>, <code>CSP</code>) and normalizes Brotli/Gzip streams for seamless embedded browsing in <strong>BDWebs Desk</strong>.</p>
        <div class="form-group">
          <input type="text" id="target" placeholder="https://www.sslshopper.com/ssl-checker.html" value="https://www.sslshopper.com/ssl-checker.html">
          <button onclick="visit()">Browse</button>
        </div>
        <script>
          function visit() {
            var val = document.getElementById('target').value.trim();
            if (val) {
              if (!val.startsWith('http://') && !val.startsWith('https://')) val = 'https://' + val;
              window.location.href = '/proxy?url=' + encodeURIComponent(val);
            }
          }
          document.getElementById('target').addEventListener('keyup', function(e) {
            if (e.key === 'Enter') visit();
          });
        </script>
      </div>
    </body>
    </html>
  `);
}

// HTTP Server
const server = http.createServer((req, res) => {
  // Handle CORS preflight
  if (req.method === 'OPTIONS') {
    res.writeHead(204, CORS_HEADERS);
    return res.end();
  }

  const parsedReq = new urlModule.URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const pathname = parsedReq.pathname;

  // Coolify Health Check
  if (pathname === '/health') {
    res.writeHead(200, { 'Content-Type': 'application/json', ...CORS_HEADERS });
    return res.end(JSON.stringify({
      status: 'ok',
      service: 'bdwebs-web-proxy',
      uptime: Math.floor(process.uptime()),
      timestamp: new Date().toISOString()
    }));
  }

  const targetUrl = parsedReq.searchParams.get('url');
  const providedToken = parsedReq.searchParams.get('token') || req.headers['x-proxy-token'] || '';

  // Token authentication if configured
  if (PROXY_TOKEN) {
    if (providedToken !== PROXY_TOKEN) {
      res.writeHead(401, { 'Content-Type': 'application/json', ...CORS_HEADERS });
      return res.end(JSON.stringify({ error: 'Unauthorized: Invalid or missing proxy token.' }));
    }
  }

  if (targetUrl) {
    return handleProxyRequest(req, res, targetUrl, providedToken);
  }

  // Fallback to landing page
  sendLandingPage(res);
});

server.listen(PORT, () => {
  console.log(`⚡ BDWebs Web Proxy is running on port ${PORT}`);
  console.log(`Ready for Coolify & BDWebs Desk integration`);
});
