/**
 * BDWebs High-Performance Anti-Framing Web Proxy
 * Designed for Coolify & BDWebs Desk Mini Browser
 * 
 * Features:
 * - Strips X-Frame-Options, CSP (frame-ancestors), COOP, COEP
 * - Injects HTML <base> and client-side link/form interceptors
 * - Modifies Set-Cookie with SameSite=None; Secure for iframe persistence
 * - Preserves redirects (301/302/307/308) inside proxy
 * - Full streaming support for large assets, CSS, JS, images, fonts
 * - Forwards POST, PUT, DELETE request bodies
 */

const http = require('http');
const https = require('https');
const urlModule = require('url');
const zlib = require('zlib');
const express = require('express');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3000;
const PROXY_TOKEN = process.env.PROXY_TOKEN || ''; // Optional secret token

app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
  allowedHeaders: '*',
  credentials: true
}));

// Coolify Health Check
app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    service: 'bdwebs-web-proxy',
    uptime: Math.floor(process.uptime()),
    timestamp: new Date().toISOString()
  });
});

// Client-side helper script injected into HTML responses
const INJECTED_HELPER_SCRIPT = `
<script id="bdwebs-proxy-helper">
(function() {
  // Prevent frame-busting scripts from escaping the iframe
  try {
    Object.defineProperty(window, 'top', { get: function() { return window.self; } });
    Object.defineProperty(window, 'parent', { get: function() { return window.self; } });
  } catch (e) {}

  // Intercept links to keep navigation inside the proxy
  document.addEventListener('click', function(e) {
    var target = e.target;
    while (target && target.tagName !== 'A') {
      target = target.parentElement;
    }
    if (target && target.href && !target.href.startsWith('javascript:') && !target.href.startsWith('#')) {
      var href = target.href;
      // If already proxy URL or mailto/tel, ignore
      if (href.indexOf('/proxy?url=') !== -1 || href.startsWith('mailto:') || href.startsWith('tel:')) return;
      e.preventDefault();
      var proxyBase = window.location.origin + '/proxy?url=';
      window.location.href = proxyBase + encodeURIComponent(href);
    }
  }, true);

  // Intercept form submissions
  document.addEventListener('submit', function(e) {
    var form = e.target;
    if (form && form.action) {
      var action = form.action;
      if (action.indexOf('/proxy?url=') === -1) {
        var proxyBase = window.location.origin + '/proxy?url=';
        form.action = proxyBase + encodeURIComponent(action);
      }
    }
  }, true);
})();
</script>
`;

/**
 * Main Proxy Handler
 */
function handleProxyRequest(req, res) {
  let targetUrlStr = req.query.url;

  // Optional Token Authentication
  if (PROXY_TOKEN) {
    const providedToken = req.query.token || req.headers['x-proxy-token'];
    if (providedToken !== PROXY_TOKEN) {
      return res.status(401).json({ error: 'Unauthorized: Invalid or missing proxy token.' });
    }
  }

  // If no URL provided, render welcoming dashboard
  if (!targetUrlStr) {
    return res.send(`
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
          input { flex: 1; padding: 0.75rem 1rem; border-radius: 0.5rem; border: 1px solid #45a29e; background: #0b0c10; color: #fff; font-size: 0.9rem; }
          button { background: #66fcf1; color: #0b0c10; border: none; padding: 0.75rem 1.25rem; font-weight: bold; border-radius: 0.5rem; cursor: pointer; }
          button:hover { background: #45a29e; }
        </style>
      </head>
      <body>
        <div class="card">
          <h1>⚡ BDWebs Web Proxy</h1>
          <p>This high-performance reverse proxy removes anti-framing headers (<code>X-Frame-Options</code>, <code>CSP</code>) and rewrites cookies for seamless embedded browsing in <strong>BDWebs Desk</strong>.</p>
          <div class="form-group">
            <input type="text" id="target" placeholder="https://dnschecker.org" value="https://dnschecker.org">
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
          </script>
        </div>
      </body>
      </html>
    `);
  }

  // Ensure protocol
  if (!targetUrlStr.startsWith('http://') && !targetUrlStr.startsWith('https://')) {
    targetUrlStr = 'https://' + targetUrlStr;
  }

  let parsedTarget;
  try {
    parsedTarget = new urlModule.URL(targetUrlStr);
  } catch (err) {
    return res.status(400).send('Invalid target URL provided.');
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
  outgoingHeaders['user-agent'] = req.headers['user-agent'] || 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36';

  const requestOptions = {
    protocol: parsedTarget.protocol,
    hostname: parsedTarget.hostname,
    port: parsedTarget.port || (isHttps ? 443 : 80),
    path: parsedTarget.pathname + parsedTarget.search,
    method: req.method,
    headers: outgoingHeaders,
    rejectUnauthorized: false // Allow self-signed or internal SSL certificates
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
    incomingHeaders['access-control-allow-origin'] = '*';
    incomingHeaders['access-control-allow-methods'] = 'GET, POST, PUT, DELETE, OPTIONS, PATCH';
    incomingHeaders['access-control-allow-headers'] = '*';
    incomingHeaders['access-control-allow-credentials'] = 'true';

    // 3. Rewrite Set-Cookie for iframe persistence
    if (incomingHeaders['set-cookie']) {
      const rawCookies = Array.isArray(incomingHeaders['set-cookie'])
        ? incomingHeaders['set-cookie']
        : [incomingHeaders['set-cookie']];

      incomingHeaders['set-cookie'] = rawCookies.map(cookieStr => {
        // Strip Domain so cookie is accepted on proxy origin
        let modified = cookieStr.replace(/Domain=[^;]+;?\s*/gi, '');
        // Force SameSite=None
        if (/SameSite=[^;]+/i.test(modified)) {
          modified = modified.replace(/SameSite=[^;]+/gi, 'SameSite=None');
        } else {
          modified += '; SameSite=None';
        }
        // Force Secure flag required for SameSite=None
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
        incomingHeaders['location'] = `/proxy?url=${encodeURIComponent(resolvedRedirect)}`;
      } catch (err) {
        // keep location as is if parsing fails
      }
      res.writeHead(statusCode, incomingHeaders);
      return targetRes.pipe(res);
    }

    const contentType = incomingHeaders['content-type'] || '';
    const isHtml = contentType.toLowerCase().includes('text/html');

    // 5. If HTML: Inject <base href="..."> and helper script
    if (isHtml) {
      delete incomingHeaders['content-length']; // Length will change after injection
      
      const contentEncoding = (incomingHeaders['content-encoding'] || '').toLowerCase();
      let stream = targetRes;
      let decompressor = null;
      let compressor = null;

      if (contentEncoding.includes('gzip')) {
        decompressor = zlib.createGunzip();
        compressor = zlib.createGzip();
      } else if (contentEncoding.includes('deflate')) {
        decompressor = zlib.createInflate();
        compressor = zlib.createDeflate();
      } else if (contentEncoding.includes('br')) {
        decompressor = zlib.createBrotliDecompress();
        compressor = zlib.createBrotliCompress();
      }

      const chunks = [];
      const readStream = decompressor ? targetRes.pipe(decompressor) : targetRes;

      readStream.on('data', chunk => chunks.push(chunk));
      readStream.on('end', () => {
        const buffer = Buffer.concat(chunks);
        let html = buffer.toString('utf8');

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

        if (compressor) {
          zlib[compressor.name === 'brotliCompress' ? 'brotliCompress' : (compressor.name === 'gzip' ? 'gzip' : 'deflate')](modifiedBuffer, (err, compressed) => {
            if (!err && compressed) {
              incomingHeaders['content-length'] = compressed.length;
              res.writeHead(statusCode, incomingHeaders);
              res.end(compressed);
            } else {
              delete incomingHeaders['content-encoding'];
              incomingHeaders['content-length'] = modifiedBuffer.length;
              res.writeHead(statusCode, incomingHeaders);
              res.end(modifiedBuffer);
            }
          });
        } else {
          delete incomingHeaders['content-encoding'];
          incomingHeaders['content-length'] = modifiedBuffer.length;
          res.writeHead(statusCode, incomingHeaders);
          res.end(modifiedBuffer);
        }
      });

      readStream.on('error', (err) => {
        console.error('Error decompressing stream:', err);
        res.writeHead(statusCode, incomingHeaders);
        targetRes.pipe(res);
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
      res.status(502).send(`
        <div style="font-family: sans-serif; padding: 2rem; background: #fff5f5; border: 1px solid #feb2b2; border-radius: 8px; color: #9b2c2c;">
          <h3>502 Bad Gateway - Failed to connect to target</h3>
          <p>Could not connect to: <code>${targetUrlStr}</code></p>
          <p>Reason: ${err.message}</p>
        </div>
      `);
    }
  });

  // Pipe incoming request body (for POST, PUT, file uploads)
  req.pipe(targetReq);
}

// Routes
app.all('/proxy', handleProxyRequest);
app.all('/', (req, res, next) => {
  if (req.query.url) {
    return handleProxyRequest(req, res);
  }
  next();
});

// Default landing page
app.get('/', handleProxyRequest);

app.listen(PORT, () => {
  console.log(`⚡ BDWebs Web Proxy is running on port ${PORT}`);
  console.log(`Ready for Coolify & BDWebs Desk integration`);
});
