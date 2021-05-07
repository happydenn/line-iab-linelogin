const express = require('express');
const cookieParser = require('cookie-parser');
const asyncHandler = require('express-async-handler');
const { AuthorizationCode } = require('simple-oauth2');
const { nanoid } = require('nanoid');

const port = parseInt(process.env.PORT, 10) || 6161;
const cookieSecret = process.env.COOKIE_SECRET || 'thecookiesecret';
const callbackUrl = `${process.env.APP_HOSTNAME}/callback`;
const scope = 'profile openid';

const config = {
  client: {
    id: process.env.LINE_CHANNEL_ID,
    secret: process.env.LINE_CHANNEL_SECRET,
  },
  auth: {
    tokenHost: 'https://api.line.me',
    tokenPath: '/oauth2/v2.1/token',
    authorizeHost: 'https://access.line.me',
    authorizePath: '/oauth2/v2.1/authorize',
  },
};

const client = new AuthorizationCode(config);

const app = express();

app.use(cookieParser(cookieSecret));

const responseHtml = `
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Login</title>
</head>
<body>
<div><pre id="href"></pre></div>

<div><pre id="response"></pre></div>
<script>
function init() {
  document.getElementById('href').textContent = window.location.href;

  var t = window.location.hash.split('#access_token=')[1];
  if (typeof t === 'undefined') {
    window.location.href = '/login';
    return;
  }

  fetch('https://api.line.me/v2/profile', {
    headers: {
      authorization: 'Bearer ' + t
    }
  })
  .then((res) => res.json())
  .then((res) => {
    var el = document.getElementById('response');
    el.textContent = JSON.stringify(res, null, 2);
  })
  .catch(() => {
    window.location.href = '/login';
  });
}

init();
</script>
</body>
</html>
`;

app.get('/', (req, res) => {
  res.type('html');
  res.send(responseHtml);
});

app.get('/login', (req, res) => {
  const state = nanoid();

  const redirectUrl = client.authorizeURL({
    redirect_uri: callbackUrl,
    scope,
    state,
  });

  const sessionData = Buffer.from(JSON.stringify({ state })).toString('base64');
  res.cookie('__session', sessionData, { httpOnly: true, maxAge: 180000, signed: true });

  res.redirect(redirectUrl);
});

app.get('/callback', asyncHandler(async (req, res) => {
  const { code, state } = req.query;
  const rawSession = req.signedCookies.__session;

  if (!code || !state || !rawSession) {
    res.sendStatus(400);
    return;
  }

  const sessionData = JSON.parse(Buffer.from(rawSession, 'base64').toString());
  const { state: origState } = sessionData;

  if (state !== origState) {
    res.sendStatus(401);
    return;
  }

  const tokenParams = {
    code,
    scope,
    redirect_uri: callbackUrl,
  };

  const { token } = await client.getToken(tokenParams);

  res.redirect(`/#access_token=${token.access_token}`);
}));

app.listen(port, () => {
  console.log(`Server started on port ${port}`);
});
