const express = require('express');
const app = express();
const crypto = require('crypto');
const cookieSession = require('cookie-session');
const cookieParser = require('cookie-parser');
const { Issuer, generators } = require('openid-client');
const config = require('./config.json');

let googleIssuer;
let client;
app.use(cookieSession({
  /* ----- session ----- */
  name: 'session',
  keys: [crypto.randomBytes(32).toString('hex')],
  // Cookie Options
  maxAge: 24 * 60 * 60 * 1000 // 24 hours
}))
app.use(cookieParser())


app.get('/', (req, res, next) => {
  (async () => {
    if (req.session.loggedIn) {
      return res.send("ok!")
    }
    const state = generators.state();
    const code_verifier = generators.codeVerifier();
    const code_challenge = generators.codeChallenge(code_verifier);
    const url = client.authorizationUrl({
      scope: 'openid',
      state,
      code_challenge,
      code_challenge_method: 'S256',
    });
    req.session.state = state;
    req.session.code_verifier = code_verifier;
    req.session.originalUrl = req.originalUrl;
    return res.redirect(url);
  })().catch(next);
});

app.get('/cb', async (req, res, next) => {
  (async () => {
    if (!req.session) {
      return res.status(403).send('failed');
    }
    const state = req.session.state;
    const code_verifier = req.session.code_verifier;
    const params = client.callbackParams(req);
    const tokenSet = await client.callback(config.redirect_uri, params, { code_verifier, state });
    console.log('received and validated tokens %j', tokenSet);
    console.log('validated ID Token claims %j', tokenSet.claims());
    req.session.loggedIn = true;
    return res.redirect(req.session.originalUrl);
  })().catch(next);
})

app.listen(3000, async () => {
  googleIssuer = await Issuer.discover('https://accounts.google.com/.well-known/openid-configuration');
  console.log('Discovered issuer %s %O', googleIssuer.issuer, googleIssuer.metadata);
  client = new googleIssuer.Client({
    client_id: config.client_id,
    client_secret: config.client_secret,
    redirect_uris: [config.redirect_uri],
    response_types: ['code'],
    // id_token_signed_response_alg (default "RS256")
    // token_endpoint_auth_method (default "client_secret_basic")
  });
  console.log('Server running at http://127.0.0.1:3000');
})