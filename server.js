const https = require('https');
const fs = require('fs');
const express = require('express');
const path = require('path');
const helmet = require('helmet');
require('dotenv').config({ path: '.env' });
const passport = require('passport');
const { Strategy } = require('passport-google-oauth20');
const cookieSession = require('cookie-session');

const PORT = 3000;

const config = {
  CLIENT_ID: process.env.CLIENT_ID,
  CLIENT_SECRET: process.env.CLIENT_SECRET,
  COOKIE_KEY_1: process.env.COOKIE_KEY_1,
  COOKIE_KEY_2: process.env.COOKIE_KEY_2,
};

const AUTH_OPTION = {
  callbackURL: '/auth/google/callback',
  clientID: config.CLIENT_ID,
  clientSecret: config.CLIENT_SECRET,
};

function verifyCallback(accessToken, refreshTokens, profile, done) {
  // console.log(accessToken, '::::::::::', refreshTokens);
  console.log(`Google profile :`, profile);
  done(null, profile);
}

passport.use(new Strategy(AUTH_OPTION, verifyCallback));

//save the session to the cookie
passport.serializeUser((user, done) => {
  done(null, user.id);
});

//read the session from the cookie
passport.deserializeUser((id, done) => {
  done(null, id);
});

const app = express();

app.use(helmet());

app.use(
  cookieSession({
    name: 'session',
    maxAge: 2 * 60 * 1000,
    keys: [config.COOKIE_KEY_2, config.COOKIE_KEY_1],
  })
);

app.use(passport.initialize());
app.use(passport.session());

function checkLoggedIn(req, res, next) {
  console.log(`Current user is :`, req.user);
  const isLoggedIn = req.isAuthenticated() && req.user;

  if (!isLoggedIn) {
    res.status(401).json({
      error: 'you must log in!',
    });
  }
  next();
}

app.get(
  '/auth/google',
  passport.authenticate('google', {
    scope: ['email'],
  })
);

app.get(
  '/auth/google/callback',
  passport.authenticate('google', {
    failureRedirect: '/failure',
    successRedirect: '/',
    session: true,
  }),
  (req, res) => {
    console.log('google called us back..');
  }
);

app.use('/failure', (req, res) => {
  return res.send('failed to log in!');
});

app.get('/auth/logout', (req, res) => {
  req.logout(); //removes req.user and clears any logged in session.
  return res.redirect('/');
});

app.get('/secret', checkLoggedIn, (req, res) => {
  res.send(`Your personal secret value is 11!`);
});

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

https
  .createServer(
    {
      key: fs.readFileSync('key.pem'),
      cert: fs.readFileSync('cert.pem'),
    },
    app
  )
  .listen(PORT, () => {
    console.log(`Listening on PORT: ${PORT}...`);
  });
