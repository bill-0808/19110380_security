const path = require('path');
const express = require('express');
const fs = require('fs');
const https = require('https')
const helmet = require('helmet')
const passport = require('passport');
const { Strategy } = require('passport-google-oauth20')
const cookieSession = require('cookie-session')

require('dotenv').config();


const PORT = 3000;
const config = {
    CLIENT_ID: process.env.CLIENT_ID,
    CLIENT_SECRET: process.env.CLIENT_SECRET,
    COOKIE_KEY_1: process.env.COOKIE_KEY_1,
    COOKIE_KEY_2: process.env.COOKIE_KEY_2
}

const AUTH_OPTIONS = {
    callbackURL: '/auth/google/callback',
    clientID: config.CLIENT_ID,
    clientSecret: config.CLIENT_SECRET,
}

function verifyCallback(accessToken, refreshToken, profile, done) {
    // console.log("Google profile", profile);
    done(null, profile)
}


passport.use(new Strategy(AUTH_OPTIONS, verifyCallback))

passport.serializeUser((user, done) => {
    done(null, user.id);
})

passport.deserializeUser((id, done) => {
    done(null, id);
})

const app = express();

app.use(cookieSession({
    name: 'session',
    maxAge: 24 * 60 * 60 * 1000,
    keys: [config.COOKIE_KEY_1, config.COOKIE_KEY_2]
}))

app.use(passport.initialize());
app.use(passport.session());

function checkLoggedIn(req, res, next) {
    console.log(req.user);
    const isLoggedIn = req.user && req.isAuthenticated(); //TODO
    if (!isLoggedIn) {
        return res.status(401).send({ message: "You must log in!!" })
    }
    next();
}


app.use(helmet());

app.get('/auth/google',
    passport.authenticate('google', {
        scope: ['email'],
    }))

app.get('/auth/google/callback',
    passport.authenticate('google', {
        failureRedirect: '/failure',
        successRedirect: '/',
        session: true,
    }),
    (req, res) => {
        console.log('Google called us back');
    }
)

app.get('failure', (req, res) => {
    return res.send({ message: 'Login fail' })
})

app.get('/auth/logout', (req, res) => {
    req.logout();
    return res.redirect('/');
})

app.get('/secret', checkLoggedIn, (req, res) => {
    return res.send('your personal secret is 42');
})

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

https.createServer({
    cert: fs.readFileSync('cert.pem'),
    key: fs.readFileSync('key.pem')
}, app).listen(PORT, () => {
    console.log(`Listening on port ${PORT}...`);
});
