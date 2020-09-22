const fs = require('fs');
const path = require('path');

const express = require('express');
const session = require('express-session');
const passport = require('passport');
const errorHandler = require('errorhandler');
const AppleStrategy = require('@nicokaiser/passport-apple').Strategy;

passport.serializeUser((user, callback) => callback(null, user));

passport.deserializeUser((user, callback) => callback(null, user));

passport.use(
    'apple',
    new AppleStrategy(
        {
            clientID: 'org.example.service',
            teamID: '1234567890',
            keyID: '1234567890',
            key: fs.readFileSync(path.join(__dirname, 'AuthKey_1234567890.p8')),
            callbackURL: '/callback',
            scope: ['name', 'email']
        },
        (accessToken, refreshToken, profile, done) => {
            const {
                id,
                name: { firstName, lastName },
                email
            } = profile;

            // Create or update the local user here.
            // Note: name and email are only submitted on the first login!

            done(null, {
                id,
                email,
                name: { firstName, lastName }
            });
        }
    )
);

const app = express();

app.set('port', process.env.PORT || 3000);
app.use(
    session({
        resave: false,
        saveUninitialized: false,
        secret: 'keyboard cat'
    })
);
app.use(passport.initialize());
app.use(passport.session());

app.get('/', (req, res) => {
    res.send('<a href="/auth/apple">Sign in with Apple</a>');
});

app.get('/auth/apple', passport.authenticate('apple'));
app.post(
    '/auth/apple/callback',
    express.urlencoded({ extended: false }),
    passport.authenticate('apple'),
    (req, res) => {
        res.json(req.user);
    }
);

app.use(errorHandler());

app.listen(app.get('port'));
