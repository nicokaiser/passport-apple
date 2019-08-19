# Sign in with Apple strategy for Passport

[![Build Status](https://travis-ci.org/nicokaiser/passport-apple.svg?branch=master)](https://travis-ci.org/nicokaiser/passport-apple)
[![NPM version](https://badge.fury.io/js/%40nicokaiser%2Fpassport-apple.svg)](https://www.npmjs.com/package/@nicokaiser/passport-apple)
[![Dependencies](https://david-dm.org/nicokaiser/passport-apple.svg)](https://david-dm.org/nicokaiser/passport-apple)

[Passport](http://www.passportjs.org/) strategy for authenticating with [Sign in with Apple](https://developer.apple.com/sign-in-with-apple/).

## Install

    $ npm install @nicokaiser/passport-apple

## Usage

### Create a Service

Before using this module, you must register a service with Apple. You need an Apple Developer Account for this.

- Register a new **App ID**, e.g. `com.example.test`, and enable the "Sign in with Apple" capability.
- Register a new **Services ID**, e.g. `com.example.account`. This is the `clientID` for the module configuration. Configure "Sign in with Apple" for this service and set the **Return URLs**.
- You might need to verify the ownership of the Domain by following the instructions.
- Register a new **Key**, enable "Sign in with Apple" for this key and download it. Its ID is the `keyID`.

### Configure Strategy

The Sign in with Apple authentication strategy authenticates users using an Apple ID and OAuth 2.0 tokens. The strategy options are supplied in the step above. The strategy also requires a `verify` callback, which receives an access token and profile, and calls `cb` providing a user.

```js
passport.use(new AppleStrategy({
    clientID: 'com.example.account', // Services ID
    teamID: '1234567890', // Team ID of your Apple Developer Account
    keyID: 'ABCDEFGHIJ', // Key ID, received from https://developer.apple.com/account/resources/authkeys/list
    key: fs.readFileSync(path.join('path', 'to', 'AuthKey_XYZ1234567.p8')), // Private key, downloaded from https://developer.apple.com/account/resources/authkeys/list
    scope: ['name', 'email'],
    callbackURL: 'https://example.com/auth/apple/callback'
  },
  (accessToken, refreshToken, profile, cb) => {
    User.findOrCreate({ exampleId: profile.id }, (err, user) => {
      return cb(err, user);
    });
  }
));
```

### Authenticate Requests

Use `passport.authenticate()`, specifying the `'apple'` strategy, to authenticate requests. You can pass the (required) authorization code via the `code` POST parameter.

For example, as route middleware in an [Express](http://expressjs.com/) application:

```js
app.get('/auth/apple',
  passport.authenticate('apple'));

app.post('/auth/apple/callback',
  passport.authenticate('apple', { failureRedirect: '/login' }),
  (req, res) => {
    // Successful authentication, redirect home.
    res.redirect('/');
  });
```

You can find a complete example at [examples/server.js](examples/server.js).

## FAQ

#### Which fields are provided in the user profile?

Apple currently returns a User ID that is tied to you Team ID. That means, the same Apple ID will result in the same User ID returned for authentication requests done with your Team ID. Other Teams will get a different ID for this User.

Also, if the User wants to, their name and email address is returned:

```js
{ id, name: { firstName, lastName }, email } = profile;
```

*Note that the `name` and `email` properties are only returned on the first login the user*.

#### Why not just use [passport-oauth2](https://github.com/jaredhanson/passport-oauth2/)?

The login flow for Sign in with Apple is similar to OAuth 2 and OpenID Connect, but there are quite some differences. The OpenID Foundation published a document about this: [How Sign In with Apple differs from OpenID Connect](https://bitbucket.org/openid/connect/src/default/How-Sign-in-with-Apple-differs-from-OpenID-Connect.md).

Namely, instead of a static `client_secret`, a JWT is used, however in a non-standard way. Also, user data is submitted alongside the authentication code via HTTP POST (and only if the "form_post" response mode is used!).

Apple is still working on the interfaces, as Sign in with Apple is still in beta, so it may be OIDC compliant at some point in the future.

#### How does this module differ from [passport-apple](https://github.com/ananay/passport-apple/)?

[passport-apple](https://github.com/ananay/passport-apple/) uses passport-oauth2 and replaces its client secret methods. This works, however it does not support retrieving user data (like name and email). In order to properly support this, you would need to basically re-write a slimmed down version of passport-oauth2, which basically is what this module provides.

## License

[The MIT License](http://opensource.org/licenses/MIT)

Copyright (c) 2019 Nico Kaiser <[https://kaiser.me/](https://kaiser.me/)>
