# Sign in with Apple strategy for Passport

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
    keyID: 'ABCDEFGHIJ', // Key ID
    key: fs.readFileSync('AuthKey_XYZ1234567.p8'),
    scope: 'name email',
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

Use `passport.authenticate()`, specifying the `'apple'` strategy, to authenticate requests.

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

## FAQ

#### Which fields are provided in the user profile?

Apple currently returns a User ID that is tied to you Team ID. That means, the same Apple ID will result in the same User ID returned for authentication requests done with your Team ID. Other Teams will get a different ID for this User.

Also, if the User wants to, their name and email address is returned:

```js
{ id, name: { firstName, lastName }, email } = profile;
```

**Note that the `name` and `email` properties are only returned on the first login the user**.

## License

[The MIT License](http://opensource.org/licenses/MIT)

Copyright (c) 2019 Nico Kaiser <[https://kaiser.me/](https://kaiser.me/)>
