# Sign in with Apple strategy for Passport

[![Build Status](https://travis-ci.org/nicokaiser/passport-apple.svg?branch=master)](https://travis-ci.org/nicokaiser/passport-apple)
[![NPM version](https://badge.fury.io/js/%40nicokaiser%2Fpassport-apple.svg)](https://www.npmjs.com/package/@nicokaiser/passport-apple)
[![Dependencies](https://david-dm.org/nicokaiser/passport-apple.svg)](https://david-dm.org/nicokaiser/passport-apple)

[Passport](http://www.passportjs.org/) strategy for authenticating with [Sign in with Apple](https://developer.apple.com/sign-in-with-apple/).

[English README is here！](https://github.com/nicokaiser/passport-apple/blob/master/README.md)

이 문서는 한국어로 제작되었습니다. 번역이 어색하다면 수정 바랍니다.

## 패키지 설치

    $ npm install @nicokaiser/passport-apple

## 사용법

### 서비스 생성하기

이 모듈을 사용하기 전에, 애플 개발자 계정이 필요하며 애플에 이 서비스가 등록되어야 합니다.
아래의 작업 목록들을 애플 개발자 페이지에서 해주시길 바랍니다.

- Identifiers 메뉴의 App IDs 항목에서 `com.example.test`처럼 새로운 **App ID**를 등록하고 "Sign in with Apple" 기능을 활성화 시킵니다.
- Services IDs 항목에서 `com.example.account`처럼(App ID를 반대로 뒤집어서 사용해도 가능) 새로운 **Services ID**를 등록합니다. 이것은 모듈 구성에 대한 `clientID` 입니다. Configure 버튼을 누르고 "Sign in with Apple"를 활성화 시킨 다음, **Return URLs**을 설정합니다.
- 지침에 따라 도메인 소유권을 증명해야 합니다.
- 새로운 **Key**를 등록하고, "Sign in with Apple"를 활성화 시키면 key 파일을 다운로드 할 수 있습니다. 여기에 표시된 ID가 `keyID`로 쓰일 것입니다.

### Strategy 설정하기

애플 로그인 인증 strategy는 Apple ID와 OAuth 2.0 토큰을 이용하여 유저를 인증하도록 구성되어 있습니다. strategy 옵션은 위의 단계에서 얻을 수 있습니다. strategy는 검증 callback 함수를 필요로 합니다. callback 함수에서는 파라미터로 access token과 refresh token, profile을 받아볼 수 있고 유저 데이터를 제공하는 `cb` 함수도 사용할 수 있습니다.

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

### 인증 요청하기

인증 요청을 수행할 라우터에 `passport.authenticate()` 함수를 사용하여 `'apple'` strategy를 등록하세요. 인증 코드는 POST 파라미터 `code`를 통해 전달됩니다, 따라서 callback으로 등록한 주소는 HTTPS POST 방식을 지원해야 하며 `req.body`를 사용할 수 있어야 합니다.

예를 들어 [Express](http://expressjs.com/) 모듈의 `express.urlencoded`를 미들웨어로 사용하면 `req.body`를 사용할 수 있습니다:

```js
app.get('/auth/apple',
  passport.authenticate('apple'));

app.post('/auth/apple/callback',
  express.urlencoded(),
  passport.authenticate('apple', { failureRedirect: '/login' }),
  (req, res) => {
    // Successful authentication, redirect home.
    res.redirect('/');
  });
```

예시 프로젝트는 여기서 확인할 수 있습니다. [examples/server.js](examples/server.js).

## FAQ

#### profile 필드에서 제공되는 정보

애플은 현재 각각의 사용자 계정을 식별할 수 있는 User ID를 제공해주고 있는데, 이 User ID는 인증을 수행한 Team ID에 대해서만 유효합니다.
즉, 같은 애플 계정이라도 서비스마다 제공되는 User ID가 다르다는 뜻입니다.

또한, 이름과 이메일(사용자 선택에 따라 진짜 주소 혹은 프록시 주소) 필드를 제공받을 수 있습니다.

```js
{ id, name: { firstName, lastName }, email } = profile;
```

*중요: `name` 과 `email` 필드는 애플 로그인에 처음 성공할 때만 제공됩니다. 이후에 시도하는 경우는 'id'만 제공됩니다.*.

#### [passport-oauth2](https://github.com/jaredhanson/passport-oauth2/)를 사용하지 않는 이유

애플 로그인 기능의 절차는 겉으로 보기에 OAuth 2나 OpenID Connect와 매우 유사하지만, 내부적으로는 꽤 많은 차이점들이 있습니다. [How Sign In with Apple differs from OpenID Connect](https://bitbucket.org/openid/connect/src/default/How-Sign-in-with-Apple-differs-from-OpenID-Connect.md)에서 OpenID 재단이 이에 대해 작성한 문서를 확인할 수 있습니다.

애플 로그인은 정적 `client_secret` 대신 JWT 토큰을 사용하는데 이 방법은 비표준적입니다. 또한, 사용자 데이터가 HTTP POST 방식으로 인증코드와 함께 제출됩니다. (단, response mode가 "form_post"로 설정되었을 경우에만)

애플이 아직 이 인터페이스에 대해 작업을 하는 중이고, 애플 로그인이 베타버전이기 때문에 나중에 OpenID Connect 기준을 준수하게 될 가능성도 있습니다.

#### [passport-apple](https://github.com/ananay/passport-apple/) 모듈과 다른점

[passport-apple](https://github.com/ananay/passport-apple/) 모듈은 passport-oauth2을 사용중이고 client secret 방법을 대체하고 있습니다만, `name`과 `email` 같은 유저 데이터를 제공받을 수 없습니다. 이 문제를 해결하려면 축소된 버전의 passport-oauth2 모듈이 제공하는 기능들로 다시 구현해야 합니다.
## License

[The MIT License](http://opensource.org/licenses/MIT)

Copyright (c) 2019 Nico Kaiser <[https://kaiser.me/](https://kaiser.me/)>
