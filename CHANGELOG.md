## 1.0.0 (2021-10-12)

  - BREAKING CHANGE: update dependencies, drop support for Node < 10
  - build: update husky config
  - build: have GitHub CI run with Node 16, not 10
  - deps: update dependencies
  - Upgrade to GitHub-native Dependabot
  - test: replace Travis with GitHub Actions
  - docs: mention usage of passReqToCallback (fixes #19)
  - docs: remove korean README, was outdated
  - nonce verification
  - re-use client secret as long as it is valid, instead of re-signing each time
  - verify the JWT signature using JWKS; set provider to 'apple'
  - Update to Prettier 2
  - Add korean README file

## 0.2.1 (2019-08-22)

- docs: Mention expess.urlencoded in README.md
- Use express.urlencoded instead of body-parser
- Add body-parser to the example to actually make it return anything

## 0.2.0 (2019-08-19)

  - return emailVerified as boolean, use array struct for scope (thanks @hansemannn)
  - Add tests, docs and an example
  - Fix jsdoc

## 0.1.0 (2019-08-14)

  - Initial release
