/* global describe, it, before */

const chai = require('chai');
const chaiPassport = require('chai-passport-strategy');

const AppleStrategy = require('../lib/strategy');
const OAuth2 = require('oauth').OAuth2;

chai.use(chaiPassport);
const expect = chai.expect;

describe('AppleStrategy', () => {
    describe('constructed', () => {
        describe('with normal options', () => {
            const strategy = new AppleStrategy(
                {
                    clientID: 'CLIENT_ID',
                    teamID: 'TEAM_ID',
                    keyID: 'KEY_ID',
                    key: 'KEY'
                },
                () => {}
            );

            it('should be named apple', () => {
                expect(strategy.name).to.equal('apple');
            });
        });

        describe('without a verify callback', function() {
            it('should throw', function() {
                expect(() => {
                    new AppleStrategy({
                        clientID: 'CLIENT_ID',
                        teamID: 'TEAM_ID',
                        keyID: 'KEY_ID',
                        key: 'KEY'
                    });
                }).to.throw(TypeError, 'AppleStrategy requires a verify callback');
            });
        });

        describe('without a clientID option', function() {
            it('should throw', function() {
                expect(() => {
                    new AppleStrategy(
                        {
                            teamID: 'TEAM_ID',
                            keyID: 'KEY_ID',
                            key: 'KEY'
                        },
                        () => {}
                    );
                }).to.throw(TypeError, 'AppleStrategy requires a clientID option');
            });
        });

        describe('without a teamID option', function() {
            it('should throw', function() {
                expect(() => {
                    new AppleStrategy(
                        {
                            clientID: 'CLIENT_ID',
                            keyID: 'KEY_ID',
                            key: 'KEY'
                        },
                        () => {}
                    );
                }).to.throw(TypeError, 'AppleStrategy requires a teamID option');
            });
        });

        describe('without a keyID option', function() {
            it('should throw', function() {
                expect(() => {
                    new AppleStrategy(
                        {
                            clientID: 'CLIENT_ID',
                            teamID: 'TEAM_ID',
                            key: 'KEY'
                        },
                        () => {}
                    );
                }).to.throw(TypeError, 'AppleStrategy requires a keyID option');
            });
        });

        describe('without a key option', function() {
            it('should throw', function() {
                expect(() => {
                    new AppleStrategy(
                        {
                            clientID: 'CLIENT_ID',
                            teamID: 'TEAM_ID',
                            keyID: 'KEY_ID'
                        },
                        () => {}
                    );
                }).to.throw(TypeError, 'AppleStrategy requires a key option');
            });
        });
    });

    describe('authorization request with display parameter', function() {
        const strategy = new AppleStrategy(
            {
                clientID: 'CLIENT_ID',
                teamID: 'TEAM_ID',
                keyID: 'KEY_ID',
                key: 'KEY'
            },
            () => {}
        );

        let url;

        before(function(done) {
            chai.passport
                .use(strategy)
                .redirect(function(u) {
                    url = u;
                    done();
                })
                .req(() => {})
                .authenticate();
        });

        it('should be redirected', function() {
            expect(url).to.equal(
                'https://appleid.apple.com/auth/authorize?client_id=CLIENT_ID&response_type=code&response_mode=form_post'
            );
        });
    });

    describe('failure caused by user denying request', function() {
        const strategy = new AppleStrategy(
            {
                clientID: 'CLIENT_ID',
                teamID: 'TEAM_ID',
                keyID: 'KEY_ID',
                key: 'KEY'
            },
            () => {}
        );

        let info;

        before(function(done) {
            chai.passport
                .use(strategy)
                .fail(i => {
                    info = i;
                    done();
                })
                .req(function(req) {
                    req.body = {};
                    req.body.error = 'user_cancelled_authorize';
                })
                .authenticate();
        });

        it('should fail with info', function() {
            expect(info).to.not.be.undefined;
            expect(info.message).to.equal('User cancelled authorize');
        });
    });

    describe('error caused by invalid code sent to token endpoint', function() {
        const strategy = new AppleStrategy(
            {
                clientID: 'CLIENT_ID',
                teamID: 'TEAM_ID',
                keyID: 'KEY_ID',
                key: 'KEY'
            },
            () => {}
        );

        strategy._getOAuth2Client = () => {
            const oauth2 = new OAuth2();
            oauth2.getOAuthAccessToken = (code, options, callback) => {
                return callback({
                    statusCode: 400,
                    data: '{"error":"invalid_grant"}'
                });
            };
            return oauth2;
        };

        let err;

        before(function(done) {
            chai.passport
                .use(strategy)
                .error(function(e) {
                    err = e;
                    done();
                })
                .req(function(req) {
                    req.body = {};
                    req.body.code = 'SplxlOBeZQQYbYS6WxSbIA+ALT1';
                })
                .authenticate();
        });

        it('should error', function() {
            expect(err.constructor.name).to.equal('TokenError');
            expect(err.code).to.equal('invalid_grant');
        });
    });
});
