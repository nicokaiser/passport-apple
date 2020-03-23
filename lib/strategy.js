const url = require('url');
const querystring = require('querystring');

const passport = require('passport-strategy');
const OAuth2 = require('oauth').OAuth2;
const jwt = require('jsonwebtoken');

const NullStateStore = require('./state/null');
const SessionStateStore = require('./state/session');
const AuthorizationError = require('./errors/authorizationerror');
const TokenError = require('./errors/tokenerror');
const InternalOAuthError = require('./errors/internaloautherror');

class AppleStrategy extends passport.Strategy {
    /**
     * @param {object} options
     * @param {string} options.clientID
     * @param {string} options.teamID
     * @param {string} options.keyID
     * @param {string} options.key
     * @param {string} [options.authorizationURL=https://appleid.apple.com/auth/authorize]
     * @param {string} [options.tokenURL=https://appleid.apple.com/auth/token]
     * @param {Array<string>} [options.scope]
     * @param {string} [options.sessionKey]
     * @param {boolean} [options.state]
     * @param {boolean} [options.passReqToCallback=false]
     * @param {string} [options.callbackURL]
     * @param {function} verify
     */
    constructor(options = {}, verify) {
        if (!verify) throw new TypeError('AppleStrategy requires a verify callback');
        if (!options.clientID) throw new TypeError('AppleStrategy requires a clientID option');
        if (!options.teamID) throw new TypeError('AppleStrategy requires a teamID option');
        if (!options.keyID) throw new TypeError('AppleStrategy requires a keyID option');
        if (!options.key) throw new TypeError('AppleStrategy requires a key option');

        super();
        this.name = 'apple';
        this._verify = verify;

        this._clientID = options.clientID;
        this._teamID = options.teamID;
        this._keyID = options.keyID;
        this._key = options.key;
        this._authorizationURL = options.authorizationURL || 'https://appleid.apple.com/auth/authorize';
        this._tokenURL = options.tokenURL || 'https://appleid.apple.com/auth/token';
        this._callbackURL = options.callbackURL;
        this._scope = options.scope;
        this._sessionKey = options.sessionKey || 'apple:' + url.parse(this._authorizationURL).hostname;

        if (options.state) {
            this._stateStore = new SessionStateStore({ key: this._sessionKey });
        } else {
            this._stateStore = new NullStateStore();
        }

        this._passReqToCallback = options.passReqToCallback;
    }

    /**
     * @param {http.IncomingMessage} req
     * @param {object} [options]
     * @param {string} [options.callbackURL]
     * @param {Array<string>} [options.scope]
     * @param {string} [options.state]
     */
    authenticate(req, options = {}) {
        if (req.body && req.body.error) {
            if (req.body.error === 'user_cancelled_authorize') {
                return this.fail({ message: 'User cancelled authorize' });
            } else {
                return this.error(new AuthorizationError(req.body.error, req.body.error));
            }
        }

        let callbackURL = options.callbackURL || this._callbackURL;

        if (req.body && req.body.code) {
            const state = req.body.state;
            try {
                this._stateStore.verify(req, state, (err, ok, state) => {
                    if (err) return this.error(err);
                    if (!ok) return this.fail(state, 403);

                    const code = req.body.code;

                    const params = { grant_type: 'authorization_code' };
                    if (callbackURL) params.redirect_uri = callbackURL;

                    const oauth2 = this._getOAuth2Client();

                    oauth2.getOAuthAccessToken(code, params, (err, accessToken, refreshToken, params) => {
                        if (err) return this.error(this._createOAuthError('Failed to obtain access token', err));

                        const idToken = params['id_token'];
                        if (!idToken) return this.error(new Error('ID Token not present in token response'));

                        const idTokenSegments = idToken.split('.');
                        let jwtClaims;

                        try {
                            const jwtClaimsStr = Buffer.from(idTokenSegments[1], 'base64').toString();
                            jwtClaims = JSON.parse(jwtClaimsStr);
                        } catch (ex) {
                            return this.error(ex);
                        }

                        const missing = ['iss', 'sub', 'aud', 'exp', 'iat'].filter((param) => !jwtClaims[param]);
                        if (missing.length)
                            return this.error(
                                new Error('id token is missing required parameter(s) - ' + missing.join(', '))
                            );

                        if (jwtClaims.iss !== 'https://appleid.apple.com')
                            return this.error(new Error('id token not issued by correct OpenID provider'));

                        if (jwtClaims.aud !== this._clientID)
                            return this.error(new Error('aud parameter does not include this client'));

                        if (jwtClaims.exp < Date.now() / 1000) return this.error(new Error('id token has expired'));

                        const profile = { id: jwtClaims.sub };

                        if (jwtClaims.email) profile.email = jwtClaims.email;

                        if (jwtClaims.email_verified) profile.emailVerified = jwtClaims.email_verified === 'true';

                        if (req.body.user) {
                            if (typeof req.body.user === 'object' && req.body.user.name) {
                                profile.name = req.body.user.name;
                            } else {
                                try {
                                    const user = JSON.parse(req.body.user);
                                    if (user && user.name) profile.name = user.name;
                                } catch (ex) {
                                    return this.error(ex);
                                }
                            }
                        }

                        const verified = (err, user, info) => {
                            if (err) return this.error(err);
                            if (!user) return this.fail(info);

                            info = info || {};
                            if (state) info.state = state;
                            this.success(user, info);
                        };

                        try {
                            if (this._passReqToCallback) {
                                this._verify(req, accessToken, refreshToken, profile, verified);
                            } else {
                                this._verify(accessToken, refreshToken, profile, verified);
                            }
                        } catch (ex) {
                            return this.error(ex);
                        }
                    });
                });
            } catch (ex) {
                return this.error(ex);
            }
        } else {
            const params = {
                client_id: this._clientID,
                response_type: 'code',
                response_mode: 'form_post'
            };
            if (callbackURL) params.redirect_uri = callbackURL;
            let scope = options.scope || this._scope;
            if (scope) {
                params.scope = scope.join(' ');
            }

            const state = options.state;
            if (state) {
                params.state = state;
                this.redirect(this._authorizationURL + '?' + querystring.stringify(params));
            } else {
                this._stateStore.store(req, (err, state) => {
                    if (err) return this.error(err);

                    if (state) params.state = state;
                    this.redirect(this._authorizationURL + '?' + querystring.stringify(params));
                });
            }
        }
    }

    /**
     * @param {string} body
     * @returns {Error}
     */
    parseErrorResponse(body) {
        const json = JSON.parse(body);
        if (json.error) {
            return new TokenError(json.error_description, json.error, json.error_uri);
        }
        return null;
    }

    /**
     * @returns {oauth2.OAuth2}
     */
    _getOAuth2Client() {
        const clientSecret = jwt.sign({}, this._key, {
            algorithm: 'ES256',
            keyid: this._keyID,
            expiresIn: '5 minutes',
            issuer: this._teamID,
            audience: 'https://appleid.apple.com',
            subject: this._clientID
        });

        return new OAuth2(this._clientID, clientSecret, '', this._authorizationURL, this._tokenURL);
    }

    /**
     * @param {string} message
     * @param {object|Error} err
     * @returns {Error}
     */
    _createOAuthError(message, err) {
        let e;
        if (err.statusCode && err.data) {
            try {
                e = this.parseErrorResponse(err.data);
            } catch (_) {
                // ignore
            }
        }
        if (!e) e = new InternalOAuthError(message, err);
        return e;
    }
}

module.exports = AppleStrategy;
