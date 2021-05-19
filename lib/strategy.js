const url = require('url');
const querystring = require('querystring');

const passport = require('passport-strategy');
const OAuth2 = require('oauth').OAuth2;
const jwt = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');

const NullStateStore = require('./state/null');
const SessionStateStore = require('./state/session');
const AuthorizationError = require('./errors/authorizationerror');
const TokenError = require('./errors/tokenerror');
const InternalOAuthError = require('./errors/internaloautherror');

const jwks_client = jwksClient({
    strictSsl: true,
    rateLimit: true,
    cache: true,
    cacheMaxEntries: 100,
    cacheMaxAge: 1000 * 60 * 60 * 24,
    jwksUri: 'https://appleid.apple.com/auth/keys'
});

const getAppleJWKSKey = (header, callback) => {
    jwks_client
        .getSigningKey(header.kid)
        .then((key) => {
            callback(null, key && (key.publicKey || key.rsaPublicKey));
        })
        .catch((err) => callback(err));
};

// the client secret for a given key is a signed JWT which is allowed to live
// for a relatively long time, so cache and re-use these to avoid unnecessary
// signature operations:
const clientSecretCache = new Map();

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
        this._clientSecretExpiry = options.clientSecretExpiry || '5 minutes';
        this._verifyNonce = options.verifyNonce;

        if (options.state) {
            this._stateStore = new SessionStateStore({ key: this._sessionKey });
        } else {
            this._stateStore = new NullStateStore();
        }

        this._passReqToCallback = options.passReqToCallback;
    }

    verifyNonce(req, nonce_supported, nonce, callback) {
        if (this._verifyNonce && nonce_supported) {
            return this._verifyNonce(req, nonce, callback);
        } else {
            return callback(null, true);
        }
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

                        const verifyOpts = {
                            audience: this._clientID,
                            issuer: 'https://appleid.apple.com',
                            algorithms: ['RS256']
                        };
                        jwt.verify(idToken, getAppleJWKSKey, verifyOpts, (err, jwtClaims) => {
                            if (err) {
                                return this.error(err);
                            }

                            this.verifyNonce(req, jwtClaims.nonce_supported, jwtClaims.nonce, (err, ok) => {
                                if (err) return this.error(err);
                                if (!ok) return this.fail({ message: 'invalid nonce' });

                                const profile = { id: jwtClaims.sub, provider: 'apple' };

                                if (jwtClaims.email) {
                                    profile.email = jwtClaims.email;
                                }

                                if (jwtClaims.email_verified) {
                                    profile.emailVerified = jwtClaims.email_verified === 'true';
                                }

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

            if (options.nonce) {
                params.nonce = options.nonce;
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
     * @returns {jwt|string} signed jwt client secret
     */
    _getClientSecret() {
        // if our current secret has expired (with a few seconds grace), or
        // hasn't been generated yet, regenerate it:
        const existing = clientSecretCache.get(this._keyID);
        if (!existing || jwt.decode(existing).exp < Date.now() / 1000 + 5) {
            clientSecretCache.set(
                this._keyID,
                jwt.sign({}, this._key, {
                    algorithm: 'ES256',
                    keyid: this._keyID,
                    expiresIn: this._clientSecretExpiry,
                    issuer: this._teamID,
                    audience: 'https://appleid.apple.com',
                    subject: this._clientID
                })
            );
        }
        return clientSecretCache.get(this._keyID);
    }

    /**
     * @returns {oauth2.OAuth2}
     */
    _getOAuth2Client() {
        return new OAuth2(this._clientID, this._getClientSecret(), '', this._authorizationURL, this._tokenURL);
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
