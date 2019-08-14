const uid = require('uid2');

class SessionStore {
    /**
     * @param {object} options
     * @param {string} options.key
     */
    constructor(options) {
        if (!options.key) throw new TypeError('Session-based state store requires a session key');
        this._key = options.key;
    }

    /**
     * @param {object} req
     * @param {function} callback
     */
    store(req, callback) {
        if (!req.session)
            return callback(
                new Error(
                    'Apple authentication requires session support when using state. Did you forget to use express-session middleware?'
                )
            );

        const key = this._key;
        const state = uid(24);
        if (!req.session[key]) req.session[key] = {};
        req.session[key].state = state;
        callback(null, state);
    }

    /**
     * @param {object} req
     * @param {string} providedState
     * @param {function} callback
     */
    verify(req, providedState, callback) {
        if (!req.session)
            return callback(
                new Error(
                    'Apple authentication requires session support when using state. Did you forget to use express-session middleware?'
                )
            );

        const key = this._key;
        if (!req.session[key])
            return callback(null, false, { message: 'Unable to verify authorization request state.' });

        const state = req.session[key].state;
        if (!state) return callback(null, false, { message: 'Unable to verify authorization request state.' });

        delete req.session[key].state;
        if (Object.keys(req.session[key]).length === 0) delete req.session[key];

        if (state !== providedState) return callback(null, false, { message: 'Invalid authorization request state.' });

        return callback(null, true);
    }
}

module.exports = SessionStore;
