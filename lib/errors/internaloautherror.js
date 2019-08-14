class InternalOAuthError extends Error {
    /**
     * @param {string} [message]
     * @param {object|Error} [err]
     */
    constructor(message, err) {
        super(message);
        Error.captureStackTrace(this, this.constructor);
        this.name = 'InternalOAuthError';
        this.message = message;
        this.oauthError = err;
    }

    /**
     * @returns {string}
     */
    toString() {
        let m = this.name;
        if (this.message) m += ': ' + this.message;

        if (this.oauthError) {
            if (this.oauthError instanceof Error) {
                m = this.oauthError.toString();
            } else if (this.oauthError.statusCode && this.oauthError.data) {
                m += ' (status: ' + this.oauthError.statusCode + ' data: ' + this.oauthError.data + ')';
            }
        }
        return m;
    }
}

module.exports = InternalOAuthError;
