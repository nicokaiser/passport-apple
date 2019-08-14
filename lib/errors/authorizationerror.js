class AuthorizationError extends Error {
    /**
     * @param {string} [message]
     * @param {string} [code]
     * @param {string} [uri]
     * @param {number} [status]
     */
    constructor(message, code, uri, status) {
        if (!status) {
            switch (code) {
                case 'access_denied':
                    status = 403;
                    break;
                case 'server_error':
                    status = 502;
                    break;
                case 'temporarily_unavailable':
                    status = 503;
                    break;
            }
        }

        super(message);
        Error.captureStackTrace(this, this.constructor);
        this.name = 'AuthorizationError';
        this.message = message;
        this.code = code || 'server_error';
        this.uri = uri;
        this.status = status || 500;
    }
}

module.exports = AuthorizationError;
