class NullStore {
    store(req, cb) {
        cb();
    }

    verify(req, providedState, cb) {
        cb(null, true);
    }
}

module.exports = NullStore;
