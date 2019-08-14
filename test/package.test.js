/* global describe, it */

const { expect } = require('chai');

var strategy = require('..');

describe('passport-apple', function() {
    it('should export Strategy constructor as module', function() {
        expect(strategy).to.be.a('function');
        expect(strategy).to.equal(strategy.Strategy);
    });

    it('should export Strategy constructor', function() {
        expect(strategy.Strategy).to.be.a('function');
    });
});
