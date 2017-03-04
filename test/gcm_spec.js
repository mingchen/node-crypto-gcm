'use strict';

const should = require('should');

const GCM = require('..').GCM;

describe('GCM crypto', function () {
    it('#urlsafe_escape', function () {
        GCM.urlsafe_escape('abc/def/xyz+123+789/==').should.equal('abc_def_xyz.123.789_--');
    });

    it('#urlsafe_usescape', function () {
        GCM.urlsafe_unescape('abc_def_xyz.123.789_--').should.equal('abc/def/xyz+123+789/==');
    });

    describe('#constructor', function() {
        it('should throw with unknown encryption algorithm', function () {
            should.throws(() => new GCM('t86GvATWQV6S', {algorithm: 'aes-256-gcm-abc'}), Error);
        });

        it('should throw with unknown encryption algorithm', function () {
            should.doesNotThrow(() => new GCM('t86GvATWQV6S', {algorithm: 'aes-256-gcm'}));
        });
    });

    describe('#encrypt', function () {
        it('should return null encrypt with unknown digest algorithm', function () {
            let plainText = 'To be or not to be, that is the question.';
            should.not.exist(new GCM('t86GvATWQV6S', {pbkdf2Digest: 'shax'}).encrypt(plainText));
        });
    });


    describe('#decrypt', function () {
        it('decrypt short data return null', function () {
            let gcm = new GCM('password');
            should.not.exist(gcm.decrypt('asdfds--'));     // return null if decrypt failed.
        });

        it('decrypt with in-correct password', function () {
            let plainText = 'To be or not to be, that is the question.';
            let gcm1 = new GCM('password');

            let output = gcm1.encrypt(plainText);

            let gcm2 = new GCM('wrong password');
            should.not.exist(gcm2.decrypt(output));     // return null if decrypt failed.
        });
    });

    describe('#encrypt/decrypt', function () {
        it('encrypt/decrypt with correct password', function () {
            let plainText = 'To be or not to be, that is the question.';
            let gcm = new GCM('t86GvATWQV6S');

            let output = gcm.encrypt(plainText);

            gcm.decrypt(output).should.equal(plainText);
        });

        it('encrypt/decrypt using aes-128-gcm with correct password', function () {
            let plainText = 'To be or not to be, that is the question.';
            let gcm = new GCM('t86GvATWQV6S', {algorithm: 'aes-128-gcm'});

            let output = gcm.encrypt(plainText);

            gcm.decrypt(output).should.equal(plainText);
        });

        it('encrypt/decrypt using aes-192-gcm with correct password', function () {
            let plainText = 'To be or not to be, that is the question.';
            let gcm = new GCM('t86GvATWQV6S', {algorithm: 'aes-192-gcm'});

            let output = gcm.encrypt(plainText);

            gcm.decrypt(output).should.equal(plainText);
        });

        it('encrypt/decrypt using aes-256-gcm with correct password', function () {
            let plainText = 'To be or not to be, that is the question.';
            let gcm = new GCM('t86GvATWQV6S', {algorithm: 'aes-256-gcm'});

            let output = gcm.encrypt(plainText);

            gcm.decrypt(output).should.equal(plainText);
        });

        it('encrypt/decrypt with correct password, custom salt rounds and digest', function () {
            let plainText = 'To be or not to be, that is the question.';
            let gcm = new GCM('t86GvATWQV6S', {algorithm: 'aes-256-gcm', saltLenght: 123, pbkdf2Rounds: 1000, pbkdf2Digest: 'sha256'});

            let output = gcm.encrypt(plainText);

            gcm.decrypt(output).should.equal(plainText);
        });

    });



});
