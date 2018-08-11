const path = require('path');
const rsaWrapper = {};
const fs = require('fs');
const NodeRSA = require('node-rsa');
const crypto = require('crypto');

// load keys from file
rsaWrapper.initLoadServerKeys = (basePath) => {
    rsaWrapper.serverPub = rsaWrapper.loadKey(basePath, 'server', 'public');
    rsaWrapper.serverPrivate = rsaWrapper.loadKey(basePath, 'server', 'private');
    rsaWrapper.clientPub = rsaWrapper.loadKey(basePath, 'client', 'private');
};

rsaWrapper.loadKey = (basePath, direction, type) => {
    return fs.readFileSync(path.resolve(basePath, 'keys', `${direction}.${type}.pem`));
};

rsaWrapper.generate = (direction) => {
    let key = new NodeRSA();
    key.generateKeyPair(2048, 65537);
    fs.writeFileSync(path.resolve(__dirname, 'keys', direction + '.private.pem'), key.exportKey('pkcs8-private-pem'));
    fs.writeFileSync(path.resolve(__dirname, 'keys', direction + '.public.pem'), key.exportKey('pkcs8-public-pem'));

    return true;
};

rsaWrapper.generateIfRequired = (direction) => {
    const exists = fs.existsSync(path.resolve(__dirname, 'keys', direction + '.private.pem'))
        && fs.existsSync(path.resolve(__dirname, 'keys', direction + '.public.pem'));

    return exists || this.generate(direction);
}

rsaWrapper.serverExampleEncrypt = () => {
    console.log('Server public encrypting');

    let enc = rsaWrapper.encrypt(rsaWrapper.serverPub, '{"sensor":"PIR","temperature":"44.77","humidity":"86.46","userid":"nakwarsi"}');
    console.log('Encrypted RSA string ', '\n', enc);
    let dec = rsaWrapper.decrypt(rsaWrapper.serverPrivate, enc);
    console.log('Decrypted RSA string ...');
    console.log(dec);
};

rsaWrapper.encrypt = (publicKey, message) => {
    let enc = crypto.publicEncrypt({
        key: publicKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING
    }, Buffer.from(message));

    return enc.toString('base64');
};

rsaWrapper.decrypt = (privateKey, message) => {
    console.log('crypto.RSA_PKCS1_OAEP_PADDING', crypto.RSA_PKCS1_OAEP_PADDING);
    let enc = crypto.privateDecrypt({
        key: privateKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING
    }, Buffer.from(message, 'base64'));

    return enc.toString();
};

module.exports = rsaWrapper;