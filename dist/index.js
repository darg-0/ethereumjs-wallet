"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.thirdparty = exports.hdkey = void 0;
const util_1 = require("@ethereumjs/util");
const base_1 = require("@scure/base");
const aes = require("ethereum-cryptography/aes");
const keccak_1 = require("ethereum-cryptography/keccak");
const random_1 = require("ethereum-cryptography/random");
const pbkdf2_1 = require("ethereum-cryptography/pbkdf2");
const scrypt_1 = require("ethereum-cryptography/scrypt");
const sha256_1 = require("ethereum-cryptography/sha256");
var hdkey_1 = require("./hdkey");
Object.defineProperty(exports, "hdkey", { enumerable: true, get: function () { return hdkey_1.default; } });
var thirdparty_1 = require("./thirdparty");
Object.defineProperty(exports, "thirdparty", { enumerable: true, get: function () { return thirdparty_1.default; } });
const uuidv4 = require('uuid').v4;
const bs58check = (0, base_1.base58check)(sha256_1.sha256);
function randomBytes(num) {
    return Buffer.from((0, random_1.getRandomBytesSync)(num));
}
function scryptV1(password, salt, kdfparams) {
    const { N, P, R, DkLen } = kdfparams;
    return (0, scrypt_1.scrypt)(password, salt, N, P, R, DkLen);
}
function scryptV3(password, kdfparams) {
    const { salt, n, p, r, dklen } = kdfparams;
    return (0, scrypt_1.scrypt)(Buffer.from(password), salt, n, p, r, dklen);
}
function scryptV3Out(password, kdfparams) {
    const { salt, n, p, r, dklen } = kdfparams;
    return (0, scrypt_1.scrypt)(Buffer.from(password), Buffer.from(salt, 'hex'), n, p, r, dklen);
}
// helpers
function keyExists(k) {
    return k !== undefined && k !== null;
}
function validateHexString(paramName, str, length) {
    if (str.toLowerCase().startsWith('0x')) {
        str = str.slice(2);
    }
    if (!str && !length) {
        return str;
    }
    if (length % 2) {
        throw new Error(`Invalid length argument, must be an even number`);
    }
    if (typeof length === 'number' && str.length !== length) {
        throw new Error(`Invalid ${paramName}, string must be ${length} hex characters`);
    }
    if (!/^([0-9a-f]{2})+$/i.test(str)) {
        const howMany = typeof length === 'number' ? length : 'empty or a non-zero even number of';
        throw new Error(`Invalid ${paramName}, string must be ${howMany} hex characters`);
    }
    return str;
}
function validateBuffer(paramName, buff, length) {
    if (!Buffer.isBuffer(buff)) {
        const howManyHex = typeof length === 'number' ? `${length * 2}` : 'empty or a non-zero even number of';
        const howManyBytes = typeof length === 'number' ? ` (${length} bytes)` : '';
        throw new Error(`Invalid ${paramName}, must be a string (${howManyHex} hex characters) or buffer${howManyBytes}`);
    }
    if (typeof length === 'number' && buff.length !== length) {
        throw new Error(`Invalid ${paramName}, buffer must be ${length} bytes`);
    }
    return buff;
}
function mergeToV3ParamsWithDefaults(params) {
    const v3Defaults = {
        cipher: 'aes-128-ctr',
        kdf: 'scrypt',
        salt: randomBytes(32),
        iv: randomBytes(16),
        uuid: randomBytes(16),
        dklen: 32,
        c: 262144,
        n: 262144,
        r: 8,
        p: 1,
    };
    if (!params) {
        return v3Defaults;
    }
    if (typeof params.salt === 'string') {
        params.salt = Buffer.from(validateHexString('salt', params.salt), 'hex');
    }
    if (typeof params.iv === 'string') {
        params.iv = Buffer.from(validateHexString('iv', params.iv, 32), 'hex');
    }
    if (typeof params.uuid === 'string') {
        params.uuid = Buffer.from(validateHexString('uuid', params.uuid, 32), 'hex');
    }
    if (params.salt) {
        validateBuffer('salt', params.salt);
    }
    if (params.iv) {
        validateBuffer('iv', params.iv, 16);
    }
    if (params.uuid) {
        validateBuffer('uuid', params.uuid, 16);
    }
    return {
        ...v3Defaults,
        ...params,
    };
}
function kdfParamsForPBKDF(opts) {
    return {
        dklen: opts.dklen,
        salt: opts.salt,
        c: opts.c,
        prf: 'hmac-sha256',
    };
}
function kdfParamsForScrypt(opts) {
    return {
        dklen: opts.dklen,
        salt: opts.salt,
        n: opts.n,
        p: opts.p,
        r: opts.r,
    };
}
// wallet implementation
class Wallet {
    constructor(privateKey, publicKey = undefined) {
        this.privateKey = privateKey;
        this.publicKey = publicKey;
        if (privateKey && publicKey) {
            throw new Error('Cannot supply both a private and a public key to the constructor');
        }
        if (privateKey && !(0, util_1.isValidPrivate)(privateKey)) {
            throw new Error('Private key does not satisfy the curve requirements (ie. it is invalid)');
        }
        if (publicKey && !(0, util_1.isValidPublic)(publicKey)) {
            throw new Error('Invalid public key');
        }
    }
    // static methods
    /**
     * Create an instance based on a new random key.
     *
     * @param icapDirect setting this to `true` will generate an address suitable for the `ICAP Direct mode`
     */
    static generate(icapDirect = false) {
        if (icapDirect) {
            const max = BigInt('0x088f924eeceeda7fe92e1f5b0fffffffffffffff');
            for (;;) {
                const privateKey = randomBytes(32);
                const hex = (0, util_1.privateToAddress)(privateKey).toString('hex');
                if (BigInt('0x' + hex) <= max) {
                    return new Wallet(privateKey);
                }
            }
        }
        else {
            return new Wallet(randomBytes(32));
        }
    }
    /**
     * Create an instance where the address is valid against the supplied pattern (**this will be very slow**)
     */
    static generateVanityAddress(pattern) {
        if (!(pattern instanceof RegExp)) {
            pattern = new RegExp(pattern);
        }
        for (;;) {
            const privateKey = randomBytes(32);
            const address = (0, util_1.privateToAddress)(privateKey);
            if (pattern.test(address.toString('hex'))) {
                return new Wallet(privateKey);
            }
        }
    }
    /**
     * Create an instance based on a public key (certain methods will not be available)
     *
     * This method only accepts uncompressed Ethereum-style public keys, unless
     * the `nonStrict` flag is set to true.
     */
    static fromPublicKey(publicKey, nonStrict = false) {
        if (nonStrict) {
            publicKey = (0, util_1.importPublic)(publicKey);
        }
        return new Wallet(undefined, publicKey);
    }
    /**
     * Create an instance based on a BIP32 extended public key (xpub)
     */
    static fromExtendedPublicKey(extendedPublicKey) {
        if (extendedPublicKey.slice(0, 4) !== 'xpub') {
            throw new Error('Not an extended public key');
        }
        const publicKey = bs58check.decode(extendedPublicKey).slice(45);
        // Convert to an Ethereum public key
        return Wallet.fromPublicKey(Buffer.from(publicKey), true);
    }
    /**
     * Create an instance based on a raw private key
     */
    static fromPrivateKey(privateKey) {
        return new Wallet(privateKey);
    }
    /**
     * Create an instance based on a BIP32 extended private key (xprv)
     */
    static fromExtendedPrivateKey(extendedPrivateKey) {
        if (extendedPrivateKey.slice(0, 4) !== 'xprv') {
            throw new Error('Not an extended private key');
        }
        const tmp = bs58check.decode(extendedPrivateKey);
        if (tmp[45] !== 0) {
            throw new Error('Invalid extended private key');
        }
        return Wallet.fromPrivateKey(Buffer.from(tmp.slice(46)));
    }
    /**
     * Import a wallet (Version 1 of the Ethereum wallet format).
     *
     * @param input A JSON serialized string, or an object representing V1 Keystore.
     * @param password The keystore password.
     */
    static async fromV1(input, password) {
        const json = typeof input === 'object' ? input : JSON.parse(input);
        if (json.Version !== '1') {
            throw new Error('Not a V1 Wallet');
        }
        if (json.Crypto.KeyHeader.Kdf !== 'scrypt') {
            throw new Error('Unsupported key derivation scheme');
        }
        const kdfparams = json.Crypto.KeyHeader.KdfParams;
        const salt = Buffer.from(json.Crypto.Salt, 'hex');
        const derivedKey = await scryptV1(Buffer.from(password), salt, kdfparams);
        const ciphertext = Buffer.from(json.Crypto.CipherText, 'hex');
        const mac = (0, keccak_1.keccak256)(Buffer.concat([derivedKey.slice(16, 32), ciphertext]));
        if (Buffer.from(mac).toString('hex') !== json.Crypto.MAC) {
            throw new Error('Key derivation failed - possibly wrong passphrase');
        }
        const seed = await aes.decrypt(ciphertext, (0, keccak_1.keccak256)(derivedKey.slice(0, 16)).slice(0, 16), Buffer.from(json.Crypto.IV, 'hex'), 'aes-128-cbc');
        return new Wallet(Buffer.from(seed));
    }
    /**
     * Import a wallet (Version 3 of the Ethereum wallet format). Set `nonStrict` true to accept files with mixed-caps.
     *
     * @param input A JSON serialized string, or an object representing V3 Keystore.
     * @param password The keystore password.
     */
    static async fromV3(input, password, nonStrict = false) {
        const json = typeof input === 'object' ? input : JSON.parse(nonStrict ? input.toLowerCase() : input);
        if (json.version !== 3) {
            throw new Error('Not a V3 wallet');
        }
        let derivedKey, kdfparams;
        if (json.crypto.kdf === 'scrypt') {
            kdfparams = json.crypto.kdfparams;
            // FIXME: support progress reporting callback
            derivedKey = await scryptV3Out(password, kdfparams);
        }
        else if (json.crypto.kdf === 'pbkdf2') {
            kdfparams = json.crypto.kdfparams;
            if (kdfparams.prf !== 'hmac-sha256') {
                throw new Error('Unsupported parameters to PBKDF2');
            }
            derivedKey = await (0, pbkdf2_1.pbkdf2)(Buffer.from(password), Buffer.from(kdfparams.salt, 'hex'), kdfparams.c, kdfparams.dklen, 'sha256');
        }
        else {
            throw new Error('Unsupported key derivation scheme');
        }
        const ciphertext = Buffer.from(json.crypto.ciphertext, 'hex');
        const mac = (0, keccak_1.keccak256)(Buffer.concat([Buffer.from(derivedKey.slice(16, 32)), ciphertext]));
        if (Buffer.from(mac).toString('hex') !== json.crypto.mac) {
            throw new Error('Key derivation failed - possibly wrong passphrase');
        }
        const seed = await aes.decrypt(ciphertext, derivedKey.slice(0, 16), Buffer.from(json.crypto.cipherparams.iv, 'hex'), json.crypto.cipher);
        return new Wallet(Buffer.from(seed));
    }
    /*
     * Import an Ethereum Pre Sale wallet.
     * Based on https://github.com/ethereum/pyethsaletool/blob/master/pyethsaletool.py
     * JSON fields: encseed, ethaddr, btcaddr, email
     *
     * @param input A JSON serialized string, or an object representing EthSale Keystore.
     * @param password The keystore password.
     */
    static async fromEthSale(input, password) {
        const json = typeof input === 'object' ? input : JSON.parse(input);
        const encseed = Uint8Array.from(Buffer.from(json.encseed, 'hex'));
        // key derivation
        const pass = Buffer.from(password, 'utf8');
        const derivedKey = (await (0, pbkdf2_1.pbkdf2)(pass, pass, 2000, 32, 'sha256')).slice(0, 16);
        // seed decoding (IV is first 16 bytes)
        // NOTE: crypto (derived from openssl) when used with aes-*-cbc will handle PKCS#7 padding internally
        //       see also http://stackoverflow.com/a/31614770/4964819
        const seed = await aes.decrypt(encseed.slice(16), derivedKey, encseed.slice(0, 16), 'aes-128-cbc', true);
        const wallet = new Wallet(Buffer.from((0, keccak_1.keccak256)(seed)));
        if (wallet.getAddress().toString('hex') !== json.ethaddr) {
            throw new Error('Decoded key mismatch - possibly wrong passphrase');
        }
        return wallet;
    }
    // private getters
    /**
     * Returns the wallet's public key.
     */
    get pubKey() {
        if (!keyExists(this.publicKey)) {
            this.publicKey = (0, util_1.privateToPublic)(this.privateKey);
        }
        return this.publicKey;
    }
    /**
     * Returns the wallet's private key.
     */
    get privKey() {
        if (!keyExists(this.privateKey)) {
            throw new Error('This is a public key only wallet');
        }
        return this.privateKey;
    }
    // public instance methods
    /**
     * Returns the wallet's private key.
     *
     */
    // tslint:disable-next-line
    getPrivateKey() {
        return this.privKey;
    }
    getPrivateKeyString() {
        return (0, util_1.bufferToHex)(this.privKey);
    }
    /**
     * Returns the wallet's public key.
     */
    // tslint:disable-next-line
    getPublicKey() {
        return this.pubKey;
    }
    /**
     * Returns the wallet's public key as a "0x" prefixed hex string
     */
    getPublicKeyString() {
        return (0, util_1.bufferToHex)(this.getPublicKey());
    }
    /**
     * Returns the wallet's address.
     */
    getAddress() {
        return (0, util_1.publicToAddress)(this.pubKey);
    }
    /**
     * Returns the wallet's address as a "0x" prefixed hex string
     */
    getAddressString() {
        return (0, util_1.bufferToHex)(this.getAddress());
    }
    /**
     * Returns the wallet's private key as a "0x" prefixed hex string checksummed
     * according to [EIP 55](https://github.com/ethereum/EIPs/issues/55).
     */
    getChecksumAddressString() {
        return (0, util_1.toChecksumAddress)(this.getAddressString());
    }
    /**
     * Returns an Etherem Version 3 Keystore Format object representing the wallet
     *
     * @param password The password used to encrypt the Keystore.
     * @param opts The options for the keystore. See [its spec](https://github.com/ethereum/wiki/wiki/Web3-Secret-Storage-Definition) for more info.
     */
    async toV3(password, opts) {
        if (!keyExists(this.privateKey)) {
            throw new Error('This is a public key only wallet');
        }
        const v3Params = mergeToV3ParamsWithDefaults(opts);
        let kdfParams;
        let derivedKey;
        switch (v3Params.kdf) {
            case "pbkdf2" /* KDFFunctions.PBKDF */:
                kdfParams = kdfParamsForPBKDF(v3Params);
                derivedKey = await (0, pbkdf2_1.pbkdf2)(Buffer.from(password), kdfParams.salt, kdfParams.c, kdfParams.dklen, 'sha256');
                break;
            case "scrypt" /* KDFFunctions.Scrypt */:
                kdfParams = kdfParamsForScrypt(v3Params);
                // FIXME: support progress reporting callback
                derivedKey = await scryptV3(password, kdfParams);
                break;
            default:
                throw new Error('Unsupported kdf');
        }
        const ciphertext = await aes.encrypt(this.privKey, derivedKey.slice(0, 16), v3Params.iv, v3Params.cipher, false);
        const mac = (0, keccak_1.keccak256)(Buffer.concat([Buffer.from(derivedKey.slice(16, 32)), Buffer.from(ciphertext)]));
        return {
            version: 3,
            id: uuidv4({ random: v3Params.uuid }),
            // @ts-ignore - the official V3 keystore spec omits the address key
            address: this.getAddress().toString('hex'),
            crypto: {
                ciphertext: Buffer.from(ciphertext).toString('hex'),
                cipherparams: { iv: v3Params.iv.toString('hex') },
                cipher: v3Params.cipher,
                kdf: v3Params.kdf,
                kdfparams: {
                    ...kdfParams,
                    salt: kdfParams.salt.toString('hex'),
                },
                mac: Buffer.from(mac).toString('hex'),
            },
        };
    }
    /**
     * Return the suggested filename for V3 keystores.
     */
    getV3Filename(timestamp) {
        /*
         * We want a timestamp like 2016-03-15T17-11-33.007598288Z. Date formatting
         * is a pain in Javascript, everbody knows that. We could use moment.js,
         * but decide to do it manually in order to save space.
         *
         * toJSON() returns a pretty close version, so let's use it. It is not UTC though,
         * but does it really matter?
         *
         * Alternative manual way with padding and Date fields: http://stackoverflow.com/a/7244288/4964819
         *
         */
        const ts = timestamp ? new Date(timestamp) : new Date();
        return ['UTC--', ts.toJSON().replace(/:/g, '-'), '--', this.getAddress().toString('hex')].join('');
    }
    async toV3String(password, opts) {
        return JSON.stringify(await this.toV3(password, opts));
    }
    /**
     * Verify the publicKey, privateKey pair
     *
     * @param publicKey the public key to verify against the private key of the wallet
     */
    verifyPublicKey(publicKey) {
        return (0, util_1.privateToPublic)(this.privateKey).equals(publicKey);
    }
}
exports.default = Wallet;
//# sourceMappingURL=index.js.map