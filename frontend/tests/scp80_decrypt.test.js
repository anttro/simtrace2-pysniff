const { test } = require('node:test');
const assert = require('node:assert');
const crypto = require('node:crypto');
const { loadSrc, extractFunc, extractSection } = require('./helpers.js');

const src = loadSrc();

// Assemble the client-side decryption machinery: DES/3DES core section,
// hex helpers, and the decryptSecured wrapper — all extracted verbatim
// from index.html so the tests exercise exactly what ships. Single
// direct eval: function declarations hoist into this module's scope.
const desSection = extractSection(src, '// ── DES / 3DES core', '// Decrypt a ciphered secured packet');
eval(
	extractFunc(src, 'hexToBytes') + '\n' +
	extractFunc(src, 'bytesToHex') + '\n' +
	desSection + '\n' +
	extractFunc(src, 'decryptSecured')
);

const b2h = b => Buffer.from(b).toString('hex').toUpperCase();

function encryptBlock(algo, key, iv, plaintext) {
	// node/OpenSSL 3 has no single DES — encrypt the reference via
	// des-ede3-cbc with K1=K2=K3 (≡ single DES). node's des-ede3-cbc
	// also requires a 24-byte key — expand 2-key (16B) to K1,K2,K1.
	let k;
	if (algo === 'des-cbc') k = Buffer.concat([key, key, key]);
	else if (algo === 'des-ede3-cbc' && key.length === 16) k = Buffer.concat([key, key.slice(0, 8)]);
	else k = key;
	const c = crypto.createCipheriv(algo === 'des-cbc' ? 'des-ede3-cbc' : algo, k, iv);
	c.setAutoPadding(false);  // SCP80 pads via PCNTR, not PKCS
	return Buffer.concat([c.update(plaintext), c.final()]);
}

// Build a fake secured-packet decode: cipher_block = 3DES/AES-CBC
// ciphertext over [CNTR(5) ‖ PCNTR(1) ‖ RC(8) ‖ data ‖ padding].
function makeSecured(algo, keyHex, cntrInt, dataHex) {
	const key = Buffer.from(keyHex, 'hex');
	const rc = Buffer.from('1122334455667788', 'hex');
	const data = Buffer.from(dataHex, 'hex');
	const block = algo === 'aes-128-cbc' ? 16 : 8;
	const iv = Buffer.alloc(block);
	const bodyLen = 5 + 1 + rc.length + data.length;
	const pad = block - (bodyLen % block);
	const pt = Buffer.concat([
		Buffer.from(cntrInt.toString(16).padStart(10, '0'), 'hex'),
		Buffer.from([pad]),
		rc,
		data,
		Buffer.alloc(pad),
	]);
	const ct = encryptBlock(algo, key, iv, pt);
	return {
		kic_raw: algo === 'aes-128-cbc' ? 0x02 : algo === 'des-cbc' ? 0x01 : 0x15,
		cipher_block: ct.toString('hex').toUpperCase(),
		rc_cc_ds: rc.toString('hex').toUpperCase(),
	};
}

test('decryptSecured: 3DES-CBC (2 keys) reveals real CNTR/PCNTR/RC/data', async () => {
	const keyHex = '0123456789ABCDEFFEDCBA9876543210';
	const sec = makeSecured('des-ede3-cbc', keyHex, 200, 'DEADBEEFCAFE');
	const r = await decryptSecured(sec, keyHex);
	assert.equal(b2h(r.cntr), '00000000C8');  // the real counter, 200
	assert.equal(r.pcntr, 4);                  // padding octets
	assert.equal(b2h(r.rc), '1122334455667788');
	assert.equal(b2h(r.data), 'DEADBEEFCAFE');
});

test('decryptSecured: 3DES-CBC (3 keys, 24-byte key)', async () => {
	const keyHex = '0123456789ABCDEFFEDCBA98765432100123456789ABCDEF';
	const sec = makeSecured('des-ede3-cbc', keyHex, 7, 'CAFE');
	const r = await decryptSecured(sec, keyHex);
	assert.equal(parseInt(b2h(r.cntr), 16), 7);
	assert.equal(b2h(r.data), 'CAFE');
});

test('decryptSecured: AES-CBC (128-bit key)', async () => {
	const keyHex = '000102030405060708090A0B0C0D0E0F';
	const sec = makeSecured('aes-128-cbc', keyHex, 1234, 'BEEF');
	const r = await decryptSecured(sec, keyHex);
	assert.equal(parseInt(b2h(r.cntr), 16), 1234);
	assert.equal(b2h(r.data), 'BEEF');
});

test('decryptSecured: wrong key detected via padding guard', async () => {
	const sec = makeSecured('des-ede3-cbc', '0123456789ABCDEFFEDCBA9876543210', 200, 'DEADBEEFCAFE');
	await assert.rejects(
		() => decryptSecured(sec, 'FFFFFFFFFEDCBA987654321001234567'),
		/wrong key|invalid padding|too short/
	);
});

test('decryptSecured: key length validation', async () => {
	const sec = makeSecured('des-ede3-cbc', '0123456789ABCDEFFEDCBA9876543210', 200, 'DEADBEEFCAFE');
	await assert.rejects(() => decryptSecured(sec, '0102'), /key must be/);
});

test('decryptSecured: unsupported algorithm nibble', async () => {
	const sec = makeSecured('des-ede3-cbc', '0123456789ABCDEFFEDCBA9876543210', 200, 'DEADBEEFCAFE');
	sec.kic_raw = 0x00;  // 'implicit' — cannot pick a cipher
	await assert.rejects(() => decryptSecured(sec, '0123456789ABCDEFFEDCBA9876543210'),
		/not supported/);
});

test('decryptSecured: DES-CBC single key (deprecated KIc 01)', async () => {
	const keyHex = '133457799BBCDFF1';
	const sec = makeSecured('des-cbc', keyHex, 42, '0123');
	const r = await decryptSecured(sec, keyHex);
	assert.equal(parseInt(b2h(r.cntr), 16), 42);
	assert.equal(b2h(r.data), '0123');
});
