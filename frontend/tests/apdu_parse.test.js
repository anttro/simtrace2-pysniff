const { test } = require('node:test');
const assert = require('node:assert');
const { loadSrc, extractFunc, extractConst } = require('./helpers.js');

const src = loadSrc();
// Single direct eval with var substitutions: function/var declarations
// hoist into this module's scope (const would collide with itself).
eval(
	extractConst(src, 'PARSE_INS').replace(/^const /m, 'var ') + '\n' +
	extractFunc(src, 'describeP1P2') + '\n' +
	extractFunc(src, 'describeInstallDataLv') + '\n' +
	extractFunc(src, 'parseOneApdu') + '\n' +
	extractFunc(src, 'parseCompactApdus')
);

function child(tree, label) {
	return (tree.children || []).find(k => k.label === label);
}

test('PARSE_INS registry: SIM/USIM + GP commands', () => {
	assert.equal(PARSE_INS.A4.name, 'SELECT');
	assert.equal(PARSE_INS.B0.name, 'READ BINARY');
	assert.equal(PARSE_INS.B0.data, 'le');
	assert.equal(PARSE_INS.D6.name, 'UPDATE BINARY');
	assert.equal(PARSE_INS.D6.data, 'lc');
	assert.equal(PARSE_INS.E6.name, 'INSTALL');
});

test('parseOneApdu: SELECT by FID (case 3)', () => {
	const t = parseOneApdu('00A40000023F00');
	assert.equal(child(t, 'INS').desc, 'SELECT');
	assert.equal(child(t, 'P1').desc, 'by FID');
	const data = child(t, 'Data');
	assert.equal(data.hex, '3F00');
	const lc = child(t, 'Lc');
	assert.equal(lc.desc, 'Data length: 2');
});

test('parseOneApdu: READ BINARY (case 2, Le)', () => {
	const t = parseOneApdu('00B0000009');
	assert.equal(child(t, 'INS').desc, 'READ BINARY');
	const le = child(t, 'Le');
	assert.equal(le.hex, '09');
	assert.match(le.desc, /Expected length: 9/);
	assert.equal(child(t, 'Data'), undefined);
});

test('parseOneApdu: UPDATE BINARY (case 3)', () => {
	const t = parseOneApdu('00D600000CAABBCCDD1122334455667788');
	const data = child(t, 'Data');
	assert.equal(data.hex, 'AABBCCDD1122334455667788');
	const lc = child(t, 'Lc');
	assert.equal(lc.desc, 'Data length: 12');
});

test('parseOneApdu: GET DATA (P1P2 = tag, P3 = Le)', () => {
	const t = parseOneApdu('80CA9F1700');
	assert.equal(child(t, 'INS').desc, 'GET DATA');
	const le = child(t, 'Le');
	assert.equal(le.hex, '00');
});

test('parseOneApdu: lowercase input normalized', () => {
	const t = parseOneApdu('00a40000023f00');
	assert.equal(child(t, 'INS').desc, 'SELECT');
	assert.equal(child(t, 'Data').hex, '3F00');
});

test('parseCompactApdus: concatenated stream with implied CLA', () => {
	// SELECT 3F00 | SELECT 2FE2 (implied CLA) | UPDATE BINARY 12B (implied CLA) | trailing Le
	const stream = '00A40000023F00' + 'A40000022FE2' +
		'D600000CAABBCCDD1122334455667788' + '99';
	const apdus = parseCompactApdus(stream);
	const named = apdus.filter(a => a.label !== 'Unknown');
	assert.equal(named.length, 4);
	assert.equal(child(named[0], 'INS').desc, 'SELECT');
	assert.equal(named[1].label, 'APDU (implied CLA)');
	assert.equal(child(named[1], 'INS').desc, 'SELECT');
	assert.equal(named[2].label, 'APDU (implied CLA)');
	assert.equal(child(named[2], 'INS').desc, 'UPDATE BINARY');
	assert.equal(named[3].label, 'Le');
});

test('parseCompactApdus: unrecognized bytes degrade gracefully', () => {
	// Trailing 2 hex chars are interpreted as Le by design — no crash,
	// and the leading unrecognized bytes come back as Unknown entries.
	const apdus = parseCompactApdus('FFFFFF');
	assert.equal(apdus.length, 3);
	assert.equal(apdus[0].label, 'Unknown');
	assert.equal(apdus[1].label, 'Unknown');
	assert.equal(apdus[2].label, 'Le');
});
