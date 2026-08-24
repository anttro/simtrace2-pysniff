// Shared helpers to extract functions/constants from the single-file
// frontend (index.html) so they can be unit-tested with node:test.
const fs = require('node:fs');
const path = require('node:path');

const INDEX_HTML = path.join(__dirname, '..', 'index.html');

function loadSrc() {
	return fs.readFileSync(INDEX_HTML, 'utf8');
}

// Extract a `function name(...) { ... }` by brace matching (includes a
// preceding `async` modifier when present).
function extractFunc(src, name) {
	const re = new RegExp('function\\s+' + name + '\\s*\\([^)]*\\)\\s*\\{');
	const m = re.exec(src);
	if (!m) throw new Error('function ' + name + ' not found');
	let start = m.index;
	if (src.slice(Math.max(0, start - 6), start) === 'async ') start -= 6;
	let i = m.index + m[0].length - 1;
	let depth = 0;
	for (; i < src.length; i++) {
		if (src[i] === '{') depth++;
		else if (src[i] === '}') {
			depth--;
			if (depth === 0) break;
		}
	}
	return src.slice(start, i + 1);
}

// Extract a `const NAME = { ... };` block by brace matching.
function extractConst(src, name) {
	const re = new RegExp('const\\s+' + name + '\\s*=\\s*\\{');
	const m = re.exec(src);
	if (!m) throw new Error('const ' + name + ' not found');
	let i = m.index + m[0].length - 1;
	let depth = 0;
	for (; i < src.length; i++) {
		if (src[i] === '{') depth++;
		else if (src[i] === '}') {
			depth--;
			if (depth === 0) break;
		}
	}
	return src.slice(m.index, i + 1) + ';';
}

// Extract a `// marker ... ` section up to the next marker comment.
function extractSection(src, startMarker, endMarker) {
	const i = src.indexOf(startMarker);
	if (i < 0) throw new Error('section not found: ' + startMarker);
	const j = endMarker ? src.indexOf(endMarker, i) : -1;
	return src.slice(i, j > i ? j : undefined);
}

module.exports = { loadSrc, extractFunc, extractConst, extractSection, INDEX_HTML };
