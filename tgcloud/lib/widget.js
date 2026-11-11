export function runWidget(record) {
  const element = (id) => document.getElementById(id);
  const telegram = window.TelegramWidget;
  const code = element('code');
  const remaining = element('remaining');
  const bar = element('bar');
  const copy = element('copy');
  const hint = element('hint');
  let key;
  let previousCounter;
  let previousCode;
  const shared = !record;

  function valid(value) {
    return value && (!shared || (value.version === 2 && value.T0 === 0)) && typeof value.name === 'string' && Array.from(value.name).length >= 1 && Array.from(value.name).length <= 80 && !/[\u0000-\u001f\u007f-\u009f\u2028\u2029]/.test(value.name) && typeof value.secret === 'string' && ['SHA1', 'SHA256', 'SHA512'].includes(value.algorithm) && [6, 8].includes(value.digits) && Number.isInteger(value.period) && value.period >= 1 && value.period <= 3600 && (value.T0 === undefined || value.T0 === 0);
  }

  function load() {
    try { record = JSON.parse(telegram.chatData); } catch { record = null; }
    key = undefined;
    previousCode = undefined;
    previousCounter = undefined;
  }
  if (shared) load();

  function decode(secret) {
    if (!/^[A-Z2-7]+$/.test(secret)) throw Error();
    let accumulator = 0;
    let bits = 0;
    const bytes = [];
    for (const character of secret) {
      accumulator = accumulator * 32 + 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'.indexOf(character);
      bits += 5;
      if (bits >= 8) {
        bits -= 8;
        bytes.push(Math.floor(accumulator / 2 ** bits));
        accumulator %= 2 ** bits;
      }
    }
    if (bits >= 5 || accumulator !== 0 || bytes.length < 10 || bytes.length > 64) throw Error();
    return bytes;
  }

  function rotate(value, amount) {
    return (value << amount) | (value >>> (32 - amount));
  }

  function sha1(input) {
    const bytes = input.slice();
    const bitLength = bytes.length * 8;
    bytes.push(128);
    while (bytes.length % 64 !== 56) bytes.push(0);
    for (let shift = 7; shift >= 0; shift--) bytes.push(Math.floor(bitLength / 256 ** shift) % 256);
    const hash = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0];
    for (let block = 0; block < bytes.length; block += 64) {
      const words = [];
      for (let index = 0; index < 16; index++) {
        const offset = block + index * 4;
        words[index] = (bytes[offset] << 24) | (bytes[offset + 1] << 16) | (bytes[offset + 2] << 8) | bytes[offset + 3];
      }
      for (let index = 16; index < 80; index++) words[index] = rotate(words[index - 3] ^ words[index - 8] ^ words[index - 14] ^ words[index - 16], 1);
      let first = hash[0];
      let second = hash[1];
      let third = hash[2];
      let fourth = hash[3];
      let fifth = hash[4];
      for (let round = 0; round < 80; round++) {
        let mixed;
        let constant;
        if (round < 20) {
          mixed = (second & third) | (~second & fourth);
          constant = 0x5a827999;
        } else if (round < 40) {
          mixed = second ^ third ^ fourth;
          constant = 0x6ed9eba1;
        } else if (round < 60) {
          mixed = (second & third) | (second & fourth) | (third & fourth);
          constant = 0x8f1bbcdc;
        } else {
          mixed = second ^ third ^ fourth;
          constant = 0xca62c1d6;
        }
        const next = (rotate(first, 5) + mixed + fifth + constant + words[round]) | 0;
        fifth = fourth;
        fourth = third;
        third = rotate(second, 30);
        second = first;
        first = next;
      }
      hash[0] = (hash[0] + first) | 0;
      hash[1] = (hash[1] + second) | 0;
      hash[2] = (hash[2] + third) | 0;
      hash[3] = (hash[3] + fourth) | 0;
      hash[4] = (hash[4] + fifth) | 0;
    }
    const result = [];
    for (const word of hash) {
      for (let shift = 24; shift >= 0; shift -= 8) result.push((word >>> shift) & 255);
    }
    return result;
  }

  function sha2(input) {
    const wide = record.algorithm === 'SHA512';
    const width = wide ? 64n : 32n;
    const mask = (1n << width) - 1n;
    const blockSize = wide ? 128 : 64;
    const constants = '428a2f98d728ae22 7137449123ef65cd b5c0fbcfec4d3b2f e9b5dba58189dbbc 3956c25bf348b538 59f111f1b605d019 923f82a4af194f9b ab1c5ed5da6d8118 d807aa98a3030242 12835b0145706fbe 243185be4ee4b28c 550c7dc3d5ffb4e2 72be5d74f27b896f 80deb1fe3b1696b1 9bdc06a725c71235 c19bf174cf692694 e49b69c19ef14ad2 efbe4786384f25e3 0fc19dc68b8cd5b5 240ca1cc77ac9c65 2de92c6f592b0275 4a7484aa6ea6e483 5cb0a9dcbd41fbd4 76f988da831153b5 983e5152ee66dfab a831c66d2db43210 b00327c898fb213f bf597fc7beef0ee4 c6e00bf33da88fc2 d5a79147930aa725 06ca6351e003826f 142929670a0e6e70 27b70a8546d22ffc 2e1b21385c26c926 4d2c6dfc5ac42aed 53380d139d95b3df 650a73548baf63de 766a0abb3c77b2a8 81c2c92e47edaee6 92722c851482353b a2bfe8a14cf10364 a81a664bbc423001 c24b8b70d0f89791 c76c51a30654be30 d192e819d6ef5218 d69906245565a910 f40e35855771202a 106aa07032bbd1b8 19a4c116b8d2d0c8 1e376c085141ab53 2748774cdf8eeb99 34b0bcb5e19b48a8 391c0cb3c5c95a63 4ed8aa4ae3418acb 5b9cca4f7763e373 682e6ff3d6b2b8a3 748f82ee5defb2fc 78a5636f43172f60 84c87814a1f0ab72 8cc702081a6439ec 90befffa23631e28 a4506cebde82bde9 bef9a3f7b2c67915 c67178f2e372532b ca273eceea26619c d186b8c721c0c207 eada7dd6cde0eb1e f57d4f7fee6ed178 06f067aa72176fba 0a637dc5a2c898a6 113f9804bef90dae 1b710b35131c471b 28db77f523047d84 32caab7b40c72493 3c9ebe0a15c9bebc 431d67c49c100d4c 4cc5d4becb3e42b6 597f299cfc657e2a 5fcb6fab3ad6faec 6c44198c4a475817'.split(' ').map(value => BigInt('0x' + (wide ? value : value.slice(0, 8))));
    const hash = '6a09e667f3bcc908 bb67ae8584caa73b 3c6ef372fe94f82b a54ff53a5f1d36f1 510e527fade682d1 9b05688c2b3e6c1f 1f83d9abfb41bd6b 5be0cd19137e2179'.split(' ').map(value => BigInt('0x' + (wide ? value : value.slice(0, 8))));
    const right = (value, amount) => (value >> BigInt(amount)) | ((value << (width - BigInt(amount))) & mask);
    const small = (value, first, second, shift) => right(value, first) ^ right(value, second) ^ (value >> BigInt(shift));
    const big = (value, first, second, third) => right(value, first) ^ right(value, second) ^ right(value, third);
    const bytes = input.slice();
    const bitLength = BigInt(bytes.length * 8);
    bytes.push(128);
    while (bytes.length % blockSize !== blockSize - (wide ? 16 : 8)) bytes.push(0);
    for (let index = wide ? 15 : 7; index >= 0; index--) bytes.push(Number((bitLength >> BigInt(index * 8)) & 255n));
    for (let block = 0; block < bytes.length; block += blockSize) {
      const words = [];
      for (let index = 0; index < 16; index++) {
        let word = 0n;
        for (let octet = 0; octet < blockSize / 16; octet++) word = (word << 8n) | BigInt(bytes[block + index * (blockSize / 16) + octet]);
        words.push(word);
      }
      for (let index = 16; index < (wide ? 80 : 64); index++) words[index] = (words[index - 16] + (wide ? small(words[index - 15], 1, 8, 7) : small(words[index - 15], 7, 18, 3)) + words[index - 7] + (wide ? small(words[index - 2], 19, 61, 6) : small(words[index - 2], 17, 19, 10))) & mask;
      let state = hash.slice();
      for (let index = 0; index < (wide ? 80 : 64); index++) {
        const first = (state[7] + (wide ? big(state[4], 14, 18, 41) : big(state[4], 6, 11, 25)) + ((state[4] & state[5]) ^ (~state[4] & state[6])) + constants[index] + words[index]) & mask;
        const second = ((wide ? big(state[0], 28, 34, 39) : big(state[0], 2, 13, 22)) + ((state[0] & state[1]) ^ (state[0] & state[2]) ^ (state[1] & state[2]))) & mask;
        state = [(first + second) & mask, state[0], state[1], state[2], (state[3] + first) & mask, state[4], state[5], state[6]];
      }
      for (let index = 0; index < 8; index++) hash[index] = (hash[index] + state[index]) & mask;
    }
    const result = [];
    for (const word of hash) for (let shift = Number(width) - 8; shift >= 0; shift -= 8) result.push(Number((word >> BigInt(shift)) & 255n));
    return result;
  }

  function calculate(counter) {
    const message = Array(8).fill(0);
    for (let index = 7; index >= 0; index--) {
      message[index] = counter % 256;
      counter = Math.floor(counter / 256);
    }
    const inner = [];
    const outer = [];
    for (let index = 0; index < (record.algorithm === 'SHA512' ? 128 : 64); index++) {
      inner.push((key[index] || 0) ^ 0x36);
      outer.push((key[index] || 0) ^ 0x5c);
    }
    const hash = record.algorithm === 'SHA1' ? sha1 : sha2;
    const digest = hash(outer.concat(hash(inner.concat(message))));
    const offset = digest[digest.length - 1] & 15;
    const binary = ((digest[offset] & 127) * 16777216) + digest[offset + 1] * 65536 + digest[offset + 2] * 256 + digest[offset + 3];
    return String(binary % 10 ** record.digits).padStart(record.digits, '0');
  }

  function setText(target, text) {
    if (target.textContent !== text) target.textContent = text;
  }

  function draw() {
    element('name').textContent = valid(record) ? record.name : '';
    element('meta').textContent = valid(record) ? 'TOTP · ' + record.algorithm + ' · ' + record.digits + ' digits · ' + record.period + ' s' : '';
    try {
      if (!valid(record)) throw Error();
      const milliseconds = Date.now();
      if (!Number.isFinite(milliseconds) || milliseconds < 0) throw Error('Device time error');
      if (!key) key = decode(record.secret);
      const seconds = Math.floor(milliseconds / 1000);
      const counter = Math.floor(seconds / record.period);
      if (!Number.isSafeInteger(counter)) throw Error('Device time error');
      if (counter !== previousCounter || !previousCode) {
        previousCode = calculate(counter);
        previousCounter = counter;
      }
      const left = record.period - seconds % record.period;
      const midpoint = previousCode.length / 2;
      setText(code, previousCode.slice(0, midpoint) + ' ' + previousCode.slice(midpoint));
      setText(remaining, left + ' s');
      bar.style.width = left / record.period * 100 + '%';
      copy.disabled = false;
      setText(hint, telegram && typeof telegram.copyText === 'function' ? '' : 'Select the code to copy');
      return previousCode;
    } catch (error) {
      previousCode = null;
      setText(code, '—');
      setText(remaining, '');
      bar.style.width = '0%';
      copy.disabled = true;
      setText(hint, error.message === 'Device time error' ? error.message : 'Code generation error');
      return null;
    }
  }

  copy.onclick = function () {
    const current = draw();
    if (current && telegram && typeof telegram.copyText === 'function') {
      try {
        telegram.copyText(current);
      } catch {
        hint.textContent = 'Select the code to copy';
      }
    }
  };
  draw();
  setInterval(draw, 250);
  if (telegram && typeof telegram.onEvent === 'function') telegram.onEvent('activated', draw);
  if (shared && telegram && typeof telegram.onEvent === 'function') telegram.onEvent('chatDataChanged', function () { load(); draw(); });
  if (telegram && typeof telegram.ready === 'function') telegram.ready();
}

export function renderWidget(record) {
  if (!['SHA1', 'SHA256', 'SHA512'].includes(record.algorithm) || ![6, 8].includes(record.digits) || !Number.isInteger(record.period) || record.period < 1 || record.period > 3600) {
    throw new Error('Неподдерживаемые параметры TOTP');
  }
  const data = JSON.stringify({ name: record.name, secret: record.secret, algorithm: record.algorithm, digits: record.digits, period: record.period, T0: 0, version: 1 })
    .replace(/[<>&\u2028\u2029]/g, (character) => '\\u' + character.charCodeAt(0).toString(16).padStart(4, '0'));
  return renderHtml(data);
}

export function renderSharedWidget() {
  return renderHtml('null');
}

function renderHtml(data) {
  return '<style>body{color:var(--tg-theme-text-color)}#name,#hint{overflow-wrap:anywhere}#name{font-weight:600}#code{font:2em monospace;user-select:text;-webkit-user-select:text}#remaining,#hint,#meta{color:var(--tg-theme-hint-color)}#track,#bar{height:4px}#track{background:var(--tg-theme-secondary-bg-color)}#bar{background:var(--tg-theme-button-color)}#copy{margin-top:12px}</style><div id="name" style="display:none"></div><div id="code">—</div><div id="remaining"></div><div id="track"><div id="bar"></div></div><button id="copy">Copy</button><div id="hint"></div><div id="meta"></div><script>(' + runWidget.toString() + ')(' + data + ');</script>';
}
