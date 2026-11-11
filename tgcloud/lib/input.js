const defaults = { algorithm: 'SHA1', digits: 6, period: 30 };
const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export function validateName(value) {
  if (typeof value !== 'string' || /[\u0000-\u001f\u007f-\u009f\u2028\u2029]/.test(value)) {
    throw new Error('Название не должно содержать переводы строк или управляющие символы.');
  }
  const name = value.trim();
  if (Array.from(name).length < 1 || Array.from(name).length > 80) {
    throw new Error('Название должно содержать от 1 до 80 символов.');
  }
  return name;
}

export function normalizeSecret(value) {
  if (typeof value !== 'string') throw new Error('Укажите секретный ключ Base32.');
  const grouped = value.replace(/ /g, '');
  if (!/^[A-Za-z2-7]+={0,6}$/.test(grouped)) throw new Error('Ключ должен содержать только Base32: A–Z и 2–7.');
  const compact = grouped.toUpperCase();
  const secret = compact.replace(/=+$/, '');
  const remainder = secret.length % 8;
  const padding = compact.length - secret.length;
  const expectedPadding = { 0: 0, 2: 6, 4: 4, 5: 3, 7: 1 }[remainder];
  if (expectedPadding === undefined || (padding !== 0 && padding !== expectedPadding)) {
    throw new Error('Некорректная длина или заполнение Base32.');
  }
  const remainingBits = (secret.length * 5) % 8;
  const lastValue = alphabet.indexOf(secret[secret.length - 1]);
  if (remainingBits && (lastValue & ((1 << remainingBits) - 1))) {
    throw new Error('Некорректные остаточные биты Base32.');
  }
  const byteLength = Math.floor(secret.length * 5 / 8);
  if (byteLength < 10 || byteLength > 64) throw new Error('Длина секрета должна составлять от 10 до 64 байт.');
  return secret;
}

function decode(value) {
  try {
    return decodeURIComponent(value);
  } catch {
    throw new Error('Некорректное percent-кодирование TOTP-ссылки.');
  }
}

function parseUri(text) {
  const match = /^otpauth:\/\/([^/?#]+)\/([^?#]*)(?:\?([^#]*))?$/i.exec(text);
  if (!match || match[1].toLowerCase() !== 'totp') throw new Error('Поддерживается только ссылка otpauth://totp/.');
  const params = {};
  const allowed = ['secret', 'issuer', 'algorithm', 'digits', 'period'];
  if (match[3] !== undefined && match[3] !== '') {
    for (const item of match[3].split('&')) {
      const separator = item.indexOf('=');
      if (separator < 0) throw new Error('Параметры TOTP-ссылки должны иметь значения.');
      const key = decode(item.slice(0, separator));
      const value = decode(item.slice(separator + 1));
      if (key === 'counter') throw new Error('Параметр counter относится к HOTP и не поддерживается.');
      if (key.toLowerCase() === 't0') throw new Error('Настройка T0 не поддерживается: используется T0=0.');
      if (!allowed.includes(key)) throw new Error('TOTP-ссылка содержит неподдерживаемый параметр.');
      if (Object.prototype.hasOwnProperty.call(params, key)) throw new Error('Параметры TOTP-ссылки не должны повторяться.');
      params[key] = value;
    }
  }
  if (!params.secret) throw new Error('В TOTP-ссылке отсутствует секретный ключ.');
  if (params.algorithm !== undefined && !['SHA1', 'SHA256', 'SHA512'].includes(params.algorithm.toUpperCase())) {
    throw new Error('Поддерживаются только алгоритмы SHA1, SHA256 и SHA512.');
  }
  if (params.digits !== undefined && !/^[68]$/.test(params.digits)) throw new Error('Разрядность кода должна быть 6 или 8.');
  if (params.period !== undefined && (!/^\d+$/.test(params.period) || Number(params.period) < 1 || Number(params.period) > 3600)) {
    throw new Error('Период должен быть целым числом от 1 до 3600 секунд.');
  }
  let label = decode(match[2]).trim();
  if (label) label = validateName(label);
  if (params.issuer !== undefined) {
    const issuer = validateName(params.issuer);
    if (label && label !== issuer && !label.startsWith(issuer + ':')) label = validateName(issuer + ': ' + label);
  }
  return {
    ...defaults,
    ...(label ? { name: label } : {}),
    secret: normalizeSecret(params.secret),
    algorithm: params.algorithm === undefined ? 'SHA1' : params.algorithm.toUpperCase(),
    digits: params.digits === undefined ? 6 : Number(params.digits),
    period: params.period === undefined ? 30 : Number(params.period)
  };
}

export function parseInput(value) {
  if (typeof value !== 'string') throw new Error('Пришлите название, ключ Base32 или ссылку otpauth://.');
  let text = value.replace(/\r\n?/g, '\n').trim();
  text = text.replace(/^\/add(?:@[A-Za-z0-9_]+)?(?:\n|[ \t]+|$)/i, '').trim();
  if (!text) throw new Error('Пришлите название, ключ Base32 или ссылку otpauth://.');
  if (/^\//.test(text)) throw new Error('Команда не является данными для добавления ключа.');
  if (/^otpauth:\/\//i.test(text)) {
    return parseUri(text);
  }
  const lines = text.split('\n');
  if (lines.length > 2) throw new Error('Пришлите две строки: название, затем ключ Base32 или TOTP-ссылку.');
  if (lines.length === 2) {
    const name = validateName(lines[0]);
    const second = lines[1].trim();
    const entry = /^otpauth:\/\//i.test(second) ? parseUri(second) : { ...defaults, secret: normalizeSecret(second) };
    return { ...entry, name };
  }
  if (/^\d{6,8}$/.test(text)) throw new Error('Текущий одноразовый код не является секретным ключом. Пришлите ключ Base32.');
  try {
    return { ...defaults, secret: normalizeSecret(text) };
  } catch (error) {
    return { ...defaults, name: validateName(text) };
  }
}
