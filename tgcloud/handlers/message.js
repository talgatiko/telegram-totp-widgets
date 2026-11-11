import { api } from 'sdk';

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


export function runWidget(v0){const v1=v0=>document.getElementById(v0),v2=window.TelegramWidget,v3=v1("code"),v4=v1("remaining"),v5=v1("bar"),v6=v1("copy"),v7=v1("hint");let v8,v9,va;const vb=!v0;function vc(v0){return v0&&(!vb||2===v0.version&&0===v0.T0)&&"string"==typeof v0.name&&Array.from(v0.name).length>=1&&Array.from(v0.name).length<=80&&!/[\u0000-\u001f\u007f-\u009f\u2028\u2029]/.test(v0.name)&&"string"==typeof v0.secret&&["SHA1","SHA256","SHA512"].includes(v0.algorithm)&&[6,8].includes(v0.digits)&&Number.isInteger(v0.period)&&v0.period>=1&&v0.period<=3600&&(void 0===v0.T0||0===v0.T0)}function vd(){try{v0=JSON.parse(v2.chatData)}catch{v0=null}v8=void 0,va=void 0,v9=void 0}function ve(v0,v1){return v0<<v1|v0>>>32-v1}function vf(v0){const v1=v0.slice(),v2=8*v1.length;for(v1.push(128);v1.length%64!=56;)v1.push(0);for(let v0=7;v0>=0;v0--)v1.push(Math.floor(v2/256**v0)%256);const v3=[1732584193,4023233417,2562383102,271733878,3285377520];for(let v0=0;v0<v1.length;v0+=64){const v2=[];for(let v3=0;v3<16;v3++){const v4=v0+4*v3;v2[v3]=v1[v4]<<24|v1[v4+1]<<16|v1[v4+2]<<8|v1[v4+3]}for(let v0=16;v0<80;v0++)v2[v0]=ve(v2[v0-3]^v2[v0-8]^v2[v0-14]^v2[v0-16],1);let v4=v3[0],v5=v3[1],v6=v3[2],v7=v3[3],v8=v3[4];for(let v0=0;v0<80;v0++){let v1,v3;v0<20?(v1=v5&v6|~v5&v7,v3=1518500249):v0<40?(v1=v5^v6^v7,v3=1859775393):v0<60?(v1=v5&v6|v5&v7|v6&v7,v3=2400959708):(v1=v5^v6^v7,v3=3395469782);const v9=ve(v4,5)+v1+v8+v3+v2[v0]|0;v8=v7,v7=v6,v6=ve(v5,30),v5=v4,v4=v9}v3[0]=v3[0]+v4|0,v3[1]=v3[1]+v5|0,v3[2]=v3[2]+v6|0,v3[3]=v3[3]+v7|0,v3[4]=v3[4]+v8|0}const v4=[];for(const v0 of v3)for(let v1=24;v1>=0;v1-=8)v4.push(v0>>>v1&255);return v4}function vg(v1){const v2="SHA512"===v0.algorithm,v3=v2?64n:32n,v4=(1n<<v3)-1n,v5=v2?128:64,v6="428a2f98d728ae22 7137449123ef65cd b5c0fbcfec4d3b2f e9b5dba58189dbbc 3956c25bf348b538 59f111f1b605d019 923f82a4af194f9b ab1c5ed5da6d8118 d807aa98a3030242 12835b0145706fbe 243185be4ee4b28c 550c7dc3d5ffb4e2 72be5d74f27b896f 80deb1fe3b1696b1 9bdc06a725c71235 c19bf174cf692694 e49b69c19ef14ad2 efbe4786384f25e3 0fc19dc68b8cd5b5 240ca1cc77ac9c65 2de92c6f592b0275 4a7484aa6ea6e483 5cb0a9dcbd41fbd4 76f988da831153b5 983e5152ee66dfab a831c66d2db43210 b00327c898fb213f bf597fc7beef0ee4 c6e00bf33da88fc2 d5a79147930aa725 06ca6351e003826f 142929670a0e6e70 27b70a8546d22ffc 2e1b21385c26c926 4d2c6dfc5ac42aed 53380d139d95b3df 650a73548baf63de 766a0abb3c77b2a8 81c2c92e47edaee6 92722c851482353b a2bfe8a14cf10364 a81a664bbc423001 c24b8b70d0f89791 c76c51a30654be30 d192e819d6ef5218 d69906245565a910 f40e35855771202a 106aa07032bbd1b8 19a4c116b8d2d0c8 1e376c085141ab53 2748774cdf8eeb99 34b0bcb5e19b48a8 391c0cb3c5c95a63 4ed8aa4ae3418acb 5b9cca4f7763e373 682e6ff3d6b2b8a3 748f82ee5defb2fc 78a5636f43172f60 84c87814a1f0ab72 8cc702081a6439ec 90befffa23631e28 a4506cebde82bde9 bef9a3f7b2c67915 c67178f2e372532b ca273eceea26619c d186b8c721c0c207 eada7dd6cde0eb1e f57d4f7fee6ed178 06f067aa72176fba 0a637dc5a2c898a6 113f9804bef90dae 1b710b35131c471b 28db77f523047d84 32caab7b40c72493 3c9ebe0a15c9bebc 431d67c49c100d4c 4cc5d4becb3e42b6 597f299cfc657e2a 5fcb6fab3ad6faec 6c44198c4a475817".split(" ").map(v0=>BigInt("0x"+(v2?v0:v0.slice(0,8)))),v7="6a09e667f3bcc908 bb67ae8584caa73b 3c6ef372fe94f82b a54ff53a5f1d36f1 510e527fade682d1 9b05688c2b3e6c1f 1f83d9abfb41bd6b 5be0cd19137e2179".split(" ").map(v0=>BigInt("0x"+(v2?v0:v0.slice(0,8)))),v8=(v0,v1)=>v0>>BigInt(v1)|v0<<v3-BigInt(v1)&v4,v9=(v0,v1,v2,v3)=>v8(v0,v1)^v8(v0,v2)^v0>>BigInt(v3),va=(v0,v1,v2,v3)=>v8(v0,v1)^v8(v0,v2)^v8(v0,v3),vb=v1.slice(),vc=BigInt(8*vb.length);for(vb.push(128);vb.length%v5!==v5-(v2?16:8);)vb.push(0);for(let v0=v2?15:7;v0>=0;v0--)vb.push(Number(vc>>BigInt(8*v0)&255n));for(let v0=0;v0<vb.length;v0+=v5){const v1=[];for(let v2=0;v2<16;v2++){let v3=0n;for(let v1=0;v1<v5/16;v1++)v3=v3<<8n|BigInt(vb[v0+v2*(v5/16)+v1]);v1.push(v3)}for(let v0=16;v0<(v2?80:64);v0++)v1[v0]=v1[v0-16]+(v2?v9(v1[v0-15],1,8,7):v9(v1[v0-15],7,18,3))+v1[v0-7]+(v2?v9(v1[v0-2],19,61,6):v9(v1[v0-2],17,19,10))&v4;let v3=v7.slice();for(let v0=0;v0<(v2?80:64);v0++){const v5=v3[7]+(v2?va(v3[4],14,18,41):va(v3[4],6,11,25))+(v3[4]&v3[5]^~v3[4]&v3[6])+v6[v0]+v1[v0]&v4;v3=[v5+((v2?va(v3[0],28,34,39):va(v3[0],2,13,22))+(v3[0]&v3[1]^v3[0]&v3[2]^v3[1]&v3[2])&v4)&v4,v3[0],v3[1],v3[2],v3[3]+v5&v4,v3[4],v3[5],v3[6]]}for(let v0=0;v0<8;v0++)v7[v0]=v7[v0]+v3[v0]&v4}const vd=[];for(const v0 of v7)for(let v1=Number(v3)-8;v1>=0;v1-=8)vd.push(Number(v0>>BigInt(v1)&255n));return vd}function vh(v0,v1){v0.textContent!==v1&&(v0.textContent=v1)}function vi(){v1("name").textContent=vc(v0)?v0.name:"",v1("meta").textContent=vc(v0)?"TOTP · "+v0.algorithm+" · "+v0.digits+" digits · "+v0.period+" s":"";try{if(!vc(v0))throw Error();const v1=Date.now();if(!Number.isFinite(v1)||v1<0)throw Error("Device time error");v8||(v8=function(v0){if(!/^[A-Z2-7]+$/.test(v0))throw Error();let v1=0,v2=0;const v3=[];for(const v4 of v0)v1=32*v1+"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".indexOf(v4),v2+=5,v2>=8&&(v2-=8,v3.push(Math.floor(v1/2**v2)),v1%=2**v2);if(v2>=5||0!==v1||v3.length<10||v3.length>64)throw Error();return v3}(v0.secret));const vb=Math.floor(v1/1e3),vd=Math.floor(vb/v0.period);if(!Number.isSafeInteger(vd))throw Error("Device time error");vd===v9&&va||(va=function(v1){const v2=Array(8).fill(0);for(let v0=7;v0>=0;v0--)v2[v0]=v1%256,v1=Math.floor(v1/256);const v3=[],v4=[];for(let v1=0;v1<("SHA512"===v0.algorithm?128:64);v1++)v3.push(54^(v8[v1]||0)),v4.push(92^(v8[v1]||0));const v5="SHA1"===v0.algorithm?vf:vg,v6=v5(v4.concat(v5(v3.concat(v2)))),v7=15&v6[v6.length-1],v9=16777216*(127&v6[v7])+65536*v6[v7+1]+256*v6[v7+2]+v6[v7+3];return String(v9%10**v0.digits).padStart(v0.digits,"0")}(vd),v9=vd);const ve=v0.period-vb%v0.period,vi=va.length/2;return vh(v3,va.slice(0,vi)+" "+va.slice(vi)),vh(v4,ve+" s"),v5.style.width=ve/v0.period*100+"%",v6.disabled=!1,vh(v7,v2&&"function"==typeof v2.copyText?"":"Select the code to copy"),va}catch(v0){return va=null,vh(v3,"—"),vh(v4,""),v5.style.width="0%",v6.disabled=!0,vh(v7,"Device time error"===v0.message?v0.message:"Code generation error"),null}}vb&&vd(),v6.onclick=function(){const v0=vi();if(v0&&v2&&"function"==typeof v2.copyText)try{v2.copyText(v0)}catch{v7.textContent="Select the code to copy"}},vi(),setInterval(vi,250),v2&&"function"==typeof v2.onEvent&&v2.onEvent("activated",vi),vb&&v2&&"function"==typeof v2.onEvent&&v2.onEvent("chatDataChanged",function(){vd(),vi()}),v2&&"function"==typeof v2.ready&&v2.ready()}

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


const KEYBOARD = { keyboard: [[{ text: 'Старт' }]], resize_keyboard: true, is_persistent: true };
const FULL_HINT = 'Пришлите полную ссылку otpauth:// либо название и ключ двумя строками в одном сообщении.\nSend the complete otpauth:// link, or send the name and key on two lines in one message.';
const UNKNOWN = 'Исход отправки неизвестен. Проверьте наличие карточки в чате. Автоматического повтора нет; только после проверки отправьте полные данные заново.';
const INTRO = 'Создаю автономные TOTP-виджеты: SHA1, SHA256 и SHA512, 6 или 8 цифр. Секрет хранится в сообщении Telegram: доступ к чату даёт доступ к кодам. Сохраните резервную копию ключа отдельно. Обновите Telegram, если виджеты не отображаются. Пришлите полную ссылку otpauth:// либо название и ключ двумя строками в одном сообщении.\n\nI create standalone TOTP widgets: SHA1, SHA256 and SHA512, with 6 or 8 digits. The secret is stored in the Telegram message: access to the chat gives access to the codes. Keep a separate backup of the key. Update Telegram if widgets are not displayed. Send the complete otpauth:// link, or send the name and key on two lines in one message.';

export function createBot(api, { parse, render, widgetId } = {}) {
  async function reply(chatId, text, extra = {}) {
    try { await api.sendMessage({ chat_id: chatId, text, ...extra }); }
    catch { return false; }
    return true;
  }

  async function send(message, record) {
    let args;
    try {
      const common = { chat_id: message.chat.id, caption: record.name, show_caption_above_media: false };
      if (widgetId) {
        const chatData = JSON.stringify({ version: 2, name: record.name, secret: record.secret, algorithm: record.algorithm, digits: record.digits, period: record.period, T0: 0 });
        if (new TextEncoder().encode(chatData).length > 1024) {
          await reply(message.chat.id, 'Данные карточки превышают допустимый размер. Запись не обрезана и не отправлена.');
          return;
        }
        args = { ...common, widget_id: widgetId, chat_data: chatData };
      } else {
        const html = render(record);
        if (typeof html !== 'string' || !html || new TextEncoder().encode(html).length > 32768) {
          await reply(message.chat.id, 'Размер виджета превышает допустимый. Запись не обрезана и не отправлена.');
          return;
        }
        args = { ...common, html, allow_queries: false, is_shared: false };
      }
    } catch {
      await reply(message.chat.id, 'Невозможно сформировать виджет. Проверьте параметры записи.');
      return;
    }
    let sent;
    try {
      sent = await (widgetId ? api.sendSharedWidget(args) : api.sendWidget(args));
    } catch (error) {
      if (Number.isInteger(error?.code) && error.code >= 400 && error.code < 500) {
        const seconds = error.code === 429 && Number.isSafeInteger(error.parameters?.retry_after) && error.parameters.retry_after >= 0 ? error.parameters.retry_after : null;
        await reply(message.chat.id, seconds === null ? 'Telegram отклонил отправку. Проверьте данные и повторите полное сообщение.' : `Telegram ограничил частоту. Повторите полное сообщение не раньше чем через ${seconds} с.`);
      } else await reply(message.chat.id, UNKNOWN);
      return;
    }
    if (sent?.chat?.id !== message.chat.id || !Number.isSafeInteger(sent?.message_id) || sent.message_id <= 0 ||
      !sent.widget || typeof sent.widget !== 'object' || Array.isArray(sent.widget) || (widgetId && sent.widget.id !== widgetId)) {
      await reply(message.chat.id, UNKNOWN);
      return;
    }
    try {
      const deleted = await api.deleteMessage({ chat_id: message.chat.id, message_id: message.message_id });
      if (deleted !== true) throw new Error('delete_unconfirmed');
    }
    catch { await reply(message.chat.id, 'Виджет создан. Исходное сообщение с ключом удалить не удалось: удалите его вручную. Секрет остаётся в сообщении виджета.'); }
  }

  async function message(message) {
    if (message?.chat?.type !== 'private' || !Number.isSafeInteger(message.chat.id) || message.chat.id <= 0 ||
      !Number.isSafeInteger(message?.from?.id) || message.from.id !== message.chat.id || message.from.is_bot ||
      !Number.isSafeInteger(message.message_id) || message.message_id <= 0 || message.edit_date !== undefined || typeof message.text !== 'string') return;
    let text = message.text.trim();
    const command = /^\/(\w+)(?:@[A-Za-z0-9_]+)?(?:\s|$)/.exec(text);
    const name = command?.[1].toLowerCase();
    if (name === 'start' || name === 'help' || text === 'Старт') {
      await reply(message.chat.id, INTRO + '\n\nGitHub: https://github.com/talgatiko/telegram-totp-widgets', { reply_markup: KEYBOARD });
      return;
    }
    if (name === 'add') text = text.slice(command[0].length).trim();
    else if (command) {
      await reply(message.chat.id, 'Неизвестная команда. Используйте /help.');
      return;
    }
    if (!text || text === 'Добавить ключ') {
      await reply(message.chat.id, FULL_HINT, { reply_markup: KEYBOARD });
      return;
    }
    let record;
    try { record = parse(text); }
    catch (error) {
      await reply(message.chat.id, typeof error?.message === 'string' ? error.message : 'Неверный формат данных. Используйте /help.');
      return;
    }
    if (!record?.name || !record.secret) {
      await reply(message.chat.id, FULL_HINT);
      return;
    }
    await send(message, record);
  }

  return { message };
}


export const sharedWidgetId = "REPLACE_WITH_YOUR_SHARED_WIDGET_ID";
export default createBot(api, { parse: parseInput, render: renderWidget, widgetId: sharedWidgetId }).message;
