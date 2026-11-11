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
