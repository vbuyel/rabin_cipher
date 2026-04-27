/**
 * main.js — Управление / DOM
 *
 * Импорты:
 *   math.js        → isPrime (используется через rabin.js)
 *   rabin.js       → validateParams, rabinEncrypt, rabinDecrypt,
 *                    cipherToDecimalString, decimalStringToCipher
 *   fileHandler.js → readFileAsArrayBuffer, downloadFile
 *
 * Связывает DOM-элементы из index.html и управляет состоянием приложения.
 */

import {
    validateParams,
    rabinEncrypt,
    rabinDecrypt,
    cipherToDecimalString,
    decimalStringToCipher,
} from './rabin.js';

import {
    readFileAsArrayBuffer,
    downloadFile,
} from './fileHandler.js';


// ===== Состояние приложения =====
let currentFileData = null;   // Uint8Array — байты загруженного файла
let currentFileName = '';     // имя файла
let currentFileDecimal = '';  // строковое представление файла в decimal
let lastCipherData = null;   // Uint8Array — результат шифрования
let lastPlainData = null;   // Uint8Array — результат дешифрования
let operationMode = null;   // 'encrypt' | 'decrypt' | null


// ===== Кэш DOM-элементов =====
let els = {};


// ===== Утилиты UI =====

/**
 * Показать сообщение об ошибке.
 */
function showError(msg) {
    const box = els.errorMessages;
    if (!box) return;
    box.querySelector('div').textContent = msg;
    box.classList.add('active');
}

/**
 * Скрыть сообщение об ошибке.
 */
function clearError() {
    const box = els.errorMessages;
    if (!box) return;
    box.querySelector('div').textContent = '';
    box.classList.remove('active');
}

/**
 * Показать текст в секции вывода.
 */
function showSource(text) {
    if (els.sourceOutput) els.sourceOutput.textContent = text;
}

function showResult(text) {
    if (els.resultOutput) els.resultOutput.textContent = text;
    if (els.outputSection) els.outputSection.style.display = 'block';
}

/**
 * Скрыть секцию вывода.
 */
function hideOutput() {
    if (els.sourceOutput) els.sourceOutput.textContent = '';
    if (els.resultOutput) els.resultOutput.textContent = '';
    if (els.outputSection) els.outputSection.style.display = 'none';
}


// ===== Валидация параметров =====

/**
 * Читает p, q, b из DOM, валидирует и возвращает BigInt.
 * Показывает ошибку и возвращает null при неудаче.
 *
 * @returns {{ p: bigint, q: bigint, b: bigint, n: bigint } | null}
 */
function getParams() {
    clearError();

    const pStr = els.pInput?.value?.trim() || '';
    const qStr = els.qInput?.value?.trim() || '';
    const bStr = els.bInput?.value?.trim() || '';

    if (!pStr) { showError('Параметр p обязателен'); return null; }
    if (!qStr) { showError('Параметр q обязателен'); return null; }
    if (!bStr) { showError('Параметр b обязателен'); return null; }

    let p, q, b;
    try {
        p = BigInt(pStr);
        q = BigInt(qStr);
        b = BigInt(bStr);
    } catch {
        showError('Некорректные числовые параметры');
        return null;
    }

    const result = validateParams(p, q, b);
    if (!result.valid) {
        showError(result.error);
        return null;
    }

    return { p, q, b, n: result.n };
}


// ===== Обработка файла =====

async function handleFileSelect() {
    const file = els.fileInput?.files?.[0];
    if (!file) return;

    currentFileName = file.name;
    if (els.fileName) els.fileName.textContent = file.name;

    try {
        currentFileData = await readFileAsArrayBuffer(file);
        // Конвертируем байты в decimal строку (первые 200 байт)
        const limit = Math.min(currentFileData.length, 200);
        currentFileDecimal = Array.from(currentFileData).slice(0, limit).join(' ');
        if (currentFileData.length > 200) {
            currentFileDecimal += ' …';
        }
        clearError();
    } catch (err) {
        showError(err.message);
    }
}


// ===== Шифрование =====

function encryptFile() {
    clearError();

    const params = getParams();
    if (!params) return;

    if (!currentFileData || currentFileData.length === 0) {
        showError('Выберите файл');
        return;
    }

    const { b, n } = params;

    try {
        const cipherBytes = rabinEncrypt(currentFileData, b, n);

        // Сохраняем для скачивания
        lastCipherData = cipherBytes;
        lastPlainData = null;
        operationMode = 'encrypt';

        // Выводим исходный файл и результат
        showSource(currentFileDecimal);

        // Выводим блоки шифротекста как десятичные числа
        const decStr = cipherToDecimalString(cipherBytes, n);
        showResult(decStr);
    } catch (err) {
        showError('Ошибка шифрования: ' + err.message);
    }
}


// ===== Дешифрование =====

function decryptFile() {
    clearError();

    const params = getParams();
    if (!params) return;

    const { p, q, b, n } = params;

    // Получаем шифротекст — либо после шифрования, либо из поля вывода
    let cipherBytes;

    if (lastCipherData) {
        // Дешифруем результат предыдущего шифрования
        cipherBytes = lastCipherData;
    } else {
        // Пробуем распарсить десятичный текст из поля вывода
        const text = els.resultOutput?.textContent?.trim();
        if (!text) {
            showError('Сначала зашифруйте файл или загрузите шифротекст');
            return;
        }
        try {
            cipherBytes = decimalStringToCipher(text, n);
        } catch {
            showError('Не удалось разобрать шифротекст');
            return;
        }
    }

    try {
        const plainBytes = rabinDecrypt(cipherBytes, b, n, p, q);

        lastPlainData = plainBytes;
        lastCipherData = null;
        operationMode = 'decrypt';

        // Показываем исходный шифротекст и результат
        const sourceText = els.resultOutput?.textContent?.trim() || '';
        showSource(sourceText);

        // Показываем превью (первые 200 байт как десятичные числа)
        const preview = Array.from(plainBytes).slice(0, 200).join(' ');
        showResult(preview + (plainBytes.length > 200 ? ' …' : ''));
    } catch (err) {
        showError('Ошибка дешифрования: ' + err.message);
    }
}


// ===== Сохранение =====

function saveData() {
    if (operationMode === 'encrypt' && lastCipherData) {
        // Сохраняем зашифрованные данные
        downloadFile(lastCipherData, currentFileName || 'data.bin', 'encrypted');
    } else if (operationMode === 'decrypt' && lastPlainData) {
        // Сохраняем расшифрованные данные
        downloadFile(lastPlainData, currentFileName || 'data.bin', 'decrypted');
    } else {
        showError('Нет данных для сохранения');
    }
}


// ===== Очистка =====

function clearAll() {
    if (els.pInput) els.pInput.value = '';
    if (els.qInput) els.qInput.value = '';
    if (els.bInput) els.bInput.value = '';
    if (els.fileName) els.fileName.textContent = 'файл не выбран';
    if (els.fileInput) els.fileInput.value = '';

    currentFileData = null;
    currentFileName = '';
    currentFileDecimal = '';
    lastCipherData = null;
    lastPlainData = null;
    operationMode = null;

    hideOutput();
    clearError();
}


// ===== Инициализация =====

function init() {
    els = {
        pInput: document.getElementById('p_input'),
        qInput: document.getElementById('q_input'),
        bInput: document.getElementById('b_input'),
        fileInput: document.getElementById('file_input'),
        btnChooseFile: document.getElementById('btn_choose_file'),
        fileName: document.getElementById('file_name'),
        sourceOutput: document.getElementById('source_output'),
        resultOutput: document.getElementById('result_output'),
        outputSection: document.getElementById('output_section'),
        btnSave: document.getElementById('btn_save'),
        errorMessages: document.querySelector('.error-messages'),
    };

    // Выбор файла: видимая кнопка открывает скрытый <input type="file">
    els.btnChooseFile?.addEventListener('click', () => els.fileInput?.click());
    els.fileInput?.addEventListener('change', handleFileSelect);

    // Кнопки действий
    document.querySelector('.action-btn-encrypt')?.addEventListener('click', encryptFile);
    document.querySelector('.action-btn-decrypt')?.addEventListener('click', decryptFile);
    document.querySelector('.action-btn-clear')?.addEventListener('click', clearAll);
    els.btnSave?.addEventListener('click', saveData);

    // Очищаем ошибки при вводе
    els.pInput?.addEventListener('input', clearError);
    els.qInput?.addEventListener('input', clearError);
    els.bInput?.addEventListener('input', clearError);
}


// Запускаем при готовности DOM
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
} else {
    init();
}
