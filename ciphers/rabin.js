/**
 * rabin.js — Криптосистема Рабина: шифрование / дешифрование
 *
 * Формула шифрования:
 *   C = m * (m + b) mod n
 *
 * Стратегия дополнения — 2-байтовый маркер (0xFF 0xFF)
 *   Перед шифрованием каждого блока добавляются два байта 0xFF 0xFF.
 *   После дешифрования правильный корень (из 4 кандидатов CRT)
 *   определяется по последним 2 байтам, равным маркеру.
 *
 * Размер блока
 *   n = p * q определяет максимальное значение блока.
 *   blockSize  = длина n в байтах минус 2 байта под маркер.
 *   Каждый чанк данных размера blockSize дополняется 0xFF 0xFF,
 *   преобразуется в BigInt, шифруется и сохраняется как фиксированный BigInt
 *   размера cipherBlockSize (длина n в байтах).
 */

import { mod, gcdExtended, power, isPrime } from './math.js';


// ===== Константы маркера =====
const MARKER = new Uint8Array([0xFF, 0xFF]);
const MARKER_LEN = MARKER.length;            // 2


// ===== Утилиты: BigInt ↔ массив байтов (big-endian) =====


/**
 * Возвращает количество байт для представления значения (≥ 1).
 */
function byteLength(value) {
    if (value <= 0n) return 1;
    let len = 0;
    let v = value;
    while (v > 0n) { v >>= 8n; len++; }
    return len;
}


/**
 * BigInt → Uint8Array (big-endian), дополненный нулями до len байт.
 */
function bigintToBytes(value, len) {
    const bytes = new Uint8Array(len);
    let v = value;
    for (let i = len - 1; i >= 0; i--) {
        bytes[i] = Number(v & 0xFFn);
        v >>= 8n;
    }
    return bytes;
}


/**
 * Uint8Array (big-endian) → BigInt.
 */
function bytesToBigint(bytes) {
    let result = 0n;
    for (let i = 0; i < bytes.length; i++) {
        result = (result << 8n) | BigInt(bytes[i]);
    }
    return result;
}


// ===== Валидация параметров =====


/**
 * Валидирует параметры Рабина p, q, b.
 *
 * Проверки:
 *   - p и q простые
 *   - p ≡ 3 (mod 4) и q ≡ 3 (mod 4)
 *   - p ≠ q
 *   - 0 < b < n
 */
export function validateParams(p, q, b) {
    if (!isPrime(p)) return { valid: false, error: 'p не является простым числом' };
    if (!isPrime(q)) return { valid: false, error: 'q не является простым числом' };
    if (p % 4n !== 3n) return { valid: false, error: 'p должно быть ≡ 3 (mod 4)' };
    if (q % 4n !== 3n) return { valid: false, error: 'q должно быть ≡ 3 (mod 4)' };
    if (p === q) return { valid: false, error: 'p и q должны быть различными' };

    const n = p * q;

    // n должен быть достаточно большим: (1 байт данных ‖ 0xFF 0xFF) как BigInt < n
    // худший случай: 0xFF 0xFF 0xFF = 16 777 215, поэтому n > 16 777 215
    const MIN_N = (1n << 24n);  // 16 777 216
    if (n < MIN_N) return { valid: false, error: `n = p·q слишком мало (нужно n ≥ ${MIN_N}, сейчас n = ${n})` };
    if (b <= 0n || b >= n) return { valid: false, error: 'b должно быть в диапазоне 0 < b < n' };

    return { valid: true, n };
}


// ===== Шифрование =====


/**
 * Шифрует произвольные бинарные данные криптосистемой Рабина.
 */
export function rabinEncrypt(data, b, n) {
    const nBytes = byteLength(n);

    // Находим максимальный размер данных k, при котором
    // дополненное значение (k+2 байт, все 0xFF) = 256^(k+2) − 1 < n
    let blockSize = 0;
    for (let k = 1; k <= nBytes; k++) {
        // худший случай с k байт данных: (256^(k + MARKER_LEN)) - 1
        const worstCase = (1n << (BigInt(k + MARKER_LEN) * 8n)) - 1n;
        if (worstCase < n) {
            blockSize = k;
        } else {
            break;
        }
    }

    if (blockSize < 1) {
        throw new Error('n слишком мало для блочного шифрования');
    }

    const cipherBlockSize = nBytes;                          // каждый шифроблок = nBytes
    const blockCount = Math.ceil(data.length / blockSize);
    const out = new Uint8Array(blockCount * cipherBlockSize);

    for (let i = 0; i < blockCount; i++) {
        // 1. Извлекаем чанк данных (может быть короче blockSize для последнего блока)
        const start = i * blockSize;
        const end = Math.min(start + blockSize, data.length);
        const chunk = data.slice(start, end);

        // 2. Добавляем маркер: chunk ‖ 0xFF 0xFF
        const padded = new Uint8Array(chunk.length + MARKER_LEN);
        padded.set(chunk, 0);
        padded.set(MARKER, chunk.length);

        // 3. Преобразуем в BigInt m
        const m = bytesToBigint(padded);

        // Проверка (не должна сработать при правильном blockSize)
        if (m >= n) {
            throw new Error(`Блок ${i + 1}: m (${m}) >= n (${n}), невозможно зашифровать`);
        }

        // 4. Шифруем:  c = m·(m + b) mod n
        const c = mod(m * (m + b), n);

        // 5. Записываем шифроблок (фиксированная ширина)
        const cBytes = bigintToBytes(c, cipherBlockSize);
        out.set(cBytes, i * cipherBlockSize);
    }

    return out;
}


// ===== Дешифрование =====


/**
 * Дешифрует шифротекст Рабина обратно в открытый текст.
 *
 * Для каждого шифроблока:
 *   1. Вычисляем дискриминант D = b² + 4c (mod n)
 *   2. Корни по модулю p, q (возможно, потому что p,q ≡ 3 mod 4)
 *   3. CRT → 4 кандидата r1…r4
 *   4. Для каждого корня:  m_candidate = (−b + root) / 2  mod n
 *      (деление — модулярный обратный элемент)
 *   5. Выбираем кандинат, чьи последние 2 байта равны 0xFF 0xFF
 */
export function rabinDecrypt(cipherData, b, n, p, q) {
    const nBytes = byteLength(n);
    const cipherBlockSize = nBytes;
    const blockCount = cipherData.length / cipherBlockSize;

    if (!Number.isInteger(blockCount) || blockCount === 0) {
        throw new Error('Некорректная длина шифротекста');
    }

    // Предвычисляем коэффициенты CRT (только один раз)
    const { x: yp, y: yq } = gcdExtended(p, q);   // p·yp + q·yq = 1

    // Модулярный обратный элемент 2 по модулю n (нужен для m = (root - b) / 2 mod n)
    const inv2 = mod(power(2n, n - p - q, n), n);
    // Упрощённый вариант: (n+1n)/2n работает для нечётного n (всегда верно для произведения двух нечётных простых)
    const inv2Simple = (n + 1n) / 2n;

    const chunks = [];

    for (let i = 0; i < blockCount; i++) {
        const cBytes = cipherData.slice(i * cipherBlockSize, (i + 1) * cipherBlockSize);
        const c = bytesToBigint(cBytes);

        // D = b² + 4c  mod n
        const D = mod(b * b + 4n * c, n);

        // Корни по модулю p и q (p,q ≡ 3 mod 4 ⇒ показатель (p+1)/4)
        const mp = power(D, (p + 1n) / 4n, p);
        const mq = power(D, (q + 1n) / 4n, q);

        // CRT комбинация для ±mp, ±mq  →  4 корня D mod n
        const t1 = mod(yp * p * mq, n);
        const t2 = mod(yq * q * mp, n);

        const roots = [
            mod(t1 + t2, n),
            mod(n - (t1 + t2), n),
            mod(t1 - t2, n),
            mod(n - (t1 - t2), n),
        ];

        // Для каждого корня r: m = (−b + r) / 2 mod n = (r - b) · inv2 mod n
        // Дополненный блок имеет размер от (MARKER_LEN+1) до (nBytes-1) байт.
        // Проверяем разные ширины для маркера.
        let found = false;
        for (const r of roots) {
            const m = mod((r - b) * inv2Simple, n);

            // Проверяем, что кандидат решифруется обратно в c
            if (mod(m * (m + b), n) !== c) continue;

            // Пробуем разные ширины: от max (nBytes - 1) до min (MARKER_LEN + 1)
            const maxW = nBytes - 1;
            const minW = MARKER_LEN + 1;       // минимум 1 байт данных + 2 байта маркера
            for (let w = maxW; w >= minW; w--) {
                const mBytes = bigintToBytes(m, w);

                if (mBytes[w - 2] === 0xFF &&
                    mBytes[w - 1] === 0xFF) {
                    // Удаляем маркер → исходный чанк
                    const plainChunk = mBytes.slice(0, w - MARKER_LEN);
                    chunks.push(plainChunk);
                    found = true;
                    break;
                }
            }
            if (found) break;
        }

        if (!found) {
            throw new Error(`Не удалось найти корректный корень для блока ${i + 1}`);
        }
    }

    // Объединяем все чанки данных
    const totalLen = chunks.reduce((s, c) => s + c.length, 0);
    const result = new Uint8Array(totalLen);
    let offset = 0;
    for (const chunk of chunks) {
        result.set(chunk, offset);
        offset += chunk.length;
    }

    return result;
}


// ===== Утилиты: представление шифротекста в виде строки десятичных чисел =====


/**
 * Преобразует байты шифротектса в строку десятичных чисел через пробел.
 * Каждый шифроблок читается как BigInt и выводится в base 10.
 */
export function cipherToDecimalString(cipherData, n) {
    const cipherBlockSize = byteLength(n);
    const count = cipherData.length / cipherBlockSize;
    const parts = [];
    for (let i = 0; i < count; i++) {
        const block = cipherData.slice(i * cipherBlockSize, (i + 1) * cipherBlockSize);
        parts.push(bytesToBigint(block).toString(10));
    }
    return parts.join(' ');
}


/**
 * Парсит строку десятичных чисел обратно в байты шифротекста.
 */
export function decimalStringToCipher(text, n) {
    const cipherBlockSize = byteLength(n);
    const values = text.trim().split(/\s+/).map(s => BigInt(s));
    const out = new Uint8Array(values.length * cipherBlockSize);
    for (let i = 0; i < values.length; i++) {
        const bytes = bigintToBytes(values[i], cipherBlockSize);
        out.set(bytes, i * cipherBlockSize);
    }
    return out;
}
