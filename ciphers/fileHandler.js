/**
 * fileHandler.js — Утилиты для работы с файлами
 *
 * Предоставляет:
 *   - readFileAsArrayBuffer(file) — читает File в Uint8Array
 *   - downloadFile(data, originalName, prefix) — скачивание в браузере
 */


/**
 * Читает File и возвращает содержимое как Uint8Array.
 */
export function readFileAsArrayBuffer(file) {
    return new Promise((resolve, reject) => {
        const reader = new FileReader();

        reader.onload = (e) => {
            resolve(new Uint8Array(e.target.result));
        };

        reader.onerror = () => {
            reject(new Error('Ошибка чтения файла'));
        };

        reader.readAsArrayBuffer(file);
    });
}


/**
 * Скачивает бинарные данные в браузере.
 *
 * Примеры имен:
 *   "photo.png" + "encrypted" → "encrypted_photo.png"
 *   "photo.png" + "decrypted" → "decrypted_photo.png"
 */
export function downloadFile(data, originalName, prefix) {
    const fileName = prefix ? `${prefix}_${originalName}` : originalName;

    let blob;
    if (data instanceof Blob) {
        blob = data;
    } else if (typeof data === 'string') {
        blob = new Blob([data], { type: 'text/plain' });
    } else {
        blob = new Blob([data], { type: 'application/octet-stream' });
    }

    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = fileName;
    a.style.display = 'none';

    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);

    URL.revokeObjectURL(url);
}