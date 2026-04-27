/**
 * math.js — Математические функции (на BigInt)
 *
 * Предоставляет:
 *   - mod(a, n)           — неотрицательный остаток
 *   - gcdExtended(a, b)   — Расширенный алгоритм Евклида (коэффициенты Безу)
 *   - power(base, exp, mod) — Бинарное (квадратно-умножительное) возведение в степень
 *   - isPrime(n)          — Проверка простоты методом пробного деления
 */


/**
 * Неотрицательный остаток.
 * Гарантирует результат в [0, n-1] даже при отрицательном a.
 */
export function mod(a, n) {
    const r = a % n;
    return r < 0n ? r + n : r;
}


/**
 * Расширенный алгоритм Евклида.
 * Находит x, y такие что a·x + b·y = gcd(a, b).
 */
export function gcdExtended(a, b) {
    let x0 = 1n, y0 = 0n;
    let x1 = 0n, y1 = 1n;

    while (b > 0n) {
        const q = a / b;
        const r = a % b;

        a = b;
        b = r;

        const x2 = x0 - q * x1;
        const y2 = y0 - q * y1;

        x0 = x1; x1 = x2;
        y0 = y1; y1 = y2;
    }

    return { gcd: a, x: x0, y: y0 };
}


/**
 * Бинарное возведение в степень по модулю.
 * Вычисляет  base^exp mod m  эффективно.
 */
export function power(base, exp, m) {
    let result = 1n;
    base = mod(base, m);

    while (exp > 0n) {
        if (exp & 1n) {
            result = mod(result * base, m);
        }
        base = mod(base * base, m);
        exp >>= 1n;
    }

    return result;
}


/**
 * Проверка простоты.
 * Метод пробного деления с колесом 6k ± 1.
 * Достаточно для размеров ключей в этой лабораторной.
 */
export function isPrime(n) {
    if (n <= 1n) return false;
    if (n <= 3n) return true;
    if (n % 2n === 0n || n % 3n === 0n) return false;

    for (let i = 5n; i * i <= n; i += 6n) {
        if (n % i === 0n || n % (i + 2n) === 0n) {
            return false;
        }
    }
    return true;
}
