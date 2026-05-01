const V_URL = 'http://localhost:8003';
const S_URL = 'http://localhost:8001';

function onSigAlgoChange() {
    const sig = document.getElementById('sigAlgo')?.value || 'rsa-pss';
    const hashSelect = document.getElementById('hashAlgo');
    if (!hashSelect) return;
    // Ed25519 does hashing internally; we hide external hash choice
    hashSelect.disabled = sig === 'ed25519';
}

async function initVault() {
    try {
        const res = await fetch(`${V_URL}/init`, { method: 'POST' });
        const data = await res.json();
        if (!res.ok) {
            return alert("Ошибка init: " + (data.detail || "unknown"));
        }
        document.getElementById('keyPart1').value = data.part1 || "";
        document.getElementById('keyPart2').value = data.part2 || "";
        document.getElementById('vaultStatus').innerText = `Статус: initialized (0/2)`;
    } catch (e) {
        alert("Бэкенд Vault не отвечает. Проверь, запущен ли сервер на порту 8003");
    }
}

async function copyKey(id) {
    const el = document.getElementById(id);
    const text = (el?.value || "").trim();
    if (!text) return alert("Нечего копировать");
    try {
        await navigator.clipboard.writeText(text);
    } catch (_) {
        el.select();
        document.execCommand('copy');
    }
}

async function unsealVault() {
    const key = document.getElementById('keyPart').value.trim();
    if (!key) return alert("Введите часть ключа!");

    try {
        const res = await fetch(`${V_URL}/unseal`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ "key_part": key })
        });
        
        const data = await res.json();
        
        if (res.ok) {
            document.getElementById('vaultStatus').innerText = `Статус: ${data.status} (${data.keys_collected}/2)`;
        } else {
            alert("Ошибка: " + (data.detail || "Неверный формат ключа"));
        }
    } catch (err) {
        alert("Бэкенд Vault не отвечает. Проверь, запущен ли сервер на порту 8003");
    }
}

async function sealVault() {
    try {
        const res = await fetch(`${V_URL}/seal`, { method: 'POST' });
        const data = await res.json();
        if (res.ok) {
            document.getElementById('vaultStatus').innerText = `Статус: ${data.status}`;
        } else {
            alert("Ошибка: " + (data.detail || "Не удалось seal"));
        }
    } catch (err) {
        alert("Бэкенд Vault не отвечает. Проверь, запущен ли сервер на порту 8003");
    }
}

async function saveSecret() {
    const k = document.getElementById('secKey').value;
    const v = document.getElementById('secVal').value;
    
    try {
        const wrapRes = await fetch(`${V_URL}/wrap`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({secret: v})
        });
        const {token} = await wrapRes.json();
        
        const storeRes = await fetch(`${V_URL}/secrets/${k}`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({value: token})
        });
        if (!storeRes.ok) {
            const err = await storeRes.json().catch(() => ({}));
            return alert("Ошибка store: " + (err.detail || "unknown"));
        }
        document.getElementById('secretResult').innerText = `Сохранено. Token (одноразовый): ${token}`;
    } catch (err) {
        alert("Ошибка при сохранении секрета. Убедитесь, что Vault разблокирован.");
    }
}

async function getSecret() {
    const k = document.getElementById('secKey').value;
    if (!k) return alert("Введите ключ!");
    try {
        const res = await fetch(`${V_URL}/secrets/${encodeURIComponent(k)}`);
        const data = await res.json();
        if (!res.ok) {
            return alert("Ошибка get: " + (data.detail || "unknown"));
        }
        document.getElementById('secretResult').innerText = `Значение: ${data.value}`;
    } catch (err) {
        alert("Бэкенд Vault не отвечает. Проверь, запущен ли сервер на порту 8003");
    }
}

async function wrapSecret() {
    const v = document.getElementById('wrapVal').value;
    if (!v) return alert("Введите секрет для wrap!");
    try {
        const res = await fetch(`${V_URL}/wrap`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ secret: v })
        });
        const data = await res.json();
        if (!res.ok) return alert("Ошибка wrap: " + (data.detail || "unknown"));
        document.getElementById('wrapToken').value = data.token || "";
        document.getElementById('wrapOutput').innerText = JSON.stringify(data, null, 2);
    } catch (err) {
        alert("Бэкенд Vault не отвечает. Проверь, запущен ли сервер на порту 8003");
    }
}

async function unwrapToken() {
    const token = document.getElementById('wrapToken').value.trim();
    if (!token) return alert("Введите токен!");
    try {
        const res = await fetch(`${V_URL}/unwrap`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ token })
        });
        const data = await res.json();
        if (!res.ok) return alert("Ошибка unwrap: " + (data.detail || "unknown"));
        document.getElementById('wrapOutput').innerText = JSON.stringify(data, null, 2);
    } catch (err) {
        alert("Бэкенд Vault не отвечает. Проверь, запущен ли сервер на порту 8003");
    }
}

async function signFile() {
    const file = document.getElementById('fileInput').files[0];
    const sigAlgo = document.getElementById('sigAlgo')?.value || 'rsa-pss';
    const hashAlgo = document.getElementById('hashAlgo').value;
    if (!file) return alert("Выберите файл!");

    const fd = new FormData();
    fd.append('file', file);

    try {
        const qs = new URLSearchParams();
        qs.set('sig', sigAlgo);
        if (sigAlgo !== 'ed25519') qs.set('hash', hashAlgo);
        const res = await fetch(`${S_URL}/sign?${qs.toString()}`, { 
            method: 'POST', 
            body: fd 
        });
        const data = await res.json();
        document.getElementById('signOutput').innerText = JSON.stringify(data, null, 2);

        // Save metadata as a separate file (document remains unchanged)
        const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `${file.name}.sig.json`;
        document.body.appendChild(a);
        a.click();
        a.remove();
        URL.revokeObjectURL(url);
    } catch (err) {
        alert("Ошибка при подписи файла. Проверь бэкенд на порту 8001");
    }
}

async function verifySignature() {
    const file = document.getElementById('verifyFileInput').files[0];
    const meta = document.getElementById('metaInput').files[0];
    if (!file) return alert("Выберите файл!");
    if (!meta) return alert("Выберите файл метаданных подписи (JSON)!");

    const fd = new FormData();
    fd.append('file', file);
    fd.append('metadata', meta);

    try {
        const res = await fetch(`${S_URL}/verify`, { method: 'POST', body: fd });
        const data = await res.json();
        document.getElementById('verifyOutput').innerText = JSON.stringify(data, null, 2);
    } catch (err) {
        alert("Ошибка при проверке подписи. Проверь бэкенд на порту 8001");
    }
}

async function weakHashCompute() {
    const file = document.getElementById('weakFileInput')?.files?.[0];
    if (!file) return alert("Выберите файл для демо!");
    const fd = new FormData();
    fd.append('file', file);
    try {
        const res = await fetch(`${S_URL}/demo/weak-hash`, { method: 'POST', body: fd });
        const data = await res.json();
        if (!res.ok) return alert("Ошибка: " + (data.detail || "unknown"));
        document.getElementById('weakHashOutput').innerText = JSON.stringify(data, null, 2);
    } catch (e) {
        alert("Signature backend не отвечает. Проверь, запущен ли сервер на порту 8001");
    }
}

async function weakHashForge() {
    const file = document.getElementById('weakFileInput')?.files?.[0];
    if (!file) return alert("Выберите файл для демо!");
    const fd = new FormData();
    fd.append('file', file);
    try {
        const res = await fetch(`${S_URL}/demo/weak-hash/forge`, { method: 'POST', body: fd });
        const data = await res.json();
        if (!res.ok) return alert("Ошибка: " + (data.detail || "unknown"));
        document.getElementById('weakHashOutput').innerText = JSON.stringify(data, null, 2);

        const forged = Uint8Array.from(atob(data.forged_file_b64), c => c.charCodeAt(0));
        downloadBytes(forged, `${file.name}.forged_same_weak_hash.bin`);
    } catch (e) {
        alert("Signature backend не отвечает. Проверь, запущен ли сервер на порту 8001");
    }
}

function downloadBytes(u8, filename) {
    const blob = new Blob([u8], { type: 'application/octet-stream' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
}

// initialize UI state
onSigAlgoChange();