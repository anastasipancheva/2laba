const V_URL = 'http://localhost:8003';
const S_URL = 'http://localhost:8001';

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

async function saveSecret() {
    const k = document.getElementById('secKey').value;
    const v = document.getElementById('secVal').value;
    
    try {
        const wrapRes = await fetch(`${V_URL}/wrap`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({data: {val: v}})
        });
        const {token} = await wrapRes.json();
        
        await fetch(`${V_URL}/secrets/${k}`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({value: token})
        });
        alert('Секрет зашифрован и сохранен!');
    } catch (err) {
        alert("Ошибка при сохранении секрета. Убедитесь, что Vault разблокирован.");
    }
}

async function signFile() {
    const file = document.getElementById('fileInput').files[0];
    const algo = document.getElementById('algo').value;
    if (!file) return alert("Выберите файл!");

    const fd = new FormData();
    fd.append('file', file);

    try {
        const res = await fetch(`${S_URL}/sign?algorithm=${algo}`, { 
            method: 'POST', 
            body: fd 
        });
        const data = await res.json();
        document.getElementById('signOutput').innerText = JSON.stringify(data, null, 2);
    } catch (err) {
        alert("Ошибка при подписи файла. Проверь бэкенд на порту 8001");
    }
}