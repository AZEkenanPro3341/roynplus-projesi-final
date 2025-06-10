// generate-keys.js (is_blocked sütunu eklendi)
require('dotenv').config();
const sqlite3 = require('sqlite3').verbose();
const crypto = require('crypto');
const path = require('path');

const dbPath = path.join(process.env.RENDER_DISK_MOUNT_PATH || '.', 'keys.db');
const db = new sqlite3.Database(dbPath);

db.serialize(() => {
    console.log("Tablolar oluşturuluyor...");
    // YENİ SÜTUN EKLENDİ: is_blocked
    db.run(`CREATE TABLE IF NOT EXISTS access_keys (
        id INTEGER PRIMARY KEY,
        key TEXT NOT NULL UNIQUE,
        first_used_at DATETIME DEFAULT NULL,
        login_count INTEGER DEFAULT 0,
        last_login_date TEXT,
        is_blocked INTEGER DEFAULT 0
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS settings (
        id INTEGER PRIMARY KEY,
        setting_key TEXT NOT NULL UNIQUE,
        setting_value TEXT
    )`);

    const settings = [
        ['copy_text', 'Lütfen kopyalanacak metni admin panelinden ayarlayın.'],
        ['tenant_id', ''],
        ['client_id', ''],
        ['client_secret', ''],
        ['target_user_id', '']
    ];
    const settingStmt = db.prepare("INSERT OR IGNORE INTO settings (setting_key, setting_value) VALUES (?, ?)");
    for (const setting of settings) {
        settingStmt.run(setting[0], setting[1]);
    }
    settingStmt.finalize();
    console.log("Başlangıç ayarları eklendi.");

    const keyStmt = db.prepare("INSERT INTO access_keys (key) VALUES (?)");
    console.log("1000 adet yeni anahtar oluşturuluyor...");
    for (let i = 0; i < 1000; i++) {
        keyStmt.run(crypto.randomUUID());
    }
    keyStmt.finalize();
    console.log("Anahtarlar başarıyla oluşturuldu.");
});

db.close();