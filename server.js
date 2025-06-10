// server.js ("Oluştur ve Kopyala" için API rotası eklendi)
require('dotenv').config();
const express = require('express');
const session = require('express-session');
const sqlite3 = require('sqlite3').verbose();
const axios = require('axios');
const path = require('path');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');
const SQLiteStore = require('connect-sqlite3')(session);
const app = express();

const PORT = process.env.PORT || 8000;
const ADMIN_KEY = process.env.ADMIN_KEY || 'BDaP5924';

const dbPath = path.join(process.env.RENDER_DISK_MOUNT_PATH || '.', 'keys.db');
let settings = {};

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.json()); // YENİ: API'den JSON kabul etmek için
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
    store: new SQLiteStore({ db: 'sessions.db', dir: path.dirname(dbPath), table: 'sessions' }),
    secret: 'klavyemden-cıkan-cok-gizli-kelimeler-3',
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 7 * 24 * 60 * 60 * 1000 }
}));

const db = new sqlite3.Database(dbPath, (err) => {
    if (err) { return console.error("Veritabanı bağlantı hatası:", err.message); }
    console.log(`Veritabanı ana bağlantısı başarılı: ${dbPath}`);
    db.configure('busyTimeout', 3000);
    initializeDatabaseAndStartServer();
});

function initializeDatabaseAndStartServer() {
    db.serialize(() => {
        db.run(`CREATE TABLE IF NOT EXISTS access_keys (id INTEGER PRIMARY KEY, key TEXT NOT NULL UNIQUE, first_used_at DATETIME DEFAULT NULL, login_count INTEGER DEFAULT 0, last_login_date TEXT, is_blocked INTEGER DEFAULT 0, daily_limit INTEGER NOT NULL DEFAULT 5)`);
        db.run(`CREATE TABLE IF NOT EXISTS settings (id INTEGER PRIMARY KEY, setting_key TEXT NOT NULL UNIQUE, setting_value TEXT)`);
        const initialSettings = [['copy_text', 'Lütfen kopyalanacak metni admin panelinden ayarlayın.'], ['tenant_id', ''], ['client_id', ''], ['client_secret', ''], ['target_user_id', '']];
        const settingStmt = db.prepare("INSERT OR IGNORE INTO settings (setting_key, setting_value) VALUES (?, ?)");
        initialSettings.forEach(s => settingStmt.run(s[0], s[1]));
        settingStmt.finalize((err) => {
            if (err) { return console.error("Başlangıç ayarları oluşturulamadı:", err); }
            loadSettings((loadErr) => {
                if (loadErr) { console.error("Sunucu başlatılamadı, ayarlar yüklenemedi."); process.exit(1); }
                app.listen(PORT, () => { console.log(`Sunucu ${PORT} numaralı portta başarıyla başlatıldı.`); });
            });
        });
    });
}

function loadSettings(callback) {
    db.all("SELECT setting_key, setting_value FROM settings", [], (err, rows) => {
        if (err) { console.error("AYARLAR YÜKLENEMEDİ:", err.message); return callback(err); }
        rows.forEach(row => { settings[row.setting_key] = row.setting_value; });
        console.log("Ayarlar veritabanından başarıyla yüklendi.");
        callback(null);
    });
}

const loginLimiter = rateLimit({ windowMs: 1 * 60 * 1000, max: 20, message: 'Çok fazla giriş denemesi yapıldı. Lütfen 1 dakika sonra tekrar deneyin.', standardHeaders: true, legacyHeaders: false });

app.get('/', (req, res) => { res.render('login', { error: null }); });

app.post('/login', loginLimiter, (req, res) => {
    const userKey = req.body.key;
    if (userKey === ADMIN_KEY) { req.session.isLoggedIn = true; req.session.isAdmin = true; return res.redirect('/viewer'); }
    const today = new Date().toISOString().split('T')[0];
    db.get("SELECT * FROM access_keys WHERE key = ?", [userKey], (err, row) => {
        if (err) { return res.render('login', { error: 'Bir veritabanı hatası oluştu.' }); }
        if (!row) { return res.render('login', { error: 'Geçersiz anahtar.' }); }
        if (row.is_blocked) { return res.render('login', { error: 'Bu anahtar yönetici tarafından engellenmiştir.' }); }
        let currentLoginCount = row.last_login_date === today ? row.login_count : 0;
        if (currentLoginCount >= row.daily_limit) { return res.render('login', { error: `Bu anahtar için günlük ${row.daily_limit} giriş hakkınız dolmuştur.` }); }
        if (row.first_used_at) {
            const expiryDate = new Date(row.first_used_at);
            expiryDate.setDate(expiryDate.getDate() + 30);
            if (expiryDate < new Date()) { return res.render('login', { error: 'Girdiğiniz anahtarın 30 günlük kullanım süresi dolmuş.' }); }
        }
        const now = row.first_used_at || new Date().toISOString();
        db.run("UPDATE access_keys SET first_used_at = ?, login_count = ?, last_login_date = ? WHERE key = ?", [now, currentLoginCount + 1, today, userKey], (updateErr) => {
            if (updateErr) { return res.render('login', { error: 'Veritabanı güncellenirken bir hata oluştu.' }); }
            req.session.isLoggedIn = true; req.session.isAdmin = false; res.redirect('/viewer');
        });
    });
});

app.get('/viewer', async (req, res) => {
    if (!req.session.isLoggedIn) { return res.redirect('/'); }
    const successMessage = req.session.success_message;
    req.session.success_message = null;
    const searchTerm = req.query.search || '';
    let query = "SELECT * FROM access_keys WHERE first_used_at IS NOT NULL";
    const queryParams = [];
    if (searchTerm) { query += " AND key LIKE ?"; queryParams.push(`%${searchTerm}%`); }
    query += " ORDER BY id DESC";
    const latestEmail = await getLatestEmail();
    if (req.session.isAdmin) {
        db.all(query, queryParams, (err, rows) => {
            if (err) { return res.status(500).send("Anahtarlar çekilirken bir hata oluştu."); }
            res.render('viewer', { email: latestEmail, isAdmin: true, settings, keys: rows, successMessage, searchTerm });
        });
    } else {
        res.render('viewer', { email: latestEmail, isAdmin: false, settings, keys: [], successMessage: null, searchTerm: '' });
    }
});

// YENİ: Anahtar oluşturup JSON döndüren API rotası
app.post('/api/generate-key', (req, res) => {
    if (!req.session.isLoggedIn || !req.session.isAdmin) {
        return res.status(403).json({ success: false, message: 'Bu işlem için yetkiniz yok.' });
    }
    const newKey = crypto.randomUUID();
    db.run("INSERT INTO access_keys (key) VALUES (?)", [newKey], function(err) {
        if (err) {
            console.error("API anahtar oluşturma hatası:", err.message);
            return res.status(500).json({ success: false, message: 'Veritabanı hatası nedeniyle anahtar oluşturulamadı.' });
        }
        res.json({ success: true, newKey: newKey });
    });
});

app.post('/update-limit/:key', (req, res) => {
    if (!req.session.isAdmin) { return res.status(403).send("Yetkiniz yok."); }
    const keyToUpdate = req.params.key;
    const newLimit = parseInt(req.body.new_limit, 10);
    const searchTerm = req.body.searchTerm || '';
    if (isNaN(newLimit) || newLimit < 0) {
        req.session.success_message = "Hata: Geçersiz limit değeri girdiniz.";
        return res.redirect(`/viewer?search=${encodeURIComponent(searchTerm)}`);
    }
    db.run("UPDATE access_keys SET daily_limit = ? WHERE key = ?", [newLimit, keyToUpdate], function(err) {
        if (err) {
            console.error(`!!! LİMİT GÜNCELLEME HATASI (Anahtar: ${keyToUpdate}):`, err.message);
            req.session.success_message = "Hata: Limit güncellenemedi.";
        } else {
            req.session.success_message = "Limit başarıyla güncellendi.";
        }
        res.redirect(`/viewer?search=${encodeURIComponent(searchTerm)}`);
    });
});

app.post('/toggle-block/:key', (req, res) => {
    if (!req.session.isAdmin) { return res.status(403).send("Yetkiniz yok."); }
    const searchTerm = req.body.searchTerm || '';
    db.run("UPDATE access_keys SET is_blocked = NOT is_blocked WHERE key = ?", [req.params.key], (err) => {
        if (err) { return res.status(500).send("İşlem sırasında bir hata oluştu."); }
        res.redirect(`/viewer?search=${encodeURIComponent(searchTerm)}`);
    });
});

app.post('/delete-key/:key', (req, res) => {
    if (!req.session.isAdmin) { return res.status(403).send("Bu işlem için yetkiniz yok."); }
    const searchTerm = req.body.searchTerm || '';
    db.run("DELETE FROM access_keys WHERE key = ?", [req.params.key], function(err) {
        req.session.success_message = err ? "Hata: Anahtar silinemedi." : "Anahtar başarıyla kalıcı olarak silindi.";
        res.redirect(`/viewer?search=${encodeURIComponent(searchTerm)}`);
    });
});

app.post('/update-copy-text', (req, res) => {
    if (!req.session.isAdmin) { return res.status(403).send("Yetkiniz yok."); }
    db.run("UPDATE settings SET setting_value = ? WHERE setting_key = 'copy_text'", [req.body.new_text], (err) => {
        if (err) { return res.status(500).send("Ayar kaydetme hatası"); }
        settings.copy_text = req.body.new_text;
        res.redirect('/viewer');
    });
});

app.post('/update-azure-settings', (req, res) => {
    if (!req.session.isAdmin) { return res.status(403).send("Yetkiniz yok."); }
    const { tenant_id, client_id, client_secret, target_user_id } = req.body;
    const stmt = db.prepare("UPDATE settings SET setting_value = ? WHERE setting_key = ?");
    stmt.run(tenant_id, 'tenant_id'); stmt.run(client_id, 'client_id'); stmt.run(client_secret, 'client_secret'); stmt.run(target_user_id, 'target_user_id');
    stmt.finalize((err) => {
        if (err) { return res.status(500).send("Azure ayarları kaydedilemedi."); }
        loadSettings(() => {
            msGraphToken = { accessToken: null, expiresAt: 0 };
            res.redirect('/viewer');
        });
    });
});

app.get('/logout', (req, res) => { req.session.destroy(() => res.redirect('/')); });

let msGraphToken = { accessToken: null, expiresAt: 0 };
async function getMsGraphToken() { if (msGraphToken.accessToken && Date.now() < msGraphToken.expiresAt) { return msGraphToken.accessToken; } if (!settings.tenant_id || !settings.client_id || !settings.client_secret) { console.log("Azure ayarları eksik, token alınamıyor."); return null; } const tokenUrl = `https://login.microsoftonline.com/${settings.tenant_id}/oauth2/v2.0/token`; const params = new URLSearchParams(); params.append('grant_type', 'client_credentials'); params.append('client_id', settings.client_id); params.append('client_secret', settings.client_secret); params.append('scope', 'https://graph.microsoft.com/.default'); try { const response = await axios.post(tokenUrl, params); msGraphToken.accessToken = response.data.access_token; msGraphToken.expiresAt = Date.now() + (response.data.expires_in - 300) * 1000; console.log("Yeni bir Microsoft Graph API token'ı alındı."); return msGraphToken.accessToken; } catch (error) { console.error("HATA: Microsoft'tan token alınamadı.", error.response?.data); return null; } }
async function getLatestEmail() { const accessToken = await getMsGraphToken(); if (!accessToken) return { error: 'API token alınamadı. Lütfen admin panelinden Azure ayarlarını kontrol edin.' }; if (!settings.target_user_id) return { error: 'Hedef mail adresi admin panelinde ayarlanmamış.' }; const graphUrl = `https://graph.microsoft.com/v1.0/users/${settings.target_user_id}/messages?$filter=from/emailAddress/address eq 'no-reply@account.capcut.com'&$top=20&$select=subject,from,receivedDateTime,body`; try { const response = await axios.get(graphUrl, { headers: { 'Authorization': `Bearer ${accessToken}` } }); const messages = response.data.value; if (messages && messages.length > 0) { messages.sort((a, b) => new Date(b.receivedDateTime) - new Date(a.receivedDateTime)); return messages[0]; } else { return null; } } catch (error) { const errorMessage = error.response?.data?.error?.message || error.message; return { error: `Mail çekilemedi: ${errorMessage}` }; } }