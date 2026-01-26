const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const db = new sqlite3.Database(
  path.join(__dirname, 'carstatus.db')
);

// ВАЖНО: serialize гарантирует порядок выполнения
db.serialize(() => {
  // 🏢 Автомойки
  db.run(`
    CREATE TABLE IF NOT EXISTS carwashes (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      owner_name TEXT,
      subscription_until TEXT,
      is_active INTEGER DEFAULT 1
    )
  `);

  // 👤 Пользователи (операторы)
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      login TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT DEFAULT 'operator',
      carwash_id INTEGER,
      is_active INTEGER DEFAULT 1,
      FOREIGN KEY (carwash_id) REFERENCES carwashes(id)
    )
  `);

  // 🚗 Автомобили
  db.run(`
    CREATE TABLE IF NOT EXISTS cars (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      brand TEXT,
      plate_number TEXT NOT NULL,
      wait_time TEXT,
      status TEXT DEFAULT 'В очереди',
      carwash_id INTEGER,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (carwash_id) REFERENCES carwashes(id)
    )
  `);
});

module.exports = db;
