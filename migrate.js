const sqlite3 = require('sqlite3').verbose();
const db = new sqlite3.Database('./carstatus.db');

db.serialize(() => {
  console.log('⏳ Обновление структуры БД...');

  db.run(`
    ALTER TABLE cars ADD COLUMN plate_number TEXT
  `, err => {
    if (err && !err.message.includes('duplicate')) console.log(err.message);
  });

  db.run(`
    ALTER TABLE cars ADD COLUMN plate_normalized TEXT
  `, err => {
    if (err && !err.message.includes('duplicate')) console.log(err.message);
  });

  console.log('✅ Готово');
});

db.close();
