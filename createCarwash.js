const db = require('./db');
const bcrypt = require('bcrypt');
const crypto = require('crypto');

function randomPassword() {
  return crypto.randomBytes(4).toString('hex');
}

async function createCarwash(name, owner) {
  const password = randomPassword();
  const hash = await bcrypt.hash(password, 10);

  db.run(
    `INSERT INTO carwashes (name, owner_name, subscription_until)
     VALUES (?, ?, datetime('now', '+30 days'))`,
    [name, owner],
    function () {
      const carwashId = this.lastID;
      const login = name.toLowerCase().replace(/\s/g, '');

      db.run(
        `INSERT INTO users (login, password_hash, role, carwash_id)
         VALUES (?, ?, 'admin', ?)`,
        [login, hash, carwashId]
      );

      console.log('=== АВТОМОЙКА СОЗДАНА ===');
      console.log('Логин:', login);
      console.log('Пароль:', password);
      console.log('Действует до: +30 дней');
    }
  );
}

// ⚠️ ИЗМЕНИ ЗНАЧЕНИЯ
createCarwash('MyCarWash1', 'Иван');
