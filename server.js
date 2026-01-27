const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const db = require('./db');
const normalizePlate = (plate) => {
  if (!plate) return '';
  return plate.toString()
    .toUpperCase()
    .replace(/\s/g, '')
    .replace(/[^A-Z0-9А-Я]/g, ''); // убираем всё кроме букв и цифр
};

const app = express();
const SECRET = process.env.JWT_SECRET || 'supersecret'; // лучше из env
const PORT = process.env.PORT || 5000;

// ✅ CORS и middleware ДОЛЖНЫ быть до маршрутов
app.use(cors({
  origin: process.env.FRONTEND_URL || '*', // для Render можно '*' или конкретный URL фронта
  credentials: true
}));
app.use(bodyParser.json());

// ✅ Health check для Render (он проверяет, жив ли сервис)
app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// ===== Регистрация =====
app.post('/register', async (req, res) => {
  const { login, password } = req.body;
  const hash = await bcrypt.hash(password, 10);

  db.run(`INSERT INTO users (login, password_hash) VALUES (?, ?)`, [login, hash], function(err){
    if(err) return res.status(400).json({error: err.message});
    res.json({message: 'Пользователь создан'});
  });
});

// ===== Вход =====
app.post('/login', (req, res) => {
  const { login, password } = req.body;
  db.get(`SELECT * FROM users WHERE login = ?`, [login], async (err, user) => {
    if(err || !user) return res.status(400).json({error: 'Неверный логин'});

    const match = await bcrypt.compare(password, user.password_hash);
    if(!match) return res.status(400).json({error: 'Неверный пароль'});

    const token = jwt.sign(
      {
        userId: user.id,
        carwashId: user.carwash_id,
        role: user.role
      },
      SECRET,
      { expiresIn: '1d' }
    );
    res.json({token});
  });
});

// ===== Middleware для авторизации =====
const auth = (req, res, next) => {
  const header = req.headers['authorization'];
  if(!header) return res.status(401).json({error: 'Нет токена'});
  const token = header.split(' ')[1];
  jwt.verify(token, SECRET, (err, user) => {
    if(err) return res.status(403).json({error: 'Неверный токен'});
    req.user = user;
    next();
  });
};

// ===== Получение списка авто =====
app.get('/api/operator/cars', auth, (req, res) => {
  const carwashId = req.user.carwashId;

  db.all(
    `SELECT id, brand, plate_number, wait_time, status FROM cars WHERE carwash_id = ?`,
    [carwashId],
    (err, rows) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json(rows);
    }
  );
});


// ===== Оператор: добавить авто =====
app.post('/api/operator/cars', auth, (req, res) => {
  const { plate_number, brand, wait_time } = req.body;
  const carwashId = req.user.carwashId;

  // ✅ Проверка данных
  console.log('Добавление авто:', { plate_number, brand, wait_time, carwashId, user: req.user });
  
  if (!carwashId) {
    return res.status(400).json({ error: 'Нет привязки к автомойке. Перелогиньтесь.' });
  }
  
  if (!plate_number || !brand) {
    return res.status(400).json({ error: 'Номер и марка обязательны' });
  }

  try {
    const normalized = normalizePlate(plate_number);
    
    db.run(
      `INSERT INTO cars 
       (plate_number, plate_normalized, brand, wait_time, status, carwash_id)
       VALUES (?, ?, ?, ?, 'В очереди', ?)`,
      [plate_number, normalized, brand, wait_time || 30, carwashId],
      function (err) {
        if (err) {
          console.error('Ошибка SQL:', err);
          return res.status(500).json({ error: err.message });
        }

        res.json({
          id: this.lastID,
          plate: plate_number,
          status: 'В очереди'
        });
      }
    );
  } catch (error) {
    console.error('Ошибка normalizePlate:', error);
    res.status(500).json({ error: 'Ошибка обработки номера' });
  }
});

// ===== Обновление статуса =====
app.put('/api/operator/cars/:id/status', auth, (req, res) => {
  const carId = req.params.id;
  const { status } = req.body;
  const carwashId = req.user.carwashId;

  if (!status) return res.status(400).json({ error: 'Статус не указан' });

  db.run(
    `UPDATE cars
     SET status = ?
     WHERE id = ? AND carwash_id = ?`,
    [status, carId, carwashId],
    function (err) {
      if (err) return res.status(500).json({ error: err.message });
      if (this.changes === 0)
        return res.status(404).json({ error: 'Авто не найдено или не принадлежит вашей мойке' });

      res.json({ id: carId, status });
    }
  );
});

// ===== Публичный поиск =====
app.get('/api/public/car-status', (req, res) => {
  const { plate } = req.query;
  if (!plate) return res.status(400).json({ error: 'Номер не указан' });

  const normalized = normalizePlate(plate);

  db.get(
    `SELECT plate_number, status
     FROM cars
     WHERE plate_normalized = ?
     ORDER BY id DESC
     LIMIT 1`,
    [normalized],
    (err, row) => {
      if (err) return res.status(500).json({ error: err.message });
      if (!row) return res.status(404).json({ error: 'Не найдено' });

      res.json(row);
    }
  );
});

// ✅ Один правильный вызов listen с process.env.PORT!
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});