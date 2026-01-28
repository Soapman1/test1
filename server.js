const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg'); // ← PostgreSQL драйвер

const app = express();
const SECRET = process.env.JWT_SECRET || 'supersecret';
const PORT = process.env.PORT || 5000;

// ===== ПОДКЛЮЧЕНИЕ К POSTGRESQL =====
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false // Обязательно для Render
  }
});

// Инициализация таблиц (создаем если нет)
const initDB = async () => {
  try {
    // Таблица users (совместимая с ботом)
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        telegram_id BIGINT UNIQUE,
        login VARCHAR(50) UNIQUE NOT NULL,
        password VARCHAR(100) NOT NULL, -- бот создает без хеша, сайт может хешировать при необходимости
        password_hash VARCHAR(100), -- для совместимости если сайт хочет хешировать
        carwash_name VARCHAR(200),
        owner_name VARCHAR(200),
        subscription_end TIMESTAMP,
        is_active BOOLEAN DEFAULT true,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Таблица cars (твоя существующая)
    await pool.query(`
      CREATE TABLE IF NOT EXISTS cars (
        id SERIAL PRIMARY KEY,
        plate_number VARCHAR(50),
        plate_normalized VARCHAR(50),
        brand VARCHAR(100),
        wait_time INTEGER,
        status VARCHAR(50),
        carwash_id INTEGER REFERENCES users(id),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    console.log('✅ Database tables ready');
  } catch (err) {
    console.error('❌ Database init error:', err);
  }
};

initDB();

// ===== НОРМАЛИЗАЦИЯ НОМЕРА =====
const normalizePlate = (plate) => {
  if (!plate) return '';
  return plate.toString()
    .toUpperCase()
    .replace(/\s/g, '')
    .replace(/-/g, '')
    .replace(/[А]/g, 'A')
    .replace(/[В]/g, 'B')
    .replace(/[Е]/g, 'E')
    .replace(/[К]/g, 'K')
    .replace(/[М]/g, 'M')
    .replace(/[Н]/g, 'H')
    .replace(/[О]/g, 'O')
    .replace(/[Р]/g, 'P')
    .replace(/[С]/g, 'C')
    .replace(/[Т]/g, 'T')
    .replace(/[У]/g, 'Y')
    .replace(/[Х]/g, 'X');
};

// ===== MIDDLEWARE =====
app.use(cors({
  origin: process.env.FRONTEND_URL || '*',
  credentials: true
}));
app.use(bodyParser.json());

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// ===== РЕГИСТРАЦИЯ (для сайта, если нужно) =====
app.post('/register', async (req, res) => {
  const { login, password, carwash_name, owner_name } = req.body;
  
  try {
    // Проверяем существует ли
    const check = await pool.query('SELECT * FROM users WHERE login = $1', [login]);
    if (check.rows.length > 0) {
      return res.status(400).json({error: 'Логин уже занят'});
    }

    // Хешируем пароль (если регистрация через сайт)
    const hash = await bcrypt.hash(password, 10);
    
    const result = await pool.query(
      `INSERT INTO users (login, password, password_hash, carwash_name, owner_name) 
       VALUES ($1, $2, $3, $4, $5) RETURNING id`,
      [login, password, hash, carwash_name, owner_name]
    );
    
    res.json({message: 'Пользователь создан', id: result.rows[0].id});
  } catch (err) {
    console.error(err);
    res.status(500).json({error: err.message});
  }
});

// ===== ВХОД =====
app.post('/login', async (req, res) => {
  const { login, password } = req.body;
  
  try {
    const result = await pool.query('SELECT * FROM users WHERE login = $1', [login]);
    const user = result.rows[0];
    
    if (!user) return res.status(400).json({error: 'Неверный логин'});

    // Проверяем пароль (может быть в password или password_hash)
    let match = false;
    if (user.password_hash) {
      match = await bcrypt.compare(password, user.password_hash);
    } else {
      // Если бот создал без хеша (для теста)
      match = (password === user.password);
    }

    if (!match) return res.status(400).json({error: 'Неверный пароль'});

    // Проверка подписки
    const now = new Date();
    const subEnd = user.subscription_end ? new Date(user.subscription_end) : null;
    
    if (!subEnd || subEnd < now) {
      return res.status(403).json({error: 'Подписка истекла или не активирована'});
    }

    const token = jwt.sign(
      {
        userId: user.id,
        carwashId: user.id, // используем id как carwash_id
        role: 'owner'
      },
      SECRET,
      { expiresIn: '1d' }
    );
    
    res.json({
      token, 
      carwash_name: user.carwash_name,
      subscription_end: user.subscription_end
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({error: err.message});
  }
});

// ===== MIDDLEWARE =====
const auth = (req, res, next) => {
  const header = req.headers['authorization'];
  if (!header) return res.status(401).json({error: 'Нет токена'});
  
  const token = header.split(' ')[1];
  jwt.verify(token, SECRET, (err, user) => {
    if (err) return res.status(403).json({error: 'Неверный токен'});
    req.user = user;
    next();
  });
};

// ===== СПИСОК АВТО =====
app.get('/api/operator/cars', auth, async (req, res) => {
  const carwashId = req.user.carwashId;
  
  try {
    const result = await pool.query(
      'SELECT id, brand, plate_number, wait_time, status FROM cars WHERE carwash_id = $1 ORDER BY id DESC',
      [carwashId]
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ===== ДОБАВИТЬ АВТО =====
app.post('/api/operator/cars', auth, async (req, res) => {
  const { plate_number, brand, wait_time } = req.body;
  const carwashId = req.user.carwashId;

  if (!carwashId) {
    return res.status(400).json({ error: 'Нет привязки к автомойке' });
  }
  
  if (!plate_number || !brand) {
    return res.status(400).json({ error: 'Номер и марка обязательны' });
  }

  try {
    const normalized = normalizePlate(plate_number);
    
    const result = await pool.query(
      `INSERT INTO cars (plate_number, plate_normalized, brand, wait_time, status, carwash_id)
       VALUES ($1, $2, $3, $4, 'В очереди', $5) RETURNING id`,
      [plate_number, normalized, brand, wait_time || 30, carwashId]
    );

    res.json({
      id: result.rows[0].id,
      plate: plate_number,
      status: 'В очереди'
    });
  } catch (error) {
    console.error('Ошибка добавления:', error);
    res.status(500).json({ error: error.message });
  }
});

// ===== ОБНОВИТЬ СТАТУС =====
app.put('/api/operator/cars/:id/status', auth, async (req, res) => {
  const carId = req.params.id;
  const { status } = req.body;
  const carwashId = req.user.carwashId;

  if (!status) return res.status(400).json({ error: 'Статус не указан' });

  try {
    const result = await pool.query(
      'UPDATE cars SET status = $1 WHERE id = $2 AND carwash_id = $3 RETURNING id',
      [status, carId, carwashId]
    );
    
    if (result.rowCount === 0) {
      return res.status(404).json({ error: 'Авто не найдено' });
    }

    res.json({ id: carId, status });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ===== ПУБЛИЧНЫЙ ПОИСК =====
app.get('/api/public/car-status', async (req, res) => {
  const { plate } = req.query;
  if (!plate) return res.status(400).json({ error: 'Номер не указан' });

  const normalized = normalizePlate(plate);

  try {
    const result = await pool.query(
      `SELECT plate_number, status FROM cars 
       WHERE plate_normalized = $1 
       ORDER BY id DESC LIMIT 1`,
      [normalized]
    );
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Не найдено' });
    }

    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ===== ЗАПУСК =====
app.listen(PORT, () => {
  console.log(`✅ Server running on port ${PORT}`);
});