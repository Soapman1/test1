const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');

const app = express();
const SECRET = process.env.JWT_SECRET || 'supersecret';
const PORT = process.env.PORT || 5000;

// ===== ПОДКЛЮЧЕНИЕ К POSTGRESQL =====
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});

// ===== CORS ДЛЯ REACT =====
app.use(cors({
  origin: process.env.FRONTEND_URL || 'https://car-status-frontend.onrender.com', // Укажи свой фронтенд URL
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(bodyParser.json());

// ===== ЛОГИРОВАНИЕ (для отладки) =====
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} - ${req.method} ${req.path}`, req.body);
  next();
});

// ===== ИНИЦИАЛИЗАЦИЯ БАЗЫ =====
const initDB = async () => {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        telegram_id BIGINT UNIQUE,
        login VARCHAR(50) UNIQUE NOT NULL,
        password VARCHAR(100) NOT NULL,
        carwash_name VARCHAR(200),
        owner_name VARCHAR(200),
        subscription_end TIMESTAMP,
        is_active BOOLEAN DEFAULT true,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

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
    console.log('✅ База данных инициализирована');
  } catch (err) {
    console.error('❌ Ошибка инициализации:', err);
  }
};

initDB();

// ===== HELPER ДЛЯ НОМЕРОВ =====
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

app.get('/health', (req, res) => {
  res.json({ status: 'ok', db: 'postgresql' });
});

// ===== РЕГИСТРАЦИЯ (для сайта) =====
app.post('/register', async (req, res) => {
  const { login, password } = req.body;
  
  try {
    const hash = await bcrypt.hash(password, 10);
    const result = await pool.query(
      'INSERT INTO users (login, password, password_hash) VALUES ($1, $2, $3) RETURNING id',
      [login, password, hash]
    );
    res.json({ message: 'Пользователь создан', id: result.rows[0].id });
  } catch (err) {
    console.error('Ошибка регистрации:', err);
    res.status(400).json({ error: 'Логин уже занят или ошибка базы' });
  }
});

// ===== ВХОД =====
app.post('/login', async (req, res) => {
  const { login, password } = req.body;
  
  console.log('Попытка входа:', login); // Debug
  
  try {
    const result = await pool.query('SELECT * FROM users WHERE login = $1', [login]);
    const user = result.rows[0];
    
    if (!user) {
      return res.status(400).json({ error: 'Неверный логин' });
    }

    // Проверка пароля (совместимость с ботом)
    let match = false;
    if (user.password_hash) {
      match = await bcrypt.compare(password, user.password_hash);
    } else {
      // Пароль создан ботом (plain text) - для теста
      match = (password === user.password);
    }
    
    // Дополнительно можно проверить bcrypt hash если есть
    if (!match && user.password.startsWith('$2')) {
      match = await bcrypt.compare(password, user.password);
    }

    if (!match) {
      return res.status(400).json({ error: 'Неверный пароль' });
    }

    // Проверка подписки
    const now = new Date();
    if (!user.subscription_end || new Date(user.subscription_end) < now) {
      return res.status(403).json({ error: 'Подписка истекла. Активируйте через бот.' });
    }

    const token = jwt.sign(
      {
        userId: user.id,
        carwashId: user.id, // Важно: используем id как carwash_id
        login: user.login,
        carwash_name: user.carwash_name
      },
      SECRET,
      { expiresIn: '7d' }
    );
    
    res.json({
      token,
      user: {
        id: user.id,
        login: user.login,
        carwash_name: user.carwash_name
      }
    });
  } catch (err) {
    console.error('Ошибка входа:', err);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

// ===== MIDDLEWARE ПРОВЕРКИ ТОКЕНА =====
const auth = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  
  if (!authHeader) {
    return res.status(403).json({ error: 'Нет заголовка Authorization' });
  }
  
  const token = authHeader.split(' ')[1]; // Bearer TOKEN
  
  if (!token) {
    return res.status(403).json({ error: 'Нет токена' });
  }
  
  try {
    const decoded = jwt.verify(token, SECRET);
    req.user = decoded;
    console.log('Авторизован:', decoded.login); // Debug
    next();
  } catch (err) {
    console.error('Ошибка токена:', err.message);
    return res.status(401).json({ error: 'Неверный токен' });
  }
};

// ===== ПОЛУЧИТЬ СПИСОК АВТО =====
app.get('/api/operator/cars', auth, async (req, res) => {
  const carwashId = req.user.carwashId;
  
  try {
    const result = await pool.query(
      'SELECT id, brand, plate_number, wait_time, status FROM cars WHERE carwash_id = $1 ORDER BY id DESC',
      [carwashId]
    );
    res.json(result.rows);
  } catch (err) {
    console.error('Ошибка получения авто:', err);
    res.status(500).json({ error: err.message });
  }
});

// ===== ДОБАВИТЬ АВТО =====
app.post('/api/operator/cars', auth, async (req, res) => {
  const { plate_number, brand, wait_time } = req.body;
  const carwashId = req.user.carwashId;

  console.log('Добавление авто:', { plate_number, brand, carwashId });

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
       VALUES ($1, $2, $3, $4, 'В очереди', $5) RETURNING id, status`,
      [plate_number, normalized, brand, wait_time || 30, carwashId]
    );

    res.json({
      id: result.rows[0].id,
      plate: plate_number,
      status: result.rows[0].status,
      message: 'Авто добавлено'
    });
  } catch (error) {
    console.error('Ошибка добавления авто:', error);
    res.status(500).json({ error: 'Ошибка базы данных: ' + error.message });
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
    console.error('Ошибка обновления:', err);
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
      `SELECT plate_number, status 
       FROM cars 
       WHERE plate_normalized = $1 AND status != 'Выдано'
       ORDER BY id DESC LIMIT 1`,
      [normalized]
    );
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Авто не найдено' });
    }

    res.json(result.rows[0]);
  } catch (err) {
    console.error('Ошибка поиска:', err);
    res.status(500).json({ error: err.message });
  }
});

// ===== 404 ОБРАБОТЧИК =====
app.use((req, res) => {
  res.status(404).json({ error: 'Endpoint not found' });
});

// ===== ОБРАБОТЧИК ОШИБОК =====
app.use((err, req, res, next) => {
  console.error('Server error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

app.listen(PORT, () => {
  console.log(`✅ Server running on port ${PORT}`);
  console.log(`📝 Environment: ${process.env.NODE_ENV || 'development'}`);
});