const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const cookieParser = require('cookie-parser');
const path = require('path');

const app = express();
const SECRET = process.env.JWT_SECRET || 'supersecret';
const PORT = process.env.PORT || 5000;


app.use(cookieParser());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ===== ПОДКЛЮЧЕНИЕ К POSTGRESQL =====
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});

// ===== CORS ДЛЯ REACT =====
app.use(cors({
  origin: process.env.FRONTEND_URL || 'https://car-status-frontend.onrender.com', 
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));


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
  const map = {'А':'A','В':'B','Е':'E','К':'K','М':'M','Н':'H','О':'O','Р':'P','С':'C','Т':'T','У':'Y','Х':'X'};
  return plate.toString().toUpperCase().replace(/\s/g, '').replace(/-/g, '').replace(/[АВЕКМНОРСТУХ]/g, char => map[char] || char);
};

// ✅ Новая функция валидации
const isValidPlate = (plate) => {
  if (!plate || plate.length < 3) return false;
  const normalized = normalizePlate(plate);
  // Проверяем что остались только латинские буквы и цифры
  // Если были буквы вроде Д, Ж, Щ, Я и т.д. — они останутся кириллицей и не пройдут проверку
  return /^[A-Z0-9]+$/.test(normalized) && normalized.length >= 3;
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
      'INSERT INTO users (login, password) VALUES ($1, $2) RETURNING id',
      [login, hash]
    );
    res.json({ message: 'Пользователь создан', id: result.rows[0].id });
  } catch (err) {
    console.error('Ошибка регистрации:', err);
    res.status(400).json({ error: 'Логин уже занят или ошибка базы' });
  }
});


// ===== MIDDLEWARE ПРОВЕРКИ ТОКЕНА (с cookie) =====
const auth = (req, res, next) => {
  const token = req.cookies.auth_token;
  
  if (!token) {
    return res.status(401).json({ error: 'Не авторизован' });
  }
  
  try {
    const decoded = jwt.verify(token, SECRET);
    req.user = decoded;
    console.log('Авторизован:', decoded.login);
    next();
  } catch (err) {
    console.error('Ошибка токена:', err.message);
    return res.status(403).json({ error: 'Неверный токен' });
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
  
  if (!carwashId) {
    return res.status(400).json({ error: 'Нет привязки к автомойке' });
  }
  
  // ✅ Валидация номера
  if (!isValidPlate(plate_number)) {
    return res.status(400).json({ 
      error: 'Неверный формат номера. Допустимы только цифры и буквы: А, В, Е, К, М, Н, О, Р, С, Т, У, Х (и латинские аналоги)' 
    });
  }
  
  const normalized = normalizePlate(plate_number);
  const waitTimeNum = parseInt(wait_time) || 30;  // Сначала объявляем!
  const createdAt = new Date();
  const expiresAt = new Date(createdAt.getTime() + waitTimeNum * 60000);  // Потом используем
  
  try {
    const result = await pool.query(
      `INSERT INTO cars (plate_number, plate_normalized, brand, wait_time, status, carwash_id, created_at)
       VALUES ($1, $2, $3, $4, 'В очереди', $5, $6)
       RETURNING id, plate_number, status, wait_time, created_at`,
      [plate_number.toUpperCase(), normalized, brand.toUpperCase(), waitTimeNum, carwashId, createdAt]
    );
    
    // ✅ Возвращаем данные + время истечения (чтобы таймер работал точно)
    res.json({
      ...result.rows[0],
      expires_at: expiresAt.toISOString()
    });
  } catch (err) {
    console.error('Add car error:', err);
    res.status(500).json({ error: err.message });
  }
});

// ===== ОБНОВИТЬ СТАТУС =====
app.put('/api/operator/cars/:id/status', auth, async (req, res) => {
  const carId = req.params.id;
  const { status } = req.body;
  const carwashId = req.user.carwashId;

  if (!status) return res.status(400).json({ error: 'Статус не указан' });

  try {
    // Если статус "Завершено" - удаляем запись полностью
    if (status === 'Завершено') {
      const result = await pool.query(
        'DELETE FROM cars WHERE id = $1 AND carwash_id = $2 RETURNING id, plate_number',
        [carId, carwashId]
      );
      
      if (result.rowCount === 0) {
        return res.status(404).json({ error: 'Авто не найдено' });
      }
      
      console.log(`Авто ${result.rows[0].plate_number} завершено и удалено`);
      return res.json({ id: carId, status: 'Завершено', deleted: true });
    }

    // Обычное обновление статуса
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
  
  // Можно не валидировать при поиске, но если хочешь — раскомментируй:
  // if (!isValidPlate(plate)) return res.status(400).json({ error: 'Неверный формат номера' });
  
  const normalized = normalizePlate(plate);
  
  try {
    const result = await pool.query(
      `SELECT plate_number, status, wait_time, created_at,
              created_at + (wait_time || ' minutes')::interval as expires_at
       FROM cars 
       WHERE plate_normalized = $1 
       ORDER BY created_at DESC 
       LIMIT 1`,
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

// ===== УДАЛИТЬ АВТО =====
app.delete('/api/operator/cars/:id', auth, async (req, res) => {
  const carId = req.params.id;
  const carwashId = req.user.carwashId;

  try {
    const result = await pool.query(
      'DELETE FROM cars WHERE id = $1 AND carwash_id = $2 RETURNING id',
      [carId, carwashId]
    );
    
    if (result.rowCount === 0) {
      return res.status(404).json({ error: 'Авто не найдено' });
    }

    res.json({ message: 'Авто удалено', id: carId });
  } catch (err) {
    console.error('Ошибка удаления:', err);
    res.status(500).json({ error: err.message });
  }
});

// ===== РЕДАКТИРОВАТЬ АВТО =====
app.put('/api/operator/cars/:id', auth, async (req, res) => {
  const carId = req.params.id;
  const { plate_number, brand, wait_time } = req.body;
  const carwashId = req.user.carwashId;

  if (!plate_number || !brand) {
    return res.status(400).json({ error: 'Номер и марка обязательны' });
  }

  // Валидация номера
  if (!isValidPlate(plate_number)) {
    return res.status(400).json({ 
      error: 'Неверный формат номера' 
    });
  }

  const normalized = normalizePlate(plate_number);
  const waitTimeNum = parseInt(wait_time) || 30;

  try {
    const result = await pool.query(
      `UPDATE cars 
       SET plate_number = $1, 
           plate_normalized = $2, 
           brand = $3, 
           wait_time = $4 
       WHERE id = $5 AND carwash_id = $6 
       RETURNING id, plate_number, brand, wait_time, status`,
      [plate_number.toUpperCase(), normalized, brand.toUpperCase(), waitTimeNum, carId, carwashId]
    );
    
    if (result.rowCount === 0) {
      return res.status(404).json({ error: 'Авто не найдено' });
    }

    res.json(result.rows[0]);
  } catch (err) {
    console.error('Ошибка обновления:', err);
    res.status(500).json({ error: err.message });
  }
});


// ===== ВХОД С COOKIE =====
app.post('/login', async (req, res) => {
  const { login, password, rememberMe = false } = req.body;

  if (!login || !password) {
    return res.status(400).json({ error: 'Логин и пароль обязательны' });
  }

  try {
    const result = await pool.query('SELECT * FROM users WHERE login = $1', [login]);
    const user = result.rows[0];

     if (!user) {
      return res.status(400).json({ error: 'Неверный логин или пароль' });
    }

    // ✅ Проверка пароля: сначала как хеш (bcrypt), потом как plain text (для бота)
    let passwordValid = false;
    
    if (user.password.startsWith('$2b$') || user.password.startsWith('$2a$')) {
      // Это bcrypt хеш
      passwordValid = await bcrypt.compare(password, user.password);
    } else {
      // Это plain text пароль от Telegram бота
      passwordValid = (password === user.password);
    }

    if (!passwordValid) {
      return res.status(400).json({ error: 'Неверный логин или пароль' });
    }

    // Проверка подписки
    const now = new Date();
    if (!user.subscription_end || new Date(user.subscription_end) < now) {
      return res.status(403).json({ error: 'Подписка истекла' });
    }

    // Генерация токена
    const token = jwt.sign(
      { userId: user.id, carwashId: user.id, login: user.login, carwash_name: user.carwash_name },
      SECRET,
      { expiresIn: rememberMe ? '7d' : '1h' }
    );

    res.cookie('auth_token', token, {
      httpOnly: true,
      secure: true,
      sameSite: 'none',
      maxAge: rememberMe ? 7 * 24 * 60 * 60 * 1000 : 60 * 60 * 1000
    });

    res.json({ 
      success: true, 
      user: { id: user.id, login: user.login, carwash_name: user.carwash_name } 
    });
  } catch (err) {
    console.error('Ошибка входа:', err);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

// ===== ПРОВЕРКА АДМИНА =====
const isAdmin = (req, res, next) => {
  if (req.user.login !== process.env.ADMIN_LOGIN) {
    return res.status(403).json({ error: 'Нет прав администратора' });
  }
  next();
};

// ===== АДМИН API =====

// Получить всех пользователей
app.get('/api/admin/users', auth, isAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, login, carwash_name, owner_name, subscription_end, is_active, created_at 
       FROM users 
       ORDER BY created_at DESC`
    );
    res.json(result.rows);
  } catch (err) {
    console.error('Ошибка получения пользователей:', err);
    res.status(500).json({ error: err.message });
  }
});

// Удалить пользователя
app.delete('/api/admin/users/:id', auth, isAdmin, async (req, res) => {
  const userId = req.params.id;
  
  try {
    // Нельзя удалить самого себя
    if (parseInt(userId) === req.user.userId) {
      return res.status(400).json({ error: 'Нельзя удалить самого себя' });
    }
    
    await pool.query('DELETE FROM users WHERE id = $1', [userId]);
    res.json({ message: 'Пользователь удален' });
  } catch (err) {
    console.error('Ошибка удаления:', err);
    res.status(500).json({ error: err.message });
  }
});

// Продлить подписку пользователю
app.post('/api/admin/users/:id/extend', auth, isAdmin, async (req, res) => {
  const userId = req.params.id;
  const { days } = req.body;
  
  if (!days || days <= 0) {
    return res.status(400).json({ error: 'Укажите количество дней' });
  }
  
  try {
    const endDate = new Date();
    endDate.setDate(endDate.getDate() + parseInt(days));
    
    await pool.query(
      'UPDATE users SET subscription_end = $1, is_active = true WHERE id = $2',
      [endDate, userId]
    );
    
    res.json({ 
      message: 'Подписка продлена', 
      subscription_end: endDate 
    });
  } catch (err) {
    console.error('Ошибка продления:', err);
    res.status(500).json({ error: err.message });
  }
});

// ===== ПОДДЕРЖКА BROWSER ROUTER =====
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'build', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`✅ Server running on port ${PORT}`);
});

// ===== ВЫХОД (очистка cookie) =====
app.post('/logout', (req, res) => {
  res.clearCookie('auth_token');
  res.json({ success: true });
});

// ===== ПРОВЕРКА СЕССИИ =====
app.get('/me', auth, (req, res) => {
  res.json({ user: req.user });
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