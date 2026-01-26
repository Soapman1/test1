const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const db = require('./db');


const app = express();
const SECRET = 'supersecret'; // для JWT
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));

app.use(cors());
app.use(bodyParser.json());


// ===== Регистрация (только для админа, можно добавить вручную) =====
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

// =====================
// ОПЕРАТОР: добавить авто
const normalizePlate = require('./utils/normalizePlate');

app.post('/api/operator/cars', auth, (req, res) => {
  const { plate, brand, wait_time } = req.body;
  const carwashId = req.user.carwashId;

  const normalized = normalizePlate(plate);

  db.run(
    `INSERT INTO cars 
     (plate_original, plate_normalized, brand, wait_time, status, carwash_id)
     VALUES (?, ?, ?, ?, 'В очереди', ?)`,
    [plate, normalized, brand, wait_time, carwashId],
    function (err) {
      if (err) return res.status(500).json({ error: err.message });

      res.json({
        id: this.lastID,
        plate: plate,
        status: 'В очереди'
      });
    }
  );
});


app.put('/api/operator/cars/:id/status', auth, (req, res) => {
  const carId = req.params.id;
  const { status } = req.body;
  const carwashId = req.user.carwashId; // оператор видит только свои авто

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

// =====================
// ПУБЛИЧНЫЙ: клиент ищет авто
const normalizePlate = require('./utils/normalizePlate');

app.get('/api/public/car-status', (req, res) => {
  const { plate } = req.query;
  if (!plate) return res.status(400).json({ error: 'Номер не указан' });

  const normalized = normalizePlate(plate);

  db.get(
    `SELECT plate_original AS plate_number, status
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


app.listen(5000, () => console.log('Server running on port 5000'));