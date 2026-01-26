const db = require('./db');
const bcrypt = require('bcrypt');


// список операторов, которых нужно добавить
const users = [
{ login: 'operator1', password: '1234' },
{ login: 'operator2', password: 'pass123' },
{ login: 'operator3', password: 'qwerty' }
];


const addUsers = async () => {
for(const user of users){
const hash = await bcrypt.hash(user.password, 10);
db.run(`INSERT INTO users (login, password_hash) VALUES (?, ?)`, [user.login, hash], function(err){
if(err){
console.log(`Ошибка при добавлении ${user.login}:`, err.message);
} else {
console.log(`Пользователь ${user.login} добавлен`);
}
});
}
};


addUsers().then(() => {
console.log('Все пользователи обработаны');
process.exit();
});