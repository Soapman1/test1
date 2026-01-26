const map = {
  А: 'A',
  В: 'B',
  Е: 'E',
  К: 'K',
  М: 'M',
  Н: 'H',
  О: 'O',
  Р: 'P',
  С: 'C',
  Т: 'T',
  У: 'Y',
  Х: 'X',
};

module.exports = function normalizePlate(input = '') {
  return input
    .toUpperCase()
    .replace(/\s/g, '')
    .split('')
    .map(char => map[char] || char)
    .join('');
};
