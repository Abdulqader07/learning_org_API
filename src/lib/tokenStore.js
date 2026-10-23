const blackList = [];

function add(token) {
  blackList.push(token);
}

function has(token) {
  return blackList.includes(token);
}

module.exports = { add, has };