const app = require('./src/app');
const db = require('./src/db');

const PORT = process.env.PORT || 3030;

app.listen(PORT, () => {
  console.log(`listening on port ${PORT}`);
});