const limit = (status) => {
  const strStatus = status.toString().toLowerCase();
  if (strStatus === 'current') return 3;
  if (strStatus === 'library') return 10;
  if (strStatus === 'finished') return 100;
  return null;
};

module.exports = limit;