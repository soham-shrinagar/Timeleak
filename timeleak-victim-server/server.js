const express = require('express');
const morgan = require('morgan');
const config = require('./config');
const { SECRET } = require('./secrets/secret');
const naiveRoutes = require('./routes/naive');
const safeRoutes = require('./routes/safe');
const createRateLimiter = require('./middleware/rateLimiter');

const app = express();

app.use(express.json());
app.use(morgan('dev'));
app.use(createRateLimiter());

app.use(naiveRoutes);
app.use(safeRoutes);

app.get('/health', (_req, res) => {
  res.json({ status: 'ok' });
});

app.listen(config.PORT, () => {
  console.log('='.repeat(60));
  console.log('TimeLeak Victim Server');
  console.log('='.repeat(60));
  console.log(`Listening on http://localhost:${config.PORT}`);
  console.log(`Secret length: ${config.SECRET_LENGTH}`);
  console.log(`Naive comparison mode: ${config.NAIVE_COMPARISON_MODE}`);
  console.log(`Simulate jitter: ${config.SIMULATE_JITTER} (max ${config.JITTER_MAX_MS}ms)`);
  console.log(`Rate limit: ${config.RATE_LIMIT_ENABLED ? config.RATE_LIMIT_MAX_PER_SECOND + '/s' : 'disabled'}`);
  console.log('');
  console.log('SERVER SECRET (do not use this in your attacker script):');
  console.log(SECRET);
  console.log('='.repeat(60));
});
