import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import { analyzeUrl } from './analyzer';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3001;

app.use(cors({ origin: ['http://localhost:3000', 'http://127.0.0.1:3000'] }));
app.use(express.json());

app.post('/api/analyze', async (req, res) => {
  const { url } = req.body;

  if (!url || typeof url !== 'string') {
    res.status(400).json({ error: 'URL is required' });
    return;
  }

  if (url.length > 2048) {
    res.status(400).json({ error: 'URL is too long' });
    return;
  }

  try {
    const result = await analyzeUrl(url);
    res.json(result);
  } catch (e: any) {
    console.error('Analysis error:', e);
    res.status(500).json({ error: 'Analysis failed' });
  }
});

app.listen(PORT, () => {
  console.log(`TrustLens API server running on http://localhost:${PORT}`);
});
