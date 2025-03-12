const express = require('express');
const { MongoClient } = require('mongodb');
const serverless = require('serverless-http');
require('dotenv').config();
const cors = require("cors");

const app = express();
app.use(cors());
app.use(express.json());

const MONGODB_URL = process.env.MONGODB_URL; // e.g., set in .env
const DB_NAME = process.env.DB_NAME || "naivasProducts";

// Global cache for the MongoDB client
let cachedClient = null;

async function getMongoClient() {
  if (cachedClient) return cachedClient;
  const client = new MongoClient(MONGODB_URL, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
    tls: true,
    // Allow invalid certs in non-production environments only
    tlsAllowInvalidCertificates: process.env.NODE_ENV !== 'production',
    connectTimeoutMS: 5000,
    socketTimeoutMS: 5000,
    retryWrites: false
  });
  await client.connect();
  cachedClient = client;
  return client;
}

async function getProductsCollection() {
  const client = await getMongoClient();
  const db = client.db(DB_NAME);
  return db.collection("products");
}

// Create the text index once on cold start
(async () => {
  try {
    const client = await getMongoClient();
    const db = client.db(DB_NAME);
    const collection = db.collection("products");
    await collection.createIndex({ productTitle: "text", category: "text" });
    console.log("Index created successfully");
  } catch (err) {
    console.error("Error creating index:", err);
  }
})();

// Health-check endpoint.
app.get('/api/health', (req, res) => {
  res.json({ status: "ok" });
});

// Search endpoint: sort by _id in ascending order.
app.get('/api/search', async (req, res) => {
  const query = req.query.q;
  if (!query) return res.status(400).json({ error: "Missing query parameter 'q'" });
  const limit = parseInt(req.query.limit, 10) || 20;
  try {
    const collection = await getProductsCollection();
    const results = await collection.find({ $text: { $search: query } })
      .sort({ _id: 1 })
      .limit(limit)
      .toArray();
    res.json(results);
  } catch (err) {
    console.error("Error during search:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Alternative search endpoint: sort by _id in descending order.
app.get('/api/search1', async (req, res) => {
  const query = req.query.q;
  if (!query) return res.status(400).json({ error: "Missing query parameter 'q'" });
  const limit = parseInt(req.query.limit, 10) || 20;
  try {
    const collection = await getProductsCollection();
    const results = await collection.find({ $text: { $search: query } })
      .sort({ _id: -1 })
      .limit(limit)
      .toArray();
    res.json(results);
  } catch (err) {
    console.error("Error during search:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// For local development: listen on a port if not in production.
if (process.env.NODE_ENV !== 'production' || require.main === module) {
  const PORT = process.env.PORT || 3001;
  app.listen(PORT, () => {
    console.log(`Server running locally on port ${PORT}`);
  });
}

// Export default handler for serverless deployment.
// We set callbackWaitsForEmptyEventLoop to false so that open connections don't delay the response.
const handler = serverless(app);
module.exports = (event, context, callback) => {
  context.callbackWaitsForEmptyEventLoop = false;
  return handler(event, context, callback);
};
