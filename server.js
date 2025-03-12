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
    tlsAllowInvalidCertificates: true, // For testing – remove in production
    connectTimeoutMS: 30000,
    socketTimeoutMS: 30000,
    retryWrites: false
  });
  await client.connect();
  cachedClient = client;
  return client;
}

async function getProductsCollection() {
  const client = await getMongoClient();
  const db = client.db(DB_NAME);
  const collection = db.collection("products");
  try {
    // Ensure a text index on productTitle and category
    await collection.createIndex({ productTitle: "text", category: "text" });
  } catch (err) {
    console.error("Error creating index:", err);
  }
  return collection;
}

// Health-check endpoint.
app.get('/api/health', (req, res) => {
  res.json({ status: "ok" });
});

// Search endpoint: search by productTitle and category.
app.get('/api/search', async (req, res) => {
  const query = req.query.q;
  if (!query) {
    return res.status(400).json({ error: "Missing query parameter 'q'" });
  }
  
  // Limit parameter to control number of returned products (default 20)
  const limit = parseInt(req.query.limit, 10) || 20;
  
  try {
    const collection = await getProductsCollection();
    // Use MongoDB's $text operator for full-text search.
    // Also sort by _id in ascending order.
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

// Alternative search endpoint sorting in descending order.
app.get('/api/search1', async (req, res) => {
  const query = req.query.q;
  if (!query) {
    return res.status(400).json({ error: "Missing query parameter 'q'" });
  }
  
  // Limit parameter to control number of returned products (default 20)
  const limit = parseInt(req.query.limit, 10) || 20;
  
  try {
    const collection = await getProductsCollection();
    // Use MongoDB's $text operator for full-text search.
    // Also sort by _id in descending order.
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

// Local development: listen on a port if not in production.
if (process.env.NODE_ENV !== 'production' || require.main === module) {
  const PORT = process.env.PORT || 3001;
  app.listen(PORT, () => {
    console.log(`Server running locally on port ${PORT}`);
  });
}

// Export for serverless deployment.
// Wrap the handler so that context.callbackWaitsForEmptyEventLoop is set to false.
const handler = serverless(app);
module.exports.handler = (event, context, callback) => {
  context.callbackWaitsForEmptyEventLoop = false;
  return handler(event, context, callback);
};
