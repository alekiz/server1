const express = require('express');
const { MongoClient } = require('mongodb');
const serverless = require('serverless-http');
require('dotenv').config();
const cors = require('cors');

const app = express();
app.use(cors());
app.use(express.json());

// Use the environment variable if set; otherwise, use the provided connection string.
const MONGODB_URL =
  process.env.MONGODB_URL ||
  'mongodb+srv://alexmutugi257:Ajib2536@cluster0.d0acd.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0';
const DB_NAME = process.env.DB_NAME || 'naivasProducts';

// Global cache for the MongoDB client.
let cachedClient = null;

async function getMongoClient() {
  if (cachedClient) return cachedClient;
  const client = new MongoClient(MONGODB_URL, {
    // These options help the connection fail fast if needed.
    useNewUrlParser: true,
    useUnifiedTopology: true,
    tls: true,
    // Allow invalid certificates in non-production only.
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
  const collection = db.collection('products');
  try {
    // Create a text index on productTitle and category on cold start.
    await collection.createIndex({ productTitle: 'text', category: 'text' });
    console.log('Index created successfully.');
  } catch (err) {
    console.error('Error creating index:', err);
  }
  return collection;
}

// Health-check endpoint.
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok' });
});

// Search endpoint: sorts by _id ascending.
app.get('/api/search', async (req, res) => {
  const query = req.query.q;
  if (!query) {
    return res.status(400).json({ error: "Missing query parameter 'q'" });
  }
  
  // Limit parameter to control number of returned products (default 20).
  const limit = parseInt(req.query.limit, 10) || 20;
  
  try {
    const collection = await getProductsCollection();
    const results = await collection.find({ $text: { $search: query } })
      .sort({ _id: 1 })
      .limit(limit)
      .toArray();
    res.json(results);
  } catch (err) {
    console.error('Error during search:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Alternative search endpoint: sorts by _id descending.
app.get('/api/search1', async (req, res) => {
  const query = req.query.q;
  if (!query) {
    return res.status(400).json({ error: "Missing query parameter 'q'" });
  }
  
  const limit = parseInt(req.query.limit, 10) || 20;
  
  try {
    const collection = await getProductsCollection();
    const results = await collection.find({ $text: { $search: query } })
      .sort({ _id: -1 })
      .limit(limit)
      .toArray();
    res.json(results);
  } catch (err) {
    console.error('Error during search:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// For local development: listen on a port if not in production.
if (process.env.NODE_ENV !== 'production' || require.main === module) {
  const PORT = process.env.PORT || 3001;
  app.listen(PORT, () => {
    console.log(`Server running locally on port ${PORT}`);
  });
}

// Export a default handler for serverless deployment.
// Set callbackWaitsForEmptyEventLoop to false to prevent timeouts.
const handler = serverless(app);
module.exports = (event, context, callback) => {
  context.callbackWaitsForEmptyEventLoop = false;
  return handler(event, context, callback);
};
const express = require('express');
const { MongoClient } = require('mongodb');
const serverless = require('serverless-http');
require('dotenv').config();
const cors = require("cors");

const app = express();
app.use(cors());
app.use(express.json());

// Ensure the connection string is defined
const MONGODB_URL = process.env.MONGODB_URL;
if (!MONGODB_URL) {
  console.error("MONGODB_URL is not defined. Please set it in your environment variables.");
  throw new Error("MONGODB_URL environment variable is not set.");
}

const DB_NAME = process.env.DB_NAME || "naivasProducts";

// Global cache for the MongoDB client
let cachedClient = null;

async function getMongoClient() {
  if (cachedClient) return cachedClient;
  const client = new MongoClient(MONGODB_URL, {
    // These options set a shorter timeout to avoid long waits.
    // Note: useNewUrlParser and useUnifiedTopology are defaults in v4+.
    tls: true,
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
  const collection = db.collection("products");
  try {
    // Create a text index only once on cold start.
    await collection.createIndex({ productTitle: "text", category: "text" });
    console.log("Index created successfully.");
  } catch (err) {
    console.error("Error creating index:", err);
  }
  return collection;
}

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

// For local development, listen on a port if not in production.
if (process.env.NODE_ENV !== 'production' || require.main === module) {
  const PORT = process.env.PORT || 3001;
  app.listen(PORT, () => {
    console.log(`Server running locally on port ${PORT}`);
  });
}

// Wrap the serverless handler so that callbackWaitsForEmptyEventLoop is false.
const handler = serverless(app);
module.exports = (event, context, callback) => {
  context.callbackWaitsForEmptyEventLoop = false;
  return handler(event, context, callback);
};
