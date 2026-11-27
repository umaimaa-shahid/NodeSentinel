const { MongoClient } = require('mongodb');

const DEFAULT_URI = 'mongodb://127.0.0.1:27017/demo_secure';

let client = null;
let db = null;

async function connectDB() {
  if (db) {
    return db;
  }

  const uri = process.env.MONGODB_URI || process.env.SECURE_MONGODB_URI || DEFAULT_URI;
  client = new MongoClient(uri, { serverSelectionTimeoutMS: 5000 });
  await client.connect();
  db = client.db();
  console.log(`[secure] Connected to MongoDB: ${db.databaseName}`);
  return db;
}

function getDB() {
  if (!db) {
    throw new Error('Database not connected. Call connectDB() first.');
  }
  return db;
}

async function closeDB() {
  if (client) {
    await client.close();
    client = null;
    db = null;
  }
}

module.exports = { connectDB, getDB, closeDB };
