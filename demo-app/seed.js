const path = require('path');
const dotenv = require('dotenv');
const bcrypt = require('bcryptjs');
const { MongoClient } = require('mongodb');

dotenv.config({ path: path.join(__dirname, '.env') });

const VULN_URI = process.env.VULN_MONGODB_URI || 'mongodb://127.0.0.1:27017/demo_vulnerable';
const SECURE_URI = process.env.SECURE_MONGODB_URI || 'mongodb://127.0.0.1:27017/demo_secure';

const SEED_USERS = [
  { username: 'admin', password: 'Admin@123', role: 'admin', email: 'admin@nodesentinel.local' },
  { username: 'alice', password: 'Alice@123', role: 'user', email: 'alice@nodesentinel.local' },
  { username: 'bob', password: 'Bob@123', role: 'user', email: 'bob@nodesentinel.local' },
];

const SEED_PRODUCTS = [
  { sku: 'NS-001', name: 'Mechanical Keyboard', category: 'Peripherals', price: 89.99, inStock: true },
  { sku: 'NS-002', name: 'USB-C Docking Station', category: 'Accessories', price: 119.50, inStock: true },
  { sku: 'NS-003', name: '27-Inch 4K Monitor', category: 'Displays', price: 349.00, inStock: true },
  { sku: 'NS-004', name: 'Ergonomic Wireless Mouse', category: 'Peripherals', price: 54.00, inStock: true },
  { sku: 'NS-005', name: 'Noise Cancelling Headphones', category: 'Audio', price: 199.99, inStock: true },
  { sku: 'NS-006', name: '1TB NVMe SSD', category: 'Storage', price: 94.99, inStock: true },
  { sku: 'NS-007', name: 'HD Conference Webcam', category: 'Peripherals', price: 69.95, inStock: true },
  { sku: 'NS-008', name: 'Laptop Aluminum Stand', category: 'Accessories', price: 39.00, inStock: true },
  { sku: 'NS-009', name: 'Wi-Fi 6E Mesh Router', category: 'Networking', price: 159.00, inStock: false },
  { sku: 'NS-010', name: 'USB Condenser Microphone', category: 'Audio', price: 129.00, inStock: true },
];

async function seedDatabase(uri, { hashPasswords }) {
  const client = new MongoClient(uri, { serverSelectionTimeoutMS: 5000 });
  try {
    await client.connect();
    const db = client.db();
    const usersCol = db.collection('users');
    const productsCol = db.collection('products');

    await usersCol.deleteMany({});
    await productsCol.deleteMany({});

    const userDocs = [];
    for (const u of SEED_USERS) {
      if (hashPasswords) {
        const passwordHash = await bcrypt.hash(u.password, 10);
        userDocs.push({
          username: u.username,
          passwordHash,
          role: u.role,
          email: u.email,
          failedLoginAttempts: 0,
          lockUntil: null,
          createdAt: new Date(),
        });
      } else {
        // Intentionally stores plaintext password in the vulnerable test database
        userDocs.push({
          username: u.username,
          password: u.password,
          role: u.role,
          email: u.email,
          createdAt: new Date(),
        });
      }
    }

    await usersCol.insertMany(userDocs);
    await usersCol.createIndex({ username: 1 }, { unique: true });

    await productsCol.insertMany(
      SEED_PRODUCTS.map((p) => ({ ...p, createdAt: new Date() }))
    );
    await productsCol.createIndex({ sku: 1 }, { unique: true });

    console.log(
      `[seed] Seeded '${db.databaseName}': ${userDocs.length} users, ${SEED_PRODUCTS.length} products.`
    );
  } finally {
    await client.close();
  }
}

async function main() {
  console.log('[seed] Seeding vulnerable and secure MongoDB databases...');
  await seedDatabase(VULN_URI, { hashPasswords: false });
  await seedDatabase(SECURE_URI, { hashPasswords: true });
  console.log('[seed] Done.');
}

main().catch((err) => {
  console.error('[seed] Failed to seed databases:', err.message);
  process.exit(1);
});
