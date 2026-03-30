import dotenv from 'dotenv'
import { getDb, isMongoConfigured } from './db.js'

dotenv.config()

if (!isMongoConfigured()) {
  console.error('MONGODB_URI is not configured.')
  process.exit(1)
}

try {
  const db = await getDb()
  await db.command({ ping: 1 })
  console.log(`MongoDB connected to database "${db.databaseName}".`)
} catch (error) {
  console.error(`MongoDB connection failed: ${error.message}`)
  process.exit(1)
}
