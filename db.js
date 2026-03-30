import dotenv from 'dotenv'
import { MongoClient } from 'mongodb'

dotenv.config()

let clientPromise = null
let cachedUri = null

const getMongoUri = () => process.env.MONGODB_URI
const getMongoDbName = () => process.env.MONGODB_DB_NAME || 'sahayak'

export const isMongoConfigured = () => {
  const mongoUri = getMongoUri()
  return Boolean(mongoUri && mongoUri !== 'your_mongodb_connection_string')
}

export const getDb = async () => {
  const mongoUri = getMongoUri()
  if (!isMongoConfigured()) {
    throw new Error('Database not configured')
  }

  if (!clientPromise || cachedUri !== mongoUri) {
    cachedUri = mongoUri
    const client = new MongoClient(mongoUri)
    clientPromise = client.connect()
  }

  const client = await clientPromise
  return client.db(getMongoDbName())
}
