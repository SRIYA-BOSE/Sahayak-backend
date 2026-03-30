import express from 'express'
import cors from 'cors'
import dotenv from 'dotenv'
import OpenAI from 'openai'
import axios from 'axios'
import bcrypt from 'bcryptjs'
import jwt from 'jsonwebtoken'
import { ObjectId } from 'mongodb'
import { getDb, isMongoConfigured } from './db.js'

dotenv.config()

const DEFAULT_AI_MODEL = process.env.DEFAULT_AI_MODEL || 'gpt-5-mini'
const JWT_SECRET = process.env.JWT_SECRET || 'change-me-in-production'
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '7d'

let openai = null
if (process.env.OPENAI_API_KEY) {
  try {
    openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY })
  } catch (error) {
    console.warn('OpenAI initialization failed:', error.message)
  }
}

const buildVoiceFallback = (message = '') => {
  const lowerMessage = String(message || '').toLowerCase()

  if (lowerMessage.includes('safety')) {
    return 'Wear your helmet, gloves, shoes, and reflective gear, and report hazards immediately.'
  }

  if (lowerMessage.includes('emergency')) {
    return 'In an emergency, call 108, alert nearby people, and move to a safe area if possible.'
  }

  if (lowerMessage.includes('weather')) {
    return 'Check heat, rain, and wind before work, and take extra water and rest breaks in hot weather.'
  }

  return 'Ask about safety, health, emergency help, weather, work guidance, or sensor usage.'
}

const generateWorkerDataset = () => {
  const workers = []
  const random = (min, max) => Math.random() * (max - min) + min

  for (let i = 1; i <= 100; i += 1) {
    workers.push({
      worker_id: i,
      oxygen_level: Number(random(90.8, 99.7).toFixed(1)),
      heart_rate: Math.round(random(62, 109)),
      temperature: Number(random(35.7, 38.54).toFixed(2)),
      bp_systolic: Math.round(random(94, 146)),
      bp_diastolic: Math.round(random(61, 104)),
      respiration_rate: Number(random(13.1, 22.5).toFixed(1)),
    })
  }

  return workers
}

const normalizeId = (value) => (value instanceof ObjectId ? value.toString() : String(value))
const serializeDocument = (item) => (item ? { ...item, id: normalizeId(item._id), _id: undefined } : null)
const serializeDocuments = (items = []) => items.map(serializeDocument)
const toObjectId = (value) => (ObjectId.isValid(value) ? new ObjectId(value) : null)
const isValidEmail = (value) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(value || '').trim())

const sanitizeUser = (user = {}) => ({
  id: normalizeId(user._id),
  email: user.email,
  created_at: user.createdAt,
  updated_at: user.updatedAt,
  user_metadata: {
    name: user.name || '',
    phone: user.phone || '',
    language: user.language || 'en',
  },
})

const sanitizeProfile = (user = {}) => ({
  id: normalizeId(user._id),
  name: user.name || '',
  phone: user.phone || '',
  language: user.language || 'en',
  created_at: user.createdAt,
  updated_at: user.updatedAt,
})

const buildSession = (user) => {
  const accessToken = jwt.sign({ sub: normalizeId(user._id), email: user.email }, JWT_SECRET, {
    expiresIn: JWT_EXPIRES_IN,
  })

  return {
    access_token: accessToken,
    token_type: 'bearer',
    expires_in: JWT_EXPIRES_IN,
  }
}

const buildRegex = (value) => new RegExp(String(value).replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'i')

const verifyToken = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ success: false, error: 'No token provided' })
    }

    if (!isMongoConfigured()) {
      return res.status(503).json({ success: false, error: 'Database not configured' })
    }

    const token = authHeader.split(' ')[1]
    const decoded = jwt.verify(token, JWT_SECRET)
    const db = await getDb()
    const user = await db.collection('users').findOne({ _id: new ObjectId(decoded.sub) })

    if (!user) {
      return res.status(401).json({ success: false, error: 'Invalid token' })
    }

    req.user = sanitizeUser(user)
    req.userDoc = user
    next()
  } catch (error) {
    res.status(401).json({ success: false, error: 'Token verification failed' })
  }
}

export const createBaseApp = ({ arduinoRoutes = false, arduinoService = null } = {}) => {
  const app = express()

  app.use(cors())
  app.use(express.json())

  app.get('/api/health', async (_req, res) => {
    let mongodb = false
    if (isMongoConfigured()) {
      try {
        const db = await getDb()
        await db.command({ ping: 1 })
        mongodb = true
      } catch {
        mongodb = false
      }
    }

    res.json({
      status: 'ok',
      message: 'SAHAYAK API is running',
      mongodb,
      mode: arduinoRoutes ? 'local' : 'serverless',
    })
  })

  app.post('/api/auth/signup', async (req, res) => {
    try {
      if (!isMongoConfigured()) {
        return res.status(503).json({ success: false, error: 'Database not configured' })
      }

      const { email, password, name, phone, language } = req.body
      if (!email || !password) {
        return res.status(400).json({ success: false, error: 'Email and password are required' })
      }
      if (!isValidEmail(email)) {
        return res.status(400).json({ success: false, error: 'Please enter a valid email address' })
      }
      if (String(password).length < 6) {
        return res.status(400).json({ success: false, error: 'Password must be at least 6 characters' })
      }

      const db = await getDb()
      const users = db.collection('users')
      const existingUser = await users.findOne({ email: String(email).toLowerCase() })

      if (existingUser) {
        return res.status(400).json({ success: false, error: 'User already exists' })
      }

      const now = new Date().toISOString()
      const passwordHash = await bcrypt.hash(password, 10)
      const userDoc = {
        email: String(email).toLowerCase(),
        passwordHash,
        name: name || '',
        phone: phone || '',
        language: language || 'en',
        createdAt: now,
        updatedAt: now,
      }

      const result = await users.insertOne(userDoc)
      const user = { ...userDoc, _id: result.insertedId }
      const session = buildSession(user)

      res.json({
        success: true,
        data: {
          user: sanitizeUser(user),
          session,
          profile: sanitizeProfile(user),
        },
      })
    } catch (error) {
      res.status(500).json({ success: false, error: error.message })
    }
  })

  app.post('/api/auth/signin', async (req, res) => {
    try {
      if (!isMongoConfigured()) {
        return res.status(503).json({ success: false, error: 'Database not configured' })
      }

      const { email, password } = req.body
      if (!email || !password) {
        return res.status(400).json({ success: false, error: 'Email and password are required' })
      }

      const db = await getDb()
      const user = await db.collection('users').findOne({ email: String(email).toLowerCase() })

      if (!user) {
        return res.status(401).json({ success: false, error: 'Invalid email or password' })
      }

      const passwordMatches = await bcrypt.compare(password, user.passwordHash || '')
      if (!passwordMatches) {
        return res.status(401).json({ success: false, error: 'Invalid email or password' })
      }

      res.json({
        success: true,
        data: {
          user: sanitizeUser(user),
          session: buildSession(user),
          profile: sanitizeProfile(user),
        },
      })
    } catch (error) {
      res.status(500).json({ success: false, error: error.message })
    }
  })

  app.get('/api/auth/user', verifyToken, async (_req, res) => {
    try {
      res.json({
        success: true,
        data: {
          user: _req.user,
          profile: sanitizeProfile(_req.userDoc),
        },
      })
    } catch (error) {
      res.status(500).json({ success: false, error: error.message })
    }
  })

  app.post('/api/auth/signout', verifyToken, async (_req, res) => {
    res.json({ success: true, error: null })
  })

  app.put('/api/auth/profile', verifyToken, async (req, res) => {
    try {
      const db = await getDb()
      const updateDoc = {
        name: req.body.name || '',
        phone: req.body.phone || '',
        language: req.body.language || 'en',
        updatedAt: new Date().toISOString(),
      }

      await db.collection('users').updateOne({ _id: req.userDoc._id }, { $set: updateDoc })
      const updatedUser = await db.collection('users').findOne({ _id: req.userDoc._id })

      res.json({ success: true, data: sanitizeProfile(updatedUser) })
    } catch (error) {
      res.status(500).json({ success: false, error: error.message })
    }
  })

  app.post('/api/health/record', verifyToken, async (req, res) => {
    try {
      const db = await getDb()
      const payload = {
        user_id: req.user.id,
        heart_rate: req.body.heartRate ?? null,
        spo2: req.body.spo2 ?? null,
        temperature: req.body.temperature ?? null,
        device_id: req.body.deviceId ?? null,
        synced: true,
        timestamp: new Date().toISOString(),
      }

      const result = await db.collection('health_records').insertOne(payload)
      res.json({ success: true, data: { ...payload, id: normalizeId(result.insertedId) } })
    } catch (error) {
      res.status(500).json({ success: false, error: error.message })
    }
  })

  app.get('/api/health/records', verifyToken, async (req, res) => {
    try {
      const db = await getDb()
      const filter = { user_id: req.user.id }
      if (req.query.startDate || req.query.endDate) {
        filter.timestamp = {}
        if (req.query.startDate) filter.timestamp.$gte = req.query.startDate
        if (req.query.endDate) filter.timestamp.$lte = req.query.endDate
      }

      const data = await db
        .collection('health_records')
        .find(filter)
        .sort({ timestamp: -1 })
        .limit(100)
        .toArray()

      res.json({
        success: true,
        data: serializeDocuments(data),
      })
    } catch (error) {
      res.status(500).json({ success: false, error: error.message })
    }
  })

  app.post('/api/ai/recommendations', async (req, res) => {
    try {
      const { vitalSigns } = req.body

      if (!openai) {
        return res.json({
          success: true,
          data: {
            recommendations: ['AI recommendations unavailable. Please consult a healthcare professional.'],
            riskLevel: 'unknown',
          },
        })
      }

      const prompt = `Analyze these vital signs and provide health recommendations:
Heart Rate: ${vitalSigns.heartRate} bpm
SpO2: ${vitalSigns.spo2}%
Temperature: ${vitalSigns.temperature}C

Format as JSON with keys riskLevel and recommendations.`

      const response = await openai.responses.create({
        model: DEFAULT_AI_MODEL,
        input: prompt,
      })

      const parsed = JSON.parse(response.output[0].content[0].text)
      res.json({ success: true, data: parsed })
    } catch (error) {
      res.json({
        success: true,
        data: {
          recommendations: ['Unable to generate recommendations. Please try again later.'],
          riskLevel: 'unknown',
        },
      })
    }
  })

  app.post('/api/ai/voice-assistant', async (req, res) => {
    try {
      const { message, language = 'en' } = req.body

      if (!openai) {
        return res.json({
          success: true,
          data: { response: buildVoiceFallback(message) },
        })
      }

      const response = await openai.responses.create({
        model: DEFAULT_AI_MODEL,
        input: [
          {
            role: 'system',
            content: `You are SAHAYAK, a helpful worker safety assistant. Reply concisely in ${language} when possible.`,
          },
          { role: 'user', content: message },
        ],
      })

      const text =
        response.output_text ||
        response.output?.[0]?.content?.[0]?.text ||
        'I ran into an issue while preparing a reply. Please try again.'

      res.json({ success: true, data: { response: text } })
    } catch (error) {
      res.json({
        success: true,
        data: { response: buildVoiceFallback(req.body?.message || '') },
      })
    }
  })

  app.post('/api/ai/job-match', async (req, res) => {
    try {
      const { userSkills, jobDescription } = req.body

      if (!openai) {
        return res.json({
          success: true,
          data: { matchScore: 0, missingSkills: [], strengths: [] },
        })
      }

      const response = await openai.responses.create({
        model: DEFAULT_AI_MODEL,
        input: `Analyze how well these skills match the job requirements:
User Skills: ${userSkills.join(', ')}
Job Description: ${jobDescription}

Format as JSON with keys matchScore, missingSkills, strengths.`,
      })

      const parsed = JSON.parse(response.output[0].content[0].text)
      res.json({ success: true, data: parsed })
    } catch (error) {
      res.json({
        success: true,
        data: { matchScore: 0, missingSkills: [], strengths: [] },
      })
    }
  })

  app.get('/api/weather', async (req, res) => {
    try {
      const { lat, lon } = req.query
      if (!lat || !lon) {
        return res.status(400).json({ success: false, error: 'Latitude and longitude required' })
      }

      const apiKey = process.env.OPENWEATHER_API_KEY
      if (!apiKey) {
        return res.status(500).json({ success: false, error: 'Weather API key not configured' })
      }

      const response = await axios.get(
        `https://api.openweathermap.org/data/2.5/weather?lat=${lat}&lon=${lon}&appid=${apiKey}&units=metric`
      )

      res.json({ success: true, data: response.data })
    } catch (error) {
      res.status(500).json({ success: false, error: error.message })
    }
  })

  app.get('/api/weather/forecast', async (req, res) => {
    try {
      const { lat, lon } = req.query
      if (!lat || !lon) {
        return res.status(400).json({ success: false, error: 'Latitude and longitude required' })
      }

      const apiKey = process.env.OPENWEATHER_API_KEY
      if (!apiKey) {
        return res.status(500).json({ success: false, error: 'Weather API key not configured' })
      }

      const response = await axios.get(
        `https://api.openweathermap.org/data/2.5/forecast?lat=${lat}&lon=${lon}&appid=${apiKey}&units=metric`
      )

      res.json({ success: true, data: response.data })
    } catch (error) {
      res.status(500).json({ success: false, error: error.message })
    }
  })

  app.get('/api/notifications', verifyToken, async (req, res) => {
    try {
      const db = await getDb()
      const limit = Number(req.query.limit || 50)
      const data = await db
        .collection('notifications')
        .find({ user_id: req.user.id })
        .sort({ timestamp: -1 })
        .limit(limit)
        .toArray()

      res.json({
        success: true,
        data: serializeDocuments(data),
      })
    } catch (error) {
      res.status(500).json({ success: false, error: error.message })
    }
  })

  app.post('/api/notifications', verifyToken, async (req, res) => {
    try {
      const db = await getDb()
      const payload = {
        user_id: req.user.id,
        type: req.body.type,
        title: req.body.title,
        message: req.body.message,
        read: false,
        timestamp: new Date().toISOString(),
      }
      const result = await db.collection('notifications').insertOne(payload)
      res.json({ success: true, data: { ...payload, id: normalizeId(result.insertedId) } })
    } catch (error) {
      res.status(500).json({ success: false, error: error.message })
    }
  })

  app.patch('/api/notifications/:id/read', verifyToken, async (req, res) => {
    try {
      const db = await getDb()
      const notificationId = toObjectId(req.params.id)
      if (!notificationId) {
        return res.status(400).json({ success: false, error: 'Invalid notification id' })
      }

      await db.collection('notifications').findOneAndUpdate(
        { _id: notificationId, user_id: req.user.id },
        { $set: { read: true } },
        { returnDocument: 'after' }
      )
      const updated = await db.collection('notifications').findOne({
        _id: notificationId,
        user_id: req.user.id,
      })

      res.json({
        success: true,
        data: serializeDocument(updated),
      })
    } catch (error) {
      res.status(500).json({ success: false, error: error.message })
    }
  })

  app.get('/api/emergency-contacts', verifyToken, async (req, res) => {
    try {
      const db = await getDb()
      const data = await db
        .collection('emergency_contacts')
        .find({ user_id: req.user.id })
        .sort({ is_primary: -1, created_at: -1 })
        .toArray()

      res.json({
        success: true,
        data: serializeDocuments(data),
      })
    } catch (error) {
      res.status(500).json({ success: false, error: error.message })
    }
  })

  app.post('/api/emergency-contacts', verifyToken, async (req, res) => {
    try {
      const db = await getDb()
      const payload = {
        user_id: req.user.id,
        name: req.body.name,
        phone: req.body.phone,
        relationship: req.body.relationship,
        is_primary: req.body.isPrimary || false,
        created_at: new Date().toISOString(),
      }

      const result = await db.collection('emergency_contacts').insertOne(payload)
      res.json({ success: true, data: { ...payload, id: normalizeId(result.insertedId) } })
    } catch (error) {
      res.status(500).json({ success: false, error: error.message })
    }
  })

  app.delete('/api/emergency-contacts/:id', verifyToken, async (req, res) => {
    try {
      const db = await getDb()
      const contactId = toObjectId(req.params.id)
      if (!contactId) {
        return res.status(400).json({ success: false, error: 'Invalid contact id' })
      }

      await db.collection('emergency_contacts').deleteOne({
        _id: contactId,
        user_id: req.user.id,
      })
      res.json({ success: true })
    } catch (error) {
      res.status(500).json({ success: false, error: error.message })
    }
  })

  app.get('/api/schemes', async (req, res) => {
    try {
      if (!isMongoConfigured()) {
        return res.json({ success: true, data: [] })
      }

      const db = await getDb()
      const filter = { active: true }
      if (req.query.category && req.query.category !== 'all') {
        filter.category = req.query.category
      }
      if (req.query.search) {
        const searchRegex = buildRegex(req.query.search)
        filter.$or = [{ title: searchRegex }, { description: searchRegex }]
      }

      const data = await db.collection('government_schemes').find(filter).sort({ created_at: -1 }).toArray()
      res.json({
        success: true,
        data: serializeDocuments(data),
      })
    } catch (error) {
      res.status(500).json({ success: false, error: error.message })
    }
  })

  app.get('/api/jobs', async (req, res) => {
    try {
      if (!isMongoConfigured()) {
        return res.json({ success: true, data: [] })
      }

      const db = await getDb()
      const filter = { active: true }
      if (req.query.type && req.query.type !== 'all') {
        filter.type = req.query.type
      }
      if (req.query.search) {
        const searchRegex = buildRegex(req.query.search)
        filter.$or = [{ title: searchRegex }, { company: searchRegex }, { description: searchRegex }]
      }

      const data = await db.collection('jobs').find(filter).sort({ created_at: -1 }).toArray()
      res.json({
        success: true,
        data: serializeDocuments(data),
      })
    } catch (error) {
      res.status(500).json({ success: false, error: error.message })
    }
  })

  app.get('/api/education', async (req, res) => {
    try {
      if (!isMongoConfigured()) {
        return res.json({ success: true, data: [] })
      }

      const db = await getDb()
      const filter = {}
      if (req.query.category) filter.category = req.query.category
      if (req.query.language) filter.language = req.query.language

      const data = await db.collection('education_content').find(filter).sort({ created_at: -1 }).toArray()
      res.json({
        success: true,
        data: serializeDocuments(data),
      })
    } catch (error) {
      res.status(500).json({ success: false, error: error.message })
    }
  })

  app.get('/api/device', verifyToken, async (req, res) => {
    try {
      const db = await getDb()
      const data = await db.collection('device_data').findOne(
        { user_id: req.user.id },
        { sort: { last_sync: -1 } }
      )

      res.json({
        success: true,
        data: serializeDocument(data),
      })
    } catch (error) {
      res.status(500).json({ success: false, error: error.message })
    }
  })

  app.post('/api/device', verifyToken, async (req, res) => {
    try {
      const db = await getDb()
      const filter = {
        user_id: req.user.id,
        device_id: req.body.deviceId,
      }
      const update = {
        $set: {
          user_id: req.user.id,
          device_id: req.body.deviceId,
          device_name: req.body.deviceName,
          battery_level: req.body.batteryLevel,
          firmware_version: req.body.firmwareVersion,
          last_sync: new Date().toISOString(),
        },
      }

      await db.collection('device_data').updateOne(filter, update, { upsert: true })
      const data = await db.collection('device_data').findOne(filter)
      res.json({
        success: true,
        data: serializeDocument(data),
      })
    } catch (error) {
      res.status(500).json({ success: false, error: error.message })
    }
  })

  if (arduinoRoutes && arduinoService) {
    app.get('/api/arduino/ports', async (_req, res) => {
      try {
        const ports = await arduinoService.listPorts()
        res.json({ success: true, data: ports })
      } catch (error) {
        res.status(500).json({ success: false, error: error.message })
      }
    })

    app.post('/api/arduino/connect', async (req, res) => {
      try {
        const { comPort = 'COM7', baudRate = 115200 } = req.body
        const result = await arduinoService.connect(comPort, baudRate)
        res.json({ success: true, ...result })
      } catch (error) {
        res.status(500).json({ success: false, error: error.message })
      }
    })

    app.post('/api/arduino/disconnect', async (_req, res) => {
      try {
        await arduinoService.disconnect()
        res.json({ success: true, message: 'Disconnected from Arduino' })
      } catch (error) {
        res.status(500).json({ success: false, error: error.message })
      }
    })

    app.get('/api/arduino/status', (_req, res) => {
      try {
        const status = arduinoService.getStatus()
        res.json({ success: true, data: status })
      } catch (error) {
        res.status(500).json({ success: false, error: error.message })
      }
    })

    app.get('/api/arduino/data', (_req, res) => {
      try {
        const data = arduinoService.getCurrentData()
        res.json({ success: true, data })
      } catch (error) {
        res.status(500).json({ success: false, error: error.message })
      }
    })
  } else {
    const unsupported = (_req, res) => {
      res.status(501).json({
        success: false,
        error: 'Arduino serial features require the local backend and are not available on Vercel serverless.',
      })
    }

    app.get('/api/arduino/ports', unsupported)
    app.post('/api/arduino/connect', unsupported)
    app.post('/api/arduino/disconnect', unsupported)
    app.get('/api/arduino/status', unsupported)
    app.get('/api/arduino/data', unsupported)
  }

  app.get('/api/workers/dataset', (_req, res) => {
    res.json({ success: true, data: generateWorkerDataset() })
  })

  return app
}
