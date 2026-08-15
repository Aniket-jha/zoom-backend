import express from 'express'
import cors from 'cors'
import dotenv from 'dotenv'
import axios from 'axios'
import jwt from 'jsonwebtoken'
import { promises as fs } from 'fs'
import path from 'path'
import admin from 'firebase-admin'
import swaggerUi from 'swagger-ui-express'
import swaggerJsdoc from 'swagger-jsdoc'

dotenv.config()

const app = express()
const port = process.env.PORT || 5050

app.use(cors({ origin: process.env.CORS_ORIGIN || '*' }))
app.use(express.json())

const swaggerSpec = swaggerJsdoc({
  definition: {
    openapi: '3.0.0',
    info: {
      title: 'Zoom Backend API',
      version: '1.0.0',
      description: 'API documentation for the Zoom backend (no auth).',
    },
    servers: [
      {
        url: 'https://zoom-backend-ht3i.onrender.com',
        description: 'Production',
      },
      {
        url: 'https://zoom-backend-ht3i.onrender.com',
        description: 'Production',
      },
    ],
  },
  apis: ['./server.js'],
})

app.use('/docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec, { explorer: true }))

const {
  ZOOM_OAUTH_CLIENT_ID,
  ZOOM_OAUTH_CLIENT_SECRET,
  ZOOM_OAUTH_REDIRECT_URL,
  FRONTEND_URL,
  ZOOM_MEETING_SDK_KEY,
  ZOOM_MEETING_SDK_SECRET,
  FIREBASE_SERVICE_ACCOUNT_PATH,
  FIREBASE_SERVICE_ACCOUNT_JSON,
  FIREBASE_DATABASE_URL,
  MOBILE_FRONTEND_URL,
} = process.env

let firebaseApp = null
const getFirebaseApp = async () => {
  if (firebaseApp) return firebaseApp
  if (!FIREBASE_SERVICE_ACCOUNT_JSON && !FIREBASE_SERVICE_ACCOUNT_PATH) {
    throw new Error(
      'Missing required env var: FIREBASE_SERVICE_ACCOUNT_JSON or FIREBASE_SERVICE_ACCOUNT_PATH'
    )
  }
  requireEnv(FIREBASE_DATABASE_URL, 'FIREBASE_DATABASE_URL')

  let serviceAccount = null
  if (FIREBASE_SERVICE_ACCOUNT_JSON) {
    serviceAccount = JSON.parse(FIREBASE_SERVICE_ACCOUNT_JSON)
  } else {
    const serviceAccountPath = path.resolve(process.cwd(), FIREBASE_SERVICE_ACCOUNT_PATH)
    const serviceAccountJson = await fs.readFile(serviceAccountPath, 'utf-8')
    serviceAccount = JSON.parse(serviceAccountJson)
  }

  firebaseApp = admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
    databaseURL: FIREBASE_DATABASE_URL,
  })

  return firebaseApp
}

const requireEnv = (value, name) => {
  if (!value) {
    throw new Error(`Missing required env var: ${name}`)
  }
}

const getFirestore = async () => {
  await getFirebaseApp()
  return admin.firestore()
}

const getTokenForAdmin = async (adminId) => {
  if (!adminId) return null
  const firestore = await getFirestore()
  const docRef = firestore.collection('zoom_tokens').doc(adminId)
  const docSnap = await docRef.get()
  return docSnap.exists ? docSnap.data() : null
}

const saveTokenForAdmin = async (adminId, tokenData) => {
  if (!adminId) return
  const firestore = await getFirestore()
  const docRef = firestore.collection('zoom_tokens').doc(adminId)
  await docRef.set(
    {
      ...tokenData,
      updatedAt: admin.firestore.FieldValue.serverTimestamp(),
    },
    { merge: true }
  )
}

const exchangeCodeForToken = async (code) => {
  requireEnv(ZOOM_OAUTH_CLIENT_ID, 'ZOOM_OAUTH_CLIENT_ID')
  requireEnv(ZOOM_OAUTH_CLIENT_SECRET, 'ZOOM_OAUTH_CLIENT_SECRET')
  requireEnv(ZOOM_OAUTH_REDIRECT_URL, 'ZOOM_OAUTH_REDIRECT_URL')

  const credentials = Buffer.from(
    `${ZOOM_OAUTH_CLIENT_ID}:${ZOOM_OAUTH_CLIENT_SECRET}`
  ).toString('base64')

  const response = await axios.post(
    `https://zoom.us/oauth/token?grant_type=authorization_code&code=${code}&redirect_uri=${encodeURIComponent(
      ZOOM_OAUTH_REDIRECT_URL
    )}`,
    null,
    {
      headers: {
        Authorization: `Basic ${credentials}`,
      },
    }
  )

  const now = Math.floor(Date.now() / 1000)
  return {
    access_token: response.data.access_token,
    refresh_token: response.data.refresh_token,
    expires_at: now + (response.data.expires_in || 0),
    scope: response.data.scope,
    token_type: response.data.token_type,
  }
}

const refreshAccessToken = async (refreshToken) => {
  requireEnv(ZOOM_OAUTH_CLIENT_ID, 'ZOOM_OAUTH_CLIENT_ID')
  requireEnv(ZOOM_OAUTH_CLIENT_SECRET, 'ZOOM_OAUTH_CLIENT_SECRET')

  const credentials = Buffer.from(
    `${ZOOM_OAUTH_CLIENT_ID}:${ZOOM_OAUTH_CLIENT_SECRET}`
  ).toString('base64')

  const response = await axios.post(
    `https://zoom.us/oauth/token?grant_type=refresh_token&refresh_token=${refreshToken}`,
    null,
    {
      headers: {
        Authorization: `Basic ${credentials}`,
      },
    }
  )

  const now = Math.floor(Date.now() / 1000)
  return {
    access_token: response.data.access_token,
    refresh_token: response.data.refresh_token,
    expires_at: now + (response.data.expires_in || 0),
    scope: response.data.scope,
    token_type: response.data.token_type,
  }
}

const getValidAccessToken = async (adminId) => {
  const token = await getTokenForAdmin(adminId)
  if (!token) return null

  const now = Math.floor(Date.now() / 1000)
  if (token.expires_at && token.expires_at - 60 > now) {
    return token.access_token
  }

  if (!token.refresh_token) return null

  const refreshed = await refreshAccessToken(token.refresh_token)
  await saveTokenForAdmin(adminId, refreshed)
  return refreshed.access_token
}

const getBearerToken = (req) => {
  const header = req.headers.authorization || ''
  if (!header.startsWith('Bearer ')) return null
  return header.slice('Bearer '.length).trim()
}

const verifyFirebaseIdToken = async (req) => {
  const idToken = getBearerToken(req)
  if (!idToken) return null
  await getFirebaseApp()
  return admin.auth().verifyIdToken(idToken)
}

/**
 * @swagger
 * /health:
 *   get:
 *     summary: Health check
 *     tags: [System]
 *     responses:
 *       200:
 *         description: Server is up
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 ok:
 *                   type: boolean
 */
app.get('/health', (req, res) => {
  res.json({ ok: true })
})

/**
 * @swagger
 * /oauth/authorize:
 *   get:
 *     summary: Redirect to Zoom OAuth authorization
 *     tags: [OAuth]
 *     parameters:
 *       - in: query
 *         name: adminId
 *         schema:
 *           type: string
 *         description: Admin identifier to store token against
 *     responses:
 *       302:
 *         description: Redirect to Zoom OAuth
 */
app.get('/oauth/authorize', (req, res) => {
  try {
    requireEnv(ZOOM_OAUTH_CLIENT_ID, 'ZOOM_OAUTH_CLIENT_ID')
    requireEnv(ZOOM_OAUTH_REDIRECT_URL, 'ZOOM_OAUTH_REDIRECT_URL')

    const adminId = req.query.adminId
    const target = req.query.target
    const state = adminId || 'unknown'
    const targetState = target ? `${state}|${target}` : state
    const authUrl =
      `https://zoom.us/oauth/authorize?response_type=code` +
      `&client_id=${ZOOM_OAUTH_CLIENT_ID}` +
      `&redirect_uri=${encodeURIComponent(ZOOM_OAUTH_REDIRECT_URL)}` +
      `&state=${encodeURIComponent(targetState)}`

    res.redirect(authUrl)
  } catch (error) {
    res.status(500).send(error.message)
  }
})

/**
 * @swagger
 * /oauth/callback:
 *   get:
 *     summary: OAuth callback handler
 *     tags: [OAuth]
 *     parameters:
 *       - in: query
 *         name: code
 *         required: true
 *         schema:
 *           type: string
 *       - in: query
 *         name: state
 *         schema:
 *           type: string
 *     responses:
 *       302:
 *         description: Redirect to frontend with connection status
 *       400:
 *         description: Missing authorization code
 */
app.get('/oauth/callback', async (req, res) => {
  try {
    const { code, state } = req.query
    if (!code) {
      return res.status(400).send('Missing authorization code')
    }

    const rawState = typeof state === 'string' ? state : ''
    const [adminId, target] = rawState.split('|')
    const tokenData = await exchangeCodeForToken(code)
    await saveTokenForAdmin(adminId || 'unknown', tokenData)

    const redirectTo =
      target === 'mobile' && MOBILE_FRONTEND_URL
        ? MOBILE_FRONTEND_URL
        : FRONTEND_URL || 'http://localhost:5173'
    res.redirect(`${redirectTo}?zoom=connected`)
  } catch (error) {
    const message = error.response?.data || error.message
    res.status(500).send(JSON.stringify(message))
  }
})

/**
 * @swagger
 * /api/zoom/status:
 *   get:
 *     summary: Check if Zoom is connected for an admin
 *     tags: [Zoom]
 *     parameters:
 *       - in: query
 *         name: adminId
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Connection status
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 connected:
 *                   type: boolean
 *       400:
 *         description: Missing adminId
 */
app.get('/api/zoom/status', async (req, res) => {
  try {
    const adminId = req.query.adminId
    if (!adminId) {
      return res.status(400).json({ error: 'adminId is required' })
    }
    const token = await getTokenForAdmin(adminId)
    res.json({ connected: !!token })
  } catch (error) {
    res.status(500).json({ error: error.message })
  }
})

/**
 * @swagger
 * /api/zoom/token:
 *   get:
 *     summary: Fetch Zoom access token for an admin (requires Firebase ID token)
 *     tags: [Zoom]
 *     parameters:
 *       - in: query
 *         name: adminId
 *         schema:
 *           type: string
 *         description: Admin identifier (defaults to caller uid)
 *     responses:
 *       200:
 *         description: Access token payload
 *       401:
 *         description: Missing or invalid auth token
 *       403:
 *         description: adminId does not match caller
 */
app.get('/api/zoom/token', async (req, res) => {
  try {
    const decoded = await verifyFirebaseIdToken(req)
    if (!decoded) {
      return res.status(401).json({ error: 'Missing or invalid auth token' })
    }

    const adminId = req.query.adminId || decoded.uid
    if (adminId !== decoded.uid) {
      return res.status(403).json({ error: 'Forbidden' })
    }

    const accessToken = await getValidAccessToken(adminId)
    if (!accessToken) {
      return res.status(404).json({ error: 'Zoom not connected for this admin' })
    }

    const tokenData = await getTokenForAdmin(adminId)
    res.json({
      access_token: accessToken,
      token_type: tokenData?.token_type || 'Bearer',
      expires_at: tokenData?.expires_at || null,
      scope: tokenData?.scope || null,
    })
  } catch (error) {
    res.status(500).json({ error: error.message })
  }
})
/**
 * @swagger
 * /api/zoom/signature:
 *   post:
 *     summary: Create a Zoom Meeting SDK signature
 *     tags: [Zoom]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               meetingNumber:
 *                 type: string
 *               role:
 *                 type: integer
 *                 example: 0
 *             required:
 *               - meetingNumber
 *     responses:
 *       200:
 *         description: Signature response
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 signature:
 *                   type: string
 *       400:
 *         description: Missing meetingNumber
 */
app.post('/api/zoom/signature', (req, res) => {
  try {
    requireEnv(ZOOM_MEETING_SDK_KEY, 'ZOOM_MEETING_SDK_KEY')
    requireEnv(ZOOM_MEETING_SDK_SECRET, 'ZOOM_MEETING_SDK_SECRET')

    const { meetingNumber, role } = req.body

    if (!meetingNumber) {
      return res.status(400).json({ error: 'meetingNumber is required' })
    }

    const now = Math.floor(Date.now() / 1000)
    const payload = {
      sdkKey: ZOOM_MEETING_SDK_KEY,
      mn: meetingNumber,
      role: role ?? 0,
      iat: now - 30,
      exp: now + 2 * 60 * 60,
      tokenExp: now + 2 * 60 * 60,
    }

    const signature = jwt.sign(payload, ZOOM_MEETING_SDK_SECRET, {
      algorithm: 'HS256',
    })

    res.json({ signature })
  } catch (error) {
    res.status(500).json({ error: error.message })
  }
})

/**
 * @swagger
 * /api/zoom/meetings:
 *   post:
 *     summary: Create a Zoom meeting
 *     tags: [Zoom]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               adminId:
 *                 type: string
 *               topic:
 *                 type: string
 *               startTime:
 *                 type: string
 *                 format: date-time
 *               duration:
 *                 type: integer
 *               timezone:
 *                 type: string
 *               agenda:
 *                 type: string
 *               password:
 *                 type: string
 *             required:
 *               - adminId
 *     responses:
 *       200:
 *         description: Zoom meeting created
 *       401:
 *         description: Zoom not connected
 *       400:
 *         description: Missing adminId
 */
app.post('/api/zoom/meetings', async (req, res) => {
  try {
    const adminId = req.body.adminId
    if (!adminId) {
      return res.status(400).json({ error: 'adminId is required' })
    }

    const accessToken = await getValidAccessToken(adminId)
    if (!accessToken) {
      return res.status(401).json({ error: 'Zoom not connected for this admin' })
    }

  const {
    topic,
    startTime,
    duration,
    timezone,
    agenda,
    password,
    autoRecording,
  } = req.body

    const payload = {
      topic: topic || 'New Meeting',
      type: startTime ? 2 : 1,
      start_time: startTime || undefined,
      duration: duration || 30,
      timezone: timezone || 'UTC',
      agenda: agenda || '',
    settings: {
      join_before_host: true,
      waiting_room: false,
      mute_upon_entry: true,
      meeting_authentication: false,
    },
  }

  if (autoRecording && autoRecording !== 'none') {
    payload.settings.auto_recording = autoRecording
  }

  if (password) {
    payload.password = password
  }

    // Always create the meeting for the token's own owner ("me"). This
    // endpoint is multi-tenant: accessToken belongs to whichever admin
    // connected via OAuth, so the meeting must be hosted under that same
    // account. A fixed/hardcoded host user here would only work for one
    // specific Zoom account and break for every other admin who connects
    // (this is what was happening — see PR description).
    const response = await axios.post(
      `https://api.zoom.us/v2/users/me/meetings`,
      payload,
      {
        headers: {
          Authorization: `Bearer ${accessToken}`,
        },
      }
    )

    res.json(response.data)
  } catch (error) {
    const status = error.response?.status || 500
    const message = error.response?.data || error.message
    console.error('Error creating Zoom meeting:', message)
    res.status(status).json({ error: message })
  }
})

/**
 * @swagger
 * /api/zoom/recording:
 *   patch:
 *     summary: Control cloud recording for a live meeting
 *     tags: [Zoom]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               adminId:
 *                 type: string
 *               meetingId:
 *                 type: string
 *               action:
 *                 type: string
 *                 enum: [start, stop, pause, resume]
 *             required:
 *               - adminId
 *               - meetingId
 *               - action
 *     responses:
 *       202:
 *         description: Recording control accepted
 *       401:
 *         description: Zoom not connected
 *       403:
 *         description: Forbidden
 */
app.patch('/api/zoom/recording', async (req, res) => {
  try {
    const decoded = await verifyFirebaseIdToken(req)
    if (!decoded) {
      return res.status(401).json({ error: 'Missing or invalid auth token' })
    }

    const { adminId, meetingId, action } = req.body
    if (!adminId || !meetingId || !action) {
      return res.status(400).json({ error: 'adminId, meetingId, action required' })
    }
    if (adminId !== decoded.uid) {
      return res.status(403).json({ error: 'Forbidden' })
    }

    const methodMap = {
      start: 'recording.start',
      stop: 'recording.stop',
      pause: 'recording.pause',
      resume: 'recording.resume',
    }
    const method = methodMap[action]
    if (!method) {
      return res.status(400).json({ error: 'Invalid action' })
    }

    const accessToken = await getValidAccessToken(adminId)
    if (!accessToken) {
      return res.status(401).json({ error: 'Zoom not connected for this admin' })
    }

    const response = await axios.patch(
      `https://api.zoom.us/v2/live_meetings/${meetingId}/events`,
      { method },
      {
        headers: {
          Authorization: `Bearer ${accessToken}`,
        },
      }
    )

    res.status(response.status).json(response.data || { ok: true })
  } catch (error) {
    const message = error.response?.data || error.message
    const status = error.response?.status || 500
    res.status(status).json({ error: message })
  }
})

/**
 * @swagger
 * /api/admin-meetings:
 *   get:
 *     summary: Fetch admin meetings and users
 *     tags: [Admin]
 *     parameters:
 *       - in: query
 *         name: adminId
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Meetings and users for the admin
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 adminId:
 *                   type: string
 *                 meetings:
 *                   type: array
 *                   items:
 *                     type: object
 *                 users:
 *                   type: array
 *                   items:
 *                     type: object
 *       400:
 *         description: Missing adminId
 */
app.get('/api/admin-meetings', async (req, res) => {
  try {
    const adminId = req.query.adminId
    if (!adminId) {
      return res.status(400).json({ error: 'adminId is required' })
    }

    await getFirebaseApp()

    const db = admin.database()
    const snapshot = await db.ref('meetings').orderByChild('adminId').equalTo(adminId).once('value')
    const meetings = snapshot.exists()
      ? Object.values(snapshot.val()).filter(Boolean)
      : []

    const firestore = admin.firestore()
    const usersSnap = await firestore.collection('users').where('adminId', '==', adminId).get()
    const users = usersSnap.docs.map((doc) => ({ id: doc.id, ...doc.data() }))

    res.json({ adminId, meetings, users })
  } catch (error) {
    res.status(500).json({ error: error.message })
  }
})

app.listen(port, () => {
  console.log(`Zoom backend listening on ${port}`)
})