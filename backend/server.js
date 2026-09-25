require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const admin = require('firebase-admin');
const { getStorage } = require('firebase-admin/storage');
const multer = require('multer');
const Stripe = require('stripe');
const { z } = require('zod');
const https = require('https');

// ==========================================
// 1. INITIALIZATION & CONFIGURATION
// ==========================================
const app = express();
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY, { apiVersion: '2023-10-16' });

// Firebase Admin Init (Uses Service Account JSON)
if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.cert({
      projectId: process.env.FIREBASE_PROJECT_ID,
      clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
      privateKey: process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n'),
    }),
    storageBucket: process.env.FIREBASE_STORAGE_BUCKET,
  });
}
const db = admin.firestore();
const bucket = getStorage().bucket();

// ==========================================
// 2. SECURITY MIDDLEWARE
// ==========================================
// Strict CORS
const allowedOrigins = ['https://creditpulse.example', 'http://localhost:3000'];
app.use(cors({
  origin: (origin, callback) => {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));

app.use(helmet({ contentSecurityPolicy: false })); // Adjust CSP as needed for your frontend
app.use(express.json({ limit: '5mb' })); // Max payload 5MB

// Rate Limiting
const generalLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 100, message: { success: false, error: 'Too many requests, please try again later.' } });
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 5, message: { success: false, error: 'Too many login attempts, please try again later.' } });

app.use('/api/', generalLimiter);
app.use('/api/auth/', authLimiter);

// ==========================================
// 3. HELPER FUNCTIONS & VALIDATION
// ==========================================
const sendResponse = (res, status, success, data = null, error = null) => {
  res.status(status).json({
    success,
    data,
    error,
    timestamp: new Date().toISOString(),
  });
};

const withTimeout = (promise, ms = 30000) => {
  let timeoutId;
  const timeout = new Promise((_, reject) => {
    timeoutId = setTimeout(() => reject(new Error('Request timeout')), ms);
  });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timeoutId));
};

// Zod Validation Middleware
const validate = (schema) => (req, res, next) => {
  try {
    schema.parse(req.body);
    next();
  } catch (err) {
    sendResponse(res, 400, false, null, 'Invalid input data');
  }
};

// Firebase JWT Verification Middleware
const verifyToken = async (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return sendResponse(res, 401, false, null, 'Missing or invalid authorization header');
  }
  const token = authHeader.split(' ')[1];
  try {
    const decodedToken = await withTimeout(admin.auth().verifyIdToken(token));
    req.user = decodedToken;
    next();
  } catch (err) {
    console.error('Token verification failed:', err.message);
    sendResponse(res, 401, false, null, 'Invalid or expired token');
  }
};

// ==========================================
// 4. ZOD SCHEMAS (Explicit Whitelisting)
// ==========================================
const signupSchema = z.object({
  email: z.string().email('Invalid email format').max(255),
  password: z.string().min(8, 'Password must be at least 8 characters').max(128),
  businessName: z.string().min(2, 'Business name is required').max(100),
});

const loginSchema = z.object({
  email: z.string().email('Invalid email format').max(255),
  password: z.string().min(1, 'Password is required').max(128),
});

const supplierSchema = z.object({
  name: z.string().min(2).max(100),
  creditPeriod: z.number().int().min(1).max(365),
  totalPurchases: z.number().min(0),
  outstanding: z.number().min(0),
  txns: z.number().int().min(0),
  onTime: z.number().min(0).max(100),
});

const invoiceSchema = z.object({
  customer: z.string().min(2).max(100),
  amount: z.number().positive('Amount must be greater than 0'),
  issued: z.string().regex(/^\d{4}-\d{2}-\d{2}$/),
  due: z.string().regex(/^\d{4}-\d{2}-\d{2}$/),
  status: z.enum(['pending', 'paid', 'partial', 'overdue']),
});

const documentSchema = z.object({
  docType: z.enum(['GST', 'Udyam', 'PAN', 'ITR', 'Bank', 'Invoice', 'Loan', 'Registration', 'Other']),
});

// ==========================================
// 5. ROUTES & CONTROLLERS
// ==========================================

// --- AUTH ---
app.post('/api/auth/signup', validate(signupSchema), async (req, res) => {
  try {
    const { email, password, businessName } = req.body; // Explicit destructuring, no spread
    
    // 1. Create Firebase Auth User
    const userRecord = await withTimeout(admin.auth().createUser({ email, password }));
    
    // 2. Create Firestore Profile (Explicit fields only)
    await withTimeout(db.collection('users').doc(userRecord.uid).set({
      userId: userRecord.uid,
      email: email.toLowerCase(),
      businessName,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      updatedAt: admin.firestore.FieldValue.serverTimestamp(),
    }));

    sendResponse(res, 201, true, { userId: userRecord.uid, email, businessName });
  } catch (err) {
    console.error('Signup error:', err.message);
    if (err.code === 'auth/email-already-exists') {
      return sendResponse(res, 400, false, null, 'Email already in use');
    }
    sendResponse(res, 500, false, null, 'An error occurred during signup');
  }
});

app.post('/api/auth/login', validate(loginSchema), async (req, res) => {
  try {
    const { email, password } = req.body;
    
    // Proxy to Firebase Identity Toolkit to verify password and get JWT securely on backend
    const response = await new Promise((resolve, reject) => {
      const reqHttps = https.request({
        hostname: 'identitytoolkit.googleapis.com',
        path: `/v1/accounts:signInWithPassword?key=${process.env.FIREBASE_WEB_API_KEY}`,
        method: 'POST',
        headers: { 'Content-Type': 'application/json' }
      }, (resp) => {
        let data = '';
        resp.on('data', chunk => data += chunk);
        resp.on('end', () => resp.statusCode === 200 ? resolve(JSON.parse(data)) : reject(new Error(resp.statusMessage)));
      });
      reqHttps.on('error', reject);
      reqHttps.write(JSON.stringify({ email, password, returnSecureToken: true }));
      reqHttps.end();
    });

    sendResponse(res, 200, true, { 
      token: response.idToken, 
      userId: response.localId,
      expiresIn: response.expiresIn 
    });
  } catch (err) {
    console.error('Login error:', err.message);
    sendResponse(res, 401, false, null, 'Invalid email or password');
  }
});

// --- USER PROFILE ---
app.get('/api/user/profile', verifyToken, async (req, res) => {
  try {
    const userId = req.user.uid;
    const doc = await withTimeout(db.collection('users').doc(userId).get());
    
    if (!doc.exists) return sendResponse(res, 404, false, null, 'Profile not found');
    
    const data = doc.data();
    // Explicit ownership check (Defense in depth)
    if (data.userId !== userId) {
      return sendResponse(res, 403, false, null, 'Forbidden: You do not own this resource');
    }

    sendResponse(res, 200, true, { email: data.email, businessName: data.businessName });
  } catch (err) {
    console.error('Profile fetch error:', err.message);
    sendResponse(res, 500, false, null, 'An error occurred');
  }
});

// --- SUPPLIERS ---
app.post('/api/suppliers', verifyToken, validate(supplierSchema), async (req, res) => {
  try {
    const { name, creditPeriod, totalPurchases, outstanding, txns, onTime } = req.body;
    const userId = req.user.uid;

    const newSupplier = {
      userId, // Explicit ownership
      name, creditPeriod, totalPurchases, outstanding, txns, onTime,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    };

    const ref = await withTimeout(db.collection('suppliers').add(newSupplier));
    sendResponse(res, 201, true, { id: ref.id, ...newSupplier });
  } catch (err) {
    console.error('Supplier create error:', err.message);
    sendResponse(res, 500, false, null, 'An error occurred');
  }
});

app.get('/api/suppliers', verifyToken, async (req, res) => {
  try {
    const userId = req.user.uid;
    // Parameterized query via Firestore SDK
    const snapshot = await withTimeout(db.collection('suppliers').where('userId', '==', userId).get());
    
    const suppliers = snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));
    sendResponse(res, 200, true, suppliers);
  } catch (err) {
    console.error('Supplier fetch error:', err.message);
    sendResponse(res, 500, false, null, 'An error occurred');
  }
});

// --- INVOICES ---
app.post('/api/invoices', verifyToken, validate(invoiceSchema), async (req, res) => {
  try {
    const { customer, amount, issued, due, status } = req.body;
    const userId = req.user.uid;

    const newInvoice = {
      userId, customer, amount, issued, due, status,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    };

    const ref = await withTimeout(db.collection('invoices').add(newInvoice));
    sendResponse(res, 201, true, { id: ref.id, ...newInvoice });
  } catch (err) {
    console.error('Invoice create error:', err.message);
    sendResponse(res, 500, false, null, 'An error occurred');
  }
});

app.get('/api/invoices', verifyToken, async (req, res) => {
  try {
    const userId = req.user.uid;
    const snapshot = await withTimeout(db.collection('invoices').where('userId', '==', userId).get());
    const invoices = snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));
    sendResponse(res, 200, true, invoices);
  } catch (err) {
    console.error('Invoice fetch error:', err.message);
    sendResponse(res, 500, false, null, 'An error occurred');
  }
});

// --- CREDIT SCORE ---
app.post('/api/credit-score', verifyToken, async (req, res) => {
  try {
    const userId = req.user.uid;
    
    // Fetch user data securely
    const [suppliersSnap, invoicesSnap] = await Promise.all([
      withTimeout(db.collection('suppliers').where('userId', '==', userId).get()),
      withTimeout(db.collection('invoices').where('userId', '==', userId).get())
    ]);

    const suppliers = suppliersSnap.docs.map(d => d.data());
    const invoices = invoicesSnap.docs.map(d => d.data());

    // Calculation Logic
    const avgOnTime = suppliers.length ? suppliers.reduce((acc, s) => acc + s.onTime, 0) / suppliers.length : 0;
    const paidInvoices = invoices.filter(i => i.status === 'paid').length;
    const collectionRate = invoices.length ? (paidInvoices / invoices.length) * 100 : 0;
    const historyLength = suppliers.length > 0 ? 12 : 0; // Simplified: 12 months if data exists

    const paymentScore = Math.min(100, avgOnTime);
    const invoiceScore = Math.min(100, collectionRate);
    const historyScore = Math.min(100, historyLength * 8);

    const totalScore = Math.round((paymentScore * 0.4) + (invoiceScore * 0.4) + (historyScore * 0.2));
    const finalScore = Math.min(900, Math.round((totalScore / 100) * 900));

    const label = finalScore >= 750 ? 'Excellent' : finalScore >= 650 ? 'Good' : finalScore >= 500 ? 'Fair' : 'Building';

    sendResponse(res, 200, true, {
      score: finalScore,
      breakdown: { paymentHistory: Math.round(paymentScore), invoiceBehavior: Math.round(invoiceScore), historyLength: Math.round(historyScore) },
      label
    });
  } catch (err) {
    console.error('Credit score error:', err.message);
    sendResponse(res, 500, false, null, 'An error occurred');
  }
});

// --- DOCUMENTS ---
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024 }, // 10MB
  fileFilter: (req, file, cb) => {
    const allowed = ['application/pdf', 'image/jpeg', 'image/png'];
    if (allowed.includes(file.mimetype)) cb(null, true);
    else cb(new Error('Invalid file type. Only PDF, JPG, PNG allowed.'));
  }
});

app.post('/api/documents/upload', verifyToken, upload.single('file'), validate(documentSchema), async (req, res) => {
  try {
    if (!req.file) return sendResponse(res, 400, false, null, 'No file provided');
    
    const { docType } = req.body;
    const userId = req.user.uid;
    const fileName = `${userId}/${Date.now()}_${req.file.originalname}`;

    const fileRef = bucket.file(fileName);
    await fileRef.save(req.file.buffer, {
      metadata: { contentType: req.file.mimetype },
      preconditionOpts: { ifGenerationMatch: 0 } // Prevent overwrite
    });

    // Generate signed URL (expires in 7 days)
    const [url] = await fileRef.getSignedUrl({ action: 'read', expires: Date.now() + 7 * 24 * 60 * 60 * 1000 });

    const docData = {
      userId, docType, fileName, originalName: req.file.originalname,
      size: req.file.size, mimeType: req.file.mimetype, downloadUrl: url,
      createdAt: admin.firestore.FieldValue.serverTimestamp()
    };

    const ref = await withTimeout(db.collection('documents').add(docData));
    sendResponse(res, 201, true, { id: ref.id, downloadUrl: url });
  } catch (err) {
    console.error('Document upload error:', err.message);
    sendResponse(res, 500, false, null, 'An error occurred during upload');
  }
});

app.get('/api/documents', verifyToken, async (req, res) => {
  try {
    const userId = req.user.uid;
    const snapshot = await withTimeout(db.collection('documents').where('userId', '==', userId).get());
    const docs = snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));
    sendResponse(res, 200, true, docs);
  } catch (err) {
    console.error('Document fetch error:', err.message);
    sendResponse(res, 500, false, null, 'An error occurred');
  }
});

// --- STRIPE WEBHOOK (Must be raw body) ---
app.post('/api/stripe-webhook', express.raw({ type: 'application/json' }), async (req, res) => {
  const sig = req.headers['stripe-signature'];
  let event;

  try {
    // 1. Verify signature and timestamp (prevents replay attacks)
    event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    console.error('Webhook signature verification failed:', err.message);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  try {
    // 2. Handle specific events
    if (event.type === 'payment_intent.succeeded') {
      const paymentIntent = event.data.object;
      const userId = paymentIntent.metadata.userId; // Must be passed from frontend during PI creation

      if (userId) {
        await withTimeout(db.collection('users').doc(userId).update({
          lastPaymentSuccess: admin.firestore.FieldValue.serverTimestamp(),
          paymentStatus: 'succeeded'
        }));
      }
    }
    // 3. Return 200 immediately to Stripe
    res.json({ received: true });
  } catch (err) {
    console.error('Webhook processing error:', err.message);
    // Still return 200 to Stripe to prevent retries, but log the error
    res.json({ received: true });
  }
});

// ==========================================
// 6. GLOBAL ERROR HANDLER
// ==========================================
app.use((err, req, res, next) => {
  console.error('Unhandled server error:', err.message);
  // NEVER expose stack traces or internal details to the client
  sendResponse(res, 500, false, null, 'An internal server error occurred');
});

const PORT = process.env.PORT || 8080;
app.listen(PORT, () => {
  console.log(`Server running securely on port ${PORT}`);
});
