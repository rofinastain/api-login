require('dotenv').config();
const express = require('express');
const { Firestore } = require('@google-cloud/firestore');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const admin = require('firebase-admin'); // Import Firebase Admin SDK
const serviceAccount = require('./service-account.json'); // Sesuaikan dengan path yang benar

const app = express();
const port = 3000;

// Inisialisasi Firestore
const firestore = new Firestore({
  projectId: 'nutrifish-425413',
  keyFilename: 'service-account.json',
});

// Inisialisasi Firebase Admin SDK
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
  databaseURL: 'https://nutrifish-425413.firebaseio.com' // Sesuaikan dengan URL database Anda
});

// Middleware untuk parsing JSON
app.use(express.json());

// Secret key untuk JWT dari environment variable
const JWT_SECRET = process.env.JWT_SECRET;

// Register endpoint
app.post('/register', async (req, res) => {
  const { email, password, name, username, profilpictURL } = req.body;

  if (!email || !password || !name || !username) {
    return res.status(400).send('Email, password, name, and username are required');
  }

  try {
    // Check if the email is already registered
    const emailRef = firestore.collection('users').doc(email);
    const emailDoc = await emailRef.get();

    if (emailDoc.exists) {
      return res.status(400).send('Email is already registered');
    }

    // Check if the username is already taken
    const usernameQuery = await firestore.collection('users').where('username', '==', username).get();
    if (!usernameQuery.empty) {
      return res.status(400).send('Username is already taken');
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Save user to Firestore
    await emailRef.set({
      email,
      name,
      password: hashedPassword,
      username // Optional field
    });

    // Create user in Firebase Authentication
    const userRecord = await admin.auth().createUser({
      email: email,
      password: password,
      displayName: name
      // You can add more fields here if needed
    });

    // Save Firebase Authentication UID to Firestore
    await emailRef.update({ firebaseUid: userRecord.uid });

    res.status(201).send('User registered successfully');
  } catch (error) {
    console.error('Error registering user:', error);
    res.status(500).send('Internal server error');
  }
});

// Login endpoint
app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({
      error: true,
      message: 'Email and password are required'
    });
  }

  try {
    // Check if the user exists
    const userRef = firestore.collection('users').doc(email);
    const userDoc = await userRef.get();

    if (!userDoc.exists) {
      return res.status(400).json({
        error: true,
        message: 'Invalid email or password'
      });
    }

    const userData = userDoc.data();

    // Verify the password
    const isPasswordValid = await bcrypt.compare(password, userData.password);

    if (!isPasswordValid) {
      return res.status(400).json({
        error: true,
        message: 'Invalid email or password'
      });
    }

    // Generate JWT token
    const token = jwt.sign({ email }, JWT_SECRET, { expiresIn: '1h' });

    res.status(200).json({
      error: false,
      message: 'success',
      loginResult: {
        username: userData.username,
        name: userData.name,
        token: token
      }
    });
  } catch (error) {
    console.error('Error logging in:', error);
    res.status(500).json({
      error: true,
      message: 'Internal server error'
    });
  }
});

app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
  });
  