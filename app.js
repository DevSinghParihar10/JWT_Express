const express = require("express");
const bodyParser = require("body-parser");
const bcrypt = require("bcrypt");
const mongoose = require("mongoose");
const User = require("./models/User");
const jwt = require("jsonwebtoken");
const axios = require("axios");
const https=require('https');
const swaggerJsdoc = require('swagger-jsdoc');
const swaggerUi = require('swagger-ui-express');

const app = express();
const PORT = 3000;
const SECRET_KEY = "your_secret_key";
app.use(bodyParser.json());

const swaggerOptions = {
    swaggerDefinition: {
      info: {
        title: 'JWT Authentication API',
        version: '1.0.0',
        description: 'API endpoints for user authentication using JWT',
      },
    },
    apis: ['app.js'], // Path to the API routes file
  };

// Initialize Swagger
const swaggerSpec = swaggerJsdoc(swaggerOptions);

// Serve Swagger UI
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec));  

// Connect to MongoDB
mongoose
  .connect("mongodb://localhost:27017/expressUsers")
  .then(() => {
    console.log("Connected to MongoDB");
  })
  .catch((error) => {
    console.error("Error connecting to MongoDB:", error);
  });
// User Registration
/**
 * @swagger
 * /register:
 *   post:
 *     summary: Register a new user
 *     description: Register a new user.
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               name:
 *                 type: string
 *               age:
 *                 type: number      
 *               company:
 *                 type: string   
 *               username:
 *                 type: string
 *               password:
 *                 type: string
 *     responses:
 *       '201':
 *         description: User registered successfully
 *       '400':
 *         description: User already exists
 */
app.post("/register", async (req, res) => {
  const { name, age, company, username, password } = req.body;
  if (!name || !age || !company || !username || !password) {
    return res.status(400).json({ message: "All fields are required" });
  }

  try {
    // Check if the user already exists
    const existingUser = await User.findOne({ username });
    if (existingUser) {
      return res.status(400).json({ message: "User already exists" });
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create a new user
    const newUser = new User({
      name,
      age,
      company,
      username,
      password: hashedPassword,
    });
    await newUser.save();

    res.status(201).json({ message: "User registered successfully" });
  } catch (error) {
    console.error("Error registering user:", error);
    res.status(500).json({ message: "Internal Server Error" });
  }
});

// User Login
/**
 * @swagger
 * /login:
 *   post:
 *     summary: Log in as an existing user
 *     description: Log in using username and password to obtain a JWT token.
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               username:
 *                 type: string
 *               password:
 *                 type: string
 *     responses:
 *       '200':
 *         description: JWT token generated successfully
 *       '401':
 *         description: Invalid credentials
 */
app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res
      .status(400)
      .json({ message: "Username and password are required" });
  }

  try {
    // Find the user in the database
    const user = await User.findOne({ username });
    if (!user) {
      return res.status(401).json({ message: "Invalid username or password" });
    }

    // Compare passwords
    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      return res.status(401).json({ message: "Invalid username or password" });
    }

    // Generate JWT token
    const token = jwt.sign({ username }, SECRET_KEY, { expiresIn: "1h" });
    res.json({ token });
  } catch (error) {
    console.error("Error during login:", error);
    res.status(500).json({ message: "Internal Server Error" });
  }
});

// Logout (No need to implement anything as JWT tokens are stateless)

// Protected route example
/**
 * @swagger
 * /protected:
 *   get:
 *     summary: Access protected route
 *     description: Access a protected route by providing a valid JWT token in the Authorization header.
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       '200':
 *         description: Protected route accessed successfully
 *       '401':
 *         description: Unauthorized
 *       '403':
 *         description: Token is not valid
 */
app.get("/protected", verifyToken, (req, res) => {
  res.json({ message: "Protected route accessed successfully" });
});

// Function to verify JWT token
function verifyToken(req, res, next) {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) {
    return res.status(403).json({ message: "No token provided" });
  }

  jwt.verify(token, SECRET_KEY, (err, decoded) => {
    if (err) {
      return res.status(401).json({ message: "Failed to authenticate token" });
    }
    req.username = decoded.username;
    next();
  });
}

app.get("/apis", async (req, res) => {
  try {
    // Fetch data from the public API
    const response = await axios.get("https://api.publicapis.org/entries", {
      httpsAgent: new https.Agent({ rejectUnauthorized: false }),
    });

    // Extract the data from the response
    const { entries } = response.data;

    // Apply filtering based on query parameters
    let filteredData = entries;

    // Filter by category if category query parameter is provided
    const category = req.query.category;
    if (category) {
      filteredData = filteredData.filter(
        (entry) => entry.Category.toLowerCase() === category.toLowerCase()
      );
    }

    // Limit the number of results if limit query parameter is provided
    const limit = parseInt(req.query.limit);
    if (!isNaN(limit)) {
      filteredData = filteredData.slice(0, limit);
    }

    // Send the filtered data as the response
    res.json(filteredData);
  } catch (error) {
    console.error("Error fetching data:", error);
    res.status(500).json({ message: "Internal Server Error" });
  }
});

// Start the server
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
