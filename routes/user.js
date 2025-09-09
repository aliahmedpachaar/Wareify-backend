// routes/user.js
const express = require("express");
const router = express.Router();
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const User = require("../models/User");

const JWT_SECRET = "supersecretkey";

// Register
router.post("/register", async (req, res) => {
  const { email, password, role } = req.body;
  const existingUser = await User.findOne({ email });
  if (existingUser) return res.status(400).send("User already exists");

  const hashed = await bcrypt.hash(password, 10);
  await User.create({ email, password: hashed, role });
  res.send("User registered successfully");
});

// Login
router.post("/login", async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });
  if (!user) return res.status(404).send("User not found");

  const valid = await bcrypt.compare(password, user.password);
  if (!valid) return res.status(401).send("Wrong password");

  const token = jwt.sign({ id: user._id, role: user.role }, JWT_SECRET, {
    expiresIn: "2h",
  });

  res.json({ token, role: user.role, message: "Login successful" });
});

module.exports = router;
