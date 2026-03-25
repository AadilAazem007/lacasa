const bcrypt = require("bcryptjs");
const User = require("../models/User");
const generateToken = require("../utils/generateToken");

let blacklist = []; // simple logout memory store

// REGISTER
exports.register = async (req, res) => {
  try {
    const { name, email, password } = req.body;

    const userExists = await User.findOne({ email });
    if (userExists)
      return res.status(400).json({ message: "User already exists" });

    const hash = await bcrypt.hash(password, 10);

    const user = await User.create({
      name,
      email,
      password: hash,
    });

    res.json({
      message: "User registered",
      userId: user._id,
    });
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
};

// LOGIN
exports.login = async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email });
    if (!user)
      return res.status(400).json({ message: "Invalid credentials" });

    const match = await bcrypt.compare(password, user.password);
    if (!match)
      return res.status(400).json({ message: "Invalid credentials" });

    const token = generateToken(user._id);

    res.json({
      message: "Login success",
      token,
    });
  } catch {
    res.status(500).json({ message: "Server error" });
  }
};

// PROFILE (Protected)
exports.profile = async (req, res) => {
  const user = await User.findById(req.user).select("-password");
  res.json(user);
};

// LOGOUT
exports.logout = async (req, res) => {
  const token = req.headers.authorization.split(" ")[1];
  blacklist.push(token);
  res.json({ message: "Logged out" });
};