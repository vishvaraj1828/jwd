import express from "express";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import rateLimit from "express-rate-limit";
import profiles from "../modals/profile.js";

const router = express.Router();

// Rate limit for login/register
router.use(
  rateLimit({
    windowMs: 20 * 60 * 1000,
    max: 5,
    message: "Too many requests, try again later",
  })
);

// Verify JWT token middleware
function verifyToken(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader) {
    return res.status(401).json({ message: "No token provided" });
  }

  const tokenSignature = authHeader.split(" ")[1];

  jwt.verify(tokenSignature, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      if (err.name === "TokenExpiredError") {
        return res.status(401).json({ message: "Access token expired" });
      } else {
        return res.status(403).json({ message: "Invalid token" });
      }
    }

    req.profile = decoded;
    next();
  });
}

// REGISTER
router.post("/api/register", async (req, res) => {
  try {
    const { name, email, role, adminCode, imageUrl, password } = req.body;
    if (!name || !email || !role || !imageUrl || !password) {
      return res.status(400).json({ message: "All fields are required" });
    }

    let userRole = role;
    if (role === "admin" && adminCode !== process.env.ADMIN_CODE) {
      return res.status(403).json({ message: `Invalid admin code` });
    } else if (role !== "admin") {
      userRole = "user";
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    await profiles.create({
      name,
      email,
      password: hashedPassword,
      role: userRole,
      imageUrl,
    });

    res.status(200).json({ message: `User created with role: ${userRole}` });
  } catch (error) {
    res.status(500).json({ message: `Something went wrong ${error}` });
  }
});

// LOGIN
router.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    const profile = await profiles.findOne({ email });
    if (!profile) {
      return res.status(404).json({ message: `User with ${email} not found` });
    }

    const isMatch = await bcrypt.compare(password, profile.password);
    if (!isMatch) {
      return res.status(401).json({ message: "Invalid password" });
    }

    const accessToken = jwt.sign(
      { id: profile._id, role: profile.role },
      process.env.JWT_SECRET,
      { expiresIn: "10m" }
    );

    const refreshToken = jwt.sign(
      { id: profile._id },
      process.env.JWT_REFRESH_SECRET,
      { expiresIn: "2d" }
    );

    profile.refreshToken = refreshToken;
    await profile.save();

    res.status(200).json({
      id: profile._id,
      accessToken,
      refreshToken,
      role: profile.role,
    });
  } catch (error) {
    res.status(500).json({ message: `Something went wrong ${error}` });
  }
});

// GET USERS / GET SELF
router.get("/api/users", verifyToken, async (req, res) => {
  try {
    if (req.profile.role === "admin") {
      const users = await profiles.find({}, "-password -refreshToken");
      return res.status(200).json(users);
    }

    const user = await profiles.findById(req.profile.id, "-password -refreshToken");
    res.status(200).json(user);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// UPDATE USER
router.put("/api/users/:id", verifyToken, async (req, res) => {
  try {
    const { name, role, imageUrl } = req.body;

    // Admin can update anyone; user can update only themselves
    if (req.profile.role !== "admin" && req.profile.id !== req.params.id) {
      return res.status(403).json({ message: "Access denied" });
    }

    const updateData = { name, imageUrl };

    // Only admin can update roles
    if (req.profile.role === "admin" && role) {
      updateData.role = role;
    }

    const updatedUser = await profiles.findByIdAndUpdate(
      req.params.id,
      updateData,
      { new: true }
    );

    if (!updatedUser) {
      return res.status(404).json({ message: "User not found" });
    }

    res.status(200).json({
      message: "User updated successfully",
      user: updatedUser,
    });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// DELETE USER
router.delete("/api/users/:id", verifyToken, async (req, res) => {
  try {
    // Only admin can delete
    if (req.profile.role !== "admin") {
      return res.status(403).json({
        message: `Access denied because you are a ${req.profile.role}`,
      });
    }

    const deleted = await profiles.findByIdAndDelete(req.params.id);

    if (!deleted) {
      return res.status(404).json({ message: "User not found" });
    }

    res
      .status(200)
      .json({ message: `User with id ${req.params.id} has been deleted` });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// REFRESH TOKEN
router.post("/api/refresh", async (req, res) => {
  const { token } = req.body;

  if (!token) return res.status(401).json({ message: "No refresh token" });

  try {
    const decoded = jwt.verify(token, process.env.JWT_REFRESH_SECRET);

    const profile = await profiles.findById(decoded.id);
    if (!profile || profile.refreshToken !== token) {
      return res.status(403).json({ message: "Invalid refresh token" });
    }

    const newAccessToken = jwt.sign(
      { id: profile._id, role: profile.role },
      process.env.JWT_SECRET,
      { expiresIn: "1m" }
    );

    res.status(200).json({ accessToken: newAccessToken });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

export default router;
