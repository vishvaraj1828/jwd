import express from "express";
import cors from "cors";
import mongoose from "mongoose";
import dotenv from "dotenv";     // FIXED spelling
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import profileRouter from "./routes/profileRoutes.js";

dotenv.config();                 // FIXED spelling

const app = express();

app.set("trust proxy", 1);

app.use(
  rateLimit({
    windowMs: 1 * 60 * 1000,
    max: 100,
    message: "Too many requests,try again later",
  })
);

app.use(cors());
app.use(express.json());
app.use(helmet());
app.use(express.urlencoded({ extended: true }));

// ROUTES
app.use("/", profileRouter);

mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log("MongoDB connected"))
  .catch((err) => console.log("Mongo ERROR:", err));

const PORT = process.env.PORT || 5000;
app.listen(PORT, () =>
  console.log(`server running on http://localhost:${PORT}`)
);
