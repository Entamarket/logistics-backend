import cors from "cors";
import { CorsOptions } from "cors";

/**
 * Get CORS origins from environment variable
 * @returns Array of allowed origins
 */
const getAllowedOrigins = (): string[] => {
  const originsEnv = process.env.CORS_ORIGINS;
  
  if (!originsEnv) {
    // Default to localhost if not specified
    return ["http://localhost:3000"];
  }

  // Split by comma and trim whitespace
  return originsEnv.split(",").map((origin) => origin.trim());
};

/**
 * CORS configuration
 */
export const corsOptions: CorsOptions = {
  origin: (origin, callback) => {
    const allowedOrigins = getAllowedOrigins();

    // Allow requests with no origin (like mobile apps or Postman)
    if (!origin) {
      return callback(null, true);
    }

    // Check if the origin is in the allowed list
    if (allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error("Not allowed by CORS"));
    }
  },
  credentials: true, // Allow cookies to be sent
  methods: ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
  exposedHeaders: ["Content-Type"],
};

/**
 * CORS middleware
 */
export const corsMiddleware = cors(corsOptions);

