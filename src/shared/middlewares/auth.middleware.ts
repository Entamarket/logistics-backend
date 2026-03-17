import { Request, Response, NextFunction } from "express";
import jwt from "jsonwebtoken";

export interface AuthPayload {
  id: string;
  email: string;
  role: string;
}

export interface AuthRequest extends Request {
  userId?: string;
  user?: AuthPayload;
}

export const authMiddleware = (
  req: AuthRequest,
  res: Response,
  next: NextFunction
): void => {
  const token = req.cookies?.token;

  if (!token) {
    res.status(401).json({ success: false, message: "Authentication required" });
    return;
  }

  const jwtSecret = process.env.JWT_SECRET || "your-secret-key-change-in-production";

  try {
    const decoded = jwt.verify(token, jwtSecret) as AuthPayload;
    req.userId = decoded.id;
    req.user = decoded;
    next();
  } catch {
    res.status(401).json({ success: false, message: "Invalid or expired token" });
  }
};
