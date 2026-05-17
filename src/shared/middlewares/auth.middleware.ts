import { Request, Response, NextFunction } from "express";
import jwt from "jsonwebtoken";
import { User } from "../models/User";
import { UserAccountStatus } from "../lib/enums";

export interface AuthPayload {
  id: string;
  email: string;
  role: string;
}

export interface AuthRequest extends Request {
  userId?: string;
  user?: AuthPayload;
}

export const authMiddleware = async (
  req: AuthRequest,
  res: Response,
  next: NextFunction
): Promise<void> => {
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

    if (decoded.role === "client") {
      const user = await User.findById(decoded.id).select("status role").lean().exec();
      if (!user) {
        res.status(401).json({ success: false, message: "User not found" });
        return;
      }
      const status = user.status || UserAccountStatus.ACTIVE;
      if (status === UserAccountStatus.SUSPENDED) {
        res.status(403).json({
          success: false,
          message: "Your account has been suspended. Contact support for assistance.",
        });
        return;
      }
      if (status === UserAccountStatus.BLOCKED) {
        res.status(403).json({
          success: false,
          message: "Your account has been blocked. Contact support for assistance.",
        });
        return;
      }
    }

    next();
  } catch {
    res.status(401).json({ success: false, message: "Invalid or expired token" });
  }
};
