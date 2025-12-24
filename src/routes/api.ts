import { Express } from "express";
import authRoutes from "../modules/auth/auth.route";

export const setupRoutes = (app: Express): void => {
  // Root route
  app.get("/", (_req, res) => {
    res.send("Server is running on port 5000");
  });

  // Auth routes
  app.use("/api/auth", authRoutes);
};