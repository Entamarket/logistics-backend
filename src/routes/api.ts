import { Express } from "express";
import authRoutes from "../modules/auth/auth.route";
import shipmentRoutes from "../modules/shipment/shipment.route";
import riderRoutes from "../modules/rider/rider.route";

export const setupRoutes = (app: Express): void => {
  // Root route
  app.get("/", (_req, res) => {
    res.send(`Server is running on port 4000`);
  });

  // Auth routes
  app.use("/api/auth", authRoutes);

  // Shipment routes (protected)
  app.use("/api/shipments", shipmentRoutes);

  // Rider routes (admin only)
  app.use("/api/riders", riderRoutes);
};