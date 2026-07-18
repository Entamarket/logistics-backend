import { Express } from "express";
import { setupSwagger } from "../config/swagger";
import authRoutes from "../modules/auth/auth.route";
import shipmentRoutes from "../modules/shipment/shipment.route";
import riderRoutes from "../modules/rider/rider.route";
import notificationRoutes from "../modules/notification/notification.route";
import feedbackRoutes from "../modules/feedback/feedback.route";
import complaintRoutes from "../modules/complaint/complaint.route";
import contactRoutes from "../modules/contact/contact.route";
import adminRoutes from "../modules/admin/admin.route";

export const setupRoutes = (app: Express): void => {
  setupSwagger(app);

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

  app.use("/api/notifications", notificationRoutes);
  app.use("/api/feedback", feedbackRoutes);
  app.use("/api/complaints", complaintRoutes);
  app.use("/api/contact", contactRoutes);
  app.use("/api/admin", adminRoutes);
};