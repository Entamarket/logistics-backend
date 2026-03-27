import { Response } from "express";
import { RiderService } from "./rider.service";
import { AuthRequest } from "../../shared/middlewares/auth.middleware";

const riderService = new RiderService();

export class RiderController {
  async create(req: AuthRequest, res: Response): Promise<void> {
    try {
      const { firstName, lastName, email, phone, password } = req.body;
      if (!firstName || !lastName || !email || !phone || !password) {
        res.status(400).json({
          success: false,
          message: "firstName, lastName, email, phone, and password are required",
        });
        return;
      }
      if (typeof password !== "string" || password.length < 8) {
        res.status(400).json({
          success: false,
          message: "Password must be at least 8 characters",
        });
        return;
      }
      const rider = await riderService.create({ firstName, lastName, email, phone, password });
      res.status(201).json({
        success: true,
        message: "Rider created successfully",
        data: rider,
      });
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : "Error creating rider";
      res.status(400).json({ success: false, message });
    }
  }

  async list(_req: AuthRequest, res: Response): Promise<void> {
    try {
      const riders = await riderService.findAll();
      res.status(200).json({
        success: true,
        data: riders,
      });
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : "Error fetching riders";
      res.status(400).json({ success: false, message });
    }
  }

  async getById(req: AuthRequest, res: Response): Promise<void> {
    try {
      const { id } = req.params;
      const rider = await riderService.findById(id);
      if (!rider) {
        res.status(404).json({ success: false, message: "Rider not found" });
        return;
      }
      res.status(200).json({
        success: true,
        data: rider,
      });
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : "Error fetching rider";
      res.status(400).json({ success: false, message });
    }
  }

  async update(req: AuthRequest, res: Response): Promise<void> {
    try {
      const { id } = req.params;
      const { status, isAvailable, isVerified, firstName, lastName, phone, email } = req.body;
      const rider = await riderService.update(id, {
        status,
        isAvailable,
        isVerified,
        firstName,
        lastName,
        phone,
        email,
      });
      if (!rider) {
        res.status(404).json({ success: false, message: "Rider not found" });
        return;
      }
      res.status(200).json({
        success: true,
        message: "Rider updated successfully",
        data: rider,
      });
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : "Error updating rider";
      res.status(400).json({ success: false, message });
    }
  }

  async getMe(req: AuthRequest, res: Response): Promise<void> {
    try {
      if (req.user?.role !== "rider") {
        res.status(403).json({ success: false, message: "Rider access required" });
        return;
      }
      const userId = req.userId;
      if (!userId) {
        res.status(401).json({ success: false, message: "Authentication required" });
        return;
      }
      const rider = await riderService.findByUserId(userId);
      if (!rider) {
        res.status(404).json({ success: false, message: "Rider profile not found" });
        return;
      }
      res.status(200).json({
        success: true,
        data: rider,
      });
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : "Error fetching rider profile";
      res.status(400).json({ success: false, message });
    }
  }

  async updateMyLocation(req: AuthRequest, res: Response): Promise<void> {
    try {
      if (req.user?.role !== "rider") {
        res.status(403).json({ success: false, message: "Rider access required" });
        return;
      }
      const userId = req.userId;
      if (!userId) {
        res.status(401).json({ success: false, message: "Authentication required" });
        return;
      }
      const { longitude, latitude } = req.body;
      const lng = typeof longitude === "number" ? longitude : parseFloat(String(longitude));
      const lat = typeof latitude === "number" ? latitude : parseFloat(String(latitude));
      if (Number.isNaN(lng) || Number.isNaN(lat) || lng < -180 || lng > 180 || lat < -90 || lat > 90) {
        res.status(400).json({
          success: false,
          message: "longitude and latitude are required (valid ranges: lng -180..180, lat -90..90)",
        });
        return;
      }
      const rider = await riderService.updateLocationByUserId(userId, lng, lat);
      if (!rider) {
        res.status(404).json({ success: false, message: "Rider profile not found" });
        return;
      }
      res.status(200).json({
        success: true,
        message: "Location updated",
        data: rider,
      });
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : "Error updating location";
      res.status(400).json({ success: false, message });
    }
  }

  async updateStatus(req: AuthRequest, res: Response): Promise<void> {
    try {
      const { id } = req.params;
      const { status } = req.body;
      if (status !== "active" && status !== "suspended" && status !== "blocked") {
        res.status(400).json({
          success: false,
          message: "status must be 'active', 'suspended', or 'blocked'",
        });
        return;
      }
      const rider = await riderService.updateStatus(id, status);
      if (!rider) {
        res.status(404).json({ success: false, message: "Rider not found" });
        return;
      }
      res.status(200).json({
        success: true,
        message: `Rider ${status} successfully`,
        data: rider,
      });
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : "Error updating rider status";
      res.status(400).json({ success: false, message });
    }
  }
}
