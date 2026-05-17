import { Response } from "express";
import { AuthRequest } from "../../shared/middlewares/auth.middleware";
import { AdminService } from "./admin.service";

const adminService = new AdminService();

export class AdminController {
  async revenueSummary(req: AuthRequest, res: Response): Promise<void> {
    try {
      const raw = typeof req.query.months === "string" ? parseInt(req.query.months, 10) : 12;
      const months = Number.isFinite(raw) ? Math.min(Math.max(raw, 3), 24) : 12;
      const data = await adminService.getRevenueSummary(months);
      res.status(200).json({ success: true, data });
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : "Error fetching revenue summary";
      res.status(500).json({ success: false, message });
    }
  }

  async listShipments(req: AuthRequest, res: Response): Promise<void> {
    try {
      const status = typeof req.query.status === "string" ? req.query.status.trim() : undefined;
      const rawLimit =
        typeof req.query.limit === "string" ? parseInt(req.query.limit, 10) : undefined;
      const limit = rawLimit !== undefined && Number.isFinite(rawLimit) ? rawLimit : undefined;
      const data = await adminService.listShipments({ status: status || undefined, limit });
      res.status(200).json({ success: true, data });
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : "Error fetching shipments";
      res.status(500).json({ success: false, message });
    }
  }

  async getShipment(req: AuthRequest, res: Response): Promise<void> {
    try {
      const { id } = req.params;
      if (!id) {
        res.status(400).json({ success: false, message: "Shipment id is required" });
        return;
      }
      const data = await adminService.getShipmentById(id);
      if (!data) {
        res.status(404).json({ success: false, message: "Shipment not found" });
        return;
      }
      res.status(200).json({ success: true, data });
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : "Error fetching shipment";
      res.status(500).json({ success: false, message });
    }
  }

  async listAvailableRiders(_req: AuthRequest, res: Response): Promise<void> {
    try {
      const data = await adminService.listAvailableRiders();
      res.status(200).json({ success: true, data });
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : "Error fetching available riders";
      res.status(500).json({ success: false, message });
    }
  }

  async assignShipment(req: AuthRequest, res: Response): Promise<void> {
    try {
      const { id } = req.params;
      const { riderId } = req.body as { riderId?: string };
      if (!id) {
        res.status(400).json({ success: false, message: "Shipment id is required" });
        return;
      }
      if (!riderId || typeof riderId !== "string") {
        res.status(400).json({ success: false, message: "riderId is required" });
        return;
      }
      const data = await adminService.assignShipmentToRider(id, riderId.trim());
      res.status(200).json({
        success: true,
        message: "Rider assigned; awaiting rider acceptance",
        data,
      });
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : "Error assigning rider";
      const status = message.includes("not found")
        ? 404
        : message.includes("cannot be assigned") || message.includes("not available")
          ? 400
          : 500;
      res.status(status).json({ success: false, message });
    }
  }

  async listClients(req: AuthRequest, res: Response): Promise<void> {
    try {
      const q = typeof req.query.q === "string" ? req.query.q.trim() : undefined;
      const rawLimit =
        typeof req.query.limit === "string" ? parseInt(req.query.limit, 10) : undefined;
      const limit = rawLimit !== undefined && Number.isFinite(rawLimit) ? rawLimit : undefined;
      const data = await adminService.listClients({ q: q || undefined, limit });
      res.status(200).json({ success: true, data });
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : "Error fetching clients";
      res.status(500).json({ success: false, message });
    }
  }

  async getClient(req: AuthRequest, res: Response): Promise<void> {
    try {
      const { id } = req.params;
      if (!id) {
        res.status(400).json({ success: false, message: "Client id is required" });
        return;
      }
      const data = await adminService.getClientById(id);
      if (!data) {
        res.status(404).json({ success: false, message: "Client not found" });
        return;
      }
      res.status(200).json({ success: true, data });
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : "Error fetching client";
      res.status(500).json({ success: false, message });
    }
  }

  async getClientActivity(req: AuthRequest, res: Response): Promise<void> {
    try {
      const { id } = req.params;
      if (!id) {
        res.status(400).json({ success: false, message: "Client id is required" });
        return;
      }
      const data = await adminService.getClientActivity(id);
      if (!data) {
        res.status(404).json({ success: false, message: "Client not found" });
        return;
      }
      res.status(200).json({ success: true, data });
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : "Error fetching client activity";
      res.status(500).json({ success: false, message });
    }
  }

  async updateClientStatus(req: AuthRequest, res: Response): Promise<void> {
    try {
      const { id } = req.params;
      const { status } = req.body as { status?: string };
      if (!id) {
        res.status(400).json({ success: false, message: "Client id is required" });
        return;
      }
      if (status !== "active" && status !== "suspended" && status !== "blocked") {
        res.status(400).json({
          success: false,
          message: "status must be 'active', 'suspended', or 'blocked'",
        });
        return;
      }
      const data = await adminService.updateClientStatus(id, status);
      res.status(200).json({ success: true, message: "Client status updated", data });
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : "Error updating client status";
      const code = message.includes("not found") ? 404 : message.includes("status must") ? 400 : 500;
      res.status(code).json({ success: false, message });
    }
  }
}
