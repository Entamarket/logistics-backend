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
}
