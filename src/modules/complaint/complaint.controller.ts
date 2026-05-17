import { Response } from "express";
import { AuthRequest } from "../../shared/middlewares/auth.middleware";
import { ComplaintService } from "./complaint.service";

const complaintService = new ComplaintService();

export class ComplaintController {
  async create(req: AuthRequest, res: Response): Promise<void> {
    try {
      const userId = req.userId;
      const role = req.user?.role ?? "";
      if (!userId) {
        res.status(401).json({ success: false, message: "Authentication required" });
        return;
      }
      const { subject, message, phone, relatedShipmentId } = req.body as {
        subject?: string;
        message?: string;
        phone?: string;
        relatedShipmentId?: string;
      };
      if (!subject || !message || !phone) {
        res.status(400).json({
          success: false,
          message: "subject, message, and phone are required",
        });
        return;
      }
      const data = await complaintService.create({
        userId,
        role,
        subject,
        message,
        phone,
        relatedShipmentId,
      });
      res.status(201).json({ success: true, message: "Complaint submitted", data });
    } catch (error: unknown) {
      const msg = error instanceof Error ? error.message : "Error submitting complaint";
      const status = msg.includes("Only clients and riders") ? 403 : 400;
      res.status(status).json({ success: false, message: msg });
    }
  }

  async listMine(req: AuthRequest, res: Response): Promise<void> {
    try {
      const userId = req.userId;
      if (!userId) {
        res.status(401).json({ success: false, message: "Authentication required" });
        return;
      }
      const data = await complaintService.listForUser(userId);
      res.status(200).json({ success: true, data });
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : "Error fetching complaints";
      res.status(500).json({ success: false, message });
    }
  }
}
