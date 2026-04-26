import { Response } from "express";
import { AuthRequest } from "../../shared/middlewares/auth.middleware";
import { FeedbackService } from "./feedback.service";

const feedbackService = new FeedbackService();

export class FeedbackController {
  async create(req: AuthRequest, res: Response): Promise<void> {
    try {
      if (req.user?.role !== "client") {
        res.status(403).json({ success: false, message: "Client access required" });
        return;
      }
      const userId = req.userId;
      if (!userId) {
        res.status(401).json({ success: false, message: "Authentication required" });
        return;
      }

      const { shipmentId, rating, comment } = req.body;
      if (!shipmentId) {
        res.status(400).json({ success: false, message: "shipmentId is required" });
        return;
      }

      const parsedRating = typeof rating === "number" ? rating : parseInt(String(rating), 10);
      const data = await feedbackService.createForDeliveredShipment({
        clientUserId: userId,
        shipmentId: String(shipmentId),
        rating: parsedRating,
        comment: typeof comment === "string" ? comment : "",
      });
      res.status(201).json({ success: true, message: "Feedback submitted", data });
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : "Error submitting feedback";
      const lower = message.toLowerCase();
      const status =
        lower.includes("not authorized") || lower.includes("client access required")
          ? 403
          : lower.includes("not found")
            ? 404
            : 400;
      res.status(status).json({ success: false, message });
    }
  }

  async listMine(req: AuthRequest, res: Response): Promise<void> {
    try {
      if (req.user?.role !== "client") {
        res.status(403).json({ success: false, message: "Client access required" });
        return;
      }
      const userId = req.userId;
      if (!userId) {
        res.status(401).json({ success: false, message: "Authentication required" });
        return;
      }
      const data = await feedbackService.listForClient(userId);
      res.status(200).json({ success: true, data });
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : "Error fetching feedback";
      res.status(500).json({ success: false, message });
    }
  }
}
