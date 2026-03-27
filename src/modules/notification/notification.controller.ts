import { Response } from "express";
import { AuthRequest } from "../../shared/middlewares/auth.middleware";
import { NotificationService } from "./notification.service";

const notificationService = new NotificationService();

export class NotificationController {
  async list(req: AuthRequest, res: Response): Promise<void> {
    try {
      const userId = req.userId;
      if (!userId) {
        res.status(401).json({ success: false, message: "Authentication required" });
        return;
      }
      const limit = Math.min(parseInt(String(req.query.limit), 10) || 50, 100);
      const data = await notificationService.listForUser(userId, limit);
      res.status(200).json({ success: true, data });
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : "Error fetching notifications";
      res.status(500).json({ success: false, message });
    }
  }

  async unreadCount(req: AuthRequest, res: Response): Promise<void> {
    try {
      const userId = req.userId;
      if (!userId) {
        res.status(401).json({ success: false, message: "Authentication required" });
        return;
      }
      const count = await notificationService.countUnread(userId);
      res.status(200).json({ success: true, data: { count } });
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : "Error fetching unread count";
      res.status(500).json({ success: false, message });
    }
  }

  async markRead(req: AuthRequest, res: Response): Promise<void> {
    try {
      const userId = req.userId;
      if (!userId) {
        res.status(401).json({ success: false, message: "Authentication required" });
        return;
      }
      const { id } = req.params;
      const updated = await notificationService.markRead(id, userId);
      if (!updated) {
        res.status(404).json({ success: false, message: "Notification not found" });
        return;
      }
      res.status(200).json({ success: true, data: updated });
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : "Error updating notification";
      res.status(500).json({ success: false, message });
    }
  }

  async markAllRead(req: AuthRequest, res: Response): Promise<void> {
    try {
      const userId = req.userId;
      if (!userId) {
        res.status(401).json({ success: false, message: "Authentication required" });
        return;
      }
      const modified = await notificationService.markAllRead(userId);
      res.status(200).json({ success: true, data: { modified } });
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : "Error updating notifications";
      res.status(500).json({ success: false, message });
    }
  }
}
