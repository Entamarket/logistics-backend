import { Router } from "express";
import { authMiddleware, AuthRequest } from "../../shared/middlewares/auth.middleware";
import { NotificationController } from "./notification.controller";

const router = Router();
const controller = new NotificationController();

router.use(authMiddleware);

router.get("/", (req, res) => controller.list(req as AuthRequest, res));
router.get("/unread-count", (req, res) => controller.unreadCount(req as AuthRequest, res));
router.patch("/:id/read", (req, res) => controller.markRead(req as AuthRequest, res));
router.post("/mark-all-read", (req, res) => controller.markAllRead(req as AuthRequest, res));

export default router;
