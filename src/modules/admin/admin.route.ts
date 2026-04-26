import { Router } from "express";
import { authMiddleware, AuthRequest } from "../../shared/middlewares/auth.middleware";
import { adminMiddleware } from "../../shared/middlewares/admin.middleware";
import { AdminController } from "./admin.controller";

const router = Router();
const adminController = new AdminController();

router.use(authMiddleware);
router.use(adminMiddleware);

router.get("/revenue", (req, res) => adminController.revenueSummary(req as AuthRequest, res));

export default router;
