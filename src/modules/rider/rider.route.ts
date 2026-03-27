import { Router } from "express";
import { RiderController } from "./rider.controller";
import { authMiddleware, AuthRequest } from "../../shared/middlewares/auth.middleware";
import { adminMiddleware } from "../../shared/middlewares/admin.middleware";

const router = Router();
const riderController = new RiderController();

router.use(authMiddleware);

router.get("/me", (req, res) => riderController.getMe(req as AuthRequest, res));
router.patch("/me/location", (req, res) => riderController.updateMyLocation(req as AuthRequest, res));

router.use(adminMiddleware);

router.post("/", (req, res) => riderController.create(req as AuthRequest, res));
router.get("/", (req, res) => riderController.list(req as AuthRequest, res));
router.get("/:id", (req, res) => riderController.getById(req as AuthRequest, res));
router.patch("/:id", (req, res) => riderController.update(req as AuthRequest, res));
router.patch("/:id/status", (req, res) => riderController.updateStatus(req as AuthRequest, res));

export default router;
