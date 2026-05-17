import { Router } from "express";
import { authMiddleware, AuthRequest } from "../../shared/middlewares/auth.middleware";
import { adminMiddleware } from "../../shared/middlewares/admin.middleware";
import { AdminController } from "./admin.controller";

const router = Router();
const adminController = new AdminController();

router.use(authMiddleware);
router.use(adminMiddleware);

router.get("/revenue", (req, res) => adminController.revenueSummary(req as AuthRequest, res));
router.get("/available-riders", (req, res) => adminController.listAvailableRiders(req as AuthRequest, res));
router.get("/shipments", (req, res) => adminController.listShipments(req as AuthRequest, res));
router.patch("/shipments/:id/assign", (req, res) => adminController.assignShipment(req as AuthRequest, res));
router.get("/shipments/:id", (req, res) => adminController.getShipment(req as AuthRequest, res));

router.get("/clients", (req, res) => adminController.listClients(req as AuthRequest, res));
router.get("/clients/:id/activity", (req, res) => adminController.getClientActivity(req as AuthRequest, res));
router.patch("/clients/:id/status", (req, res) => adminController.updateClientStatus(req as AuthRequest, res));
router.get("/clients/:id", (req, res) => adminController.getClient(req as AuthRequest, res));

export default router;
