import { Router } from "express";
import { ShipmentController } from "./shipment.controller";
import { authMiddleware, AuthRequest } from "../../shared/middlewares/auth.middleware";

const router = Router();
const shipmentController = new ShipmentController();

router.post("/", authMiddleware, (req, res) =>
  shipmentController.createShipment(req as AuthRequest, res)
);

router.get("/", authMiddleware, (req, res) =>
  shipmentController.getShipments(req as AuthRequest, res)
);

export default router;
