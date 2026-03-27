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

router.get("/rider/me", authMiddleware, (req, res) =>
  shipmentController.getShipmentsForRider(req as AuthRequest, res)
);

router.patch("/:id/rider/accept", authMiddleware, (req, res) =>
  shipmentController.acceptRiderOffer(req as AuthRequest, res)
);

router.patch("/:id/rider/reject", authMiddleware, (req, res) =>
  shipmentController.rejectRiderOffer(req as AuthRequest, res)
);

router.patch("/:id/delivered", authMiddleware, (req, res) =>
  shipmentController.markDelivered(req as AuthRequest, res)
);

export default router;
