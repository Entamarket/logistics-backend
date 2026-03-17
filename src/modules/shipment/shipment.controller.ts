import { Response } from "express";
import { ShipmentService } from "./shipment.service";
import { AuthRequest } from "../../shared/middlewares/auth.middleware";

const shipmentService = new ShipmentService();

export class ShipmentController {
  async createShipment(req: AuthRequest, res: Response): Promise<void> {
    try {
      const { deliveryType, senderDetails, recipientDetails, packageDetails, pickupWindowStart, pickupWindowEnd } = req.body;

      if (!senderDetails || !recipientDetails || !packageDetails) {
        res.status(400).json({
          success: false,
          message: "senderDetails, recipientDetails, and packageDetails are required",
        });
        return;
      }
      if (!deliveryType || (deliveryType !== "instant" && deliveryType !== "scheduled")) {
        res.status(400).json({
          success: false,
          message: "deliveryType is required and must be 'instant' or 'scheduled'",
        });
        return;
      }

      const userId = req.userId;
      if (!userId) {
        res.status(401).json({ success: false, message: "Authentication required" });
        return;
      }

      const shipment = await shipmentService.createShipment(userId, {
        deliveryType,
        senderDetails,
        recipientDetails,
        packageDetails,
        ...(pickupWindowStart != null && pickupWindowEnd != null && { pickupWindowStart, pickupWindowEnd }),
      });

      res.status(201).json({
        success: true,
        message: "Shipment created successfully",
        data: shipment,
      });
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : "Error creating shipment";
      res.status(400).json({
        success: false,
        message,
      });
    }
  }

  async getShipments(req: AuthRequest, res: Response): Promise<void> {
    try {
      const userId = req.userId;
      if (!userId) {
        res.status(401).json({ success: false, message: "Authentication required" });
        return;
      }
      const shipments = await shipmentService.findByUserId(userId);
      res.status(200).json({
        success: true,
        data: shipments,
      });
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : "Error fetching shipments";
      res.status(500).json({
        success: false,
        message,
      });
    }
  }
}
