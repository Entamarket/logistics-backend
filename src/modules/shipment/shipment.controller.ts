import { Response } from "express";
import { ShipmentService } from "./shipment.service";
import { AuthRequest } from "../../shared/middlewares/auth.middleware";

const shipmentService = new ShipmentService();

export class ShipmentController {
  async createShipment(req: AuthRequest, res: Response): Promise<void> {
    try {
      const {
        deliveryType,
        senderDetails,
        recipientDetails,
        packageDetails,
        pickupWindowStart,
        pickupWindowEnd,
        pickupLongitude,
        pickupLatitude,
      } = req.body;

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

      const lng =
        pickupLongitude !== undefined && pickupLongitude !== null && pickupLongitude !== ""
          ? Number(pickupLongitude)
          : undefined;
      const lat =
        pickupLatitude !== undefined && pickupLatitude !== null && pickupLatitude !== ""
          ? Number(pickupLatitude)
          : undefined;

      const shipment = await shipmentService.createShipment(userId, {
        deliveryType,
        senderDetails,
        recipientDetails,
        packageDetails,
        ...(pickupWindowStart != null && pickupWindowEnd != null && { pickupWindowStart, pickupWindowEnd }),
        ...(lng !== undefined && !Number.isNaN(lng) && { pickupLongitude: lng }),
        ...(lat !== undefined && !Number.isNaN(lat) && { pickupLatitude: lat }),
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

  private mapRiderOfferError(message: string): number {
    const m = message.toLowerCase();
    if (m.includes("not found")) return 404;
    if (m.includes("rider access required") || m.includes("not authorized")) return 403;
    return 400;
  }

  async acceptRiderOffer(req: AuthRequest, res: Response): Promise<void> {
    try {
      const userId = req.userId;
      const role = req.user?.role ?? "";
      if (!userId) {
        res.status(401).json({ success: false, message: "Authentication required" });
        return;
      }
      const { id } = req.params;
      if (!id) {
        res.status(400).json({ success: false, message: "Shipment id is required" });
        return;
      }
      const shipment = await shipmentService.acceptRiderOffer(id, userId, role);
      res.status(200).json({
        success: true,
        message: "Offer accepted",
        data: shipment,
      });
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : "Error accepting offer";
      res.status(this.mapRiderOfferError(message)).json({
        success: false,
        message,
      });
    }
  }

  async rejectRiderOffer(req: AuthRequest, res: Response): Promise<void> {
    try {
      const userId = req.userId;
      const role = req.user?.role ?? "";
      if (!userId) {
        res.status(401).json({ success: false, message: "Authentication required" });
        return;
      }
      const { id } = req.params;
      if (!id) {
        res.status(400).json({ success: false, message: "Shipment id is required" });
        return;
      }
      const shipment = await shipmentService.rejectRiderOffer(id, userId, role);
      res.status(200).json({
        success: true,
        message: "Offer declined; reassigned when another rider is available",
        data: shipment,
      });
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : "Error declining offer";
      res.status(this.mapRiderOfferError(message)).json({
        success: false,
        message,
      });
    }
  }

  async markDelivered(req: AuthRequest, res: Response): Promise<void> {
    try {
      const userId = req.userId;
      const role = req.user?.role ?? "";
      if (!userId) {
        res.status(401).json({ success: false, message: "Authentication required" });
        return;
      }
      const { id } = req.params;
      if (!id) {
        res.status(400).json({ success: false, message: "Shipment id is required" });
        return;
      }
      const shipment = await shipmentService.markDelivered(id, userId, role);
      res.status(200).json({
        success: true,
        message: "Shipment marked as delivered",
        data: shipment,
      });
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : "Error updating shipment";
      const lower = message.toLowerCase();
      const status =
        lower.includes("not found") ? 404 : lower.includes("not authorized") ? 403 : 400;
      res.status(status).json({
        success: false,
        message,
      });
    }
  }

  async getShipmentsForRider(req: AuthRequest, res: Response): Promise<void> {
    try {
      if (req.user?.role !== "rider") {
        res.status(403).json({ success: false, message: "Rider access required" });
        return;
      }
      const userId = req.userId;
      if (!userId) {
        res.status(401).json({ success: false, message: "Authentication required" });
        return;
      }
      const raw = typeof req.query.scope === "string" ? req.query.scope : "active";
      const scope =
        raw === "history" ? "history" : raw === "all" ? "all" : ("active" as const);
      const shipments = await shipmentService.findShipmentsForRiderUser(userId, scope);
      if (shipments === null) {
        res.status(404).json({ success: false, message: "Rider profile not found" });
        return;
      }
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
