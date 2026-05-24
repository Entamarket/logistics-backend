import { Response } from "express";
import { ShipmentService } from "./shipment.service";
import { AuthRequest } from "../../shared/middlewares/auth.middleware";

const shipmentService = new ShipmentService();

export class ShipmentController {
  async estimateShipmentPrice(req: AuthRequest, res: Response): Promise<void> {
    try {
      const userId = req.userId;
      if (!userId) {
        res.status(401).json({ success: false, message: "Authentication required" });
        return;
      }

      const { senderDetails, recipientDetails, weight, lengthCm, widthCm, heightCm } = req.body ?? {};
      if (!senderDetails || !recipientDetails) {
        res.status(400).json({
          success: false,
          message: "senderDetails and recipientDetails are required",
        });
        return;
      }
      if (weight === undefined || weight === null || weight === "") {
        res.status(400).json({ success: false, message: "weight is required" });
        return;
      }
      if (lengthCm === undefined || widthCm === undefined || heightCm === undefined) {
        res.status(400).json({
          success: false,
          message: "lengthCm, widthCm, and heightCm are required",
        });
        return;
      }

      const breakdown = await shipmentService.estimateShipmentPrice({
        senderDetails,
        recipientDetails,
        weight: Number(weight),
        lengthCm: Number(lengthCm),
        widthCm: Number(widthCm),
        heightCm: Number(heightCm),
      });

      res.status(200).json({
        success: true,
        data: breakdown,
      });
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : "Error estimating shipment price";
      res.status(400).json({ success: false, message });
    }
  }

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
        recipientLongitude,
        recipientLatitude,
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

      const recLng =
        recipientLongitude !== undefined && recipientLongitude !== null && recipientLongitude !== ""
          ? Number(recipientLongitude)
          : undefined;
      const recLat =
        recipientLatitude !== undefined && recipientLatitude !== null && recipientLatitude !== ""
          ? Number(recipientLatitude)
          : undefined;

      const shipment = await shipmentService.createShipment(userId, {
        deliveryType,
        senderDetails,
        recipientDetails,
        packageDetails,
        ...(pickupWindowStart != null && pickupWindowEnd != null && { pickupWindowStart, pickupWindowEnd }),
        ...(lng !== undefined && !Number.isNaN(lng) && { pickupLongitude: lng }),
        ...(lat !== undefined && !Number.isNaN(lat) && { pickupLatitude: lat }),
        ...(recLng !== undefined && !Number.isNaN(recLng) && { recipientLongitude: recLng }),
        ...(recLat !== undefined && !Number.isNaN(recLat) && { recipientLatitude: recLat }),
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

  async getRiderAddressBook(req: AuthRequest, res: Response): Promise<void> {
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
      const entries = await shipmentService.findAddressBookForRiderUser(userId);
      if (entries === null) {
        res.status(404).json({ success: false, message: "Rider profile not found" });
        return;
      }
      res.status(200).json({ success: true, data: entries });
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : "Error fetching address book";
      res.status(500).json({ success: false, message });
    }
  }

  async getTracking(req: AuthRequest, res: Response): Promise<void> {
    try {
      const userId = req.userId;
      if (!userId) {
        res.status(401).json({ success: false, message: "Authentication required" });
        return;
      }
      const { id } = req.params;
      if (!id) {
        res.status(400).json({ success: false, message: "Shipment id is required" });
        return;
      }
      const data = await shipmentService.getTrackingForOwner(id, userId);
      if (!data) {
        res.status(404).json({ success: false, message: "Shipment not found" });
        return;
      }
      res.status(200).json({ success: true, data });
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : "Error fetching tracking";
      const lower = message.toLowerCase();
      const status = lower.includes("not authorized") ? 403 : 500;
      res.status(status).json({ success: false, message });
    }
  }

  async markPickedUp(req: AuthRequest, res: Response): Promise<void> {
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
      const shipment = await shipmentService.markPickedUp(id, userId, role);
      res.status(200).json({
        success: true,
        message: "Marked as picked up",
        data: shipment,
      });
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : "Error updating shipment";
      res.status(this.mapRiderOfferError(message)).json({ success: false, message });
    }
  }

  async markInTransit(req: AuthRequest, res: Response): Promise<void> {
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
      const shipment = await shipmentService.markInTransit(id, userId, role);
      res.status(200).json({
        success: true,
        message: "Marked as in transit",
        data: shipment,
      });
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : "Error updating shipment";
      res.status(this.mapRiderOfferError(message)).json({ success: false, message });
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
